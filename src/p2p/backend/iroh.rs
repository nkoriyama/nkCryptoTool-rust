use crate::config::CryptoConfig;
use crate::error::{CryptoError, Result};
use crate::network::{ALPN_CHAT, ALPN_FILE, ALPN_INBOX, ALPN_MLS};
use iroh::{Endpoint, SecretKey, Watcher};
use std::path::Path;
use std::str::FromStr;

// ---------------------------------------------------------------------------
// iroh ↔ application address conversions.
//
// The application talks in `crate::p2p::PeerAddr`; only iroh-aware code
// (this file) materialises `iroh::NodeAddr`. These helpers will move to
// `crate::p2p::backend::iroh` once that module is introduced (step 3).
// ---------------------------------------------------------------------------

fn peer_addr_from_iroh(addr: &iroh::EndpointAddr) -> crate::p2p::PeerAddr {
    // iroh 1.0 collapses relay URL + direct socket addrs into a single
    // `addrs: BTreeSet<TransportAddr>`; split them back out for `PeerAddr`.
    let mut relay_url = None;
    let mut direct_addrs = Vec::new();
    for a in &addr.addrs {
        match a {
            iroh::TransportAddr::Relay(u) => relay_url = Some(u.to_string()),
            iroh::TransportAddr::Ip(s) => direct_addrs.push(*s),
            _ => {}
        }
    }
    crate::p2p::PeerAddr {
        peer_id: crate::p2p::PeerId::new(*addr.id.as_bytes()),
        relay_url,
        direct_addrs,
    }
}

fn iroh_node_addr_from_peer(addr: &crate::p2p::PeerAddr) -> Result<iroh::EndpointAddr> {
    let id = iroh::EndpointId::from_bytes(addr.peer_id.as_bytes())
        .map_err(|e| CryptoError::Parameter(format!("Invalid EndpointId: {}", e)))?;
    let mut addrs: Vec<iroh::TransportAddr> = Vec::new();
    if let Some(s) = addr.relay_url.as_ref() {
        let relay_url = iroh::RelayUrl::from_str(s)
            .map_err(|e| CryptoError::Parameter(format!("Invalid RelayUrl: {}", e)))?;
        addrs.push(iroh::TransportAddr::Relay(relay_url));
    }
    for s in &addr.direct_addrs {
        addrs.push(iroh::TransportAddr::Ip(*s));
    }
    Ok(iroh::EndpointAddr::from_parts(id, addrs))
}

/// Load the persistent iroh node secret key from `path`, or create one
/// (0600, parent dirs made as needed) on first use. The key is a raw
/// 32-byte ed25519 seed — the same wire form `SecretKey::to_bytes`
/// produces — so the file is forward/backward compatible with iroh's own
/// key encoding. Returning a stable key keeps our NodeId fixed across runs.
fn load_or_create_node_secret(path: &Path) -> Result<SecretKey> {
    use zeroize::Zeroizing;
    if path.exists() {
        let bytes = Zeroizing::new(
            std::fs::read(path)
                .map_err(|e| CryptoError::Parameter(format!("read node key {path:?}: {e}")))?,
        );
        let seed: &[u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            CryptoError::Parameter(format!(
                "node key {path:?} is {} bytes, expected 32",
                bytes.len()
            ))
        })?;
        return Ok(SecretKey::from_bytes(seed));
    }

    // First run: mint a fresh seed and persist it 0600 before returning.
    let mut seed = Zeroizing::new([0u8; 32]);
    {
        use rand_core::RngCore;
        rand_core::OsRng.fill_bytes(seed.as_mut());
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                CryptoError::Parameter(format!("create node key dir {parent:?}: {e}"))
            })?;
        }
    }
    // Create owner-only from the start so the seed is never briefly world-
    // readable between write and chmod.
    write_owner_only(path, seed.as_ref())
        .map_err(|e| CryptoError::Parameter(format!("write node key {path:?}: {e}")))?;
    Ok(SecretKey::from_bytes(&seed))
}

/// Write `bytes` to `path`, creating it exclusively (`O_EXCL`) so we never
/// follow a symlink an attacker raced into place between the existence check
/// and here, and never clobber a file that appeared concurrently. On unix
/// the file is opened mode 0600 so it is never group/other-readable; other
/// platforms fall back to an exclusive create (perms inherited from the
/// parent dir, matching how the rest of the at-rest key files are handled).
fn write_owner_only(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(bytes)?;
    f.flush()
}

// ---------------------------------------------------------------------------
// IrohEndpoint — full `crate::p2p::P2pEndpoint` implementation backed by an
// `iroh::Endpoint`. Coexists with the legacy `NetworkProcessor` in this file:
// the trait surface is what the mock backend (step 5) and any future
// alternative transport (e.g. libp2p) need to match; `NetworkProcessor`
// still uses iroh directly via its own `create_endpoint`.
//
// A `MigrationContext` migration of `NetworkProcessor` to consume
// `IrohEndpoint` through the trait is intentionally deferred — it touches
// ~1000 lines of NKCT protocol code and benefits from its own focused PR.
// ---------------------------------------------------------------------------

/// `AsyncRead + AsyncWrite` adapter joining iroh's split bi-stream halves
/// (`SendStream` + `RecvStream`) into a single object so it satisfies
/// the application's `crate::p2p::P2pStream` trait.
pub struct IrohBiStream {
    send: iroh::endpoint::SendStream,
    recv: iroh::endpoint::RecvStream,
}

// iroh's SendStream / RecvStream expose inherent `poll_*` methods whose
// error type is iroh's own (quinn-derived) WriteError/ReadError. tokio's
// AsyncRead/AsyncWrite traits require `io::Error`, so we convert at the
// boundary via `Poll::map`.
fn map_io<T, E: std::error::Error + Send + Sync + 'static>(
    p: std::task::Poll<std::result::Result<T, E>>,
) -> std::task::Poll<std::io::Result<T>> {
    p.map(|r| r.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)))
}

impl tokio::io::AsyncRead for IrohBiStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for IrohBiStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        map_io(std::pin::Pin::new(&mut self.send).poll_write(cx, buf))
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        map_io(std::pin::Pin::new(&mut self.send).poll_flush(cx))
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        map_io(std::pin::Pin::new(&mut self.send).poll_shutdown(cx))
    }
}

/// `P2pEndpoint` implementation backed by an `iroh::Endpoint`.
///
/// The set of supported application protocols (ALPNs) is fixed at
/// construction; the same set MUST also have been registered on the
/// wrapped `iroh::Endpoint` via `Endpoint::builder().alpns(...)` so the
/// QUIC layer can negotiate them. `accept` rejects any peer whose
/// negotiated ALPN is not in this set so the caller never sees an
/// unknown protocol.
/// A half-open incoming iroh connection: the `Accepting` future plus the
/// endpoint's registered protocols, so `establish` can negotiate the ALPN and
/// open the stream off the accept loop under a timeout.
struct IrohPending {
    accepting: iroh::endpoint::Accepting,
    protocols: Vec<crate::p2p::P2pProtocol>,
}

#[async_trait::async_trait]
impl crate::p2p::P2pPending for IrohPending {
    async fn establish(
        self: Box<Self>,
        timeout: std::time::Duration,
    ) -> std::result::Result<crate::p2p::P2pIncoming, crate::p2p::P2pError> {
        let IrohPending {
            mut accepting,
            protocols,
        } = *self;
        tokio::time::timeout(timeout, async move {
            let alpn_bytes = accepting
                .alpn()
                .await
                .map_err(|e| crate::p2p::P2pError::Accept(format!("ALPN detection: {}", e)))?;
            let protocol = protocols
                .iter()
                .find(|p| p.0 == alpn_bytes.as_slice())
                .copied()
                .ok_or_else(|| {
                    crate::p2p::P2pError::Accept(format!(
                        "Unknown ALPN: {:?}",
                        String::from_utf8_lossy(alpn_bytes.as_slice())
                    ))
                })?;
            let connection = accepting
                .await
                .map_err(|e| crate::p2p::P2pError::Accept(e.to_string()))?;
            let remote_node_id = connection.remote_id();
            let peer_id = crate::p2p::PeerId::new(*remote_node_id.as_bytes());
            let (send, recv) = connection
                .accept_bi()
                .await
                .map_err(|e| crate::p2p::P2pError::Accept(format!("accept_bi: {}", e)))?;
            Ok::<_, crate::p2p::P2pError>(crate::p2p::P2pIncoming {
                peer_id,
                protocol,
                stream: Box::new(IrohBiStream { send, recv }),
            })
        })
        .await
        .map_err(|_| crate::p2p::P2pError::Accept("connection setup timed out".to_string()))?
    }
}

pub struct IrohEndpoint {
    endpoint: iroh::Endpoint,
    local_id: crate::p2p::PeerId,
    protocols: Vec<crate::p2p::P2pProtocol>,
    /// Whether this endpoint was built with a relay (n0 default or a custom
    /// `--relay-url`). When true, `local_addr` waits for the home relay to be
    /// assigned before producing the ticket address, so the relay URL — the
    /// NAT-traversal fallback a cross-network peer needs — is embedded in the
    /// ticket. When false (`--no-relay` / test mode) there is no relay to wait
    /// for, so `local_addr` returns as soon as any direct address is known.
    relay_enabled: bool,
    /// Live metrics for the most recent outgoing `connect` (selected-path
    /// relay/direct + RTT), exposed via `last_connect_metrics` for the status bar.
    last_metrics: std::sync::Mutex<Option<std::sync::Arc<dyn crate::p2p::ConnMetrics>>>,
}

/// [`crate::p2p::ConnMetrics`] over a live iroh `Connection`: reads the selected
/// path's relay flag and RTT from a fresh `paths()` snapshot on each poll.
struct IrohConnMetrics {
    conn: iroh::endpoint::Connection,
}

impl crate::p2p::ConnMetrics for IrohConnMetrics {
    fn snapshot(&self) -> Option<crate::p2p::ConnSnapshot> {
        let paths = self.conn.paths();
        // Prefer the path QUIC has selected for transmission; fall back to the
        // first known path so a just-established connection still reports.
        let chosen = paths.iter().find(|p| p.is_selected()).or_else(|| paths.iter().next())?;
        Some(crate::p2p::ConnSnapshot {
            relay: chosen.is_relay(),
            rtt_ms: Some(chosen.rtt().as_millis().min(u32::MAX as u128) as u32),
        })
    }
}

impl IrohEndpoint {
    /// Wrap an already-built `iroh::Endpoint`. `protocols` must match
    /// the ALPNs the endpoint was built with.
    pub fn from_endpoint(
        endpoint: iroh::Endpoint,
        protocols: Vec<crate::p2p::P2pProtocol>,
    ) -> Self {
        let local_id = crate::p2p::PeerId::new(*endpoint.id().as_bytes());
        Self {
            endpoint,
            local_id,
            protocols,
            // Safe default for callers that build their own endpoint: assume a
            // relay may be in use and wait for it (bounded by a timeout). `new`
            // overrides this with the exact relay configuration.
            relay_enabled: true,
            last_metrics: std::sync::Mutex::new(None),
        }
    }

    /// Convenience constructor: builds an `iroh::Endpoint` configured
    /// from `config` (relay mode honours `no_relay` / `relay_url`),
    /// registers the application's ALPNs (`ALPN_CHAT`, `ALPN_FILE`,
    /// `ALPN_MLS`), and wraps the result.
    ///
    /// `is_test=true` forces `RelayMode::Disabled` regardless of config
    /// so the integration test suite does not depend on the public
    /// relay network.
    pub async fn new(config: &CryptoConfig, is_test: bool) -> Result<Self> {
        // Discovery selects the endpoint preset:
        //   `None`  → `Minimal` (crypto provider only): ticket-only reachability,
        //             no presence published — the private default.
        //   `N0`    → `N0` (adds a pkarr publisher + n0 DNS lookup): publishes to
        //             and resolves via n0's public DNS. Required for reachability
        //             across real NATs / cloud firewalls — relay and hole-punch
        //             coordination need the node discoverable, which ticket-only
        //             `None` does not provide beyond a shared LAN (verified: an
        //             OCI VPS is unreachable under `None`, connects with a direct
        //             hole-punch under `N0`). Costs a third-party (n0 DNS)
        //             observation point.
        //   `Local` → mDNS, not yet available on iroh 1.0 (see DiscoveryMode).
        // The relay mode a preset may set is overridden unconditionally below.
        let preset_builder = match config.discovery {
            crate::config::DiscoveryMode::None => {
                Endpoint::builder(iroh::endpoint::presets::Minimal)
            }
            crate::config::DiscoveryMode::N0 => {
                Endpoint::builder(iroh::endpoint::presets::N0)
            }
            crate::config::DiscoveryMode::Local => {
                return Err(CryptoError::Parameter(
                    "--discovery local (mDNS) is not yet supported on the iroh 1.0 \
                     transport. Use --discovery none (ticket-only, LAN / out-of-band) \
                     or --discovery n0 (n0 DNS/pkarr, cross-NAT) for now."
                        .to_string(),
                ));
            }
        };
        let mut builder = preset_builder.alpns(vec![
            ALPN_CHAT.to_vec(),
            ALPN_FILE.to_vec(),
            ALPN_MLS.to_vec(),
            ALPN_INBOX.to_vec(),
            crate::network::ALPN_SHELL.to_vec(),
            crate::network::ALPN_FWD.to_vec(),
            crate::network::ALPN_SCP.to_vec(),
        ]);

        // A persistent node key gives us a stable NodeId across runs, which
        // the asynchronous inbox/prekey flow needs (PUBLISH in one run, POLL
        // in another, both addressing the same recipient slot). Without it
        // iroh mints a fresh ephemeral key on every `bind()`.
        if let Some(path) = config.node_key_path.as_deref() {
            builder = builder.secret_key(load_or_create_node_secret(path)?);
        }

        if is_test || config.no_relay {
            builder = builder.relay_mode(iroh::RelayMode::Disabled);
        } else if let Some(ref url) = config.relay_url {
            let relay_url = iroh::RelayUrl::from_str(url)
                .map_err(|e| CryptoError::Parameter(format!("Invalid RelayUrl: {}", e)))?;
            builder = builder.relay_mode(iroh::RelayMode::Custom(
                iroh_relay::RelayMap::from(relay_url),
            ));
        } else {
            // Set the relay mode explicitly regardless of preset (`Minimal` sets
            // none; `N0` already sets this): the historical default is n0 public
            // relays when neither `--no-relay` nor `--relay-url` is given.
            builder = builder.relay_mode(iroh::endpoint::default_relay_mode());
        }


        let endpoint = builder
            .bind()
            .await
            .map_err(|e| CryptoError::Parameter(e.to_string()))?;

        let protocols = vec![
            crate::p2p::P2pProtocol(ALPN_CHAT),
            crate::p2p::P2pProtocol(ALPN_FILE),
            crate::p2p::P2pProtocol(ALPN_MLS),
            crate::p2p::P2pProtocol(ALPN_INBOX),
            crate::p2p::P2pProtocol(crate::network::ALPN_SHELL),
            crate::p2p::P2pProtocol(crate::network::ALPN_FWD),
            crate::p2p::P2pProtocol(crate::network::ALPN_SCP),
        ];
        let mut ep = Self::from_endpoint(endpoint, protocols);
        // Relay is in use unless explicitly disabled (test mode or `--no-relay`).
        // A custom `--relay-url` and the n0 default both count as enabled.
        ep.relay_enabled = !(is_test || config.no_relay);
        Ok(ep)
    }

    /// Direct access to the underlying iroh endpoint. Intended for the
    /// transitional period only — application code should reach for the
    /// trait, not this method.
    pub fn raw(&self) -> &iroh::Endpoint {
        &self.endpoint
    }
}

#[async_trait::async_trait]
impl crate::p2p::P2pEndpoint for IrohEndpoint {
    fn local_id(&self) -> crate::p2p::PeerId {
        self.local_id
    }

    async fn local_addr(
        &self,
    ) -> std::result::Result<crate::p2p::PeerAddr, crate::p2p::P2pError> {
        // iroh 1.0's `watch_addr()` yields an `EndpointAddr` (not an `Option`),
        // so there is no `initialized()`; we poll it until the address set is
        // "ready enough" to put in a ticket.
        //
        // Readiness is NOT simply "any address known": iroh discovers local
        // direct addresses almost immediately but assigns the home *relay* a
        // beat later (it needs a round-trip to the relay server). If we returned
        // on the first direct address we would publish a ticket with only
        // LAN-private addresses and `relay_url = None` — unreachable from
        // another network, which is exactly why callers previously had to pass
        // `--relay-url` by hand. So when a relay is in use we wait for the relay
        // address to appear (bounded by `RELAY_READY_TIMEOUT` so a relay outage
        // can't hang us — we then ship whatever we have). With `--no-relay`
        // there is no relay to wait for, so any direct address is enough.
        const RELAY_READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
        let want_relay = self.relay_enabled;
        let mut watcher = self.endpoint.watch_addr();
        let wait = async {
            loop {
                let addr = watcher.get();
                let has_relay = addr
                    .addrs
                    .iter()
                    .any(|a| matches!(a, iroh::TransportAddr::Relay(_)));
                let ready = if want_relay {
                    has_relay
                } else {
                    !addr.addrs.is_empty()
                };
                if ready {
                    break addr;
                }
                if watcher.updated().await.is_err() {
                    break watcher.get();
                }
            }
        };
        let node_addr = match tokio::time::timeout(RELAY_READY_TIMEOUT, wait).await {
            Ok(addr) => addr,
            // Relay never came up within the budget; fall back to whatever
            // addresses are known so we still produce a (best-effort) ticket.
            Err(_) => watcher.get(),
        };
        Ok(peer_addr_from_iroh(&node_addr))
    }

    async fn connect(
        &self,
        addr: &crate::p2p::PeerAddr,
        protocol: crate::p2p::P2pProtocol,
    ) -> std::result::Result<Box<dyn crate::p2p::P2pStream>, crate::p2p::P2pError> {
        let node_addr = iroh_node_addr_from_peer(addr)
            .map_err(|e| crate::p2p::P2pError::Backend(e.to_string()))?;
        let connection = self
            .endpoint
            .connect(node_addr, protocol.0)
            .await
            .map_err(|e| crate::p2p::P2pError::Connect(e.to_string()))?;
        let (send, recv) = connection
            .open_bi()
            .await
            .map_err(|e| crate::p2p::P2pError::Connect(format!("open_bi: {}", e)))?;
        // Retain a clone of the connection for live status metrics. iroh's
        // `Connection` is an internal handle (cheap to clone) and stays alive as
        // long as the streams do, so this does not extend its lifetime.
        if let Ok(mut slot) = self.last_metrics.lock() {
            *slot = Some(std::sync::Arc::new(IrohConnMetrics { conn: connection.clone() }));
        }
        Ok(Box::new(IrohBiStream { send, recv }))
    }

    fn last_connect_metrics(&self) -> Option<std::sync::Arc<dyn crate::p2p::ConnMetrics>> {
        self.last_metrics.lock().ok().and_then(|m| m.clone())
    }

    async fn accept(
        &self,
    ) -> std::result::Result<Box<dyn crate::p2p::P2pPending>, crate::p2p::P2pError> {
        // Only the cheap, peer-independent steps run here: wait for a QUIC
        // incoming and turn it into an `Accepting`. Protocol negotiation and
        // `accept_bi` — the steps a malicious peer can stall — are deferred to
        // `IrohPending::establish`, run off the accept loop under a timeout.
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or(crate::p2p::P2pError::Closed)?;
        let accepting = incoming
            .accept()
            .map_err(|e| crate::p2p::P2pError::Accept(e.to_string()))?;
        Ok(Box::new(IrohPending {
            accepting,
            protocols: self.protocols.clone(),
        }))
    }

    async fn close(&self) -> std::result::Result<(), crate::p2p::P2pError> {
        self.endpoint.close().await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;
    use crate::utils;
    use std::sync::atomic::Ordering;
    use serial_test::serial;
    use crate::network::{TestIOProvider, CHAT_ACTIVE, PEER_COOLDOWNS};
    use crate::p2p::NetworkProcessor;
    use std::sync::Arc;
    use std::time::Duration;
    use crate::ticket::Ticket;
    use sha3::{Digest, Sha3_256};
    use crate::backend;

    async fn new_iroh_with_io_for_test(
        config: CryptoConfig,
        io_provider: Arc<dyn crate::network::IOProvider>,
    ) -> NetworkProcessor {
        let endpoint = Arc::new(IrohEndpoint::new(&config, true).await.unwrap());
        NetworkProcessor::new(config, endpoint, io_provider)
    }

    fn reset_state() {
        CHAT_ACTIVE.store(false, Ordering::SeqCst);
        PEER_COOLDOWNS.lock().clear();
    }

    /// The persistent node key is created on first use and reloaded
    /// verbatim afterwards, so our NodeId is stable across runs.
    #[test]
    fn node_key_is_created_then_reloaded_stably() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("sub").join("node.key");

        // First call mints + persists; the file appears 0600.
        let k1 = load_or_create_node_secret(&path).unwrap();
        assert!(path.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "node key must be owner-only");
        }

        // Second call reloads the same bytes → identical public NodeId.
        let k2 = load_or_create_node_secret(&path).unwrap();
        assert_eq!(k1.to_bytes(), k2.to_bytes());
        assert_eq!(k1.public(), k2.public());
    }

    /// A truncated/corrupt key file is rejected loudly rather than
    /// silently producing a different identity.
    #[test]
    fn node_key_wrong_length_is_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("node.key");
        fs::write(&path, [0u8; 16]).unwrap();
        assert!(load_or_create_node_secret(&path).is_err());
    }

    /// `--discovery local` (mDNS) is temporarily unsupported on the iroh 1.0
    /// transport: 1.0 removed local-network discovery from core and no iroh-1.0
    /// mDNS adapter exists yet (re-implementation over swarm-discovery is tracked
    /// separately). Until then `Local` must fail loudly rather than silently
    /// downgrade to `None`, while the default `None` still builds.
    #[tokio::test]
    #[serial]
    async fn local_discovery_is_rejected_on_iroh_1_0() {
        let mut config = CryptoConfig::default();
        config.transport = crate::config::TransportKind::Iroh;
        config.discovery = crate::config::DiscoveryMode::Local;
        config.no_relay = true;
        assert!(
            IrohEndpoint::new(&config, true).await.is_err(),
            "--discovery local must fail loudly until mDNS is re-implemented on iroh 1.0"
        );
        // None is the historical default and must still build (no discovery).
        let mut plain = CryptoConfig::default();
        plain.transport = crate::config::TransportKind::Iroh;
        plain.no_relay = true;
        assert!(IrohEndpoint::new(&plain, true).await.is_ok());
    }

    fn modify_ticket(ticket_str: &str, sign_fp: Option<[u8; 32]>, enc_fp: Option<[u8; 32]>) -> String {
        let mut ticket = Ticket::from_str(ticket_str).unwrap();
        let mut algo = 0u8;
        if let Some(fp) = sign_fp {
            algo |= 1;
            ticket.pqc_sign_fp = fp;
        } else {
            ticket.pqc_sign_fp = [0u8; 32];
        }
        if let Some(fp) = enc_fp {
            algo |= 2;
            ticket.pqc_enc_fp = fp;
        } else {
            ticket.pqc_enc_fp = [0u8; 32];
        }
        ticket.pqc_fp_algo = algo;
        ticket.to_string()
    }

    #[tokio::test]
    #[serial]
    async fn test_iroh_handshake_unauth() {
        reset_state();
        let (ticket_tx, ticket_rx) = tokio::sync::oneshot::channel();
        let mut server_config = CryptoConfig::default();
        server_config.transport = crate::config::TransportKind::Iroh;
        server_config.chat_mode = false;
        server_config.allow_unauth = true;
        server_config.handshake_timeout = 30;
        let server_task = tokio::spawn(async move {
            let mut processor = new_iroh_with_io_for_test(server_config, Arc::new(TestIOProvider)).await;
            processor.preload_allowlist().await.unwrap();
            let _ = processor.start_with_ticket_callback(|ticket| {
                let _ = ticket_tx.send(ticket.to_string());
            }).await;
        });
        let ticket_str = tokio::time::timeout(Duration::from_secs(60), ticket_rx).await.unwrap().unwrap();
        let mut client_config = CryptoConfig::default();
        client_config.transport = crate::config::TransportKind::Iroh;
        client_config.connect_addr = Some(modify_ticket(&ticket_str, None, None));
        client_config.chat_mode = false;
        client_config.allow_unauth = true;
        client_config.handshake_timeout = 30;
        let client_res = tokio::time::timeout(Duration::from_secs(60), async {
            let processor = new_iroh_with_io_for_test(client_config, Arc::new(TestIOProvider)).await;
            processor.run_connect().await
        }).await;
        server_task.abort();
        assert!(client_res.unwrap().is_ok());
    }

    #[tokio::test]
    #[serial]
    async fn test_iroh_handshake_auth_success() {
        reset_state();
        let dir = tempdir().unwrap();
        let s_key_path = dir.path().join("s.priv.pem");
        let s_pub_path = dir.path().join("s.pub.pem");
        let c_key_path = dir.path().join("c.priv.pem");
        let c_pub_path = dir.path().join("c.pub.pem");
        let (s_priv, s_pub, _) = backend::pqc_keygen_dsa("ML-DSA-65").unwrap();
        let (c_priv, c_pub, _) = backend::pqc_keygen_dsa("ML-DSA-65").unwrap();
        fs::write(&s_key_path, utils::wrap_to_pem(&utils::wrap_pqc_priv_to_pkcs8(&s_priv, "ML-DSA-65").unwrap(), "PRIVATE KEY")).unwrap();
        fs::write(&s_pub_path, utils::wrap_to_pem(&utils::wrap_pqc_pub_to_spki(&s_pub, "ML-DSA-65").unwrap(), "PUBLIC KEY")).unwrap();
        fs::write(&c_key_path, utils::wrap_to_pem(&utils::wrap_pqc_priv_to_pkcs8(&c_priv, "ML-DSA-65").unwrap(), "PRIVATE KEY")).unwrap();
        fs::write(&c_pub_path, utils::wrap_to_pem(&utils::wrap_pqc_pub_to_spki(&c_pub, "ML-DSA-65").unwrap(), "PUBLIC KEY")).unwrap();
        let s_fp = Sha3_256::digest(&s_pub).into();
        let (ticket_tx, ticket_rx) = tokio::sync::oneshot::channel();
        let mut server_config = CryptoConfig::default();
        server_config.transport = crate::config::TransportKind::Iroh;
        server_config.chat_mode = false;
        server_config.allow_unauth = false;
        server_config.signing_privkey = Some(s_key_path.to_str().unwrap().to_string());
        server_config.signing_pubkey = Some(c_pub_path.to_str().unwrap().to_string());
        server_config.handshake_timeout = 30;
        let _server_task = tokio::spawn(async move {
            let mut processor = new_iroh_with_io_for_test(server_config, Arc::new(TestIOProvider)).await;
            processor.preload_allowlist().await.unwrap();
            let _ = processor.start_with_ticket_callback(|ticket| {
                let _ = ticket_tx.send(ticket.to_string());
            }).await;
        });
        let ticket_str = ticket_rx.await.unwrap();
        let mut client_config = CryptoConfig::default();
        client_config.transport = crate::config::TransportKind::Iroh;
        client_config.connect_addr = Some(modify_ticket(&ticket_str, Some(s_fp), None));
        client_config.chat_mode = false;
        client_config.allow_unauth = false;
        client_config.signing_privkey = Some(c_key_path.to_str().unwrap().to_string());
        client_config.signing_pubkey = Some(s_pub_path.to_str().unwrap().to_string());
        client_config.handshake_timeout = 30;
        let client_res = tokio::time::timeout(Duration::from_secs(60), async {
            let processor = new_iroh_with_io_for_test(client_config, Arc::new(TestIOProvider)).await;
            processor.run_connect().await
        }).await;
        assert!(client_res.unwrap().is_ok());
    }

    // A-init (server side): the server pins client C via signing_pubkey; a different
    // client A (valid self-signature, wrong identity) must be REJECTED. Locks in that
    // the server binds the wire #6 to the pinned key before trusting sig_I — a
    // regression guard for the pin-before-verify ordering (symmetric with the
    // initiator's A-init).
    #[tokio::test]
    #[serial]
    async fn test_iroh_handshake_server_pins_client_rejects_other() {
        reset_state();
        let dir = tempdir().unwrap();
        let s_key_path = dir.path().join("s.priv.pem");
        let c_pub_path = dir.path().join("c.pub.pem");
        let a_key_path = dir.path().join("a.priv.pem");
        let (s_priv, _s_pub, _) = backend::pqc_keygen_dsa("ML-DSA-65").unwrap();
        let (_c_priv, c_pub, _) = backend::pqc_keygen_dsa("ML-DSA-65").unwrap();
        let (a_priv, _a_pub, _) = backend::pqc_keygen_dsa("ML-DSA-65").unwrap();
        fs::write(&s_key_path, utils::wrap_to_pem(&utils::wrap_pqc_priv_to_pkcs8(&s_priv, "ML-DSA-65").unwrap(), "PRIVATE KEY")).unwrap();
        fs::write(&c_pub_path, utils::wrap_to_pem(&utils::wrap_pqc_pub_to_spki(&c_pub, "ML-DSA-65").unwrap(), "PUBLIC KEY")).unwrap();
        fs::write(&a_key_path, utils::wrap_to_pem(&utils::wrap_pqc_priv_to_pkcs8(&a_priv, "ML-DSA-65").unwrap(), "PRIVATE KEY")).unwrap();
        let (ticket_tx, ticket_rx) = tokio::sync::oneshot::channel();
        let mut server_config = CryptoConfig::default();
        server_config.transport = crate::config::TransportKind::Iroh;
        server_config.chat_mode = false;
        server_config.allow_unauth = false;
        server_config.signing_privkey = Some(s_key_path.to_str().unwrap().to_string());
        server_config.signing_pubkey = Some(c_pub_path.to_str().unwrap().to_string()); // pins client C
        server_config.handshake_timeout = 30;
        let _server_task = tokio::spawn(async move {
            let mut processor = new_iroh_with_io_for_test(server_config, Arc::new(TestIOProvider)).await;
            processor.preload_allowlist().await.unwrap();
            let _ = processor.start_with_ticket_callback(|ticket| {
                let _ = ticket_tx.send(ticket.to_string());
            }).await;
        });
        let ticket_str = ticket_rx.await.unwrap();
        let mut client_config = CryptoConfig::default();
        client_config.transport = crate::config::TransportKind::Iroh;
        client_config.connect_addr = Some(modify_ticket(&ticket_str, None, None));
        client_config.chat_mode = false;
        client_config.allow_unauth = true; // A self-authenticates but does not pin the server
        client_config.signing_privkey = Some(a_key_path.to_str().unwrap().to_string()); // WRONG identity (not C)
        client_config.handshake_timeout = 30;
        let client_res = tokio::time::timeout(Duration::from_secs(60), async {
            let processor = new_iroh_with_io_for_test(client_config, Arc::new(TestIOProvider)).await;
            processor.run_connect().await
        }).await;
        assert!(client_res.unwrap().is_err(), "server must reject a client whose identity != the pinned key");
    }

    #[tokio::test]
    #[serial]
    async fn test_iroh_handshake_auth_fail_fingerprint_mismatch() {
        reset_state();
        let dir = tempdir().unwrap();
        let s_key_path = dir.path().join("s.priv.pem");
        let c_pub_path = dir.path().join("c.pub.pem");
        let (s_priv, _, _) = backend::pqc_keygen_dsa("ML-DSA-65").unwrap_or_else(|_| panic!("keygen failed"));
        let (_, c_pub, _) = backend::pqc_keygen_dsa("ML-DSA-65").unwrap();
        fs::write(&s_key_path, utils::wrap_to_pem(&utils::wrap_pqc_priv_to_pkcs8(&s_priv, "ML-DSA-65").unwrap(), "PRIVATE KEY")).unwrap();
        fs::write(&c_pub_path, utils::wrap_to_pem(&utils::wrap_pqc_pub_to_spki(&c_pub, "ML-DSA-65").unwrap(), "PUBLIC KEY")).unwrap();
        let wrong_fp = [0u8; 32];
        let (ticket_tx, ticket_rx) = tokio::sync::oneshot::channel();
        let mut server_config = CryptoConfig::default();
        server_config.transport = crate::config::TransportKind::Iroh;
        server_config.chat_mode = false;
        server_config.allow_unauth = true;
        server_config.signing_privkey = Some(s_key_path.to_str().unwrap().to_string());
        server_config.handshake_timeout = 30;
        let _server_task = tokio::spawn(async move {
            let mut processor = new_iroh_with_io_for_test(server_config, Arc::new(TestIOProvider)).await;
            processor.preload_allowlist().await.unwrap();
            let _ = processor.start_with_ticket_callback(|ticket| {
                let _ = ticket_tx.send(ticket.to_string());
            }).await;
        });
        let ticket_str = ticket_rx.await.unwrap();
        let mut client_config = CryptoConfig::default();
        client_config.transport = crate::config::TransportKind::Iroh;
        client_config.connect_addr = Some(modify_ticket(&ticket_str, Some(wrong_fp), None));
        client_config.chat_mode = false;
        client_config.allow_unauth = true;
        client_config.handshake_timeout = 30;
        let client_res = tokio::time::timeout(Duration::from_secs(60), async {
            let processor = new_iroh_with_io_for_test(client_config, Arc::new(TestIOProvider)).await;
            processor.run_connect().await
        }).await;
        assert!(client_res.unwrap().is_err());
    }

    #[tokio::test]
    #[serial]
    async fn test_iroh_handshake_auth_fail_invalid_sig() {
        reset_state();
        let dir = tempdir().unwrap();
        let s_key_path = dir.path().join("s.priv.pem");
        let c_pub_path = dir.path().join("c.pub.pem");
        let (s_priv, _, _) = backend::pqc_keygen_dsa("ML-DSA-65").unwrap_or_else(|_| panic!("keygen failed"));
        let (_, _, _) = backend::pqc_keygen_dsa("ML-DSA-65").unwrap_or_else(|_| panic!("keygen failed"));
        let (_, wrong_c_pub, _) = backend::pqc_keygen_dsa("ML-DSA-65").unwrap();
        fs::write(&s_key_path, utils::wrap_to_pem(&utils::wrap_pqc_priv_to_pkcs8(&s_priv, "ML-DSA-65").unwrap(), "PRIVATE KEY")).unwrap();
        fs::write(&c_pub_path, utils::wrap_to_pem(&utils::wrap_pqc_pub_to_spki(&wrong_c_pub, "ML-DSA-65").unwrap(), "PUBLIC KEY")).unwrap();
        let (ticket_tx, ticket_rx) = tokio::sync::oneshot::channel();
        let mut server_config = CryptoConfig::default();
        server_config.transport = crate::config::TransportKind::Iroh;
        server_config.chat_mode = false;
        server_config.allow_unauth = false;
        server_config.signing_privkey = Some(s_key_path.to_str().unwrap().to_string());
        server_config.signing_pubkey = Some(c_pub_path.to_str().unwrap().to_string());
        server_config.handshake_timeout = 30;
        let _server_task = tokio::spawn(async move {
            let mut processor = new_iroh_with_io_for_test(server_config, Arc::new(TestIOProvider)).await;
            processor.preload_allowlist().await.unwrap();
            let _ = processor.start_with_ticket_callback(|ticket| {
                let _ = ticket_tx.send(ticket.to_string());
            }).await;
        });
        let ticket_str = ticket_rx.await.unwrap();
        let mut client_config = CryptoConfig::default();
        client_config.transport = crate::config::TransportKind::Iroh;
        client_config.connect_addr = Some(modify_ticket(&ticket_str, None, None));
        client_config.chat_mode = false;
        client_config.allow_unauth = true;
        let client_res = tokio::time::timeout(Duration::from_secs(60), async {
            let processor = new_iroh_with_io_for_test(client_config, Arc::new(TestIOProvider)).await;
            processor.run_connect().await
        }).await;
        assert!(client_res.unwrap().is_err());
    }

    #[tokio::test]
    #[serial]
    async fn test_iroh_handshake_allowlist_reject() {
        reset_state();
        let dir = tempdir().unwrap();
        let allowlist_path = dir.path().join("allowlist.txt");
        fs::write(&allowlist_path, "0000000000000000000000000000000000000000000000000000000000000000\n").unwrap();
        let (ticket_tx, ticket_rx) = tokio::sync::oneshot::channel();
        let mut server_config = CryptoConfig::default();
        server_config.transport = crate::config::TransportKind::Iroh;
        server_config.chat_mode = false;
        server_config.allow_unauth = true;
        server_config.peer_allowlist = Some(allowlist_path.to_str().unwrap().to_string());
        server_config.handshake_timeout = 30;
        let _server_task = tokio::spawn(async move {
            let mut processor = new_iroh_with_io_for_test(server_config, Arc::new(TestIOProvider)).await;
            processor.preload_allowlist().await.unwrap();
            let _ = processor.start_with_ticket_callback(|ticket| {
                let _ = ticket_tx.send(ticket.to_string());
            }).await;
        });
        let ticket_str = ticket_rx.await.unwrap();
        let mut client_config = CryptoConfig::default();
        client_config.transport = crate::config::TransportKind::Iroh;
        client_config.connect_addr = Some(modify_ticket(&ticket_str, None, None));
        client_config.chat_mode = false;
        client_config.allow_unauth = true;
        let client_res = tokio::time::timeout(Duration::from_secs(60), async {
            let processor = new_iroh_with_io_for_test(client_config, Arc::new(TestIOProvider)).await;
            processor.run_connect().await
        }).await;
        assert!(client_res.unwrap().is_err());
    }

    #[tokio::test]
    #[serial]
    async fn test_iroh_handshake_multi_client_auth_success() {
        reset_state();
        let dir = tempdir().unwrap();
        let s_key_path = dir.path().join("s.priv.pem");
        let c_key_path = dir.path().join("c.priv.pem");
        let allowlist_path = dir.path().join("allowlist.txt");
        let (s_priv, _, _) = backend::pqc_keygen_dsa("ML-DSA-65").unwrap();
        let (c_priv, c_pub, _) = backend::pqc_keygen_dsa("ML-DSA-65").unwrap();
        fs::write(&s_key_path, utils::wrap_to_pem(&utils::wrap_pqc_priv_to_pkcs8(&s_priv, "ML-DSA-65").unwrap(), "PRIVATE KEY")).unwrap();
        fs::write(&c_key_path, utils::wrap_to_pem(&utils::wrap_pqc_priv_to_pkcs8(&c_priv, "ML-DSA-65").unwrap(), "PRIVATE KEY")).unwrap();
        fs::write(&allowlist_path, format!("{}\n", hex::encode(Sha3_256::digest(&c_pub)))).unwrap();
        let (ticket_tx, ticket_rx) = tokio::sync::oneshot::channel();
        let mut server_config = CryptoConfig::default();
        server_config.transport = crate::config::TransportKind::Iroh;
        server_config.chat_mode = false;
        server_config.allow_unauth = false;
        server_config.signing_privkey = Some(s_key_path.to_str().unwrap().to_string());
        server_config.peer_allowlist = Some(allowlist_path.to_str().unwrap().to_string());
        server_config.handshake_timeout = 30;
        let _server_task = tokio::spawn(async move {
            let mut processor = new_iroh_with_io_for_test(server_config, Arc::new(TestIOProvider)).await;
            processor.preload_allowlist().await.unwrap();
            let _ = processor.start_with_ticket_callback(|ticket| {
                let _ = ticket_tx.send(ticket.to_string());
            }).await;
        });
        let ticket_str = ticket_rx.await.unwrap();
        let mut client_config = CryptoConfig::default();
        client_config.transport = crate::config::TransportKind::Iroh;
        client_config.connect_addr = Some(modify_ticket(&ticket_str, None, None));
        client_config.chat_mode = false;
        // This test exercises CLIENT auth (the server allowlists the client); the
        // client does not pin the server's identity. Under KEY_EXCHANGE_DESIGN.md
        // §4.4, requiring responder auth (allow_unauth=false) without a server pin is
        // refused — so the honest setting for a client that self-authenticates but
        // does not pin the server is allow_unauth=true (anonymous-server mode).
        // (Mutual auth with a server pin / #7 pre-commit is covered by
        // test_iroh_handshake_auth_success.)
        client_config.allow_unauth = true;
        client_config.signing_privkey = Some(c_key_path.to_str().unwrap().to_string());
        let client_res = tokio::time::timeout(Duration::from_secs(60), async {
            let processor = new_iroh_with_io_for_test(client_config, Arc::new(TestIOProvider)).await;
            processor.run_connect().await
        }).await;
        assert!(client_res.unwrap().is_ok());
    }

    #[tokio::test]
    #[serial]
    async fn test_iroh_chat_loop_smoke() {
        reset_state();
        let (ticket_tx, ticket_rx) = tokio::sync::oneshot::channel();
        let mut server_config = CryptoConfig::default();
        server_config.transport = crate::config::TransportKind::Iroh;
        server_config.chat_mode = true;
        server_config.allow_unauth = true;
        let _server_task = tokio::spawn(async move {
            let mut processor = new_iroh_with_io_for_test(server_config, Arc::new(TestIOProvider)).await;
            processor.preload_allowlist().await.unwrap();
            let _ = processor.start_with_ticket_callback(|ticket| {
                let _ = ticket_tx.send(ticket.to_string());
            }).await;
        });
        let ticket_str = tokio::time::timeout(Duration::from_secs(60), ticket_rx).await.unwrap().unwrap();
        let mut client_config = CryptoConfig::default();
        client_config.transport = crate::config::TransportKind::Iroh;
        client_config.connect_addr = Some(modify_ticket(&ticket_str, None, None));
        client_config.chat_mode = true;
        client_config.allow_unauth = true;
        let client_res = tokio::time::timeout(Duration::from_secs(60), async {
            let processor = new_iroh_with_io_for_test(client_config, Arc::new(TestIOProvider)).await;
            processor.run_connect().await
        }).await;
        match client_res {
            Ok(res) => assert!(res.is_ok(), "Chat loop should exit cleanly on stdin EOF"),
            Err(_) => panic!("Chat loop timed out unexpectedly"),
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_iroh_file_transfer_smoke() {
        reset_state();
        let (ticket_tx, ticket_rx) = tokio::sync::oneshot::channel();
        let mut server_config = CryptoConfig::default();
        server_config.transport = crate::config::TransportKind::Iroh;
        server_config.chat_mode = false;
        server_config.allow_unauth = true;
        let _server_task = tokio::spawn(async move {
            let mut processor = new_iroh_with_io_for_test(server_config, Arc::new(TestIOProvider)).await;
            processor.preload_allowlist().await.unwrap();
            let _ = processor.start_with_ticket_callback(|ticket| {
                let _ = ticket_tx.send(ticket.to_string());
            }).await;
        });
        let ticket_str = tokio::time::timeout(Duration::from_secs(60), ticket_rx).await.unwrap().unwrap();
        let mut client_config = CryptoConfig::default();
        client_config.transport = crate::config::TransportKind::Iroh;
        client_config.connect_addr = Some(modify_ticket(&ticket_str, None, None));
        client_config.chat_mode = false;
        client_config.allow_unauth = true;
        let client_res = tokio::time::timeout(Duration::from_secs(60), async {
            let processor = new_iroh_with_io_for_test(client_config, Arc::new(TestIOProvider)).await;
            processor.run_connect().await
        }).await;
        assert!(client_res.unwrap().is_ok());
    }
}
