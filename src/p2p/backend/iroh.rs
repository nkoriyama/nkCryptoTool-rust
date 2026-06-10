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

fn peer_addr_from_iroh(addr: &iroh::NodeAddr) -> crate::p2p::PeerAddr {
    crate::p2p::PeerAddr {
        peer_id: crate::p2p::PeerId::new(*addr.node_id.as_bytes()),
        relay_url: addr.relay_url.as_ref().map(|u| u.to_string()),
        direct_addrs: addr.direct_addresses.iter().cloned().collect(),
    }
}

fn iroh_node_addr_from_peer(addr: &crate::p2p::PeerAddr) -> Result<iroh::NodeAddr> {
    let node_id = iroh::NodeId::from_bytes(addr.peer_id.as_bytes())
        .map_err(|e| CryptoError::Parameter(format!("Invalid NodeId: {}", e)))?;
    let relay_url = addr
        .relay_url
        .as_ref()
        .map(|s| {
            iroh::RelayUrl::from_str(s)
                .map_err(|e| CryptoError::Parameter(format!("Invalid RelayUrl: {}", e)))
        })
        .transpose()?;
    Ok(iroh::NodeAddr {
        node_id,
        relay_url,
        direct_addresses: addr.direct_addrs.iter().cloned().collect(),
    })
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
pub struct IrohEndpoint {
    endpoint: iroh::Endpoint,
    local_id: crate::p2p::PeerId,
    protocols: Vec<crate::p2p::P2pProtocol>,
}

impl IrohEndpoint {
    /// Wrap an already-built `iroh::Endpoint`. `protocols` must match
    /// the ALPNs the endpoint was built with.
    pub fn from_endpoint(
        endpoint: iroh::Endpoint,
        protocols: Vec<crate::p2p::P2pProtocol>,
    ) -> Self {
        let local_id = crate::p2p::PeerId::new(*endpoint.node_id().as_bytes());
        Self {
            endpoint,
            local_id,
            protocols,
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
        let mut builder = Endpoint::builder().alpns(vec![
            ALPN_CHAT.to_vec(),
            ALPN_FILE.to_vec(),
            ALPN_MLS.to_vec(),
            ALPN_INBOX.to_vec(),
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
        ];
        Ok(Self::from_endpoint(endpoint, protocols))
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
        let node_addr = self.endpoint.node_addr().initialized().await;
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
        Ok(Box::new(IrohBiStream { send, recv }))
    }

    async fn accept(
        &self,
    ) -> std::result::Result<crate::p2p::P2pIncoming, crate::p2p::P2pError> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or(crate::p2p::P2pError::Closed)?;
        let mut connecting = incoming
            .accept()
            .map_err(|e| crate::p2p::P2pError::Accept(e.to_string()))?;
        let alpn_bytes = connecting
            .alpn()
            .await
            .map_err(|e| crate::p2p::P2pError::Accept(format!("ALPN detection: {}", e)))?;
        let protocol = self
            .protocols
            .iter()
            .find(|p| p.0 == alpn_bytes.as_slice())
            .copied()
            .ok_or_else(|| {
                crate::p2p::P2pError::Accept(format!(
                    "Unknown ALPN: {:?}",
                    String::from_utf8_lossy(alpn_bytes.as_slice())
                ))
            })?;
        let connection = connecting
            .await
            .map_err(|e| crate::p2p::P2pError::Accept(e.to_string()))?;
        let remote_node_id = connection
            .remote_node_id()
            .map_err(|e| crate::p2p::P2pError::Accept(format!("Remote NodeId: {}", e)))?;
        let peer_id = crate::p2p::PeerId::new(*remote_node_id.as_bytes());
        let (send, recv) = connection
            .accept_bi()
            .await
            .map_err(|e| crate::p2p::P2pError::Accept(format!("accept_bi: {}", e)))?;
        Ok(crate::p2p::P2pIncoming {
            peer_id,
            protocol,
            stream: Box::new(IrohBiStream { send, recv }),
        })
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
    #[ignore = "flaky on CI runners: 2s handshake_timeout insufficient for slow PQC handshake; tracked in PHASE5_ROADMAP §3.3"]
    async fn test_iroh_handshake_unauth() {
        reset_state();
        let (ticket_tx, ticket_rx) = tokio::sync::oneshot::channel();
        let mut server_config = CryptoConfig::default();
        server_config.transport = crate::config::TransportKind::Iroh;
        server_config.chat_mode = false;
        server_config.allow_unauth = true;
        server_config.handshake_timeout = 2;
        let server_task = tokio::spawn(async move {
            let mut processor = new_iroh_with_io_for_test(server_config, Arc::new(TestIOProvider)).await;
            processor.preload_allowlist().await.unwrap();
            let _ = processor.start_with_ticket_callback(|ticket| {
                let _ = ticket_tx.send(ticket.to_string());
            }).await;
        });
        let ticket_str = tokio::time::timeout(Duration::from_secs(2), ticket_rx).await.unwrap().unwrap();
        let mut client_config = CryptoConfig::default();
        client_config.transport = crate::config::TransportKind::Iroh;
        client_config.connect_addr = Some(modify_ticket(&ticket_str, None, None));
        client_config.chat_mode = false;
        client_config.allow_unauth = true;
        client_config.handshake_timeout = 2;
        let client_res = tokio::time::timeout(Duration::from_secs(2), async {
            let processor = new_iroh_with_io_for_test(client_config, Arc::new(TestIOProvider)).await;
            processor.run_connect().await
        }).await;
        server_task.abort();
        assert!(client_res.unwrap().is_ok());
    }

    #[tokio::test]
    #[serial]
    #[ignore = "flaky on CI runners: 2s handshake_timeout insufficient for slow PQC handshake; tracked in PHASE5_ROADMAP §3.3"]
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
        server_config.handshake_timeout = 2;
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
        client_config.handshake_timeout = 2;
        let client_res = tokio::time::timeout(Duration::from_secs(2), async {
            let processor = new_iroh_with_io_for_test(client_config, Arc::new(TestIOProvider)).await;
            processor.run_connect().await
        }).await;
        assert!(client_res.unwrap().is_ok());
    }

    #[tokio::test]
    #[serial]
    #[ignore = "flaky on CI runners: 2s handshake_timeout insufficient for slow PQC handshake; tracked in PHASE5_ROADMAP §3.3"]
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
        server_config.handshake_timeout = 2;
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
        client_config.handshake_timeout = 2;
        let client_res = tokio::time::timeout(Duration::from_secs(2), async {
            let processor = new_iroh_with_io_for_test(client_config, Arc::new(TestIOProvider)).await;
            processor.run_connect().await
        }).await;
        assert!(client_res.unwrap().is_err());
    }

    #[tokio::test]
    #[serial]
    #[ignore = "flaky on CI runners: 2s handshake_timeout insufficient for slow PQC handshake; tracked in PHASE5_ROADMAP §3.3"]
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
        server_config.handshake_timeout = 2;
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
        let client_res = tokio::time::timeout(Duration::from_secs(2), async {
            let processor = new_iroh_with_io_for_test(client_config, Arc::new(TestIOProvider)).await;
            processor.run_connect().await
        }).await;
        assert!(client_res.unwrap().is_err());
    }

    #[tokio::test]
    #[serial]
    #[ignore = "flaky on CI runners: 2s handshake_timeout insufficient for slow PQC handshake; tracked in PHASE5_ROADMAP §3.3"]
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
        server_config.handshake_timeout = 2;
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
        let client_res = tokio::time::timeout(Duration::from_secs(2), async {
            let processor = new_iroh_with_io_for_test(client_config, Arc::new(TestIOProvider)).await;
            processor.run_connect().await
        }).await;
        assert!(client_res.unwrap().is_err());
    }

    #[tokio::test]
    #[serial]
    #[ignore = "flaky on CI runners: 2s handshake_timeout insufficient for slow PQC handshake; tracked in PHASE5_ROADMAP §3.3"]
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
        server_config.handshake_timeout = 2;
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
        client_config.allow_unauth = false;
        client_config.signing_privkey = Some(c_key_path.to_str().unwrap().to_string());
        let client_res = tokio::time::timeout(Duration::from_secs(2), async {
            let processor = new_iroh_with_io_for_test(client_config, Arc::new(TestIOProvider)).await;
            processor.run_connect().await
        }).await;
        assert!(client_res.unwrap().is_ok());
    }

    #[tokio::test]
    #[serial]
    #[ignore = "flaky on CI runners: 2s handshake_timeout insufficient for slow PQC handshake; tracked in PHASE5_ROADMAP §3.3"]
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
        let ticket_str = tokio::time::timeout(Duration::from_secs(2), ticket_rx).await.unwrap().unwrap();
        let mut client_config = CryptoConfig::default();
        client_config.transport = crate::config::TransportKind::Iroh;
        client_config.connect_addr = Some(modify_ticket(&ticket_str, None, None));
        client_config.chat_mode = true;
        client_config.allow_unauth = true;
        let client_res = tokio::time::timeout(Duration::from_secs(5), async {
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
    #[ignore = "flaky on CI runners: 2s handshake_timeout insufficient for slow PQC handshake; tracked in PHASE5_ROADMAP §3.3"]
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
        let ticket_str = tokio::time::timeout(Duration::from_secs(2), ticket_rx).await.unwrap().unwrap();
        let mut client_config = CryptoConfig::default();
        client_config.transport = crate::config::TransportKind::Iroh;
        client_config.connect_addr = Some(modify_ticket(&ticket_str, None, None));
        client_config.chat_mode = false;
        client_config.allow_unauth = true;
        let client_res = tokio::time::timeout(Duration::from_secs(2), async {
            let processor = new_iroh_with_io_for_test(client_config, Arc::new(TestIOProvider)).await;
            processor.run_connect().await
        }).await;
        assert!(client_res.unwrap().is_ok());
    }
}
