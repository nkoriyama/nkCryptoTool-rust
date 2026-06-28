/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

//! P2P port forwarding (bastion-less `ssh -L`) over `ALPN_FWD` — see
//! `P2P_SHELL_DESIGN.md` Phase 3.
//!
//! A single PQC-authenticated, AEAD-secured connection (the same handshake and
//! counter-nonce packet layer as the shell, reused via
//! [`crate::shell::send_packet`] / [`crate::shell::recv_packet`]) carries many
//! independent TCP streams, each a **logical channel** identified by a `u32`.
//! Only the **client** opens channels (local forward, `-L`): for every accepted
//! local TCP connection it asks the server to connect onward to `host:port`. The
//! server connects only to targets allowed by its per-fingerprint forward policy
//! (default deny) and records every decision to the audit log.
//!
//! Wire payload (inside one AEAD packet) is one [`FwdFrame`]; the multiplexer
//! tags each with its channel id so the two ends can demultiplex.
//!
//! **Isolation & limits.** Every forward client gets its own
//! PQC-authenticated connection, hence its own demultiplexer task and its own
//! pool of at most [`MAX_CHANNELS`] channels (a semaphore bounds concurrent
//! channels including in-flight connects). One client therefore cannot exhaust
//! the server or interfere with another client.
//!
//! **Known v1 limitation — no per-channel flow control.** Within *one* client's
//! connection the demultiplexer applies backpressure globally: if a single
//! channel's target stops reading, that channel's buffer fills and the shared
//! reader/writer stalls that client's other channels (head-of-line blocking).
//! This is bounded and confined to the misbehaving client's own connection (it is
//! self-inflicted; other clients are unaffected). Per-channel credit windows
//! (SSH-style) are the planned hardening.
//!
//! **Target trust (SSRF).** The server connects to whatever `host:port` its
//! operator-defined policy allows. Reaching internal/loopback addresses is often
//! the whole point (that is the bastion-less value), so there is no IP filtering;
//! prefer **IP literals** over hostnames in the policy when you do not control the
//! name's DNS, since an allowed hostname is only as trustworthy as its resolver.

use crate::error::{CryptoError, Result};
use crate::shell::{
    audit, audit_best_effort, fp_hex, parse_fp_hex, rate_limited, recv_packet, role_keys,
    send_packet,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex, OwnedSemaphorePermit, Semaphore};

const F_OPEN: u8 = 0x01;
const F_CONNECTED: u8 = 0x02;
const F_REJECTED: u8 = 0x03;
const F_DATA: u8 = 0x04;
const F_EOF: u8 = 0x05;
const F_CLOSE: u8 = 0x06;

/// Largest single forward DATA payload; bounds the per-frame allocation and keeps
/// one channel from monopolizing the shared stream.
const MAX_FWD_DATA: usize = 64 * 1024;
const TCP_READ_BUF: usize = 32 * 1024;
/// Cap on simultaneously open channels per connection (DoS bound).
const MAX_CHANNELS: usize = 256;

/// One multiplexed control/data frame on `ALPN_FWD`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FwdFrame {
    /// Client → server: open a channel forwarding to `host:port`.
    Open { chan: u32, host: String, port: u16 },
    /// Server → client: the onward TCP connect succeeded.
    Connected { chan: u32 },
    /// Server → client: the onward connect was denied or failed.
    Rejected { chan: u32, reason: String },
    /// Either direction: stream bytes for `chan`.
    Data { chan: u32, data: Vec<u8> },
    /// Either direction: no more data will be sent on `chan` (half-close).
    Eof { chan: u32 },
    /// Either direction: tear down `chan` completely.
    Close { chan: u32 },
}

impl FwdFrame {
    /// Serialize to the plaintext that goes inside one AEAD packet.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::new();
        match self {
            FwdFrame::Open { chan, host, port } => {
                v.push(F_OPEN);
                v.extend_from_slice(&chan.to_be_bytes());
                // Host length is a single byte; `ForwardSpec::parse` already caps
                // it at 255, but clamp defensively so an over-long host can never
                // wrap the length and emit a corrupt frame.
                let hlen = host.len().min(255);
                v.push(hlen as u8);
                v.extend_from_slice(&host.as_bytes()[..hlen]);
                v.extend_from_slice(&port.to_be_bytes());
            }
            FwdFrame::Connected { chan } => {
                v.push(F_CONNECTED);
                v.extend_from_slice(&chan.to_be_bytes());
            }
            FwdFrame::Rejected { chan, reason } => {
                v.push(F_REJECTED);
                v.extend_from_slice(&chan.to_be_bytes());
                v.extend_from_slice(reason.as_bytes());
            }
            FwdFrame::Data { chan, data } => {
                v.push(F_DATA);
                v.extend_from_slice(&chan.to_be_bytes());
                v.extend_from_slice(data);
            }
            FwdFrame::Eof { chan } => {
                v.push(F_EOF);
                v.extend_from_slice(&chan.to_be_bytes());
            }
            FwdFrame::Close { chan } => {
                v.push(F_CLOSE);
                v.extend_from_slice(&chan.to_be_bytes());
            }
        }
        v
    }

    /// Parse a frame from one packet's plaintext. Every length is bounds-checked,
    /// so a malformed frame is a clean error, never a panic.
    pub fn decode(buf: &[u8]) -> Result<FwdFrame> {
        let bad = || CryptoError::Parameter("malformed forward frame".to_string());
        let (&ty, rest) = buf.split_first().ok_or_else(bad)?;
        // Every frame starts with the 4-byte channel id.
        if rest.len() < 4 {
            return Err(bad());
        }
        let chan = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);
        let rest = &rest[4..];
        match ty {
            F_OPEN => {
                let (&hlen, rest) = rest.split_first().ok_or_else(bad)?;
                let hlen = hlen as usize;
                if rest.len() < hlen + 2 {
                    return Err(bad());
                }
                let host = std::str::from_utf8(&rest[..hlen]).map_err(|_| bad())?.to_string();
                let port = u16::from_be_bytes([rest[hlen], rest[hlen + 1]]);
                Ok(FwdFrame::Open { chan, host, port })
            }
            F_CONNECTED => Ok(FwdFrame::Connected { chan }),
            F_REJECTED => {
                Ok(FwdFrame::Rejected { chan, reason: String::from_utf8_lossy(rest).into_owned() })
            }
            F_DATA => {
                if rest.len() > MAX_FWD_DATA {
                    return Err(CryptoError::Parameter("forward DATA too large".to_string()));
                }
                Ok(FwdFrame::Data { chan, data: rest.to_vec() })
            }
            F_EOF => Ok(FwdFrame::Eof { chan }),
            F_CLOSE => Ok(FwdFrame::Close { chan }),
            _ => Err(CryptoError::Parameter(format!("unknown forward frame type {ty}"))),
        }
    }
}

/// One `-L localport:host:remoteport` request.
#[derive(Debug, Clone)]
pub struct ForwardSpec {
    pub local_port: u16,
    pub host: String,
    pub remote_port: u16,
}

impl ForwardSpec {
    /// Parse `localport:host:remoteport` (host may contain no `:` — IPv6 literals
    /// are not supported in this compact form).
    pub fn parse(s: &str) -> std::result::Result<Self, String> {
        let parts: Vec<&str> = s.splitn(3, ':').collect();
        if parts.len() != 3 {
            return Err(format!("expected localport:host:remoteport, got {s:?}"));
        }
        let local_port: u16 = parts[0].parse().map_err(|_| format!("bad local port {:?}", parts[0]))?;
        let host = parts[1].to_string();
        if host.is_empty() || host.len() > 255 {
            return Err(format!("bad host {host:?}"));
        }
        let remote_port: u16 =
            parts[2].parse().map_err(|_| format!("bad remote port {:?}", parts[2]))?;
        Ok(ForwardSpec { local_port, host, remote_port })
    }
}

/// Messages routed from the demux reader to a single channel's task.
enum Inbound {
    Connected,
    Rejected(String),
    Data(Vec<u8>),
    Eof,
    Close,
}

/// The set of live channels: channel id → sender into that channel's task.
type Registry = Arc<Mutex<HashMap<u32, mpsc::Sender<Inbound>>>>;

/// Pump one connected channel: copy the local TCP socket to/from the multiplexed
/// stream until either side ends, then send `Close` once and deregister.
async fn pump_channel(
    chan: u32,
    tcp: TcpStream,
    frame_tx: mpsc::Sender<FwdFrame>,
    mut in_rx: mpsc::Receiver<Inbound>,
    registry: Registry,
) {
    let (mut rd, mut wr) = tcp.into_split();

    // TCP → multiplexed DATA frames.
    let up_tx = frame_tx.clone();
    let up = tokio::spawn(async move {
        let mut buf = vec![0u8; TCP_READ_BUF];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) => {
                    let _ = up_tx.send(FwdFrame::Eof { chan }).await;
                    break;
                }
                Ok(n) => {
                    if up_tx.send(FwdFrame::Data { chan, data: buf[..n].to_vec() }).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Inbound DATA/EOF/Close → TCP.
    while let Some(msg) = in_rx.recv().await {
        match msg {
            Inbound::Data(d) => {
                if wr.write_all(&d).await.is_err() {
                    break;
                }
            }
            Inbound::Eof => {
                let _ = wr.shutdown().await; // peer is done sending; half-close
            }
            Inbound::Close => break,
            // Connected/Rejected are only meaningful before the pump starts.
            Inbound::Connected | Inbound::Rejected(_) => {}
        }
    }

    up.abort();
    registry.lock().await.remove(&chan);
    let _ = frame_tx.send(FwdFrame::Close { chan }).await;
}

// ===========================================================================
// Client: local-forward listeners → multiplexed channels.
// ===========================================================================

/// Client side (`--forward`): bind each `ForwardSpec`'s local port and forward
/// every accepted connection to the server as a channel. Runs until the secured
/// stream closes or a fatal transport error occurs.
pub async fn run_forward_client<R, W>(
    reader: R,
    writer: W,
    aead_name: &str,
    s2c_key: &[u8],
    c2s_key: &[u8],
    specs: &[ForwardSpec],
) -> Result<()>
where
    R: AsyncReadExt + Unpin + Send + 'static,
    W: AsyncWriteExt + Unpin + Send + 'static,
{
    let (rx_key, tx_key) = role_keys(s2c_key, c2s_key, false);
    let registry: Registry = Arc::new(Mutex::new(HashMap::new()));
    let next_chan = Arc::new(AtomicU32::new(1));

    // Single writer task serializes all outbound frames so the send counter
    // stays consistent across channels.
    let (frame_tx, frame_rx) = mpsc::channel::<FwdFrame>(256);
    let writer_task = spawn_writer(writer, aead_name.to_string(), tx_key.to_vec(), frame_rx);

    // Demux reader: route inbound frames to their channel.
    let reader_task = {
        let registry = registry.clone();
        let aead = aead_name.to_string();
        let rx_key = rx_key.to_vec();
        tokio::spawn(async move {
            demux_reader(reader, &aead, &rx_key, registry, None).await
        })
    };

    // Bind every local listener and accept forever.
    let mut listeners = Vec::new();
    for spec in specs {
        let addr = ("127.0.0.1", spec.local_port);
        let l = TcpListener::bind(addr)
            .await
            .map_err(|e| CryptoError::Parameter(format!("bind 127.0.0.1:{}: {e}", spec.local_port)))?;
        eprintln!(
            "[fwd] listening on 127.0.0.1:{} → {}:{}",
            spec.local_port, spec.host, spec.remote_port
        );
        listeners.push((l, spec.clone()));
    }

    let mut accept_tasks = Vec::new();
    for (listener, spec) in listeners {
        let frame_tx = frame_tx.clone();
        let registry = registry.clone();
        let next_chan = next_chan.clone();
        accept_tasks.push(tokio::spawn(async move {
            loop {
                let (tcp, _peer) = match listener.accept().await {
                    Ok(p) => p,
                    Err(_) => break,
                };
                if registry.lock().await.len() >= MAX_CHANNELS {
                    eprintln!("[fwd] too many open channels; dropping new connection");
                    continue;
                }
                let chan = next_chan.fetch_add(1, Ordering::Relaxed);
                let (in_tx, in_rx) = mpsc::channel::<Inbound>(64);
                registry.lock().await.insert(chan, in_tx);
                // Ask the server to connect onward, then run the channel.
                if frame_tx
                    .send(FwdFrame::Open {
                        chan,
                        host: spec.host.clone(),
                        port: spec.remote_port,
                    })
                    .await
                    .is_err()
                {
                    registry.lock().await.remove(&chan);
                    break;
                }
                let frame_tx = frame_tx.clone();
                let registry = registry.clone();
                tokio::spawn(client_channel(chan, tcp, frame_tx, in_rx, registry));
            }
        }));
    }

    // The session lives as long as the secured stream; when the reader ends
    // (peer closed / error), stop everything.
    let _ = reader_task.await;
    for t in accept_tasks {
        t.abort();
    }
    drop(frame_tx);
    let _ = writer_task.await;
    Ok(())
}

/// Client channel: wait for the server's connect result, then pump if connected.
async fn client_channel(
    chan: u32,
    tcp: TcpStream,
    frame_tx: mpsc::Sender<FwdFrame>,
    mut in_rx: mpsc::Receiver<Inbound>,
    registry: Registry,
) {
    match in_rx.recv().await {
        Some(Inbound::Connected) => {
            pump_channel(chan, tcp, frame_tx, in_rx, registry).await;
        }
        Some(Inbound::Rejected(reason)) => {
            eprintln!("[fwd] channel {chan} rejected: {reason}");
            registry.lock().await.remove(&chan);
            // TCP socket drops here, closing the local connection.
        }
        _ => {
            registry.lock().await.remove(&chan);
        }
    }
}

// ===========================================================================
// Server: accept channel opens, enforce policy, connect onward.
// ===========================================================================

/// Server side (`--serve-forward`): for each `Open`, consult the forward policy
/// and, if allowed, connect onward and bridge the channel. Default deny.
#[allow(clippy::too_many_arguments)]
pub async fn run_forward_server<R, W>(
    reader: R,
    writer: W,
    aead_name: &str,
    s2c_key: &[u8],
    c2s_key: &[u8],
    peer_fp: [u8; 32],
    policy_path: Option<&str>,
    audit_path: Option<&str>,
) -> Result<()>
where
    R: AsyncReadExt + Unpin + Send + 'static,
    W: AsyncWriteExt + Unpin + Send + 'static,
{
    let (rx_key, tx_key) = role_keys(s2c_key, c2s_key, true);

    // Per-fingerprint rate limit before doing any work.
    if rate_limited(&peer_fp) {
        audit_best_effort(audit_path, &peer_fp, "fwd deny: rate limited").await;
        return Err(CryptoError::Parameter("forward: rate limited".into()));
    }

    // Load the policy once per connection (off the runtime thread).
    let policy = match policy_path {
        Some(pp) => {
            let pp = pp.to_string();
            Some(
                tokio::task::spawn_blocking(move || ForwardPolicy::load(&pp))
                    .await
                    .map_err(std::io::Error::other)
                    .map_err(|e| CryptoError::Parameter(format!("load forward policy: {e}")))??,
            )
        }
        None => None,
    };
    let policy = Arc::new(policy);

    let registry: Registry = Arc::new(Mutex::new(HashMap::new()));
    // Bound concurrent channels — including in-flight onward connects — so a flood
    // of OPEN frames cannot exhaust fds/tasks. A permit is held for each channel's
    // whole lifetime.
    let sem = Arc::new(Semaphore::new(MAX_CHANNELS));
    let (frame_tx, frame_rx) = mpsc::channel::<FwdFrame>(256);
    let writer_task = spawn_writer(writer, aead_name.to_string(), tx_key.to_vec(), frame_rx);

    // The server's demux loop also handles Open (client→server only).
    let on_open = {
        let frame_tx = frame_tx.clone();
        let registry = registry.clone();
        let policy = policy.clone();
        let sem = sem.clone();
        let audit_path = audit_path.map(str::to_string);
        Arc::new(move |chan: u32, host: String, port: u16| {
            let frame_tx = frame_tx.clone();
            let registry = registry.clone();
            let policy = policy.clone();
            let sem = sem.clone();
            let audit_path = audit_path.clone();
            tokio::spawn(async move {
                server_open(
                    chan, host, port, peer_fp, policy, sem, audit_path, frame_tx, registry,
                )
                .await;
            });
        })
    };

    let res = demux_reader(reader, aead_name, rx_key, registry.clone(), Some(on_open)).await;
    drop(frame_tx);
    let _ = writer_task.await;
    res
}

/// Server: handle one `Open` — authorize, reserve the channel, connect onward,
/// then bridge. A concurrency permit is acquired before the connect and held for
/// the channel's whole life; the channel id is reserved under the registry lock
/// so a client cannot hijack or duplicate an existing channel.
#[allow(clippy::too_many_arguments)]
async fn server_open(
    chan: u32,
    host: String,
    port: u16,
    peer_fp: [u8; 32],
    policy: Arc<Option<ForwardPolicy>>,
    sem: Arc<Semaphore>,
    audit_path: Option<String>,
    frame_tx: mpsc::Sender<FwdFrame>,
    registry: Registry,
) {
    let reject = |reason: String| {
        let frame_tx = frame_tx.clone();
        async move {
            let _ = frame_tx.send(FwdFrame::Rejected { chan, reason }).await;
        }
    };
    let target = format!("{host}:{port}");

    // Authorize: a policy is required to forward at all (default deny).
    let decision = match policy.as_ref() {
        Some(p) => p.authorize(&peer_fp, &host, port),
        None => Err("no forward policy configured (default deny)".to_string()),
    };
    if let Err(reason) = decision {
        audit_best_effort(audit_path.as_deref(), &peer_fp, &format!("fwd deny {target}: {reason}"))
            .await;
        reject(reason).await;
        return;
    }

    // Bound concurrent channels (incl. in-flight connects): hold a permit for the
    // channel's whole life.
    let _permit: OwnedSemaphorePermit = match sem.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            reject("too many channels".into()).await;
            return;
        }
    };

    // Reserve the channel id under the lock so a malicious client cannot reuse an
    // active id to hijack/overwrite an existing channel's routing.
    let (in_tx, in_rx) = mpsc::channel::<Inbound>(64);
    {
        let mut reg = registry.lock().await;
        if reg.contains_key(&chan) {
            drop(reg);
            reject(format!("channel {chan} already in use")).await;
            return;
        }
        reg.insert(chan, in_tx);
    }
    // From here on, any early return must release the reserved id.
    let release = || async {
        registry.lock().await.remove(&chan);
    };

    // Audit the (authorized) access *before* connecting and fail closed: a
    // missing audit trail must not let us even open the onward TCP connection
    // (no untraced port-scan / connect via a full disk).
    if let Err(e) = audit(audit_path.as_deref(), &peer_fp, &format!("fwd allow {target}")).await {
        release().await;
        reject("audit unavailable".into()).await;
        eprintln!("[fwd] audit write failed, refusing channel {chan}: {e}");
        return;
    }

    // Connect onward.
    let tcp = match TcpStream::connect((host.as_str(), port)).await {
        Ok(s) => s,
        Err(e) => {
            audit_best_effort(audit_path.as_deref(), &peer_fp, &format!("fwd fail {target}: {e}"))
                .await;
            release().await;
            reject(format!("connect {target}: {e}")).await;
            return;
        }
    };

    if frame_tx.send(FwdFrame::Connected { chan }).await.is_err() {
        release().await;
        return;
    }
    pump_channel(chan, tcp, frame_tx, in_rx, registry).await;
    // `_permit` is held until pump_channel returns, then released here.
}

// ===========================================================================
// Shared writer + demux reader.
// ===========================================================================

/// Spawn the single task that serializes every outbound [`FwdFrame`] into AEAD
/// packets on `writer`, keeping the per-direction counter monotonic.
fn spawn_writer<W>(
    writer: W,
    aead_name: String,
    tx_key: Vec<u8>,
    mut frame_rx: mpsc::Receiver<FwdFrame>,
) -> tokio::task::JoinHandle<()>
where
    W: AsyncWriteExt + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut writer = writer;
        let tx_key = zeroize::Zeroizing::new(tx_key);
        let mut ctr = 0u64;
        while let Some(f) = frame_rx.recv().await {
            let pt = zeroize::Zeroizing::new(f.encode());
            if send_packet(&mut writer, &aead_name, &tx_key, &mut ctr, &pt).await.is_err() {
                break;
            }
        }
    })
}

/// Read AEAD packets, decode [`FwdFrame`]s, and route them. `on_open` is `Some`
/// on the server (handles client-initiated `Open`); `None` on the client (an
/// `Open` from the server is a protocol error and is ignored).
async fn demux_reader<R>(
    mut reader: R,
    aead_name: &str,
    rx_key: &[u8],
    registry: Registry,
    on_open: Option<Arc<dyn Fn(u32, String, u16) + Send + Sync>>,
) -> Result<()>
where
    R: AsyncReadExt + Unpin + Send,
{
    let mut ctr = 0u64;
    loop {
        let pt = match recv_packet(&mut reader, aead_name, rx_key, &mut ctr).await? {
            Some(p) => p,
            None => break, // clean close
        };
        let frame = FwdFrame::decode(&pt)?;
        match frame {
            FwdFrame::Open { chan, host, port } => {
                if let Some(cb) = &on_open {
                    cb(chan, host, port);
                }
                // Client never expects Open; silently ignore.
            }
            FwdFrame::Connected { chan } => route(&registry, chan, Inbound::Connected).await,
            FwdFrame::Rejected { chan, reason } => {
                route(&registry, chan, Inbound::Rejected(reason)).await
            }
            FwdFrame::Data { chan, data } => route(&registry, chan, Inbound::Data(data)).await,
            FwdFrame::Eof { chan } => route(&registry, chan, Inbound::Eof).await,
            FwdFrame::Close { chan } => route(&registry, chan, Inbound::Close).await,
        }
    }
    Ok(())
}

/// Deliver `msg` to channel `chan` if it is still live (drop otherwise).
async fn route(registry: &Registry, chan: u32, msg: Inbound) {
    let tx = registry.lock().await.get(&chan).cloned();
    if let Some(tx) = tx {
        let _ = tx.send(msg).await;
    }
}

// ===========================================================================
// Forward policy: per-fingerprint allowed targets. Default deny.
// ===========================================================================

/// One allowed target pattern: host (`*` = any) and port (`None` = any).
#[derive(Debug, Clone)]
struct TargetPattern {
    host: String, // "*" or an exact host/ip
    port: Option<u16>,
}

impl TargetPattern {
    fn matches(&self, host: &str, port: u16) -> bool {
        (self.host == "*" || self.host.eq_ignore_ascii_case(host))
            && self.port.is_none_or(|p| p == port)
    }
}

/// `fingerprint → allowed targets`. A fingerprint that is absent, or present with
/// no matching target, is denied.
pub struct ForwardPolicy {
    entries: HashMap<[u8; 32], Vec<TargetPattern>>,
}

impl ForwardPolicy {
    /// Parse a policy file. Each non-comment line is:
    /// `<sha3-256 fp hex>  allow="host:port, host2:*, *:443"`.
    /// A malformed `allow=` list is a hard error (never silently unrestricted).
    pub fn load(path: &str) -> std::io::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let mut entries: HashMap<[u8; 32], Vec<TargetPattern>> = HashMap::new();
        for (lineno, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (fp_hex_str, rest) = match line.split_once(char::is_whitespace) {
                Some((a, b)) => (a, b.trim()),
                None => (line, ""),
            };
            let fp = parse_fp_hex(fp_hex_str).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("line {}: bad fingerprint", lineno + 1),
                )
            })?;
            let (allow_val, _, _) =
                crate::shell::extract_quoted_span(rest, "allow=").ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("line {}: missing allow=\"...\"", lineno + 1),
                    )
                })?;
            let mut patterns = Vec::new();
            for item in allow_val.split(',') {
                let item = item.trim();
                if item.is_empty() {
                    continue;
                }
                let (h, p) = item.rsplit_once(':').ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("line {}: target {item:?} is not host:port", lineno + 1),
                    )
                })?;
                let port = if p == "*" {
                    None
                } else {
                    Some(p.parse::<u16>().map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("line {}: bad port {p:?}", lineno + 1),
                        )
                    })?)
                };
                if h.is_empty() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("line {}: empty host in {item:?}", lineno + 1),
                    ));
                }
                patterns.push(TargetPattern { host: h.to_string(), port });
            }
            if patterns.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("line {}: allow list is empty", lineno + 1),
                ));
            }
            entries.entry(fp).or_default().extend(patterns);
        }
        Ok(ForwardPolicy { entries })
    }

    /// Authorize forwarding to `host:port` for `fp`. Default deny.
    fn authorize(&self, fp: &[u8; 32], host: &str, port: u16) -> std::result::Result<(), String> {
        match self.entries.get(fp) {
            None => Err(format!("fingerprint {} not in forward policy", &fp_hex(fp)[..16])),
            Some(pats) => {
                if pats.iter().any(|p| p.matches(host, port)) {
                    Ok(())
                } else {
                    Err(format!("{host}:{port} not in this fingerprint's allow list"))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let frames = vec![
            FwdFrame::Open { chan: 7, host: "db.internal".into(), port: 5432 },
            FwdFrame::Connected { chan: 7 },
            FwdFrame::Rejected { chan: 9, reason: "denied".into() },
            FwdFrame::Data { chan: 7, data: vec![0, 1, 2, 250, 255] },
            FwdFrame::Eof { chan: 7 },
            FwdFrame::Close { chan: 7 },
        ];
        for f in frames {
            let enc = f.encode();
            assert_eq!(FwdFrame::decode(&enc).unwrap(), f);
        }
    }

    #[test]
    fn decode_rejects_truncated() {
        assert!(FwdFrame::decode(&[]).is_err());
        assert!(FwdFrame::decode(&[F_DATA, 0, 0]).is_err()); // chan id truncated
        assert!(FwdFrame::decode(&[F_OPEN, 0, 0, 0, 1, 5, b'a']).is_err()); // host short
        assert!(FwdFrame::decode(&[0xFF, 0, 0, 0, 1]).is_err()); // unknown type
    }

    #[test]
    fn spec_parse() {
        let s = ForwardSpec::parse("8080:db.internal:5432").unwrap();
        assert_eq!(s.local_port, 8080);
        assert_eq!(s.host, "db.internal");
        assert_eq!(s.remote_port, 5432);
        assert!(ForwardSpec::parse("8080:db.internal").is_err());
        assert!(ForwardSpec::parse("notaport:h:5432").is_err());
    }

    #[test]
    fn policy_matches_and_denies() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("nkfwdpol_{}.txt", std::process::id()));
        let fp = [0xabu8; 32];
        let fph: String = fp.iter().map(|b| format!("{b:02x}")).collect();
        std::fs::write(&path, format!("{fph}  allow=\"db.internal:5432, *:443, web:*\"\n"))
            .unwrap();
        let pol = ForwardPolicy::load(path.to_str().unwrap()).unwrap();
        assert!(pol.authorize(&fp, "db.internal", 5432).is_ok());
        assert!(pol.authorize(&fp, "anything", 443).is_ok());
        assert!(pol.authorize(&fp, "web", 9999).is_ok());
        assert!(pol.authorize(&fp, "db.internal", 5433).is_err()); // wrong port
        assert!(pol.authorize(&fp, "other", 22).is_err()); // not listed
        assert!(pol.authorize(&[0u8; 32], "db.internal", 5432).is_err()); // unknown fp
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn policy_malformed_is_error() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("nkfwdpol_bad_{}.txt", std::process::id()));
        let fph = "ab".repeat(32);
        // missing allow="..."
        std::fs::write(&path, format!("{fph}  user=root\n")).unwrap();
        assert!(ForwardPolicy::load(path.to_str().unwrap()).is_err());
        let _ = std::fs::remove_file(&path);
    }
}
