/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

//! P2P port forwarding (bastion-less `ssh -L` / `-R`) over `ALPN_FWD` — see
//! `P2P_SHELL_DESIGN.md`.
//!
//! A single PQC-authenticated, AEAD-secured connection (the same handshake and
//! counter-nonce packet layer as the shell, reused via
//! [`crate::shell::send_packet`] / [`crate::shell::recv_packet`]) carries many
//! independent TCP streams, each a **logical channel** identified by a `u32`.
//!
//! Two directions, symmetric over the wire:
//! - **Local forward (`-L`)**: the *client* binds a local port; for every accepted
//!   connection it asks the server to connect onward to `host:port`.
//! - **Remote forward (`-R`)**: the *client* asks the server to bind a port; for
//!   every connection the server accepts there, it asks the *client* to connect to
//!   `host:port` on the client's side.
//!
//! In both, one side is the **opener** (accepts a TCP connection, sends `Open`)
//! and the other is the **connector** (receives `Open`, connects onward, sends
//! `Connected`). Channel ids are partitioned by originator (client: `1..`, server:
//! `0x8000_0000..`) so the two ends never collide.
//!
//! **Authorization (default deny).** The server's per-fingerprint
//! [`ForwardPolicy`] gates *both* which targets `-L` may reach (`allow=`) and which
//! ports `-R` may bind (`bind=`); every decision is audited. The `-R` client also
//! refuses any server `Open` whose `host:port` is not one it explicitly requested
//! (a malicious server cannot make the client dial arbitrary addresses).
//!
//! **Isolation & limits.** Every client gets its own connection, demultiplexer,
//! and pool of at most [`MAX_CHANNELS`] channels (a semaphore bounds concurrent
//! channels including in-flight connects), so one client cannot exhaust the server
//! or affect another. Remote-forward listeners bind `127.0.0.1` on the server
//! only (no `GatewayPorts`), so a forwarded port is never exposed off-box.
//!
//! **Known v1 limitation — no per-channel flow control.** Within *one* client's
//! connection the demultiplexer applies backpressure globally: a single stuck
//! channel head-of-line-blocks that client's other channels. Bounded and confined
//! to the misbehaving client's own connection; per-channel credit windows are the
//! planned hardening.
//!
//! **Target trust (SSRF).** The server connects to whatever `host:port` its
//! operator-defined policy allows; reaching internal/loopback addresses is the
//! intended use, so there is no IP filtering. Prefer **IP literals** over
//! hostnames you do not control the DNS for.

use crate::error::{CryptoError, Result};
use crate::shell::{
    audit, audit_best_effort, fp_hex, parse_fp_hex, recv_packet, role_keys,
    send_packet,
};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex, Semaphore};
use tokio::task::JoinHandle;

const F_OPEN: u8 = 0x01;
const F_CONNECTED: u8 = 0x02;
const F_REJECTED: u8 = 0x03;
const F_DATA: u8 = 0x04;
const F_EOF: u8 = 0x05;
const F_CLOSE: u8 = 0x06;
const F_BINDREQ: u8 = 0x07;
const F_BINDOK: u8 = 0x08;
const F_BINDERR: u8 = 0x09;
const F_WINADJ: u8 = 0x0a;

/// Largest single forward DATA payload; bounds the per-frame allocation and keeps
/// one channel from monopolizing the shared stream.
const MAX_FWD_DATA: usize = 64 * 1024;
const TCP_READ_BUF: usize = 32 * 1024;
/// Cap on simultaneously open channels per connection (DoS bound).
const MAX_CHANNELS: usize = 256;
/// Per-channel, per-direction flow-control window (bytes). A sender may have at
/// most this many bytes in flight before the receiver acknowledges consumption
/// via [`FwdFrame::WindowAdjust`]; the receiver enforces it, so a stuck channel
/// buffers at most `WINDOW` bytes and never head-of-line-blocks other channels.
/// Per-connection worst-case inbound buffering is `WINDOW * MAX_CHANNELS`.
const WINDOW: usize = 256 * 1024;
/// Hard cap on un-drained inbound messages per channel. The byte `WINDOW` keeps a
/// well-behaved peer far below this (frames are read in `TCP_READ_BUF` chunks); it
/// only fires on a peer that floods tiny data or control frames in violation of
/// flow control, and then the connection is torn down.
const MAX_INFLIGHT_MSGS: usize = 1024;
/// First channel id for each originator; the high bit keeps the two ranges apart.
const CLIENT_CHAN_BASE: u32 = 1;
const SERVER_CHAN_BASE: u32 = 0x8000_0000;

/// One multiplexed control/data frame on `ALPN_FWD`. Every frame begins with a
/// 4-byte id: a channel id for stream frames, or a request id for bind frames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FwdFrame {
    /// Opener → connector: open a channel forwarding to `host:port`.
    Open { chan: u32, host: String, port: u16 },
    /// Connector → opener: the onward TCP connect succeeded.
    Connected { chan: u32 },
    /// Connector → opener: the onward connect was denied or failed.
    Rejected { chan: u32, reason: String },
    /// Either direction: stream bytes for `chan`.
    Data { chan: u32, data: Vec<u8> },
    /// Either direction: no more data will be sent on `chan` (half-close).
    Eof { chan: u32 },
    /// Either direction: tear down `chan` completely.
    Close { chan: u32 },
    /// Either direction: the receiver consumed `bytes` on `chan`, replenishing the
    /// sender's flow-control credit by that much.
    WindowAdjust { chan: u32, bytes: u32 },
    /// Client → server (`-R`): listen on `bind_port`; forward each connection to
    /// `host:port` on the client's side.
    BindRequest { req: u32, bind_port: u16, host: String, port: u16 },
    /// Server → client: the requested remote bind succeeded.
    BindOk { req: u32 },
    /// Server → client: the requested remote bind was denied or failed.
    BindErr { req: u32, reason: String },
}

impl FwdFrame {
    /// Serialize to the plaintext that goes inside one AEAD packet.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::new();
        // Helper: push a host with a 1-byte length, clamped so an over-long host
        // can never wrap the length and emit a corrupt frame.
        let push_host = |v: &mut Vec<u8>, host: &str| {
            let hlen = host.len().min(255);
            v.push(hlen as u8);
            v.extend_from_slice(&host.as_bytes()[..hlen]);
        };
        match self {
            FwdFrame::Open { chan, host, port } => {
                v.push(F_OPEN);
                v.extend_from_slice(&chan.to_be_bytes());
                push_host(&mut v, host);
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
            FwdFrame::WindowAdjust { chan, bytes } => {
                v.push(F_WINADJ);
                v.extend_from_slice(&chan.to_be_bytes());
                v.extend_from_slice(&bytes.to_be_bytes());
            }
            FwdFrame::BindRequest { req, bind_port, host, port } => {
                v.push(F_BINDREQ);
                v.extend_from_slice(&req.to_be_bytes());
                v.extend_from_slice(&bind_port.to_be_bytes());
                push_host(&mut v, host);
                v.extend_from_slice(&port.to_be_bytes());
            }
            FwdFrame::BindOk { req } => {
                v.push(F_BINDOK);
                v.extend_from_slice(&req.to_be_bytes());
            }
            FwdFrame::BindErr { req, reason } => {
                v.push(F_BINDERR);
                v.extend_from_slice(&req.to_be_bytes());
                v.extend_from_slice(reason.as_bytes());
            }
        }
        v
    }

    /// Parse a frame from one packet's plaintext. Every length is bounds-checked,
    /// so a malformed frame is a clean error, never a panic.
    pub fn decode(buf: &[u8]) -> Result<FwdFrame> {
        let bad = || CryptoError::Parameter("malformed forward frame".to_string());
        let (&ty, rest) = buf.split_first().ok_or_else(bad)?;
        // Every frame begins with the 4-byte id (channel or request).
        if rest.len() < 4 {
            return Err(bad());
        }
        let id = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);
        let rest = &rest[4..];
        // Parse a `host:port` tail (1-byte host len ‖ host ‖ u16 port).
        let parse_host_port = |rest: &[u8]| -> Result<(String, u16)> {
            let (&hlen, rest) = rest.split_first().ok_or_else(bad)?;
            let hlen = hlen as usize;
            if rest.len() < hlen + 2 {
                return Err(bad());
            }
            let host = std::str::from_utf8(&rest[..hlen]).map_err(|_| bad())?.to_string();
            let port = u16::from_be_bytes([rest[hlen], rest[hlen + 1]]);
            Ok((host, port))
        };
        match ty {
            F_OPEN => {
                let (host, port) = parse_host_port(rest)?;
                Ok(FwdFrame::Open { chan: id, host, port })
            }
            F_CONNECTED => Ok(FwdFrame::Connected { chan: id }),
            F_REJECTED => {
                // Peer-authored and printed by `open_from_tcp`, which runs on
                // BOTH roles — so on the `-R` path an authenticated forward
                // client drives this onto the server operator's console or
                // audit log. Sanitized and bounded at decode (the frame body
                // may be up to the 128 KiB packet cap).
                let reason = crate::utils::sanitize_for_terminal_bounded(
                    &String::from_utf8_lossy(rest),
                    256,
                );
                Ok(FwdFrame::Rejected { chan: id, reason })
            }
            F_DATA => {
                if rest.len() > MAX_FWD_DATA {
                    return Err(CryptoError::Parameter("forward DATA too large".to_string()));
                }
                Ok(FwdFrame::Data { chan: id, data: rest.to_vec() })
            }
            F_EOF => Ok(FwdFrame::Eof { chan: id }),
            F_CLOSE => Ok(FwdFrame::Close { chan: id }),
            F_WINADJ => {
                if rest.len() < 4 {
                    return Err(bad());
                }
                let bytes = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);
                Ok(FwdFrame::WindowAdjust { chan: id, bytes })
            }
            F_BINDREQ => {
                if rest.len() < 2 {
                    return Err(bad());
                }
                let bind_port = u16::from_be_bytes([rest[0], rest[1]]);
                let (host, port) = parse_host_port(&rest[2..])?;
                Ok(FwdFrame::BindRequest { req: id, bind_port, host, port })
            }
            F_BINDOK => Ok(FwdFrame::BindOk { req: id }),
            F_BINDERR => {
                // Same treatment as `Rejected`: printed at forward.rs:708.
                let reason = crate::utils::sanitize_for_terminal_bounded(
                    &String::from_utf8_lossy(rest),
                    256,
                );
                Ok(FwdFrame::BindErr { req: id, reason })
            }
            _ => Err(CryptoError::Parameter(format!("unknown forward frame type {ty}"))),
        }
    }
}

/// One forward request from the command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardSpec {
    /// `-L localport:host:remoteport`: bind `local_port` locally, server connects
    /// to `host:remote_port`.
    Local { local_port: u16, host: String, remote_port: u16 },
    /// `-R bindport:host:destport`: server binds `bind_port`, client connects to
    /// `host:dest_port`.
    Remote { bind_port: u16, host: String, dest_port: u16 },
}

impl ForwardSpec {
    /// Parse a local forward `localport:host:remoteport`.
    pub fn parse_local(s: &str) -> std::result::Result<Self, String> {
        let (a, host, b) = Self::split3(s)?;
        Ok(ForwardSpec::Local { local_port: a, host, remote_port: b })
    }

    /// Parse a remote forward `bindport:host:destport`.
    pub fn parse_remote(s: &str) -> std::result::Result<Self, String> {
        let (a, host, b) = Self::split3(s)?;
        Ok(ForwardSpec::Remote { bind_port: a, host, dest_port: b })
    }

    fn split3(s: &str) -> std::result::Result<(u16, String, u16), String> {
        let parts: Vec<&str> = s.splitn(3, ':').collect();
        if parts.len() != 3 {
            return Err(format!("expected port:host:port, got {s:?}"));
        }
        let p1: u16 = parts[0].parse().map_err(|_| format!("bad port {:?}", parts[0]))?;
        let host = parts[1].to_string();
        if host.is_empty() || host.len() > 255 {
            return Err(format!("bad host {host:?}"));
        }
        let p2: u16 = parts[2].parse().map_err(|_| format!("bad port {:?}", parts[2]))?;
        Ok((p1, host, p2))
    }
}

/// Messages routed from the demux reader to a single channel's task.
enum Inbound {
    Connected,
    Rejected(String),
    Data(Vec<u8>),
    /// The peer consumed `bytes` of our outbound data: replenish send credit.
    WindowAdjust(u32),
    Eof,
    Close,
}

/// One live channel as seen by the demultiplexer: where to deliver inbound
/// messages, plus the remaining receive-window budget it enforces.
#[derive(Clone)]
struct Chan {
    /// Bounded so a flood cannot grow it without bound; the demux `try_send`s and
    /// treats a full queue as a flow-control violation (connection torn down).
    in_tx: mpsc::Sender<Inbound>,
    /// Bytes the peer may still send us before it must wait for a `WindowAdjust`.
    /// Decremented by the demux on inbound `Data`, replenished by the channel task
    /// as it drains to the local socket. Never legitimately negative.
    recv_window: Arc<std::sync::atomic::AtomicI64>,
}

/// The set of live channels: channel id → handle.
type Registry = Arc<Mutex<HashMap<u32, Chan>>>;

/// Pump one connected channel: copy the local TCP socket to/from the multiplexed
/// stream until either side ends, then send `Close` once and deregister.
///
/// Flow control: our `up` reader spends from a `credit` semaphore (initially
/// [`WINDOW`]) before emitting `Data`, and refills it on the peer's
/// `WindowAdjust`; symmetrically, after writing inbound `Data` to the socket we
/// bump `recv_window` and send the peer a `WindowAdjust`. This bounds in-flight
/// bytes per direction so a stuck socket never blocks the shared demultiplexer.
async fn pump_channel(
    chan: u32,
    tcp: TcpStream,
    frame_tx: mpsc::Sender<FwdFrame>,
    mut in_rx: mpsc::Receiver<Inbound>,
    registry: Registry,
    recv_window: Arc<std::sync::atomic::AtomicI64>,
) {
    use std::sync::atomic::Ordering;
    let (mut rd, mut wr) = tcp.into_split();

    let credit = Arc::new(Semaphore::new(WINDOW));
    let up_tx = frame_tx.clone();
    let up_credit = credit.clone();
    let up = tokio::spawn(async move {
        let mut buf = vec![0u8; TCP_READ_BUF];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) => {
                    let _ = up_tx.send(FwdFrame::Eof { chan }).await;
                    break;
                }
                Ok(n) => {
                    // Spend `n` bytes of send credit (waits if the peer's window is
                    // full); `close()` on teardown unblocks this.
                    match up_credit.acquire_many(n as u32).await {
                        Ok(p) => p.forget(),
                        Err(_) => break,
                    }
                    if up_tx.send(FwdFrame::Data { chan, data: buf[..n].to_vec() }).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    while let Some(msg) = in_rx.recv().await {
        match msg {
            Inbound::Data(d) => {
                let n = d.len();
                if wr.write_all(&d).await.is_err() {
                    break;
                }
                // Consumed `n` bytes: give the budget back and tell the peer.
                recv_window.fetch_add(n as i64, Ordering::SeqCst);
                if frame_tx.send(FwdFrame::WindowAdjust { chan, bytes: n as u32 }).await.is_err() {
                    break;
                }
            }
            Inbound::WindowAdjust(n) => {
                // Clamp so a malicious/oversized adjustment can never push credit
                // above WINDOW (which would bypass flow control or overflow the
                // semaphore's permit cap and panic). Only this task adds permits
                // and the reader only spends them, so `available_permits` is a safe
                // upper bound here.
                let add = (n as usize).min(WINDOW.saturating_sub(credit.available_permits()));
                if add > 0 {
                    credit.add_permits(add);
                }
            }
            Inbound::Eof => {
                let _ = wr.shutdown().await;
            }
            Inbound::Close => break,
            Inbound::Connected | Inbound::Rejected(_) => {}
        }
    }

    up.abort();
    credit.close(); // unblock the reader if it is waiting on credit
    registry.lock().await.remove(&chan);
    let _ = frame_tx.send(FwdFrame::Close { chan }).await;
}

/// Role-specific state and authorization for one endpoint of a forward session.
enum Role {
    /// Forward client: validates server `Open`s against the `-R` destinations it
    /// actually requested.
    Client { remote_dests: HashSet<(String, u16)> },
    /// Forward server: authorizes `-L` targets and `-R` binds against the policy.
    Server { peer_fp: [u8; 32], policy: Arc<Option<ForwardPolicy>>, audit_path: Option<String> },
}

/// Shared per-connection state driving the multiplexer.
struct Endpoint {
    frame_tx: mpsc::Sender<FwdFrame>,
    registry: Registry,
    sem: Arc<Semaphore>,
    next_chan: AtomicU32,
    role: Role,
    /// Server `-R` bind listener tasks, aborted when the connection ends.
    bind_tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl Endpoint {
    fn alloc_chan(&self) -> u32 {
        self.next_chan.fetch_add(1, Ordering::Relaxed)
    }

    async fn reject(&self, chan: u32, reason: String) {
        let _ = self.frame_tx.send(FwdFrame::Rejected { chan, reason }).await;
    }

    /// Opener side: a local TCP connection was accepted; ask the peer to connect
    /// to `host:port` and bridge. Allocates the channel id from our range.
    async fn open_from_tcp(self: Arc<Self>, tcp: TcpStream, host: String, port: u16) {
        let permit = match self.sem.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                eprintln!("[fwd] too many channels; dropping connection");
                return;
            }
        };
        let chan = self.alloc_chan();
        let (in_tx, mut in_rx) = mpsc::channel::<Inbound>(MAX_INFLIGHT_MSGS);
        let recv_window = Arc::new(std::sync::atomic::AtomicI64::new(WINDOW as i64));
        self.registry.lock().await.insert(chan, Chan { in_tx, recv_window: recv_window.clone() });
        if self.frame_tx.send(FwdFrame::Open { chan, host, port }).await.is_err() {
            self.registry.lock().await.remove(&chan);
            return;
        }
        // Wait for the connector's verdict, then pump or clean up.
        match in_rx.recv().await {
            Some(Inbound::Connected) => {
                pump_channel(
                    chan, tcp, self.frame_tx.clone(), in_rx, self.registry.clone(), recv_window,
                )
                .await;
            }
            Some(Inbound::Rejected(reason)) => {
                eprintln!("[fwd] channel {chan} rejected: {reason}");
                self.registry.lock().await.remove(&chan);
            }
            _ => {
                self.registry.lock().await.remove(&chan);
            }
        }
        drop(permit);
    }

    /// Connector side: an `Open` arrived; authorize, connect to `host:port`, and
    /// bridge. The channel id was chosen by the opener (the other range).
    async fn handle_open(self: Arc<Self>, chan: u32, host: String, port: u16) {
        let target = format!("{host}:{port}");

        // The peer may only open channels in *its* id range; otherwise a peer
        // could pre-register a channel in our opener range and have our own
        // `open_from_tcp` later overwrite/collide with it (cross-channel mixing).
        let peer_range_ok = match &self.role {
            Role::Client { .. } => chan >= SERVER_CHAN_BASE, // server-originated
            Role::Server { .. } => chan < SERVER_CHAN_BASE,  // client-originated
        };
        if !peer_range_ok {
            self.reject(chan, "channel id out of peer range".into()).await;
            return;
        }

        // Authorize per role.
        let (audit_path, allow_audit) = match &self.role {
            Role::Client { remote_dests } => {
                if !remote_dests.contains(&(host.to_ascii_lowercase(), port)) {
                    // A server must never make the client dial something it did not
                    // ask to forward.
                    self.reject(chan, "destination not requested by client".into()).await;
                    return;
                }
                (None, None)
            }
            Role::Server { peer_fp, policy, audit_path } => {
                let decision = match policy.as_ref() {
                    Some(p) => p.authorize_target(peer_fp, &host, port),
                    None => Err("no forward policy configured (default deny)".to_string()),
                };
                if let Err(reason) = decision {
                    audit_best_effort(
                        audit_path.as_deref(),
                        peer_fp,
                        &format!("fwd deny {target}: {reason}"),
                    )
                    .await;
                    self.reject(chan, reason).await;
                    return;
                }
                (audit_path.clone(), Some(*peer_fp))
            }
        };

        let permit = match self.sem.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                self.reject(chan, "too many channels".into()).await;
                return;
            }
        };

        // Reserve the channel id under the lock so a peer cannot hijack/duplicate
        // an active channel (the opener controls the id).
        let (in_tx, in_rx) = mpsc::channel::<Inbound>(MAX_INFLIGHT_MSGS);
        let recv_window = Arc::new(std::sync::atomic::AtomicI64::new(WINDOW as i64));
        {
            let mut reg = self.registry.lock().await;
            if reg.contains_key(&chan) {
                drop(reg);
                self.reject(chan, format!("channel {chan} already in use")).await;
                return;
            }
            reg.insert(chan, Chan { in_tx, recv_window: recv_window.clone() });
        }

        // Server: audit the authorized access *before* connecting, fail-closed.
        if let (Some(fp), Some(ap)) = (allow_audit, audit_path.as_deref()) {
            if let Err(e) = audit(Some(ap), &fp, &format!("fwd allow {target}")).await {
                self.registry.lock().await.remove(&chan);
                self.reject(chan, "audit unavailable".into()).await;
                eprintln!("[fwd] audit write failed, refusing channel {chan}: {e}");
                return;
            }
        }

        let tcp = match TcpStream::connect((host.as_str(), port)).await {
            Ok(s) => s,
            Err(e) => {
                if let Some(fp) = allow_audit {
                    audit_best_effort(audit_path.as_deref(), &fp, &format!("fwd fail {target}: {e}"))
                        .await;
                }
                self.registry.lock().await.remove(&chan);
                self.reject(chan, format!("connect {target}: {e}")).await;
                return;
            }
        };
        if self.frame_tx.send(FwdFrame::Connected { chan }).await.is_err() {
            self.registry.lock().await.remove(&chan);
            return;
        }
        pump_channel(chan, tcp, self.frame_tx.clone(), in_rx, self.registry.clone(), recv_window)
            .await;
        drop(permit);
    }

    /// Server side: a client asked us to bind `bind_port` and forward to its
    /// `host:port`. Authorize against the policy, bind `127.0.0.1`, and accept.
    async fn handle_bind_request(self: Arc<Self>, req: u32, bind_port: u16, host: String, port: u16) {
        let Role::Server { peer_fp, policy, audit_path } = &self.role else {
            // A client must never receive a BindRequest.
            let _ = self.frame_tx.send(FwdFrame::BindErr { req, reason: "not a server".into() }).await;
            return;
        };
        let allowed = match policy.as_ref() {
            Some(p) => p.authorize_bind(peer_fp, bind_port),
            None => Err("no forward policy configured (default deny)".to_string()),
        };
        if let Err(reason) = allowed {
            audit_best_effort(audit_path.as_deref(), peer_fp, &format!("fwd bind deny {bind_port}: {reason}"))
                .await;
            let _ = self.frame_tx.send(FwdFrame::BindErr { req, reason }).await;
            return;
        }
        // Bind 127.0.0.1 only: a forwarded port is never exposed off the server.
        let listener = match TcpListener::bind(("127.0.0.1", bind_port)).await {
            Ok(l) => l,
            Err(e) => {
                let _ = self
                    .frame_tx
                    .send(FwdFrame::BindErr { req, reason: format!("bind {bind_port}: {e}") })
                    .await;
                return;
            }
        };
        audit_best_effort(audit_path.as_deref(), peer_fp, &format!("fwd bind allow {bind_port} -> {host}:{port}"))
            .await;
        let _ = self.frame_tx.send(FwdFrame::BindOk { req }).await;

        // Accept loop: each connection becomes a channel the client connects back.
        let ep = self.clone();
        let task = tokio::spawn(async move {
            loop {
                let (tcp, _peer) = match listener.accept().await {
                    Ok(p) => p,
                    Err(_) => break,
                };
                tokio::spawn(ep.clone().open_from_tcp(tcp, host.clone(), port));
            }
        });
        self.bind_tasks.lock().await.push(task);
    }

    /// Deliver `msg` to channel `chan` if it is still live. Uses `try_send`, so the
    /// demultiplexer never blocks on a slow channel. Inbound `Data` is charged
    /// against the channel's receive window first; a peer that overruns the byte
    /// window it was granted, or that floods past the bounded queue, is a
    /// flow-control violation that tears the connection down (a well-behaved peer,
    /// gated by its send credit, never reaches either bound).
    async fn route(&self, chan: u32, msg: Inbound) -> Result<()> {
        use std::sync::atomic::Ordering;
        let h = match self.registry.lock().await.get(&chan) {
            Some(h) => h.clone(),
            None => return Ok(()), // unknown/closed channel: drop
        };
        if let Inbound::Data(d) = &msg {
            let remaining = h.recv_window.fetch_sub(d.len() as i64, Ordering::SeqCst) - d.len() as i64;
            if remaining < 0 {
                return Err(CryptoError::Parameter(format!(
                    "channel {chan} exceeded its receive window"
                )));
            }
        }
        match h.in_tx.try_send(msg) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => Ok(()), // channel gone: drop
            Err(mpsc::error::TrySendError::Full(_)) => Err(CryptoError::Parameter(format!(
                "channel {chan} inbound queue overflow (flow-control violation)"
            ))),
        }
    }
}

/// Spawn the single task that serializes every outbound [`FwdFrame`] into AEAD
/// packets on `writer`, keeping the per-direction counter monotonic.
fn spawn_writer<W>(
    writer: W,
    aead_name: String,
    tx_key: Vec<u8>,
    mut frame_rx: mpsc::Receiver<FwdFrame>,
) -> JoinHandle<()>
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

/// Read AEAD packets, decode [`FwdFrame`]s, and dispatch them via `endpoint`.
async fn demux_reader<R>(
    mut reader: R,
    aead_name: &str,
    rx_key: &[u8],
    endpoint: Arc<Endpoint>,
) -> Result<()>
where
    R: AsyncReadExt + Unpin + Send,
{
    let mut ctr = 0u64;
    loop {
        let pt = match recv_packet(&mut reader, aead_name, rx_key, &mut ctr).await? {
            Some(p) => p,
            None => break,
        };
        match FwdFrame::decode(&pt)? {
            FwdFrame::Open { chan, host, port } => {
                tokio::spawn(endpoint.clone().handle_open(chan, host, port));
            }
            FwdFrame::BindRequest { req, bind_port, host, port } => {
                // Await inline (not spawn) so the listener's accept task is
                // recorded in `bind_tasks` before the demux can return; otherwise a
                // disconnect right after BindRequest could race teardown and leave
                // a zombie listener holding the port. Binding is fast and the
                // accept loop itself runs on its own task, so this does not block.
                endpoint.clone().handle_bind_request(req, bind_port, host, port).await;
            }
            FwdFrame::Connected { chan } => endpoint.route(chan, Inbound::Connected).await?,
            FwdFrame::Rejected { chan, reason } => {
                endpoint.route(chan, Inbound::Rejected(reason)).await?
            }
            FwdFrame::Data { chan, data } => endpoint.route(chan, Inbound::Data(data)).await?,
            FwdFrame::WindowAdjust { chan, bytes } => {
                endpoint.route(chan, Inbound::WindowAdjust(bytes)).await?
            }
            FwdFrame::Eof { chan } => endpoint.route(chan, Inbound::Eof).await?,
            FwdFrame::Close { chan } => endpoint.route(chan, Inbound::Close).await?,
            FwdFrame::BindOk { req } => eprintln!("[fwd] remote bind #{req} established"),
            FwdFrame::BindErr { req, reason } => {
                eprintln!("[fwd] remote bind #{req} failed: {reason}")
            }
        }
    }
    Ok(())
}

// ===========================================================================
// Client
// ===========================================================================

/// Client side (`--forward` / `--remote-forward`): set up local listeners for
/// `-L` specs and request remote binds for `-R` specs, then multiplex. Runs until
/// the secured stream closes.
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

    // The client only connects to `-R` destinations it explicitly requested.
    // Hosts are compared case-insensitively (lowercased) so a benign case change
    // in round-tripping never rejects a legitimate destination.
    let remote_dests: HashSet<(String, u16)> = specs
        .iter()
        .filter_map(|s| match s {
            ForwardSpec::Remote { host, dest_port, .. } => {
                Some((host.to_ascii_lowercase(), *dest_port))
            }
            _ => None,
        })
        .collect();

    let (frame_tx, frame_rx) = mpsc::channel::<FwdFrame>(256);
    let writer_task = spawn_writer(writer, aead_name.to_string(), tx_key.to_vec(), frame_rx);

    let endpoint = Arc::new(Endpoint {
        frame_tx: frame_tx.clone(),
        registry: Arc::new(Mutex::new(HashMap::new())),
        sem: Arc::new(Semaphore::new(MAX_CHANNELS)),
        next_chan: AtomicU32::new(CLIENT_CHAN_BASE),
        role: Role::Client { remote_dests },
        bind_tasks: Mutex::new(Vec::new()),
    });

    // Bind local listeners for `-L`.
    let mut accept_tasks = Vec::new();
    for spec in specs {
        if let ForwardSpec::Local { local_port, host, remote_port } = spec {
            let l = TcpListener::bind(("127.0.0.1", *local_port)).await.map_err(|e| {
                CryptoError::Parameter(format!("bind 127.0.0.1:{local_port}: {e}"))
            })?;
            eprintln!("[fwd] -L listening 127.0.0.1:{local_port} → {host}:{remote_port}");
            let ep = endpoint.clone();
            let host = host.clone();
            let remote_port = *remote_port;
            accept_tasks.push(tokio::spawn(async move {
                loop {
                    let (tcp, _peer) = match l.accept().await {
                        Ok(p) => p,
                        Err(_) => break,
                    };
                    tokio::spawn(ep.clone().open_from_tcp(tcp, host.clone(), remote_port));
                }
            }));
        }
    }

    // Request remote binds for `-R`.
    let mut req_id = 1u32;
    for spec in specs {
        if let ForwardSpec::Remote { bind_port, host, dest_port } = spec {
            eprintln!("[fwd] -R requesting server bind :{bind_port} → {host}:{dest_port} (client-side)");
            frame_tx
                .send(FwdFrame::BindRequest {
                    req: req_id,
                    bind_port: *bind_port,
                    host: host.clone(),
                    port: *dest_port,
                })
                .await
                .map_err(|_| CryptoError::Parameter("forward writer gone".into()))?;
            req_id += 1;
        }
    }

    // Demux until the stream closes, then tear everything down.
    let res = {
        let aead = aead_name.to_string();
        let rx_key = zeroize::Zeroizing::new(rx_key.to_vec());
        let ep = endpoint.clone();
        tokio::spawn(async move { demux_reader(reader, &aead, &rx_key, ep).await }).await
    };
    for t in accept_tasks {
        t.abort();
    }
    // Drop every channel's inbound sender so any task still waiting on a verdict
    // or on inbound data unblocks (`recv` → None) and frees itself; otherwise a
    // mid-open channel would leak its task and the Endpoint Arc.
    endpoint.registry.lock().await.clear();
    drop(frame_tx);
    let _ = writer_task.await;
    res.map_err(|e| CryptoError::Parameter(format!("forward demux join: {e}")))?
}

// ===========================================================================
// Server
// ===========================================================================

/// Server side (`--serve-forward`): authorize `-L` targets and `-R` binds against
/// the per-fingerprint policy (default deny) and bridge channels.
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

    // No per-operation throttle: the peer is authenticated and channel count is
    // bounded by MAX_CHANNELS. Brute-force is limited on the handshake failure
    // path (see `crate::shell::auth_failure_blocked`).

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

    let (frame_tx, frame_rx) = mpsc::channel::<FwdFrame>(256);
    let writer_task = spawn_writer(writer, aead_name.to_string(), tx_key.to_vec(), frame_rx);

    let endpoint = Arc::new(Endpoint {
        frame_tx: frame_tx.clone(),
        registry: Arc::new(Mutex::new(HashMap::new())),
        sem: Arc::new(Semaphore::new(MAX_CHANNELS)),
        next_chan: AtomicU32::new(SERVER_CHAN_BASE),
        role: Role::Server { peer_fp, policy: Arc::new(policy), audit_path: audit_path.map(str::to_string) },
        bind_tasks: Mutex::new(Vec::new()),
    });

    let res = demux_reader(reader, aead_name, rx_key, endpoint.clone()).await;
    // Tear down any `-R` listeners this connection opened.
    for t in endpoint.bind_tasks.lock().await.drain(..) {
        t.abort();
    }
    // Unblock and free any channel task still waiting on a verdict / inbound data.
    endpoint.registry.lock().await.clear();
    drop(frame_tx);
    let _ = writer_task.await;
    res
}

// ===========================================================================
// Forward policy: per-fingerprint allowed targets (`-L`) and bind ports (`-R`).
// ===========================================================================

/// One allowed `-L` target pattern: host (`*` = any) and port (`None` = any).
#[derive(Debug, Clone)]
struct TargetPattern {
    host: String,
    port: Option<u16>,
}

impl TargetPattern {
    fn matches(&self, host: &str, port: u16) -> bool {
        (self.host == "*" || self.host.eq_ignore_ascii_case(host))
            && self.port.is_none_or(|p| p == port)
    }
}

/// `fingerprint → (allowed -L targets, allowed -R bind ports)`. Default deny.
pub struct ForwardPolicy {
    targets: HashMap<[u8; 32], Vec<TargetPattern>>,
    binds: HashMap<[u8; 32], Vec<u16>>,
}

impl ForwardPolicy {
    /// Parse a policy file. Each non-comment line is:
    /// `<sha3-256 fp hex>  [allow="host:port, *:443"]  [bind="8080, 9000"]`.
    /// At least one of `allow=` / `bind=` is required; malformed lists are a hard
    /// error (never silently unrestricted).
    pub fn load(path: &str) -> std::io::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let mut targets: HashMap<[u8; 32], Vec<TargetPattern>> = HashMap::new();
        let mut binds: HashMap<[u8; 32], Vec<u16>> = HashMap::new();
        let err = |lineno: usize, msg: String| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, format!("line {}: {msg}", lineno + 1))
        };
        for (lineno, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (fp_hex_str, rest) = match line.split_once(char::is_whitespace) {
                Some((a, b)) => (a, b.trim()),
                None => (line, ""),
            };
            let fp = parse_fp_hex(fp_hex_str).ok_or_else(|| err(lineno, "bad fingerprint".into()))?;

            let mut had_any = false;
            if let Some((allow_val, _, _)) = crate::shell::extract_quoted_span(rest, "allow=") {
                let pats = Self::parse_targets(&allow_val, lineno)?;
                targets.entry(fp).or_default().extend(pats);
                had_any = true;
            }
            if let Some((bind_val, _, _)) = crate::shell::extract_quoted_span(rest, "bind=") {
                let ports = Self::parse_ports(&bind_val, lineno)?;
                binds.entry(fp).or_default().extend(ports);
                had_any = true;
            }
            if !had_any {
                return Err(err(lineno, "expected allow=\"...\" and/or bind=\"...\"".into()));
            }
        }
        Ok(ForwardPolicy { targets, binds })
    }

    fn parse_targets(val: &str, lineno: usize) -> std::io::Result<Vec<TargetPattern>> {
        let err = |msg: String| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, format!("line {}: {msg}", lineno + 1))
        };
        let mut out = Vec::new();
        for item in val.split(',') {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }
            let (h, p) = item.rsplit_once(':').ok_or_else(|| err(format!("{item:?} is not host:port")))?;
            if h.is_empty() {
                return Err(err(format!("empty host in {item:?}")));
            }
            // The matcher supports only `*` (any host) or an exact name. A
            // partial glob like `*.internal` would be stored as a literal that
            // never matches any real host — a silently dead rule — so refuse
            // it here instead (fail closed on ambiguous patterns).
            if h.contains('*') && h != "*" {
                return Err(err(format!(
                    "partial wildcard {h:?} is not supported: use \"*\" or an exact host"
                )));
            }
            let port = if p == "*" {
                None
            } else {
                Some(p.parse::<u16>().map_err(|_| err(format!("bad port {p:?}")))?)
            };
            out.push(TargetPattern { host: h.to_string(), port });
        }
        if out.is_empty() {
            return Err(err("allow list is empty".into()));
        }
        Ok(out)
    }

    fn parse_ports(val: &str, lineno: usize) -> std::io::Result<Vec<u16>> {
        let err = |msg: String| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, format!("line {}: {msg}", lineno + 1))
        };
        let mut out = Vec::new();
        for item in val.split(',') {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }
            out.push(item.parse::<u16>().map_err(|_| err(format!("bad bind port {item:?}")))?);
        }
        if out.is_empty() {
            return Err(err("bind list is empty".into()));
        }
        Ok(out)
    }

    /// Authorize a `-L` connect to `host:port` for `fp`. Default deny.
    fn authorize_target(&self, fp: &[u8; 32], host: &str, port: u16) -> std::result::Result<(), String> {
        match self.targets.get(fp) {
            None => Err(format!("fingerprint {} not allowed any target", &fp_hex(fp)[..16])),
            Some(pats) if pats.iter().any(|p| p.matches(host, port)) => Ok(()),
            Some(_) => Err(format!("{host}:{port} not in this fingerprint's allow list")),
        }
    }

    /// Authorize a `-R` bind on `port` for `fp`. Default deny.
    fn authorize_bind(&self, fp: &[u8; 32], port: u16) -> std::result::Result<(), String> {
        match self.binds.get(fp) {
            Some(ports) if ports.contains(&port) => Ok(()),
            _ => Err(format!("bind port {port} not allowed for this fingerprint")),
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
            FwdFrame::WindowAdjust { chan: 7, bytes: 65536 },
            FwdFrame::BindRequest { req: 3, bind_port: 8080, host: "127.0.0.1".into(), port: 3000 },
            FwdFrame::BindOk { req: 3 },
            FwdFrame::BindErr { req: 3, reason: "nope".into() },
        ];
        for f in frames {
            let enc = f.encode();
            assert_eq!(FwdFrame::decode(&enc).unwrap(), f);
        }
    }

    #[test]
    fn decode_rejects_truncated() {
        assert!(FwdFrame::decode(&[]).is_err());
        assert!(FwdFrame::decode(&[F_DATA, 0, 0]).is_err());
        assert!(FwdFrame::decode(&[F_OPEN, 0, 0, 0, 1, 5, b'a']).is_err());
        assert!(FwdFrame::decode(&[F_BINDREQ, 0, 0, 0, 1]).is_err()); // no bind_port
        assert!(FwdFrame::decode(&[0xFF, 0, 0, 0, 1]).is_err());
    }

    #[test]
    fn spec_parse() {
        assert_eq!(
            ForwardSpec::parse_local("8080:db.internal:5432").unwrap(),
            ForwardSpec::Local { local_port: 8080, host: "db.internal".into(), remote_port: 5432 }
        );
        assert_eq!(
            ForwardSpec::parse_remote("9000:127.0.0.1:3000").unwrap(),
            ForwardSpec::Remote { bind_port: 9000, host: "127.0.0.1".into(), dest_port: 3000 }
        );
        assert!(ForwardSpec::parse_local("8080:db.internal").is_err());
        assert!(ForwardSpec::parse_remote("notaport:h:5432").is_err());
    }

    #[test]
    fn policy_targets_and_binds() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("nkfwdpol_{}.txt", std::process::id()));
        let fp = [0xabu8; 32];
        let fph: String = fp.iter().map(|b| format!("{b:02x}")).collect();
        std::fs::write(
            &path,
            format!("{fph}  allow=\"db.internal:5432, *:443\"  bind=\"8080, 9000\"\n"),
        )
        .unwrap();
        let pol = ForwardPolicy::load(path.to_str().unwrap()).unwrap();
        // -L targets
        assert!(pol.authorize_target(&fp, "db.internal", 5432).is_ok());
        assert!(pol.authorize_target(&fp, "anything", 443).is_ok());
        assert!(pol.authorize_target(&fp, "db.internal", 5433).is_err());
        assert!(pol.authorize_target(&[0u8; 32], "db.internal", 5432).is_err());
        // -R binds
        assert!(pol.authorize_bind(&fp, 8080).is_ok());
        assert!(pol.authorize_bind(&fp, 9000).is_ok());
        assert!(pol.authorize_bind(&fp, 22).is_err());
        assert!(pol.authorize_bind(&[0u8; 32], 8080).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn policy_partial_wildcard_is_error_not_dead_rule() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("nkfwdpol_glob_{}.txt", std::process::id()));
        let fph = "ab".repeat(32);
        // `*.internal` would be stored as a literal hostname that never
        // matches — reject at parse time instead of silently allowing nothing.
        std::fs::write(&path, format!("{fph}  allow=\"*.internal:80\"\n")).unwrap();
        assert!(ForwardPolicy::load(path.to_str().unwrap()).is_err());
        // The two supported wildcard forms still parse.
        std::fs::write(&path, format!("{fph}  allow=\"*:443, db.internal:*\"\n")).unwrap();
        assert!(ForwardPolicy::load(path.to_str().unwrap()).is_ok());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn policy_malformed_is_error() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("nkfwdpol_bad_{}.txt", std::process::id()));
        let fph = "ab".repeat(32);
        std::fs::write(&path, format!("{fph}  user=root\n")).unwrap();
        assert!(ForwardPolicy::load(path.to_str().unwrap()).is_err());
        let _ = std::fs::remove_file(&path);
    }
}
