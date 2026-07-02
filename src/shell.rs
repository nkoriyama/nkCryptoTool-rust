/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

//! P2P shell (bastion-less PQC SSH) — see `P2P_SHELL_DESIGN.md`.
//!
//! **Phase 0** of that plan: the `ALPN_SHELL` wire framing plus an **echo**
//! server/client, with no PTY yet. It validates that the typed control frames
//! survive a round trip over the existing PQC-authenticated, AEAD-secured
//! stream. Authorization is still only the transport `allowlist` (the handshake
//! already rejects unknown peers); per-user / PTY / privilege-drop come in later
//! phases.
//!
//! Each frame is carried as one AEAD packet: `len(u32 LE) ‖ ciphertext ‖
//! tag(16)`, sealed under the per-direction session key. The 96-bit nonce is a
//! **monotonic per-direction counter** (not transmitted; each side derives it
//! from its own counter), so a nonce is never reused under a session key, and a
//! replayed / reordered / tampered packet decrypts under the wrong counter and
//! fails AEAD authentication — no separate replay window needed. Session keys
//! are ephemeral (per connection, from the PQC handshake), so counters reset
//! safely each connection. The plaintext inside one packet is a single
//! [`Frame`].

use crate::backend;
use crate::backend::AeadBackend;
use crate::error::{CryptoError, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

/// Largest AEAD packet we will read (ciphertext + tag). Sized for a terminal
/// write burst, bounded so a peer cannot force a large allocation per packet.
const MAX_PACKET: usize = 128 * 1024;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const MIN_PACKET: usize = TAG_LEN + 1; // tag + at least the 1-byte frame type

/// Derive the 96-bit AEAD nonce for a direction's message counter: 4 zero bytes
/// followed by the big-endian counter. Monotonic and never reused under a given
/// session key.
fn nonce_from_ctr(ctr: u64) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[4..].copy_from_slice(&ctr.to_be_bytes());
    n
}

const T_OPEN: u8 = 0x01;
const T_DATA: u8 = 0x02;
const T_WINSZ: u8 = 0x03;
const T_EXIT: u8 = 0x04;
const T_ERROR: u8 = 0x05;

/// One control/data frame exchanged over `ALPN_SHELL`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// Client → server, once: request a session. `cmd` empty = login shell.
    Open { cols: u16, rows: u16, term: String, cmd: String },
    /// Terminal bytes (client→server = stdin, server→client = stdout/err).
    Data(Vec<u8>),
    /// Client → server: the controlling terminal resized.
    Winsz { cols: u16, rows: u16 },
    /// Server → client: the remote program exited with this status.
    Exit(i32),
    /// Either direction: a textual error (authz denied, spawn failed, …).
    Error(String),
}

impl Frame {
    /// Serialize to the plaintext that goes inside one AEAD packet.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::new();
        match self {
            Frame::Open { cols, rows, term, cmd } => {
                v.push(T_OPEN);
                v.extend_from_slice(&cols.to_be_bytes());
                v.extend_from_slice(&rows.to_be_bytes());
                v.extend_from_slice(&(term.len() as u16).to_be_bytes());
                v.extend_from_slice(term.as_bytes());
                v.extend_from_slice(&(cmd.len() as u16).to_be_bytes());
                v.extend_from_slice(cmd.as_bytes());
            }
            Frame::Data(d) => {
                v.push(T_DATA);
                v.extend_from_slice(d);
            }
            Frame::Winsz { cols, rows } => {
                v.push(T_WINSZ);
                v.extend_from_slice(&cols.to_be_bytes());
                v.extend_from_slice(&rows.to_be_bytes());
            }
            Frame::Exit(code) => {
                v.push(T_EXIT);
                v.extend_from_slice(&code.to_be_bytes());
            }
            Frame::Error(m) => {
                v.push(T_ERROR);
                v.extend_from_slice(m.as_bytes());
            }
        }
        v
    }

    /// Parse a frame from one packet's plaintext. Every length is bounds-checked
    /// against the buffer so a malformed frame is a clean error, never a panic.
    pub fn decode(buf: &[u8]) -> Result<Frame> {
        let bad = || CryptoError::Parameter("malformed shell frame".to_string());
        let (&ty, rest) = buf.split_first().ok_or_else(bad)?;
        match ty {
            T_OPEN => {
                if rest.len() < 6 {
                    return Err(bad());
                }
                let cols = u16::from_be_bytes([rest[0], rest[1]]);
                let rows = u16::from_be_bytes([rest[2], rest[3]]);
                let tlen = u16::from_be_bytes([rest[4], rest[5]]) as usize;
                let rest = &rest[6..];
                if rest.len() < tlen + 2 {
                    return Err(bad());
                }
                let term = std::str::from_utf8(&rest[..tlen]).map_err(|_| bad())?.to_string();
                let rest = &rest[tlen..];
                let clen = u16::from_be_bytes([rest[0], rest[1]]) as usize;
                let rest = &rest[2..];
                if rest.len() < clen {
                    return Err(bad());
                }
                let cmd = std::str::from_utf8(&rest[..clen]).map_err(|_| bad())?.to_string();
                Ok(Frame::Open { cols, rows, term, cmd })
            }
            T_DATA => Ok(Frame::Data(rest.to_vec())),
            T_WINSZ => {
                if rest.len() < 4 {
                    return Err(bad());
                }
                Ok(Frame::Winsz {
                    cols: u16::from_be_bytes([rest[0], rest[1]]),
                    rows: u16::from_be_bytes([rest[2], rest[3]]),
                })
            }
            T_EXIT => {
                if rest.len() < 4 {
                    return Err(bad());
                }
                Ok(Frame::Exit(i32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]])))
            }
            T_ERROR => Ok(Frame::Error(String::from_utf8_lossy(rest).into_owned())),
            _ => Err(CryptoError::Parameter(format!("unknown shell frame type {ty}"))),
        }
    }
}

/// Seal an arbitrary plaintext payload under `key` with the nonce derived from
/// `ctr` (incremented on success) and write it as one length-prefixed AEAD packet
/// (`len(u32 LE) ‖ ciphertext ‖ tag(16)`). The shared transport primitive behind
/// both the shell [`Frame`]s and the port-forward channel frames.
pub(crate) async fn send_packet<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    aead_name: &str,
    key: &[u8],
    ctr: &mut u64,
    pt: &[u8],
) -> Result<()> {
    let nonce = nonce_from_ctr(*ctr);
    let mut aead = backend::new_encrypt(aead_name, key, &nonce)?;
    let mut ct = Zeroizing::new(vec![0u8; pt.len() + 32]);
    let n = aead.update(pt, &mut ct)?;
    let fin = aead.finalize(&mut ct[n..])?;
    let mut tag = [0u8; TAG_LEN];
    aead.get_tag(&mut tag)?;

    let mut packet = Vec::with_capacity(n + fin + TAG_LEN);
    packet.extend_from_slice(&ct[..n + fin]);
    packet.extend_from_slice(&tag);

    w.write_all(&(packet.len() as u32).to_le_bytes()).await.map_err(io_err)?;
    w.write_all(&packet).await.map_err(io_err)?;
    w.flush().await.map_err(io_err)?;
    *ctr = ctr.checked_add(1).ok_or_else(|| {
        CryptoError::Parameter("send counter overflow".to_string())
    })?;
    Ok(())
}

/// Read one length-prefixed AEAD packet and decrypt it under `key` with the nonce
/// derived from `ctr` (incremented on success). Returns `Ok(None)` on a clean
/// stream close (zero-length packet or EOF). A replayed/reordered/tampered packet
/// decrypts under the wrong counter-nonce and surfaces as an authentication error.
pub(crate) async fn recv_packet<R: AsyncReadExt + Unpin>(
    r: &mut R,
    aead_name: &str,
    key: &[u8],
    ctr: &mut u64,
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let mut len_bytes = [0u8; 4];
    match r.read_exact(&mut len_bytes).await {
        Ok(_) => {}
        Err(_) => return Ok(None), // EOF / peer closed
    }
    let len = u32::from_le_bytes(len_bytes) as usize;
    if len == 0 {
        return Ok(None);
    }
    if !(MIN_PACKET..=MAX_PACKET).contains(&len) {
        return Err(CryptoError::Parameter(format!("packet size {len} out of range")));
    }
    let mut packet = Zeroizing::new(vec![0u8; len]);
    r.read_exact(&mut packet).await.map_err(io_err)?;

    let (ciphertext, tag) = packet.split_at(packet.len() - TAG_LEN);
    let nonce = nonce_from_ctr(*ctr);
    let mut aead = backend::new_decrypt(aead_name, key, &nonce)?;
    aead.set_tag(tag)?;
    let mut out = Zeroizing::new(vec![0u8; ciphertext.len() + 32]);
    let n = aead.update(ciphertext, &mut out)?;
    let fin = aead.finalize(&mut out[n..])?;
    *ctr = ctr.checked_add(1).ok_or_else(|| {
        CryptoError::Parameter("recv counter overflow".to_string())
    })?;
    out.truncate(n + fin);
    Ok(Some(out))
}

/// Seal `frame` under `key` and write it as one AEAD packet (see [`send_packet`]).
pub async fn send_frame<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    aead_name: &str,
    key: &[u8],
    ctr: &mut u64,
    frame: &Frame,
) -> Result<()> {
    let pt = Zeroizing::new(frame.encode());
    send_packet(w, aead_name, key, ctr, &pt).await
}

/// Read one AEAD packet (see [`recv_packet`]) and decode the [`Frame`].
pub async fn recv_frame<R: AsyncReadExt + Unpin>(
    r: &mut R,
    aead_name: &str,
    key: &[u8],
    ctr: &mut u64,
) -> Result<Option<Frame>> {
    match recv_packet(r, aead_name, key, ctr).await? {
        Some(pt) => Frame::decode(&pt).map(Some),
        None => Ok(None),
    }
}

pub(crate) fn io_err(e: std::io::Error) -> CryptoError {
    CryptoError::FileRead(e.to_string())
}

/// Pick `(rx_key, tx_key)` from the session keys for our role, matching
/// `chat_loop`: the server receives on c2s and sends on s2c.
pub(crate) fn role_keys<'a>(s2c: &'a [u8], c2s: &'a [u8], is_server: bool) -> (&'a [u8], &'a [u8]) {
    if is_server {
        (c2s, s2c)
    } else {
        (s2c, c2s)
    }
}

/// **Phase 0 echo server.** Accepts the `Open`, then echoes every `Data` frame
/// straight back, until the client sends `Exit` or the stream closes. No PTY yet
/// — this exercises the framing and the secured transport end to end.
pub async fn run_echo_server<R, W>(
    mut reader: R,
    mut writer: W,
    aead_name: &str,
    s2c_key: &[u8],
    c2s_key: &[u8],
) -> Result<()>
where
    R: AsyncReadExt + Unpin + Send,
    W: AsyncWriteExt + Unpin + Send,
{
    let (rx_key, tx_key) = role_keys(s2c_key, c2s_key, true);
    let (mut rx_ctr, mut tx_ctr) = (0u64, 0u64);
    let mut opened = false;
    loop {
        let frame = match recv_frame(&mut reader, aead_name, rx_key, &mut rx_ctr).await? {
            Some(f) => f,
            None => break,
        };
        match frame {
            Frame::Open { term, cmd, .. } => {
                opened = true;
                eprintln!(
                    "[shell] echo session opened (TERM={term:?}, cmd={})",
                    if cmd.is_empty() { "<login>" } else { cmd.as_str() }
                );
            }
            Frame::Data(d) if opened => {
                send_frame(&mut writer, aead_name, tx_key, &mut tx_ctr, &Frame::Data(d)).await?;
            }
            Frame::Data(_) => {
                send_frame(
                    &mut writer,
                    aead_name,
                    tx_key,
                    &mut tx_ctr,
                    &Frame::Error("DATA before OPEN".to_string()),
                )
                .await?;
                break;
            }
            Frame::Exit(_) => break,
            Frame::Winsz { .. } => {} // ignored by the echo server
            Frame::Error(_) => break,
        }
    }
    let _ = send_frame(&mut writer, aead_name, tx_key, &mut tx_ctr, &Frame::Exit(0)).await;
    Ok(())
}

/// **Phase 0 echo client.** Sends `Open`, then for each line on `input` sends a
/// `Data` frame and prints the echoed reply to `out`, until `input` ends; then
/// sends `Exit`. Mirrors how the real client will pump a PTY in later phases.
pub async fn run_echo_client<R, W, IN, OUT>(
    mut reader: R,
    mut writer: W,
    aead_name: &str,
    s2c_key: &[u8],
    c2s_key: &[u8],
    mut input: IN,
    out: &mut OUT,
) -> Result<()>
where
    R: AsyncReadExt + Unpin + Send,
    W: AsyncWriteExt + Unpin + Send,
    IN: AsyncReadExt + Unpin + Send,
    OUT: AsyncWriteExt + Unpin + Send,
{
    let (rx_key, tx_key) = role_keys(s2c_key, c2s_key, false);
    let (mut rx_ctr, mut tx_ctr) = (0u64, 0u64);
    send_frame(
        &mut writer,
        aead_name,
        tx_key,
        &mut tx_ctr,
        &Frame::Open { cols: 80, rows: 24, term: "xterm-256color".to_string(), cmd: String::new() },
    )
    .await?;

    let mut buf = vec![0u8; 4096];
    loop {
        let n = input.read(&mut buf).await.map_err(io_err)?;
        if n == 0 {
            break;
        }
        send_frame(&mut writer, aead_name, tx_key, &mut tx_ctr, &Frame::Data(buf[..n].to_vec()))
            .await?;
        // Read the echoed reply for this burst (Phase 0 is lockstep; the real
        // PTY client in Phase 1 pumps both directions concurrently).
        match recv_frame(&mut reader, aead_name, rx_key, &mut rx_ctr).await? {
            Some(Frame::Data(d)) => {
                out.write_all(&d).await.map_err(io_err)?;
                out.flush().await.map_err(io_err)?;
            }
            Some(Frame::Error(m)) => {
                return Err(CryptoError::Parameter(format!("shell server error: {m}")));
            }
            Some(Frame::Exit(_)) | None => break,
            Some(_) => {}
        }
    }
    send_frame(&mut writer, aead_name, tx_key, &mut tx_ctr, &Frame::Exit(0)).await?;
    Ok(())
}

// ===========================================================================
// Phase 2a: authorization policy, command restriction, audit log, rate limit.
// (Per-user privilege drop / setuid is Phase 2b; here the shell still runs as
// the server's own user.)
// ===========================================================================

/// One policy entry: what an authorized peer fingerprint may do.
#[derive(Debug, Clone, Default)]
pub struct PolicyEntry {
    /// Local user this fingerprint maps to. Recorded/audited now; *enforced*
    /// (setuid privilege drop) in Phase 2b.
    pub user: Option<String>,
    /// If set, the peer may only run one of these exact commands (ssh
    /// `command=` style); an interactive/login shell is then refused.
    pub cmd_allow: Option<Vec<String>>,
}

/// `fingerprint -> PolicyEntry` map loaded from `--shell-policy`. When a policy
/// is configured, only listed fingerprints may obtain a shell at all.
#[derive(Debug, Clone, Default)]
pub struct ShellPolicy {
    entries: std::collections::HashMap<[u8; 32], PolicyEntry>,
}

/// Outcome of authorizing a peer's OPEN against the policy.
pub enum PolicyDecision {
    Deny(String),
    Allow { user: Option<String>, run_cmd: String },
}

impl ShellPolicy {
    /// Parse a policy file. Each non-blank, non-`#` line is
    /// `<sha3-256-hex> [user=NAME] [cmd-allow="c1,c2,..."]`.
    pub fn load(path: &str) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| CryptoError::Parameter(format!("read shell policy {path}: {e}")))?;
        let mut entries = std::collections::HashMap::new();
        for (lineno, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut it = line.splitn(2, char::is_whitespace);
            let fp_hex = it.next().unwrap_or("");
            let fp = parse_fp_hex(fp_hex).ok_or_else(|| {
                CryptoError::Parameter(format!(
                    "shell policy line {}: bad SHA3-256 fingerprint", lineno + 1
                ))
            })?;
            let rest = it.next().unwrap_or("");
            // Pull out the quoted `cmd-allow="..."` value *and remove its span*
            // before searching for `user=`, so a `user=` appearing inside a
            // command in the allow list can never be mistaken for the user
            // mapping (which would map the peer to an unintended local user).
            let (cmd_allow, rest_wo_cmd) = match extract_quoted_span(rest, "cmd-allow=") {
                Some((value, start, end)) => {
                    let list = value
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect::<Vec<_>>();
                    (Some(list), format!("{}{}", &rest[..start], &rest[end..]))
                }
                // Fail closed: if `cmd-allow=` is present but not a well-formed
                // quoted value, treat it as a policy error rather than silently
                // dropping the restriction (which would grant an unrestricted
                // shell). A genuinely unrestricted entry simply omits cmd-allow.
                None if rest.contains("cmd-allow=") => {
                    return Err(CryptoError::Parameter(format!(
                        "shell policy line {}: malformed cmd-allow (expected cmd-allow=\"...\")",
                        lineno + 1
                    )));
                }
                None => (None, rest.to_string()),
            };
            let user = extract_kv(&rest_wo_cmd, "user=").map(|s| s.to_string());
            entries.insert(fp, PolicyEntry { user, cmd_allow });
        }
        Ok(Self { entries })
    }

    /// Authorize a `(fingerprint, requested_cmd)` (empty `requested_cmd` = login
    /// shell). A fingerprint absent from the policy is denied; a `cmd-allow`
    /// entry permits only its exact commands and refuses a login shell.
    pub fn authorize(&self, fp: &[u8; 32], requested_cmd: &str) -> PolicyDecision {
        let entry = match self.entries.get(fp) {
            Some(e) => e,
            None => return PolicyDecision::Deny("fingerprint not in shell policy".into()),
        };
        match &entry.cmd_allow {
            Some(allowed) => {
                if requested_cmd.is_empty() {
                    PolicyDecision::Deny(
                        "this fingerprint is restricted to specific commands (no login shell)".into(),
                    )
                } else if allowed.iter().any(|c| c == requested_cmd) {
                    PolicyDecision::Allow { user: entry.user.clone(), run_cmd: requested_cmd.to_string() }
                } else {
                    PolicyDecision::Deny("command not in this fingerprint's cmd-allow list".into())
                }
            }
            None => PolicyDecision::Allow { user: entry.user.clone(), run_cmd: requested_cmd.to_string() },
        }
    }
}

pub(crate) fn parse_fp_hex(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Extract the whitespace-terminated value of `key` (e.g. `user=`) from `rest`.
pub(crate) fn extract_kv<'a>(rest: &'a str, key: &str) -> Option<&'a str> {
    let i = rest.find(key)? + key.len();
    let v = &rest[i..];
    Some(v.split(char::is_whitespace).next().unwrap_or(v))
}

/// Extract the double-quoted value of `key` (e.g. `cmd-allow="a,b"`) from `rest`,
/// returning the value plus the `[start, end)` byte span of the whole
/// `key="..."` match so the caller can excise it.
pub(crate) fn extract_quoted_span(rest: &str, key: &str) -> Option<(String, usize, usize)> {
    let key_at = rest.find(key)?;
    let after = rest[key_at + key.len()..].strip_prefix('"')?;
    let close = after.find('"')?;
    let value = after[..close].to_string();
    let end = key_at + key.len() + 1 + close + 1; // past the closing quote
    Some((value, key_at, end))
}

/// Hex of a fingerprint, for policy lookup logging / audit.
pub(crate) fn fp_hex(fp: &[u8; 32]) -> String {
    fp.iter().map(|b| format!("{b:02x}")).collect()
}

/// Auth-failure throttle — a flood / retry-storm dampener on the *handshake
/// failure* path, keyed by the peer's transport **NodeId** (the one identifier
/// we have before application authentication runs). That NodeId is authenticated
/// by the QUIC/TLS transport (it is the peer's ed25519 key, proven during
/// connection setup), so a peer cannot present another's — a failure only ever
/// counts against the actual connecting node, never a spoofed victim.
///
/// Deliberately **separate from any limit on authenticated operations**: a peer
/// that has proven its identity (pinned key / allowlist) may then open sessions
/// or transfer files as fast as the concurrency semaphore allows — only *failed*
/// handshakes are counted. Conflating the two (the old per-fingerprint 2 s
/// window applied *post*-auth) throttled legitimate use, e.g. a client copying
/// several files in a row over scp.
///
/// Scope, honestly: unlike password SSH there is **no secret to brute-force** —
/// authentication is a public-key match, so a wrong key is rejected
/// deterministically and cheaply. This throttle therefore targets *resource
/// floods*, not credential guessing, and it only bites a peer that **reuses its
/// NodeId** (a long-lived process reconnecting, the prekey/inbox flow). A
/// process-per-transfer CLI attacker mints a fresh NodeId each time and slips
/// past — but each attempt is still rejected cheaply by the pinned key /
/// allowlist, and total concurrency is bounded by the accept semaphore.
const AUTH_FAIL_WINDOW: std::time::Duration = std::time::Duration::from_secs(30);
/// Failed handshakes allowed from one NodeId within the window before it is
/// temporarily blocked.
const AUTH_FAIL_MAX: u32 = 8;
/// Hard cap on tracked NodeIds. A flood of *distinct* NodeIds must not grow the
/// map without bound or make cleanup expensive, so we only scan when over this
/// cap and, if a live flood keeps it over cap, drop tracking entirely (fail-open
/// — this is a dampener; the accept semaphore is the real concurrency bound).
const AUTH_FAIL_MAX_TRACKED: usize = 4096;

/// `NodeId -> (failure_count, window_start)`, shared by [`note_auth_failure`] and
/// [`auth_failure_blocked`]. `None` until first use.
static AUTH_FAILURES: std::sync::Mutex<
    Option<std::collections::HashMap<[u8; 32], (u32, std::time::Instant)>>,
> = std::sync::Mutex::new(None);

/// Amortized cleanup: an O(N) scan only when the map has grown past the cap, so
/// the common path stays O(1). Called from the write path only.
fn prune_auth_failures(
    map: &mut std::collections::HashMap<[u8; 32], (u32, std::time::Instant)>,
    now: std::time::Instant,
) {
    if map.len() <= AUTH_FAIL_MAX_TRACKED {
        return;
    }
    map.retain(|_, (_, start)| now.duration_since(*start) < AUTH_FAIL_WINDOW);
    if map.len() > AUTH_FAIL_MAX_TRACKED {
        // Still over cap under a live distinct-NodeId flood: bound memory by
        // dropping tracking. Rotating-NodeId attempts are rejected cheaply by the
        // pinned key / allowlist anyway.
        map.clear();
    }
}

/// Record one failed handshake/authentication from `node` (its transport NodeId).
pub(crate) fn note_auth_failure(node: &[u8; 32]) {
    let now = std::time::Instant::now();
    // Recover from a poisoned lock rather than propagating the panic, so one
    // panicking caller can't wedge auth throttling for the life of the process.
    let mut guard = AUTH_FAILURES.lock().unwrap_or_else(|e| e.into_inner());
    let map = guard.get_or_insert_with(std::collections::HashMap::new);
    prune_auth_failures(map, now);
    let e = map.entry(*node).or_insert((0, now));
    if now.duration_since(e.1) >= AUTH_FAIL_WINDOW {
        *e = (0, now); // window rolled: reset the counter
    }
    e.0 = e.0.saturating_add(1);
}

/// True if `node` has reached [`AUTH_FAIL_MAX`] failed handshakes *within the
/// current window*. The window is checked inline (no map scan), so this stays
/// O(1) and a stale over-threshold entry never falsely blocks a peer.
pub(crate) fn auth_failure_blocked(node: &[u8; 32]) -> bool {
    let now = std::time::Instant::now();
    let mut guard = AUTH_FAILURES.lock().unwrap_or_else(|e| e.into_inner());
    let map = guard.get_or_insert_with(std::collections::HashMap::new);
    map.get(node)
        .is_some_and(|(count, start)| *count >= AUTH_FAIL_MAX && now.duration_since(*start) < AUTH_FAIL_WINDOW)
}

/// Append one line to the audit log, off the async runtime thread. Returns the
/// I/O result so a security-relevant record (the allow/deny decision) can be
/// made *fail-closed* by the caller; best-effort records ignore it.
pub(crate) async fn audit(path: Option<&str>, fp: &[u8; 32], event: &str) -> std::io::Result<()> {
    let Some(path) = path else { return Ok(()) };
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Neutralize control characters (notably newlines) in the event — part of
    // it is client-supplied (the command), so a raw `\n` would let a peer forge
    // additional audit records / erase its tracks.
    let safe_event: String = event
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let line = format!("{ts} fp={} {safe_event}\n", fp_hex(fp));
    let path = path.to_string();
    tokio::task::spawn_blocking(move || {
        use std::io::Write as _;
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).append(true);
        // Audit records (fingerprints, commands) are sensitive: create the file
        // owner-only so other local users cannot read the access trail.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&path)?;
        f.write_all(line.as_bytes())?;
        f.flush()
    })
    .await
    .map_err(std::io::Error::other)?
}

/// Audit a non-decision event (rate-limit, deny, session end). A failed write is
/// not fail-closed (we are already denying / ending), but it is surfaced to
/// stderr so the attempt is never lost completely silently.
pub(crate) async fn audit_best_effort(path: Option<&str>, fp: &[u8; 32], event: &str) {
    if let Err(e) = audit(path, fp, event).await {
        eprintln!("[shell] audit write failed for {event:?}: {e}");
    }
}

// ===========================================================================
// Phase 2b: per-user privilege drop (unix). The user/group resolution
// (`getpwnam`/`getgrouplist`) runs in the parent; the post-fork `pre_exec`
// closure then only makes async-signal-safe syscalls (`setgroups`/`setgid`/
// `setuid`).
// ===========================================================================

/// Resolved drop target: the uid/gid/supplementary-groups to become, plus the
/// user's own login shell (from `/etc/passwd`) to run instead of the operator's.
#[cfg(unix)]
#[derive(Clone)]
struct DropTarget {
    uid: libc::uid_t,
    gid: libc::gid_t,
    groups: Vec<libc::gid_t>,
    shell: Option<String>,
}

/// Look up a user's uid, primary gid, and supplementary groups by name.
#[cfg(unix)]
fn lookup_user(name: &str) -> std::result::Result<DropTarget, String> {
    use std::ffi::CString;
    let cname = CString::new(name).map_err(|_| "user name contains NUL".to_string())?;
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 8192];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe {
        libc::getpwnam_r(cname.as_ptr(), &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result)
    };
    if rc != 0 || result.is_null() {
        return Err(format!("unknown user {name:?}"));
    }
    let (uid, gid) = (pwd.pw_uid, pwd.pw_gid);
    // Copy the user's login shell out of the pwd buffer (a non-empty, absolute
    // path); used so a dropped session runs that user's shell, not the operator's.
    let shell = if pwd.pw_shell.is_null() {
        None
    } else {
        let s = unsafe { std::ffi::CStr::from_ptr(pwd.pw_shell) }
            .to_string_lossy()
            .into_owned();
        if s.starts_with('/') { Some(s) } else { None }
    };
    // getgrouplist: query the count, then fetch.
    let mut ngroups: libc::c_int = 64;
    let mut gids = vec![0 as libc::gid_t; ngroups as usize];
    let r = unsafe {
        libc::getgrouplist(cname.as_ptr(), gid as _, gids.as_mut_ptr(), &mut ngroups)
    };
    if r < 0 {
        gids = vec![0 as libc::gid_t; ngroups.max(0) as usize];
        let r2 = unsafe {
            libc::getgrouplist(cname.as_ptr(), gid as _, gids.as_mut_ptr(), &mut ngroups)
        };
        if r2 < 0 {
            return Err(format!("getgrouplist failed for {name:?}"));
        }
    }
    gids.truncate(ngroups.max(0) as usize);
    Ok(DropTarget { uid, gid, groups: gids, shell })
}

/// Allocate a pty pair sized to `(cols, rows)`, returning `(master_fd,
/// slave_fd)`. We use `libc::openpty` directly because we need the *slave* fd to
/// hand the child as its controlling terminal/stdio under a `pre_exec` privilege
/// drop (which the higher-level pty crate's spawn does not support).
#[cfg(unix)]
fn open_pty(cols: u16, rows: u16) -> Result<(std::os::fd::RawFd, std::os::fd::RawFd)> {
    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;
    let ws = libc::winsize { ws_row: rows, ws_col: cols, ws_xpixel: 0, ws_ypixel: 0 };
    let r = unsafe {
        libc::openpty(&mut master, &mut slave, std::ptr::null_mut(), std::ptr::null(), &ws)
    };
    if r != 0 {
        return Err(CryptoError::Parameter(format!(
            "openpty: {}", std::io::Error::last_os_error()
        )));
    }
    // Mark both ends close-on-exec so the spawned shell does not inherit the raw
    // master/slave fds. The child's stdio is set up from separate `dup`s (which
    // clear CLOEXEC), and the slave's controlling-terminal `ioctl` runs in
    // `pre_exec` before `exec`, so CLOEXEC there is harmless.
    for fd in [master, slave] {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
            let e = std::io::Error::last_os_error();
            unsafe { libc::close(master); libc::close(slave); }
            return Err(CryptoError::Parameter(format!("pty FD_CLOEXEC: {e}")));
        }
    }
    Ok((master, slave))
}

/// Decide how (or whether) to drop privileges for `policy_user`:
/// - **root server**: must drop to a mapped *non-root* user; a missing `user=`
///   or a mapping to uid 0 is refused (never serve a root shell).
/// - **non-root server**: cannot become another user; the mapped user (if any)
///   must be ourselves, otherwise the session is refused (no privilege gain).
///
/// Returns `Ok(None)` when no drop is needed (already the right user).
#[cfg(unix)]
fn resolve_drop(policy_user: Option<&str>) -> std::result::Result<Option<DropTarget>, String> {
    let cur = unsafe { libc::geteuid() };
    // Treat the server as root if EITHER the real or effective uid is 0 (matching
    // the startup gate in main.rs): a real uid of 0 with a non-zero effective uid
    // could otherwise skip the drop entirely and leave a shell able to regain root
    // via setuid(0). The actual drop below sets real/effective/saved ids.
    let server_is_root = cur == 0 || unsafe { libc::getuid() } == 0;
    match policy_user {
        Some(u) => {
            let t = lookup_user(u)?;
            if server_is_root {
                if t.uid == 0 {
                    return Err(format!("policy maps {u:?} to root; refusing a root shell"));
                }
                // A non-root uid is not enough: a primary or supplementary GID of
                // 0 (root/wheel) would still grant root-group file access and,
                // on many systems, sudo/wheel privileges. Refuse any such mapping
                // so the dropped shell holds no root-equivalent group.
                if t.gid == 0 || t.groups.contains(&0) {
                    return Err(format!(
                        "policy maps {u:?} to a root group (gid 0); refusing a root-group shell"
                    ));
                }
                Ok(Some(t))
            } else if t.uid == cur {
                Ok(None) // already this user
            } else {
                Err(format!("cannot run as {u:?} without root (server is uid {cur})"))
            }
        }
        None => {
            if server_is_root {
                Err("server runs as root but no user= is mapped for this fingerprint; \
                     refusing a root shell"
                    .into())
            } else {
                Ok(None)
            }
        }
    }
}

// ===========================================================================
// Phase 1: single-user PTY bridge (unix). The server allocates a PTY and runs
// the shell, dropping to the policy's mapped user (Phase 2b) when configured;
// the client puts its terminal in raw mode and pumps both directions.
// ===========================================================================

/// Server side of a real shell session: allocate a PTY, spawn the shell, and
/// bridge it to the client over the secured frame stream until the shell exits.
/// Authorization (who may reach this at all) is the transport allowlist / pinned
/// key enforced before this runs; this still runs the shell as the server user.
#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
// allow(too_many_arguments): the secured stream halves + session keys + the
// authenticated peer fingerprint + policy/audit paths are all genuinely needed
// to authorize and audit one shell session; bundling them into a struct would
// just move the noise. Future: fold transport+keys into a SecureChannel type.
pub async fn run_pty_server<R, W>(
    mut reader: R,
    mut writer: W,
    aead_name: &str,
    s2c_key: &[u8],
    c2s_key: &[u8],
    peer_fp: [u8; 32],
    policy_path: Option<&str>,
    audit_path: Option<&str>,
) -> Result<()>
where
    R: AsyncReadExt + Unpin + Send + 'static,
    W: AsyncWriteExt + Unpin + Send,
{
    let (rx_key, tx_key) = role_keys(s2c_key, c2s_key, true);
    let (mut rx_ctr, mut tx_ctr) = (0u64, 0u64);

    // No per-operation throttle here: this peer is already authenticated, and
    // concurrency is bounded by the accept semaphore. Brute-force protection
    // lives on the handshake failure path (see `auth_failure_blocked`).

    // First frame must be OPEN.
    let (cols, rows, term, cmd) =
        match recv_frame(&mut reader, aead_name, rx_key, &mut rx_ctr).await? {
            Some(Frame::Open { cols, rows, term, cmd }) => (cols, rows, term, cmd),
            _ => {
                let _ = send_frame(&mut writer, aead_name, tx_key, &mut tx_ctr,
                    &Frame::Error("expected OPEN".into())).await;
                return Err(CryptoError::Parameter("shell: first frame was not OPEN".into()));
            }
        };

    // Authorize against the policy (when one is configured): an unlisted
    // fingerprint, or a command outside its cmd-allow list, is refused.
    // Resolve the audit record for the access decision; if a policy denies, the
    // session never starts. The *allow* record is fail-closed: if it can't be
    // written, refuse the session rather than run it untraced.
    let allow_event = match policy_path {
        Some(pp) => {
            let pp = pp.to_string();
            let policy = tokio::task::spawn_blocking(move || ShellPolicy::load(&pp))
                .await
                .map_err(std::io::Error::other)
                .map_err(|e| CryptoError::Parameter(format!("load shell policy: {e}")))??;
            match policy.authorize(&peer_fp, &cmd) {
                PolicyDecision::Allow { user, run_cmd } => (
                    run_cmd.clone(),
                    user.clone(),
                    format!(
                        "allow user={} cmd={}",
                        user.as_deref().unwrap_or("<server>"),
                        if run_cmd.is_empty() { "<login>" } else { run_cmd.as_str() }
                    ),
                ),
                PolicyDecision::Deny(reason) => {
                    audit_best_effort(audit_path, &peer_fp, &format!("deny: {reason}")).await;
                    let _ = send_frame(&mut writer, aead_name, tx_key, &mut tx_ctr,
                        &Frame::Error(reason.clone())).await;
                    return Err(CryptoError::Parameter(format!("shell denied: {reason}")));
                }
            }
        }
        None => (
            cmd.clone(),
            None,
            format!("allow (no policy) cmd={}", if cmd.is_empty() { "<login>" } else { cmd.as_str() }),
        ),
    };
    let run_cmd = allow_event.0;
    let drop_user = allow_event.1;
    if let Err(e) = audit(audit_path, &peer_fp, &allow_event.2).await {
        let _ = send_frame(&mut writer, aead_name, tx_key, &mut tx_ctr,
            &Frame::Error("audit log unavailable; refusing".into())).await;
        return Err(CryptoError::Parameter(format!("shell refused: audit write failed: {e}")));
    }

    // Resolve privilege drop (Phase 2b). A failure here (e.g. server is root but
    // the fingerprint maps to no user / to root) refuses the session.
    let drop_target = match resolve_drop(drop_user.as_deref()) {
        Ok(t) => t,
        Err(reason) => {
            audit_best_effort(audit_path, &peer_fp, &format!("deny: {reason}")).await;
            let _ = send_frame(&mut writer, aead_name, tx_key, &mut tx_ctr,
                &Frame::Error(reason.clone())).await;
            return Err(CryptoError::Parameter(format!("shell denied: {reason}")));
        }
    };

    // When dropping to another user, run *that* user's login shell (from
    // /etc/passwd) rather than the operator's `$SHELL`; otherwise fall back to the
    // operator's `$SHELL`, then `/bin/sh`.
    let shell = drop_target
        .as_ref()
        .and_then(|t| t.shell.clone())
        .or_else(|| std::env::var("SHELL").ok())
        .unwrap_or_else(|| "/bin/sh".to_string());
    // Sanitize the client-supplied TERM: it ends up in the shell's environment
    // and is looked up by terminfo, so restrict it to a safe, bounded name (else
    // fall back to a conservative default).
    let safe_term = if !term.is_empty()
        && term.len() <= 64
        && term.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        term.clone()
    } else {
        "xterm".to_string()
    };

    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let (master_fd, slave_fd) = open_pty(cols, rows)?;
    // Own both pty ends immediately so any early return below (a failed `dup` or
    // `spawn`) closes them instead of leaking an fd — repeated failed connections
    // must not exhaust the server's fd table.
    let master = unsafe { std::fs::File::from_raw_fd(master_fd) };
    let slave = unsafe { OwnedFd::from_raw_fd(slave_fd) };
    let slave_raw = slave.as_raw_fd();
    // Child stdio = three dups of the slave (Command takes ownership of each).
    // Use F_DUPFD_CLOEXEC so each dup is close-on-exec: otherwise, between this
    // dup and our `spawn`, another thread spawning an unrelated child could leak
    // this shell's pty slave into that child (i/o interception). Our own child
    // gets it as stdio via std's `dup2` (which clears CLOEXEC), so it still works.
    let dup_stdio = || -> Result<std::process::Stdio> {
        let fd = unsafe { libc::fcntl(slave_raw, libc::F_DUPFD_CLOEXEC, 0) };
        if fd < 0 {
            return Err(CryptoError::Parameter(format!(
                "dup pty slave: {}", std::io::Error::last_os_error()
            )));
        }
        Ok(std::process::Stdio::from(unsafe { OwnedFd::from_raw_fd(fd) }))
    };
    let (sin, sout, serr) = (dup_stdio()?, dup_stdio()?, dup_stdio()?);

    let mut command = std::process::Command::new(&shell);
    command.env("TERM", &safe_term);
    if run_cmd.is_empty() {
        command.arg("-l");
    } else {
        command.arg("-c").arg(&run_cmd);
    }
    command.stdin(sin).stdout(sout).stderr(serr);

    // After fork, before exec — async-signal-safe syscalls only: new session,
    // make the pty our controlling terminal, then drop privileges in the
    // required order (supplementary groups → gid → uid) and verify root cannot
    // be regained. Any failure returns Err so exec never happens (no shell runs
    // with the wrong privileges).
    let ctty_fd = slave_raw;
    // Flatten the drop target into a fixed-size, `Copy`-only value so the
    // `pre_exec` closure captures NO heap-owning object: nothing is dropped in the
    // child between fork and exec, so there is no chance of deadlocking on the
    // allocator lock held by another parent thread. Refuse (fail-closed) a user
    // with more supplementary groups than the inline array holds.
    const MAX_DROP_GROUPS: usize = 64;
    let drop_in_child: Option<([libc::gid_t; MAX_DROP_GROUPS], usize, libc::uid_t, libc::gid_t)> =
        match &drop_target {
            Some(t) => {
                if t.groups.len() > MAX_DROP_GROUPS {
                    return Err(CryptoError::Parameter(format!(
                        "user has {} supplementary groups (max {MAX_DROP_GROUPS})",
                        t.groups.len()
                    )));
                }
                let mut arr = [0 as libc::gid_t; MAX_DROP_GROUPS];
                arr[..t.groups.len()].copy_from_slice(&t.groups);
                Some((arr, t.groups.len(), t.uid, t.gid))
            }
            None => None,
        };
    unsafe {
        use std::os::unix::process::CommandExt;
        command.pre_exec(move || {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::ioctl(ctty_fd, libc::TIOCSCTTY as _, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if let Some((groups, ngroups, uid, gid)) = &drop_in_child {
                if libc::setgroups(*ngroups as _, groups.as_ptr()) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::setgid(*gid) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::setuid(*uid) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                // If we can still regain root, the drop did not stick — abort the
                // exec. Use a raw-errno error (no heap allocation): allocating
                // here, post-fork, could deadlock on the allocator lock held by
                // another parent thread.
                if libc::setuid(0) == 0 {
                    return Err(std::io::Error::from_raw_os_error(libc::EPERM));
                }
            }
            Ok(())
        });
    }
    let mut child = command
        .spawn()
        .map_err(|e| CryptoError::Parameter(format!("spawn shell: {e}")))?;
    // Drop the Command so the parent's copies of the child's stdio (three dups of
    // the pty slave, owned by `command`) are closed; otherwise the slave stays
    // open in this process and the master never reaches EOF when the shell exits.
    drop(command);
    // Close our remaining slave end so the child holds the only slave (the master
    // then sees EOF/EIO once the shell exits and closes its stdio).
    drop(slave);
    // `master` is kept for resize (TIOCSWINSZ); dup it for the blocking
    // reader/writer threads.
    let mut pty_reader = master
        .try_clone()
        .map_err(|e| CryptoError::Parameter(format!("clone pty master (read): {e}")))?;
    let mut pty_writer = master
        .try_clone()
        .map_err(|e| CryptoError::Parameter(format!("clone pty master (write): {e}")))?;

    // Blocking PTY master → async, via a reader thread feeding a channel.
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    std::thread::spawn(move || {
        use std::io::Read;
        let mut buf = [0u8; 32 * 1024];
        loop {
            match pty_reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if out_tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    // Client DATA → PTY master, via a writer thread fed by a channel.
    let (in_tx, mut in_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    std::thread::spawn(move || {
        use std::io::Write;
        while let Some(bytes) = in_rx.blocking_recv() {
            if pty_writer.write_all(&bytes).is_err() || pty_writer.flush().is_err() {
                break;
            }
        }
    });

    // Decode inbound frames in a dedicated task feeding a channel, so the main
    // loop only ever `select!`s over channel receives (which are cancel-safe).
    // Putting `recv_frame` directly in `select!` would drop a partially-read
    // packet whenever the other branch fires, desyncing the stream and failing
    // the next MAC — a client could trigger that just by producing output.
    let (in_frame_tx, mut in_frame_rx) = tokio::sync::mpsc::channel::<Frame>(64);
    let aead_r = aead_name.to_string();
    let rx_key_v = Zeroizing::new(rx_key.to_vec());
    let reader_task = tokio::spawn(async move {
        let mut rx_ctr = rx_ctr;
        while let Ok(Some(f)) = recv_frame(&mut reader, &aead_r, &rx_key_v, &mut rx_ctr).await {
            if in_frame_tx.send(f).await.is_err() {
                break;
            }
        }
    });

    loop {
        tokio::select! {
            chunk = out_rx.recv() => match chunk {
                Some(bytes) => send_frame(&mut writer, aead_name, tx_key, &mut tx_ctr,
                    &Frame::Data(bytes)).await?,
                None => break, // PTY closed (shell exited)
            },
            frame = in_frame_rx.recv() => match frame {
                Some(Frame::Data(d)) => { let _ = in_tx.send(d).await; }
                Some(Frame::Winsz { cols, rows }) => {
                    let ws = libc::winsize {
                        ws_row: rows, ws_col: cols, ws_xpixel: 0, ws_ypixel: 0,
                    };
                    unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ, &ws); }
                }
                Some(Frame::Exit(_)) | Some(Frame::Error(_)) | None => break,
                Some(Frame::Open { .. }) => {} // ignore a duplicate OPEN
            },
        }
    }

    // Always reap the shell. If we are here because the client went away while
    // the shell is still running, kill it so neither the process nor the PTY
    // bridge threads leak (kill on an already-exited child is a harmless no-op).
    reader_task.abort();
    let _ = child.kill();
    let code = tokio::task::spawn_blocking(move || child.wait())
        .await
        .ok()
        .and_then(|r| r.ok())
        .and_then(|s| s.code())
        .unwrap_or(-1);
    audit_best_effort(audit_path, &peer_fp, &format!("session end exit={code}")).await;
    let _ = send_frame(&mut writer, aead_name, tx_key, &mut tx_ctr, &Frame::Exit(code)).await;
    Ok(())
}

#[cfg(not(unix))]
#[allow(clippy::too_many_arguments)]
pub async fn run_pty_server<R, W>(
    _reader: R, _writer: W, _aead_name: &str, _s2c_key: &[u8], _c2s_key: &[u8],
    _peer_fp: [u8; 32], _policy_path: Option<&str>, _audit_path: Option<&str>,
) -> Result<()> {
    Err(CryptoError::Parameter("the P2P shell server is only supported on unix".into()))
}

/// Restores terminal attributes on drop, so a panic or early return never leaves
/// the user's terminal stuck in raw mode.
#[cfg(unix)]
struct RawModeGuard {
    fd: std::os::fd::RawFd,
    orig: libc::termios,
}

#[cfg(unix)]
impl RawModeGuard {
    /// Put `fd` (a tty) into raw mode; returns `None` if `fd` is not a terminal.
    fn enable(fd: std::os::fd::RawFd) -> Option<Self> {
        if unsafe { libc::isatty(fd) } != 1 {
            return None;
        }
        let mut orig: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut orig) } != 0 {
            return None;
        }
        let mut raw = orig;
        unsafe { libc::cfmakeraw(&mut raw) };
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } != 0 {
            return None;
        }
        Some(Self { fd, orig })
    }
}

#[cfg(unix)]
impl Drop for RawModeGuard {
    fn drop(&mut self) {
        unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.orig) };
    }
}

/// Read the controlling terminal's window size, or `(80, 24)` if `fd` is not a
/// tty (e.g. piped input for a scripted session).
#[cfg(unix)]
fn term_size(fd: std::os::fd::RawFd) -> (u16, u16) {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) } == 0 && ws.ws_col > 0 {
        (ws.ws_col, ws.ws_row)
    } else {
        (80, 24)
    }
}

// ===========================================================================
// Optional status bar (`--tui`). tmux-style: reserve the bottom line with a
// DECSTBM scroll region (so the remote PTY, sized one row shorter, never writes
// there) and draw a status line into it with raw ANSI. No alternate screen, no
// extra dependency — it composes with the raw byte passthrough and full-screen
// TUIs (vim/top) and preserves scrollback.
// ===========================================================================


/// How the P2P path is carried (drives the badge colour).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ConnKind {
    /// Connected, exact path not yet known (v1 default).
    #[default]
    P2p,
    /// Direct hole-punched path.
    Direct,
    /// Carried over a relay.
    Relay,
    /// Some streams direct, some relayed.
    Mixed,
}

/// Snapshot of connection info shown on the status line.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ConnStatus {
    pub conn: ConnKind,
    pub latency_ms: Option<u32>,
    pub crypto: String,
    pub node_short: String,
    pub stable: bool,
}

impl ConnStatus {
    fn badge(&self) -> (&'static str, &'static str) {
        match self.conn {
            ConnKind::Direct => ("32", "Direct P2P"), // green
            ConnKind::Relay => ("33", "Via Relay"),   // yellow
            ConnKind::Mixed => ("36", "Mixed"),       // cyan
            ConnKind::P2p => ("36", "P2P"),
        }
    }

    /// Rows the bar needs at width `cols`: one line if everything fits, two
    /// otherwise. The estimate reserves worst-case widths for the *live* fields
    /// (badge label, latency, stability) so a latency/kind update never flips the
    /// line count — only `cols`, the cipher name and the NodeId (all fixed for a
    /// session) do, so the reserved height changes only on an actual resize.
    pub fn height(&self, cols: u16) -> u16 {
        let worst = format!(
            " ●Direct P2P  Latency:8888ms  {}  {}  unstable   exit:Ctrl-D ",
            self.crypto, self.node_short
        );
        if worst.chars().count() <= cols as usize {
            1
        } else {
            2
        }
    }

    /// One reverse-video segment at absolute `row`: clear, no-wrap, draw `body`,
    /// reset, restore wrap. `body` may carry colour SGRs.
    fn bar(row: u16, body: &str) -> String {
        format!("\x1b[{row};1H\x1b[2K\x1b[?7l\x1b[7m{body}\x1b[0m\x1b[?7h")
    }

    /// Neutralize control / bidi / zero-width characters before they reach the
    /// terminal. The displayed fields are local (cipher names) or a hex NodeId, so
    /// this is defense-in-depth, but it guarantees the bar can never inject escape
    /// sequences or reorder the operator's display regardless of their source.
    fn safe_field(s: &str) -> String {
        s.chars()
            .map(|c| {
                if c.is_control()
                    || ('\u{200B}'..='\u{200F}').contains(&c)
                    || ('\u{202A}'..='\u{202E}').contains(&c)
                    || ('\u{2066}'..='\u{2069}').contains(&c)
                {
                    ' '
                } else {
                    c
                }
            })
            .collect()
    }

    /// Build the ANSI to (re)draw the status bar across its 1–2 rows ending at the
    /// terminal's bottom row `rows`, then restore the cursor (the PTY's cursor
    /// lives in the scroll region above, so DECSC/DECRC keeps it put).
    fn render(&self, cols: u16, rows: u16) -> String {
        let (color, label) = self.badge();
        let lat = self.latency_ms.map(|m| format!("{m}ms")).unwrap_or_else(|| "—".into());
        let state = if self.stable { "stable" } else { "unstable" };
        let crypto = Self::safe_field(&self.crypto);
        let node = Self::safe_field(&self.node_short);
        // Colour the badge dot/label, then `\x1b[22;39m` (not-bold, default fg)
        // returns to the bar's reverse video for the rest.
        let badge = format!(" \x1b[{color};1m●{label}\x1b[22;39m");
        if self.height(cols) == 1 {
            let body = format!("{badge}  Latency:{lat}  {crypto}  {node}  {state}   exit:Ctrl-D ");
            format!("\x1b7{}\x1b8", Self::bar(rows, &body))
        } else {
            // Live status on top, static identity on the bottom row.
            let top = format!("{badge}  Latency:{lat}  {state} ");
            let bot = format!(" {crypto}  {node}   exit:Ctrl-D ");
            format!(
                "\x1b7{}{}\x1b8",
                Self::bar(rows.saturating_sub(1), &top),
                Self::bar(rows, &bot),
            )
        }
    }
}

/// Releases the terminal scroll region on drop, so an early return or a panic
/// never leaves the bottom rows reserved. (The normal exit path resets it
/// explicitly too, since `process::exit` skips `Drop`.)
#[cfg(unix)]
struct ScrollRegionGuard;
#[cfg(unix)]
impl Drop for ScrollRegionGuard {
    fn drop(&mut self) {
        use std::io::Write as _;
        let mut o = std::io::stdout();
        let _ = o.write_all(b"\x1b[r"); // DECSTBM reset = whole screen
        let _ = o.flush();
    }
}

/// Client side of a real shell session: announce our terminal, go raw, and pump
/// stdin↔stdout against the remote PTY until the remote shell exits. When
/// `tui_status` is `Some`, reserve the bottom row for a status line.
#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
// allow(too_many_arguments): the secured stream halves + AEAD name + session keys
// + the optional one-shot command + the optional status-bar seed and live metrics
// source are each genuinely needed to drive one client session; bundling them into
// a struct would only move the noise. Future: a SecureChannel type could fold the
// stream halves + keys together.
pub async fn run_pty_client<R, W>(
    mut reader: R,
    writer: W,
    aead_name: &str,
    s2c_key: &[u8],
    c2s_key: &[u8],
    cmd: &str,
    tui_status: Option<ConnStatus>,
    metrics: Option<std::sync::Arc<dyn crate::p2p::ConnMetrics>>,
) -> Result<()>
where
    R: AsyncReadExt + Unpin + Send,
    W: AsyncWriteExt + Unpin + Send + 'static,
{
    use std::os::fd::AsRawFd;
    let stdin_fd = std::io::stdin().as_raw_fd();
    let (cols, rows) = term_size(stdin_fd);
    let term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string());

    // With a status bar, give the remote PTY fewer rows and reserve the bottom
    // 1–2 rows (narrow terminals wrap the bar onto a second line) via a scroll
    // region. Disable if the terminal is too short to spare the rows. The live
    // status is shared so the metrics poller and the SIGWINCH redraw both see the
    // latest values.
    let status: Option<std::sync::Arc<tokio::sync::Mutex<ConnStatus>>> =
        tui_status.map(|s| std::sync::Arc::new(tokio::sync::Mutex::new(s)));
    let status_h = match &status {
        Some(st) => {
            let h = st.lock().await.height(cols);
            if rows > h + 1 { h } else { 0 }
        }
        None => 0,
    };
    // No room (or no bar requested): fully disable the TUI path.
    let status = if status_h > 0 { status } else { None };
    let pty_rows = rows.saturating_sub(status_h).max(1);

    let (rx_key, tx_key) = role_keys(s2c_key, c2s_key, false);
    let tx_key = Zeroizing::new(tx_key.to_vec());
    let aead_owned = aead_name.to_string();
    let (mut rx_ctr, tx_ctr) = (0u64, 0u64);

    // One writer task serializes all outbound frames (DATA from stdin, WINSZ
    // from SIGWINCH) so the send counter stays consistent.
    let (frame_tx, mut frame_rx) = tokio::sync::mpsc::channel::<Frame>(64);
    frame_tx
        .send(Frame::Open { cols, rows: pty_rows, term, cmd: cmd.to_string() })
        .await
        .map_err(|_| CryptoError::Parameter("shell: writer gone".into()))?;
    let writer_task = tokio::spawn(async move {
        let mut writer = writer;
        let mut ctr = tx_ctr;
        while let Some(f) = frame_rx.recv().await {
            if send_frame(&mut writer, &aead_owned, &tx_key, &mut ctr, &f).await.is_err() {
                break;
            }
        }
    });

    // Raw mode for the duration of the session (restored on drop).
    let _raw = RawModeGuard::enable(stdin_fd);

    // Shared stdout: the PTY passthrough and the status redraw both write here, so
    // a lock keeps a status draw (save→move→print→restore) atomic w.r.t. PTY bytes.
    let stdout = std::sync::Arc::new(tokio::sync::Mutex::new(tokio::io::stdout()));

    // TUI: start on a clean screen — clear the viewport and scrollback so the
    // session doesn't append below whatever was already in the terminal — then
    // install the scroll region (top `pty_rows` rows) and draw the bar once. The
    // guard resets the region on a panic / early return (the normal exit path
    // resets it explicitly before `process::exit`).
    let mut _region: Option<ScrollRegionGuard> = None;
    if let Some(st) = &status {
        let bar = st.lock().await.render(cols, rows);
        let mut o = stdout.lock().await;
        // \x1b[2J clear screen, \x1b[3J clear scrollback, \x1b[H home, then the
        // scroll region and the status bar.
        let init = format!("\x1b[2J\x1b[3J\x1b[H\x1b[1;{pty_rows}r{bar}");
        let _ = o.write_all(init.as_bytes()).await;
        let _ = o.flush().await;
        _region = Some(ScrollRegionGuard);
    }

    // Status metrics poller (v2): every second, read the live path (relay/direct +
    // RTT) and, when it changed, update the shared status and redraw. Only spawned
    // when both the bar and a metrics source are present.
    let poll_task = if let (Some(st), Some(m)) = (&status, &metrics) {
        let st = st.clone();
        let m = m.clone();
        let poll_stdout = stdout.clone();
        Some(tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
            loop {
                tick.tick().await;
                let snap = m.snapshot();
                let (cols, rows) = term_size(stdin_fd);
                let bar = {
                    let mut s = st.lock().await;
                    let mut changed = false;
                    if let Some(sn) = snap {
                        let kind = if sn.relay { ConnKind::Relay } else { ConnKind::Direct };
                        if s.conn != kind {
                            s.conn = kind;
                            changed = true;
                        }
                        if s.latency_ms != sn.rtt_ms {
                            s.latency_ms = sn.rtt_ms;
                            changed = true;
                        }
                    }
                    let fits = rows > s.height(cols) + 1;
                    (changed && fits).then(|| s.render(cols, rows))
                };
                if let Some(bar) = bar {
                    let mut o = poll_stdout.lock().await;
                    let _ = o.write_all(bar.as_bytes()).await;
                    let _ = o.flush().await;
                }
            }
        }))
    } else {
        None
    };

    // stdin → DATA frames.
    let stdin_tx = frame_tx.clone();
    let stdin_task = tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match stdin.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if stdin_tx.send(Frame::Data(buf[..n].to_vec())).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    // SIGWINCH → WINSZ frames; with a status bar, recompute the reserved row,
    // reinstall the scroll region, and redraw at the new size.
    let winch_tx = frame_tx.clone();
    let winch_status = status.clone();
    let winch_stdout = stdout.clone();
    let winch_task = tokio::spawn(async move {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
        {
            while sig.recv().await.is_some() {
                let (cols, rows) = term_size(stdin_fd);
                // Recompute the bar height for the new width (1 or 2 rows). The bar
                // only fits when there's a spare row above it; if the window shrank
                // below that, drop the reservation for this size (full-screen scroll
                // region, PTY gets every row) and re-enable it when it grows back —
                // never install a degenerate `\x1b[1;1r` region.
                let h = match &winch_status {
                    Some(st) => st.lock().await.height(cols),
                    None => 0,
                };
                let fits = winch_status.is_some() && h > 0 && rows > h + 1;
                let status_h = if fits { h } else { 0 };
                let pty_rows = rows.saturating_sub(status_h).max(1);
                if winch_tx.send(Frame::Winsz { cols, rows: pty_rows }).await.is_err() {
                    break;
                }
                if let Some(st) = &winch_status {
                    // Redraw with the latest live status at the new geometry.
                    let s = if fits {
                        format!("\x1b[1;{pty_rows}r{}", st.lock().await.render(cols, rows))
                    } else {
                        "\x1b[r".to_string() // too small: release the scroll region
                    };
                    let mut o = winch_stdout.lock().await;
                    let _ = o.write_all(s.as_bytes()).await;
                    let _ = o.flush().await;
                }
            }
        }
    });

    // Main loop: remote PTY output → stdout, until EXIT. A recv/write error breaks
    // (rather than `?`-returning) so the terminal-restoring teardown always runs.
    let exit_code = loop {
        let frame = match recv_frame(&mut reader, aead_name, rx_key, &mut rx_ctr).await {
            Ok(f) => f,
            Err(_) => break 1,
        };
        match frame {
            Some(Frame::Data(d)) => {
                let mut o = stdout.lock().await;
                if o.write_all(&d).await.is_err() || o.flush().await.is_err() {
                    break 1;
                }
            }
            Some(Frame::Exit(code)) => break code,
            Some(Frame::Error(m)) => {
                // Terminal is restored uniformly after the loop; `\r\n` keeps this
                // readable even while still in raw mode.
                eprintln!("\r\n[shell] remote error: {m}");
                break 1;
            }
            None => break 0,
            Some(_) => {}
        }
    };

    // Tear down. We do NOT await the writer task: the stdin task is parked in
    // `tokio::io::stdin().read()`, an OS blocking read that cannot be cancelled, so
    // its cloned frame sender never drops and `writer_task.await` (and even runtime
    // shutdown) would hang until the user happens to press a key. Abort everything,
    // restore the terminal, and exit directly.
    {
        let mut o = stdout.lock().await;
        if status.is_some() {
            // Release the scroll region and clear the (up to two) status rows.
            let reset = format!(
                "\x1b[r\x1b[{};1H\x1b[2K\x1b[{rows};1H\x1b[2K",
                rows.saturating_sub(1)
            );
            let _ = o.write_all(reset.as_bytes()).await;
        }
        let _ = o.flush().await;
    }
    stdin_task.abort();
    winch_task.abort();
    writer_task.abort();
    if let Some(t) = poll_task {
        t.abort();
    }
    drop(frame_tx);
    // Restore the terminal explicitly (its `Drop` would not run after the
    // `process::exit` below).
    drop(_raw);
    if exit_code != 0 {
        eprintln!("\r\n[shell] remote shell exited with code {exit_code}");
    }
    // The session is over and its keys are ephemeral; exit with the remote shell's
    // status (like ssh) rather than returning through a runtime that would block on
    // the un-cancellable stdin read.
    use std::io::Write as _;
    let _ = std::io::stdout().flush();
    std::process::exit(exit_code & 0xff);
}

#[cfg(not(unix))]
pub async fn run_pty_client<R, W>(
    _reader: R, _writer: W, _aead_name: &str, _s2c_key: &[u8], _c2s_key: &[u8], _cmd: &str,
    _tui_status: Option<ConnStatus>,
    _metrics: Option<std::sync::Arc<dyn crate::p2p::ConnMetrics>>,
) -> Result<()> {
    Err(CryptoError::Parameter("the P2P shell client is only supported on unix".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_failure_blocks_only_after_threshold() {
        // Unique NodeId so the process-global map doesn't collide with other tests.
        let node = {
            let mut n = [0u8; 32];
            n[0] = 0xA1;
            n[1..9].copy_from_slice(&(std::process::id() as u64).to_be_bytes());
            n
        };
        // A fresh NodeId is not blocked.
        assert!(!auth_failure_blocked(&node));
        // Below the threshold: still allowed.
        for _ in 0..(AUTH_FAIL_MAX - 1) {
            note_auth_failure(&node);
        }
        assert!(!auth_failure_blocked(&node), "must allow up to the threshold");
        // Reaching the threshold blocks.
        note_auth_failure(&node);
        assert!(auth_failure_blocked(&node), "must block at the threshold");
        // A different NodeId is unaffected (per-peer, not global).
        let mut other = node;
        other[0] = 0xB2;
        assert!(!auth_failure_blocked(&other));
    }

    #[test]
    fn status_render_positions_and_colours() {
        let st = ConnStatus {
            conn: ConnKind::Relay,
            latency_ms: Some(42),
            crypto: "ML-KEM-768+AES-256-GCM".into(),
            node_short: "7f3abc…b191".into(),
            stable: true,
        };
        // Wide terminal → single line at the bottom row.
        assert_eq!(st.height(120), 1);
        let s = st.render(120, 24);
        // Saves the cursor, parks at the bottom row, and restores afterwards.
        assert!(s.starts_with("\x1b7"));
        assert!(s.ends_with("\x1b8"));
        assert!(s.contains("\x1b[24;1H")); // bottom row of a 24-row terminal
        assert!(!s.contains("\x1b[23;1H")); // and only one row used
        // Relay badge is yellow (33) and the dynamic fields are present.
        assert!(s.contains("\x1b[33;1m●Via Relay"));
        assert!(s.contains("Latency:42ms"));
        assert!(s.contains("ML-KEM-768+AES-256-GCM"));
        assert!(s.contains("7f3abc…b191"));
        // Auto-wrap is toggled off then back on around the draw.
        assert!(s.contains("\x1b[?7l") && s.contains("\x1b[?7h"));
    }

    #[test]
    fn status_render_wraps_to_two_lines_when_narrow() {
        let st = ConnStatus {
            conn: ConnKind::Direct,
            latency_ms: Some(7),
            crypto: "ML-KEM-768+AES-256-GCM".into(),
            node_short: "7f3abc…b191".into(),
            stable: true,
        };
        // Narrow terminal → two rows (the bottom two of a 24-row screen).
        assert_eq!(st.height(40), 2);
        let s = st.render(40, 24);
        assert!(s.contains("\x1b[23;1H")); // top status row
        assert!(s.contains("\x1b[24;1H")); // bottom status row
        // Live info on top, identity on the bottom.
        assert!(s.contains("\x1b[32;1m●Direct P2P"));
        assert!(s.contains("Latency:7ms"));
        assert!(s.contains("ML-KEM-768+AES-256-GCM"));
    }

    #[test]
    fn status_render_latency_placeholder_and_colours() {
        let st = ConnStatus {
            conn: ConnKind::Direct,
            latency_ms: None,
            crypto: "x".into(),
            node_short: "n".into(),
            stable: false,
        };
        let s = st.render(120, 10);
        assert!(s.contains("\x1b[32;1m●Direct P2P")); // green badge
        assert!(s.contains("Latency:—")); // unknown latency placeholder
        assert!(s.contains("unstable"));
    }

    #[test]
    fn frame_encode_decode_roundtrip() {
        let frames = vec![
            Frame::Open { cols: 120, rows: 40, term: "xterm".into(), cmd: "ls -la".into() },
            Frame::Open { cols: 80, rows: 24, term: String::new(), cmd: String::new() },
            Frame::Data(vec![0, 1, 2, 255, 254]),
            Frame::Winsz { cols: 200, rows: 50 },
            Frame::Exit(-7),
            Frame::Error("denied".into()),
        ];
        for f in frames {
            let enc = f.encode();
            assert_eq!(Frame::decode(&enc).unwrap(), f);
        }
    }

    #[test]
    fn policy_parse_and_authorize() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.txt");
        let fp_a = "a".repeat(64); // all 0xaa
        let fp_b = "b".repeat(64); // all 0xbb
        std::fs::write(
            &path,
            format!(
                "# comment\n\n{fp_a}  user=alice\n{fp_b} user=deploy cmd-allow=\"systemctl restart x, journalctl -u x\"\n"
            ),
        )
        .unwrap();
        let pol = ShellPolicy::load(path.to_str().unwrap()).unwrap();
        let a = parse_fp_hex(&fp_a).unwrap();
        let b = parse_fp_hex(&fp_b).unwrap();
        let unknown = [0u8; 32];

        // alice: no cmd-allow → login shell and any command allowed.
        assert!(matches!(pol.authorize(&a, ""), PolicyDecision::Allow { .. }));
        assert!(matches!(pol.authorize(&a, "whoami"), PolicyDecision::Allow { .. }));

        // deploy: cmd-allow → only the exact listed commands; no login shell.
        assert!(matches!(pol.authorize(&b, ""), PolicyDecision::Deny(_)));
        assert!(matches!(
            pol.authorize(&b, "systemctl restart x"),
            PolicyDecision::Allow { .. }
        ));
        assert!(matches!(pol.authorize(&b, "rm -rf /"), PolicyDecision::Deny(_)));

        // a fingerprint absent from the policy is denied outright.
        assert!(matches!(pol.authorize(&unknown, ""), PolicyDecision::Deny(_)));

        // the mapped user is surfaced for audit/Phase-2b privilege drop.
        match pol.authorize(&a, "ls") {
            PolicyDecision::Allow { user, .. } => assert_eq!(user.as_deref(), Some("alice")),
            _ => panic!(),
        }
    }

    #[test]
    fn cmd_allow_value_cannot_be_misparsed_as_user() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.txt");
        let fp = "c".repeat(64);
        // A `user=` substring *inside* the cmd-allow value must not become the
        // user mapping (that would map the peer to an unintended local user).
        std::fs::write(
            &path,
            format!("{fp} user=alice cmd-allow=\"echo user=root, id\"\n"),
        )
        .unwrap();
        let pol = ShellPolicy::load(path.to_str().unwrap()).unwrap();
        let f = parse_fp_hex(&fp).unwrap();
        match pol.authorize(&f, "echo user=root") {
            PolicyDecision::Allow { user, .. } => assert_eq!(user.as_deref(), Some("alice")),
            _ => panic!("the exact allowed command should be permitted"),
        }
    }

    #[test]
    fn malformed_cmd_allow_is_rejected_not_silently_unrestricted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.txt");
        let fp = "d".repeat(64);
        // Missing quotes on cmd-allow must error, not silently drop the limit.
        std::fs::write(&path, format!("{fp} user=x cmd-allow=echo\n")).unwrap();
        assert!(ShellPolicy::load(path.to_str().unwrap()).is_err());
    }

    #[test]
    fn fp_hex_parse_roundtrip() {
        let fp = [0x0fu8; 32];
        assert_eq!(parse_fp_hex(&fp_hex(&fp)), Some(fp));
        assert_eq!(parse_fp_hex("xyz"), None);
        assert_eq!(parse_fp_hex(&"a".repeat(63)), None);
    }

    #[test]
    fn decode_rejects_truncated_open() {
        assert!(Frame::decode(&[T_OPEN, 0, 80]).is_err());
        assert!(Frame::decode(&[]).is_err());
        assert!(Frame::decode(&[0x99]).is_err());
    }

    #[tokio::test]
    async fn secure_frame_roundtrip_over_duplex() {
        let aead = "AES-256-GCM";
        let s2c = vec![7u8; 32];
        let c2s = vec![9u8; 32];
        let (mut a, mut b) = tokio::io::duplex(65536);

        // Client (sender) seals under c2s; server (receiver) opens with c2s.
        // Two frames to confirm the counter advances in lockstep.
        let (mut tx, mut rx) = (0u64, 0u64);
        let f1 = Frame::Data(b"secure hello".to_vec());
        let f2 = Frame::Winsz { cols: 100, rows: 30 };
        send_frame(&mut a, aead, &c2s, &mut tx, &f1).await.unwrap();
        send_frame(&mut a, aead, &c2s, &mut tx, &f2).await.unwrap();
        assert_eq!(recv_frame(&mut b, aead, &c2s, &mut rx).await.unwrap(), Some(f1));
        assert_eq!(recv_frame(&mut b, aead, &c2s, &mut rx).await.unwrap(), Some(f2));
        assert_eq!((tx, rx), (2, 2));
        let _ = &s2c;
    }

    #[tokio::test]
    async fn replayed_or_reordered_packet_fails_auth() {
        let aead = "AES-256-GCM";
        let key = vec![5u8; 32];
        let (mut a, mut b) = tokio::io::duplex(65536);
        let mut tx = 0u64;
        send_frame(&mut a, aead, &key, &mut tx, &Frame::Data(b"x".to_vec())).await.unwrap();
        // Receiver expects counter 1 (e.g. this packet is a replay of an earlier
        // one, or arrived out of order): the derived nonce differs → AEAD fails.
        let mut rx = 1u64;
        assert!(recv_frame(&mut b, aead, &key, &mut rx).await.is_err());
    }

    #[tokio::test]
    async fn echo_server_and_client_roundtrip() {
        let aead = "AES-256-GCM";
        let s2c = vec![1u8; 32];
        let c2s = vec![2u8; 32];
        // Two duplex pipes: client→server and server→client.
        let (c_tx, s_rx) = tokio::io::duplex(65536); // client writes, server reads
        let (s_tx, c_rx) = tokio::io::duplex(65536); // server writes, client reads

        let (s2c_s, c2s_s) = (s2c.clone(), c2s.clone());
        let server = tokio::spawn(async move {
            run_echo_server(s_rx, s_tx, aead, &s2c_s, &c2s_s).await
        });

        let input = std::io::Cursor::new(b"line-one\nline-two\n".to_vec());
        let mut out: Vec<u8> = Vec::new();
        run_echo_client(c_rx, c_tx, aead, &s2c, &c2s, input, &mut out)
            .await
            .unwrap();
        assert_eq!(out, b"line-one\nline-two\n");
        server.await.unwrap().unwrap();
    }
}
