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

/// Seal `frame` under `key` with the nonce derived from `ctr` (incremented on
/// success) and write it as one length-prefixed AEAD packet (`ct ‖ tag`).
pub async fn send_frame<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    aead_name: &str,
    key: &[u8],
    ctr: &mut u64,
    frame: &Frame,
) -> Result<()> {
    let nonce = nonce_from_ctr(*ctr);
    let pt = Zeroizing::new(frame.encode());
    let mut aead = backend::new_encrypt(aead_name, key, &nonce)?;
    let mut ct = Zeroizing::new(vec![0u8; pt.len() + 32]);
    let n = aead.update(&pt, &mut ct)?;
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
        CryptoError::Parameter("shell send counter overflow".to_string())
    })?;
    Ok(())
}

/// Read one length-prefixed AEAD packet, decrypt under `key` with the nonce
/// derived from `ctr` (incremented on success), and decode the [`Frame`].
/// Returns `Ok(None)` on a clean stream close (zero-length frame or EOF). A
/// replayed/reordered/tampered packet decrypts under the wrong counter-nonce and
/// surfaces as an authentication error.
pub async fn recv_frame<R: AsyncReadExt + Unpin>(
    r: &mut R,
    aead_name: &str,
    key: &[u8],
    ctr: &mut u64,
) -> Result<Option<Frame>> {
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
        return Err(CryptoError::Parameter(format!("shell packet size {len} out of range")));
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
        CryptoError::Parameter("shell recv counter overflow".to_string())
    })?;
    Frame::decode(&out[..n + fin]).map(Some)
}

fn io_err(e: std::io::Error) -> CryptoError {
    CryptoError::FileRead(e.to_string())
}

/// Pick `(rx_key, tx_key)` from the session keys for our role, matching
/// `chat_loop`: the server receives on c2s and sends on s2c.
fn role_keys<'a>(s2c: &'a [u8], c2s: &'a [u8], is_server: bool) -> (&'a [u8], &'a [u8]) {
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

fn parse_fp_hex(s: &str) -> Option<[u8; 32]> {
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
fn extract_kv<'a>(rest: &'a str, key: &str) -> Option<&'a str> {
    let i = rest.find(key)? + key.len();
    let v = &rest[i..];
    Some(v.split(char::is_whitespace).next().unwrap_or(v))
}

/// Extract the double-quoted value of `key` (e.g. `cmd-allow="a,b"`) from `rest`,
/// returning the value plus the `[start, end)` byte span of the whole
/// `key="..."` match so the caller can excise it.
fn extract_quoted_span(rest: &str, key: &str) -> Option<(String, usize, usize)> {
    let key_at = rest.find(key)?;
    let after = rest[key_at + key.len()..].strip_prefix('"')?;
    let close = after.find('"')?;
    let value = after[..close].to_string();
    let end = key_at + key.len() + 1 + close + 1; // past the closing quote
    Some((value, key_at, end))
}

/// Hex of a fingerprint, for policy lookup logging / audit.
fn fp_hex(fp: &[u8; 32]) -> String {
    fp.iter().map(|b| format!("{b:02x}")).collect()
}

/// Per-fingerprint connection rate limit: reject a new shell within
/// `SHELL_RATE_WINDOW` of the previous attempt by the same fingerprint.
const SHELL_RATE_WINDOW: std::time::Duration = std::time::Duration::from_secs(2);

fn rate_limited(fp: &[u8; 32]) -> bool {
    use std::sync::Mutex;
    use std::time::Instant;
    static LAST: Mutex<Option<std::collections::HashMap<[u8; 32], Instant>>> = Mutex::new(None);
    // Recover from a poisoned lock instead of propagating the panic, so one
    // panicking caller can't wedge rate limiting (and thus all shell auth) for
    // the life of the process.
    let mut guard = LAST.lock().unwrap_or_else(|e| e.into_inner());
    let map = guard.get_or_insert_with(std::collections::HashMap::new);
    let now = Instant::now();
    // Evict entries past the window so the map stays bounded by the number of
    // fingerprints active *within* the window (a flood of distinct fingerprints
    // can't grow it without bound).
    map.retain(|_, t| now.duration_since(*t) < SHELL_RATE_WINDOW);
    if map.contains_key(fp) {
        return true;
    }
    map.insert(*fp, now);
    false
}

/// Append one line to the audit log, off the async runtime thread. Returns the
/// I/O result so a security-relevant record (the allow/deny decision) can be
/// made *fail-closed* by the caller; best-effort records ignore it.
async fn audit(path: Option<&str>, fp: &[u8; 32], event: &str) -> std::io::Result<()> {
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
async fn audit_best_effort(path: Option<&str>, fp: &[u8; 32], event: &str) {
    if let Err(e) = audit(path, fp, event).await {
        eprintln!("[shell] audit write failed for {event:?}: {e}");
    }
}

// ===========================================================================
// Phase 1: single-user PTY bridge (unix). The server allocates a PTY and runs
// the operator's shell as *its own* user (per-user mapping / privilege drop is
// Phase 2b); the client puts its terminal in raw mode and pumps both directions.
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
    use portable_pty::{native_pty_system, CommandBuilder, PtySize};

    let (rx_key, tx_key) = role_keys(s2c_key, c2s_key, true);
    let (mut rx_ctr, mut tx_ctr) = (0u64, 0u64);

    // Per-fingerprint rate limit before doing any work.
    if rate_limited(&peer_fp) {
        audit_best_effort(audit_path, &peer_fp, "deny: rate limited").await;
        let _ = send_frame(&mut writer, aead_name, tx_key, &mut tx_ctr,
            &Frame::Error("rate limited; try again shortly".into())).await;
        return Err(CryptoError::Parameter("shell: rate limited".into()));
    }

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
            format!("allow (no policy) cmd={}", if cmd.is_empty() { "<login>" } else { cmd.as_str() }),
        ),
    };
    let run_cmd = allow_event.0;
    if let Err(e) = audit(audit_path, &peer_fp, &allow_event.1).await {
        let _ = send_frame(&mut writer, aead_name, tx_key, &mut tx_ctr,
            &Frame::Error("audit log unavailable; refusing".into())).await;
        return Err(CryptoError::Parameter(format!("shell refused: audit write failed: {e}")));
    }

    let pair = native_pty_system()
        .openpty(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 })
        .map_err(|e| CryptoError::Parameter(format!("openpty: {e}")))?;

    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
    let mut builder = CommandBuilder::new(&shell);
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
    builder.env("TERM", &safe_term);
    if run_cmd.is_empty() {
        builder.arg("-l"); // login shell
    } else {
        builder.arg("-c");
        builder.arg(&run_cmd);
    }
    let mut child = pair
        .slave
        .spawn_command(builder)
        .map_err(|e| CryptoError::Parameter(format!("spawn shell: {e}")))?;
    drop(pair.slave); // close our copy so the child holds the only slave end

    let mut pty_reader = pair
        .master
        .try_clone_reader()
        .map_err(|e| CryptoError::Parameter(format!("pty reader: {e}")))?;
    let mut pty_writer = pair
        .master
        .take_writer()
        .map_err(|e| CryptoError::Parameter(format!("pty writer: {e}")))?;

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
        loop {
            match recv_frame(&mut reader, &aead_r, &rx_key_v, &mut rx_ctr).await {
                Ok(Some(f)) => {
                    if in_frame_tx.send(f).await.is_err() {
                        break;
                    }
                }
                Ok(None) | Err(_) => break,
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
                    let _ = pair.master.resize(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 });
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
        .map(|s| s.exit_code() as i32)
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

/// Client side of a real shell session: announce our terminal, go raw, and pump
/// stdin↔stdout against the remote PTY until the remote shell exits.
#[cfg(unix)]
pub async fn run_pty_client<R, W>(
    mut reader: R,
    writer: W,
    aead_name: &str,
    s2c_key: &[u8],
    c2s_key: &[u8],
    cmd: &str,
) -> Result<()>
where
    R: AsyncReadExt + Unpin + Send,
    W: AsyncWriteExt + Unpin + Send + 'static,
{
    use std::os::fd::AsRawFd;
    let stdin_fd = std::io::stdin().as_raw_fd();
    let (cols, rows) = term_size(stdin_fd);
    let term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string());

    let (rx_key, tx_key) = role_keys(s2c_key, c2s_key, false);
    let tx_key = Zeroizing::new(tx_key.to_vec());
    let aead_owned = aead_name.to_string();
    let (mut rx_ctr, tx_ctr) = (0u64, 0u64);

    // One writer task serializes all outbound frames (DATA from stdin, WINSZ
    // from SIGWINCH) so the send counter stays consistent.
    let (frame_tx, mut frame_rx) = tokio::sync::mpsc::channel::<Frame>(64);
    frame_tx
        .send(Frame::Open { cols, rows, term, cmd: cmd.to_string() })
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

    // SIGWINCH → WINSZ frames.
    let winch_tx = frame_tx.clone();
    let winch_task = tokio::spawn(async move {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
        {
            while sig.recv().await.is_some() {
                let (cols, rows) = term_size(stdin_fd);
                if winch_tx.send(Frame::Winsz { cols, rows }).await.is_err() {
                    break;
                }
            }
        }
    });

    // Main loop: remote PTY output → stdout, until EXIT.
    let mut stdout = tokio::io::stdout();
    let exit_code = loop {
        match recv_frame(&mut reader, aead_name, rx_key, &mut rx_ctr).await? {
            Some(Frame::Data(d)) => {
                stdout.write_all(&d).await.map_err(io_err)?;
                stdout.flush().await.map_err(io_err)?;
            }
            Some(Frame::Exit(code)) => break code,
            Some(Frame::Error(m)) => {
                drop(_raw);
                eprintln!("\r\n[shell] remote error: {m}");
                break 1;
            }
            None => break 0,
            Some(_) => {}
        }
    };

    stdin_task.abort();
    winch_task.abort();
    drop(frame_tx);
    let _ = writer_task.await;
    if exit_code != 0 {
        eprintln!("\r\n[shell] remote shell exited with code {exit_code}");
    }
    Ok(())
}

#[cfg(not(unix))]
pub async fn run_pty_client<R, W>(
    _reader: R, _writer: W, _aead_name: &str, _s2c_key: &[u8], _c2s_key: &[u8], _cmd: &str,
) -> Result<()> {
    Err(CryptoError::Parameter("the P2P shell client is only supported on unix".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

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
