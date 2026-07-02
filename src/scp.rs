/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

//! P2P scp (`nkct/scp/1`) — bastion-less PQC file transfer. See `P2P_SCP_DESIGN.md`.
//!
//! A third service ALPN alongside the PTY shell (`nkct/shell/1`) and the
//! port-forward (`nkct/fwd/1`). Where the legacy `ALPN_FILE` stream was a raw
//! one-way byte push with no remote-path selection or authorization, this offers
//! `scp`-style **get / put** with a per-fingerprint read/write policy and path
//! confinement.
//!
//! Wire framing reuses the shared AEAD packet primitive
//! ([`crate::shell::send_packet`] / [`recv_packet`]): each [`ScpFrame`] is one
//! AEAD packet sealed under the per-direction session key with a monotonic
//! counter nonce, so truncation / reorder / tamper surfaces as an
//! authentication failure. Bulk bytes are chunked to [`CHUNK`].
//!
//! Security posture (this increment): single-file get/put only; `user=` in the
//! policy is parsed and audited but **not enforced** (no per-request privilege
//! drop yet), so `--serve-scp` refuses to run as root and every file operation
//! runs as the server's own user, confined to the policy's read/write roots.
//! Directory recursion (`-r`) is a documented follow-up.

use crate::error::{CryptoError, Result};
use crate::shell::{
    audit, audit_best_effort, extract_kv, extract_quoted_span, io_err, parse_fp_hex, rate_limited,
    recv_packet, role_keys, send_packet,
};
use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

/// Bulk-data chunk size. One `Data` frame is `1 (type) + CHUNK` plaintext, which
/// must stay under the reader's `MAX_PACKET` (128 KiB) after the AEAD tag.
const CHUNK: usize = 64 * 1024;

const T_PUT: u8 = 0x01;
const T_GET: u8 = 0x02;
const T_META: u8 = 0x03;
const T_DATA: u8 = 0x04;
const T_EOF: u8 = 0x05;
const T_OK: u8 = 0x06;
const T_ERR: u8 = 0x07;

/// One control/data frame exchanged over `ALPN_SCP`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScpFrame {
    /// Client → server: write `size` bytes (mode `mode`) to `path`.
    Put { path: String, mode: u32, size: u64 },
    /// Client → server: read `path`.
    Get { path: String },
    /// Server → client: `Get` response header.
    Meta { mode: u32, size: u64 },
    /// Either direction: bulk file bytes (≤ [`CHUNK`] per frame).
    Data(Vec<u8>),
    /// Sender → receiver: end of the byte stream.
    Eof,
    /// Responder: the operation succeeded (terminal).
    Ok,
    /// Either direction: a textual error (authz denied, I/O failure, …).
    Err(String),
}

impl ScpFrame {
    /// Serialize to the plaintext that goes inside one AEAD packet.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::new();
        match self {
            ScpFrame::Put { path, mode, size } => {
                v.push(T_PUT);
                v.extend_from_slice(&mode.to_be_bytes());
                v.extend_from_slice(&size.to_be_bytes());
                v.extend_from_slice(&(path.len() as u32).to_be_bytes());
                v.extend_from_slice(path.as_bytes());
            }
            ScpFrame::Get { path } => {
                v.push(T_GET);
                v.extend_from_slice(&(path.len() as u32).to_be_bytes());
                v.extend_from_slice(path.as_bytes());
            }
            ScpFrame::Meta { mode, size } => {
                v.push(T_META);
                v.extend_from_slice(&mode.to_be_bytes());
                v.extend_from_slice(&size.to_be_bytes());
            }
            ScpFrame::Data(d) => {
                v.push(T_DATA);
                v.extend_from_slice(d);
            }
            ScpFrame::Eof => v.push(T_EOF),
            ScpFrame::Ok => v.push(T_OK),
            ScpFrame::Err(m) => {
                v.push(T_ERR);
                v.extend_from_slice(m.as_bytes());
            }
        }
        v
    }

    /// Parse a frame from one packet's plaintext. Every length is bounds-checked
    /// against the buffer so a malformed frame is a clean error, never a panic.
    pub fn decode(buf: &[u8]) -> Result<ScpFrame> {
        let bad = || CryptoError::Parameter("malformed scp frame".to_string());
        let (&ty, rest) = buf.split_first().ok_or_else(bad)?;
        match ty {
            T_PUT => {
                if rest.len() < 16 {
                    return Err(bad());
                }
                let mode = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);
                let size = u64::from_be_bytes(rest[4..12].try_into().map_err(|_| bad())?);
                let plen = u32::from_be_bytes([rest[12], rest[13], rest[14], rest[15]]) as usize;
                let rest = &rest[16..];
                if rest.len() < plen {
                    return Err(bad());
                }
                let path = std::str::from_utf8(&rest[..plen]).map_err(|_| bad())?.to_string();
                Ok(ScpFrame::Put { path, mode, size })
            }
            T_GET => {
                if rest.len() < 4 {
                    return Err(bad());
                }
                let plen = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
                let rest = &rest[4..];
                if rest.len() < plen {
                    return Err(bad());
                }
                let path = std::str::from_utf8(&rest[..plen]).map_err(|_| bad())?.to_string();
                Ok(ScpFrame::Get { path })
            }
            T_META => {
                if rest.len() < 12 {
                    return Err(bad());
                }
                let mode = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);
                let size = u64::from_be_bytes(rest[4..12].try_into().map_err(|_| bad())?);
                Ok(ScpFrame::Meta { mode, size })
            }
            T_DATA => Ok(ScpFrame::Data(rest.to_vec())),
            T_EOF => Ok(ScpFrame::Eof),
            T_OK => Ok(ScpFrame::Ok),
            T_ERR => Ok(ScpFrame::Err(String::from_utf8_lossy(rest).into_owned())),
            _ => Err(CryptoError::Parameter(format!("unknown scp frame type {ty}"))),
        }
    }
}

async fn send(w: &mut (impl AsyncWriteExt + Unpin), aead: &str, key: &[u8], ctr: &mut u64, f: &ScpFrame) -> Result<()> {
    let pt = Zeroizing::new(f.encode());
    send_packet(w, aead, key, ctr, &pt).await
}

async fn recv(r: &mut (impl AsyncReadExt + Unpin), aead: &str, key: &[u8], ctr: &mut u64) -> Result<Option<ScpFrame>> {
    match recv_packet(r, aead, key, ctr).await? {
        Some(pt) => Ok(Some(ScpFrame::decode(&pt)?)),
        None => Ok(None),
    }
}

/// After a terminal frame, keep the connection alive until the peer has drained
/// the response and closed its send side (bounded). Returning immediately would
/// drop the stream and reset it with bulk data still in flight — the peer would
/// see "connection lost" mid-read. The client closes (or acks-then-closes) only
/// once it has fully received and committed, so an EOF here means safe delivery.
async fn drain_until_close(reader: &mut (impl AsyncReadExt + Unpin)) {
    // Hard 10s cap on the whole wait (not reset per byte), so a client that
    // trickles bytes without closing cannot pin a connection slot / fd for long.
    // Well-behaved clients ack-and-close within milliseconds.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let mut b = [0u8; 256];
        loop {
            match reader.read(&mut b).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    })
    .await;
}

// ===========================================================================
// Policy: per-fingerprint read/write roots. Default deny.
// ===========================================================================

/// `fingerprint → (read roots, write roots, user)`. A fingerprint absent from
/// the policy is denied outright.
pub struct ScpPolicy {
    read: HashMap<[u8; 32], Vec<PathBuf>>,
    write: HashMap<[u8; 32], Vec<PathBuf>>,
    #[allow(dead_code)] // parsed + audited now; enforced (privilege drop) in a follow-up.
    user: HashMap<[u8; 32], String>,
}

impl ScpPolicy {
    /// Parse a policy file. Each non-blank, non-`#` line is
    /// `<sha3-256-hex> read="r1, r2" write="w1" [user=NAME]`; at least one of
    /// `read=` / `write=` is required.
    pub fn load(path: &str) -> Result<Self> {
        let err = |lineno: usize, m: String| {
            CryptoError::Parameter(format!("scp policy line {}: {m}", lineno + 1))
        };
        let text = std::fs::read_to_string(path)
            .map_err(|e| CryptoError::Parameter(format!("read scp policy {path}: {e}")))?;
        let mut read = HashMap::new();
        let mut write = HashMap::new();
        let mut user = HashMap::new();
        for (lineno, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut it = line.splitn(2, char::is_whitespace);
            let fp_hex = it.next().unwrap_or("");
            let fp = parse_fp_hex(fp_hex)
                .ok_or_else(|| err(lineno, "bad SHA3-256 fingerprint".into()))?;
            let mut rest = it.next().unwrap_or("").to_string();

            // Excise each quoted span before scanning for `user=`, so a `user=`
            // inside a path can never be mistaken for the user mapping.
            let read_roots = take_root_list(&mut rest, "read=", lineno, &err)?;
            let write_roots = take_root_list(&mut rest, "write=", lineno, &err)?;
            if read_roots.is_none() && write_roots.is_none() {
                return Err(err(lineno, "expected read=\"...\" and/or write=\"...\"".into()));
            }
            if let Some(r) = read_roots {
                read.insert(fp, r);
            }
            if let Some(w) = write_roots {
                write.insert(fp, w);
            }
            if let Some(u) = extract_kv(&rest, "user=") {
                user.insert(fp, u.to_string());
            }
        }
        Ok(Self { read, write, user })
    }

    fn roots(&self, fp: &[u8; 32], write: bool) -> &[PathBuf] {
        let map = if write { &self.write } else { &self.read };
        map.get(fp).map(Vec::as_slice).unwrap_or(&[])
    }
}

/// Pull a quoted, comma-separated root list for `key` out of `rest`, removing its
/// span. Each root is **canonicalized once here** (symlinks resolved), so
/// per-request confinement is a pure `starts_with` with no repeated I/O and a
/// stable notion of the root. A root that does not resolve is skipped with a
/// warning (fail closed — that root simply grants nothing). `Ok(None)` if the key
/// is absent; an error if present but malformed, or if every root was
/// unresolvable (rather than silently dropping the whole restriction).
fn take_root_list(
    rest: &mut String,
    key: &str,
    lineno: usize,
    err: &impl Fn(usize, String) -> CryptoError,
) -> Result<Option<Vec<PathBuf>>> {
    match extract_quoted_span(rest, key) {
        Some((value, start, end)) => {
            let raw: Vec<&str> = value.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
            *rest = format!("{}{}", &rest[..start], &rest[end..]);
            if raw.is_empty() {
                return Err(err(lineno, format!("{key} has no roots")));
            }
            let roots: Vec<PathBuf> = raw
                .iter()
                .filter_map(|s| match std::fs::canonicalize(s) {
                    Ok(p) => Some(p),
                    Err(e) => {
                        eprintln!("[scp] policy line {}: {key} root {s:?} skipped (unresolvable: {e})", lineno + 1);
                        None
                    }
                })
                .collect();
            if roots.is_empty() {
                return Err(err(lineno, format!("{key} has no resolvable roots")));
            }
            Ok(Some(roots))
        }
        None if rest.contains(key) => {
            Err(err(lineno, format!("malformed {key} (expected {key}\"...\")")))
        }
        None => Ok(None),
    }
}

// ===========================================================================
// Path confinement.
// ===========================================================================

/// True when `canon` is one of `roots` or a descendant (component-wise). `roots`
/// are already canonical (resolved at policy load), so this does no I/O.
fn under_any(canon: &Path, roots: &[PathBuf]) -> bool {
    roots.iter().any(|r| canon.starts_with(r))
}

/// The kernel's fully symlink-resolved path of an open fd, via `/proc/self/fd`
/// (Linux). Used to re-verify **after open** that the opened inode is still under
/// a policy root: `confine_*` canonicalizes at check time and `O_NOFOLLOW` guards
/// only the final component, so an attacker who swaps an *intermediate* directory
/// for a symlink between check and open could otherwise escape the root. The
/// post-open path reflects what the kernel actually traversed, closing that race.
#[cfg(target_os = "linux")]
fn fd_real_path(fd: std::os::fd::RawFd) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/self/fd/{fd}")).ok()
}

/// Confine a `Get` request: the path must be absolute, resolve (symlinks and all)
/// to a real file under one of `roots`.
fn confine_read(req: &str, roots: &[PathBuf]) -> std::result::Result<PathBuf, String> {
    let p = Path::new(req);
    if !p.is_absolute() {
        return Err("path must be absolute".into());
    }
    let canon = std::fs::canonicalize(p).map_err(|e| format!("resolve path: {e}"))?;
    if !under_any(&canon, roots) {
        return Err("path is not under any read root".into());
    }
    Ok(canon)
}

/// Confine a `Put` request: the path must be absolute; its *parent* must resolve
/// to a directory under one of `roots`, and the file name must be a single plain
/// component (no `/`, no `.`/`..`). The file itself need not exist.
fn confine_write(req: &str, roots: &[PathBuf]) -> std::result::Result<PathBuf, String> {
    let p = Path::new(req);
    if !p.is_absolute() {
        return Err("path must be absolute".into());
    }
    let parent = p.parent().ok_or("path has no parent directory")?;
    let name = p.file_name().ok_or("path has no file name")?;
    // The file name must be exactly one normal component.
    let is_plain = Path::new(name)
        .components()
        .eq([Component::Normal(name)]);
    if !is_plain {
        return Err("file name must be a single plain component".into());
    }
    let canon_parent = std::fs::canonicalize(parent).map_err(|e| format!("resolve parent dir: {e}"))?;
    if !under_any(&canon_parent, roots) {
        return Err("destination directory is not under any write root".into());
    }
    Ok(canon_parent.join(name))
}

// ===========================================================================
// Staging: write to a hardened temp, commit with an atomic same-dir rename so an
// interrupted / unauthenticated transfer never leaves bytes at the final path.
// ===========================================================================

struct Staged {
    temp: PathBuf,
    final_path: PathBuf,
    file: Option<tokio::fs::File>,
}

impl Staged {
    /// Create `.{name}.tmp.{rand}` next to `final_path`, exclusively and (on unix)
    /// `O_NOFOLLOW` + mode 0600, so a pre-planted symlink can't redirect the write.
    fn create(final_path: PathBuf) -> std::io::Result<Self> {
        use rand_core::RngCore;
        let fname = final_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("recv");
        let temp_name = format!(".{}.tmp.{:016x}", fname, rand_core::OsRng.next_u64());
        let temp = match final_path.parent() {
            Some(dir) if !dir.as_os_str().is_empty() => dir.join(temp_name),
            _ => PathBuf::from(temp_name),
        };
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let std_file = opts.open(&temp)?;
        Ok(Self {
            temp,
            final_path,
            file: Some(tokio::fs::File::from_std(std_file)),
        })
    }

    async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.file.as_mut().expect("staged file open").write_all(buf).await
    }

    /// The real directory the staging fd actually lives in (Linux), for a
    /// post-create confinement re-check against intermediate-symlink swaps.
    #[cfg(target_os = "linux")]
    fn temp_real_parent(&self) -> Option<PathBuf> {
        use std::os::fd::AsRawFd;
        let fd = self.file.as_ref()?.as_raw_fd();
        fd_real_path(fd)?.parent().map(Path::to_path_buf)
    }

    /// fsync, apply `mode`, then atomically rename onto the final path. Consumes
    /// the handle.
    ///
    /// Permissions are applied **on the open file descriptor** (`fchmod`), never
    /// via a path lookup after the file is closed: a path-based
    /// `set_permissions(temp)` could be redirected by a local attacker who swaps
    /// the temp for a symlink between close and chmod (TOCTOU), chmod'ing an
    /// unrelated file. The mode is masked to `0o0777` so **setuid / setgid /
    /// sticky are stripped** — an uploaded (server) or downloaded (client) file
    /// can never carry a privilege-escalation bit chosen by the peer.
    async fn commit(mut self, mode: u32) -> std::io::Result<()> {
        if let Some(f) = self.file.as_mut() {
            f.flush().await?;
            f.sync_all().await?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perm = std::fs::Permissions::from_mode(mode & 0o0777);
                f.set_permissions(perm).await?; // fchmod on the fd, not the path
            }
        }
        // Close the handle before the rename (Windows requires it); on unix the
        // fchmod above already landed on this same inode.
        let _ = self.file.take();
        std::fs::rename(&self.temp, &self.final_path)
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        // Any staging file still present at drop was never committed: discard it
        // so unauthenticated / partial bytes are not left behind.
        let _ = self.file.take();
        let _ = std::fs::remove_file(&self.temp);
    }
}

/// Read a local file's permission bits (unix), or a sane default elsewhere.
fn local_mode(path: &Path) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(path).map(|m| m.mode()).unwrap_or(0o644)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        0o644
    }
}

// ===========================================================================
// Client
// ===========================================================================

/// What the scp client was asked to do.
pub enum ScpOp {
    /// Upload `local` to remote `remote`.
    Put { local: PathBuf, remote: String },
    /// Download remote `remote` to `local`.
    Get { remote: String, local: PathBuf },
}

/// Run the scp client: perform a single `Put` or `Get` against the peer's
/// `--serve-scp` server, then return.
pub async fn run_scp_client<R, W>(
    mut reader: R,
    mut writer: W,
    aead_name: &str,
    s2c_key: &[u8],
    c2s_key: &[u8],
    op: &ScpOp,
) -> Result<()>
where
    R: AsyncReadExt + Unpin + Send,
    W: AsyncWriteExt + Unpin + Send,
{
    // rx_key/tx_key are borrows into the caller's session keys (owned and
    // zeroized by the handshake code); no owned copy is made here.
    let (rx_key, tx_key) = role_keys(s2c_key, c2s_key, false);
    let (mut rx, mut tx) = (0u64, 0u64);

    match op {
        ScpOp::Put { local, remote } => {
            let meta = std::fs::metadata(local)
                .map_err(|e| CryptoError::Parameter(format!("open {}: {e}", local.display())))?;
            if !meta.is_file() {
                return Err(CryptoError::Parameter(format!("{} is not a regular file", local.display())));
            }
            let mode = local_mode(local);
            let size = meta.len();
            send(&mut writer, aead_name, tx_key, &mut tx, &ScpFrame::Put {
                path: remote.clone(),
                mode,
                size,
            })
            .await?;

            let mut f = tokio::fs::File::open(local)
                .await
                .map_err(|e| CryptoError::Parameter(format!("open {}: {e}", local.display())))?;
            // Read straight into the frame plaintext buffer ([T_DATA] ‖ payload)
            // and seal it in place — no per-chunk Data(to_vec()) + encode() copy.
            let mut pt = vec![0u8; 1 + CHUNK];
            pt[0] = T_DATA;
            loop {
                let n = f.read(&mut pt[1..]).await.map_err(io_err)?;
                if n == 0 {
                    break;
                }
                send_packet(&mut writer, aead_name, tx_key, &mut tx, &pt[..1 + n]).await?;
            }
            send(&mut writer, aead_name, tx_key, &mut tx, &ScpFrame::Eof).await?;

            match recv(&mut reader, aead_name, rx_key, &mut rx).await? {
                Some(ScpFrame::Ok) => {
                    let _ = writer.shutdown().await;
                    eprintln!("[nkct] uploaded {} ({} bytes) → {}", local.display(), size, remote);
                    Ok(())
                }
                Some(ScpFrame::Err(m)) => Err(CryptoError::Parameter(format!("scp put refused: {m}"))),
                other => Err(CryptoError::Parameter(format!("scp put: unexpected reply {other:?}"))),
            }
        }
        ScpOp::Get { remote, local } => {
            send(&mut writer, aead_name, tx_key, &mut tx, &ScpFrame::Get { path: remote.clone() }).await?;

            let (mode, size) = match recv(&mut reader, aead_name, rx_key, &mut rx).await? {
                Some(ScpFrame::Meta { mode, size }) => (mode, size),
                Some(ScpFrame::Err(m)) => return Err(CryptoError::Parameter(format!("scp get refused: {m}"))),
                other => return Err(CryptoError::Parameter(format!("scp get: unexpected reply {other:?}"))),
            };

            let mut staged = Staged::create(local.clone())
                .map_err(|e| CryptoError::Parameter(format!("stage {}: {e}", local.display())))?;
            let mut received = 0u64;
            loop {
                match recv(&mut reader, aead_name, rx_key, &mut rx).await? {
                    Some(ScpFrame::Data(d)) => {
                        received += d.len() as u64;
                        // Bound the local write by the size the server declared in
                        // Meta, so a misbehaving/compromised server cannot overrun
                        // our disk past what we agreed to receive.
                        if received > size {
                            return Err(CryptoError::Parameter(format!(
                                "scp get: server sent more than the declared {size} bytes"
                            )));
                        }
                        staged.write_all(&d).await.map_err(io_err)?;
                    }
                    Some(ScpFrame::Eof) => break,
                    Some(ScpFrame::Err(m)) => return Err(CryptoError::Parameter(format!("scp get failed: {m}"))),
                    other => return Err(CryptoError::Parameter(format!("scp get: unexpected frame {other:?}"))),
                }
            }
            // Require the terminal Ok before committing: the server sends it only
            // after the whole file was streamed, so a truncated transfer (Eof
            // without Ok, or a dropped stream) is never published.
            match recv(&mut reader, aead_name, rx_key, &mut rx).await? {
                Some(ScpFrame::Ok) => {}
                Some(ScpFrame::Err(m)) => return Err(CryptoError::Parameter(format!("scp get failed: {m}"))),
                other => return Err(CryptoError::Parameter(format!("scp get: expected Ok, got {other:?}"))),
            }
            if received != size {
                return Err(CryptoError::Parameter(format!(
                    "scp get: size mismatch (expected {size}, got {received})"
                )));
            }
            staged
                .commit(mode)
                .await
                .map_err(|e| CryptoError::Parameter(format!("commit {}: {e}", local.display())))?;
            // Ack receipt, then close our send side gracefully. The server waits
            // for this before returning, which keeps the stream alive until we've
            // drained and committed the whole file (see `drain_until_close`).
            send(&mut writer, aead_name, tx_key, &mut tx, &ScpFrame::Ok).await?;
            let _ = writer.shutdown().await;
            eprintln!("[nkct] downloaded {} ({} bytes) → {}", remote, size, local.display());
            Ok(())
        }
    }
}

// ===========================================================================
// Server
// ===========================================================================

/// Run the scp server for one accepted connection: authorize the peer's `Put` /
/// `Get` against `policy_path`, confine the path, and stream the file.
// allow(too_many_arguments): mirrors run_pty_server/run_forward_server — the
// secured stream halves + AEAD name + session keys + peer fp + policy/audit
// paths are each a distinct required input; a bundling struct would only move
// the argument list elsewhere.
#[allow(clippy::too_many_arguments)]
pub async fn run_scp_server<R, W>(
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
    R: AsyncReadExt + Unpin + Send,
    W: AsyncWriteExt + Unpin + Send,
{
    // rx_key/tx_key are borrows into the caller's session keys (owned and
    // zeroized by the handshake code); no owned copy is made here.
    let (rx_key, tx_key) = role_keys(s2c_key, c2s_key, true);
    let (mut rx, mut tx) = (0u64, 0u64);

    if rate_limited(&peer_fp) {
        audit_best_effort(audit_path, &peer_fp, "scp deny: rate limited").await;
        let _ = send(&mut writer, aead_name, tx_key, &mut tx, &ScpFrame::Err("rate limited; try again shortly".into())).await;
        drain_until_close(&mut reader).await;
        return Err(CryptoError::Parameter("scp: rate limited".into()));
    }

    // A policy is mandatory for the server (enforced at startup); default deny.
    let policy = match policy_path {
        Some(pp) => {
            let pp = pp.to_string();
            tokio::task::spawn_blocking(move || ScpPolicy::load(&pp))
                .await
                .map_err(std::io::Error::other)
                .map_err(|e| CryptoError::Parameter(format!("load scp policy: {e}")))??
        }
        None => {
            let _ = send(&mut writer, aead_name, tx_key, &mut tx, &ScpFrame::Err("scp not configured".into())).await;
            drain_until_close(&mut reader).await;
            return Err(CryptoError::Parameter("scp: no policy configured".into()));
        }
    };

    // Fail-closed audit helper for the access decision. The wire reply is
    // deliberately the uniform "denied": distinguishing "not authorized" from "no
    // such file" / "not a regular file" would let a peer use the difference as an
    // existence oracle for paths outside its policy roots (enumerate a directory
    // it may not read). The specific reason is recorded in the audit log only —
    // same rationale as ssh not revealing why an auth attempt failed.
    macro_rules! deny {
        ($reason:expr) => {{
            let reason: String = $reason;
            audit_best_effort(audit_path, &peer_fp, &format!("scp deny: {reason}")).await;
            let _ = send(&mut writer, aead_name, tx_key, &mut tx, &ScpFrame::Err("denied".into())).await;
            // Let the client read the denial before we tear down the stream.
            drain_until_close(&mut reader).await;
            return Err(CryptoError::Parameter(format!("scp denied: {reason}")));
        }};
    }

    match recv(&mut reader, aead_name, rx_key, &mut rx).await? {
        Some(ScpFrame::Put { path, mode, size }) => {
            let dest = match confine_write(&path, policy.roots(&peer_fp, true)) {
                Ok(d) => d,
                Err(e) => deny!(format!("put {path}: {e}")),
            };
            if let Err(e) = audit(audit_path, &peer_fp, &format!("scp allow put path={} bytes={size}", dest.display())).await {
                let _ = send(&mut writer, aead_name, tx_key, &mut tx, &ScpFrame::Err("audit unavailable; refusing".into())).await;
                return Err(CryptoError::Parameter(format!("scp refused: audit write failed: {e}")));
            }

            let mut staged = match Staged::create(dest.clone()) {
                Ok(s) => s,
                Err(e) => deny!(format!("stage {}: {e}", dest.display())),
            };
            // Post-create confinement re-check (Linux): verify the staging file's
            // real directory is still under a write root, closing the window where
            // an intermediate directory was swapped for a symlink between
            // confine_write's canonicalize and this open.
            #[cfg(target_os = "linux")]
            if !staged
                .temp_real_parent()
                .map(|p| under_any(&p, policy.roots(&peer_fp, true)))
                .unwrap_or(false)
            {
                deny!(format!("put {path}: destination escaped write root after open (symlink race)"));
            }
            let mut received = 0u64;
            loop {
                match recv(&mut reader, aead_name, rx_key, &mut rx).await? {
                    Some(ScpFrame::Data(d)) => {
                        received += d.len() as u64;
                        // Enforce the declared size as an upper bound *as bytes
                        // arrive*, not just at Eof: otherwise a peer could stream
                        // unboundedly past its declared size and fill the disk
                        // before we ever reach the final check.
                        if received > size {
                            deny!(format!("stream exceeds declared size {size}"));
                        }
                        if staged.write_all(&d).await.is_err() {
                            let _ = send(&mut writer, aead_name, tx_key, &mut tx, &ScpFrame::Err("transfer failed".into())).await;
                            return Err(CryptoError::FileWrite("scp put: staging write failed".into()));
                        }
                    }
                    Some(ScpFrame::Eof) => break,
                    Some(ScpFrame::Err(m)) => {
                        audit_best_effort(audit_path, &peer_fp, &format!("scp put aborted by client: {m}")).await;
                        return Ok(()); // staged temp dropped/discarded
                    }
                    None => {
                        audit_best_effort(audit_path, &peer_fp, "scp put: stream closed before Eof").await;
                        return Ok(());
                    }
                    other => deny!(format!("unexpected frame during put: {other:?}")),
                }
            }
            // Eof reached: the byte count must match the declared size exactly
            // (the loop already rejected any overshoot, so this catches a short
            // stream — fewer bytes than promised).
            if received != size {
                deny!(format!("size mismatch (declared {size}, got {received})"));
            }
            if let Err(e) = staged.commit(mode).await {
                let _ = send(&mut writer, aead_name, tx_key, &mut tx, &ScpFrame::Err(format!("commit: {e}"))).await;
                return Err(CryptoError::FileWrite(e.to_string()));
            }
            audit_best_effort(audit_path, &peer_fp, &format!("scp put ok path={} bytes={received}", dest.display())).await;
            send(&mut writer, aead_name, tx_key, &mut tx, &ScpFrame::Ok).await?;
            // Hold the connection open until the client has read our Ok and closed,
            // so the final frame is not lost to a stream reset on return.
            drain_until_close(&mut reader).await;
            Ok(())
        }
        Some(ScpFrame::Get { path }) => {
            let src = match confine_read(&path, policy.roots(&peer_fp, false)) {
                Ok(s) => s,
                Err(e) => deny!(format!("get {path}: {e}")),
            };
            // Open with O_NOFOLLOW so the final component can't be a symlink out of
            // the confined root (canonicalize already resolved intermediate links).
            let mut opts = std::fs::OpenOptions::new();
            opts.read(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.custom_flags(libc::O_NOFOLLOW);
            }
            let file = match opts.open(&src) {
                Ok(f) => f,
                Err(e) => deny!(format!("open {}: {e}", src.display())),
            };
            // Post-open confinement re-check (Linux): the opened inode's real path
            // must still be under a read root, closing the intermediate-directory
            // symlink race that O_NOFOLLOW (final component only) leaves open.
            #[cfg(target_os = "linux")]
            {
                use std::os::fd::AsRawFd;
                if !fd_real_path(file.as_raw_fd())
                    .map(|p| under_any(&p, policy.roots(&peer_fp, false)))
                    .unwrap_or(false)
                {
                    deny!(format!("get {path}: path escaped read root after open (symlink race)"));
                }
            }
            let meta = file.metadata().map_err(io_err)?;
            if !meta.is_file() {
                deny!(format!("{} is not a regular file", src.display()));
            }
            // Mode from the open fd's metadata (not a second path lookup, which
            // could resolve to a different inode after the check).
            let mode = {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    meta.mode()
                }
                #[cfg(not(unix))]
                {
                    0o644
                }
            };
            let size = meta.len();
            if let Err(e) = audit(audit_path, &peer_fp, &format!("scp allow get path={} bytes={size}", src.display())).await {
                let _ = send(&mut writer, aead_name, tx_key, &mut tx, &ScpFrame::Err("audit unavailable; refusing".into())).await;
                return Err(CryptoError::Parameter(format!("scp refused: audit write failed: {e}")));
            }

            send(&mut writer, aead_name, tx_key, &mut tx, &ScpFrame::Meta { mode, size }).await?;
            let mut f = tokio::fs::File::from_std(file);
            // Read straight into the frame plaintext buffer and seal in place.
            let mut pt = vec![0u8; 1 + CHUNK];
            pt[0] = T_DATA;
            let mut sent = 0u64;
            loop {
                let n = f.read(&mut pt[1..]).await.map_err(io_err)?;
                if n == 0 {
                    break;
                }
                sent += n as u64;
                send_packet(&mut writer, aead_name, tx_key, &mut tx, &pt[..1 + n]).await?;
            }
            send(&mut writer, aead_name, tx_key, &mut tx, &ScpFrame::Eof).await?;
            send(&mut writer, aead_name, tx_key, &mut tx, &ScpFrame::Ok).await?;
            // Critical for a non-empty Get: the whole file may still be in flight
            // when we return. Wait for the client to drain, commit and ack-close
            // (its ScpFrame::Ok then EOF) before dropping the stream — otherwise the
            // reset discards buffered bulk data and the client sees "connection
            // lost" mid-read.
            drain_until_close(&mut reader).await;
            audit_best_effort(audit_path, &peer_fp, &format!("scp get ok path={} bytes={sent}", src.display())).await;
            Ok(())
        }
        Some(other) => Err(CryptoError::Parameter(format!("scp: expected Put/Get, got {other:?}"))),
        None => Ok(()), // clean close before any request
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let frames = [
            ScpFrame::Put { path: "/a/b/c.bin".into(), mode: 0o644, size: 1 << 40 },
            ScpFrame::Get { path: "/srv/pub/x".into() },
            ScpFrame::Meta { mode: 0o600, size: 12345 },
            ScpFrame::Data(vec![0, 1, 2, 3, 255, 128]),
            ScpFrame::Eof,
            ScpFrame::Ok,
            ScpFrame::Err("nope".into()),
        ];
        for f in frames {
            let enc = f.encode();
            let dec = ScpFrame::decode(&enc).expect("decode");
            assert_eq!(f, dec);
        }
    }

    #[test]
    fn decode_rejects_truncated() {
        assert!(ScpFrame::decode(&[]).is_err());
        assert!(ScpFrame::decode(&[T_PUT, 0, 0]).is_err()); // header too short
        assert!(ScpFrame::decode(&[T_GET, 0, 0, 0, 9]).is_err()); // claims 9-byte path, none present
        assert!(ScpFrame::decode(&[0xff]).is_err()); // unknown type
    }

    #[test]
    fn confine_write_rejects_traversal_and_escape() {
        let dir = std::env::temp_dir().join(format!("nkct-scp-cw-{:x}", std::process::id()));
        let root = dir.join("root");
        std::fs::create_dir_all(&root).unwrap();
        // Policy roots are canonical (resolved at load); mirror that here.
        let croot = std::fs::canonicalize(&root).unwrap();
        let roots = vec![croot.clone()];

        // Inside the root: allowed, and confined to the canonical join.
        let ok = confine_write(&root.join("file.bin").to_string_lossy(), &roots).unwrap();
        assert!(ok.starts_with(&croot));

        // `..` in the file name is rejected (not a single plain component).
        assert!(confine_write(&root.join("../escape").to_string_lossy(), &roots).is_err());
        // A sibling directory outside the root is rejected.
        let outside = dir.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        assert!(confine_write(&outside.join("f").to_string_lossy(), &roots).is_err());
        // Relative paths are rejected.
        assert!(confine_write("relative/f", &roots).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn staged_commit_zero_bytes() {
        // A zero-byte transfer (Put{size:0} → no Data → Eof) must still stage and
        // commit a real empty file — the most-often-broken boundary in this kind
        // of streaming protocol.
        let dir = std::env::temp_dir().join(format!("nkct-scp-zero-{:x}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let final_path = dir.join("empty.bin");
        let staged = Staged::create(final_path.clone()).unwrap();
        staged.commit(0o644).await.unwrap();
        let meta = std::fs::metadata(&final_path).unwrap();
        assert_eq!(meta.len(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn staged_commit_strips_setuid_setgid() {
        // A peer-chosen mode with setuid (0o4000) / setgid (0o2000) / sticky
        // (0o1000) must never survive to the committed file — otherwise an
        // authorized uploader (or a malicious server, on the client side) could
        // plant a privilege-escalation binary.
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("nkct-scp-suid-{:x}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let final_path = dir.join("evil.bin");
        let mut staged = Staged::create(final_path.clone()).unwrap();
        staged.write_all(b"#!/bin/sh\n").await.unwrap();
        staged.commit(0o6755).await.unwrap(); // setuid+setgid+rwxr-xr-x
        let mode = std::fs::metadata(&final_path).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o0755, "setuid/setgid must be stripped, got {mode:o}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn staged_discard_leaves_no_final() {
        // Dropping a Staged without commit (interrupted / unauthenticated
        // transfer) must leave neither the temp nor the final path behind.
        let dir = std::env::temp_dir().join(format!("nkct-scp-disc-{:x}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let final_path = dir.join("nope.bin");
        {
            let mut staged = Staged::create(final_path.clone()).unwrap();
            staged.write_all(b"partial").await.unwrap();
            // dropped here without commit
        }
        assert!(!final_path.exists(), "final path must not be published");
        let leftovers: Vec<_> = std::fs::read_dir(&dir).unwrap().filter_map(|e| e.ok()).collect();
        assert!(leftovers.is_empty(), "temp must be discarded, found {leftovers:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fd_real_path_reveals_intermediate_symlink_escape() {
        // The post-open re-check's mechanism: opening a file through an
        // intermediate directory symlink that escapes the root yields an fd whose
        // /proc/self/fd real path is *outside* the root, so under_any() rejects it
        // — this is what closes the check→open swap race that O_NOFOLLOW (final
        // component only) cannot.
        use std::os::fd::AsRawFd;
        let dir = std::env::temp_dir().join(format!("nkct-scp-fdrp-{:x}", std::process::id()));
        let root = dir.join("root");
        let secret = dir.join("secret");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&secret).unwrap();
        std::fs::write(secret.join("data"), b"x").unwrap();
        // An *intermediate* directory symlink inside the root pointing outside it.
        std::os::unix::fs::symlink(&secret, root.join("link")).unwrap();
        let roots = vec![std::fs::canonicalize(&root).unwrap()];

        // Final component ("data") is a real file, so O_NOFOLLOW open succeeds even
        // though we traversed the symlinked intermediate dir.
        let f = std::fs::OpenOptions::new()
            .read(true)
            .open(root.join("link").join("data"))
            .unwrap();
        let real = fd_real_path(f.as_raw_fd()).unwrap();
        assert!(!under_any(&real, &roots), "escaped path {real:?} must be rejected");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn confine_read_rejects_symlink_escape() {
        let dir = std::env::temp_dir().join(format!("nkct-scp-cr-{:x}", std::process::id()));
        let root = dir.join("root");
        let secret_dir = dir.join("secret");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&secret_dir).unwrap();
        std::fs::write(secret_dir.join("passwd"), b"secret").unwrap();
        // A symlink inside the root pointing at a file outside it.
        let link = root.join("leak");
        std::os::unix::fs::symlink(secret_dir.join("passwd"), &link).unwrap();
        let roots = vec![std::fs::canonicalize(&root).unwrap()];

        // canonicalize() resolves the symlink to the outside target, which is not
        // under the root → rejected.
        assert!(confine_read(&link.to_string_lossy(), &roots).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
