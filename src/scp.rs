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
    audit, audit_best_effort, extract_kv, extract_quoted_span, io_err, parse_fp_hex,
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
const T_MKDIR: u8 = 0x02;
const T_DATA: u8 = 0x03;
const T_EOF: u8 = 0x04;
const T_ACK: u8 = 0x05;
const T_FAIL: u8 = 0x06;
const T_GET: u8 = 0x07;
const T_DONE: u8 = 0x08;
const T_ERR: u8 = 0x09;

/// One control/data frame over `ALPN_SCP`. The protocol is a *sender → receiver*
/// stream of files: the sender emits `MkDir` / `Put`+`Data`*+`Eof` per entry and
/// a terminal `Done`; the receiver replies `Ack` / `Fail` per entry. For a `put`
/// the client is the sender; for a `get` the server becomes the sender after the
/// client's `Get`. `file_id` scopes the per-file frames — for the serial
/// transport it is a simple monotonic counter, but it is carried on the wire so a
/// future parallel variant can multiplex several files over one connection
/// without breaking serial peers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScpFrame {
    /// Sender → receiver: begin a regular file of `size` bytes (perm `mode`).
    Put { file_id: u32, path: String, mode: u32, size: u64 },
    /// Sender → receiver: create a directory (`-r`).
    MkDir { file_id: u32, path: String, mode: u32 },
    /// Sender → receiver: bulk file bytes (≤ [`CHUNK`] per frame).
    Data { file_id: u32, bytes: Vec<u8> },
    /// Sender → receiver: end of this file's bytes.
    Eof { file_id: u32 },
    /// Receiver → sender: this entry was committed successfully.
    Ack { file_id: u32 },
    /// Receiver → sender: this entry failed (per-file; the batch continues).
    Fail { file_id: u32, msg: String },
    /// Client → server: request a download; `recursive` walks a directory tree.
    Get { path: String, recursive: bool },
    /// Sender → receiver: no more entries — the batch is complete.
    Done,
    /// Either direction: a fatal / connection-level error (authz denied, protocol).
    Err(String),
}

fn put_u32(v: &mut Vec<u8>, n: u32) {
    v.extend_from_slice(&n.to_be_bytes());
}
fn get_u32(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4).map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

impl ScpFrame {
    /// Serialize to the plaintext that goes inside one AEAD packet.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::new();
        match self {
            ScpFrame::Put { file_id, path, mode, size } => {
                v.push(T_PUT);
                put_u32(&mut v, *file_id);
                put_u32(&mut v, *mode);
                v.extend_from_slice(&size.to_be_bytes());
                put_u32(&mut v, path.len() as u32);
                v.extend_from_slice(path.as_bytes());
            }
            ScpFrame::MkDir { file_id, path, mode } => {
                v.push(T_MKDIR);
                put_u32(&mut v, *file_id);
                put_u32(&mut v, *mode);
                put_u32(&mut v, path.len() as u32);
                v.extend_from_slice(path.as_bytes());
            }
            ScpFrame::Data { file_id, bytes } => {
                v.push(T_DATA);
                put_u32(&mut v, *file_id);
                v.extend_from_slice(bytes);
            }
            ScpFrame::Eof { file_id } => {
                v.push(T_EOF);
                put_u32(&mut v, *file_id);
            }
            ScpFrame::Ack { file_id } => {
                v.push(T_ACK);
                put_u32(&mut v, *file_id);
            }
            ScpFrame::Fail { file_id, msg } => {
                v.push(T_FAIL);
                put_u32(&mut v, *file_id);
                v.extend_from_slice(msg.as_bytes());
            }
            ScpFrame::Get { path, recursive } => {
                v.push(T_GET);
                v.push(if *recursive { 1 } else { 0 });
                put_u32(&mut v, path.len() as u32);
                v.extend_from_slice(path.as_bytes());
            }
            ScpFrame::Done => v.push(T_DONE),
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
        // Parse a `file_id(4) ‖ mode(4) ‖ [size(8)] ‖ plen(4) ‖ path` tail.
        let path_entry = |rest: &[u8], with_size: bool| -> Result<(u32, u32, u64, String)> {
            let fixed = if with_size { 20 } else { 12 };
            if rest.len() < fixed {
                return Err(bad());
            }
            let file_id = get_u32(rest, 0).ok_or_else(bad)?;
            let mode = get_u32(rest, 4).ok_or_else(bad)?;
            let (size, poff) = if with_size {
                (u64::from_be_bytes(rest[8..16].try_into().map_err(|_| bad())?), 16)
            } else {
                (0, 8)
            };
            let plen = get_u32(rest, poff).ok_or_else(bad)? as usize;
            let body = &rest[poff + 4..];
            if body.len() < plen {
                return Err(bad());
            }
            let path = std::str::from_utf8(&body[..plen]).map_err(|_| bad())?.to_string();
            Ok((file_id, mode, size, path))
        };
        match ty {
            T_PUT => {
                let (file_id, mode, size, path) = path_entry(rest, true)?;
                Ok(ScpFrame::Put { file_id, path, mode, size })
            }
            T_MKDIR => {
                let (file_id, mode, _sz, path) = path_entry(rest, false)?;
                Ok(ScpFrame::MkDir { file_id, path, mode })
            }
            T_DATA => {
                let file_id = get_u32(rest, 0).ok_or_else(bad)?;
                Ok(ScpFrame::Data { file_id, bytes: rest[4..].to_vec() })
            }
            T_EOF => Ok(ScpFrame::Eof { file_id: get_u32(rest, 0).ok_or_else(bad)? }),
            T_ACK => Ok(ScpFrame::Ack { file_id: get_u32(rest, 0).ok_or_else(bad)? }),
            T_FAIL => {
                let file_id = get_u32(rest, 0).ok_or_else(bad)?;
                Ok(ScpFrame::Fail { file_id, msg: String::from_utf8_lossy(&rest[4..]).into_owned() })
            }
            T_GET => {
                if rest.len() < 5 {
                    return Err(bad());
                }
                let recursive = rest[0] != 0;
                let plen = get_u32(rest, 1).ok_or_else(bad)? as usize;
                let body = &rest[5..];
                if body.len() < plen {
                    return Err(bad());
                }
                let path = std::str::from_utf8(&body[..plen]).map_err(|_| bad())?.to_string();
                Ok(ScpFrame::Get { path, recursive })
            }
            T_DONE => Ok(ScpFrame::Done),
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

/// Confine a `MkDir` request (`-r`): same rules as [`confine_write`] — the parent
/// must resolve to a directory under a write root and the new component must be a
/// single plain name. The directory itself need not exist yet. If it already
/// exists (re-`put` of a tree), that is fine and handled by the caller.
fn confine_mkdir(req: &str, roots: &[PathBuf]) -> std::result::Result<PathBuf, String> {
    // Identical validation to a file destination: absolute, plain final
    // component, parent canonicalized under a root.
    confine_write(req, roots)
}

/// Open a confined source file for a `get`: `O_NOFOLLOW` on the final component
/// plus the Linux `/proc/self/fd` real-path re-check against `roots` (closing the
/// intermediate-directory symlink race). Returns `(file, mode, size)`; `mode`
/// comes from the open fd, not a second path lookup. Errors carry a reason for
/// the audit log — the wire reply is uniformized to "denied" by the caller.
fn open_confined_read(src: &Path, roots: &[PathBuf]) -> std::result::Result<(std::fs::File, u32, u64), String> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    let file = opts.open(src).map_err(|e| format!("open {}: {e}", src.display()))?;
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        if !fd_real_path(file.as_raw_fd()).map(|p| under_any(&p, roots)).unwrap_or(false) {
            return Err("path escaped read root after open (symlink race)".into());
        }
    }
    let meta = file.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file() {
        return Err(format!("{} is not a regular file", src.display()));
    }
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
    Ok((file, mode, meta.len()))
}

/// Validate a **relative** path received from a peer for a `get -r` (the server
/// sends tree-relative paths; the client places them under its local base). Reject
/// absolute paths and any `..` / root / prefix component so a malicious server
/// cannot write outside the client's chosen destination directory. Returns the
/// path joined under `base`.
fn safe_join(base: &Path, rel: &str) -> std::result::Result<PathBuf, String> {
    let relp = Path::new(rel);
    if relp.is_absolute() {
        return Err(format!("relative path expected, got absolute {rel:?}"));
    }
    for comp in relp.components() {
        match comp {
            Component::Normal(_) => {}
            _ => return Err(format!("unsafe path component in {rel:?}")),
        }
    }
    Ok(base.join(relp))
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

/// Set a directory's permission bits via its **fd** (`fchmod`), opening it with
/// `O_NOFOLLOW | O_DIRECTORY` — never a path-based `set_permissions`, which a
/// symlink swapped in at `dir` between create and chmod could redirect onto an
/// arbitrary file (TOCTOU). Best-effort: a failure to chmod is ignored (the
/// directory still exists with default perms).
fn set_dir_mode_nofollow(dir: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut o = std::fs::OpenOptions::new();
        o.read(true).custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY);
        if let Ok(dfd) = o.open(dir) {
            let _ = dfd.set_permissions(std::fs::Permissions::from_mode(mode & 0o0777));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (dir, mode);
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

/// Depth-first walk of `base`, returning `(relative_path, is_dir)` with every
/// directory listed before its contents (so a receiver can `MkDir` parents
/// first). Symlinks and special files are skipped — never followed — so the walk
/// cannot loop or escape `base`.
fn walk_tree(base: &Path) -> std::io::Result<Vec<(PathBuf, bool)>> {
    // Iterative DFS with an explicit stack — a recursive walk could overflow the
    // call stack on a pathologically deep tree. A directory is emitted (in its
    // parent's listing) before it is expanded, so parents always precede their
    // contents (the receiver can MkDir before writing into it).
    // Bound the entry count so a pathological tree can't exhaust memory (the list
    // is held before transfer); fail loudly rather than OOM.
    const MAX_TREE_ENTRIES: usize = 1_000_000;
    let mut out = Vec::new();
    let mut stack: Vec<PathBuf> = vec![base.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let mut entries: Vec<_> = std::fs::read_dir(&dir)?.collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by_key(|e| e.file_name());
        let mut subdirs = Vec::new();
        for e in entries {
            let path = e.path();
            let ft = e.file_type()?; // does NOT follow symlinks
            let rel = match path.strip_prefix(base) {
                Ok(r) => r.to_path_buf(),
                Err(_) => continue,
            };
            if ft.is_dir() {
                out.push((rel, true));
                subdirs.push(path);
            } else if ft.is_file() {
                out.push((rel, false));
            }
            // symlinks / sockets / fifos: skipped (never followed)
            if out.len() > MAX_TREE_ENTRIES {
                return Err(std::io::Error::other(format!(
                    "directory tree exceeds {MAX_TREE_ENTRIES} entries"
                )));
            }
        }
        // Push in reverse so siblings pop back in sorted order.
        for d in subdirs.into_iter().rev() {
            stack.push(d);
        }
    }
    Ok(out)
}

/// Send one file's bytes as `Data{file_id}`* followed by `Eof{file_id}`, reading
/// straight into the frame plaintext buffer (`[T_DATA]‖file_id‖payload`) and
/// sealing it in place — no per-chunk copy. Returns the number of bytes sent.
async fn stream_bytes<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    aead: &str,
    key: &[u8],
    ctr: &mut u64,
    file_id: u32,
    f: &mut tokio::fs::File,
) -> Result<u64> {
    let mut pt = vec![0u8; 5 + CHUNK];
    pt[0] = T_DATA;
    pt[1..5].copy_from_slice(&file_id.to_be_bytes());
    let mut sent = 0u64;
    loop {
        let n = f.read(&mut pt[5..]).await.map_err(io_err)?;
        if n == 0 {
            break;
        }
        sent += n as u64;
        send_packet(w, aead, key, ctr, &pt[..5 + n]).await?;
    }
    send(w, aead, key, ctr, &ScpFrame::Eof { file_id }).await?;
    Ok(sent)
}

/// Receive `Data{file_id}`* / `Eof{file_id}` into `staged`, bounded by `size`.
/// A frame for another `file_id`, an overshoot, or a short stream is an error.
async fn recv_into_staged<R: AsyncReadExt + Unpin>(
    r: &mut R,
    aead: &str,
    key: &[u8],
    ctr: &mut u64,
    file_id: u32,
    size: u64,
    staged: &mut Staged,
) -> Result<()> {
    let param = |m: String| CryptoError::Parameter(m);
    let mut received = 0u64;
    loop {
        match recv(r, aead, key, ctr).await? {
            Some(ScpFrame::Data { file_id: fid, bytes }) if fid == file_id => {
                received += bytes.len() as u64;
                if received > size {
                    return Err(param(format!("stream exceeds declared size {size}")));
                }
                staged.write_all(&bytes).await.map_err(io_err)?;
            }
            Some(ScpFrame::Eof { file_id: fid }) if fid == file_id => break,
            Some(ScpFrame::Err(m)) => return Err(param(format!("peer error mid-file: {m}"))),
            Some(other) => return Err(param(format!("unexpected frame in file body: {other:?}"))),
            None => return Err(param("stream closed before Eof".into())),
        }
    }
    if received != size {
        return Err(param(format!("size mismatch (declared {size}, got {received})")));
    }
    Ok(())
}

// ===========================================================================
// Client
// ===========================================================================

/// What the scp client was asked to do.
pub enum ScpOp {
    /// Upload `local` to remote `remote`. With `recursive`, `local` is a
    /// directory tree copied under the remote path.
    Put { local: PathBuf, remote: String, recursive: bool },
    /// Download remote `remote` to `local`. With `recursive`, `remote` is a
    /// directory tree copied under the local path.
    Get { remote: String, local: PathBuf, recursive: bool },
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
        ScpOp::Put { local, remote, recursive } => {
            // One entry to send: either a directory to create, or a file to stream.
            struct Entry { remote: String, local: Option<PathBuf>, mode: u32, size: u64 }
            let base_meta = std::fs::metadata(local)
                .map_err(|e| CryptoError::Parameter(format!("open {}: {e}", local.display())))?;
            let mut entries: Vec<Entry> = Vec::new();
            if *recursive {
                if !base_meta.is_dir() {
                    return Err(CryptoError::Parameter(format!("{} is not a directory (use without -r)", local.display())));
                }
                // Create the remote base directory first, then its tree (parents
                // before children, per walk_tree's ordering).
                entries.push(Entry { remote: remote.clone(), local: None, mode: local_mode(local), size: 0 });
                for (rel, is_dir) in walk_tree(local).map_err(io_err)? {
                    let rp = format!("{}/{}", remote.trim_end_matches('/'), rel.to_string_lossy());
                    let full = local.join(&rel);
                    if is_dir {
                        entries.push(Entry { remote: rp, local: None, mode: local_mode(&full), size: 0 });
                    } else {
                        let m = std::fs::metadata(&full).map_err(io_err)?;
                        entries.push(Entry { remote: rp, local: Some(full.clone()), mode: local_mode(&full), size: m.len() });
                    }
                }
            } else {
                if !base_meta.is_file() {
                    return Err(CryptoError::Parameter(format!("{} is not a regular file (use -r for a directory)", local.display())));
                }
                entries.push(Entry { remote: remote.clone(), local: Some(local.clone()), mode: local_mode(local), size: base_meta.len() });
            }

            let total = entries.iter().filter(|e| e.local.is_some()).count();
            // Pipeline: stream every entry (+ Done) and collect the per-entry acks
            // concurrently over the two independent stream halves, instead of
            // blocking for each file's ack before sending the next. On a
            // high-latency link this removes one round-trip per file (the whole
            // point of many-small-files transfer); on loopback it is a no-op.
            // Acks arrive in send order over the single ordered stream, so the
            // i-th ack pairs with the i-th entry (the file_id confirms it).
            let sender = async {
                let mut file_id = 0u32;
                for e in &entries {
                    file_id += 1;
                    match &e.local {
                        None => {
                            send(&mut writer, aead_name, tx_key, &mut tx, &ScpFrame::MkDir { file_id, path: e.remote.clone(), mode: e.mode }).await?;
                        }
                        Some(path) => {
                            send(&mut writer, aead_name, tx_key, &mut tx, &ScpFrame::Put { file_id, path: e.remote.clone(), mode: e.mode, size: e.size }).await?;
                            let mut f = tokio::fs::File::open(path)
                                .await
                                .map_err(|er| CryptoError::Parameter(format!("open {}: {er}", path.display())))?;
                            stream_bytes(&mut writer, aead_name, tx_key, &mut tx, file_id, &mut f).await?;
                        }
                    }
                }
                send(&mut writer, aead_name, tx_key, &mut tx, &ScpFrame::Done).await?;
                Ok::<(), CryptoError>(())
            };
            let collector = async {
                let mut done = 0usize;
                for e in &entries {
                    match recv(&mut reader, aead_name, rx_key, &mut rx).await? {
                        Some(ScpFrame::Ack { .. }) => {
                            if e.local.is_some() {
                                done += 1;
                            }
                        }
                        Some(ScpFrame::Fail { msg, .. }) => {
                            eprintln!("[nkct] skipped {}: {msg}", e.remote);
                        }
                        Some(ScpFrame::Err(m)) => return Err(CryptoError::Parameter(format!("scp put refused: {m}"))),
                        other => return Err(CryptoError::Parameter(format!("scp put: unexpected reply {other:?}"))),
                    }
                }
                Ok::<usize, CryptoError>(done)
            };
            let ((), done) = tokio::try_join!(sender, collector)?;
            let _ = writer.shutdown().await;
            if *recursive {
                eprintln!("[nkct] uploaded {done}/{total} files → {remote}");
            } else {
                eprintln!("[nkct] uploaded {} ({} bytes) → {}", local.display(), entries[0].size, remote);
            }
            Ok(())
        }
        ScpOp::Get { remote, local, recursive } => {
            send(&mut writer, aead_name, tx_key, &mut tx, &ScpFrame::Get { path: remote.clone(), recursive: *recursive }).await?;

            if !*recursive {
                // Single file: expect one Put header, then its body, then Done. The
                // server's path is advisory — we write to the client-chosen `local`.
                let (file_id, mode, size) = match recv(&mut reader, aead_name, rx_key, &mut rx).await? {
                    Some(ScpFrame::Put { file_id, mode, size, .. }) => (file_id, mode, size),
                    Some(ScpFrame::Err(m)) => return Err(CryptoError::Parameter(format!("scp get refused: {m}"))),
                    other => return Err(CryptoError::Parameter(format!("scp get: unexpected reply {other:?}"))),
                };
                let mut staged = Staged::create(local.clone())
                    .map_err(|e| CryptoError::Parameter(format!("stage {}: {e}", local.display())))?;
                recv_into_staged(&mut reader, aead_name, rx_key, &mut rx, file_id, size, &mut staged).await?;
                staged.commit(mode).await.map_err(|e| CryptoError::Parameter(format!("commit {}: {e}", local.display())))?;
                send(&mut writer, aead_name, tx_key, &mut tx, &ScpFrame::Ack { file_id }).await?;
                match recv(&mut reader, aead_name, rx_key, &mut rx).await? {
                    Some(ScpFrame::Done) | None => {}
                    Some(ScpFrame::Err(m)) => return Err(CryptoError::Parameter(format!("scp get failed: {m}"))),
                    other => return Err(CryptoError::Parameter(format!("scp get: expected Done, got {other:?}"))),
                }
                let _ = writer.shutdown().await;
                eprintln!("[nkct] downloaded {remote} ({size} bytes) → {}", local.display());
                Ok(())
            } else {
                // Directory tree: create the local base, then place each entry the
                // server sends under it (relative paths validated by safe_join).
                std::fs::create_dir_all(local)
                    .map_err(|e| CryptoError::Parameter(format!("create {}: {e}", local.display())))?;
                let (mut files, mut dirs) = (0usize, 0usize);
                loop {
                    match recv(&mut reader, aead_name, rx_key, &mut rx).await? {
                        Some(ScpFrame::MkDir { file_id, path, mode }) => {
                            let d = safe_join(local, &path).map_err(CryptoError::Parameter)?;
                            std::fs::create_dir_all(&d).map_err(|e| CryptoError::Parameter(format!("mkdir {}: {e}", d.display())))?;
                            // fchmod via the dir fd (O_NOFOLLOW), not a path-based
                            // set_permissions a local symlink swap could redirect.
                            set_dir_mode_nofollow(&d, mode);
                            send(&mut writer, aead_name, tx_key, &mut tx, &ScpFrame::Ack { file_id }).await?;
                            dirs += 1;
                        }
                        Some(ScpFrame::Put { file_id, path, mode, size }) => {
                            let dest = safe_join(local, &path).map_err(CryptoError::Parameter)?;
                            let mut staged = Staged::create(dest.clone())
                                .map_err(|e| CryptoError::Parameter(format!("stage {}: {e}", dest.display())))?;
                            recv_into_staged(&mut reader, aead_name, rx_key, &mut rx, file_id, size, &mut staged).await?;
                            staged.commit(mode).await.map_err(|e| CryptoError::Parameter(format!("commit {}: {e}", dest.display())))?;
                            send(&mut writer, aead_name, tx_key, &mut tx, &ScpFrame::Ack { file_id }).await?;
                            files += 1;
                        }
                        Some(ScpFrame::Done) | None => break,
                        Some(ScpFrame::Err(m)) => return Err(CryptoError::Parameter(format!("scp get failed: {m}"))),
                        other => return Err(CryptoError::Parameter(format!("scp get: unexpected frame {other:?}"))),
                    }
                }
                let _ = writer.shutdown().await;
                eprintln!("[nkct] downloaded {files} files, {dirs} dirs → {}", local.display());
                Ok(())
            }
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

    // No per-operation throttle: an authenticated, policy-allowed client copying
    // several files in a row is normal use. Brute-force is limited on the
    // handshake failure path (see `crate::shell::auth_failure_blocked`);
    // concurrency is bounded by the accept semaphore.

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

    // A `put` batch is a stream of MkDir / (Put + body) entries ended by Done; a
    // `get` is a single request that flips us into the sender role. The first
    // frame selects which. Per-entry problems reply Fail (the batch continues);
    // protocol violations (wrong frame, overshoot, mid-file close) are fatal and
    // close the stream. Confine on every entry — the write/read roots are the
    // boundary, applied per path, so `-r` is just many independently-confined
    // entries.
    let (mut n_ok, mut n_fail) = (0usize, 0usize);
    let mut next_id: u32 = 0;

    loop {
        match recv(&mut reader, aead_name, rx_key, &mut rx).await? {
            // ---- put: create a directory ----
            Some(ScpFrame::MkDir { file_id, path, mode }) => {
                let made = match confine_mkdir(&path, policy.roots(&peer_fp, true)) {
                    Ok(dir) => {
                        let created = match tokio::fs::create_dir(&dir).await {
                            Ok(()) => true,
                            // A re-put of an existing tree is fine.
                            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
                            Err(_) => {
                                // couldn't create; fall through to reject
                                send(&mut writer, aead_name, tx_key, &mut tx, &ScpFrame::Fail { file_id, msg: "denied".into() }).await?;
                                n_fail += 1;
                                continue;
                            }
                        };
                        // Verify + set mode on the *directory fd* (fchmod), never a
                        // path-based set_permissions that a symlink swap could
                        // redirect. Open with O_NOFOLLOW|O_DIRECTORY and re-check the
                        // fd's real path is under a write root (closes the
                        // confine→create intermediate-symlink race, Linux).
                        let mut o = std::fs::OpenOptions::new();
                        o.read(true);
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::OpenOptionsExt;
                            o.custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY);
                        }
                        let ok = match o.open(&dir) {
                            Ok(dfd) => {
                                let under = {
                                    #[cfg(target_os = "linux")]
                                    {
                                        use std::os::fd::AsRawFd;
                                        fd_real_path(dfd.as_raw_fd()).map(|p| under_any(&p, policy.roots(&peer_fp, true))).unwrap_or(false)
                                    }
                                    #[cfg(not(target_os = "linux"))]
                                    {
                                        true
                                    }
                                };
                                if under {
                                    #[cfg(unix)]
                                    {
                                        use std::os::unix::fs::PermissionsExt;
                                        let _ = dfd.set_permissions(std::fs::Permissions::from_mode(mode & 0o0777));
                                    }
                                    true
                                } else {
                                    false
                                }
                            }
                            Err(_) => false,
                        };
                        if ok {
                            Some(dir)
                        } else {
                            if created {
                                let _ = std::fs::remove_dir(&dir);
                            }
                            None
                        }
                    }
                    Err(_) => None,
                };
                match made {
                    Some(dir) => {
                        // Mode was already applied via the directory fd above
                        // (fchmod); no path-based set_permissions here — it would
                        // reintroduce the symlink-swap TOCTOU we just closed.
                        audit_best_effort(audit_path, &peer_fp, &format!("scp mkdir ok path={}", dir.display())).await;
                        send(&mut writer, aead_name, tx_key, &mut tx, &ScpFrame::Ack { file_id }).await?;
                        n_ok += 1;
                    }
                    None => {
                        audit_best_effort(audit_path, &peer_fp, &format!("scp deny: mkdir {path}")).await;
                        send(&mut writer, aead_name, tx_key, &mut tx, &ScpFrame::Fail { file_id, msg: "denied".into() }).await?;
                        n_fail += 1;
                    }
                }
            }
            // ---- put: receive a file ----
            Some(ScpFrame::Put { file_id, path, mode, size }) => {
                let dest = confine_write(&path, policy.roots(&peer_fp, true));
                let mut staged: Option<Staged> = match &dest {
                    Ok(d) => Staged::create(d.clone()).ok(),
                    Err(_) => None,
                };
                // Post-create confinement re-check (Linux): if the staging file's
                // real directory is not under a write root (intermediate-symlink
                // swap between confine and open), discard — we still consume the
                // body below to keep the stream in sync, then Fail.
                #[cfg(target_os = "linux")]
                if let Some(s) = &staged {
                    if !s.temp_real_parent().map(|p| under_any(&p, policy.roots(&peer_fp, true))).unwrap_or(false) {
                        staged = None;
                    }
                }
                // Consume this file's body (bounded by the declared size) whether or
                // not we are keeping it, so a per-file reject never desyncs the batch.
                let mut received = 0u64;
                loop {
                    match recv(&mut reader, aead_name, rx_key, &mut rx).await? {
                        Some(ScpFrame::Data { file_id: fid, bytes }) if fid == file_id => {
                            received += bytes.len() as u64;
                            if received > size {
                                let _ = send(&mut writer, aead_name, tx_key, &mut tx, &ScpFrame::Err("transfer failed".into())).await;
                                drain_until_close(&mut reader).await;
                                return Err(CryptoError::Parameter("scp put: stream exceeds declared size".into()));
                            }
                            if let Some(s) = staged.as_mut() {
                                if s.write_all(&bytes).await.is_err() {
                                    staged = None; // I/O failed: stop keeping, keep consuming
                                }
                            }
                        }
                        Some(ScpFrame::Eof { file_id: fid }) if fid == file_id => break,
                        None => {
                            drain_until_close(&mut reader).await;
                            return Err(CryptoError::Parameter("scp put: stream closed mid-file".into()));
                        }
                        other => {
                            let _ = send(&mut writer, aead_name, tx_key, &mut tx, &ScpFrame::Err("protocol error".into())).await;
                            drain_until_close(&mut reader).await;
                            return Err(CryptoError::Parameter(format!("scp put: unexpected frame in body: {other:?}")));
                        }
                    }
                }
                let committed = match (&dest, staged.take(), received == size) {
                    (Ok(d), Some(s), true) => match s.commit(mode).await {
                        Ok(()) => {
                            audit_best_effort(audit_path, &peer_fp, &format!("scp put ok path={} bytes={received}", d.display())).await;
                            true
                        }
                        Err(_) => false,
                    },
                    _ => false,
                };
                if committed {
                    send(&mut writer, aead_name, tx_key, &mut tx, &ScpFrame::Ack { file_id }).await?;
                    n_ok += 1;
                } else {
                    let reason = match &dest {
                        Err(e) => format!("put {path}: {e}"),
                        Ok(_) if received != size => format!("put {path}: size mismatch"),
                        Ok(_) => format!("put {path}: stage/commit failed"),
                    };
                    audit_best_effort(audit_path, &peer_fp, &format!("scp fail: {reason}")).await;
                    send(&mut writer, aead_name, tx_key, &mut tx, &ScpFrame::Fail { file_id, msg: "denied".into() }).await?;
                    n_fail += 1;
                }
            }
            // ---- get: we become the sender (single file or recursive tree) ----
            Some(ScpFrame::Get { path, recursive }) => {
                let read_roots = policy.roots(&peer_fp, false);
                if !recursive {
                    let src = match confine_read(&path, read_roots) {
                        Ok(s) => s,
                        Err(e) => deny!(format!("get {path}: {e}")),
                    };
                    let (file, mode, size) = match open_confined_read(&src, read_roots) {
                        Ok(t) => t,
                        Err(e) => deny!(format!("get {path}: {e}")),
                    };
                    if let Err(e) = audit(audit_path, &peer_fp, &format!("scp allow get path={} bytes={size}", src.display())).await {
                        let _ = send(&mut writer, aead_name, tx_key, &mut tx, &ScpFrame::Err("audit unavailable; refusing".into())).await;
                        return Err(CryptoError::Parameter(format!("scp refused: audit write failed: {e}")));
                    }
                    next_id += 1;
                    let name = src.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
                    send(&mut writer, aead_name, tx_key, &mut tx, &ScpFrame::Put { file_id: next_id, path: name, mode, size }).await?;
                    let mut f = tokio::fs::File::from_std(file);
                    let sent = stream_bytes(&mut writer, aead_name, tx_key, &mut tx, next_id, &mut f).await?;
                    // The client acks after committing; then Done + drain.
                    let _ = recv(&mut reader, aead_name, rx_key, &mut rx).await?;
                    send(&mut writer, aead_name, tx_key, &mut tx, &ScpFrame::Done).await?;
                    audit_best_effort(audit_path, &peer_fp, &format!("scp get ok path={} bytes={sent}", src.display())).await;
                    drain_until_close(&mut reader).await;
                    return Ok(());
                }
                // Recursive: the request must resolve to a directory under a read root.
                let root = match confine_read(&path, read_roots) {
                    Ok(d) => d,
                    Err(e) => deny!(format!("get {path}: {e}")),
                };
                if !root.is_dir() {
                    deny!(format!("get {path}: not a directory (recursive)"));
                }
                let entries = match walk_tree(&root) {
                    Ok(e) => e,
                    Err(e) => deny!(format!("get {path}: walk: {e}")),
                };
                audit_best_effort(audit_path, &peer_fp, &format!("scp allow get -r path={} entries={}", root.display(), entries.len())).await;
                for (rel, is_dir) in entries {
                    next_id += 1;
                    let rels = rel.to_string_lossy().into_owned();
                    if is_dir {
                        let dmode = local_mode(&root.join(&rel));
                        send(&mut writer, aead_name, tx_key, &mut tx, &ScpFrame::MkDir { file_id: next_id, path: rels, mode: dmode }).await?;
                    } else {
                        let full = root.join(&rel);
                        match open_confined_read(&full, read_roots) {
                            Ok((file, mode, size)) => {
                                send(&mut writer, aead_name, tx_key, &mut tx, &ScpFrame::Put { file_id: next_id, path: rels, mode, size }).await?;
                                let mut f = tokio::fs::File::from_std(file);
                                stream_bytes(&mut writer, aead_name, tx_key, &mut tx, next_id, &mut f).await?;
                            }
                            Err(e) => {
                                // A file walk_tree listed can no longer be opened
                                // safely (removed / perms changed / symlink race
                                // mid-transfer). Fail the whole get *loudly* rather
                                // than silently delivering an incomplete tree.
                                audit_best_effort(audit_path, &peer_fp, &format!("scp get -r abort: {}: {e}", full.display())).await;
                                let _ = send(&mut writer, aead_name, tx_key, &mut tx, &ScpFrame::Err("transfer failed".into())).await;
                                drain_until_close(&mut reader).await;
                                return Err(CryptoError::Parameter(format!("scp get -r: {} unreadable mid-transfer", full.display())));
                            }
                        }
                    }
                    // Consume the client's per-entry ack (Ack/Fail); ignore its kind.
                    let _ = recv(&mut reader, aead_name, rx_key, &mut rx).await?;
                }
                send(&mut writer, aead_name, tx_key, &mut tx, &ScpFrame::Done).await?;
                drain_until_close(&mut reader).await;
                return Ok(());
            }
            // ---- end of a put batch ----
            Some(ScpFrame::Done) | None => {
                audit_best_effort(audit_path, &peer_fp, &format!("scp batch end ok={n_ok} fail={n_fail}")).await;
                drain_until_close(&mut reader).await;
                return Ok(());
            }
            other => {
                let _ = send(&mut writer, aead_name, tx_key, &mut tx, &ScpFrame::Err("protocol error".into())).await;
                drain_until_close(&mut reader).await;
                return Err(CryptoError::Parameter(format!("scp: unexpected frame {other:?}")));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let frames = [
            ScpFrame::Put { file_id: 7, path: "/a/b/c.bin".into(), mode: 0o644, size: 1 << 40 },
            ScpFrame::MkDir { file_id: 3, path: "sub/dir".into(), mode: 0o755 },
            ScpFrame::Data { file_id: 7, bytes: vec![0, 1, 2, 3, 255, 128] },
            ScpFrame::Eof { file_id: 7 },
            ScpFrame::Ack { file_id: 7 },
            ScpFrame::Fail { file_id: 7, msg: "nope".into() },
            ScpFrame::Get { path: "/srv/pub/x".into(), recursive: false },
            ScpFrame::Get { path: "/srv/pub".into(), recursive: true },
            ScpFrame::Done,
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
        assert!(ScpFrame::decode(&[T_GET, 0, 0, 0, 0, 9]).is_err()); // claims 9-byte path, none present
        assert!(ScpFrame::decode(&[T_DATA, 0, 0]).is_err()); // missing file_id
        assert!(ScpFrame::decode(&[0xff]).is_err()); // unknown type
    }

    #[test]
    fn safe_join_rejects_escapes() {
        let base = Path::new("/tmp/base");
        assert!(safe_join(base, "a/b/c.txt").is_ok());
        assert!(safe_join(base, "../etc/passwd").is_err());
        assert!(safe_join(base, "/etc/passwd").is_err());
        assert!(safe_join(base, "a/../../x").is_err());
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
