/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

//! P2P scp (`nkct/scp/3`) — bastion-less PQC file transfer. See `P2P_SCP_DESIGN.md`.
//!
//! A third service ALPN alongside the PTY shell (`nkct/shell/2`) and the
//! port-forward (`nkct/fwd/2`). Where the legacy `ALPN_FILE` stream was a raw
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
//! Security posture: every file operation runs as the server's own user
//! (`--serve-scp` refuses to run as root), confined to the policy's read/write
//! roots. A policy `user=NAME` is enforced under the **per-user-instance model**
//! (`enforce_scp_user`): with no in-process privilege drop, it is honored only
//! when NAME is the server's own user — to serve another user's files, run a
//! separate `--serve-scp` as that user. A `user=` naming anyone else refuses the
//! session (fail closed) rather than silently running as the wrong user.
//! Directory recursion (`-r`) is implemented: serial tree put/get with
//! per-entry confinement (see `walk_tree` / `safe_join`).
//!
//! ## Path-confinement hardening by platform
//!
//! Every open pairs a no-follow final component (`O_NOFOLLOW` on unix; a
//! reparse-point refusal on windows) with an **after-open real-path re-check**
//! against the policy roots ([`recheck_fd_confined`] /
//! [`recheck_handle_confined`]), which closes the intermediate-directory link
//! race a check-time `canonicalize` cannot. That re-check is available on
//! **Linux** (`/proc/self/fd`), **macOS** (`fcntl(F_GETPATH)`) and **windows**
//! (`GetFinalPathNameByHandleW`). On any other Unix the re-check **fails
//! closed** — the operation is refused rather than served unconfined (porting
//! FreeBSD `O_RESOLVE_BENEATH` would re-enable it). Wire `mode` bits are unix
//! permissions; windows does not map them (staged files keep their owner-only
//! DACL, directories inherit the parent ACL).

use crate::error::{CryptoError, Result};
use crate::shell::{
    audit, audit_best_effort, extract_kv, extract_quoted_span, io_err, parse_fp_hex,
    recv_packet, role_keys, send_packet,
};
use std::collections::HashMap;
use std::io::{IsTerminal, Write as _};
use std::path::{Component, Path, PathBuf};
use std::time::Instant;
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
const T_RESUME: u8 = 0x0a;
const T_RESUMEFROM: u8 = 0x0b;

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
    /// Client → server: resume a single-file download from `offset`. The client
    /// proves its partial matches the server's current file by sending the
    /// SHA-256 of its first `offset` bytes; the server re-hashes and replies with
    /// [`ScpFrame::ResumeFrom`].
    Resume { path: String, offset: u64, prefix_sha256: [u8; 32] },
    /// Server → client: response to `Resume`. `size` is the file's full size; the
    /// `Data` stream that follows covers `[offset, size)`. `offset` equals the
    /// client's offset when the partial verified (true resume), or `0` when it did
    /// not (stale / shrunk / changed) — the client then truncates its partial and
    /// takes the full file. One connection handles both without a re-run.
    ResumeFrom { file_id: u32, mode: u32, size: u64, offset: u64 },
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
            ScpFrame::Resume { path, offset, prefix_sha256 } => {
                v.push(T_RESUME);
                v.extend_from_slice(&offset.to_be_bytes());
                v.extend_from_slice(prefix_sha256);
                put_u32(&mut v, path.len() as u32);
                v.extend_from_slice(path.as_bytes());
            }
            ScpFrame::ResumeFrom { file_id, mode, size, offset } => {
                v.push(T_RESUMEFROM);
                put_u32(&mut v, *file_id);
                put_u32(&mut v, *mode);
                v.extend_from_slice(&size.to_be_bytes());
                v.extend_from_slice(&offset.to_be_bytes());
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
            T_RESUME => {
                // offset(8) ‖ prefix_sha256(32) ‖ plen(4) ‖ path
                if rest.len() < 44 {
                    return Err(bad());
                }
                let offset = u64::from_be_bytes(rest[0..8].try_into().map_err(|_| bad())?);
                let mut prefix_sha256 = [0u8; 32];
                prefix_sha256.copy_from_slice(&rest[8..40]);
                let plen = get_u32(rest, 40).ok_or_else(bad)? as usize;
                let body = &rest[44..];
                if body.len() < plen {
                    return Err(bad());
                }
                let path = std::str::from_utf8(&body[..plen]).map_err(|_| bad())?.to_string();
                Ok(ScpFrame::Resume { path, offset, prefix_sha256 })
            }
            T_RESUMEFROM => {
                // file_id(4) ‖ mode(4) ‖ size(8) ‖ offset(8)
                if rest.len() < 24 {
                    return Err(bad());
                }
                let file_id = get_u32(rest, 0).ok_or_else(bad)?;
                let mode = get_u32(rest, 4).ok_or_else(bad)?;
                let size = u64::from_be_bytes(rest[8..16].try_into().map_err(|_| bad())?);
                let offset = u64::from_be_bytes(rest[16..24].try_into().map_err(|_| bad())?);
                Ok(ScpFrame::ResumeFrom { file_id, mode, size, offset })
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
pub(crate) async fn drain_until_close(reader: &mut (impl AsyncReadExt + Unpin)) {
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
    // The per-fingerprint `user=` mapping, enforced under the per-user-instance
    // model: honored only when it names the server's OWN user (see
    // `enforce_scp_user`), since there is no in-process privilege drop.
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

    /// The `user=` mapping for a fingerprint, if any.
    fn user_for(&self, fp: &[u8; 32]) -> Option<&str> {
        self.user.get(fp).map(String::as_str)
    }
}

/// Enforce a policy `user=` mapping under the **per-user-instance model**. The
/// scp server has no in-process privilege drop — every file operation runs as
/// the server's own user (root is refused at startup) — so a `user=NAME` is
/// honored only when NAME is the server's own user. To serve a different user's
/// files, run a separate `--serve-scp` logged in as that user. Mirrors the
/// shell's Tier-1 `enforce_same_user`. `None` (no mapping) always passes.
#[cfg(unix)]
fn enforce_scp_user(policy_user: Option<&str>) -> std::result::Result<(), String> {
    let Some(name) = policy_user else { return Ok(()) };
    let euid = unsafe { libc::geteuid() };
    match crate::utils::uid_by_name(name) {
        Some(uid) if uid == euid => Ok(()),
        Some(_) => Err(format!(
            "policy maps this fingerprint to user {name:?}, but --serve-scp cannot switch \
             users (running as uid {euid}); map to the server's own user or run a per-user \
             --serve-scp instance"
        )),
        None => Err(format!("policy maps this fingerprint to unknown user {name:?}")),
    }
}

/// Windows has no setuid drop, so a `user=` mapping to any account cannot be
/// honored; the transfer always runs as the server's own account. Refuse rather
/// than silently run as the wrong user (mirrors the shell).
#[cfg(windows)]
fn enforce_scp_user(policy_user: Option<&str>) -> std::result::Result<(), String> {
    match policy_user {
        None => Ok(()),
        Some(name) => Err(format!(
            "policy maps this fingerprint to user {name:?}, but --serve-scp on Windows runs \
             as the server's own account (no user switching); remove user= or run a per-user \
             --serve-scp instance"
        )),
    }
}

/// Fallback for platforms with neither setuid nor a Windows token model: a
/// `user=` mapping cannot be honored, so refuse it.
#[cfg(not(any(unix, windows)))]
fn enforce_scp_user(policy_user: Option<&str>) -> std::result::Result<(), String> {
    match policy_user {
        None => Ok(()),
        Some(name) => Err(format!("policy user= ({name:?}) is unsupported on this platform")),
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

/// The kernel's fully symlink-resolved path of an open fd. Used to re-verify
/// **after open** that the opened inode is still under a policy root: `confine_*`
/// canonicalizes at check time and `O_NOFOLLOW` guards only the final component,
/// so an attacker who swaps an *intermediate* directory for a symlink between
/// check and open could otherwise escape the root. The post-open path reflects
/// what the kernel actually traversed, closing that race.
///
/// Linux reads `/proc/self/fd/<fd>`; macOS uses `fcntl(F_GETPATH)`, which returns
/// the vnode's real path (intermediate symlinks resolved). Both are the sound
/// fd-based analog — a second path-based `canonicalize` would just reintroduce
/// the same TOCTOU. Platforms without such a primitive are handled by
/// [`recheck_fd_confined`] (fail closed).
#[cfg(target_os = "linux")]
fn fd_real_path(fd: std::os::fd::RawFd) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/self/fd/{fd}")).ok()
}

#[cfg(target_os = "macos")]
fn fd_real_path(fd: std::os::fd::RawFd) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStringExt;
    // F_GETPATH writes a NUL-terminated path of at most PATH_MAX bytes into buf.
    let mut buf = vec![0u8; libc::PATH_MAX as usize];
    // SAFETY: `buf` is PATH_MAX bytes and `fd` is a live descriptor for the call.
    let rc = unsafe { libc::fcntl(fd, libc::F_GETPATH, buf.as_mut_ptr()) };
    if rc != 0 {
        return None;
    }
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    buf.truncate(len);
    Some(PathBuf::from(std::ffi::OsString::from_vec(buf)))
}

/// Windows analog of [`fd_real_path`]: the kernel's fully-resolved path of an
/// open handle via `GetFinalPathNameByHandleW` (`FILE_NAME_NORMALIZED` +
/// `VOLUME_NAME_DOS`, i.e. `\\?\C:\...`). `CreateFileW` silently follows
/// junctions/symlinks in *intermediate* components even when the final
/// component is opened with `FILE_FLAG_OPEN_REPARSE_POINT`, so this post-open
/// re-check plays exactly the role `/proc/self/fd` does on Linux. The policy
/// roots are canonicalized at load time, which yields the same `\\?\`-prefixed,
/// true-case form, so `under_any`'s component-wise `starts_with` compares like
/// with like.
#[cfg(windows)]
fn handle_real_path(handle: std::os::windows::io::RawHandle) -> Option<PathBuf> {
    use windows_sys::Win32::Storage::FileSystem::{
        GetFinalPathNameByHandleW, FILE_NAME_NORMALIZED, VOLUME_NAME_DOS,
    };
    let mut buf = vec![0u16; 512];
    loop {
        // Returns the LENGTH written (excl. NUL) on success, or the REQUIRED
        // buffer size (incl. NUL) when the buffer is too small.
        let n = unsafe {
            GetFinalPathNameByHandleW(
                handle as _,
                buf.as_mut_ptr(),
                buf.len() as u32,
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
            )
        };
        if n == 0 {
            return None;
        }
        if (n as usize) < buf.len() {
            buf.truncate(n as usize);
            use std::os::windows::ffi::OsStringExt;
            return Some(PathBuf::from(std::ffi::OsString::from_wide(&buf)));
        }
        buf.resize(n as usize + 1, 0);
    }
}

/// Windows twin of [`recheck_fd_confined`]: re-verify that an open handle
/// actually landed under one of `roots` (closing the intermediate
/// junction/symlink race that a check-time `canonicalize` plus a no-follow
/// final component cannot).
#[cfg(windows)]
fn recheck_handle_confined(
    handle: std::os::windows::io::RawHandle,
    roots: &[PathBuf],
) -> std::result::Result<(), String> {
    match handle_real_path(handle) {
        Some(p) if under_any(&p, roots) => Ok(()),
        Some(_) => Err("path escaped root after open (intermediate-link race)".into()),
        None => Err("could not verify the opened path against a policy root".into()),
    }
}

/// Re-verify, after opening `fd` with `O_NOFOLLOW`, that the kernel actually
/// landed on an inode under one of `roots` — closing the intermediate-directory
/// symlink race that `O_NOFOLLOW` (final component only) plus a check-time
/// `canonicalize` cannot.
///
/// On Linux and macOS this consults [`fd_real_path`]; on windows,
/// [`recheck_handle_confined`] is the handle-based twin. On any other Unix
/// (FreeBSD and friends) there is no equivalent fd→realpath primitive here, so
/// we **fail closed**: rather than silently skip the re-check and serve an
/// operation we cannot confine, we refuse it. Serving scp on those platforms
/// therefore requires porting this re-check (e.g. FreeBSD `O_RESOLVE_BENEATH`).
#[cfg(unix)]
fn recheck_fd_confined(
    fd: std::os::fd::RawFd,
    roots: &[PathBuf],
) -> std::result::Result<(), String> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        match fd_real_path(fd) {
            Some(p) if under_any(&p, roots) => Ok(()),
            Some(_) => Err("path escaped root after open (intermediate-symlink race)".into()),
            None => Err("could not verify the opened path against a policy root".into()),
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (fd, roots);
        Err("scp path confinement is only hardened against local symlink races on \
             Linux and macOS; refusing this operation on the current platform"
            .into())
    }
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
/// plus the fd real-path re-check against `roots` (closing the intermediate-
/// directory link race; Linux/macOS/windows, fail-closed on other Unix — see
/// [`recheck_fd_confined`]). Returns `(file, mode, size)`; `mode`
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
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // O_NOFOLLOW analog: open a final-component link as the link entity
        // (rejected right below) instead of following it.
        opts.custom_flags(
            windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT,
        );
    }
    let file = opts.open(src).map_err(|e| format!("open {}: {e}", src.display()))?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        recheck_fd_confined(file.as_raw_fd(), roots)?;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use std::os::windows::io::AsRawHandle;
        let attrs = file.metadata().map_err(|e| e.to_string())?.file_attributes();
        if attrs & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(format!("{} is a reparse point (symlink/junction)", src.display()));
        }
        recheck_handle_confined(file.as_raw_handle(), roots)?;
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

/// Blocking: verify the client's resume prefix and position `file` for the send.
/// Returns `(from_offset, file)` = `(offset, file@offset)` when the first
/// `offset` bytes of `file` hash to `expect` (and `offset <= size`), else
/// `(0, file@0)` — a shrink / change / stale partial falls back to a full send,
/// and the client truncates its partial. The comparison is over an integrity
/// hash (no secret), so plain equality is fine.
fn verify_resume(
    mut file: std::fs::File,
    size: u64,
    offset: u64,
    expect: &[u8; 32],
) -> std::io::Result<(u64, std::fs::File)> {
    use sha2::{Digest, Sha256};
    use std::io::{Read, Seek, SeekFrom};
    fn rewind(mut f: std::fs::File) -> std::io::Result<(u64, std::fs::File)> {
        f.seek(SeekFrom::Start(0))?;
        Ok((0, f))
    }
    if offset == 0 || offset > size {
        return rewind(file);
    }
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut remaining = offset;
    let mut buf = vec![0u8; 128 * 1024];
    while remaining > 0 {
        let want = remaining.min(buf.len() as u64) as usize;
        let n = file.read(&mut buf[..want])?;
        if n == 0 {
            return rewind(file); // file is now shorter than offset → restart
        }
        hasher.update(&buf[..n]);
        remaining -= n as u64;
    }
    let got: [u8; 32] = hasher.finalize().into();
    if &got == expect {
        Ok((offset, file)) // position is exactly at `offset` after the read
    } else {
        rewind(file)
    }
}

/// Blocking: SHA-256 of the first `len` bytes of `path` (the client's resume
/// partial). Matches `verify_resume` on the server so a prefix compare succeeds.
fn hash_prefix_blocking(path: &Path, len: u64) -> std::io::Result<[u8; 32]> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut f = crate::secure_fs::open_existing_no_follow(path, false)?;
    let mut hasher = Sha256::new();
    let mut remaining = len;
    let mut buf = vec![0u8; 128 * 1024];
    while remaining > 0 {
        let want = remaining.min(buf.len() as u64) as usize;
        let n = f.read(&mut buf[..want])?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        remaining -= n as u64;
    }
    Ok(hasher.finalize().into())
}

struct Staged {
    temp: PathBuf,
    final_path: PathBuf,
    file: Option<tokio::fs::File>,
    /// When true (a `--scp-resume` partial), Drop keeps the staging file so an
    /// interrupted download can continue next time; commit still renames it away.
    keep_partial: bool,
}

/// Stable staging name for a resumable get: `.<name>.nkct-partial` next to the
/// final path, so a re-run finds the partial to continue from.
fn partial_path(final_path: &Path) -> PathBuf {
    let fname = final_path.file_name().and_then(|s| s.to_str()).unwrap_or("recv");
    let name = format!(".{fname}.nkct-partial");
    match final_path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.join(name),
        _ => PathBuf::from(name),
    }
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
        // SECURITY-CRITICAL: this 64-bit `OsRng` draw is not a uniquifier for
        // debugging — it is what makes `commit`'s rename safe against a parent
        // swap (see `commit`). An attacker who could predict the temp name could
        // pre-place a file under it in a directory they swap in, and win the
        // race. Never replace it with a pid, a counter, or a timestamp.
        let temp_name = format!(".{}.tmp.{:016x}", fname, rand_core::OsRng.next_u64());
        let temp = match final_path.parent() {
            Some(dir) if !dir.as_os_str().is_empty() => dir.join(temp_name),
            _ => PathBuf::from(temp_name),
        };
        // Exclusive create, owner-only from birth on unix (0600) and windows
        // (owner-only DACL via SECURITY_ATTRIBUTES) alike, link refusal
        // included — see `crate::secure_fs`. Partial transfer bytes are never
        // readable by other local users while staged.
        let std_file = crate::secure_fs::create_owner_only(&temp, false)?;
        Ok(Self {
            temp,
            final_path,
            file: Some(tokio::fs::File::from_std(std_file)),
            keep_partial: false,
        })
    }

    /// Open the stable resume partial for `final_path`. `from == 0` truncates a
    /// fresh partial; `from > 0` opens the existing partial for append. Returns
    /// `(staged, actual_len)` — the caller checks `actual_len == from` for append.
    /// The partial is owner-only + link-refusing, and (unlike `create`) is kept on
    /// Drop so an interrupted transfer can resume.
    fn open_partial(final_path: PathBuf, from: u64) -> std::io::Result<(Self, u64)> {
        let temp = partial_path(&final_path);
        let (std_file, actual_len) = if from > 0 {
            let f = crate::secure_fs::open_append_owner_only(&temp)?;
            let len = f.metadata()?.len();
            (f, len)
        } else {
            (crate::secure_fs::create_owner_only(&temp, true)?, 0)
        };
        Ok((
            Self {
                temp,
                final_path,
                file: Some(tokio::fs::File::from_std(std_file)),
                keep_partial: true,
            },
            actual_len,
        ))
    }

    async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.file.as_mut().expect("staged file open").write_all(buf).await
    }

    /// Re-verify the staging fd/handle actually landed under a write root — a
    /// post-create confinement check against an intermediate-link swap between
    /// confine and open. Real check on Linux/macOS/windows, fail-closed on
    /// other Unix (see [`recheck_fd_confined`]).
    fn recheck_confined(&self, roots: &[PathBuf]) -> std::result::Result<(), String> {
        let f = self.file.as_ref().ok_or("staging file already closed")?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            recheck_fd_confined(f.as_raw_fd(), roots)
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            recheck_handle_confined(f.as_raw_handle(), roots)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (f, roots);
            Err("scp path confinement is not implemented on this platform".into())
        }
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
        // The wire `mode` is unix permission bits; on windows the staged file
        // keeps the owner-only DACL it was created with (there is no
        // meaningful mapping, and inheriting looser ACLs would be a downgrade).
        #[cfg(not(unix))]
        let _ = mode;
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
        // The rename is path-based — the one operation on this path that is not
        // anchored to an already-verified fd. Its safety rests on two properties,
        // and on nothing else; both hold at every call site (client get, get -r,
        // resume, and server put):
        //
        //   1. `temp` and `final_path` share the SAME parent directory, so an
        //      attacker who swaps an intermediate directory has BOTH names
        //      resolve under the swapped-in directory. Source and destination
        //      move together, never apart.
        //   2. `temp`'s name carries 64 unpredictable bits (see `create`), and
        //      the staged file is owner-only, so that name cannot be observed
        //      from outside this process.
        //
        // To publish content of their choosing at `final_path`, an attacker
        // would have to pre-place a file under that unguessed name inside the
        // directory they swap in — a 2^-64 shot. Not an impossibility: it is the
        // margin this design is built on, which is why (2) must not be weakened.
        // Losing that race means `rename` finds no source and fails with ENOENT,
        // so the transfer fails and nothing is published anywhere.
        //
        // Note the scope: server-side `put` additionally re-verifies the staging
        // fd against the policy roots before reaching here (`recheck_confined`),
        // but the three client-side paths have no policy roots and rest on (1)
        // and (2) alone. Any claim stronger than that does not hold for them.
        std::fs::rename(&self.temp, &self.final_path)
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        // A committed transfer already renamed the temp away. An interrupted one:
        // for a resume partial (`keep_partial`) keep the bytes so the next run can
        // continue; otherwise discard them (no partial/unauthenticated bytes left).
        let _ = self.file.take();
        if !self.keep_partial {
            let _ = std::fs::remove_file(&self.temp);
        }
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
/// Below this size a transfer is effectively instant, so a `\r` progress line
/// would only flicker; draw one only for larger files.
const PROGRESS_MIN: u64 = 512 * 1024;

/// A `\r`-updating transfer-progress line on stderr, throttled to ~10 Hz. Active
/// only when stderr is a TTY — so a backgrounded server never draws it, only an
/// interactive client does — and only for transfers past [`PROGRESS_MIN`]. No
/// extra deps: same raw-ANSI approach as the shell's status bar.
struct Progress {
    total: u64,
    start: Instant,
    last: Instant,
    label: &'static str,
    active: bool,
}

impl Progress {
    fn new(total: u64, label: &'static str) -> Self {
        let active = total >= PROGRESS_MIN && std::io::stderr().is_terminal();
        let now = Instant::now();
        Progress { total, start: now, last: now, label, active }
    }

    fn tick(&mut self, done: u64) {
        if !self.active {
            return;
        }
        let now = Instant::now();
        // Redraw at most ~10 Hz, but always draw the final (done == total) frame.
        if done < self.total && now.duration_since(self.last).as_millis() < 100 {
            return;
        }
        self.last = now;
        let pct = if self.total > 0 { done.saturating_mul(100) / self.total } else { 100 };
        let mib = 1024.0 * 1024.0;
        let secs = self.start.elapsed().as_secs_f64().max(0.001);
        let mut err = std::io::stderr();
        // Trailing spaces clear any remainder of a previous, longer line.
        let _ = write!(
            err,
            "\r[scp] {} {:3}%  {:.1}/{:.1} MiB  {:.1} MiB/s   ",
            self.label,
            pct,
            done as f64 / mib,
            self.total as f64 / mib,
            (done as f64 / secs) / mib,
        );
        let _ = err.flush();
    }

    fn finish(&mut self) {
        if self.active {
            let _ = writeln!(std::io::stderr());
        }
    }
}

/// sealing it in place — no per-chunk copy. Returns the number of bytes sent.
async fn stream_bytes<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    aead: &str,
    key: &[u8],
    ctr: &mut u64,
    file_id: u32,
    f: &mut tokio::fs::File,
) -> Result<u64> {
    let total = f.metadata().await.map(|m| m.len()).unwrap_or(0);
    let mut prog = Progress::new(total, "send");
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
        prog.tick(sent);
    }
    prog.finish();
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
    let mut prog = Progress::new(size, "recv");
    loop {
        match recv(r, aead, key, ctr).await? {
            Some(ScpFrame::Data { file_id: fid, bytes }) if fid == file_id => {
                received += bytes.len() as u64;
                if received > size {
                    return Err(param(format!("stream exceeds declared size {size}")));
                }
                staged.write_all(&bytes).await.map_err(io_err)?;
                prog.tick(received);
            }
            Some(ScpFrame::Eof { file_id: fid }) if fid == file_id => break,
            Some(ScpFrame::Err(m)) => return Err(param(format!("peer error mid-file: {m}"))),
            Some(other) => return Err(param(format!("unexpected frame in file body: {other:?}"))),
            None => return Err(param("stream closed before Eof".into())),
        }
    }
    prog.finish();
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
    /// directory tree copied under the local path. `resume` (single file only)
    /// continues from a kept `.<name>.nkct-partial`.
    Get { remote: String, local: PathBuf, recursive: bool, resume: bool },
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
        ScpOp::Get { remote, local, recursive, resume } => {
            if *resume && !*recursive {
                // --- resumable single-file get -------------------------------
                // If a partial exists, ask the server to continue from its end
                // (proving the prefix by hash); else start fresh. The server's
                // ResumeFrom.offset is our offset (true resume) or 0 (restart —
                // the partial was stale, take the whole file).
                let partial = partial_path(local);
                let have = std::fs::metadata(&partial).map(|m| m.len()).unwrap_or(0);
                if have > 0 {
                    let p = partial.clone();
                    let prefix = tokio::task::spawn_blocking(move || hash_prefix_blocking(&p, have))
                        .await
                        .map_err(|e| CryptoError::Parameter(format!("hash partial: {e}")))?
                        .map_err(|e| CryptoError::Parameter(format!("hash partial {}: {e}", partial.display())))?;
                    send(&mut writer, aead_name, tx_key, &mut tx, &ScpFrame::Resume { path: remote.clone(), offset: have, prefix_sha256: prefix }).await?;
                } else {
                    send(&mut writer, aead_name, tx_key, &mut tx, &ScpFrame::Get { path: remote.clone(), recursive: false }).await?;
                }
                let (file_id, mode, size, from) = match recv(&mut reader, aead_name, rx_key, &mut rx).await? {
                    Some(ScpFrame::ResumeFrom { file_id, mode, size, offset }) => (file_id, mode, size, offset),
                    Some(ScpFrame::Put { file_id, mode, size, .. }) => (file_id, mode, size, 0),
                    Some(ScpFrame::Err(m)) => return Err(CryptoError::Parameter(format!("scp get refused: {m}"))),
                    other => return Err(CryptoError::Parameter(format!("scp get: unexpected reply {other:?}"))),
                };
                if from > size {
                    return Err(CryptoError::Parameter("scp resume: server offset past size".into()));
                }
                let (mut staged, actual) = Staged::open_partial(local.clone(), from)
                    .map_err(|e| CryptoError::Parameter(format!("stage {}: {e}", partial.display())))?;
                if from > 0 && actual != from {
                    return Err(CryptoError::Parameter(format!(
                        "scp resume: partial changed under us (have {actual}, expected {from})"
                    )));
                }
                if from > 0 {
                    eprintln!("[nkct] resuming {remote} from {from}/{size} bytes");
                }
                // The Data stream covers [from, size): recv_into_staged is bounded
                // by that remainder and appends (the partial is positioned at `from`).
                recv_into_staged(&mut reader, aead_name, rx_key, &mut rx, file_id, size - from, &mut staged).await?;
                staged.commit(mode).await.map_err(|e| CryptoError::Parameter(format!("commit {}: {e}", local.display())))?;
                send(&mut writer, aead_name, tx_key, &mut tx, &ScpFrame::Ack { file_id }).await?;
                match recv(&mut reader, aead_name, rx_key, &mut rx).await? {
                    Some(ScpFrame::Done) | None => {}
                    Some(ScpFrame::Err(m)) => return Err(CryptoError::Parameter(format!("scp get failed: {m}"))),
                    other => return Err(CryptoError::Parameter(format!("scp get: expected Done, got {other:?}"))),
                }
                let _ = writer.shutdown().await;
                eprintln!("[nkct] downloaded {remote} ({size} bytes) → {}", local.display());
                return Ok(());
            }
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
    // concurrency is bounded by the session admission pool
    // (`crate::p2p::processor::AdmissionLimits`, NKCT_MAX_SESSIONS), which unauthenticated peers
    // cannot spend from.

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

    // Session-level `user=` gate (per-user-instance model): if the policy maps
    // this fingerprint to a user we are not, refuse the whole session before any
    // file operation. Uniform "denied" on the wire; reason to the audit log.
    if let Err(reason) = enforce_scp_user(policy.user_for(&peer_fp)) {
        deny!(reason);
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
                // unix permission bits; on windows the created directory keeps
                // the parent-inherited ACL (no meaningful mapping).
                #[cfg(not(unix))]
                let _ = mode;
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
                        // confine→create intermediate-link race, Linux/macOS/windows).
                        let mut o = std::fs::OpenOptions::new();
                        o.read(true);
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::OpenOptionsExt;
                            o.custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY);
                        }
                        #[cfg(windows)]
                        {
                            use std::os::windows::fs::OpenOptionsExt;
                            // BACKUP_SEMANTICS is required to open a directory
                            // handle; OPEN_REPARSE_POINT opens a planted
                            // junction as the link entity (rejected below).
                            o.custom_flags(
                                windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS
                                    | windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT,
                            );
                        }
                        let ok = match o.open(&dir) {
                            Ok(dfd) => {
                                // Re-check the opened directory handle is under a
                                // write root (Linux/macOS/windows; fail-closed on
                                // other platforms).
                                #[cfg(unix)]
                                let under = {
                                    use std::os::fd::AsRawFd;
                                    recheck_fd_confined(dfd.as_raw_fd(), policy.roots(&peer_fp, true)).is_ok()
                                };
                                #[cfg(windows)]
                                let under = {
                                    use std::os::windows::fs::MetadataExt;
                                    use std::os::windows::io::AsRawHandle;
                                    let not_reparse = dfd.metadata().is_ok_and(|m| {
                                        m.file_attributes()
                                            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
                                            == 0
                                    });
                                    not_reparse
                                        && recheck_handle_confined(
                                            dfd.as_raw_handle(),
                                            policy.roots(&peer_fp, true),
                                        )
                                        .is_ok()
                                };
                                #[cfg(not(any(unix, windows)))]
                                let under = false;
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
                // Post-create confinement re-check: if the staging fd/handle did
                // not land under a write root (intermediate-link swap between
                // confine and open), or the platform cannot verify it, discard —
                // we still consume the body below to keep the stream in sync,
                // then Fail.
                if let Some(s) = &staged {
                    if s.recheck_confined(policy.roots(&peer_fp, true)).is_err() {
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
            // ---- resume: single-file download continued from a verified offset ----
            Some(ScpFrame::Resume { path, offset, prefix_sha256 }) => {
                let read_roots = policy.roots(&peer_fp, false);
                let src = match confine_read(&path, read_roots) {
                    Ok(s) => s,
                    Err(e) => deny!(format!("resume {path}: {e}")),
                };
                let (file, mode, size) = match open_confined_read(&src, read_roots) {
                    Ok(t) => t,
                    Err(e) => deny!(format!("resume {path}: {e}")),
                };
                if let Err(e) = audit(audit_path, &peer_fp, &format!("scp allow resume path={} off={offset} bytes={size}", src.display())).await {
                    let _ = send(&mut writer, aead_name, tx_key, &mut tx, &ScpFrame::Err("audit unavailable; refusing".into())).await;
                    return Err(CryptoError::Parameter(format!("scp refused: audit write failed: {e}")));
                }
                // Verify the client's partial prefix off the executor; on any
                // mismatch / shrink, fall back to a full send from 0 (the client
                // truncates its partial). Same connection, no re-run.
                let (from_offset, positioned) = tokio::task::spawn_blocking(move || verify_resume(file, size, offset, &prefix_sha256))
                    .await
                    .map_err(|e| CryptoError::Parameter(format!("resume verify join: {e}")))?
                    .map_err(|e| CryptoError::Parameter(format!("resume verify: {e}")))?;
                next_id += 1;
                send(&mut writer, aead_name, tx_key, &mut tx, &ScpFrame::ResumeFrom { file_id: next_id, mode, size, offset: from_offset }).await?;
                let mut f = tokio::fs::File::from_std(positioned);
                let sent = stream_bytes(&mut writer, aead_name, tx_key, &mut tx, next_id, &mut f).await?;
                let _ = recv(&mut reader, aead_name, rx_key, &mut rx).await?;
                send(&mut writer, aead_name, tx_key, &mut tx, &ScpFrame::Done).await?;
                audit_best_effort(audit_path, &peer_fp, &format!("scp resume ok path={} from={from_offset} sent={sent}", src.display())).await;
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
            ScpFrame::Resume { path: "/srv/pub/big.bin".into(), offset: 1 << 33, prefix_sha256: [0x5a; 32] },
            ScpFrame::ResumeFrom { file_id: 3, mode: 0o644, size: 1 << 40, offset: 1 << 33 },
            ScpFrame::ResumeFrom { file_id: 4, mode: 0o600, size: 100, offset: 0 },
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
    fn resume_verify_prefix() {
        use sha2::{Digest, Sha256};
        use std::io::{Seek, SeekFrom};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.bin");
        let data = vec![7u8; 1000];
        std::fs::write(&path, &data).unwrap();
        let good: [u8; 32] = { let mut h = Sha256::new(); h.update(&data[..500]); h.finalize().into() };

        // Correct prefix at offset 500 → resume from 500, positioned at 500.
        let f = std::fs::File::open(&path).unwrap();
        let (off, mut fp) = verify_resume(f, 1000, 500, &good).unwrap();
        assert_eq!(off, 500);
        assert_eq!(fp.stream_position().unwrap(), 500);

        // Wrong prefix → restart from 0, rewound.
        let f = std::fs::File::open(&path).unwrap();
        let (off, mut fp) = verify_resume(f, 1000, 500, &[0u8; 32]).unwrap();
        assert_eq!(off, 0);
        assert_eq!(fp.seek(SeekFrom::Current(0)).unwrap(), 0);

        // Offset past current size → restart from 0.
        let f = std::fs::File::open(&path).unwrap();
        assert_eq!(verify_resume(f, 1000, 2000, &good).unwrap().0, 0);
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

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn fd_real_path_reveals_intermediate_symlink_escape() {
        // The post-open re-check's mechanism: opening a file through an
        // intermediate directory symlink that escapes the root yields an fd whose
        // real path (Linux /proc/self/fd, macOS F_GETPATH) is *outside* the root,
        // so under_any() rejects it — this is what closes the check→open swap race
        // that O_NOFOLLOW (final component only) cannot. `recheck_fd_confined`
        // wraps exactly this and must Err on the escaped fd while Ok'ing a
        // genuinely-confined one.
        use std::os::fd::AsRawFd;
        let dir = std::env::temp_dir().join(format!("nkct-scp-fdrp-{:x}", std::process::id()));
        let root = dir.join("root");
        let secret = dir.join("secret");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&secret).unwrap();
        std::fs::write(secret.join("data"), b"x").unwrap();
        std::fs::write(root.join("real"), b"y").unwrap();
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
        assert!(
            recheck_fd_confined(f.as_raw_fd(), &roots).is_err(),
            "recheck must reject the escaped fd",
        );

        // A genuinely-confined open re-checks Ok.
        let g = std::fs::OpenOptions::new()
            .read(true)
            .open(root.join("real"))
            .unwrap();
        assert!(
            recheck_fd_confined(g.as_raw_fd(), &roots).is_ok(),
            "recheck must accept an in-root fd",
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Create an NTFS directory junction (`mklink /J`) — needs no privilege,
    /// unlike a file symlink, so it runs on any windows box.
    #[cfg(windows)]
    fn make_junction(link: &Path, target: &Path) {
        let st = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .status()
            .expect("spawn cmd mklink");
        assert!(st.success(), "mklink /J failed");
    }

    /// Windows twin of `fd_real_path_reveals_intermediate_symlink_escape`: an
    /// *intermediate* junction inside the root pointing outside it is followed
    /// silently by CreateFileW, but `GetFinalPathNameByHandleW` reveals the
    /// escape and `recheck_handle_confined` must reject it — while accepting a
    /// genuinely in-root handle. `open_confined_read` wires both together and
    /// must deny end-to-end.
    #[cfg(windows)]
    #[test]
    fn windows_confine_handle_reveals_junction_escape() {
        use std::os::windows::io::AsRawHandle;
        let dir = std::env::temp_dir().join(format!("nkct-scp-wj-{:x}", std::process::id()));
        let root = dir.join("root");
        let secret = dir.join("secret");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&secret).unwrap();
        std::fs::write(secret.join("data"), b"x").unwrap();
        std::fs::write(root.join("real"), b"y").unwrap();
        make_junction(&root.join("link"), &secret);
        let roots = vec![std::fs::canonicalize(&root).unwrap()];

        // Final component ("data") is a real file, so the open succeeds even
        // though it traversed the junction — the post-open re-check must catch it.
        let f = std::fs::OpenOptions::new()
            .read(true)
            .open(root.join("link").join("data"))
            .unwrap();
        let real = handle_real_path(f.as_raw_handle()).unwrap();
        assert!(!under_any(&real, &roots), "escaped path {real:?} must be rejected");
        assert!(
            recheck_handle_confined(f.as_raw_handle(), &roots).is_err(),
            "recheck must reject the escaped handle",
        );
        assert!(
            open_confined_read(&root.join("link").join("data"), &roots).is_err(),
            "open_confined_read must deny a junction escape",
        );

        // A genuinely-confined open re-checks Ok end-to-end.
        let g = std::fs::OpenOptions::new().read(true).open(root.join("real")).unwrap();
        assert!(recheck_handle_confined(g.as_raw_handle(), &roots).is_ok());
        assert!(open_confined_read(&root.join("real"), &roots).is_ok());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Windows: a staging file created under an intermediate junction that
    /// escapes the write root must be caught by `Staged::recheck_confined`.
    #[cfg(windows)]
    #[tokio::test]
    async fn windows_confine_staged_rejects_junction_parent() {
        let dir = std::env::temp_dir().join(format!("nkct-scp-wsj-{:x}", std::process::id()));
        let root = dir.join("root");
        let outside = dir.join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        make_junction(&root.join("jdir"), &outside);
        let roots = vec![std::fs::canonicalize(&root).unwrap()];

        // Staged under the junction: physically lands outside the root.
        let s = Staged::create(root.join("jdir").join("up.bin")).unwrap();
        assert!(
            s.recheck_confined(&roots).is_err(),
            "staging under an escaping junction must be rejected",
        );
        drop(s);

        // Staged directly under the root passes.
        let ok = Staged::create(root.join("up.bin")).unwrap();
        assert!(ok.recheck_confined(&roots).is_ok());
        drop(ok);

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
