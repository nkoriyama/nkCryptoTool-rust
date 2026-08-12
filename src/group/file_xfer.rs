/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

//! File transfer framed over MLS **Application messages** (option 2 of the
//! group-file-transfer design): a file is split into a `START` / `DATA*` /
//! `END` sequence of frames, each sent as one MLS Application message. MLS
//! itself provides the confidentiality, integrity, sender authentication,
//! forward secrecy and post-compromise security for every frame — this layer
//! only adds in-band *framing* (so a receiver can tell a file apart from chat,
//! order the chunks, and know when the file is complete) plus a whole-file
//! SHA3-256 end-to-end integrity check.
//!
//! Frame layout (all integers big-endian), each carried in one app message:
//! ```text
//! START : MAGIC ‖ 0x01 ‖ id(16) ‖ total_size(u64) ‖ name_len(u16) ‖ name
//! DATA  : MAGIC ‖ 0x02 ‖ id(16) ‖ seq(u32) ‖ chunk_bytes
//! END   : MAGIC ‖ 0x03 ‖ id(16) ‖ total_chunks(u32) ‖ sha3_256(32)
//! ```
//! `id` is a random per-transfer identifier so concurrent transfers (and chat)
//! interleave safely. A body that does not begin with `MAGIC` is plain chat and
//! is left for the normal display path.

use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Magic prefix marking an app message as a file-transfer frame. Chosen to be
/// extremely unlikely to collide with a chat message's leading bytes.
pub const FILE_MAGIC: &[u8; 7] = b"NKFILE1";

/// Payload bytes per `DATA` frame. Kept well under `MAX_MLS_FRAME_BYTES` (16
/// MiB) so the framed app message — plus MLS overhead — stays comfortably
/// within one transport frame.
pub const FILE_CHUNK_SIZE: usize = 256 * 1024;

/// Hard cap on a single transfer's declared size (mirrors the 1:1 transfer
/// `MAX_FILE_SIZE`), so a malicious `START` cannot make a receiver pre-trust an
/// unbounded length.
pub const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024 * 1024;

const T_START: u8 = 1;
const T_DATA: u8 = 2;
const T_END: u8 = 3;

const ID_LEN: usize = 16;

/// Aggregate upper bound on simultaneously in-progress inbound transfers across
/// every group and sender, so a peer that opens many `START`s without ever
/// finishing them cannot exhaust memory / open staging files. Reaching this cap
/// *refuses* the new `START`: making room by discarding an in-progress transfer
/// would mean one sender destroying another sender's (or another group's)
/// receipt, which is exactly the cross-principal reach this cap must not have.
const MAX_CONCURRENT_TRANSFERS: usize = 16;

/// Per-principal bound: how many transfers one authenticated `(group, sender)`
/// may have in progress at once. A sender that reaches its own cap and opens a
/// genuinely new transfer discards *its own* oldest one — self-healing, so a
/// sender whose earlier transfers died mid-stream (crash, dropped link) is never
/// permanently locked out, and self-inflicted, so it can never reach another
/// principal's state. `MAX_CONCURRENT_TRANSFERS / MAX_TRANSFERS_PER_SENDER`
/// distinct authenticated principals are therefore needed before the aggregate
/// cap starts refusing anyone.
const MAX_TRANSFERS_PER_SENDER: usize = 4;

/// Reassembly key: a transfer is owned by the authenticated `(group, sender)`
/// that opened it, not just by the on-the-wire `id`. MLS authenticates the
/// sender (leaf index), so a *different* group member replaying a stolen `id`
/// lands under a different key — it cannot hijack or substitute another
/// sender's file. The `id` still lets one sender run concurrent transfers.
type TransferKey = ([u8; 32], u32, [u8; ID_LEN]);

/// True if `body` is one of our file-transfer frames (vs a chat message).
pub fn is_file_frame(body: &[u8]) -> bool {
    body.starts_with(FILE_MAGIC)
}

fn put_u16(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_be_bytes());
}
fn put_u32(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_be_bytes());
}
fn put_u64(v: &mut Vec<u8>, x: u64) {
    v.extend_from_slice(&x.to_be_bytes());
}

fn encode_start(id: &[u8; ID_LEN], total_size: u64, name: &str) -> Vec<u8> {
    let mut f = Vec::with_capacity(FILE_MAGIC.len() + 1 + ID_LEN + 8 + 2 + name.len());
    f.extend_from_slice(FILE_MAGIC);
    f.push(T_START);
    f.extend_from_slice(id);
    put_u64(&mut f, total_size);
    put_u16(&mut f, name.len() as u16);
    f.extend_from_slice(name.as_bytes());
    f
}

fn encode_data(id: &[u8; ID_LEN], seq: u32, chunk: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(FILE_MAGIC.len() + 1 + ID_LEN + 4 + chunk.len());
    f.extend_from_slice(FILE_MAGIC);
    f.push(T_DATA);
    f.extend_from_slice(id);
    put_u32(&mut f, seq);
    f.extend_from_slice(chunk);
    f
}

fn encode_end(id: &[u8; ID_LEN], total_chunks: u32, sha: &[u8; 32]) -> Vec<u8> {
    let mut f = Vec::with_capacity(FILE_MAGIC.len() + 1 + ID_LEN + 4 + 32);
    f.extend_from_slice(FILE_MAGIC);
    f.push(T_END);
    f.extend_from_slice(id);
    put_u32(&mut f, total_chunks);
    f.extend_from_slice(sha);
    f
}

/// Read `path` and produce the ordered frame sequence
/// (`START`, `DATA`×N, `END`) to send as MLS application messages, along with
/// the basename announced to receivers. The whole-file SHA3-256 is carried in
/// `END` for an end-to-end integrity check on the far side.
pub fn frame_file(path: &Path) -> std::io::Result<(String, Vec<Vec<u8>>)> {
    let data = std::fs::read(path)?;
    if data.len() as u64 > MAX_FILE_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "file exceeds MAX_FILE_SIZE",
        ));
    }
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| !n.is_empty())
        .unwrap_or("file.bin")
        .to_string();

    let mut id = [0u8; ID_LEN];
    {
        use rand_core::RngCore;
        rand_core::OsRng.fill_bytes(&mut id);
    }
    let sha: [u8; 32] = Sha3_256::digest(&data).into();

    let mut frames = Vec::new();
    frames.push(encode_start(&id, data.len() as u64, &name));
    let mut seq: u32 = 0;
    for chunk in data.chunks(FILE_CHUNK_SIZE) {
        frames.push(encode_data(&id, seq, chunk));
        seq += 1;
    }
    frames.push(encode_end(&id, seq, &sha));
    Ok((name, frames))
}

/// Streaming sender: yields the `START` / `DATA` / `END` frames for a file one
/// at a time, reading only one chunk into memory per `DATA` frame, so sending a
/// multi-gigabyte file does not load the whole file (nor all frames) into RAM.
pub struct OutgoingFile {
    id: [u8; ID_LEN],
    name: String,
    total_size: u64,
    reader: std::io::BufReader<std::fs::File>,
    seq: u32,
    hasher: Sha3_256,
    phase: Phase,
}

enum Phase {
    Start,
    Data,
    End,
    Done,
}

impl OutgoingFile {
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let meta = std::fs::metadata(path)?;
        if meta.len() > MAX_FILE_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "file exceeds MAX_FILE_SIZE",
            ));
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .filter(|n| !n.is_empty())
            .unwrap_or("file.bin")
            .to_string();
        let mut id = [0u8; ID_LEN];
        {
            use rand_core::RngCore;
            rand_core::OsRng.fill_bytes(&mut id);
        }
        Ok(Self {
            id,
            name,
            total_size: meta.len(),
            reader: std::io::BufReader::new(std::fs::File::open(path)?),
            seq: 0,
            hasher: Sha3_256::new(),
            phase: Phase::Start,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Produce the next frame to send, or `None` once the `END` has been
    /// yielded. Each `DATA` frame reads exactly one chunk from disk.
    pub fn next_frame(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        match self.phase {
            Phase::Start => {
                self.phase = Phase::Data;
                Ok(Some(encode_start(&self.id, self.total_size, &self.name)))
            }
            Phase::Data => {
                use std::io::Read;
                let mut buf = vec![0u8; FILE_CHUNK_SIZE];
                let mut filled = 0;
                while filled < buf.len() {
                    let n = self.reader.read(&mut buf[filled..])?;
                    if n == 0 {
                        break;
                    }
                    filled += n;
                }
                if filled == 0 {
                    self.phase = Phase::End;
                    return self.next_frame();
                }
                buf.truncate(filled);
                self.hasher.update(&buf);
                let frame = encode_data(&self.id, self.seq, &buf);
                self.seq += 1;
                Ok(Some(frame))
            }
            Phase::End => {
                self.phase = Phase::Done;
                let sha: [u8; 32] = self.hasher.finalize_reset().into();
                Ok(Some(encode_end(&self.id, self.seq, &sha)))
            }
            Phase::Done => Ok(None),
        }
    }
}

/// Status surfaced to the UI as file frames are reassembled.
#[derive(Debug, PartialEq, Eq)]
pub enum FileStatus {
    Started {
        name: String,
        size: u64,
        /// Set when accepting this `START` discarded an in-progress transfer of
        /// the *same* authenticated sender to stay within
        /// [`MAX_TRANSFERS_PER_SENDER`] — the name of the receipt that was
        /// cancelled, so the operator is told rather than left waiting for a
        /// file that will never arrive. Sender-controlled text.
        cancelled: Option<String>,
    },
    Progress { name: String, received: u64, total: u64 },
    Completed { name: String, path: PathBuf },
    Error(String),
}

struct Partial {
    name: String,
    total_size: u64,
    received: u64,
    next_seq: u32,
    tmp_path: PathBuf,
    file: std::fs::File,
    hasher: Sha3_256,
    /// Insertion order, used to evict the oldest transfer at the cap.
    started: u64,
}

/// Reassembles file transfers from inbound app-message frames, writing chunks
/// to a staging file under `dir` and only publishing the final file once the
/// `END` frame's chunk count and SHA3-256 both verify.
pub struct Reassembler {
    dir: PathBuf,
    partial: HashMap<TransferKey, Partial>,
    /// Monotonic counter stamped onto each new transfer so the *oldest* can be
    /// evicted when the concurrency cap is hit.
    next_started: u64,
}

impl Reassembler {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir, partial: HashMap::new(), next_started: 0 }
    }

    /// Reduce a sender-controlled name to a safe basename inside `dir`: only the
    /// final path component is kept, so `../`, absolute paths and embedded
    /// separators cannot escape the receive directory.
    fn safe_name(name: &str) -> Option<String> {
        let base = Path::new(name).file_name()?.to_str()?;
        if base.is_empty() || base == "." || base == ".." {
            return None;
        }
        // `Path::file_name` only strips the platform's separator, so on unix a
        // name full of Windows separators (`..\\..\\x`) survives as one
        // component. Reject any residual path separator or NUL so a received
        // file can never escape the receive directory on any platform.
        if base.contains('/') || base.contains('\\') || base.contains('\0') {
            return None;
        }
        // The sender chooses this name and it becomes both a real filename and
        // display text. Control characters (ESC/CSI, CR) and the bidi/zero-width
        // marks let a sender repaint the receiving operator's transcript or
        // disguise an extension, so refuse them outright rather than only
        // escaping them at one print site.
        if base.chars().any(|c| {
            c.is_control()
                || ('\u{200B}'..='\u{200F}').contains(&c)
                || ('\u{202A}'..='\u{202E}').contains(&c)
                || ('\u{2066}'..='\u{2069}').contains(&c)
        }) {
            return None;
        }
        Some(base.to_string())
    }

    /// Feed one inbound app-message body, attributed to the authenticated
    /// `(group, sender)` that MLS reports for the message. Returns `None` if the
    /// body is not a file frame (the caller should display it as chat);
    /// otherwise a [`FileStatus`] describing the transfer's progress.
    pub fn ingest(&mut self, group: &[u8; 32], sender: u32, body: &[u8]) -> Option<FileStatus> {
        if !is_file_frame(body) {
            return None;
        }
        let rest = &body[FILE_MAGIC.len()..];
        if rest.len() < 1 + ID_LEN {
            return Some(FileStatus::Error("file frame too short".into()));
        }
        let ftype = rest[0];
        let mut id = [0u8; ID_LEN];
        id.copy_from_slice(&rest[1..1 + ID_LEN]);
        let key: TransferKey = (*group, sender, id);
        let payload = &rest[1 + ID_LEN..];
        match ftype {
            T_START => Some(self.on_start(key, payload)),
            T_DATA => Some(self.on_data(key, payload)),
            T_END => Some(self.on_end(key, payload)),
            other => Some(FileStatus::Error(format!("unknown file frame type {other}"))),
        }
    }

    fn on_start(&mut self, key: TransferKey, payload: &[u8]) -> FileStatus {
        let id = key.2;
        if payload.len() < 10 {
            return FileStatus::Error("malformed START".into());
        }
        let total_size = u64::from_be_bytes(payload[0..8].try_into().unwrap());
        if total_size > MAX_FILE_SIZE {
            return FileStatus::Error("START declares oversize file".into());
        }
        let name_len = u16::from_be_bytes(payload[8..10].try_into().unwrap()) as usize;
        if payload.len() < 10 + name_len {
            return FileStatus::Error("START name truncated".into());
        }
        let raw_name = match std::str::from_utf8(&payload[10..10 + name_len]) {
            Ok(s) => s,
            Err(_) => return FileStatus::Error("START name not UTF-8".into()),
        };
        let name = match Self::safe_name(raw_name) {
            Some(n) => n,
            None => return FileStatus::Error("START name unsafe".into()),
        };
        // Bound concurrent transfers — *after* every check above, so a malformed
        // or oversize START can never cost anyone an in-progress transfer.
        //
        // A re-START of an existing key just replaces that key's own transfer
        // (below) and does not grow the map, so only a genuinely new key is
        // capped. The map is shared across all groups and senders, so the choice
        // of what gives way decides whose data one sender can destroy:
        //   * over this sender's *own* cap → discard this sender's own oldest
        //     transfer. Self-healing (abandoned transfers of this sender are
        //     reclaimed by its next START) and it cannot touch anybody else.
        //   * otherwise, at the aggregate cap → refuse this START. The only
        //     transfers left to discard belong to other principals, and taking
        //     one would let any single group member silently destroy the
        //     receipts of other members — including members of a different MLS
        //     group, a boundary MLS otherwise keeps separate.
        // The actual discard is deferred until the new staging file exists, so a
        // failed create cannot destroy a transfer either.
        let mut evict: Option<TransferKey> = None;
        if !self.partial.contains_key(&key) {
            let mine = self.partial.keys().filter(|(g, s, _)| *g == key.0 && *s == key.1).count();
            if mine >= MAX_TRANSFERS_PER_SENDER {
                evict = self
                    .partial
                    .iter()
                    .filter(|((g, s, _), _)| *g == key.0 && *s == key.1)
                    .min_by_key(|(_, p)| p.started)
                    .map(|(k, _)| *k);
            } else if self.partial.len() >= MAX_CONCURRENT_TRANSFERS {
                return FileStatus::Error(format!(
                    "too many transfers in progress ({MAX_CONCURRENT_TRANSFERS}); \
                     refusing START of {name:?}"
                ));
            }
        }
        // Stage to a sibling temp created exclusively (no clobber / symlink
        // follow), mirroring the at-rest temp-file pattern.
        let tmp_path = self.dir.join(format!(".{}.{}.part", name, hex16(&id)));
        let file = match exclusive_create(&tmp_path) {
            Ok(f) => f,
            Err(e) => return FileStatus::Error(format!("stage {tmp_path:?}: {e}")),
        };
        // The staging file exists now, so the deferred per-sender discard can be
        // carried out: it only ever names a transfer of this same authenticated
        // `(group, sender)` (chosen above), and the cancelled name is reported
        // back so the operator learns that receipt is not coming.
        let cancelled = evict.and_then(|old| {
            let name = self.partial.get(&old).map(|p| p.name.clone());
            self.abort(&old);
            name
        });
        // A re-START under the same key supersedes any transfer already open on
        // it, and `Partial` has no `Drop`, so the superseded staging file has to
        // be unlinked here or it is orphaned in the receive directory forever.
        // Order matters twice:
        //   * the new staging file is created *first* (above), so a create that
        //     fails cannot destroy an in-progress transfer; and
        //   * the old entry is taken out of the map *before* the unlink, so its
        //     `File` is dropped and the handle closed first — `create_owner_only`
        //     opens with a deny-all share mode on Windows, where deleting a path
        //     this process still holds open fails with a sharing violation.
        // Nothing between here and the `insert` below can return early, so no new
        // orphan can be created in the gap. The path comparison only matters when
        // something outside this process removed the old `.part` (a same-name
        // re-START with the file still there fails in `exclusive_create` and
        // returns above) — in that case the old path names the file we just
        // created, which must not be deleted.
        if let Some(old) = self.partial.remove(&key) {
            drop(old.file);
            if old.tmp_path != tmp_path {
                if let Err(e) = std::fs::remove_file(&old.tmp_path) {
                    // Non-fatal, but never silent: a failure here is exactly the
                    // leak this cleanup exists to prevent.
                    eprintln!(
                        "[mls] warning: could not remove superseded staging file {:?}: {e}",
                        old.tmp_path
                    );
                }
            }
        }
        let started = self.next_started;
        self.next_started += 1;
        self.partial.insert(
            key,
            Partial {
                name: name.clone(),
                total_size,
                received: 0,
                next_seq: 0,
                tmp_path,
                file,
                hasher: Sha3_256::new(),
                started,
            },
        );
        FileStatus::Started { name, size: total_size, cancelled }
    }

    fn on_data(&mut self, key: TransferKey, payload: &[u8]) -> FileStatus {
        if payload.len() < 4 {
            return FileStatus::Error("malformed DATA".into());
        }
        let seq = u32::from_be_bytes(payload[0..4].try_into().unwrap());
        let chunk = &payload[4..];
        let p = match self.partial.get_mut(&key) {
            Some(p) => p,
            None => return FileStatus::Error("DATA for unknown/forgotten transfer".into()),
        };
        if seq != p.next_seq {
            let e = format!("DATA out of order (got {seq}, expected {})", p.next_seq);
            self.abort(&key);
            return FileStatus::Error(e);
        }
        if p.received + chunk.len() as u64 > p.total_size {
            self.abort(&key);
            return FileStatus::Error("DATA exceeds declared size".into());
        }
        if let Err(e) = p.file.write_all(chunk) {
            let e = format!("write chunk: {e}");
            self.abort(&key);
            return FileStatus::Error(e);
        }
        p.hasher.update(chunk);
        p.received += chunk.len() as u64;
        p.next_seq += 1;
        FileStatus::Progress { name: p.name.clone(), received: p.received, total: p.total_size }
    }

    fn on_end(&mut self, key: TransferKey, payload: &[u8]) -> FileStatus {
        if payload.len() < 4 + 32 {
            return FileStatus::Error("malformed END".into());
        }
        let total_chunks = u32::from_be_bytes(payload[0..4].try_into().unwrap());
        let mut want_sha = [0u8; 32];
        want_sha.copy_from_slice(&payload[4..36]);
        let mut p = match self.partial.remove(&key) {
            Some(p) => p,
            None => return FileStatus::Error("END for unknown/forgotten transfer".into()),
        };
        // Close the staging handle before *any* of the path operations below:
        // every exit from here on either unlinks `tmp_path` or renames it onto
        // the destination, and `create_owner_only` opens with a deny-all share
        // mode on Windows, where renaming or deleting a path this process still
        // holds open fails with a sharing violation — the same reason the
        // superseded-transfer cleanup in `on_start` drops first. Flushing has to
        // precede the close, so it is hoisted above the count/size checks, but
        // its *result* is still reported at the original point: the error a
        // doomed transfer reports, and its precedence, are unchanged. (Writes in
        // `on_data` go straight to the `File`, so this flush is a no-op and puts
        // no new bytes on disk for a transfer that is about to be unlinked.)
        let flushed = p.file.flush();
        drop(p.file);
        if p.next_seq != total_chunks {
            let _ = std::fs::remove_file(&p.tmp_path);
            return FileStatus::Error(format!(
                "END chunk count mismatch (have {}, expected {total_chunks})",
                p.next_seq
            ));
        }
        if p.received != p.total_size {
            let _ = std::fs::remove_file(&p.tmp_path);
            return FileStatus::Error("END size mismatch".into());
        }
        if let Err(e) = flushed {
            let _ = std::fs::remove_file(&p.tmp_path);
            return FileStatus::Error(format!("flush: {e}"));
        }
        let got_sha: [u8; 32] = p.hasher.finalize_reset().into();
        if got_sha != want_sha {
            let _ = std::fs::remove_file(&p.tmp_path);
            return FileStatus::Error("SHA3-256 mismatch — file not committed".into());
        }
        // Publish: atomically reserve a free destination name (exclusive create,
        // no clobber/symlink-follow), then rename our staged temp over the
        // empty file we just reserved. Reserving with O_EXCL closes the
        // check-then-rename race where a concurrent process could create the
        // same name in between.
        let dest = match self.claim_dest(&p.name) {
            Some(d) => d,
            None => {
                let _ = std::fs::remove_file(&p.tmp_path);
                return FileStatus::Error("no free destination filename".into());
            }
        };
        if let Err(e) = std::fs::rename(&p.tmp_path, &dest) {
            let _ = std::fs::remove_file(&p.tmp_path);
            return FileStatus::Error(format!("rename to {dest:?}: {e}"));
        }
        FileStatus::Completed { name: p.name.clone(), path: dest }
    }

    fn abort(&mut self, key: &TransferKey) {
        if let Some(p) = self.partial.remove(key) {
            // Handle first, path second — see `on_end`.
            drop(p.file);
            let _ = std::fs::remove_file(&p.tmp_path);
        }
    }

    /// Atomically claim a free destination: try `dir/name`, then
    /// `dir/name (k)`, creating the first one that does not already exist via an
    /// exclusive create (so a received file never silently overwrites an
    /// existing one, even under a concurrent creator). Returns the claimed path,
    /// or `None` if every candidate is taken.
    fn claim_dest(&self, name: &str) -> Option<PathBuf> {
        if exclusive_create(&self.dir.join(name)).is_ok() {
            return Some(self.dir.join(name));
        }
        let (stem, ext) = match name.rsplit_once('.') {
            Some((s, e)) => (s.to_string(), format!(".{e}")),
            None => (name.to_string(), String::new()),
        };
        for k in 1..10_000 {
            let cand = self.dir.join(format!("{stem} ({k}){ext}"));
            if exclusive_create(&cand).is_ok() {
                return Some(cand);
            }
        }
        None
    }
}

fn hex16(id: &[u8; ID_LEN]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

/// Create `path` for writing, failing if it already exists and never following
/// a link raced into place — the same exclusive-create discipline the node-key
/// and at-rest temp files use (owner-only on unix and windows alike).
fn exclusive_create(path: &Path) -> std::io::Result<std::fs::File> {
    crate::secure_fs::create_owner_only(path, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn safe_name_rejects_control_and_bidi_characters() {
        // The sender picks this name and it becomes both a real filename and
        // the text of the completion line the receiving operator reads.
        assert!(Reassembler::safe_name("\u{1b}[2K\rinvoice.pdf").is_none());
        assert!(Reassembler::safe_name("report\u{202E}fdp.exe").is_none());
        assert!(Reassembler::safe_name("a\u{200B}b").is_none());
        assert!(Reassembler::safe_name("line\nbreak").is_none());
        // Still rejected for the reasons it always was.
        assert!(Reassembler::safe_name("").is_none());
        assert!(Reassembler::safe_name("..").is_none());
        assert!(Reassembler::safe_name("a\\b").is_none());
        // Ordinary names, including non-ASCII ones, keep working.
        assert_eq!(Reassembler::safe_name("hello.bin").as_deref(), Some("hello.bin"));
        assert_eq!(Reassembler::safe_name("報告書 v2.pdf").as_deref(), Some("報告書 v2.pdf"));
    }

    #[test]
    fn frame_and_reassemble_roundtrip() {
        let dir = tempdir().unwrap();
        // A file spanning several chunks plus a partial last chunk.
        let src = dir.path().join("hello.bin");
        let content: Vec<u8> = (0..(FILE_CHUNK_SIZE * 2 + 1234)).map(|i| (i % 251) as u8).collect();
        std::fs::write(&src, &content).unwrap();

        let (name, frames) = frame_file(&src).unwrap();
        assert_eq!(name, "hello.bin");
        // START + 3 DATA (2 full + 1 partial) + END
        assert_eq!(frames.len(), 1 + 3 + 1);

        let recv_dir = tempdir().unwrap();
        let mut r = Reassembler::new(recv_dir.path().to_path_buf());
        let g = [9u8; 32];
        let mut completed = None;
        for f in &frames {
            match r.ingest(&g, 1, f) {
                Some(FileStatus::Completed { path, .. }) => completed = Some(path),
                Some(FileStatus::Error(e)) => panic!("unexpected error: {e}"),
                Some(_) => {}
                None => panic!("frame not recognized as file frame"),
            }
        }
        let out = completed.expect("transfer completed");
        assert_eq!(std::fs::read(&out).unwrap(), content, "received file must match");
    }

    #[test]
    fn chat_message_is_not_a_file_frame() {
        let mut r = Reassembler::new(tempdir().unwrap().path().to_path_buf());
        assert!(r.ingest(&[0u8; 32], 0, b"just a normal chat line").is_none());
    }

    #[test]
    fn frames_from_a_different_sender_do_not_hijack_a_transfer() {
        // Alice (sender 1) opens a transfer; Carol (sender 2) replays the same
        // wire id with her own DATA. Because the reassembler keys on
        // (group, sender, id), Carol's frame lands under a *different* key and
        // cannot corrupt or finish Alice's transfer.
        let dir = tempdir().unwrap();
        let src = dir.path().join("a.bin");
        std::fs::write(&src, vec![1u8; FILE_CHUNK_SIZE + 10]).unwrap();
        let (_n, frames) = frame_file(&src).unwrap();
        let recv = tempdir().unwrap();
        let mut r = Reassembler::new(recv.path().to_path_buf());
        let g = [5u8; 32];
        // Alice's START establishes the transfer under (g, 1, id).
        assert!(matches!(r.ingest(&g, 1, &frames[0]), Some(FileStatus::Started { .. })));
        // Carol (sender 2) sends Alice's first DATA frame verbatim: it is a DATA
        // for a transfer Carol never started under (g, 2, id) → rejected, and
        // Alice's transfer is untouched.
        assert!(matches!(r.ingest(&g, 2, &frames[1]), Some(FileStatus::Error(_))));
        // Alice's own DATA still applies.
        assert!(matches!(r.ingest(&g, 1, &frames[1]), Some(FileStatus::Progress { .. })));
    }

    fn count_parts(dir: &Path) -> usize {
        std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".part"))
            .count()
    }

    /// Fill `r`'s shared table to the aggregate cap with in-progress transfers
    /// in `group`, spread over just enough senders that none of them exceeds its
    /// own per-sender cap. Returns `(sender, id)` of the *oldest* entry — the
    /// one a global "evict the oldest" policy would sacrifice.
    fn fill_to_cap(r: &mut Reassembler, group: &[u8; 32]) -> (u32, [u8; ID_LEN]) {
        let senders = (MAX_CONCURRENT_TRANSFERS / MAX_TRANSFERS_PER_SENDER) as u32;
        let mut oldest = None;
        for s in 0..senders {
            for k in 0..MAX_TRANSFERS_PER_SENDER as u32 {
                let mut id = [0u8; ID_LEN];
                id[0] = s as u8;
                id[1] = k as u8;
                let name = format!("victim{s}_{k}.bin");
                assert!(matches!(
                    r.ingest(group, s, &encode_start(&id, 4096, &name)),
                    Some(FileStatus::Started { .. })
                ));
                assert!(matches!(
                    r.ingest(group, s, &encode_data(&id, 0, &[1u8; 64])),
                    Some(FileStatus::Progress { .. })
                ));
                oldest.get_or_insert((s, id));
            }
        }
        assert_eq!(r.partial.len(), MAX_CONCURRENT_TRANSFERS);
        oldest.unwrap()
    }

    #[test]
    fn a_sender_in_one_group_cannot_evict_another_groups_transfer() {
        // The reassembly table is shared across every group this node is in. A
        // member of group A must not be able to make room for itself by
        // discarding a receipt belonging to group B — MLS keeps those groups
        // apart, and this table must not join them back together.
        let recv = tempdir().unwrap();
        let mut r = Reassembler::new(recv.path().to_path_buf());
        let victim_group = [0xbbu8; 32];
        let (v_sender, v_id) = fill_to_cap(&mut r, &victim_group);
        assert_eq!(count_parts(recv.path()), MAX_CONCURRENT_TRANSFERS);

        let attacker_group = [0xaau8; 32];
        let atk_id = [0xffu8; ID_LEN];
        match r.ingest(&attacker_group, 9, &encode_start(&atk_id, 4096, "evil.bin")) {
            Some(FileStatus::Error(e)) => {
                assert!(e.contains("too many transfers in progress"), "unexpected error: {e}")
            }
            other => panic!("a START at the aggregate cap must be refused, got {other:?}"),
        }

        // Nothing of the victim group's was destroyed: same number of staging
        // files, and the oldest transfer still accepts its next chunk.
        assert_eq!(count_parts(recv.path()), MAX_CONCURRENT_TRANSFERS);
        assert_eq!(r.partial.len(), MAX_CONCURRENT_TRANSFERS);
        assert!(matches!(
            r.ingest(&victim_group, v_sender, &encode_data(&v_id, 1, &[2u8; 64])),
            Some(FileStatus::Progress { .. })
        ));
        // Repeating the attack cannot wear the table down either.
        for i in 0..8u8 {
            let id = [i; ID_LEN];
            assert!(matches!(
                r.ingest(&attacker_group, 9, &encode_start(&id, 4096, "evil.bin")),
                Some(FileStatus::Error(_))
            ));
        }
        assert_eq!(r.partial.len(), MAX_CONCURRENT_TRANSFERS);
    }

    #[test]
    fn per_sender_cap_discards_only_that_senders_own_oldest_and_reports_it() {
        // Over its own cap a sender gives up *its own* oldest transfer, so the
        // cap is self-healing (a sender whose transfers died mid-stream is never
        // locked out) without reaching another sender's state. The operator was
        // told that file was arriving, so the cancellation is surfaced.
        let recv = tempdir().unwrap();
        let mut r = Reassembler::new(recv.path().to_path_buf());
        let g = [7u8; 32];

        // A bystander in the same group, opened first so it is the globally
        // oldest entry — the one the old policy would have taken.
        let other_id = [0xeeu8; ID_LEN];
        assert!(matches!(
            r.ingest(&g, 2, &encode_start(&other_id, 4096, "bystander.bin")),
            Some(FileStatus::Started { .. })
        ));

        for k in 0..MAX_TRANSFERS_PER_SENDER as u8 {
            let id = [k; ID_LEN];
            assert!(matches!(
                r.ingest(&g, 1, &encode_start(&id, 4096, &format!("mine{k}.bin"))),
                Some(FileStatus::Started { cancelled: None, .. })
            ));
        }

        let new_id = [0x99u8; ID_LEN];
        match r.ingest(&g, 1, &encode_start(&new_id, 4096, "newest.bin")) {
            Some(FileStatus::Started { name, cancelled, .. }) => {
                assert_eq!(name, "newest.bin");
                assert_eq!(
                    cancelled.as_deref(),
                    Some("mine0.bin"),
                    "the sender's own oldest must be the one cancelled, and reported"
                );
            }
            other => panic!("a sender's own cap must discard its own oldest, got {other:?}"),
        }

        // Its own oldest is gone, staging file and all …
        assert!(!recv.path().join(format!(".mine0.bin.{}.part", hex16(&[0u8; ID_LEN]))).exists());
        assert!(matches!(
            r.ingest(&g, 1, &encode_data(&[0u8; ID_LEN], 0, &[3u8; 16])),
            Some(FileStatus::Error(_))
        ));
        // … while the bystander's older transfer is untouched.
        assert!(matches!(
            r.ingest(&g, 2, &encode_data(&other_id, 0, &[4u8; 16])),
            Some(FileStatus::Progress { .. })
        ));
    }

    #[test]
    fn a_malformed_start_at_the_cap_destroys_no_transfer() {
        // Capacity accounting happens only after a START has fully validated, so
        // a frame that is rejected outright cannot cost anybody a transfer.
        let recv = tempdir().unwrap();
        let mut r = Reassembler::new(recv.path().to_path_buf());
        let victim_group = [0xbbu8; 32];
        let (v_sender, v_id) = fill_to_cap(&mut r, &victim_group);

        let attacker_group = [0xaau8; 32];
        let id = [0xfeu8; ID_LEN];
        // Oversize declaration.
        assert!(matches!(
            r.ingest(&attacker_group, 9, &encode_start(&id, MAX_FILE_SIZE + 1, "big.bin")),
            Some(FileStatus::Error(_))
        ));
        // Unsafe name.
        assert!(matches!(
            r.ingest(&attacker_group, 9, &encode_start(&id, 4096, "..")),
            Some(FileStatus::Error(_))
        ));
        // name_len running past the frame.
        let mut truncated = encode_start(&id, 4096, "x.bin");
        let off = FILE_MAGIC.len() + 1 + ID_LEN + 8;
        truncated[off..off + 2].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(matches!(
            r.ingest(&attacker_group, 9, &truncated),
            Some(FileStatus::Error(_))
        ));

        assert_eq!(r.partial.len(), MAX_CONCURRENT_TRANSFERS);
        assert_eq!(count_parts(recv.path()), MAX_CONCURRENT_TRANSFERS);
        assert!(matches!(
            r.ingest(&victim_group, v_sender, &encode_data(&v_id, 1, &[2u8; 64])),
            Some(FileStatus::Progress { .. })
        ));
    }

    #[test]
    fn tampered_chunk_fails_sha_and_is_not_committed() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("f.bin");
        std::fs::write(&src, vec![7u8; 100]).unwrap();
        let (_n, mut frames) = frame_file(&src).unwrap();
        // Flip a byte in the single DATA frame's payload (last byte of chunk).
        let data = &mut frames[1];
        let last = data.len() - 1;
        data[last] ^= 0xff;

        let recv = tempdir().unwrap();
        let mut r = Reassembler::new(recv.path().to_path_buf());
        let g = [3u8; 32];
        let mut saw_err = false;
        for f in &frames {
            if let Some(FileStatus::Error(_)) = r.ingest(&g, 0, f) {
                saw_err = true;
            }
        }
        assert!(saw_err, "tampered transfer must surface an error");
        // No committed file should be left in the receive dir.
        let leftover: Vec<_> = std::fs::read_dir(recv.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| !e.file_name().to_string_lossy().starts_with('.'))
            .collect();
        assert!(leftover.is_empty(), "no file committed on integrity failure");
    }

    #[test]
    fn restart_of_a_transfer_does_not_orphan_its_staging_file() {
        // A sender opens a transfer, streams data into `.a.bin.<id>.part`, then
        // re-STARTs the *same* id under a different name. The old staging file
        // is superseded and no code path will ever look at it again, so it must
        // be unlinked here; otherwise repeating this leaks staging files (up to
        // MAX_FILE_SIZE each) into the receive dir without bound.
        let recv = tempdir().unwrap();
        let mut r = Reassembler::new(recv.path().to_path_buf());
        let g = [4u8; 32];
        let id = [0xabu8; ID_LEN];
        let count_parts = || {
            std::fs::read_dir(recv.path())
                .unwrap()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_string_lossy().ends_with(".part"))
                .count()
        };

        assert!(matches!(
            r.ingest(&g, 1, &encode_start(&id, 4096, "a.bin")),
            Some(FileStatus::Started { .. })
        ));
        assert!(matches!(
            r.ingest(&g, 1, &encode_data(&id, 0, &[7u8; 512])),
            Some(FileStatus::Progress { .. })
        ));
        assert_eq!(count_parts(), 1, "one staging file after the first START");

        // Re-START the same (group, sender, id) under a new name.
        assert!(matches!(
            r.ingest(&g, 1, &encode_start(&id, 4096, "b.bin")),
            Some(FileStatus::Started { .. })
        ));
        assert_eq!(count_parts(), 1, "re-START must not leave the old .part behind");
        assert!(recv.path().join(format!(".b.bin.{}.part", hex16(&id))).exists());
        assert!(!recv.path().join(format!(".a.bin.{}.part", hex16(&id))).exists());
    }

    #[test]
    fn no_exit_from_end_leaves_a_staging_file_behind() {
        // Every exit from `on_end` disposes of the staging file — the failure
        // paths unlink it, the success path renames it onto the claimed
        // destination — and each of them must run *after* the staging handle is
        // closed: `create_owner_only` opens with a deny-all share mode on
        // Windows, so an exit still holding it would leave the `.part` orphaned
        // (and would fail the rename, never completing the transfer at all).
        //
        // Honest caveat: on unix this holds with or without that close, because
        // unlinking and renaming an open file both succeed — so this test
        // regresses the handle lifetime only on Windows. It is left portable
        // rather than `#[cfg(windows)]` so the disposal itself stays guarded
        // everywhere.
        let recv = tempdir().unwrap();
        let parts = || -> Vec<String> {
            std::fs::read_dir(recv.path())
                .unwrap()
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.ends_with(".part"))
                .collect()
        };
        let mut r = Reassembler::new(recv.path().to_path_buf());
        let g = [0x5au8; 32];
        let body = vec![3u8; 300];
        let sha: [u8; 32] = Sha3_256::digest(&body).into();

        // END chunk-count mismatch.
        let id = [0x01u8; ID_LEN];
        r.ingest(&g, 1, &encode_start(&id, 300, "count.bin"));
        r.ingest(&g, 1, &encode_data(&id, 0, &body));
        assert!(matches!(r.ingest(&g, 1, &encode_end(&id, 2, &sha)), Some(FileStatus::Error(_))));
        assert_eq!(parts(), Vec::<String>::new(), "count mismatch left a staging file");

        // END size mismatch (fewer bytes than START declared).
        let id = [0x02u8; ID_LEN];
        r.ingest(&g, 1, &encode_start(&id, 300, "size.bin"));
        r.ingest(&g, 1, &encode_data(&id, 0, &body[..100]));
        assert!(matches!(r.ingest(&g, 1, &encode_end(&id, 1, &sha)), Some(FileStatus::Error(_))));
        assert_eq!(parts(), Vec::<String>::new(), "size mismatch left a staging file");

        // SHA3-256 mismatch.
        let id = [0x03u8; ID_LEN];
        r.ingest(&g, 1, &encode_start(&id, 300, "sha.bin"));
        r.ingest(&g, 1, &encode_data(&id, 0, &body));
        assert!(matches!(
            r.ingest(&g, 1, &encode_end(&id, 1, &[0xffu8; 32])),
            Some(FileStatus::Error(_))
        ));
        assert_eq!(parts(), Vec::<String>::new(), "sha mismatch left a staging file");

        // Abort (out-of-order DATA) unlinks its staging file too.
        let id = [0x04u8; ID_LEN];
        r.ingest(&g, 1, &encode_start(&id, 300, "abort.bin"));
        assert!(matches!(r.ingest(&g, 1, &encode_data(&id, 7, &body)), Some(FileStatus::Error(_))));
        assert_eq!(parts(), Vec::<String>::new(), "abort left a staging file");

        // The honest path still commits the exact bytes, and consumes the
        // staging file in doing so.
        let id = [0x05u8; ID_LEN];
        r.ingest(&g, 1, &encode_start(&id, 300, "ok.bin"));
        r.ingest(&g, 1, &encode_data(&id, 0, &body));
        let out = match r.ingest(&g, 1, &encode_end(&id, 1, &sha)) {
            Some(FileStatus::Completed { path, .. }) => path,
            other => panic!("honest transfer must complete, got {other:?}"),
        };
        assert_eq!(out, recv.path().join("ok.bin"));
        assert_eq!(std::fs::read(&out).unwrap(), body);
        assert_eq!(parts(), Vec::<String>::new(), "success path left a staging file");
    }

    #[test]
    fn path_traversal_name_rejected() {
        assert_eq!(Reassembler::safe_name("../../etc/passwd"), Some("passwd".to_string()));
        assert_eq!(Reassembler::safe_name("/abs/path"), Some("path".to_string()));
        assert_eq!(Reassembler::safe_name(".."), None);
        assert_eq!(Reassembler::safe_name(""), None);
        // Windows-style separators survive unix file_name(); must be rejected.
        assert_eq!(Reassembler::safe_name("..\\..\\foo"), None);
        assert_eq!(Reassembler::safe_name("a\\b"), None);
        assert_eq!(Reassembler::safe_name("with\0nul"), None);
    }
}
