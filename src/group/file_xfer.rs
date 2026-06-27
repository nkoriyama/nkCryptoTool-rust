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

/// Upper bound on simultaneously in-progress inbound transfers, so a peer that
/// opens many `START`s without ever finishing them cannot exhaust memory / temp
/// files. New `START`s beyond this are rejected until existing ones complete.
const MAX_CONCURRENT_TRANSFERS: usize = 16;

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
    Started { name: String, size: u64 },
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
        // Bound concurrent transfers. A re-START of an existing key just
        // replaces it; a genuinely new transfer at the cap evicts the *oldest*
        // in-progress one (rather than refusing forever), so a peer that opens
        // STARTs and abandons them cannot permanently block new file receipts.
        if !self.partial.contains_key(&key) && self.partial.len() >= MAX_CONCURRENT_TRANSFERS {
            if let Some(oldest) = self
                .partial
                .iter()
                .min_by_key(|(_, p)| p.started)
                .map(|(k, _)| *k)
            {
                self.abort(&oldest);
            }
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
        // Stage to a sibling temp created exclusively (no clobber / symlink
        // follow), mirroring the at-rest temp-file pattern.
        let tmp_path = self.dir.join(format!(".{}.{}.part", name, hex16(&id)));
        let file = match exclusive_create(&tmp_path) {
            Ok(f) => f,
            Err(e) => return FileStatus::Error(format!("stage {tmp_path:?}: {e}")),
        };
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
        FileStatus::Started { name, size: total_size }
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
        if let Err(e) = p.file.flush() {
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

/// Create `path` for writing, failing if it already exists and (on unix) never
/// following a symlink raced into place — the same exclusive-create discipline
/// the node-key and at-rest temp files use.
fn exclusive_create(path: &Path) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

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
