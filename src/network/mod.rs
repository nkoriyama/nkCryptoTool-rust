pub mod tcp;
#[cfg(feature = "mls")]
pub mod inbox;

use crate::backend;
use crate::backend::{Aead, AeadBackend};
use crate::config::{CryptoConfig, TransportKind};
use crate::error::{CryptoError, Result};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::{Zeroize, Zeroizing};

pub const BUF_SIZE: usize = 1024 * 1024;
pub const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024 * 1024; // 10GB
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
/// Short timeout for *control-plane handshakes* (a small, fixed-size header /
/// request a well-behaved peer sends immediately on connecting, and the short
/// response). Distinct from [`IDLE_TIMEOUT`], which is sized for bulk transfer
/// and is far too long for a control read: a peer that connects then stalls
/// before sending its header must be dropped quickly so it cannot occupy a
/// serialized accept loop (head-of-line DoS).
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub const CUMULATIVE_TIMEOUT: Duration = Duration::from_secs(7200);
pub const CHAT_SESSION_TIMEOUT: Duration = Duration::from_secs(7200); // 2 hours

pub const ALPN_CHAT: &[u8] = b"nkct/chat/1";
pub const ALPN_FILE: &[u8] = b"nkct/file/1";
/// P2P shell (bastion-less PQC SSH; see `P2P_SHELL_DESIGN.md`). Phase 0 carries
/// an echo session; later phases carry a PTY bridge.
pub const ALPN_SHELL: &[u8] = b"nkct/shell/1";
/// MLS group chat ALPN (P4). Each accepted stream under this protocol
/// carries exactly one length-prefixed `mls_rs::MlsMessage` per the
/// [`crate::group::transport`] framing helpers — Welcome / Commit /
/// Application / Proposal as discriminated by `MlsMessage::wire_format`.
pub const ALPN_MLS: &[u8] = b"nkct/mls/1";

/// Inbox store-and-forward ALPN. Carries opaque payloads addressed to
/// a recipient PeerId; the server stores them in sqlite and returns
/// them on demand to the matching peer. See [`crate::network::inbox`]
/// for the wire protocol and client/server implementations.
pub const ALPN_INBOX: &[u8] = b"nkct/inbox/1";

/// F3: 64 KiB chunk threshold for progress callback emission. Progress is
/// emitted at most once per `PROGRESS_CHUNK_BYTES` bytes plus a final emission
/// at end-of-transfer.
pub const PROGRESS_CHUNK_BYTES: u64 = 64 * 1024;

/// F3: Progress callback type. `(sent_bytes, total_bytes_if_known)`. The
/// `total` argument is None when the function itself does not know the
/// expected total (e.g. receive side reads from the wire). Callers may wrap
/// this in a closure that substitutes a captured total when needed.
pub type ProgressCallback = Arc<dyn Fn(u64, Option<u64>) + Send + Sync>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PeerId {
    Ip(std::net::IpAddr),
    Node([u8; 32]), // Iroh NodeId
    Pubkey([u8; 32]),
}

#[derive(Debug, PartialEq, Eq)]
pub enum LineRead {
    Line,       // Got a full line ending with \n (or \r\n)
    PartialEof, // Got EOF but with some data before it
    Eof,        // Got EOF with 0 bytes
}

pub static CHAT_ACTIVE: Lazy<std::sync::atomic::AtomicBool> =
    Lazy::new(|| std::sync::atomic::AtomicBool::new(false));

pub static PEER_COOLDOWNS: Lazy<Mutex<std::collections::HashMap<PeerId, std::time::Instant>>> =
    Lazy::new(|| Mutex::new(std::collections::HashMap::new()));

pub struct ChatActiveGuard {
    pub peer_id: PeerId,
    pub _start_time: std::time::Instant,
}

impl Drop for ChatActiveGuard {
    fn drop(&mut self) {
        let mut cooldowns = PEER_COOLDOWNS.lock();
        cooldowns.insert(self.peer_id.clone(), std::time::Instant::now());
        CHAT_ACTIVE.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

pub struct AbortGuard(pub tokio::task::AbortHandle);
impl Drop for AbortGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Provider for standard I/O streams.
/// Note: DefaultIOProvider returns handles to global stdin/stdout.
/// Mutual exclusion for these shared resources MUST be managed by the caller
/// (e.g., using CHAT_ACTIVE or Arc<Mutex<...>>).
pub trait IOProvider: Send + Sync + 'static {
    fn stdin(&self) -> Box<dyn tokio::io::AsyncRead + Unpin + Send>;
    fn stdout(&self) -> Box<dyn tokio::io::AsyncWrite + Unpin + Send>;

    /// Called once by the file-receive flow after the transfer attempt.
    /// `committed` is true only when decryption AND the trailing AEAD tag
    /// verified (i.e. `receive_file` returned `Ok`). Implementations that stage
    /// received plaintext to a temporary file MUST move it to its final
    /// destination only when `committed`, and discard it otherwise, so that
    /// unauthenticated plaintext is never persisted at the destination path.
    /// The default is a no-op, which is correct for stdout-backed providers
    /// (the bytes have already been streamed to the consumer).
    fn finalize_recv(&self, committed: bool) -> std::io::Result<()> {
        let _ = committed;
        Ok(())
    }
}

pub struct DefaultIOProvider;
impl IOProvider for DefaultIOProvider {
    fn stdin(&self) -> Box<dyn tokio::io::AsyncRead + Unpin + Send> {
        Box::new(open_stdin())
    }
    fn stdout(&self) -> Box<dyn tokio::io::AsyncWrite + Unpin + Send> {
        Box::new(tokio::io::stdout())
    }
}

// ---------------------------------------------------------------------------
// Detached-thread stdin reader.
//
// `tokio::io::stdin()` parks a blocking task on a `read(2)` syscall that the
// runtime *joins* during shutdown. The syscall cannot be cancelled, so after
// the chat loop returns on a peer disconnect the process would hang until the
// user pressed a key — the runtime's drop waits for that parked read. We move
// the blocking read onto a plain `std::thread` instead: when `main` unwinds,
// every `Drop` (hence every `Zeroizing`/`ZeroizeOnDrop` secret) still runs and
// the process exits immediately, because a plain thread does not keep the
// process alive once `main` returns.
//
// CRITICAL invariant: there is exactly ONE reader thread for the whole process,
// spawned lazily on first use. A naive "one thread per `stdin()` call" leaks a
// thread per connection — the previous reader stays parked in `read(2)` holding
// the `std::io::stdin()` lock, so the next connection's thread blocks forever on
// `lock()`. The persistent `--listen` server calls `stdin()` once per accepted
// connection (`processor::run_listen_loop`), so repeated connect/disconnect
// would otherwise exhaust threads (DoS). The single reader forwards bytes to the
// *currently registered* consumer (a chat session); when no consumer is
// registered the bytes are discarded. A generation counter makes a consumer's
// `Drop` deregister only its own sink, never a newer one's.
// ---------------------------------------------------------------------------

/// `(generation, sender)` of the currently registered stdin consumer.
///
/// The channel is *bounded*: when it fills, the reader thread's `blocking_send`
/// applies backpressure instead of queueing without limit (which a malicious or
/// careless huge stdin redirect could otherwise grow into an OOM). Blocking the
/// reader is benign here because chat is serialised to one session at a time by
/// [`CHAT_ACTIVE`] — there is never a second consumer being starved — and the
/// block self-heals: when the lone consumer's connection ends it drops its
/// receiver, so `blocking_send` returns `Err` and the reader resumes. Payloads
/// are `Zeroizing` so transient chat plaintext is wiped when each chunk drops.
type StdinSink = Option<(u64, tokio::sync::mpsc::Sender<Zeroizing<Vec<u8>>>)>;

/// Bounded depth of the stdin delivery channel (see [`StdinSink`]).
const STDIN_CHAN_CAP: usize = 64;

/// The currently registered stdin consumer (see [`StdinSink`]).
static STDIN_SINK: std::sync::Mutex<StdinSink> = std::sync::Mutex::new(None);
/// Spawns the single reader thread exactly once.
static STDIN_THREAD: std::sync::Once = std::sync::Once::new();
/// Monotonic generation handed to each consumer so `Drop` is self-targeted.
static STDIN_GEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// Set once the reader thread observes stdin EOF; later consumers get EOF too.
/// Written and read only while holding the [`STDIN_SINK`] lock, so EOF latching
/// and consumer registration cannot race (a sender registered into a sink the
/// reader is tearing down would never be dropped, hanging that consumer).
static STDIN_EOF: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// stdin reader surfaced as an `AsyncRead`, fed by the single global reader
/// thread over an mpsc channel. The consumer (`read_line_secure`) reads one
/// byte at a time, so a delivered chunk is held in `buffered` with a read
/// cursor until drained. `buffered` is a single `Zeroizing<Vec<u8>>` that is
/// never grown — when it is fully consumed (or dropped) its whole allocation is
/// wiped, leaving no drained-region or reallocation residue. The authoritative
/// wipe of the assembled line and keys also stays in `chat_loop`.
struct ThreadStdin {
    generation: u64,
    rx: tokio::sync::mpsc::Receiver<Zeroizing<Vec<u8>>>,
    /// Leftover from the last delivered chunk and the read offset into it.
    buffered: Option<(Zeroizing<Vec<u8>>, usize)>,
}

impl Drop for ThreadStdin {
    fn drop(&mut self) {
        // Deregister, but only if we are still the active sink — a later
        // consumer may have replaced us (it bumped the generation).
        let mut sink = STDIN_SINK.lock().unwrap(); // ALLOW-UNWRAP: a poisoned STDIN_SINK mutex is unrecoverable
        if matches!(sink.as_ref(), Some((cur, _)) if *cur == self.generation) {
            *sink = None;
        }
        // `buffered` is `Zeroizing`, so any unconsumed bytes wipe on drop.
    }
}

impl tokio::io::AsyncRead for ThreadStdin {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // Serve leftover bytes from the last chunk first.
        if let Some((data, pos)) = this.buffered.as_mut() {
            let n = std::cmp::min(buf.remaining(), data.len() - *pos);
            buf.put_slice(&data[*pos..*pos + n]);
            *pos += n;
            if *pos >= data.len() {
                this.buffered = None; // drops Zeroizing → wipes the allocation
            }
            return std::task::Poll::Ready(Ok(()));
        }

        match this.rx.poll_recv(cx) {
            std::task::Poll::Ready(Some(data)) => {
                let n = std::cmp::min(buf.remaining(), data.len());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    // Keep the remainder; `data` stays `Zeroizing`.
                    this.buffered = Some((data, n));
                }
                // else `data` is fully consumed and dropped here → wiped.
                std::task::Poll::Ready(Ok(()))
            }
            // Sender dropped = our turn ended / stdin hit EOF. Clean EOF.
            std::task::Poll::Ready(None) => std::task::Poll::Ready(Ok(())),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

/// Register a fresh consumer of the global stdin reader and return its
/// `AsyncRead`. Spawns the single reader thread on first call.
fn open_stdin() -> ThreadStdin {
    ensure_stdin_thread();
    let (tx, rx) = tokio::sync::mpsc::channel::<Zeroizing<Vec<u8>>>(STDIN_CHAN_CAP);

    // Check EOF and register under the same lock the reader uses to latch EOF +
    // clear the sink. This closes the race where the reader hits EOF between an
    // unlocked check and the registration: there we would store a sender the
    // (now-exited) reader never drops, so `rx` would never yield `None` and the
    // consumer would hang on `Pending` forever.
    let mut sink = STDIN_SINK.lock().unwrap(); // ALLOW-UNWRAP: a poisoned STDIN_SINK mutex is unrecoverable
    if STDIN_EOF.load(std::sync::atomic::Ordering::Acquire) {
        // stdin already closed: drop `tx` now (don't register) so `rx` yields
        // `None` immediately. Sentinel generation 0 never matches a real
        // consumer (those are >= 1), so `Drop` won't clobber a live sink.
        drop(tx);
        drop(sink);
        return ThreadStdin { generation: 0, rx, buffered: None };
    }
    let generation = STDIN_GEN.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
    *sink = Some((generation, tx));
    drop(sink);
    ThreadStdin { generation, rx, buffered: None }
}

/// Spawn the process-wide stdin reader thread exactly once. It reads global
/// stdin forever, forwarding each chunk to the currently registered consumer
/// (or discarding it if none). On EOF/read-error it drops the active sink (so
/// that consumer sees EOF) and latches `STDIN_EOF`, then exits.
fn ensure_stdin_thread() {
    STDIN_THREAD.call_once(|| {
        std::thread::Builder::new()
            .name("nkct-stdin".to_string())
            .spawn(|| {
                use std::io::Read;
                let stdin = std::io::stdin();
                let mut lock = stdin.lock();
                let mut buf = [0u8; 4096];
                loop {
                    match lock.read(&mut buf) {
                        Ok(0) => break, // EOF
                        Ok(n) => {
                            // Clone the sender out under the lock, then release
                            // it before the (bounded) send so we never hold the
                            // mutex across backpressure. `blocking_send` blocks
                            // only while the lone registered consumer is alive
                            // but not draining, and returns `Err` the moment it
                            // drops its receiver — see `StdinSink`.
                            let sink = STDIN_SINK.lock().unwrap().clone(); // ALLOW-UNWRAP: a poisoned STDIN_SINK mutex is unrecoverable
                            if let Some((_, tx)) = sink {
                                // `Zeroizing::new` moves (does not copy) the
                                // `to_vec` allocation, so that single allocation
                                // is exactly what gets wiped on drop — no second
                                // un-zeroized heap copy is created.
                                let _ = tx.blocking_send(Zeroizing::new(buf[..n].to_vec()));
                            }
                            // Wipe the plaintext keystrokes from the stack buffer.
                            buf[..n].zeroize();
                        }
                        Err(_) => break,
                    }
                }
                // Latch EOF and clear the active sink under the same lock
                // `open_stdin` checks, so a concurrent registration cannot leak
                // a sender into a dead reader. Dropping the active sender makes
                // the current consumer observe EOF.
                let mut sink = STDIN_SINK.lock().unwrap(); // ALLOW-UNWRAP: a poisoned STDIN_SINK mutex is unrecoverable
                STDIN_EOF.store(true, std::sync::atomic::Ordering::Release);
                *sink = None;
                drop(sink);
            })
            .expect("spawn nkct-stdin reader thread"); // ALLOW-UNWRAP: stdin reader thread spawn failure is fatal at startup
    });
}

#[cfg(feature = "gui")]
pub struct GuiIOProvider {
    pub stdin_rx: Arc<tokio::sync::Mutex<tokio::sync::mpsc::Receiver<Vec<u8>>>>,
    pub stdout_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
}

#[cfg(feature = "gui")]
impl IOProvider for GuiIOProvider {
    fn stdin(&self) -> Box<dyn tokio::io::AsyncRead + Unpin + Send> {
        Box::new(GuiStdin {
            rx: self.stdin_rx.clone(),
            pending: std::collections::VecDeque::new(),
        })
    }
    fn stdout(&self) -> Box<dyn tokio::io::AsyncWrite + Unpin + Send> {
        Box::new(GuiStdout(self.stdout_tx.clone()))
    }
}

#[cfg(feature = "gui")]
struct GuiStdin {
    rx: Arc<tokio::sync::Mutex<tokio::sync::mpsc::Receiver<Vec<u8>>>>,
    pending: std::collections::VecDeque<u8>,
}
#[cfg(feature = "gui")]
impl tokio::io::AsyncRead for GuiStdin {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // First, drain pending buffer up to buf.remaining()
        if !this.pending.is_empty() {
            let n = std::cmp::min(buf.remaining(), this.pending.len());
            let drained: Vec<u8> = this.pending.drain(..n).collect();
            buf.put_slice(&drained);
            return std::task::Poll::Ready(Ok(()));
        }

        // Otherwise, try to receive new data
        let mut rx = match this.rx.try_lock() {
            Ok(rx) => rx,
            Err(_) => return std::task::Poll::Pending,
        };
        match rx.poll_recv(cx) {
            std::task::Poll::Ready(Some(data)) => {
                let n = std::cmp::min(buf.remaining(), data.len());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    // Stash leftover for next poll_read
                    this.pending.extend(data[n..].iter().copied());
                }
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(None) => std::task::Poll::Ready(Ok(())),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

#[cfg(feature = "gui")]
struct GuiStdout(tokio::sync::mpsc::Sender<Vec<u8>>);
#[cfg(feature = "gui")]
impl tokio::io::AsyncWrite for GuiStdout {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let data = buf.to_vec();
        match self.0.try_send(data) {
            Ok(_) => std::task::Poll::Ready(Ok(buf.len())),
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => std::task::Poll::Pending,
            Err(_) => std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "GUI stdout closed",
            ))),
        }
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

/// File-backed IOProvider for GUI file transfer (Phase 4 F2).
///
/// `stdin()` returns a reader for the send file (one-shot; subsequent calls
/// return an empty reader). `stdout()` returns a writer for the receive file
/// (one-shot; subsequent calls return a sink). File handles are pre-opened in
/// the async constructor so any path/permission errors surface before listen
/// or connect starts.
pub struct FileIOProvider {
    send_file: parking_lot::Mutex<Option<tokio::fs::File>>,
    recv_file: parking_lot::Mutex<Option<tokio::fs::File>>,
    // Received plaintext is staged to `recv_temp` and only renamed to
    // `recv_final` once the trailing AEAD tag verifies (`finalize_recv(true)`),
    // so a tampered transfer never leaves unauthenticated bytes at the
    // destination path. `None` for send-only providers.
    recv_temp: Option<std::path::PathBuf>,
    recv_final: Option<std::path::PathBuf>,
}

impl FileIOProvider {
    pub async fn new_send(path: std::path::PathBuf) -> std::io::Result<Self> {
        let file = tokio::fs::File::open(&path).await?;
        Ok(Self {
            send_file: parking_lot::Mutex::new(Some(file)),
            recv_file: parking_lot::Mutex::new(None),
            recv_temp: None,
            recv_final: None,
        })
    }

    pub async fn new_recv(path: std::path::PathBuf) -> std::io::Result<Self> {
        use rand_core::RngCore;
        // Stage to a sibling temp file in the destination directory so the final
        // commit is an atomic same-filesystem rename. The plaintext is only
        // moved into place after the AEAD tag verifies (see `finalize_recv`).
        let fname = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "recv".to_string());
        let temp_name = format!(".{}.tmp.{:016x}", fname, rand_core::OsRng.next_u64());
        let temp = match path.parent() {
            Some(dir) if !dir.as_os_str().is_empty() => dir.join(temp_name),
            _ => std::path::PathBuf::from(temp_name),
        };
        // Create the staging file exclusively (create_new) and, on unix, with
        // O_NOFOLLOW + mode 0600, so a pre-planted symlink/file at the temp path
        // cannot redirect the write to or truncate another file. Mirrors the
        // hardened temp creation in the local-file decrypt path (processor.rs).
        let std_file = {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
            }
            opts.open(&temp)?
        };
        let file = tokio::fs::File::from_std(std_file);
        Ok(Self {
            send_file: parking_lot::Mutex::new(None),
            recv_file: parking_lot::Mutex::new(Some(file)),
            recv_temp: Some(temp),
            recv_final: Some(path),
        })
    }
}

impl IOProvider for FileIOProvider {
    fn stdin(&self) -> Box<dyn tokio::io::AsyncRead + Unpin + Send> {
        match self.send_file.lock().take() {
            Some(f) => Box::new(f),
            None => Box::new(tokio::io::empty()),
        }
    }
    fn stdout(&self) -> Box<dyn tokio::io::AsyncWrite + Unpin + Send> {
        match self.recv_file.lock().take() {
            Some(f) => Box::new(f),
            None => Box::new(tokio::io::sink()),
        }
    }

    fn finalize_recv(&self, committed: bool) -> std::io::Result<()> {
        // Drop any temp handle still held (e.g. if `stdout()` was never taken,
        // such as a handshake failure before transfer) so the OS file is closed
        // before we rename/remove it (required on Windows).
        let _ = self.recv_file.lock().take();
        let (temp, final_path) = match (self.recv_temp.as_ref(), self.recv_final.as_ref()) {
            (Some(t), Some(f)) => (t, f),
            // Send-only provider, or constructed without staging: nothing to do.
            _ => return Ok(()),
        };
        if committed {
            // Atomic same-directory rename publishes the verified plaintext.
            std::fs::rename(temp, final_path)
        } else {
            // Discard unauthenticated bytes; tolerate an already-absent temp.
            match std::fs::remove_file(temp) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e),
            }
        }
    }
}

impl Drop for FileIOProvider {
    fn drop(&mut self) {
        // Safety net: if a staged recv temp file still exists (finalize_recv was
        // never reached due to an early error/panic), best-effort remove it so
        // decrypted-but-unauthenticated plaintext is not left on disk. After a
        // successful commit the temp was renamed away, so this is a no-op.
        if let Some(temp) = self.recv_temp.take() {
            let _ = std::fs::remove_file(temp);
        }
    }
}

#[cfg(test)]
pub struct TestIOProvider;
#[cfg(test)]
impl IOProvider for TestIOProvider {
    fn stdin(&self) -> Box<dyn tokio::io::AsyncRead + Unpin + Send> {
        Box::new(tokio::io::empty())
    }
    fn stdout(&self) -> Box<dyn tokio::io::AsyncWrite + Unpin + Send> {
        Box::new(tokio::io::sink())
    }
}

pub struct NetworkProcessor;

impl NetworkProcessor {
    pub async fn listen(config: &CryptoConfig) -> Result<()> {
        match config.transport {
            TransportKind::Tcp => tcp::NetworkProcessor::listen(config).await,
            TransportKind::Iroh => {
                let endpoint = Arc::new(crate::p2p::backend::iroh::IrohEndpoint::new(config, false).await?);
                let mut processor = crate::p2p::NetworkProcessor::new(config.clone(), endpoint, Arc::new(DefaultIOProvider));
                processor.preload_allowlist().await?;
                processor.start().await
            }
        }
    }

    pub async fn connect(config: &CryptoConfig) -> Result<()> {
        match config.transport {
            TransportKind::Tcp => tcp::NetworkProcessor::connect(config).await,
            TransportKind::Iroh => {
                let endpoint = Arc::new(crate::p2p::backend::iroh::IrohEndpoint::new(config, false).await?);
                let mut processor = crate::p2p::NetworkProcessor::new(config.clone(), endpoint, Arc::new(DefaultIOProvider));
                processor.preload_allowlist().await?;
                processor.run_connect().await
            }
        }
    }

    pub async fn read_line_secure<R: AsyncReadExt + Unpin>(
        reader: &mut R,
        buf: &mut Vec<u8>,
    ) -> Result<LineRead> {
        let mut b = [0u8; 1];
        let mut total = 0;
        const MAX_LINE_LEN: usize = 65536;
        loop {
            match reader.read(&mut b).await {
                Ok(0) => {
                    if total > 0 {
                        return Ok(LineRead::PartialEof);
                    } else {
                        return Ok(LineRead::Eof);
                    }
                }
                Ok(1) => {
                    if b[0] == b'\n' {
                        return Ok(LineRead::Line);
                    }
                    if b[0] != b'\r' {
                        if total >= MAX_LINE_LEN {
                            return Err(CryptoError::Parameter("Line too long".to_string()));
                        }
                        buf.push(b[0]);
                        total += 1;
                    }
                }
                _ => return Err(CryptoError::FileRead("Unexpected read result".to_string())),
            }
        }
    }

    pub fn update_transcript(transcript: &mut Vec<u8>, data: &[u8]) {
        transcript.extend_from_slice(&(data.len() as u32).to_le_bytes());
        transcript.extend_from_slice(data);
    }

    pub async fn read_vec<R: AsyncReadExt + Unpin>(stream: &mut R) -> Result<Vec<u8>> {
        let mut len_bytes = [0u8; 4];
        stream
            .read_exact(&mut len_bytes)
            .await
            .map_err(|e| CryptoError::FileRead(e.to_string()))?;
        let len = u32::from_le_bytes(len_bytes) as usize;
        if len > 8192 {
            return Err(CryptoError::Parameter("Vector too large".to_string()));
        }
        let mut v = vec![0u8; len];
        stream
            .read_exact(&mut v)
            .await
            .map_err(|e| CryptoError::FileRead(e.to_string()))?;
        Ok(v)
    }

    pub async fn write_vec<W: AsyncWriteExt + Unpin>(stream: &mut W, v: &[u8]) -> Result<()> {
        stream
            .write_all(&(v.len() as u32).to_le_bytes())
            .await
            .map_err(|e| CryptoError::FileRead(e.to_string()))?;
        stream
            .write_all(v)
            .await
            .map_err(|e| CryptoError::FileRead(e.to_string()))?;
        Ok(())
    }

    pub async fn receive_file<R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
        reader: R,
        writer: W,
        aead_algo: &str,
        key: &[u8],
        iv: &[u8],
    ) -> Result<()> {
        Self::receive_file_with_progress(reader, writer, aead_algo, key, iv, None).await
    }

    pub async fn receive_file_with_progress<R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
        mut reader: R,
        mut writer: W,
        aead_algo: &str,
        key: &[u8],
        iv: &[u8],
        on_progress: Option<ProgressCallback>,
    ) -> Result<()> {
        let mut aead = backend::new_decrypt(aead_algo, key, iv)?;
        let mut out_buffer = Zeroizing::new(vec![0u8; BUF_SIZE + 32]);
        let mut total_received = 0u64;
        let mut next_emit_at = PROGRESS_CHUNK_BYTES;
        loop {
            let mut len_bytes = [0u8; 4];
            let read_res =
                tokio::time::timeout(IDLE_TIMEOUT, reader.read_exact(&mut len_bytes)).await;
            match read_res {
                Ok(Ok(_)) => {}
                Ok(Err(_)) | Err(_) => break,
            }

            let chunk_len = u32::from_le_bytes(len_bytes) as usize;
            if chunk_len == 0 {
                break;
            }
            if chunk_len > BUF_SIZE + 256 {
                return Err(CryptoError::Parameter(format!(
                    "Chunk size {} exceeds limit",
                    chunk_len
                )));
            }
            total_received += chunk_len as u64;
            if total_received > MAX_FILE_SIZE {
                return Err(CryptoError::Parameter(
                    "File size limit exceeded".to_string(),
                ));
            }

            let mut encrypted_chunk = Zeroizing::new(vec![0u8; chunk_len]);
            tokio::time::timeout(IDLE_TIMEOUT, reader.read_exact(&mut encrypted_chunk))
                .await
                .map_err(|_| {
                    CryptoError::Parameter("Idle timeout while reading chunk".to_string())
                })?
                .map_err(|e| CryptoError::FileRead(e.to_string()))?;

            let n = aead.update(&encrypted_chunk, &mut out_buffer)?;
            writer
                .write_all(&out_buffer[..n])
                .await
                .map_err(|e| CryptoError::FileRead(e.to_string()))?;

            if let Some(ref cb) = on_progress {
                if total_received >= next_emit_at {
                    cb(total_received, None);
                    next_emit_at = total_received + PROGRESS_CHUNK_BYTES;
                }
            }
        }

        let mut tag = [0u8; 16];
        tokio::time::timeout(IDLE_TIMEOUT, reader.read_exact(&mut tag))
            .await
            .map_err(|_| CryptoError::Parameter("Idle timeout while reading tag".to_string()))?
            .map_err(|e| CryptoError::FileRead(format!("Failed to read GCM tag: {}", e)))?;

        aead.set_tag(&tag)?;
        let final_n = aead.finalize(&mut out_buffer)?;
        writer
            .write_all(&out_buffer[..final_n])
            .await
            .map_err(|e| CryptoError::FileRead(e.to_string()))?;
        writer
            .flush()
            .await
            .map_err(|e| CryptoError::FileRead(e.to_string()))?;

        if let Some(ref cb) = on_progress {
            cb(total_received, None);
        }

        eprintln!("File received and decrypted successfully.");
        Ok(())
    }

    pub async fn send_file<R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
        reader: R,
        writer: W,
        aead_algo: &str,
        key: &[u8],
        iv: &[u8],
    ) -> Result<()> {
        Self::send_file_with_progress(reader, writer, aead_algo, key, iv, None).await
    }

    pub async fn send_file_with_progress<R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
        mut reader: R,
        mut writer: W,
        aead_algo: &str,
        key: &[u8],
        iv: &[u8],
        on_progress: Option<ProgressCallback>,
    ) -> Result<()> {
        let mut aead = backend::new_encrypt(aead_algo, key, iv)?;
        let mut buffer = Zeroizing::new(vec![0u8; BUF_SIZE]);
        let mut out_buffer = Zeroizing::new(vec![0u8; BUF_SIZE + 32]);
        let mut sent: u64 = 0;
        let mut next_emit_at: u64 = PROGRESS_CHUNK_BYTES;

        loop {
            let n = reader
                .read(&mut buffer)
                .await
                .map_err(|e| CryptoError::FileRead(e.to_string()))?;
            if n == 0 {
                break;
            }
            let enc_n = aead.update(&buffer[..n], &mut out_buffer)?;

            tokio::time::timeout(IDLE_TIMEOUT, writer.write_all(&(enc_n as u32).to_le_bytes()))
                .await
                .map_err(|_| {
                    CryptoError::Parameter("Idle timeout while sending chunk header".to_string())
                })?
                .map_err(|e| CryptoError::FileRead(e.to_string()))?;
            tokio::time::timeout(IDLE_TIMEOUT, writer.write_all(&out_buffer[..enc_n]))
                .await
                .map_err(|_| {
                    CryptoError::Parameter("Idle timeout while sending chunk".to_string())
                })?
                .map_err(|e| CryptoError::FileRead(e.to_string()))?;

            sent += n as u64;
            if let Some(ref cb) = on_progress {
                if sent >= next_emit_at {
                    cb(sent, None);
                    next_emit_at = sent + PROGRESS_CHUNK_BYTES;
                }
            }
        }

        let final_n = aead.finalize(&mut out_buffer)?;
        let mut tag = vec![0u8; 16];
        aead.get_tag(&mut tag)?;

        tokio::time::timeout(IDLE_TIMEOUT, writer.write_all(&(final_n as u32).to_le_bytes()))
            .await
            .map_err(|_| {
                CryptoError::Parameter(
                    "Idle timeout while sending final chunk header".to_string(),
                )
            })?
            .map_err(|e| CryptoError::FileRead(e.to_string()))?;
        tokio::time::timeout(IDLE_TIMEOUT, writer.write_all(&out_buffer[..final_n]))
            .await
            .map_err(|_| {
                CryptoError::Parameter("Idle timeout while sending final chunk".to_string())
            })?
            .map_err(|e| CryptoError::FileRead(e.to_string()))?;
        tokio::time::timeout(IDLE_TIMEOUT, writer.write_all(&tag))
            .await
            .map_err(|_| CryptoError::Parameter("Idle timeout while sending tag".to_string()))?
            .map_err(|e| CryptoError::FileRead(e.to_string()))?;

        writer
            .flush()
            .await
            .map_err(|e| CryptoError::FileRead(e.to_string()))?;

        // Graceful close: signal end-of-stream to the receiver. Without this,
        // iroh QUIC SendStream reset on drop causes a "connection lost"
        // error on the receiver mid-read of the GCM tag. AsyncWrite shutdown
        // maps to QUIC FIN/finish for iroh streams and to a no-op for TCP.
        writer
            .shutdown()
            .await
            .map_err(|e| CryptoError::FileRead(e.to_string()))?;

        if let Some(ref cb) = on_progress {
            cb(sent, None);
        }

        eprintln!("File sent successfully.");
        Ok(())
    }

    // allow(clippy::too_many_arguments): each parameter is a distinct, required
    // input (streams/keys/IVs/role flag); bundling into a struct adds field-swap
    // risk in this security-critical loop for no functional benefit.
    // Future: revisit only if a cohesive context type emerges naturally.
    #[allow(clippy::too_many_arguments)]
    pub async fn chat_loop<R, W, SI, SO>(
        mut stream_rx: R,
        mut stream_tx: W,
        mut stdin: SI,
        stdout: Arc<tokio::sync::Mutex<SO>>,
        aead_name: &str,
        s2c_key: &[u8],
        c2s_key: &[u8],
        is_server: bool,
    ) -> Result<()>
    where
        R: AsyncReadExt + Unpin + Send + 'static,
        W: AsyncWriteExt + Unpin + Send + 'static,
        SI: AsyncReadExt + Unpin + Send,
        SO: AsyncWriteExt + Unpin + Send + 'static,
    {
        let (rx_key, tx_key) = if is_server {
            (
                Zeroizing::new(c2s_key.to_vec()),
                Zeroizing::new(s2c_key.to_vec()),
            )
        } else {
            (
                Zeroizing::new(s2c_key.to_vec()),
                Zeroizing::new(c2s_key.to_vec()),
            )
        };

        let aead_name_str = aead_name.to_string();
        let (rx_done_tx, mut rx_done_rx) = tokio::sync::mpsc::channel(1);

        let stdout_rx = stdout.clone();
        let rx_task = tokio::spawn(async move {
            let mut out_buf = Zeroizing::new(vec![0u8; 70000]);
            let mut seen_nonces: std::collections::HashSet<Vec<u8>> =
                std::collections::HashSet::new();
            let mut nonce_history = std::collections::VecDeque::new();
            let mut rx_aead_opt: Option<Aead> = None;
            let result = async {
                loop {
                    let mut len_bytes = [0u8; 4];
                    let read_res =
                        tokio::time::timeout(IDLE_TIMEOUT, stream_rx.read_exact(&mut len_bytes))
                            .await;
                    match read_res {
                        Ok(Ok(_)) => {}
                        Ok(Err(_)) | Err(_) => break,
                    }

                    let chunk_len = u32::from_le_bytes(len_bytes) as usize;
                    if chunk_len == 0 {
                        break;
                    }
                    if chunk_len < 29 || chunk_len > 70000 {
                        return Err(CryptoError::Parameter("Invalid packet size".to_string()));
                    }

                    let mut packet = Zeroizing::new(vec![0u8; chunk_len]);
                    tokio::time::timeout(IDLE_TIMEOUT, stream_rx.read_exact(&mut packet))
                        .await
                        .map_err(|_| {
                            CryptoError::Parameter(
                                "Idle timeout while reading chat packet".to_string(),
                            )
                        })?
                        .map_err(|e| CryptoError::FileRead(e.to_string()))?;

                    let (nonce, rest) = packet.split_at(12);
                    let (ciphertext, tag) = rest.split_at(rest.len() - 16);

                    if seen_nonces.contains(nonce) {
                        return Err(CryptoError::Parameter(
                            "Replayed nonce detected".to_string(),
                        ));
                    }
                    let nonce_vec = nonce.to_vec();
                    seen_nonces.insert(nonce_vec.clone());
                    nonce_history.push_back(nonce_vec);
                    if nonce_history.len() > 100000 {
                        if let Some(oldest) = nonce_history.pop_front() {
                            seen_nonces.remove(&oldest);
                        }
                    }

                    let rx_aead = match rx_aead_opt.as_mut() {
                        Some(aead) => {
                            aead.re_init(&rx_key, nonce)?;
                            aead
                        }
                        None => rx_aead_opt.insert(backend::new_decrypt(&aead_name_str, &rx_key, nonce)?),
                    };
                    rx_aead.set_tag(tag)?;

                    let n = rx_aead.update(ciphertext, &mut out_buf)?;
                    let final_n = rx_aead.finalize(&mut out_buf[n..])?;
                    let used = n + final_n;

                    // Lossy decode: preserve valid UTF-8 portions and mark
                    // bad bytes with U+FFFD instead of dropping the entire
                    // message. Some peers' terminals/IMEs occasionally emit
                    // non-UTF-8 bytes, and showing a partial-but-readable
                    // message is more useful than a single placeholder line.
                    let msg_content: Zeroizing<String> = Zeroizing::new(
                        String::from_utf8_lossy(&out_buf[..used]).into_owned(),
                    );
                    let msg = Zeroizing::new(
                        msg_content
                            .chars()
                            .filter(|c| {
                                let is_dangerous = match *c {
                                    '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' => true,
                                    '\u{200B}'..='\u{200D}' | '\u{FEFF}' => true,
                                    '\u{061C}' => true,
                                    '\u{180E}' => true,
                                    '\u{E0000}'..='\u{E007F}' => true,
                                    '\u{115F}' | '\u{1160}' | '\u{3164}' | '\u{FFA0}' => true,
                                    _ => false,
                                };
                                (!c.is_control() || *c == '\n' || *c == '\t') && !is_dangerous
                            })
                            .collect::<String>(),
                    );
                    {
                        let mut out = stdout_rx.lock().await;
                        let _ = out.write_all(b"\r[Peer]: ").await;
                        let _ = out.write_all(msg.as_bytes()).await;
                        let _ = out.write_all(b"\n> ").await;
                        let _ = out.flush().await;
                    }

                    out_buf.fill(0);
                }
                Ok::<(), CryptoError>(())
            }
            .await;
            let _ = rx_done_tx.send(result).await;
        });

        let _rx_guard = AbortGuard(rx_task.abort_handle());

        let mut line_buf = Zeroizing::new(Vec::new());

        eprintln!("--- Chat mode started ---");
        {
            let mut out = stdout.lock().await;
            let _ = out.write_all(b"> ").await;
            let _ = out.flush().await;
        }

        let mut tx_aead_opt: Option<Aead> = None;
        loop {
            tokio::select! {
                rx_result = rx_done_rx.recv() => {
                    if let Some(Err(e)) = rx_result {
                        eprintln!("\r\n[System]: Connection closed due to error: {}", e);
                        return Err(e);
                    }
                    eprintln!("\r\n[System]: Connection closed by peer.");
                    break Ok(());
                }
                res = Self::read_line_secure(&mut stdin, &mut line_buf) => {
                    let lr = res?;
                    if lr == LineRead::Eof {
                        eprintln!("\r\n[System]: stdin closed.");
                        break Ok(());
                    }
                    if lr == LineRead::Line && line_buf.is_empty() {
                        let mut out = stdout.lock().await;
                        let _ = out.write_all(b"> ").await;
                        let _ = out.flush().await;
                        continue;
                    }
                    // Lossy decode of local keyboard bytes: if the user's
                    // terminal/IME emits non-UTF-8 bytes (e.g. Shift-JIS or a
                    // partial multibyte read), preserve the valid characters
                    // and replace bad bytes with U+FFFD instead of sending
                    // the literal placeholder "[Invalid UTF-8]" over the
                    // wire. The peer at least sees what we typed.
                    let line = Zeroizing::new(
                        String::from_utf8_lossy(&line_buf).into_owned()
                    );
                    line_buf.zeroize();
                    line_buf.clear();

                    let mut data = line.as_bytes();
                    if data.len() > 65000 {
                        data = &data[..65000];
                        eprintln!("Warning: Message truncated to 65000 bytes.");
                    }

                    let mut nonce = Zeroizing::new(vec![0u8; 12]);
                    #[cfg(feature = "backend-openssl")]
                    openssl::rand::rand_bytes(&mut nonce).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
                    #[cfg(feature = "backend-rustcrypto")]
                    {
                        use rand_core::{RngCore, OsRng};
                        OsRng.fill_bytes(&mut nonce);
                    }

                    let tx_aead = match tx_aead_opt.as_mut() {
                        Some(aead) => {
                            aead.re_init(&tx_key, &nonce)?;
                            aead
                        }
                        None => tx_aead_opt.insert(backend::new_encrypt(aead_name, &tx_key, &nonce)?),
                    };
                    let mut encrypted = Zeroizing::new(vec![0u8; data.len() + 32]);
                    let n = tx_aead.update(data, &mut encrypted)?;
                    let final_n = tx_aead.finalize(&mut encrypted[n..])?;

                    let mut tag = Zeroizing::new(vec![0u8; 16]);
                    tx_aead.get_tag(&mut tag)?;

                    let mut packet = Zeroizing::new(Vec::with_capacity(12 + n + final_n + 16));
                    packet.extend_from_slice(&nonce);
                    packet.extend_from_slice(&encrypted[..n + final_n]);
                    packet.extend_from_slice(&tag);

                    tokio::time::timeout(IDLE_TIMEOUT, stream_tx.write_all(&(packet.len() as u32).to_le_bytes())).await
                        .map_err(|_| CryptoError::Parameter("Idle timeout while sending chat header".to_string()))?
                        .map_err(|e| CryptoError::FileRead(e.to_string()))?;
                    tokio::time::timeout(IDLE_TIMEOUT, stream_tx.write_all(&packet)).await
                        .map_err(|_| CryptoError::Parameter("Idle timeout while sending chat packet".to_string()))?
                        .map_err(|e| CryptoError::FileRead(e.to_string()))?;

                    {
                        let mut out = stdout.lock().await;
                        let _ = out.write_all(b"> ").await;
                        let _ = out.flush().await;
                    }

                    if lr == LineRead::PartialEof {
                        eprintln!("\r\n[System]: stdin closed.");
                        break Ok(());
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_read_line_secure_eof() {
        let mut input = tokio::io::empty();
        let mut buf = Vec::new();
        let res = NetworkProcessor::read_line_secure(&mut input, &mut buf).await.unwrap();
        assert_eq!(res, LineRead::Eof);
        assert!(buf.is_empty());
    }

    #[tokio::test]
    async fn test_read_line_secure_empty_line() {
        let mut input = std::io::Cursor::new(b"\n");
        let mut buf = Vec::new();
        let res = NetworkProcessor::read_line_secure(&mut input, &mut buf).await.unwrap();
        assert_eq!(res, LineRead::Line);
        assert!(buf.is_empty());
    }

    #[tokio::test]
    async fn test_read_line_secure_line() {
        let mut input = std::io::Cursor::new(b"hello\n");
        let mut buf = Vec::new();
        let res = NetworkProcessor::read_line_secure(&mut input, &mut buf).await.unwrap();
        assert_eq!(res, LineRead::Line);
        assert_eq!(buf, b"hello");
    }

    #[tokio::test]
    async fn test_read_line_secure_partial_eof() {
        let mut input = std::io::Cursor::new(b"partial");
        let mut buf = Vec::new();
        let res = NetworkProcessor::read_line_secure(&mut input, &mut buf).await.unwrap();
        assert_eq!(res, LineRead::PartialEof);
        assert_eq!(buf, b"partial");
    }

    #[tokio::test]
    async fn test_chat_loop_e2e_full() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        async fn read_until<R: AsyncReadExt + Unpin>(reader: &mut R, target: &str) -> String {
            let mut full = String::new();
            let mut buf = [0u8; 1024];
            loop {
                let n = tokio::time::timeout(std::time::Duration::from_secs(2), reader.read(&mut buf))
                    .await
                    .expect("Read timeout")
                    .expect("Read failed");
                if n == 0 {
                    break;
                }
                full.push_str(&String::from_utf8_lossy(&buf[..n]));
                if full.contains(target) {
                    break;
                }
            }
            full
        }

        let (alice_net, bob_net) = tokio::io::duplex(65536);
        let (alice_net_rx, alice_net_tx) = tokio::io::split(alice_net);
        let (bob_net_rx, bob_net_tx) = tokio::io::split(bob_net);

        let (mut alice_stdin_tx, alice_stdin_rx) = tokio::io::duplex(1024);
        let (alice_stdout_rx_tx, mut alice_stdout_rx_rx) = tokio::io::duplex(1024);

        let (mut bob_stdin_tx, bob_stdin_rx) = tokio::io::duplex(1024);
        let (bob_stdout_rx_tx, mut bob_stdout_rx_rx) = tokio::io::duplex(1024);

        let key = vec![0u8; 32];
        let key_alice1 = key.clone();
        let key_alice2 = key.clone();
        let key_bob1 = key.clone();
        let key_bob2 = key.clone();

        let alice_stdout = Arc::new(tokio::sync::Mutex::new(alice_stdout_rx_tx));
        let alice_handle = tokio::spawn(async move {
            NetworkProcessor::chat_loop(
                alice_net_rx,
                alice_net_tx,
                alice_stdin_rx,
                alice_stdout,
                "AES-256-GCM",
                &key_alice1,
                &key_alice2,
                true,
            )
            .await
        });

        let bob_stdout = Arc::new(tokio::sync::Mutex::new(bob_stdout_rx_tx));
        let bob_handle = tokio::spawn(async move {
            NetworkProcessor::chat_loop(
                bob_net_rx,
                bob_net_tx,
                bob_stdin_rx,
                bob_stdout,
                "AES-256-GCM",
                &key_bob1,
                &key_bob2,
                false,
            )
            .await
        });

        // Alice sends message to Bob
        alice_stdin_tx.write_all(b"Hello Bob\n").await.unwrap();

        // Bob receives message
        let bob_msg = read_until(&mut bob_stdout_rx_rx, "Hello Bob").await;
        assert!(bob_msg.contains("Hello Bob"));

        // Bob sends message to Alice
        bob_stdin_tx.write_all(b"Hello Alice\n").await.unwrap();

        // Alice receives message
        let alice_msg = read_until(&mut alice_stdout_rx_rx, "Hello Alice").await;
        assert!(alice_msg.contains("Hello Alice"));

        // Clean termination: close stdin
        drop(alice_stdin_tx);
        drop(bob_stdin_tx);

        let (alice_res, bob_res) = tokio::join!(alice_handle, bob_handle);
        alice_res.unwrap().expect("Alice chat_loop failed");
        bob_res.unwrap().expect("Bob chat_loop failed");
    }
}
