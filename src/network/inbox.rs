//! `nkct/inbox/1` — store-and-forward delivery for opaque payloads.
//!
//! Designed as an untrusted Delivery Service in the sense of RFC 9420 §3:
//! the server stores envelopes keyed by recipient PeerId and returns
//! them on demand to the matching peer, but it never reads, decrypts, or
//! interprets the payload bytes. Combined with the MLS layer in
//! [`crate::group`], this provides asynchronous (offline-capable)
//! delivery without weakening the end-to-end cryptographic guarantees.
//!
//! ## Wire protocol
//!
//! One operation per stream. Frames are little-endian; payloads are
//! capped at [`MAX_PAYLOAD`] bytes (matches
//! [`crate::group::transport::MAX_MLS_FRAME_BYTES`]).
//!
//! ### DEPOSIT
//!
//! ```text
//! request:  u8(0x01) || recipient([u8;32]) || payload_len(u32) || payload
//! reply:    u8(0x00 = ok | 0xFF = rejected)
//! ```
//!
//! Anyone can deposit to anyone — the server intentionally accepts
//! unauthenticated DEPOSIT so a sender can reach a recipient whose
//! direct iroh connect failed. Sender's NodeId is recorded in the
//! sqlite row for abuse tracing but is NOT exposed to the recipient.
//!
//! ### POLL
//!
//! ```text
//! request:  u8(0x02) || since_cursor(u64) || max(u32)
//! reply:    count(u32) || [ cursor(u64) || payload_len(u32) || payload ] * count
//! ```
//!
//! The server authenticates the caller via the iroh QUIC handshake —
//! the connecting NodeId IS the recipient ID for the SELECT — so a
//! peer cannot poll someone else's inbox even by claiming a different
//! ID in the request (there is no ID field to claim).
//!
//! `cursor` is the server-side sqlite row id, monotonic per recipient.
//! Pass `since_cursor = 0` on first call to drain the backlog; pass the
//! largest returned cursor on subsequent calls to receive only new
//! envelopes. `max` is clamped server-side to [`MAX_POLL_BATCH`].

use crate::network::ALPN_INBOX;
use crate::p2p::{P2pEndpoint, P2pError, P2pIncoming, P2pProtocol, PeerAddr, PeerId};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Largest payload accepted by either DEPOSIT or POLL. Matches the MLS
/// transport's frame cap so any MLS frame fits.
pub const MAX_PAYLOAD: usize = 16 * 1024 * 1024;

/// Server-imposed upper bound on envelopes returned per POLL. Clients
/// repeat polls until they get a count < this cap to fully drain.
pub const MAX_POLL_BATCH: u32 = 64;

/// Default per-frame idle timeout. Generous enough to absorb iroh
/// hole-punching latency; short enough to bound retry cost.
pub const IO_TIMEOUT: Duration = Duration::from_secs(30);

const TAG_DEPOSIT: u8 = 0x01;
const TAG_POLL: u8 = 0x02;
const REPLY_OK: u8 = 0x00;
const REPLY_FAIL: u8 = 0xFF;

#[derive(thiserror::Error, Debug)]
pub enum InboxError {
    #[error("transport: {0}")]
    Transport(#[from] P2pError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("server rejected deposit")]
    Rejected,
    #[error("invalid protocol frame: {0}")]
    Protocol(String),
    #[error("payload too large: {0}")]
    TooLarge(usize),
    #[error("timed out: {0}")]
    Timeout(&'static str),
    #[cfg(feature = "mls")]
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

async fn write_timed<S>(
    stream: &mut S,
    buf: &[u8],
    label: &'static str,
) -> Result<(), InboxError>
where
    S: AsyncWriteExt + Unpin + ?Sized,
{
    tokio::time::timeout(IO_TIMEOUT, stream.write_all(buf))
        .await
        .map_err(|_| InboxError::Timeout(label))??;
    Ok(())
}

async fn read_timed<S>(
    stream: &mut S,
    buf: &mut [u8],
    label: &'static str,
) -> Result<(), InboxError>
where
    S: AsyncReadExt + Unpin + ?Sized,
{
    tokio::time::timeout(IO_TIMEOUT, stream.read_exact(buf))
        .await
        .map_err(|_| InboxError::Timeout(label))??;
    Ok(())
}

// -----------------------------------------------------------------------------
// Client API
// -----------------------------------------------------------------------------

/// Deposit `payload` for `recipient` at the inbox `server`. The server
/// returns ok / rejected; sender doesn't get a delivery confirmation
/// beyond "the bytes are stored". The recipient surfaces them on its
/// next POLL.
pub async fn deposit(
    endpoint: &dyn P2pEndpoint,
    server: &PeerAddr,
    recipient: PeerId,
    payload: &[u8],
) -> Result<(), InboxError> {
    if payload.is_empty() || payload.len() > MAX_PAYLOAD {
        return Err(InboxError::TooLarge(payload.len()));
    }
    let mut stream = endpoint
        .connect(server, P2pProtocol(ALPN_INBOX))
        .await?;
    let mut header = Vec::with_capacity(1 + 32 + 4);
    header.push(TAG_DEPOSIT);
    header.extend_from_slice(recipient.as_bytes());
    header.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    write_timed(&mut stream, &header, "deposit header").await?;
    write_timed(&mut stream, payload, "deposit payload").await?;
    tokio::time::timeout(IO_TIMEOUT, stream.flush())
        .await
        .map_err(|_| InboxError::Timeout("deposit flush"))??;
    let mut reply = [0u8; 1];
    read_timed(&mut stream, &mut reply, "deposit reply").await?;
    let _ = stream.shutdown().await;
    match reply[0] {
        REPLY_OK => Ok(()),
        _ => Err(InboxError::Rejected),
    }
}

/// Poll the inbox `server` for envelopes addressed to us (identified
/// implicitly by the QUIC handshake's NodeId). Returns the new cursor
/// to pass on the next poll, and the raw payload bytes of every
/// envelope. The caller decides how to dispatch each payload — for the
/// MLS use case, feed each into [`crate::group::transport::recv_mls_message`]
/// — equivalent framing.
pub async fn poll(
    endpoint: &dyn P2pEndpoint,
    server: &PeerAddr,
    since_cursor: u64,
) -> Result<(u64, Vec<Vec<u8>>), InboxError> {
    let mut stream = endpoint
        .connect(server, P2pProtocol(ALPN_INBOX))
        .await?;
    let mut header = Vec::with_capacity(1 + 8 + 4);
    header.push(TAG_POLL);
    header.extend_from_slice(&since_cursor.to_le_bytes());
    header.extend_from_slice(&MAX_POLL_BATCH.to_le_bytes());
    write_timed(&mut stream, &header, "poll header").await?;
    tokio::time::timeout(IO_TIMEOUT, stream.flush())
        .await
        .map_err(|_| InboxError::Timeout("poll flush"))??;
    let mut count_buf = [0u8; 4];
    read_timed(&mut stream, &mut count_buf, "poll count").await?;
    let count = u32::from_le_bytes(count_buf);
    if count > MAX_POLL_BATCH {
        return Err(InboxError::Protocol(format!(
            "server returned count={count} > MAX_POLL_BATCH={MAX_POLL_BATCH}"
        )));
    }
    let mut last_cursor = since_cursor;
    let mut envelopes = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let mut cursor_buf = [0u8; 8];
        read_timed(&mut stream, &mut cursor_buf, "envelope cursor").await?;
        let cursor = u64::from_le_bytes(cursor_buf);
        let mut len_buf = [0u8; 4];
        read_timed(&mut stream, &mut len_buf, "envelope len").await?;
        let len = u32::from_le_bytes(len_buf) as usize;
        if len == 0 || len > MAX_PAYLOAD {
            return Err(InboxError::TooLarge(len));
        }
        let mut payload = vec![0u8; len];
        read_timed(&mut stream, &mut payload, "envelope payload").await?;
        envelopes.push(payload);
        if cursor > last_cursor {
            last_cursor = cursor;
        }
    }
    let _ = stream.shutdown().await;
    Ok((last_cursor, envelopes))
}

// -----------------------------------------------------------------------------
// Server
// -----------------------------------------------------------------------------

#[cfg(feature = "mls")]
mod server {
    use super::*;
    use rusqlite::{params, Connection};
    use std::path::Path;
    use tokio::sync::Mutex as AsyncMutex;

    /// Persistent inbox: sqlite-backed envelope storage + ALPN_INBOX
    /// accept loop.
    pub struct InboxServer {
        db: Arc<AsyncMutex<Connection>>,
    }

    impl InboxServer {
        /// Open an inbox at `path`, creating the schema on first use.
        /// WAL + NORMAL synchronous so concurrent DEPOSIT/POLL don't
        /// block each other.
        pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, InboxError> {
            let conn = Connection::open(path).map_err(InboxError::Sqlite)?;
            conn.execute_batch(
                "
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = NORMAL;
                PRAGMA busy_timeout = 5000;
                CREATE TABLE IF NOT EXISTS envelopes (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    recipient   BLOB NOT NULL,
                    sender      BLOB NOT NULL,
                    payload     BLOB NOT NULL,
                    created_at  INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS envelopes_recipient_id
                    ON envelopes(recipient, id);
                ",
            )
            .map_err(InboxError::Sqlite)?;
            Ok(Self {
                db: Arc::new(AsyncMutex::new(conn)),
            })
        }

        /// Run the accept loop. Each accepted stream is dispatched on
        /// its own task; the server is fully concurrent for both
        /// DEPOSIT and POLL.
        pub async fn run(
            self: Arc<Self>,
            endpoint: Arc<dyn P2pEndpoint>,
        ) -> Result<(), InboxError> {
            loop {
                let incoming = endpoint
                    .accept()
                    .await
                    .map_err(InboxError::Transport)?;
                if incoming.protocol != P2pProtocol(ALPN_INBOX) {
                    // Not addressed to us — drop. (Endpoint may serve
                    // multiple ALPNs; only ours is interesting here.)
                    continue;
                }
                let me = Arc::clone(&self);
                tokio::spawn(async move {
                    if let Err(e) = me.handle(incoming).await {
                        eprintln!("[inbox] handle error: {e}");
                    }
                });
            }
        }

        async fn handle(&self, mut incoming: P2pIncoming) -> Result<(), InboxError> {
            let sender = incoming.peer_id;
            let mut tag = [0u8; 1];
            read_timed(&mut incoming.stream, &mut tag, "request tag").await?;
            match tag[0] {
                TAG_DEPOSIT => self.handle_deposit(&mut *incoming.stream, sender).await,
                TAG_POLL => self.handle_poll(&mut *incoming.stream, sender).await,
                t => Err(InboxError::Protocol(format!("unknown tag {t:#x}"))),
            }
        }

        async fn handle_deposit<S>(
            &self,
            stream: &mut S,
            sender: PeerId,
        ) -> Result<(), InboxError>
        where
            S: AsyncReadExt + AsyncWriteExt + Unpin + ?Sized,
        {
            let mut recipient_buf = [0u8; 32];
            read_timed(stream, &mut recipient_buf, "deposit recipient").await?;
            let recipient = PeerId::new(recipient_buf);
            let mut len_buf = [0u8; 4];
            read_timed(stream, &mut len_buf, "deposit len").await?;
            let len = u32::from_le_bytes(len_buf) as usize;
            if len == 0 || len > MAX_PAYLOAD {
                let _ = write_timed(stream, &[REPLY_FAIL], "deposit reply (fail)").await;
                return Err(InboxError::TooLarge(len));
            }
            let mut payload = vec![0u8; len];
            read_timed(stream, &mut payload, "deposit payload").await?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            {
                let db = self.db.lock().await;
                db.execute(
                    "INSERT INTO envelopes(recipient, sender, payload, created_at) \
                     VALUES(?, ?, ?, ?)",
                    params![
                        recipient.as_bytes().as_slice(),
                        sender.as_bytes().as_slice(),
                        payload,
                        now,
                    ],
                )?;
            }
            write_timed(stream, &[REPLY_OK], "deposit reply (ok)").await?;
            tokio::time::timeout(IO_TIMEOUT, stream.flush())
                .await
                .map_err(|_| InboxError::Timeout("deposit flush"))??;
            let _ = stream.shutdown().await;
            Ok(())
        }

        async fn handle_poll<S>(
            &self,
            stream: &mut S,
            recipient: PeerId,
        ) -> Result<(), InboxError>
        where
            S: AsyncReadExt + AsyncWriteExt + Unpin + ?Sized,
        {
            let mut cursor_buf = [0u8; 8];
            read_timed(stream, &mut cursor_buf, "poll cursor").await?;
            let since = u64::from_le_bytes(cursor_buf);
            let mut max_buf = [0u8; 4];
            read_timed(stream, &mut max_buf, "poll max").await?;
            let max =
                std::cmp::min(u32::from_le_bytes(max_buf), MAX_POLL_BATCH) as i64;
            // SELECT recipient = handshake-authenticated NodeId, so no
            // peer can read someone else's inbox even by crafting the
            // request (there is no recipient field in the wire to
            // override).
            let rows: Vec<(i64, Vec<u8>)> = {
                let db = self.db.lock().await;
                let mut stmt = db.prepare(
                    "SELECT id, payload FROM envelopes \
                     WHERE recipient = ? AND id > ? \
                     ORDER BY id ASC LIMIT ?",
                )?;
                let iter = stmt.query_map(
                    params![recipient.as_bytes().as_slice(), since as i64, max],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
                )?;
                iter.collect::<Result<Vec<_>, _>>()?
            };
            let count = rows.len() as u32;
            write_timed(stream, &count.to_le_bytes(), "poll count").await?;
            for (id, payload) in &rows {
                write_timed(stream, &(*id as u64).to_le_bytes(), "envelope cursor").await?;
                write_timed(stream, &(payload.len() as u32).to_le_bytes(), "envelope len").await?;
                write_timed(stream, payload, "envelope payload").await?;
            }
            tokio::time::timeout(IO_TIMEOUT, stream.flush())
                .await
                .map_err(|_| InboxError::Timeout("poll flush"))??;
            let _ = stream.shutdown().await;
            Ok(())
        }
    }
}

#[cfg(feature = "mls")]
pub use server::InboxServer;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(all(test, feature = "mls"))]
mod tests {
    use super::*;
    use crate::p2p::backend::mock::MockNetwork;
    use crate::p2p::PeerAddr;
    use tempfile::tempdir;

    fn pid(b: u8) -> PeerId {
        PeerId::new([b; 32])
    }

    /// End-to-end: alice deposits a payload addressed to bob; bob polls
    /// and retrieves it. Cursor advances across calls; a second poll
    /// from the new cursor returns nothing until a fresh deposit lands.
    #[tokio::test]
    async fn deposit_then_poll_roundtrip() {
        let net = MockNetwork::new();
        let alice = Arc::new(
            net.register(pid(1), vec![P2pProtocol(ALPN_INBOX)]),
        ) as Arc<dyn P2pEndpoint>;
        let bob = Arc::new(
            net.register(pid(2), vec![P2pProtocol(ALPN_INBOX)]),
        ) as Arc<dyn P2pEndpoint>;
        let server_ep = Arc::new(
            net.register(pid(99), vec![P2pProtocol(ALPN_INBOX)]),
        ) as Arc<dyn P2pEndpoint>;

        let dir = tempdir().expect("tempdir");
        let server = Arc::new(InboxServer::open(dir.path().join("inbox.db")).expect("open"));
        let server_task = {
            let s = Arc::clone(&server);
            let ep = Arc::clone(&server_ep);
            tokio::spawn(async move {
                let _ = s.run(ep).await;
            })
        };

        let server_addr = PeerAddr::new(pid(99));
        let bob_id = pid(2);

        deposit(alice.as_ref(), &server_addr, bob_id, b"hello bob 1")
            .await
            .expect("deposit 1");
        deposit(alice.as_ref(), &server_addr, bob_id, b"hello bob 2")
            .await
            .expect("deposit 2");

        let (cursor, envelopes) = poll(bob.as_ref(), &server_addr, 0)
            .await
            .expect("first poll");
        assert_eq!(envelopes.len(), 2);
        assert_eq!(&envelopes[0], b"hello bob 1");
        assert_eq!(&envelopes[1], b"hello bob 2");
        assert!(cursor > 0);

        // Second poll from the same cursor returns nothing.
        let (cursor2, e2) = poll(bob.as_ref(), &server_addr, cursor)
            .await
            .expect("second poll");
        assert!(e2.is_empty());
        assert_eq!(cursor2, cursor);

        // Fresh deposit lands; new poll picks it up.
        deposit(alice.as_ref(), &server_addr, bob_id, b"hello bob 3")
            .await
            .expect("deposit 3");
        let (cursor3, e3) = poll(bob.as_ref(), &server_addr, cursor2)
            .await
            .expect("third poll");
        assert_eq!(e3.len(), 1);
        assert_eq!(&e3[0], b"hello bob 3");
        assert!(cursor3 > cursor2);

        server_task.abort();
    }

    /// A peer's POLL only sees envelopes addressed to itself, even
    /// though carol shares the same server with alice/bob.
    #[tokio::test]
    async fn poll_is_isolated_by_handshake_id() {
        let net = MockNetwork::new();
        let alice = Arc::new(
            net.register(pid(1), vec![P2pProtocol(ALPN_INBOX)]),
        ) as Arc<dyn P2pEndpoint>;
        let bob = Arc::new(
            net.register(pid(2), vec![P2pProtocol(ALPN_INBOX)]),
        ) as Arc<dyn P2pEndpoint>;
        let carol = Arc::new(
            net.register(pid(3), vec![P2pProtocol(ALPN_INBOX)]),
        ) as Arc<dyn P2pEndpoint>;
        let server_ep = Arc::new(
            net.register(pid(99), vec![P2pProtocol(ALPN_INBOX)]),
        ) as Arc<dyn P2pEndpoint>;
        let dir = tempdir().expect("tempdir");
        let server = Arc::new(InboxServer::open(dir.path().join("inbox.db")).expect("open"));
        let task = {
            let s = Arc::clone(&server);
            let ep = Arc::clone(&server_ep);
            tokio::spawn(async move { let _ = s.run(ep).await; })
        };
        let server_addr = PeerAddr::new(pid(99));

        deposit(alice.as_ref(), &server_addr, pid(2), b"for bob")
            .await
            .expect("dep bob");
        deposit(alice.as_ref(), &server_addr, pid(3), b"for carol")
            .await
            .expect("dep carol");

        let (_, bob_mail) = poll(bob.as_ref(), &server_addr, 0)
            .await
            .expect("bob poll");
        let (_, carol_mail) = poll(carol.as_ref(), &server_addr, 0)
            .await
            .expect("carol poll");
        assert_eq!(bob_mail, vec![b"for bob".to_vec()]);
        assert_eq!(carol_mail, vec![b"for carol".to_vec()]);

        task.abort();
    }
}
