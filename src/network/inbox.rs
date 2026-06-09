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
//!
//! ### PUBLISH (One-Time Prekeys)
//!
//! ```text
//! request:  u8(0x04) || count(u32) || [ blob_len(u32) || blob ] * count
//! reply:    u8(0x00 = ok | 0xFF = rejected)
//! ```
//!
//! The recipient pre-publishes a batch of *signed* One-Time Prekeys
//! (PQ-FS, see `crate::prekey` and PQFS_DESIGN.md) into its **own** slot —
//! the slot key is the handshake-authenticated NodeId, never a wire field,
//! so no peer can stuff prekeys into someone else's slot. Each `blob` is an
//! opaque `SignedPrekey::to_bytes()`; the server stores it verbatim and
//! never parses or verifies it (verification is the *fetching sender's*
//! job, against the recipient's ML-DSA identity). A per-recipient cap of
//! [`MAX_PREKEYS_STORED`] bounds storage abuse: the newest prekeys win.
//!
//! ### FETCH (One-Time Prekey)
//!
//! ```text
//! request:  u8(0x05) || recipient([u8;32])
//! reply (ok):           u8(0x00) || blob_len(u32) || blob
//! reply (depleted):     u8(0xFD)
//! reply (rate limited): u8(0xFC)
//! ```
//!
//! A sender fetches a single prekey for `recipient` to build a
//! forward-secret one-shot ciphertext. Prekeys are **one-time**: the served
//! row is deleted in the same critical section, so each is handed out once.
//!
//! FETCH is the prekey-*depletion downgrade* attack surface (PQFS_DESIGN.md
//! §4.1): an attacker who drains the pool forces the recipient down to the
//! no-FS static-key fallback. The mitigation is a **token-bucket rate limit
//! keyed by the connecting (sender) NodeId** ([`FETCH_RL_CAPACITY`] /
//! [`FETCH_RL_REFILL_PER_SEC`]). It raises the per-identity cost of
//! draining; it is not a complete defence (NodeIds are cheap to mint), so
//! the Strict profile's "refuse on depletion" policy remains the backstop.
//! `depleted` and `rate limited` are distinct replies so the sender can
//! tell genuine exhaustion (→ fallback / refuse) from a transient throttle
//! (→ back off and retry).

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

/// Largest single serialized prekey blob accepted by PUBLISH/FETCH. A
/// X-Wing `SignedPrekey` is ~4.5 KiB (1216 B key + 3309 B ML-DSA-65 sig +
/// framing); 8 KiB leaves headroom while rejecting absurd lengths.
pub const MAX_PREKEY_BLOB: usize = 8 * 1024;

/// Largest number of prekeys accepted in one PUBLISH.
pub const MAX_PUBLISH_BATCH: u32 = 128;

/// Per-recipient cap on stored prekeys. A PUBLISH that pushes the slot over
/// this trims the oldest, bounding storage abuse by a malicious recipient.
pub const MAX_PREKEYS_STORED: u64 = 256;

/// FETCH token-bucket burst capacity, per connecting NodeId: a sender may
/// fetch this many prekeys back-to-back (e.g. fanning out to several
/// recipients) before the refill rate gates it.
pub const FETCH_RL_CAPACITY: f64 = 8.0;

/// FETCH token-bucket refill rate (tokens/second), per connecting NodeId.
/// One token every 30 s (≈120/hour) sustains legitimate use — a sender
/// normally fetches *one* prekey per recipient — while making a single
/// identity's attempt to drain a [`MAX_PREKEYS_STORED`] pool slow and
/// conspicuous. Tunable policy; see the FETCH note in the module docs.
pub const FETCH_RL_REFILL_PER_SEC: f64 = 1.0 / 30.0;

/// Soft cap on distinct NodeIds tracked for FETCH rate limiting. When the
/// table reaches this, fully-refilled (idle) buckets are pruned, bounding
/// memory without losing any throttle state for active senders.
const FETCH_RL_MAX_TRACKED: usize = 4096;

/// Default per-frame idle timeout. Generous enough to absorb iroh
/// hole-punching latency; short enough to bound retry cost.
pub const IO_TIMEOUT: Duration = Duration::from_secs(30);

const TAG_DEPOSIT: u8 = 0x01;
const TAG_POLL: u8 = 0x02;
/// CHECKPOINT: the client reports its current at-rest rollback epoch; the
/// server (an independent, off-device trust boundary) remembers the
/// highest epoch seen per authenticated peer and flags a regression. See
/// the anti-rollback phase 3 in ATREST_ANTIROLLBACK_DESIGN.md.
const TAG_CHECKPOINT: u8 = 0x03;
/// PUBLISH: recipient deposits a batch of signed One-Time Prekeys into its
/// own slot. FETCH: a sender pops one prekey for a named recipient. See the
/// PUBLISH/FETCH sections in the module docs and PQFS_DESIGN.md §4.1.
const TAG_PUBLISH: u8 = 0x04;
const TAG_FETCH: u8 = 0x05;
const REPLY_OK: u8 = 0x00;
/// FETCH reply: the connecting NodeId exceeded the per-identity FETCH rate
/// limit. Transient — distinct from depletion so the sender backs off
/// rather than treating the pool as exhausted.
const REPLY_RATE_LIMITED: u8 = 0xFC;
/// FETCH reply: the recipient has no prekeys left. The sender falls back to
/// a static-only encapsulation (default profile) or refuses (Strict).
const REPLY_PREKEY_NONE: u8 = 0xFD;
/// CHECKPOINT reply: the reported epoch is *older* than one the server has
/// already seen for this peer — the client's local at-rest state may have
/// been rolled back.
const REPLY_ROLLBACK: u8 = 0xFE;
const REPLY_FAIL: u8 = 0xFF;

/// Outcome of a [`checkpoint`] exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckpointStatus {
    /// The reported epoch was ≥ the server's record; the record is updated.
    Ok,
    /// The reported epoch is older than the server's record — a possible
    /// at-rest rollback. Advisory only: the inbox server is semi-trusted
    /// (it could equally lie), so callers should warn rather than hard-fail;
    /// the local TPM/software counter remains the authoritative check.
    RollbackSuspected,
}

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
    #[cfg(feature = "mls")]
    #[error("at-rest: {0}")]
    AtRest(String),
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

/// Report the local at-rest rollback `epoch` to the inbox `server` and ask
/// whether it has seen a newer one for us (identified by the QUIC
/// handshake NodeId). The server records `max(epoch, stored)` and replies
/// [`CheckpointStatus::RollbackSuspected`] if `epoch` is *older* than its
/// record — an online cross-device signal that the local storage was
/// reverted to an earlier snapshot (closing the software-counter residual
/// when online).
///
/// Advisory: the inbox server is semi-trusted, so a `RollbackSuspected`
/// result should be surfaced as a warning, not a hard failure.
pub async fn checkpoint(
    endpoint: &dyn P2pEndpoint,
    server: &PeerAddr,
    epoch: u64,
) -> Result<CheckpointStatus, InboxError> {
    let mut stream = endpoint.connect(server, P2pProtocol(ALPN_INBOX)).await?;
    let mut header = Vec::with_capacity(1 + 8);
    header.push(TAG_CHECKPOINT);
    header.extend_from_slice(&epoch.to_le_bytes());
    write_timed(&mut stream, &header, "checkpoint header").await?;
    tokio::time::timeout(IO_TIMEOUT, stream.flush())
        .await
        .map_err(|_| InboxError::Timeout("checkpoint flush"))??;
    let mut reply = [0u8; 1];
    read_timed(&mut stream, &mut reply, "checkpoint reply").await?;
    let _ = stream.shutdown().await;
    match reply[0] {
        REPLY_OK => Ok(CheckpointStatus::Ok),
        REPLY_ROLLBACK => Ok(CheckpointStatus::RollbackSuspected),
        other => Err(InboxError::Protocol(format!(
            "checkpoint: unexpected reply {other:#x}"
        ))),
    }
}

/// Outcome of a [`fetch_prekey`] call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FetchOutcome {
    /// A serialized prekey blob. The caller MUST parse it
    /// (`SignedPrekey::from_bytes`) and verify the signature against the
    /// recipient's ML-DSA identity before use — the inbox server is
    /// untrusted and could substitute a forged blob.
    Prekey(Vec<u8>),
    /// The recipient's prekey pool is empty. The sender encrypts with the
    /// static key only (default profile, no PQ-FS) or refuses (Strict).
    Depleted,
    /// This sender NodeId is being rate-limited; back off and retry later.
    /// Deliberately *not* folded into `Depleted` so a throttle is never
    /// mistaken for genuine exhaustion (which would wrongly trigger the
    /// static-key downgrade).
    RateLimited,
}

/// Publish a batch of signed One-Time Prekeys to our **own** slot on the
/// inbox `server`. The slot is keyed by our handshake-authenticated NodeId,
/// so this only ever writes to the caller's own prekey pool. Each entry is
/// an opaque `SignedPrekey::to_bytes()`; the server stores it verbatim.
pub async fn publish_prekeys(
    endpoint: &dyn P2pEndpoint,
    server: &PeerAddr,
    prekeys: &[Vec<u8>],
) -> Result<(), InboxError> {
    if prekeys.is_empty() || prekeys.len() > MAX_PUBLISH_BATCH as usize {
        return Err(InboxError::Protocol(format!(
            "publish batch of {} out of range (1..={MAX_PUBLISH_BATCH})",
            prekeys.len()
        )));
    }
    for p in prekeys {
        if p.is_empty() || p.len() > MAX_PREKEY_BLOB {
            return Err(InboxError::TooLarge(p.len()));
        }
    }
    let mut stream = endpoint.connect(server, P2pProtocol(ALPN_INBOX)).await?;
    let mut header = Vec::with_capacity(1 + 4);
    header.push(TAG_PUBLISH);
    header.extend_from_slice(&(prekeys.len() as u32).to_le_bytes());
    write_timed(&mut stream, &header, "publish header").await?;
    for p in prekeys {
        write_timed(&mut stream, &(p.len() as u32).to_le_bytes(), "publish blob len").await?;
        write_timed(&mut stream, p, "publish blob").await?;
    }
    tokio::time::timeout(IO_TIMEOUT, stream.flush())
        .await
        .map_err(|_| InboxError::Timeout("publish flush"))??;
    let mut reply = [0u8; 1];
    read_timed(&mut stream, &mut reply, "publish reply").await?;
    let _ = stream.shutdown().await;
    match reply[0] {
        REPLY_OK => Ok(()),
        _ => Err(InboxError::Rejected),
    }
}

/// Fetch a single One-Time Prekey for `recipient` from the inbox `server`,
/// to build a forward-secret one-shot ciphertext. Prekeys are one-time —
/// the server hands each out once. Returns [`FetchOutcome::Depleted`] if the
/// pool is empty or [`FetchOutcome::RateLimited`] if this NodeId is being
/// throttled; the caller decides the fallback per its profile.
pub async fn fetch_prekey(
    endpoint: &dyn P2pEndpoint,
    server: &PeerAddr,
    recipient: PeerId,
) -> Result<FetchOutcome, InboxError> {
    let mut stream = endpoint.connect(server, P2pProtocol(ALPN_INBOX)).await?;
    let mut header = Vec::with_capacity(1 + 32);
    header.push(TAG_FETCH);
    header.extend_from_slice(recipient.as_bytes());
    write_timed(&mut stream, &header, "fetch header").await?;
    tokio::time::timeout(IO_TIMEOUT, stream.flush())
        .await
        .map_err(|_| InboxError::Timeout("fetch flush"))??;
    let mut reply = [0u8; 1];
    read_timed(&mut stream, &mut reply, "fetch reply").await?;
    let outcome = match reply[0] {
        REPLY_OK => {
            let mut len_buf = [0u8; 4];
            read_timed(&mut stream, &mut len_buf, "fetch len").await?;
            let len = u32::from_le_bytes(len_buf) as usize;
            if len == 0 || len > MAX_PREKEY_BLOB {
                return Err(InboxError::TooLarge(len));
            }
            let mut blob = vec![0u8; len];
            read_timed(&mut stream, &mut blob, "fetch blob").await?;
            FetchOutcome::Prekey(blob)
        }
        REPLY_PREKEY_NONE => FetchOutcome::Depleted,
        REPLY_RATE_LIMITED => FetchOutcome::RateLimited,
        other => {
            return Err(InboxError::Protocol(format!(
                "fetch: unexpected reply {other:#x}"
            )))
        }
    };
    let _ = stream.shutdown().await;
    Ok(outcome)
}

// -----------------------------------------------------------------------------
// Server
// -----------------------------------------------------------------------------

#[cfg(feature = "mls")]
mod server {
    use super::*;
    use rusqlite::{params, Connection, OptionalExtension};
    use std::collections::HashMap;
    use std::path::Path;
    use std::sync::Mutex as StdMutex;
    use std::time::Instant;
    use tokio::sync::Mutex as AsyncMutex;
    use zeroize::Zeroizing;

    /// A leaky-bucket throttle for one connecting NodeId: `tokens` refills
    /// at [`FETCH_RL_REFILL_PER_SEC`] up to [`FETCH_RL_CAPACITY`], and each
    /// FETCH costs one token.
    struct TokenBucket {
        tokens: f64,
        last: Instant,
    }

    impl TokenBucket {
        fn new(now: Instant) -> Self {
            Self { tokens: FETCH_RL_CAPACITY, last: now }
        }

        /// Refill for elapsed time, then take a token if one is available.
        fn try_take(&mut self, now: Instant) -> bool {
            let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
            self.last = now;
            self.tokens =
                (self.tokens + elapsed * FETCH_RL_REFILL_PER_SEC).min(FETCH_RL_CAPACITY);
            if self.tokens >= 1.0 {
                self.tokens -= 1.0;
                true
            } else {
                false
            }
        }

        /// A bucket that has refilled to capacity is indistinguishable from a
        /// fresh one, so it can be pruned to reclaim memory.
        fn is_full(&self) -> bool {
            self.tokens >= FETCH_RL_CAPACITY
        }
    }

    /// Persistent inbox: sqlite-backed envelope storage + ALPN_INBOX
    /// accept loop.
    pub struct InboxServer {
        db: Arc<AsyncMutex<Connection>>,
        /// Per-NodeId FETCH rate limiters (prekey-depletion mitigation).
        /// A std mutex, not async: the critical section is a few map ops
        /// with no `.await`, so it never blocks the runtime meaningfully.
        fetch_rl: StdMutex<HashMap<PeerId, TokenBucket>>,
    }

    impl InboxServer {
        /// Open an inbox at `path`, creating the schema on first use.
        /// WAL + NORMAL synchronous so concurrent DEPOSIT/POLL don't
        /// block each other.
        ///
        /// The DB is SQLCipher-encrypted with a 256-bit DEK wrapped by the
        /// same PQC at-rest layer as the MLS storage (see `group::at_rest`
        /// and SECURITY_PROFILE.md §7.3). This matters even though every
        /// `payload` is already MLS ciphertext: the `recipient`, `sender`,
        /// and `created_at` columns are *metadata* that would otherwise sit
        /// in plaintext on the relay's disk. `passphrase` decrypts the
        /// hybrid key file; a legacy plaintext `inbox.db` is migrated in
        /// place on first open.
        pub fn open<P: AsRef<Path>>(
            path: P,
            passphrase: &Zeroizing<String>,
        ) -> Result<Self, InboxError> {
            // Recover (or initialise) the DEK via the at-rest layer, then
            // hand it to SQLCipher as the page key. `PRAGMA key` MUST run
            // before any other statement on the connection.
            //
            // `beside_db` keeps the inbox's hybrid key in `inbox.db.at-rest.key`
            // rather than the shared `at-rest.key`, so an MLS client and a
            // co-located inbox server in the same directory never race to
            // create one key file.
            let at_rest_paths = crate::group::AtRestPaths::beside_db(path.as_ref());
            let dek = crate::group::resolve_dek(&at_rest_paths, passphrase)
                .map_err(|e| InboxError::AtRest(e.to_string()))?;
            let conn = Connection::open(path.as_ref()).map_err(InboxError::Sqlite)?;
            let key_pragma =
                Zeroizing::new(format!("PRAGMA key = \"x'{}'\";", hex::encode(dek.as_ref())));
            conn.execute_batch(key_pragma.as_str())
                .map_err(InboxError::Sqlite)?;
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
                CREATE TABLE IF NOT EXISTS checkpoints (
                    peer   BLOB PRIMARY KEY,
                    epoch  INTEGER NOT NULL
                );
                -- One-Time Prekey pool. `blob` is an opaque
                -- SignedPrekey::to_bytes(); the server never parses it. Keyed
                -- by the recipient (= publisher's handshake NodeId); FETCH
                -- pops the lowest id (FIFO) for one-time use.
                CREATE TABLE IF NOT EXISTS prekeys (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    recipient   BLOB NOT NULL,
                    blob        BLOB NOT NULL,
                    created_at  INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS prekeys_recipient_id
                    ON prekeys(recipient, id);
                ",
            )
            .map_err(InboxError::Sqlite)?;

            // Defence in depth on top of SQLCipher: keep the ciphertext DB
            // unreadable by other local users.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = std::fs::metadata(path.as_ref()) {
                    let mut perms = meta.permissions();
                    perms.set_mode(0o600);
                    let _ = std::fs::set_permissions(path.as_ref(), perms);
                }
            }

            Ok(Self {
                db: Arc::new(AsyncMutex::new(conn)),
                fetch_rl: StdMutex::new(HashMap::new()),
            })
        }

        /// Charge one FETCH token against the connecting NodeId's bucket,
        /// returning `true` if the request is within the rate limit. Prunes
        /// idle (fully-refilled) buckets when the table grows past
        /// [`FETCH_RL_MAX_TRACKED`] so the map can't grow without bound under
        /// a stream of distinct NodeIds.
        fn allow_fetch(&self, who: PeerId) -> bool {
            let now = Instant::now();
            // Recover from a poisoned lock rather than propagating the panic:
            // a throttle table is not security-critical state, and the server
            // must keep serving other peers.
            let mut map = self
                .fetch_rl
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if map.len() >= FETCH_RL_MAX_TRACKED {
                map.retain(|_, b| !b.is_full());
            }
            map.entry(who)
                .or_insert_with(|| TokenBucket::new(now))
                .try_take(now)
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
                TAG_CHECKPOINT => self.handle_checkpoint(&mut *incoming.stream, sender).await,
                TAG_PUBLISH => self.handle_publish(&mut *incoming.stream, sender).await,
                TAG_FETCH => self.handle_fetch(&mut *incoming.stream, sender).await,
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

        async fn handle_checkpoint<S>(
            &self,
            stream: &mut S,
            peer: PeerId,
        ) -> Result<(), InboxError>
        where
            S: AsyncReadExt + AsyncWriteExt + Unpin + ?Sized,
        {
            let mut epoch_buf = [0u8; 8];
            read_timed(stream, &mut epoch_buf, "checkpoint epoch").await?;
            // Counters fit comfortably in i63; clamp defensively so a bogus
            // huge value can't wrap when stored as sqlite INTEGER.
            let epoch = u64::from_le_bytes(epoch_buf).min(i64::MAX as u64) as i64;
            // `peer` is the handshake-authenticated NodeId, so a client can
            // only checkpoint its own record (no peer field on the wire).
            let reply = {
                let db = self.db.lock().await;
                let stored: Option<i64> = db
                    .query_row(
                        "SELECT epoch FROM checkpoints WHERE peer = ?",
                        params![peer.as_bytes().as_slice()],
                        |r| r.get(0),
                    )
                    .optional()?;
                match stored {
                    Some(s) if epoch < s => REPLY_ROLLBACK, // regression: do not update
                    _ => {
                        let newv = stored.map_or(epoch, |s| s.max(epoch));
                        db.execute(
                            "INSERT INTO checkpoints(peer, epoch) VALUES(?1, ?2) \
                             ON CONFLICT(peer) DO UPDATE SET epoch = ?2",
                            params![peer.as_bytes().as_slice(), newv],
                        )?;
                        REPLY_OK
                    }
                }
            };
            write_timed(stream, &[reply], "checkpoint reply").await?;
            tokio::time::timeout(IO_TIMEOUT, stream.flush())
                .await
                .map_err(|_| InboxError::Timeout("checkpoint flush"))??;
            let _ = stream.shutdown().await;
            Ok(())
        }

        async fn handle_publish<S>(
            &self,
            stream: &mut S,
            recipient: PeerId,
        ) -> Result<(), InboxError>
        where
            S: AsyncReadExt + AsyncWriteExt + Unpin + ?Sized,
        {
            let mut count_buf = [0u8; 4];
            read_timed(stream, &mut count_buf, "publish count").await?;
            let count = u32::from_le_bytes(count_buf);
            if count == 0 || count > MAX_PUBLISH_BATCH {
                let _ = write_timed(stream, &[REPLY_FAIL], "publish reply (fail)").await;
                return Err(InboxError::Protocol(format!(
                    "publish count {count} out of range (1..={MAX_PUBLISH_BATCH})"
                )));
            }
            // Read the whole (bounded) batch before touching the DB so a
            // slow/short writer can't hold the db mutex across reads.
            let mut blobs: Vec<Vec<u8>> = Vec::with_capacity(count as usize);
            for _ in 0..count {
                let mut len_buf = [0u8; 4];
                read_timed(stream, &mut len_buf, "publish blob len").await?;
                let len = u32::from_le_bytes(len_buf) as usize;
                if len == 0 || len > MAX_PREKEY_BLOB {
                    let _ = write_timed(stream, &[REPLY_FAIL], "publish reply (fail)").await;
                    return Err(InboxError::TooLarge(len));
                }
                let mut blob = vec![0u8; len];
                read_timed(stream, &mut blob, "publish blob").await?;
                blobs.push(blob);
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            // The slot is keyed by `recipient` = the handshake-authenticated
            // NodeId, so a peer can only ever publish into its own pool.
            {
                let db = self.db.lock().await;
                let tx = db.unchecked_transaction()?;
                for blob in &blobs {
                    tx.execute(
                        "INSERT INTO prekeys(recipient, blob, created_at) VALUES(?, ?, ?)",
                        params![recipient.as_bytes().as_slice(), blob, now],
                    )?;
                }
                // Bound storage abuse: keep only the newest MAX_PREKEYS_STORED
                // for this recipient, dropping the oldest by id.
                tx.execute(
                    "DELETE FROM prekeys WHERE recipient = ?1 AND id NOT IN (
                         SELECT id FROM prekeys WHERE recipient = ?1
                         ORDER BY id DESC LIMIT ?2
                     )",
                    params![recipient.as_bytes().as_slice(), MAX_PREKEYS_STORED as i64],
                )?;
                tx.commit()?;
            }
            write_timed(stream, &[REPLY_OK], "publish reply (ok)").await?;
            tokio::time::timeout(IO_TIMEOUT, stream.flush())
                .await
                .map_err(|_| InboxError::Timeout("publish flush"))??;
            let _ = stream.shutdown().await;
            Ok(())
        }

        async fn handle_fetch<S>(
            &self,
            stream: &mut S,
            fetcher: PeerId,
        ) -> Result<(), InboxError>
        where
            S: AsyncReadExt + AsyncWriteExt + Unpin + ?Sized,
        {
            // Read the recipient field first so the wire framing stays
            // consistent even when we go on to reject the request.
            let mut recip_buf = [0u8; 32];
            read_timed(stream, &mut recip_buf, "fetch recipient").await?;
            let recipient = PeerId::new(recip_buf);

            // Rate-limit by the connecting (sender) NodeId — the documented
            // mitigation for the prekey-depletion downgrade (PQFS_DESIGN.md
            // §4.1). Done before the DB pop so a throttled caller can't drain.
            if !self.allow_fetch(fetcher) {
                write_timed(stream, &[REPLY_RATE_LIMITED], "fetch reply (rate limited)").await?;
                tokio::time::timeout(IO_TIMEOUT, stream.flush())
                    .await
                    .map_err(|_| InboxError::Timeout("fetch flush"))??;
                let _ = stream.shutdown().await;
                return Ok(());
            }

            // Pop the lowest-id prekey atomically: SELECT then DELETE under the
            // single db mutex, so two concurrent FETCHes can never be handed
            // the same one-time key.
            let blob: Option<Vec<u8>> = {
                let db = self.db.lock().await;
                let row: Option<(i64, Vec<u8>)> = db
                    .query_row(
                        "SELECT id, blob FROM prekeys WHERE recipient = ? \
                         ORDER BY id ASC LIMIT 1",
                        params![recipient.as_bytes().as_slice()],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional()?;
                match row {
                    Some((id, blob)) => {
                        db.execute("DELETE FROM prekeys WHERE id = ?", params![id])?;
                        Some(blob)
                    }
                    None => None,
                }
            };

            match blob {
                Some(b) => {
                    write_timed(stream, &[REPLY_OK], "fetch reply (ok)").await?;
                    write_timed(stream, &(b.len() as u32).to_le_bytes(), "fetch len").await?;
                    write_timed(stream, &b, "fetch blob").await?;
                }
                None => {
                    write_timed(stream, &[REPLY_PREKEY_NONE], "fetch reply (none)").await?;
                }
            }
            tokio::time::timeout(IO_TIMEOUT, stream.flush())
                .await
                .map_err(|_| InboxError::Timeout("fetch flush"))??;
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

    fn test_passphrase() -> zeroize::Zeroizing<String> {
        zeroize::Zeroizing::new("nkct-inbox-test-passphrase".to_string())
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
        let server = Arc::new(
            InboxServer::open(dir.path().join("inbox.db"), &test_passphrase()).expect("open"),
        );
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
        let server = Arc::new(
            InboxServer::open(dir.path().join("inbox.db"), &test_passphrase()).expect("open"),
        );
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

    /// The inbox DB is SQLCipher-encrypted under a per-DB at-rest key, and
    /// the wrong passphrase cannot reopen it.
    #[test]
    fn inbox_db_is_encrypted_at_rest() {
        let dir = tempdir().expect("tempdir");
        let db = dir.path().join("inbox.db");
        drop(InboxServer::open(&db, &test_passphrase()).expect("open"));

        // Per-DB at-rest triple lives beside inbox.db (not a shared
        // `at-rest.key`), so a co-located groups.db can't race it.
        assert!(dir.path().join("inbox.db.at-rest.key").exists());
        assert!(dir.path().join("inbox.db.kek").exists());
        assert!(!dir.path().join("at-rest.key").exists());

        // The DB file is not a plaintext sqlite: its 16-byte header is the
        // SQLCipher salt, not the `SQLite format 3\0` magic.
        let mut hdr = [0u8; 16];
        {
            use std::io::Read as _;
            std::fs::File::open(&db)
                .expect("open db file")
                .read_exact(&mut hdr)
                .expect("read header");
        }
        assert_ne!(&hdr, b"SQLite format 3\0", "inbox.db must be encrypted");

        // Reopening with the same passphrase works; a wrong one fails.
        drop(InboxServer::open(&db, &test_passphrase()).expect("reopen"));
        match InboxServer::open(&db, &zeroize::Zeroizing::new("wrong".to_string())) {
            Ok(_) => panic!("wrong passphrase must fail"),
            Err(e) => assert!(matches!(e, InboxError::AtRest(_)), "unexpected error: {e}"),
        }
    }

    #[tokio::test]
    async fn checkpoint_tracks_max_and_flags_regression() {
        let net = MockNetwork::new();
        let client =
            Arc::new(net.register(pid(7), vec![P2pProtocol(ALPN_INBOX)])) as Arc<dyn P2pEndpoint>;
        let other =
            Arc::new(net.register(pid(8), vec![P2pProtocol(ALPN_INBOX)])) as Arc<dyn P2pEndpoint>;
        let server_ep =
            Arc::new(net.register(pid(99), vec![P2pProtocol(ALPN_INBOX)])) as Arc<dyn P2pEndpoint>;
        let dir = tempdir().expect("tempdir");
        let server = Arc::new(
            InboxServer::open(dir.path().join("inbox.db"), &test_passphrase()).expect("open"),
        );
        let task = {
            let s = Arc::clone(&server);
            let ep = Arc::clone(&server_ep);
            tokio::spawn(async move {
                let _ = s.run(ep).await;
            })
        };
        let srv = PeerAddr::new(pid(99));

        // Monotonic non-decreasing reports are accepted.
        assert_eq!(checkpoint(client.as_ref(), &srv, 5).await.unwrap(), CheckpointStatus::Ok);
        assert_eq!(checkpoint(client.as_ref(), &srv, 5).await.unwrap(), CheckpointStatus::Ok);
        assert_eq!(checkpoint(client.as_ref(), &srv, 9).await.unwrap(), CheckpointStatus::Ok);

        // A lower epoch than the server's record => rollback suspected, and
        // the record is NOT lowered.
        assert_eq!(
            checkpoint(client.as_ref(), &srv, 3).await.unwrap(),
            CheckpointStatus::RollbackSuspected
        );
        assert_eq!(checkpoint(client.as_ref(), &srv, 9).await.unwrap(), CheckpointStatus::Ok);
        assert_eq!(
            checkpoint(client.as_ref(), &srv, 8).await.unwrap(),
            CheckpointStatus::RollbackSuspected
        );

        // Records are per-peer: a different NodeId starts fresh.
        assert_eq!(checkpoint(other.as_ref(), &srv, 1).await.unwrap(), CheckpointStatus::Ok);

        task.abort();
    }

    /// Spin up an inbox server on a fresh MockNetwork and return the network,
    /// server handle, accept-loop task, and its address. Shared by the
    /// prekey tests below.
    async fn spawn_server() -> (
        Arc<MockNetwork>,
        Arc<InboxServer>,
        tokio::task::JoinHandle<()>,
        PeerAddr,
        tempfile::TempDir,
    ) {
        let net = MockNetwork::new();
        let server_ep =
            Arc::new(net.register(pid(99), vec![P2pProtocol(ALPN_INBOX)])) as Arc<dyn P2pEndpoint>;
        let dir = tempdir().expect("tempdir");
        let server = Arc::new(
            InboxServer::open(dir.path().join("inbox.db"), &test_passphrase()).expect("open"),
        );
        let task = {
            let s = Arc::clone(&server);
            let ep = Arc::clone(&server_ep);
            tokio::spawn(async move {
                let _ = s.run(ep).await;
            })
        };
        (net, server, task, PeerAddr::new(pid(99)), dir)
    }

    /// bob publishes prekeys into his own slot; alice fetches them in FIFO
    /// order, one-time (each served once), and gets Depleted once drained.
    #[tokio::test]
    async fn publish_then_fetch_is_fifo_one_time() {
        let (net, _server, task, srv, _dir) = spawn_server().await;
        let bob =
            Arc::new(net.register(pid(2), vec![P2pProtocol(ALPN_INBOX)])) as Arc<dyn P2pEndpoint>;
        let alice =
            Arc::new(net.register(pid(1), vec![P2pProtocol(ALPN_INBOX)])) as Arc<dyn P2pEndpoint>;

        let batch = vec![b"prekey-A".to_vec(), b"prekey-B".to_vec()];
        publish_prekeys(bob.as_ref(), &srv, &batch).await.expect("publish");

        // FIFO: A then B.
        assert_eq!(
            fetch_prekey(alice.as_ref(), &srv, pid(2)).await.unwrap(),
            FetchOutcome::Prekey(b"prekey-A".to_vec())
        );
        assert_eq!(
            fetch_prekey(alice.as_ref(), &srv, pid(2)).await.unwrap(),
            FetchOutcome::Prekey(b"prekey-B".to_vec())
        );
        // One-time: the pool is now empty.
        assert_eq!(
            fetch_prekey(alice.as_ref(), &srv, pid(2)).await.unwrap(),
            FetchOutcome::Depleted
        );

        task.abort();
    }

    /// Prekey pools are isolated by recipient slot, which is the publisher's
    /// handshake NodeId — bob cannot publish into carol's slot.
    #[tokio::test]
    async fn prekey_pools_are_isolated_by_recipient() {
        let (net, _server, task, srv, _dir) = spawn_server().await;
        let bob =
            Arc::new(net.register(pid(2), vec![P2pProtocol(ALPN_INBOX)])) as Arc<dyn P2pEndpoint>;
        let alice =
            Arc::new(net.register(pid(1), vec![P2pProtocol(ALPN_INBOX)])) as Arc<dyn P2pEndpoint>;

        publish_prekeys(bob.as_ref(), &srv, &[b"bob-pk".to_vec()])
            .await
            .expect("publish");

        // Fetching for bob (pid 2) yields bob's prekey...
        assert_eq!(
            fetch_prekey(alice.as_ref(), &srv, pid(2)).await.unwrap(),
            FetchOutcome::Prekey(b"bob-pk".to_vec())
        );
        // ...but carol (pid 3) published nothing, so her slot is empty even
        // though bob deposited to the same server.
        assert_eq!(
            fetch_prekey(alice.as_ref(), &srv, pid(3)).await.unwrap(),
            FetchOutcome::Depleted
        );

        task.abort();
    }

    /// A single sender NodeId fetching in a tight burst is throttled once it
    /// exhausts its token bucket — and the throttle is reported as
    /// RateLimited, distinct from genuine Depletion (the pool still has keys).
    #[tokio::test]
    async fn fetch_is_rate_limited_per_sender() {
        let (net, _server, task, srv, _dir) = spawn_server().await;
        let bob =
            Arc::new(net.register(pid(2), vec![P2pProtocol(ALPN_INBOX)])) as Arc<dyn P2pEndpoint>;
        let alice =
            Arc::new(net.register(pid(1), vec![P2pProtocol(ALPN_INBOX)])) as Arc<dyn P2pEndpoint>;

        // Publish more prekeys than the burst capacity so we hit the rate
        // limit before the pool runs dry — proving the two are distinct.
        let cap = FETCH_RL_CAPACITY as usize;
        let batch: Vec<Vec<u8>> = (0..cap + 4).map(|i| format!("pk-{i}").into_bytes()).collect();
        publish_prekeys(bob.as_ref(), &srv, &batch).await.expect("publish");

        // The first `cap` fetches succeed (burst); negligible time passes so
        // the bucket barely refills.
        for _ in 0..cap {
            assert!(matches!(
                fetch_prekey(alice.as_ref(), &srv, pid(2)).await.unwrap(),
                FetchOutcome::Prekey(_)
            ));
        }
        // The next fetch is throttled — NOT depleted (keys remain).
        assert_eq!(
            fetch_prekey(alice.as_ref(), &srv, pid(2)).await.unwrap(),
            FetchOutcome::RateLimited
        );

        task.abort();
    }
}
