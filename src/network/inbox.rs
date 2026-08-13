//! `nkct/inbox/1` — store-and-forward delivery for opaque payloads.
//!
//! Designed as an untrusted Delivery Service in the sense of RFC 9420 §3:
//! the server stores envelopes keyed by recipient PeerId and returns
//! them on demand to the matching peer, and this implementation never
//! reads, decrypts, or interprets the payload bytes.
//!
//! That is a property of *this code*, not a guarantee about the operator,
//! who holds the bytes and can read anything in them that is not
//! encrypted. Whether store-and-forward costs the end-to-end guarantees
//! is therefore decided by what the depositor hands over, not here — and
//! for the MLS layer in [`crate::group`] today, **it does cost them**.
//! Application messages (`PrivateMessage`), `Welcome`s (GroupSecrets
//! HPKE-encrypted to the joiner) and KeyPackages (publishable by
//! construction) are all opaque to this server. Commits and Proposals are
//! not: mls-rs's default MlsRules emit them as `PublicMessage`, signed but
//! unencrypted, and
//! [`crate::group::transport::send_one_with_inbox`] deposits them like
//! anything else — so an operator that keeps what it stores can
//! reconstruct the group's membership graph and every member's transport
//! identity. Unmitigated today; the fix is the `encrypt_control_messages`
//! wire-format flag day. See `KNOWN_ISSUES.md` "Security Audit Residuals"
//! item 11.
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
//! stored row for abuse tracing but is NOT exposed to the recipient.
//!
//! Because `recipient` is an unauthenticated wire field, a deposit that
//! does not fit is **refused** (`0xFF`) rather than made to fit: the
//! store never removes an existing envelope to admit a new one, so no
//! peer can flush a queue it does not own by depositing into it. The
//! quotas are a per-recipient row cap
//! ([`MAX_ENVELOPES_PER_RECIPIENT`]), a per-*depositor* byte budget
//! keyed on the handshake-authenticated sender, and the store's global
//! byte budget; space comes back by expiry, not eviction. See
//! [`crate::group::redb_storage::RedbInboxStore::deposit`].
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
//! A reply is bounded by **bytes as well as rows**
//! ([`crate::group::redb_storage::MAX_POLL_BYTES`]), so a batch may be short
//! while envelopes are still waiting: `max` counts rows, and 64 rows of
//! [`MAX_PAYLOAD`] would be ~1 GiB of relay memory bought with one 13-byte
//! request. **The signal that a slot is drained is therefore `count == 0`, not
//! `count < MAX_POLL_BATCH`.** A client that stops on the latter stops early
//! rather than losing mail — nothing is deleted by POLL and the cursor it
//! keeps is the last row it actually received, so its next poll picks up
//! exactly where it left off. Both in-tree clients already work that way: they
//! re-poll from the returned cursor (on a timer, or on the next `recv`).
//! At least one envelope is always returned when any is waiting, so a poll
//! that returns nothing really does mean nothing is waiting.
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
//! PUBLISH is also where the reserve below gets its anchor: the pool level this
//! call leaves in the slot is recorded as the recipient's *stocking level*, in
//! the same transaction, and the FETCH reserve floor is computed from it. It is
//! **replaced**, not raised, on every PUBLISH — a recipient that chooses to
//! stock fewer prekeys must be able to say so, or a stale high mark would gate
//! every draw against a pool it no longer keeps.
//!
//! A pool stocked before that record existed carries none, so the *draw* path
//! anchors it instead, at the level standing before its own pop. That is the
//! only circumstance in which anything but a PUBLISH writes the level, it
//! happens once per pool, and it can only *create* a level, never move one — so
//! a fetcher still cannot talk a floor down. See `RESERVE_MAX_TRACKED`.
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
//! no-FS static-key fallback. The first mitigation is a **token-bucket rate
//! limit keyed by the connecting (sender) NodeId** ([`FETCH_RL_CAPACITY`] /
//! [`FETCH_RL_REFILL_PER_SEC`]). It raises the per-identity cost of
//! draining; it is not a complete defence (NodeIds are cheap to mint), so
//! the Strict profile's "refuse on depletion" policy remains the backstop.
//! Because that key is free to mint, the table holding the buckets is itself
//! hard-bounded (`FETCH_RL_MAX_TRACKED`): idle buckets are pruned, and a
//! caller arriving when there is no room is served *untracked* rather than
//! refused. Failing open there gives away nothing — the flood that fills the
//! table is made of fresh NodeIds, which this bucket never restrained anyway —
//! while refusing would throttle the honest sender, whose idle bucket is the
//! one that gets pruned. The aggregate bound is the per-recipient reserve
//! described next.
//! `depleted` and `rate limited` are distinct replies so the sender can
//! tell genuine exhaustion (→ fallback / refuse) from a transient throttle
//! (→ back off and retry).
//!
//! Because that bucket is keyed on a free-to-mint identity it bounds nothing
//! in aggregate, so a FETCH is additionally gated by a **per-recipient
//! reserve**. Each PUBLISH records the pool level it leaves in the slot as that
//! recipient's *stocking level*, persisted in the store beside the pool itself
//! and keyed on the same blind index. **No fetcher can move that level**: only
//! the recipient can set it, since PUBLISH is keyed on the authenticated
//! connection and no wire field names another identity's slot, and the one
//! write the draw path makes — anchoring a pool that has no level yet, at the
//! level standing before its own pop — cannot change one that is already
//! there. The server
//! treats the lowest `1/PREKEY_RESERVE_DIVISOR` of that level as a reserve
//! band. **Above the band a draw
//! is not gated at all**: a healthy pool is served to however many identities
//! ask, so honest senders never meet the gate. A draw *at or below* the band
//! also costs a token from a bucket keyed by the **recipient**
//! ([`RESERVE_RL_CAPACITY`] / [`RESERVE_RL_REFILL_PER_SEC`]), so the
//! below-floor drain rate is bounded no matter how many NodeIds an attacker
//! mints. This bounds the rate and keeps real prekeys reachable while an
//! attack runs, and it disengages the moment the recipient replenishes; it
//! does **not** prevent the downgrade — a sustained attacker still ends in a
//! `MODE_STATIC_ONLY` seal under the default profile, and refusing that
//! remains the Strict profile's job.
//!
//! ### COUNT (own prekey pool size)
//!
//! ```text
//! request:  u8(0x06)
//! reply:    u8(0x00) || count(u32)
//! ```
//!
//! The recipient asks how many of its prekeys remain, to drive
//! auto-replenishment ([`crate::one_shot::replenish_to_target`]). Like
//! PUBLISH/POLL it is keyed by the handshake NodeId and carries **no
//! recipient field**, so it can only report the *caller's own* slot — it
//! cannot probe a victim's pool size. The count is a semi-trusted
//! *availability* hint: a hostile server can lie, but it can already drain
//! the pool outright, so this grants it no new power. The downgrade defence
//! stays sender-side (FETCH rate limit + Strict profile); COUNT only keeps
//! the honest-server case topped up.

use crate::network::ALPN_INBOX;
use crate::p2p::{
    P2pEndpoint, P2pError, P2pIncoming, P2pProtocol, PeerAddr, PeerId, P2P_SETUP_TIMEOUT,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Largest payload accepted by either DEPOSIT or POLL. Matches the MLS
/// transport's frame cap so any MLS frame fits.
pub const MAX_PAYLOAD: usize = 16 * 1024 * 1024;

/// Server-imposed upper bound on envelopes returned per POLL. It is a *row*
/// cap only: the reply is separately bounded by
/// [`crate::group::redb_storage::MAX_POLL_BYTES`], so a batch can be shorter
/// than this while more envelopes wait. Clients repeat polls, following the
/// returned cursor, until a poll returns **nothing**.
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

/// Per-recipient cap on stored inbox envelopes. DEPOSIT is unauthenticated
/// ("anyone can deposit to anyone"), so this — together with the store's global
/// and per-depositor byte budgets — bounds a disk-exhaustion flood.
///
/// A deposit into a slot already holding this many envelopes is **refused**;
/// the store evicts nothing. Making room by deleting would let any peer that
/// can name a recipient on the wire flush that recipient's undelivered mail,
/// and POLL's `id > since_cursor` semantics mean the loss would be silent.
/// The cost of refusing instead is that an occupied slot stays occupied until
/// its backlog expires — see the residual recorded in `KNOWN_ISSUES.md`.
pub const MAX_ENVELOPES_PER_RECIPIENT: u64 = 256;

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

/// Hard cap on distinct NodeIds tracked for FETCH rate limiting. When the
/// table reaches this, fully-refilled (idle) buckets are pruned, bounding
/// memory without losing any throttle state for active senders. Pruning is
/// best-effort, so the cap is also enforced on admission: a caller that
/// arrives when the table is full of *active* buckets is served **without
/// being tracked**, exactly as [`RESERVE_MAX_TRACKED`] does for the reserve
/// table. The table therefore cannot grow past this under any flood.
///
/// Failing open costs nothing here, because this bucket is keyed on the
/// connecting NodeId and a NodeId is free to mint. The caller who can fill
/// the table is precisely the caller a per-identity throttle never restrained
/// — a fresh NodeId per request draws a fresh full bucket, cap or no cap — so
/// there is no adversary that refusing untracked callers would hold back.
/// Refusing would only reach honest senders: one FETCH per message leaves a
/// bucket idle, and idle means pruned within
/// `FETCH_RL_CAPACITY / FETCH_RL_REFILL_PER_SEC`, so an honest sender is
/// routinely the one *without* an entry. It would also be a downgrade lever
/// rather than a throttle: [`REPLY_RATE_LIMITED`] is not a retry signal to the
/// in-tree client — [`crate::one_shot`] handles it in the same arm as
/// depletion, sealing STATIC-ONLY (no PQ forward secrecy) under the default
/// profile and refusing to send under Strict. What bounds prekey drain in
/// aggregate is the per-recipient reserve in `InboxServer::draw_prekey`,
/// keyed on a recipient rather than on anything an attacker can mint.
const FETCH_RL_MAX_TRACKED: usize = 4096;

/// Shortest interval between two prunes of the FETCH table. The prune is O(n)
/// over the table, so paying it on every request once the table sits at
/// [`FETCH_RL_MAX_TRACKED`] would make the FETCH path quadratic in the number
/// of requests served — work an attacker buys cheaply, since FETCH is
/// unauthenticated. Amortizing it bounds that to one pass per second whatever
/// the request rate, and idle buckets are worth reclaiming no more often than
/// that: a bucket needs minutes to refill at [`FETCH_RL_REFILL_PER_SEC`].
const FETCH_RL_PRUNE_INTERVAL: Duration = Duration::from_secs(1);

/// Fraction of a recipient's recorded stocking level held in reserve: the
/// lowest `1/PREKEY_RESERVE_DIVISOR` of the pool is the rate-limited band,
/// everything above it is drawn freely. A quarter leaves an honest,
/// default-stocked recipient (`--prekey-count 100`) 75 ungated draws — far
/// more than ordinary use consumes between two `maintain` runs — while still
/// reserving a quarter of the pool for delivery at a bounded rate once the
/// pool has genuinely been drawn down. Integer division, so a pool smaller
/// than the divisor has a floor of 0 and is never gated: there is nothing
/// meaningful to reserve out of three keys. Tunable policy, like the
/// `FETCH_RL_*` pair, but never below 2: the floor must stay *under* the level
/// it is compared against, or a pool would be gated the first time it is drawn
/// from.
pub const PREKEY_RESERVE_DIVISOR: u64 = 4;

/// Reserve-band burst capacity, per **recipient**: this many draws may be
/// taken back-to-back from a pool that is already inside its reserve band
/// before the refill rate gates them — by any mix of senders, since the
/// bucket is keyed on the recipient, not the caller.
pub const RESERVE_RL_CAPACITY: f64 = 8.0;

/// Reserve-band refill rate (tokens/second), per **recipient**. Deliberately
/// the same shape as [`FETCH_RL_CAPACITY`] / [`FETCH_RL_REFILL_PER_SEC`]: once
/// a pool is inside its reserve band, *everyone together* may draw it down no
/// faster than a single well-behaved sender was already allowed to — which is
/// the bound minting NodeIds cannot buy its way out of.
pub const RESERVE_RL_REFILL_PER_SEC: f64 = 1.0 / 30.0;

/// Soft cap on recipients tracked for the prekey reserve. When the table
/// reaches it, refilled (idle) buckets are pruned, exactly as for the
/// per-NodeId table: a recipient under active below-floor draw has the
/// emptiest bucket and survives. If nothing is prunable — this many
/// *distinct* pools being drawn below their floors at once, each at the
/// sustained below-floor cost above — a not-yet-seen recipient goes
/// untracked, and so ungated, until room appears.
///
/// **This table no longer holds anything a prune can destroy.** It used to
/// carry each recipient's stocking mark, and that made the prune an attack:
/// the mark is only charged against a bucket by a draw at or *below* the floor
/// ([`TokenBucket::new`] starts a bucket full, and the `||` in `draw_prekey`
/// short-circuits above the floor), so an attacker that walked a pool down to
/// exactly its floor and stopped left the victim's entry full and prunable at
/// once — and the next draw re-derived the mark from the drawn-down level,
/// collapsing the floor in stages until the pool was empty. Firing the prune
/// needs this many tracked recipients, which an attacker can mint itself
/// (PUBLISH keys on the connecting NodeId and does not parse the blob), so the
/// whole sequence was repeatable on demand.
///
/// The stocking level now comes from the store
/// (`RedbInboxStore::prekey_level_and_mark`), so a prune cannot reach it —
/// written there by the recipient's own PUBLISH, and anchored there on the
/// first draw for a pool that predates the record. **Both halves are needed.**
/// Anchoring only at PUBLISH would have left every pool in an upgraded
/// deployment on a memory-held fallback, i.e. left the attack above standing
/// in full until each owner happened to republish.
///
/// What is left in the table is the token bucket, and pruning one buys an
/// attacker exactly nothing: the prune's test is [`TokenBucket::is_full_at`],
/// and a bucket that is full holds the same eight tokens the fresh bucket
/// replacing it would. A bucket with tokens spent is not full, so it cannot be
/// pruned before the refill it is enforcing has already elapsed.
///
/// One residual stands, recorded in `KNOWN_ISSUES.md` item 3: an attacker
/// holding this many *distinct* pools below their floors at once keeps the
/// table full, and a recipient first drawn from while it is full goes untracked
/// — hence ungated — until room appears. Its floor is known; there is simply no
/// room for the bucket that would charge it, and the admission rule fails open
/// deliberately (see [`FETCH_RL_MAX_TRACKED`]).
const RESERVE_MAX_TRACKED: usize = 4096;

/// Upper bound on connections whose per-connection setup + handling run
/// concurrently. A permit is reserved BEFORE the per-connection task is spawned,
/// so a flood of half-open peers cannot spawn unbounded setup tasks each holding
/// a connection (and its [`P2P_SETUP_TIMEOUT`] window) open. Generous enough not
/// to serialize honest clients (DEPOSIT / POLL are brief); bounded enough to cap
/// concurrent resource use under an accept flood.
const MAX_CONCURRENT_CONNECTIONS: usize = 256;

/// Shortest interval between two accept-failure lines on the operator's
/// stderr. A failed accept is remotely triggerable, so logging each one would
/// hand any peer an unbounded write to the operator's log; logging only the
/// first would instead leave a permanently broken socket (fd exhaustion, a
/// dead endpoint) silent forever, now that such a failure no longer ends
/// `run()`. One line per interval, carrying the number suppressed since the
/// previous line, keeps both bounded and still visible.
const ACCEPT_ERROR_LOG_INTERVAL: Duration = Duration::from_secs(60);

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
/// COUNT: the recipient asks how many of its own prekeys remain on the
/// server, to drive auto-replenishment. Authenticated by the handshake
/// NodeId (= the caller's own slot) exactly like POLL/PUBLISH, so it can
/// only ever read the caller's own pool — no field on the wire names a
/// recipient, so it cannot probe a victim's pool size. The count is a
/// semi-trusted hint (a malicious server can lie, but it can already drain
/// the pool outright); the real downgrade defense stays sender-side
/// (FETCH rate limit + Strict profile). See PQFS_DESIGN.md §4.1.
const TAG_COUNT: u8 = 0x06;
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
    #[error("storage: {0}")]
    Storage(String),
    #[cfg(feature = "mls")]
    #[error("at-rest: {0}")]
    AtRest(String),
}

#[cfg(feature = "mls")]
impl From<crate::group::redb_storage::RedbStorageError> for InboxError {
    fn from(e: crate::group::redb_storage::RedbStorageError) -> Self {
        InboxError::Storage(e.to_string())
    }
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

/// Graceful-close barrier for the server side: after sending a full response,
/// wait for the peer to finish its send stream (EOF) before letting the
/// connection drop. Every client reads our response *in full* and only then
/// calls `shutdown()` on its own send half, so observing that EOF proves the
/// response was delivered. Without this barrier the handler returns, drops the
/// last reference to the QUIC connection, and quinn emits an immediate
/// CONNECTION_CLOSE(0) that races the still-in-flight response — the client
/// then sees "connection lost: closed by peer: 0" instead of its reply.
/// Best-effort and bounded: any read error (peer reset) or the timeout just
/// ends the wait.
async fn await_peer_close<S>(stream: &mut S)
where
    S: AsyncReadExt + Unpin + ?Sized,
{
    let _ = tokio::time::timeout(IO_TIMEOUT, async {
        let mut scratch = [0u8; 64];
        loop {
            match stream.read(&mut scratch).await {
                Ok(0) => break,    // clean EOF: peer finished after reading us
                Ok(_) => continue, // unexpected trailing bytes — ignore and keep draining
                Err(_) => break,   // reset/closed — nothing left to wait for
            }
        }
    })
    .await;
}

// -----------------------------------------------------------------------------
// Client API
// -----------------------------------------------------------------------------

/// Deposit `payload` for `recipient` at the inbox `server`. The server
/// returns ok / rejected; sender doesn't get a delivery confirmation
/// beyond "the bytes are stored". The recipient surfaces them on its
/// next POLL.
///
/// [`InboxError::Rejected`] covers a *refused* deposit as well as a malformed
/// one: the server turns a deposit away when the recipient's slot is full or a
/// byte budget is spent, rather than deleting a stored envelope to make room.
/// Nothing was written, so the caller may retry once the recipient's backlog
/// expires (`ENVELOPE_TTL_SECS`, 7 days) — the retry reclaims that recipient's
/// expired rows itself before it counts the slot, so it does not depend on
/// anything else having run first. POLL does not delete what it returns, so the
/// recipient draining the slot does not free room sooner. A deposit refused on
/// the *store's* byte budget is the one case where waiting out the TTL may not
/// be enough: that budget comes back only as the table-wide sweep walks (see
/// `KNOWN_ISSUES.md` item 10).
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
/// envelope **in this batch**. The caller decides how to dispatch each
/// payload — for the MLS use case, feed each into
/// [`crate::group::transport::recv_mls_message`] — equivalent framing.
///
/// One call is one batch, bounded by rows *and* by bytes (see the POLL
/// section of the module docs), so a non-empty result never means "that
/// was everything". Keep polling from the returned cursor until a poll
/// returns no envelopes; nothing is dropped in between, because POLL does
/// not delete and the cursor only advances past rows actually delivered.
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

/// Ask the inbox `server` how many of **our own** unused prekeys it still
/// holds, for auto-replenishment. Authenticated by our handshake NodeId, so
/// it reads only our slot. The result is a semi-trusted availability hint —
/// see [`TAG_COUNT`] — not a security boundary.
pub async fn count_prekeys(
    endpoint: &dyn P2pEndpoint,
    server: &PeerAddr,
) -> Result<u32, InboxError> {
    let mut stream = endpoint.connect(server, P2pProtocol(ALPN_INBOX)).await?;
    write_timed(&mut stream, &[TAG_COUNT], "count tag").await?;
    tokio::time::timeout(IO_TIMEOUT, stream.flush())
        .await
        .map_err(|_| InboxError::Timeout("count flush"))??;
    let mut reply = [0u8; 1];
    read_timed(&mut stream, &mut reply, "count reply").await?;
    if reply[0] != REPLY_OK {
        let _ = stream.shutdown().await;
        return Err(InboxError::Protocol(format!(
            "count: unexpected reply {:#x}",
            reply[0]
        )));
    }
    let mut count_buf = [0u8; 4];
    read_timed(&mut stream, &mut count_buf, "count value").await?;
    let _ = stream.shutdown().await;
    Ok(u32::from_le_bytes(count_buf))
}

// -----------------------------------------------------------------------------
// Server
// -----------------------------------------------------------------------------

#[cfg(feature = "mls")]
mod server {
    use super::*;
    use crate::group::redb_storage::{CheckpointOutcome, RedbInboxStore, RedbStorageError};
    use std::collections::HashMap;
    use std::path::Path;
    use std::sync::Mutex as StdMutex;
    use std::time::Instant;
    use zeroize::Zeroizing;

    /// A leaky-bucket throttle: `tokens` refills at `refill_per_sec` up to
    /// `capacity`, and each charged operation costs one token. Used twice with
    /// different keys and rates — once per connecting NodeId
    /// ([`FETCH_RL_CAPACITY`] / [`FETCH_RL_REFILL_PER_SEC`], keyed on the
    /// caller) and once per recipient ([`RESERVE_RL_CAPACITY`] /
    /// [`RESERVE_RL_REFILL_PER_SEC`], keyed on whose pool is being drawn).
    struct TokenBucket {
        tokens: f64,
        last: Instant,
        capacity: f64,
        refill_per_sec: f64,
    }

    impl TokenBucket {
        fn new(capacity: f64, refill_per_sec: f64, now: Instant) -> Self {
            Self { tokens: capacity, last: now, capacity, refill_per_sec }
        }

        /// Tokens this bucket would hold at `now`, without mutating it. The
        /// refill is lazy — it happens when the bucket is charged — so the
        /// recorded `tokens` of a bucket nobody has touched still carries the
        /// level it had when it was last charged.
        fn tokens_at(&self, now: Instant) -> f64 {
            let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
            (self.tokens + elapsed * self.refill_per_sec).min(self.capacity)
        }

        /// Refill for elapsed time, then take a token if one is available.
        fn try_take(&mut self, now: Instant) -> bool {
            self.tokens = self.tokens_at(now);
            self.last = now;
            if self.tokens >= 1.0 {
                self.tokens -= 1.0;
                true
            } else {
                false
            }
        }

        /// A bucket that has refilled to capacity is indistinguishable from a
        /// fresh one, so it can be pruned to reclaim memory. Both throttle
        /// tables prune on this.
        ///
        /// Counting the refill owed since the bucket was last charged is the
        /// whole point: `try_take` always leaves the *recorded* level at
        /// `capacity - 1` or below, so a predicate reading `self.tokens`
        /// directly would call no bucket that has ever been charged idle, and
        /// a prune built on it would free nothing, ever.
        fn is_full_at(&self, now: Instant) -> bool {
            self.tokens_at(now) >= self.capacity
        }
    }

    /// The FETCH throttle table and the state that keeps it bounded.
    ///
    /// Its key is the connecting NodeId, which is free to mint, so the prune
    /// of idle buckets has to be amortized rather than paid per request — see
    /// [`FETCH_RL_MAX_TRACKED`] and [`FETCH_RL_PRUNE_INTERVAL`].
    struct FetchLimiter {
        /// One bucket per tracked NodeId. Never larger than
        /// [`FETCH_RL_MAX_TRACKED`].
        buckets: HashMap<PeerId, TokenBucket>,
        /// When `buckets` was last pruned, to keep the O(n) pass off the
        /// per-request path.
        last_prune: Instant,
    }

    impl FetchLimiter {
        fn new(now: Instant) -> Self {
            Self {
                buckets: HashMap::new(),
                // Backdated so the first prune is not itself gated by the
                // interval: a flood can reach the cap within a second of start.
                last_prune: now.checked_sub(FETCH_RL_PRUNE_INTERVAL).unwrap_or(now),
            }
        }
    }

    /// Per-recipient reserve state: the below-floor draw budget, and nothing
    /// else.
    ///
    /// **The stocking level is not kept here, and no fallback for it is kept
    /// here either.** It lives in the store, where a PUBLISH writes it and
    /// where `RedbInboxStore::prekey_level_and_mark` anchors any pool that
    /// still lacks one. This table is bounded and prunable, so anything held in
    /// it can be dropped on demand by an unauthenticated peer that fills it —
    /// which is precisely how a mark kept here was reset, letting the floor
    /// re-derive from an already-drained pool. See [`RESERVE_MAX_TRACKED`].
    ///
    /// What is left here is soft state that can be dropped without consequence.
    /// A pruned entry costs the attacker nothing and gains it nothing: the
    /// prune only removes buckets that are *full* ([`TokenBucket::is_full_at`]),
    /// and a full bucket is by definition indistinguishable from the fresh one
    /// that replaces it. A bucket with tokens spent is not full, so it is not
    /// prunable until the refill it is throttling on has already happened.
    struct Reserve {
        /// Below-floor draw budget, keyed by the **recipient**.
        bucket: TokenBucket,
    }

    impl Reserve {
        fn new(now: Instant) -> Self {
            Self {
                bucket: TokenBucket::new(RESERVE_RL_CAPACITY, RESERVE_RL_REFILL_PER_SEC, now),
            }
        }
    }

    /// The reserve floor for a recipient whose recorded stocking level is
    /// `stock`: draws are ungated while strictly more than this many prekeys
    /// remain. See [`PREKEY_RESERVE_DIVISOR`].
    fn reserve_floor(stock: u64) -> u64 {
        stock / PREKEY_RESERVE_DIVISOR
    }

    /// The line [`InboxServer::run`] logs for a failed `accept()`, reporting
    /// how many failures went unlogged since the previous line (see
    /// [`ACCEPT_ERROR_LOG_INTERVAL`]).
    ///
    /// Split out so a test can assert what reaches the operator's terminal: a
    /// backend error message can quote peer-supplied bytes — an unknown ALPN,
    /// a rejected token — so it goes through the shared terminal sanitizer
    /// rather than to stderr raw.
    pub(super) fn accept_error_line(e: &P2pError, suppressed: u64) -> String {
        format!(
            "[inbox] accept error (continuing to serve; {suppressed} suppressed \
             since the previous line): {}",
            crate::utils::sanitize_for_terminal(&e.to_string())
        )
    }

    /// Outcome of [`InboxServer::draw_prekey`].
    enum Draw {
        /// A popped one-time prekey blob.
        Prekey(Vec<u8>),
        /// The recipient's pool is empty.
        Depleted,
        /// The pool is inside its reserve band and the recipient's reserve
        /// budget is spent. Distinct from `Depleted` — prekeys remain, and the
        /// caller is told to back off rather than that the pool is exhausted.
        Throttled,
    }

    /// Persistent inbox: redb-backed envelope storage + ALPN_INBOX accept loop.
    pub struct InboxServer {
        store: RedbInboxStore,
        /// Per-NodeId FETCH rate limiters (prekey-depletion mitigation).
        /// A std mutex, not async: the critical section is a few map ops
        /// with no `.await`, so it never blocks the runtime meaningfully —
        /// which is also why the O(n) prune inside it is amortized (see
        /// [`FETCH_RL_PRUNE_INTERVAL`]) instead of running per request.
        fetch_rl: StdMutex<FetchLimiter>,
        /// Per-recipient prekey reserve (the second half of the same
        /// mitigation), taken **only** by [`Self::draw_prekey`] — no other
        /// handler touches it. Also the serialization point for count+pop, so
        /// the critical section spans two synchronous redb calls and, still,
        /// no `.await`.
        prekey_reserve: StdMutex<HashMap<PeerId, Reserve>>,
        /// Bounds concurrent per-connection setup + handling (see
        /// [`MAX_CONCURRENT_CONNECTIONS`]).
        conn_sem: Arc<tokio::sync::Semaphore>,
    }

    impl InboxServer {
        /// Open an inbox at `path`, creating the redb schema on first use.
        ///
        /// The DB is encrypted with a 256-bit DEK wrapped by the same PQC
        /// at-rest layer as the MLS storage (see `group::at_rest` and
        /// SECURITY_PROFILE.md §7.3). This matters even though every `payload`
        /// is already MLS ciphertext: the `recipient`/`sender`/`created_at`
        /// metadata would otherwise sit in plaintext on the relay's disk. The
        /// recipient is stored as a blind index and all values are encrypted;
        /// see `group::redb_storage`. `passphrase` decrypts the hybrid key file.
        ///
        /// `beside_db` keeps the inbox's hybrid key in `inbox.db.at-rest.key`
        /// rather than the shared `at-rest.key`, so an MLS client and a
        /// co-located inbox server in the same directory never race to create
        /// one key file.
        pub fn open<P: AsRef<Path>>(
            path: P,
            passphrase: &Zeroizing<String>,
        ) -> Result<Self, InboxError> {
            let at_rest_paths = crate::group::AtRestPaths::beside_db(path.as_ref());
            let dek = crate::group::resolve_dek(&at_rest_paths, passphrase)
                .map_err(|e| InboxError::AtRest(e.to_string()))?;
            let store = RedbInboxStore::open(
                path.as_ref(),
                &dek,
                MAX_PREKEYS_STORED as usize,
                MAX_ENVELOPES_PER_RECIPIENT as usize,
            )?;
            Ok(Self {
                store,
                fetch_rl: StdMutex::new(FetchLimiter::new(Instant::now())),
                prekey_reserve: StdMutex::new(HashMap::new()),
                conn_sem: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNECTIONS)),
            })
        }

        /// Charge one FETCH token against the connecting NodeId's bucket,
        /// returning `true` if the request is within the rate limit.
        fn allow_fetch(&self, who: PeerId) -> bool {
            self.allow_fetch_at(who, Instant::now())
        }

        /// [`Self::allow_fetch`] with the clock passed in, so a test can place
        /// two calls minutes apart without waiting for them.
        ///
        /// FETCH is unauthenticated and its key here is a free-to-mint NodeId,
        /// so this table has to stay bounded against a caller that never
        /// repeats itself. Two rules do that:
        ///
        /// * At [`FETCH_RL_MAX_TRACKED`] entries, buckets that have refilled
        ///   to capacity are pruned — they hold no throttle state a fresh
        ///   bucket would not. The test is [`TokenBucket::is_full_at`], on the
        ///   *refilled* level: `try_take` always leaves the recorded level
        ///   below capacity, so a prune reading that would free nothing and
        ///   the table would grow without bound. The pass is O(n), so it runs
        ///   at most once per [`FETCH_RL_PRUNE_INTERVAL`] and only for a
        ///   caller not already tracked — an established sender never pays for
        ///   the size of the table.
        /// * A caller that still finds no room is **served untracked** rather
        ///   than inserted, so the table is capped even when nothing is
        ///   prunable. See [`FETCH_RL_MAX_TRACKED`] for why failing open there
        ///   gives an attacker nothing it did not already have, and why
        ///   refusing instead would only reach honest senders. This is the
        ///   same admission rule `draw_prekey` applies at
        ///   [`RESERVE_MAX_TRACKED`].
        fn allow_fetch_at(&self, who: PeerId, now: Instant) -> bool {
            // Recover from a poisoned lock rather than propagating the panic:
            // a throttle table is not security-critical state, and the server
            // must keep serving other peers.
            let mut rl = self
                .fetch_rl
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(bucket) = rl.buckets.get_mut(&who) {
                return bucket.try_take(now);
            }
            if rl.buckets.len() >= FETCH_RL_MAX_TRACKED
                && now.saturating_duration_since(rl.last_prune) >= FETCH_RL_PRUNE_INTERVAL
            {
                rl.buckets.retain(|_, b| !b.is_full_at(now));
                rl.last_prune = now;
            }
            if rl.buckets.len() < FETCH_RL_MAX_TRACKED {
                let mut bucket = TokenBucket::new(FETCH_RL_CAPACITY, FETCH_RL_REFILL_PER_SEC, now);
                let allowed = bucket.try_take(now);
                rl.buckets.insert(who, bucket);
                allowed
            } else {
                // No room to track this caller, so it goes ungated rather than
                // refused: a fresh NodeId was never gated by this table in the
                // first place, and refusing would throttle only the honest
                // sender whose idle bucket has been pruned.
                true
            }
        }

        /// The single path from a FETCH to [`RedbInboxStore::fetch_prekey`].
        ///
        /// Counts the recipient's remaining prekeys and pops one inside **one**
        /// critical section, so concurrent fetches cannot all observe a healthy
        /// level and then all pop past the floor.
        ///
        /// Above the floor there is no per-recipient check at all — a healthy
        /// pool is served to however many identities ask, so an honest sender
        /// never meets the gate. At or below the floor the draw also costs a
        /// token from a bucket keyed by the **recipient**, which is what bounds
        /// the aggregate below-floor drain rate: minting fresh NodeIds defeats
        /// `allow_fetch`, but every one of them draws from the same bucket
        /// here. The floor itself is a function of the *recipient's own* pool
        /// (`Reserve::stock`), never of a global constant, so a recipient that
        /// stocks 100 and one that stocks 256 are each gated only over their
        /// own drained tail — and a recipient that has never published gets no
        /// entry at all.
        ///
        /// The stocking level that floor is computed from is read from the
        /// store — written there by the recipient's own PUBLISH, or anchored
        /// there on the first draw of a pool that predates the record — never
        /// from this process's memory: memory here is capped and prunable, and
        /// a prune is something an unauthenticated peer can provoke. Only the
        /// token bucket lives in the table now, and losing one of those to a
        /// prune is free in both directions (see [`Reserve`]).
        fn draw_prekey(&self, recipient: PeerId) -> Result<Draw, InboxError> {
            let now = Instant::now();
            // Poison recovery as in `allow_fetch`: throttle bookkeeping must
            // not take the whole server down for other peers.
            let mut reserve = self
                .prekey_reserve
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            // One transaction, so the level and the mark it is measured against
            // cannot straddle a concurrent PUBLISH. This also *writes* the mark
            // for a pool that has none yet, at the level standing before the
            // pop below — see `prekey_level_and_mark`. Both happen under this
            // mutex, so the anchor is settled before any key leaves the pool.
            let (level, stock) = self.store.prekey_level_and_mark(recipient.as_bytes())?;
            let level = level as u64;
            if level == 0 {
                // Nothing to reserve. Return before touching the table so an
                // identity that never published — any stranger can name one on
                // the wire — allocates no state here.
                return Ok(Draw::Depleted);
            }
            let allowed = match reserve.get_mut(&recipient) {
                Some(r) => level > reserve_floor(stock) || r.bucket.try_take(now),
                None => {
                    // No bucket for this recipient — either its first draw, or
                    // its entry was pruned. Either way the floor is whatever
                    // the recipient's own record says, so unlike before this is
                    // *not* an automatically free draw: a pool already inside
                    // its band is charged from the first draw on. The charge
                    // still lands (a fresh bucket is full), so nothing an
                    // honest sender does changes; what changes is that the
                    // entry is no longer left full, and therefore immediately
                    // prunable, by an attacker that stopped at the floor.
                    if reserve.len() >= RESERVE_MAX_TRACKED {
                        reserve.retain(|_, r| !r.bucket.is_full_at(now));
                    }
                    if reserve.len() < RESERVE_MAX_TRACKED {
                        let mut fresh = Reserve::new(now);
                        let allowed =
                            level > reserve_floor(stock) || fresh.bucket.try_take(now);
                        reserve.insert(recipient, fresh);
                        allowed
                    } else {
                        // No room to track this recipient. Served rather than
                        // refused, for the reason [`FETCH_RL_MAX_TRACKED`]
                        // gives: `REPLY_RATE_LIMITED` is a downgrade lever, not
                        // a retry signal. Unchanged by this fix, and still a
                        // residual — see [`RESERVE_MAX_TRACKED`].
                        true
                    }
                }
            };
            if !allowed {
                return Ok(Draw::Throttled);
            }
            // Still under the same lock as the count above, so no other pop can
            // slip in between "the pool is above its floor" and taking a key.
            match self.store.fetch_prekey(recipient.as_bytes())? {
                Some(b) => Ok(Draw::Prekey(b)),
                None => Ok(Draw::Depleted),
            }
        }

        /// Test-only view of the reserve table's size, so the tests can assert
        /// that an empty slot allocates no per-recipient state.
        #[cfg(test)]
        pub(crate) fn tracked_reserves(&self) -> usize {
            self.prekey_reserve
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .len()
        }

        /// Test-only view of the FETCH throttle table's size, so the tests can
        /// assert that a stream of minted NodeIds cannot grow it without bound.
        #[cfg(test)]
        pub(crate) fn tracked_fetchers(&self) -> usize {
            self.fetch_rl
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .buckets
                .len()
        }

        /// Test-only door onto [`Self::allow_fetch_at`]. The throttle is
        /// otherwise reachable only over a connection, and its bounds need
        /// thousands of callers and a clock that moves by minutes.
        #[cfg(test)]
        pub(crate) fn allow_fetch_at_for_test(&self, who: PeerId, now: Instant) -> bool {
            self.allow_fetch_at(who, now)
        }

        /// Test-only door onto [`Self::draw_prekey`] and the PUBLISH slot,
        /// reporting the FETCH reply byte a draw would produce.
        ///
        /// The reserve's bound is `RESERVE_MAX_TRACKED` = 4096 *recipients*, so
        /// a test that forces its prune has to stock and draw from thousands of
        /// slots; over the mock network that is thousands of connections for
        /// one assertion. These skip the transport and nothing else — the
        /// handler does exactly `store.publish_prekeys(<authenticated NodeId>,
        /// ..)` and `draw_prekey(<wire recipient>)` around them. The one thing
        /// left out is `allow_fetch`, the per-connecting-NodeId bucket, which is
        /// the part an attacker walks around for free by minting a NodeId per
        /// request.
        #[cfg(test)]
        pub(crate) fn draw_prekey_reply_for_test(
            &self,
            recipient: PeerId,
        ) -> Result<u8, InboxError> {
            Ok(match self.draw_prekey(recipient)? {
                Draw::Prekey(_) => REPLY_OK,
                Draw::Depleted => REPLY_PREKEY_NONE,
                Draw::Throttled => REPLY_RATE_LIMITED,
            })
        }

        /// Test-only door onto the PUBLISH store call. See
        /// [`Self::draw_prekey_reply_for_test`].
        #[cfg(test)]
        pub(crate) fn publish_for_test(
            &self,
            recipient: PeerId,
            blobs: &[Vec<u8>],
        ) -> Result<(), InboxError> {
            self.store.publish_prekeys(recipient.as_bytes(), blobs, 0)?;
            Ok(())
        }

        /// Test-only view of a slot's pool level, for asserting what a drain
        /// left behind without a COUNT round trip.
        #[cfg(test)]
        pub(crate) fn pool_level_for_test(&self, recipient: PeerId) -> usize {
            self.store
                .count_prekeys(recipient.as_bytes())
                .expect("count prekeys")
        }

        /// Test-only door onto the store's mark-forgetting helper, so a test
        /// can build the on-disk shape of a pool published before stocking
        /// marks were kept.
        #[cfg(test)]
        pub(crate) fn forget_prekey_mark_for_test(&self, recipient: PeerId) {
            self.store
                .forget_prekey_mark_for_test(recipient.as_bytes())
                .expect("forget prekey mark");
        }

        /// Run the accept loop. Each accepted stream is dispatched on
        /// its own task; the server is fully concurrent for both
        /// DEPOSIT and POLL.
        pub async fn run(
            self: Arc<Self>,
            endpoint: Arc<dyn P2pEndpoint>,
        ) -> Result<(), InboxError> {
            // Accept-failure log state: when the last line was written, and how
            // many failures went unreported since. See `ACCEPT_ERROR_LOG_INTERVAL`.
            let mut last_error_log: Option<Instant> = None;
            let mut suppressed_errors: u64 = 0;
            loop {
                // `accept()` is cheap: it does NOT run the per-connection setup
                // (ALPN negotiation + stream open), so a peer that stalls the
                // handshake can no longer block new accepts. Setup runs in the
                // spawned task below, bounded by `P2P_SETUP_TIMEOUT` (the H2
                // head-of-line fix).
                //
                // A failure here is per-connection — a malformed or unsupported
                // QUIC initial, a peer that vanished between the datagram and
                // the accept — and anyone can send the datagram that causes one.
                // It must NOT end store-and-forward for every user of this
                // relay, so only a closed endpoint leaves the loop. (This was
                // `?`, so one stray packet exited `run()` and stopped DEPOSIT,
                // POLL, PUBLISH and FETCH until an operator restarted the
                // process.) Same shape as `NetworkProcessor::run_listen_loop`,
                // including the cooperative-yield-only recovery: see the
                // serial-accept note there for why no delay is added on error.
                let pending = match endpoint.accept().await {
                    Ok(p) => p,
                    // Endpoint shut down (close / ctrl-c). Unchanged from
                    // before: still the error this returned, so a supervisor
                    // sees the same exit status it always did.
                    Err(e @ P2pError::Closed) => return Err(InboxError::Transport(e)),
                    Err(e) => {
                        let now = Instant::now();
                        let due = last_error_log
                            .is_none_or(|t| {
                                now.saturating_duration_since(t) >= ACCEPT_ERROR_LOG_INTERVAL
                            });
                        if due {
                            eprintln!("{}", accept_error_line(&e, suppressed_errors));
                            last_error_log = Some(now);
                            suppressed_errors = 0;
                        } else {
                            suppressed_errors = suppressed_errors.saturating_add(1);
                        }
                        tokio::task::yield_now().await;
                        continue;
                    }
                };
                // Reserve a slot BEFORE spawning so an accept flood cannot spawn
                // unbounded setup tasks; a stalling peer's `establish` times out
                // and frees the slot.
                let permit = match Arc::clone(&self.conn_sem).acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => return Ok(()), // semaphore closed → shutting down
                };
                let me = Arc::clone(&self);
                tokio::spawn(async move {
                    let _permit = permit; // held for the connection's lifetime
                    let incoming = match pending.establish(P2P_SETUP_TIMEOUT).await {
                        Ok(inc) => inc,
                        Err(_) => {
                            // Timed out or dropped mid-setup. No detail is logged:
                            // the message can embed remote-supplied bytes (an
                            // unknown ALPN) that would inject terminal escapes.
                            eprintln!("[inbox] connection setup failed or timed out");
                            return;
                        }
                    };
                    if incoming.protocol != P2pProtocol(ALPN_INBOX) {
                        // Not addressed to us — drop. (Endpoint may serve
                        // multiple ALPNs; only ours is interesting here.)
                        return;
                    }
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
            let result = match tag[0] {
                TAG_DEPOSIT => self.handle_deposit(&mut *incoming.stream, sender).await,
                TAG_POLL => self.handle_poll(&mut *incoming.stream, sender).await,
                TAG_CHECKPOINT => self.handle_checkpoint(&mut *incoming.stream, sender).await,
                TAG_PUBLISH => self.handle_publish(&mut *incoming.stream, sender).await,
                TAG_FETCH => self.handle_fetch(&mut *incoming.stream, sender).await,
                TAG_COUNT => self.handle_count(&mut *incoming.stream, sender).await,
                t => Err(InboxError::Protocol(format!("unknown tag {t:#x}"))),
            };
            // On success the handler has written its full response and finished
            // our send half; hold the connection open until the client closes
            // so the response is not truncated by an eager CONNECTION_CLOSE.
            // See `await_peer_close`. On error there is nothing to protect.
            if result.is_ok() {
                await_peer_close(&mut *incoming.stream).await;
            }
            result
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
            // `recipient` is a wire field naming someone else's slot, but
            // `sender` is the handshake-authenticated NodeId — the store keys
            // its per-depositor byte budget on that, so no request can forge
            // which budget it spends.
            //
            // The store call is synchronous redb work (a write transaction, the
            // bounded expiry sweep, and up to MAX_PAYLOAD of AEAD), so it runs
            // on the blocking pool instead of stalling a runtime worker for the
            // duration.
            let store = self.store.clone();
            let recipient_bytes = *recipient.as_bytes();
            let sender_bytes = *sender.as_bytes();
            let stored = tokio::task::spawn_blocking(move || {
                store.deposit(&recipient_bytes, &sender_bytes, &payload, now)
            })
            .await
            .map_err(|e| InboxError::Storage(format!("deposit task: {e}")))?;
            if matches!(stored, Err(RedbStorageError::QuotaExceeded(_))) {
                // Refused, not failed — and refused without deleting anything,
                // which is the point: a depositor cannot make room in a slot it
                // does not own. Answer the existing REPLY_FAIL and return `Ok`
                // so the graceful-close barrier still delivers that byte.
                write_timed(stream, &[REPLY_FAIL], "deposit reply (refused)").await?;
                tokio::time::timeout(IO_TIMEOUT, stream.flush())
                    .await
                    .map_err(|_| InboxError::Timeout("deposit flush"))??;
                let _ = stream.shutdown().await;
                return Ok(());
            }
            stored?;
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
                std::cmp::min(u32::from_le_bytes(max_buf), MAX_POLL_BATCH) as usize;
            // The recipient is the handshake-authenticated NodeId, so no peer
            // can read someone else's inbox even by crafting the request (there
            // is no recipient field on the wire to override).
            //
            // The store call is synchronous redb work (a read transaction plus
            // an AEAD open per envelope), so it runs on the blocking pool
            // instead of stalling a runtime worker, exactly as `handle_deposit`
            // does. What it may return is bounded by
            // [`crate::group::redb_storage::MAX_POLL_BYTES`] as well as by
            // `max`, so this `Vec` — held across the writes below while the
            // peer may be refusing to read — cannot grow to `max` x
            // [`MAX_PAYLOAD`].
            let store = self.store.clone();
            let recipient_bytes = *recipient.as_bytes();
            let rows: Vec<(u64, Vec<u8>)> =
                tokio::task::spawn_blocking(move || store.poll(&recipient_bytes, since, max))
                    .await
                    .map_err(|e| InboxError::Storage(format!("poll task: {e}")))??;
            let count = rows.len() as u32;
            write_timed(stream, &count.to_le_bytes(), "poll count").await?;
            for (id, payload) in &rows {
                write_timed(stream, &id.to_le_bytes(), "envelope cursor").await?;
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
            let epoch = u64::from_le_bytes(epoch_buf);
            // `peer` is the handshake-authenticated NodeId, so a client can
            // only checkpoint its own record (no peer field on the wire).
            let reply = match self.store.checkpoint(peer.as_bytes(), epoch)? {
                CheckpointOutcome::Rollback => REPLY_ROLLBACK,
                CheckpointOutcome::Ok => REPLY_OK,
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
            // NodeId, so a peer can only ever publish into its own pool. The
            // store appends the batch and evicts the oldest beyond the cap.
            self.store.publish_prekeys(recipient.as_bytes(), &blobs, now)?;
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
            // §4.1). Done before the DB pop so a throttled caller can't drain,
            // and before the reserve below: `allow_fetch` takes and drops its
            // own lock, so the two throttle locks are never held at once.
            if !self.allow_fetch(fetcher) {
                write_timed(stream, &[REPLY_RATE_LIMITED], "fetch reply (rate limited)").await?;
                tokio::time::timeout(IO_TIMEOUT, stream.flush())
                    .await
                    .map_err(|_| InboxError::Timeout("fetch flush"))??;
                let _ = stream.shutdown().await;
                return Ok(());
            }

            // `recipient` is an unauthenticated wire field: it names *someone
            // else's* one-time key to consume, and the caller's NodeId is free
            // to mint, so the bucket charged above bounds nothing in aggregate.
            // `draw_prekey` therefore counts and pops under one lock and, once
            // the pool is inside its own reserve band, charges the draw to a
            // budget keyed on the recipient. It also pops the lowest-id prekey
            // atomically (single redb write txn), so two concurrent FETCHes can
            // never be handed the same one-time key.
            match self.draw_prekey(recipient)? {
                Draw::Prekey(b) => {
                    write_timed(stream, &[REPLY_OK], "fetch reply (ok)").await?;
                    write_timed(stream, &(b.len() as u32).to_le_bytes(), "fetch len").await?;
                    write_timed(stream, &b, "fetch blob").await?;
                }
                Draw::Depleted => {
                    write_timed(stream, &[REPLY_PREKEY_NONE], "fetch reply (none)").await?;
                }
                Draw::Throttled => {
                    write_timed(stream, &[REPLY_RATE_LIMITED], "fetch reply (rate limited)")
                        .await?;
                }
            }
            tokio::time::timeout(IO_TIMEOUT, stream.flush())
                .await
                .map_err(|_| InboxError::Timeout("fetch flush"))??;
            let _ = stream.shutdown().await;
            Ok(())
        }

        /// COUNT: report how many prekeys remain in the **caller's own** slot.
        /// `caller` is the handshake-authenticated NodeId, so the count is
        /// always of the requester's pool — no recipient field is read, which
        /// is what makes it impossible to probe another identity's pool size.
        async fn handle_count<S>(
            &self,
            stream: &mut S,
            caller: PeerId,
        ) -> Result<(), InboxError>
        where
            S: AsyncReadExt + AsyncWriteExt + Unpin + ?Sized,
        {
            let count = self.store.count_prekeys(caller.as_bytes())?;
            // The per-recipient pool is capped at MAX_PREKEYS_STORED, well
            // within u32; clamp defensively so the cast can never wrap.
            let count = count.min(u32::MAX as usize) as u32;
            write_timed(stream, &[REPLY_OK], "count reply (ok)").await?;
            write_timed(stream, &count.to_le_bytes(), "count value").await?;
            tokio::time::timeout(IO_TIMEOUT, stream.flush())
                .await
                .map_err(|_| InboxError::Timeout("count flush"))??;
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

    /// Drain every envelope addressed to `who`, following the cursor across the
    /// [`MAX_POLL_BATCH`] row limit *and* the
    /// [`crate::group::redb_storage::MAX_POLL_BYTES`] byte limit.
    ///
    /// Stops on an **empty** batch, not on a short one: a batch stops early once
    /// its bytes reach the budget, so a short batch does not mean the slot is
    /// drained. Terminating is still guaranteed — a poll always returns at least
    /// one row while any row matches, so the cursor advances every round.
    async fn drain(
        who: &dyn P2pEndpoint,
        server: &PeerAddr,
    ) -> Vec<Vec<u8>> {
        let mut cursor = 0u64;
        let mut all = Vec::new();
        loop {
            let (next, batch) = poll(who, server, cursor).await.expect("poll");
            if batch.is_empty() {
                return all;
            }
            all.extend(batch);
            cursor = next;
        }
    }

    /// Over the wire: one POLL cannot be made to materialise a whole slot. The
    /// reply stops at [`crate::group::redb_storage::MAX_POLL_BYTES`] even
    /// though the row cap would have admitted every envelope — and following
    /// the cursor still drains the slot completely, so the bound costs a round
    /// trip and not a message.
    #[tokio::test]
    async fn poll_reply_is_byte_bounded_and_still_drains() {
        let (net, _server, task, srv, _dir) = spawn_server().await;
        let alice =
            Arc::new(net.register(pid(1), vec![P2pProtocol(ALPN_INBOX)])) as Arc<dyn P2pEndpoint>;
        let bob =
            Arc::new(net.register(pid(2), vec![P2pProtocol(ALPN_INBOX)])) as Arc<dyn P2pEndpoint>;

        // 6 MiB in six envelopes: over the byte budget, far under the 64-row
        // cap the client asks for, so only the byte bound can shorten a reply.
        const N: usize = 6;
        const EACH: usize = 1024 * 1024;
        for i in 0..N {
            deposit(alice.as_ref(), &srv, pid(2), &vec![i as u8; EACH])
                .await
                .unwrap_or_else(|e| panic!("deposit {i}: {e}"));
        }

        let (cursor, first) = poll(bob.as_ref(), &srv, 0).await.expect("first poll");
        assert!(!first.is_empty(), "a poll with mail waiting must return some");
        assert!(first.len() < N, "one reply carried the whole {N}-envelope slot");
        assert!(cursor > 0, "cursor must advance past what was delivered");

        let mail = drain(bob.as_ref(), &srv).await;
        assert_eq!(mail.len(), N, "envelopes stranded or duplicated by a short batch");
        for (i, m) in mail.iter().enumerate() {
            assert_eq!(m, &vec![i as u8; EACH], "envelope {i} altered or reordered");
        }

        task.abort();
    }

    /// F2, over the wire: once a recipient's slot is full, a DEPOSIT to it is
    /// **refused**, and the envelopes already waiting there are all still
    /// waiting afterwards.
    ///
    /// The recipient field of a DEPOSIT is unauthenticated — any peer that can
    /// dial the ALPN names whatever slot it likes — so the old "make room by
    /// evicting the oldest" cap let a stranger flush a victim's undelivered
    /// queue. POLL only returns ids above the caller's cursor, so the victim
    /// would never have learned those messages existed.
    #[tokio::test]
    async fn deposit_into_a_full_slot_is_refused_and_evicts_nothing() {
        let (net, _server, task, srv, _dir) = spawn_server().await;
        let honest =
            Arc::new(net.register(pid(1), vec![P2pProtocol(ALPN_INBOX)])) as Arc<dyn P2pEndpoint>;
        let victim =
            Arc::new(net.register(pid(2), vec![P2pProtocol(ALPN_INBOX)])) as Arc<dyn P2pEndpoint>;
        let attacker =
            Arc::new(net.register(pid(3), vec![P2pProtocol(ALPN_INBOX)])) as Arc<dyn P2pEndpoint>;

        // Fill the victim's slot with mail it has not polled yet.
        for i in 0..MAX_ENVELOPES_PER_RECIPIENT {
            deposit(honest.as_ref(), &srv, pid(2), format!("mail-{i:03}").as_bytes())
                .await
                .unwrap_or_else(|e| panic!("deposit {i}: {e}"));
        }

        // A stranger cannot buy room in someone else's slot.
        match deposit(attacker.as_ref(), &srv, pid(2), b"evicts-the-oldest").await {
            Err(InboxError::Rejected) => {}
            other => panic!("a full slot must be refused, got {other:?}"),
        }

        // Nothing was dropped to make room for it, and nothing was stored.
        let mail = drain(victim.as_ref(), &srv).await;
        assert_eq!(mail.len(), MAX_ENVELOPES_PER_RECIPIENT as usize);
        assert_eq!(mail.first().map(|m| m.as_slice()), Some(&b"mail-000"[..]));
        assert_eq!(mail.last().map(|m| m.as_slice()), Some(&b"mail-255"[..]));

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

    /// A never-before-seen fetcher identity. An iroh NodeId is a free-to-mint
    /// keypair, which is exactly what lets an attacker walk around the
    /// per-NodeId FETCH bucket — so the reserve tests below spend a fresh one
    /// on every draw, leaving the per-recipient reserve as the only thing that
    /// can be measuring them.
    fn fresh_fetcher(net: &Arc<MockNetwork>, n: u16) -> Arc<dyn P2pEndpoint> {
        // Shaped so it can never collide with the `pid(b)` = [b; 32] ids.
        let mut raw = [0u8; 32];
        raw[0] = 0xA5;
        raw[1] = (n >> 8) as u8;
        raw[2] = n as u8;
        Arc::new(net.register(PeerId::new(raw), vec![P2pProtocol(ALPN_INBOX)]))
            as Arc<dyn P2pEndpoint>
    }

    /// The reserve gates the drained tail and nothing else, for a recipient
    /// that stocked the `--prekey-count` default of 100.
    ///
    /// Above the floor (the lowest quarter of what this recipient actually
    /// stocks) no per-recipient budget is consulted at all, however many fresh
    /// identities ask — an honest sender never meets the gate. Inside the band
    /// a draw also costs a recipient-keyed token, and once that burst is spent
    /// the answer is RateLimited *with prekeys still in the pool*, not
    /// Depleted: the remaining keys stay there for whoever draws next, and a
    /// single replenishment disengages the gate again.
    #[tokio::test]
    async fn reserve_gates_only_the_drained_tail_of_a_default_pool() {
        const STOCK: u64 = 100; // the `--prekey-count` default
        let (net, _server, task, srv, _dir) = spawn_server().await;
        let bob =
            Arc::new(net.register(pid(2), vec![P2pProtocol(ALPN_INBOX)])) as Arc<dyn P2pEndpoint>;
        let batch: Vec<Vec<u8>> = (0..STOCK).map(|i| format!("pk-{i}").into_bytes()).collect();
        publish_prekeys(bob.as_ref(), &srv, &batch).await.expect("publish");

        let floor = STOCK / PREKEY_RESERVE_DIVISOR; // 25
        let free = STOCK - floor; // 75 ungated draws
        let mut minted = Vec::new();

        for i in 0..free {
            let ep = fresh_fetcher(&net, i as u16);
            assert!(
                matches!(
                    fetch_prekey(ep.as_ref(), &srv, pid(2)).await.unwrap(),
                    FetchOutcome::Prekey(_)
                ),
                "draw {i} is above the floor and must not be gated"
            );
            minted.push(ep);
        }
        // The pool now sits exactly at its floor. What is left of the reserve
        // is one burst, shared by every identity rather than granted per one.
        for i in 0..RESERVE_RL_CAPACITY as u64 {
            let ep = fresh_fetcher(&net, (free + i) as u16);
            assert!(
                matches!(
                    fetch_prekey(ep.as_ref(), &srv, pid(2)).await.unwrap(),
                    FetchOutcome::Prekey(_)
                ),
                "reserve burst draw {i} must still be served"
            );
            minted.push(ep);
        }

        // Burst spent: a brand-new identity is throttled, and the reply says
        // *throttled*, not depleted — because prekeys really do remain.
        let attacker = fresh_fetcher(&net, 9000);
        assert_eq!(
            fetch_prekey(attacker.as_ref(), &srv, pid(2)).await.unwrap(),
            FetchOutcome::RateLimited
        );
        let left = count_prekeys(bob.as_ref(), &srv).await.unwrap() as u64;
        assert_eq!(left, floor - RESERVE_RL_CAPACITY as u64, "the reserve must be held back");
        assert!(left > 0);

        // A `maintain` run (top back up to the same target) disengages the gate
        // on the very next draw: the pool is above its floor again, so no token
        // is consulted even though the reserve bucket is still empty.
        let refill: Vec<Vec<u8>> = (0..STOCK - left).map(|i| format!("re-{i}").into_bytes()).collect();
        publish_prekeys(bob.as_ref(), &srv, &refill).await.expect("republish");
        let after = fresh_fetcher(&net, 9001);
        assert!(matches!(
            fetch_prekey(after.as_ref(), &srv, pid(2)).await.unwrap(),
            FetchOutcome::Prekey(_)
        ));

        task.abort();
    }

    /// Minting a fresh NodeId walks around the per-NodeId FETCH bucket but not
    /// around the recipient's reserve: once a pool is drawn into its band and
    /// the reserve burst is spent, brand-new identities are throttled on that
    /// recipient — while the very same brand-new identity draws normally from a
    /// *different*, healthy recipient, proving it is the recipient's budget
    /// doing the gating and not the caller's.
    #[tokio::test]
    async fn fresh_nodeid_cannot_bypass_the_recipient_reserve() {
        const STOCK: u64 = 40; // floor 10, so the band outlives the burst
        let (net, _server, task, srv, _dir) = spawn_server().await;
        let bob =
            Arc::new(net.register(pid(2), vec![P2pProtocol(ALPN_INBOX)])) as Arc<dyn P2pEndpoint>;
        let carol =
            Arc::new(net.register(pid(3), vec![P2pProtocol(ALPN_INBOX)])) as Arc<dyn P2pEndpoint>;
        let bobs: Vec<Vec<u8>> = (0..STOCK).map(|i| format!("bob-{i}").into_bytes()).collect();
        publish_prekeys(bob.as_ref(), &srv, &bobs).await.expect("publish bob");
        let carols: Vec<Vec<u8>> = (0..8u64).map(|i| format!("carol-{i}").into_bytes()).collect();
        publish_prekeys(carol.as_ref(), &srv, &carols).await.expect("publish carol");

        // Drain bob's pool through its floor with one fresh identity per draw.
        let mut minted = Vec::new();
        let drawn = STOCK - STOCK / PREKEY_RESERVE_DIVISOR + RESERVE_RL_CAPACITY as u64;
        for i in 0..drawn {
            let ep = fresh_fetcher(&net, i as u16);
            assert!(matches!(
                fetch_prekey(ep.as_ref(), &srv, pid(2)).await.unwrap(),
                FetchOutcome::Prekey(_)
            ));
            minted.push(ep);
        }

        for i in 0..3u16 {
            let ep = fresh_fetcher(&net, 5000 + i);
            // Never seen before, its own bucket untouched — still throttled on
            // bob, because the budget it is spending is bob's.
            assert_eq!(
                fetch_prekey(ep.as_ref(), &srv, pid(2)).await.unwrap(),
                FetchOutcome::RateLimited
            );
            // ...and not throttled at all on carol, whose pool is healthy.
            assert!(matches!(
                fetch_prekey(ep.as_ref(), &srv, pid(3)).await.unwrap(),
                FetchOutcome::Prekey(_)
            ));
            minted.push(ep);
        }
        // Bob's reserve still holds real keys after all of that.
        assert!(count_prekeys(bob.as_ref(), &srv).await.unwrap() > 0);

        task.abort();
    }

    /// A relay with no network in front of it, for the reserve tests that need
    /// thousands of draws. See [`InboxServer::draw_prekey_reply_for_test`].
    fn bare_server(dir: &std::path::Path) -> InboxServer {
        InboxServer::open(dir.join("inbox.db"), &test_passphrase()).expect("open")
    }

    /// One of the attacker's own filler recipients: an identity it minted and
    /// stocked itself, purely to occupy a slot in the reserve table.
    fn filler(i: usize) -> PeerId {
        // Shaped so it can never collide with the `pid(b)` = [b; 32] ids.
        let mut raw = [0xF1u8; 32];
        raw[..8].copy_from_slice(&(i as u64).to_le_bytes());
        PeerId::new(raw)
    }

    /// Drive `server`'s reserve table to its cap and force the prune, using
    /// recipients the attacker minted and stocked itself. Returns once a draw
    /// has been taken for [`RESERVE_MAX_TRACKED`] distinct recipients.
    ///
    /// Nothing here needs a victim's cooperation: PUBLISH writes to the slot of
    /// the handshake-authenticated NodeId and never parses the blob, so a junk
    /// byte string per minted identity is a stocked pool as far as the relay is
    /// concerned, and no third party's prekeys are consumed.
    fn flood_reserve_table(server: &InboxServer) {
        for i in 0..RESERVE_MAX_TRACKED {
            server
                .publish_for_test(filler(i), &[b"junk".to_vec()])
                .expect("publish filler");
            assert_eq!(
                server.draw_prekey_reply_for_test(filler(i)).expect("draw filler"),
                REPLY_OK,
                "a filler's own freshly stocked pool is above its floor"
            );
        }
    }

    /// The attack `KNOWN_ISSUES.md` item 3 describes, run end to end.
    ///
    /// An attacker walks a victim's pool down to *exactly* its floor and stops.
    /// Every one of those draws is above the floor, so the `||` in
    /// `draw_prekey` short-circuits and the victim's reserve bucket is never
    /// charged — it stays full from creation, and a full bucket is what the
    /// prune removes. The attacker then fills the reserve table with 4096
    /// recipients it minted and stocked itself, which fires that prune, and
    /// draws the victim again.
    ///
    /// While the stocking level lived in the pruned table this bought the
    /// attacker the whole remaining quarter of the pool: the mark re-derived
    /// from the drawn-down level (25, floor 6), so 19 more keys came out
    /// ungated, no token spent and no waiting, repeatable until the pool was
    /// empty. The level now comes from the victim's own PUBLISH record in the
    /// store, which no prune can reach, so past the floor the attacker gets one
    /// reserve burst and is then told to back off — with real prekeys still in
    /// the pool for an honest sender to draw.
    #[test]
    fn a_forced_prune_cannot_collapse_a_victims_reserve_floor() {
        const STOCK: u64 = 100; // the `--prekey-count` default
        let dir = tempdir().expect("tempdir");
        let server = bare_server(dir.path());
        let victim = pid(2);

        let batch: Vec<Vec<u8>> = (0..STOCK).map(|i| format!("pk-{i}").into_bytes()).collect();
        server.publish_for_test(victim, &batch).expect("publish");

        // Walk the pool down to exactly its floor, spending nothing.
        let floor = STOCK / PREKEY_RESERVE_DIVISOR; // 25
        for i in 0..(STOCK - floor) {
            assert_eq!(
                server.draw_prekey_reply_for_test(victim).expect("draw"),
                REPLY_OK,
                "draw {i} is above the floor and must not be gated"
            );
        }
        assert_eq!(server.pool_level_for_test(victim) as u64, floor);

        flood_reserve_table(&server);
        assert_eq!(
            server.tracked_reserves(),
            1,
            "the flood must actually fire the prune, and the prune takes every \
             full bucket — the victim's among them. That is the attack's \
             precondition: without it there is nothing to re-derive."
        );

        // The pool sits at its floor, so every draw from here is inside the
        // band and costs a token. One fresh burst is served; after that the
        // reply is a throttle, not another key.
        let mut served = 0u64;
        for _ in 0..(floor + 1) {
            match server.draw_prekey_reply_for_test(victim).expect("draw") {
                REPLY_OK => served += 1,
                REPLY_RATE_LIMITED => break,
                other => panic!("unexpected reply {other:#x} with prekeys still in the pool"),
            }
        }
        assert_eq!(
            served,
            RESERVE_RL_CAPACITY as u64,
            "a forced prune must not re-anchor the floor to the drawn-down level: \
             {served} draws were served below a floor of {floor}"
        );
        assert_eq!(
            server.pool_level_for_test(victim) as u64,
            floor - RESERVE_RL_CAPACITY as u64,
            "the reserve must still be held back after the prune"
        );
    }

    /// The stocking level survives a relay restart, so a pool that was drawn
    /// down while the process was gone is not re-anchored to what it was
    /// drained to. This was the second residual of the process-local table: a
    /// restart re-derived every mark from the live pool levels.
    #[test]
    fn a_restart_does_not_re_anchor_the_floor_to_a_drained_pool() {
        const STOCK: u64 = 100;
        let dir = tempdir().expect("tempdir");
        let victim = pid(2);
        let floor = STOCK / PREKEY_RESERVE_DIVISOR; // 25

        {
            let server = bare_server(dir.path());
            let batch: Vec<Vec<u8>> =
                (0..STOCK).map(|i| format!("pk-{i}").into_bytes()).collect();
            server.publish_for_test(victim, &batch).expect("publish");
            for _ in 0..(STOCK - floor) {
                assert_eq!(
                    server.draw_prekey_reply_for_test(victim).expect("draw"),
                    REPLY_OK
                );
            }
            // Dropped here: redb's file lock has to go before the reopen.
        }

        let server = bare_server(dir.path());
        let mut served = 0u64;
        for _ in 0..(floor + 1) {
            match server.draw_prekey_reply_for_test(victim).expect("draw") {
                REPLY_OK => served += 1,
                REPLY_RATE_LIMITED => break,
                other => panic!("unexpected reply {other:#x}"),
            }
        }
        assert_eq!(
            served,
            RESERVE_RL_CAPACITY as u64,
            "a restart must not re-derive the floor from the drained level"
        );
    }

    /// The same forced-prune attack, against a pool that carries **no** mark —
    /// the on-disk shape of every pool in a database that predates the record,
    /// and so of every pool in a deployment on the day it upgrades.
    ///
    /// This is where the first attempt at this fix was still broken: unmarked
    /// pools fell back to a high-water level kept in the reserve table, the
    /// prune destroyed that, and the next draw re-seeded it from the
    /// drawn-down level — the whole of the original attack, untouched, for
    /// every pool until its owner next published. A pool is now anchored in the
    /// store on its **first draw**, at the level standing before that draw
    /// pops, so there is no window in which the floor is resettable.
    ///
    /// Asserts both halves: the ungated draws an honest sender expects are
    /// served exactly as before (nothing fails closed on upgrade), *and* the
    /// floor survives the prune.
    #[test]
    fn a_forced_prune_cannot_collapse_an_unmarked_pools_floor() {
        const STOCK: u64 = 100;
        let dir = tempdir().expect("tempdir");
        let server = bare_server(dir.path());
        let victim = pid(2);

        let batch: Vec<Vec<u8>> = (0..STOCK).map(|i| format!("pk-{i}").into_bytes()).collect();
        server.publish_for_test(victim, &batch).expect("publish");
        // The on-disk shape of a pool stocked by the previous version.
        server.forget_prekey_mark_for_test(victim);

        // Unchanged for an honest sender: the whole ungated run is served.
        let floor = STOCK / PREKEY_RESERVE_DIVISOR; // 25
        for i in 0..(STOCK - floor) {
            assert_eq!(
                server.draw_prekey_reply_for_test(victim).expect("draw"),
                REPLY_OK,
                "an unmarked pool must still serve its ungated draws (draw {i})"
            );
        }
        assert_eq!(server.pool_level_for_test(victim) as u64, floor);

        flood_reserve_table(&server);
        assert_eq!(
            server.tracked_reserves(),
            1,
            "the flood must actually fire the prune, taking the victim's \
             full bucket with it — the attack's precondition"
        );

        let mut served = 0u64;
        for _ in 0..(floor + 1) {
            match server.draw_prekey_reply_for_test(victim).expect("draw") {
                REPLY_OK => served += 1,
                REPLY_RATE_LIMITED => break,
                other => panic!("unexpected reply {other:#x} with prekeys still in the pool"),
            }
        }
        assert_eq!(
            served,
            RESERVE_RL_CAPACITY as u64,
            "a pool with no mark of its own must still be anchored durably: \
             {served} draws were served below a floor of {floor}"
        );
        assert_eq!(
            server.pool_level_for_test(victim) as u64,
            floor - RESERVE_RL_CAPACITY as u64,
            "the reserve must still be held back"
        );
    }

    /// The anchor an unmarked pool is given survives a restart, and the
    /// recipient's own PUBLISH still replaces it afterwards.
    #[test]
    fn an_anchored_pool_keeps_its_floor_across_a_restart_and_a_republish() {
        const STOCK: u64 = 100;
        let dir = tempdir().expect("tempdir");
        let bob = pid(2);
        let floor = STOCK / PREKEY_RESERVE_DIVISOR; // 25

        {
            let server = bare_server(dir.path());
            let batch: Vec<Vec<u8>> =
                (0..STOCK).map(|i| format!("pk-{i}").into_bytes()).collect();
            server.publish_for_test(bob, &batch).expect("publish");
            server.forget_prekey_mark_for_test(bob);
            // One draw is all it takes to anchor the pool at 100.
            assert_eq!(server.draw_prekey_reply_for_test(bob).expect("draw"), REPLY_OK);
            for _ in 1..(STOCK - floor) {
                assert_eq!(server.draw_prekey_reply_for_test(bob).expect("draw"), REPLY_OK);
            }
        }

        let server = bare_server(dir.path());
        let mut served = 0u64;
        for _ in 0..(floor + 1) {
            match server.draw_prekey_reply_for_test(bob).expect("draw") {
                REPLY_OK => served += 1,
                REPLY_RATE_LIMITED => break,
                other => panic!("unexpected reply {other:#x}"),
            }
        }
        assert_eq!(
            served,
            RESERVE_RL_CAPACITY as u64,
            "the anchor written on the first draw must outlive the process"
        );

        // And the owner still governs it: republishing to the full target puts
        // the pool back above its floor and disengages the gate at once.
        let refill: Vec<Vec<u8>> = (0..(STOCK - server.pool_level_for_test(bob) as u64))
            .map(|i| format!("re-{i}").into_bytes())
            .collect();
        server.publish_for_test(bob, &refill).expect("republish");
        assert_eq!(server.pool_level_for_test(bob) as u64, STOCK);
        assert_eq!(
            server.draw_prekey_reply_for_test(bob).expect("draw"),
            REPLY_OK,
            "a replenished pool is above its floor, so no token is consulted"
        );
    }

    /// A recipient may lower its own stocking level. The mark is *replaced* by
    /// each PUBLISH rather than raised to a high-water mark, because a peer
    /// that drops from 40 prekeys to 8 would otherwise sit forever under a
    /// floor of 10: every draw inside the reserve band, honest senders
    /// throttled to one prekey per `RESERVE_RL_REFILL_PER_SEC`, on a pool it
    /// deliberately keeps small.
    ///
    /// This costs nothing against the attack, because the only party that can
    /// *change* the mark is the slot's own owner — PUBLISH is keyed on the
    /// handshake-authenticated NodeId, and the draw path's one write only ever
    /// creates a mark that is missing.
    #[test]
    fn a_recipient_may_lower_its_own_stocking_level() {
        const STOCK: u64 = 40; // floor 10
        let dir = tempdir().expect("tempdir");
        let server = bare_server(dir.path());
        let bob = pid(2);

        let batch: Vec<Vec<u8>> = (0..STOCK).map(|i| format!("pk-{i}").into_bytes()).collect();
        server.publish_for_test(bob, &batch).expect("publish");
        let floor = STOCK / PREKEY_RESERVE_DIVISOR; // 10
        for _ in 0..(STOCK - floor + RESERVE_RL_CAPACITY as u64) {
            assert_eq!(server.draw_prekey_reply_for_test(bob).expect("draw"), REPLY_OK);
        }
        // Budget spent, pool inside the old band.
        assert_eq!(
            server.draw_prekey_reply_for_test(bob).expect("draw"),
            REPLY_RATE_LIMITED
        );
        let left = server.pool_level_for_test(bob) as u64; // 2

        // bob now stocks 8 rather than 40. The reserve bucket is still empty,
        // so a gated draw would answer RATE_LIMITED — the new level being above
        // the new floor is the only thing that can serve this.
        let small: Vec<Vec<u8>> = (0..8u64.saturating_sub(left))
            .map(|i| format!("sm-{i}").into_bytes())
            .collect();
        server.publish_for_test(bob, &small).expect("republish small");
        assert_eq!(server.pool_level_for_test(bob), 8);
        for i in 0..(8 - 8 / PREKEY_RESERVE_DIVISOR) {
            assert_eq!(
                server.draw_prekey_reply_for_test(bob).expect("draw"),
                REPLY_OK,
                "draw {i} is above the *current* stocking level's floor; a \
                 high-water mark would gate the whole pool"
            );
        }
    }

    /// A recipient that has never published allocates no per-recipient state,
    /// however often a stranger names it on the wire: the recipient id in a
    /// FETCH is unauthenticated, so an empty slot must not be a way to make the
    /// server allocate. Tracking starts at the first draw from a slot that
    /// actually holds prekeys.
    #[tokio::test]
    async fn never_published_recipient_allocates_no_reserve_bucket() {
        let (net, server, task, srv, _dir) = spawn_server().await;
        let stranger = fresh_fetcher(&net, 1);

        for _ in 0..5 {
            assert_eq!(
                fetch_prekey(stranger.as_ref(), &srv, pid(4)).await.unwrap(),
                FetchOutcome::Depleted
            );
        }
        assert_eq!(
            server.tracked_reserves(),
            0,
            "an empty slot must not allocate a reserve bucket"
        );

        // A slot that does hold prekeys is tracked from its first draw — that
        // record is what the floor is derived from.
        let bob =
            Arc::new(net.register(pid(2), vec![P2pProtocol(ALPN_INBOX)])) as Arc<dyn P2pEndpoint>;
        publish_prekeys(bob.as_ref(), &srv, &[b"pk-1".to_vec()]).await.expect("publish");
        assert!(matches!(
            fetch_prekey(stranger.as_ref(), &srv, pid(2)).await.unwrap(),
            FetchOutcome::Prekey(_)
        ));
        assert_eq!(server.tracked_reserves(), 1);

        task.abort();
    }

    /// COUNT reports the caller's OWN slot (authenticated by NodeId), tracks
    /// consumption as fetches drain the pool, and cannot be used to probe
    /// another identity's pool size.
    #[tokio::test]
    async fn count_reports_own_slot_and_tracks_consumption() {
        let (net, _server, task, srv, _dir) = spawn_server().await;
        let bob =
            Arc::new(net.register(pid(2), vec![P2pProtocol(ALPN_INBOX)])) as Arc<dyn P2pEndpoint>;
        let alice =
            Arc::new(net.register(pid(1), vec![P2pProtocol(ALPN_INBOX)])) as Arc<dyn P2pEndpoint>;

        // Empty slot → 0.
        assert_eq!(count_prekeys(bob.as_ref(), &srv).await.unwrap(), 0);

        let batch = vec![b"pk-A".to_vec(), b"pk-B".to_vec(), b"pk-C".to_vec()];
        publish_prekeys(bob.as_ref(), &srv, &batch).await.expect("publish");
        assert_eq!(count_prekeys(bob.as_ref(), &srv).await.unwrap(), 3);

        // A fetch consumes one → the count drops.
        assert!(matches!(
            fetch_prekey(alice.as_ref(), &srv, pid(2)).await.unwrap(),
            FetchOutcome::Prekey(_)
        ));
        assert_eq!(count_prekeys(bob.as_ref(), &srv).await.unwrap(), 2);

        // COUNT reads the *caller's* slot: alice (pid 1) published nothing, so
        // she sees 0 even though bob's slot on the same server holds 2. The op
        // therefore cannot probe a victim's pool size.
        assert_eq!(count_prekeys(alice.as_ref(), &srv).await.unwrap(), 0);

        task.abort();
    }

    /// The per-NodeId FETCH throttle table stays bounded under a flood of
    /// minted identities, and its prune really does reclaim.
    ///
    /// FETCH is unauthenticated and the bucket key is a free-to-mint NodeId, so
    /// a stranger can present a new one on every request. Three properties:
    /// the table never exceeds `FETCH_RL_MAX_TRACKED` however many identities
    /// call (the prune used to test the *recorded* token level, which
    /// `try_take` always leaves below capacity — so it removed nothing, the
    /// insert was unconditional, and the map grew forever while every later
    /// FETCH paid for a full scan of it); an honest sender is served
    /// throughout a *sustained* flood, because a caller the full table cannot
    /// track is served rather than refused (refusing would be a PQ-FS
    /// downgrade lever, since `one_shot` treats `RateLimited` like depletion);
    /// and once the flood's buckets have refilled they are reclaimed, so the
    /// table returns to tracking callers individually.
    #[tokio::test]
    async fn fetch_throttle_table_is_bounded_and_reclaims_idle_buckets() {
        let dir = tempdir().expect("tempdir");
        let server =
            InboxServer::open(dir.path().join("inbox.db"), &test_passphrase()).expect("open");

        fn minted(i: usize) -> PeerId {
            let mut raw = [0u8; 32];
            raw[..8].copy_from_slice(&(i as u64).to_le_bytes());
            PeerId::new(raw)
        }

        // One FETCH from each of far more identities than the table may hold,
        // all at the same instant so no bucket refills mid-flood.
        let t0 = std::time::Instant::now();
        let flood = FETCH_RL_MAX_TRACKED + 5_000;
        for i in 0..flood {
            let _ = server.allow_fetch_at_for_test(minted(i), t0);
        }
        assert!(
            server.tracked_fetchers() <= FETCH_RL_MAX_TRACKED,
            "the FETCH throttle table must stay bounded: {} entries after {flood} callers",
            server.tracked_fetchers()
        );

        // Now keep the flood running and interleave an honest sender's FETCHes
        // with it, at the same instant, so nothing is prunable and the sender
        // never gets an entry of its own. Every one of its requests must still
        // be served: a REPLY_RATE_LIMITED here is not a retry signal but a
        // static-only downgrade (see `one_shot::seal_for_recipient`), so an
        // unauthenticated flood must not be able to provoke one for a stranger.
        let honest = pid(7);
        for i in flood..flood + 500 {
            let _ = server.allow_fetch_at_for_test(minted(i), t0);
            assert!(
                server.allow_fetch_at_for_test(honest, t0),
                "an honest sender must be served through a sustained flood \
                 (iteration {i}); refusing untracked callers is a downgrade lever"
            );
        }
        assert!(server.tracked_fetchers() <= FETCH_RL_MAX_TRACKED);

        // Well past a full refill (capacity / FETCH_RL_REFILL_PER_SEC = 240 s),
        // every flood bucket is idle: the next new caller prunes them all and is
        // tracked in its own right again.
        let later = t0 + Duration::from_secs(600);
        assert!(server.allow_fetch_at_for_test(minted(usize::MAX - 1), later));
        assert_eq!(
            server.tracked_fetchers(),
            1,
            "idle buckets must be reclaimed once they have refilled"
        );
    }

    /// An endpoint whose first `remaining_failures` `accept()` calls fail before
    /// it delegates to the mock. Models the per-connection transport failure any
    /// stranger can provoke with one malformed QUIC initial: the iroh backend
    /// reports it as `P2pError::Accept`, never `Closed`.
    struct FlakyAcceptEndpoint {
        inner: Arc<dyn P2pEndpoint>,
        remaining_failures: std::sync::atomic::AtomicUsize,
    }

    /// The backend message [`FlakyAcceptEndpoint`] reports. It embeds an ESC
    /// because a real backend error quotes peer-supplied bytes (an unknown
    /// ALPN), which is what the log line has to neutralize.
    const FLAKY_ACCEPT_MSG: &str = "malformed initial \u{1b}[2J from peer";

    #[async_trait::async_trait]
    impl P2pEndpoint for FlakyAcceptEndpoint {
        fn local_id(&self) -> PeerId {
            self.inner.local_id()
        }

        async fn local_addr(&self) -> Result<PeerAddr, P2pError> {
            self.inner.local_addr().await
        }

        async fn connect(
            &self,
            addr: &PeerAddr,
            protocol: P2pProtocol,
        ) -> Result<Box<dyn crate::p2p::P2pStream>, P2pError> {
            self.inner.connect(addr, protocol).await
        }

        async fn accept(&self) -> Result<Box<dyn crate::p2p::P2pPending>, P2pError> {
            use std::sync::atomic::Ordering;
            if self
                .remaining_failures
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok()
            {
                return Err(P2pError::Accept(FLAKY_ACCEPT_MSG.to_string()));
            }
            self.inner.accept().await
        }

        async fn close(&self) -> Result<(), P2pError> {
            self.inner.close().await
        }
    }

    /// A failed `accept()` must not end the relay. Any datagram reaching the
    /// QUIC socket can provoke one, and `accept()` used to be `?`-propagated, so
    /// a single unauthenticated packet stopped DEPOSIT, POLL, PUBLISH and FETCH
    /// for every user of the relay until an operator restarted the process.
    #[tokio::test]
    async fn accept_error_does_not_end_the_relay() {
        let net = MockNetwork::new();
        let alice =
            Arc::new(net.register(pid(1), vec![P2pProtocol(ALPN_INBOX)])) as Arc<dyn P2pEndpoint>;
        let bob =
            Arc::new(net.register(pid(2), vec![P2pProtocol(ALPN_INBOX)])) as Arc<dyn P2pEndpoint>;
        let server_ep = Arc::new(FlakyAcceptEndpoint {
            inner: Arc::new(net.register(pid(99), vec![P2pProtocol(ALPN_INBOX)])),
            remaining_failures: std::sync::atomic::AtomicUsize::new(3),
        }) as Arc<dyn P2pEndpoint>;

        let dir = tempdir().expect("tempdir");
        let server = Arc::new(
            InboxServer::open(dir.path().join("inbox.db"), &test_passphrase()).expect("open"),
        );
        let task = tokio::spawn(async move {
            let _ = server.run(server_ep).await;
        });
        let srv = PeerAddr::new(pid(99));

        // Bounded, because the failure mode is a relay that no longer answers:
        // without the fix this hangs to the 30 s frame timeout instead.
        tokio::time::timeout(Duration::from_secs(5), async {
            deposit(alice.as_ref(), &srv, pid(2), b"still serving")
                .await
                .expect("deposit after accept errors");
            let (_cursor, envelopes) = poll(bob.as_ref(), &srv, 0).await.expect("poll");
            assert_eq!(envelopes, vec![b"still serving".to_vec()]);
        })
        .await
        .expect("the relay must keep serving after a transient accept error");

        assert!(!task.is_finished(), "the accept loop must still be running");
        task.abort();

        // What those failures put on the operator's terminal: peer-supplied
        // bytes are neutralized, and the line accounts for what it swallowed.
        let line = super::server::accept_error_line(
            &P2pError::Accept(FLAKY_ACCEPT_MSG.to_string()),
            41,
        );
        assert!(
            !line.contains('\u{1b}'),
            "the accept error log must be sanitized: {line:?}"
        );
        assert!(line.contains("malformed initial"), "{line:?}");
        assert!(line.contains("41 suppressed"), "{line:?}");
    }

    /// A closed endpoint — and nothing else — ends the accept loop, so shutdown
    /// neither hangs nor spins on a socket that will never accept again, and it
    /// still reports the transport error the caller has always seen.
    #[tokio::test]
    async fn closed_endpoint_ends_the_accept_loop() {
        let net = MockNetwork::new();
        let server_ep =
            Arc::new(net.register(pid(99), vec![P2pProtocol(ALPN_INBOX)])) as Arc<dyn P2pEndpoint>;
        let dir = tempdir().expect("tempdir");
        let server = Arc::new(
            InboxServer::open(dir.path().join("inbox.db"), &test_passphrase()).expect("open"),
        );
        let task = {
            let ep = Arc::clone(&server_ep);
            tokio::spawn(async move { server.run(ep).await })
        };

        server_ep.close().await.expect("close");
        let outcome = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("run() must return once the endpoint is closed")
            .expect("the accept loop task must not panic");
        assert!(
            matches!(outcome, Err(InboxError::Transport(P2pError::Closed))),
            "a closed endpoint must still surface the transport error \
             `run()` has always returned, so a supervisor's exit status is \
             unchanged; got {outcome:?}"
        );
    }
}
