/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

//! One-shot PQ-FS sealed envelope (PQ-FS phase 2c). Ties the blended key
//! schedule of [`crate::prekey`] and the inbox `FETCH`/`PUBLISH` ops of
//! [`crate::network::inbox`] into a complete async one-shot flow. See
//! `PQFS_DESIGN.md` §3.2.
//!
//! ## Sender
//!
//! 1. `FETCH` a One-Time Prekey for the recipient from the inbox DS,
//! 2. verify its ML-DSA-65 signature against the recipient's *already
//!    trusted* identity key (the untrusted DS cannot substitute a prekey),
//! 3. blend a static-key encapsulation (reachability) with the prekey
//!    encapsulation (the source of forward secrecy) into a session key,
//! 4. AEAD-seal the payload, authenticating the schedule **mode** in the
//!    AAD so a full-FS envelope can never be silently downgraded.
//!
//! When no prekey is available (depleted pool or a FETCH throttle) the
//! [`FsProfile`] decides: `DefaultFallback` seals static-only with a loud
//! warning (availability first, no PQ-FS), `StrictPqFs` refuses
//! ([`OneShotError::NoPrekeyStrict`]) so a downgrade can never be forced.
//!
//! ## Recipient
//!
//! [`open`] derives the same session key — loading the matching prekey
//! private key from the [`PrekeyStore`] by id for full mode — and decrypts.
//! Only **after** the AEAD tag verifies is the one-time prekey deleted
//! ([`PrekeyStore::delete`]), so a forged ciphertext can neither drain the
//! pool nor be replayed (a second open finds no private key). A later
//! compromise of the recipient's *static* key alone cannot reconstruct a
//! full-mode session key — that is the post-quantum forward secrecy.
//!
//! A static-only envelope consumes no prekey, so it gets the equivalent
//! single-use gate from the store's seen-envelope cache
//! ([`PrekeyStore::record_static_only_seen`]), likewise recorded only after
//! the tag verifies: the untrusted DS cannot make one envelope decrypt twice.
//! That closes the *replay* half of a DS-forced downgrade. It does not
//! restore forward secrecy — only a real prekey can, and whether a
//! downgraded envelope is accepted at all remains the [`FsProfile`] policy.
//! The downgrade itself stays the DS's to force, but no longer silently: a
//! static-only envelope arriving while our *own* pool is stocked means the
//! DS answered the sender's FETCH "no prekey" — depleted, or throttled —
//! though we had stocked one, and [`open`] says so on stderr. That is a
//! signal worth investigating rather than proof of a lie: the server-side
//! pool also empties without our local keys being consumed whenever a FETCH
//! is followed by a deposit that fails or is refused, each of which burns a
//! published prekey and delivers nothing.
//!
//! ## Envelope wire format
//!
//! ```text
//! magic(4 = "NKO1") || version(1) || mode(1)
//!   [ mode == FULL only:  prekey_id(4 BE) || prekey_pub_len(4 LE) || prekey_pub ]
//!   enc_static_len(4 LE) || enc_static
//!   [ mode == FULL only:  enc_prekey_len(4 LE) || enc_prekey ]
//!   salt(16) || nonce(12) || ciphertext_and_tag
//! ```
//!
//! `prekey_pub` is the recipient's own published (hence public) prekey key;
//! it is carried because mls-rs's DHKEM mixes the recipient public key into
//! the KEM context, and the recipient cannot derive it from the stored
//! private key. A tampered `prekey_pub` only yields a different KEM context
//! → key mismatch → AEAD failure, so it cannot be abused.

use crate::network::inbox::{self, FetchOutcome};
use crate::p2p::{P2pEndpoint, PeerAddr, PeerId};
use crate::prekey::{
    self, peer_id_from_dsa_pub, recipient_key_schedule, sender_key_schedule, PrekeyError,
    PrekeyStore, SignedPrekey, MODE_FULL, MODE_STATIC_ONLY, XWING_PK_LEN,
};
use crate::strategy::streaming_aead::{aead_decrypt_chunk, aead_encrypt_chunk, V3_NONCE_LEN};
use crate::ticket::Ticket;
use data_encoding::HEXLOWER;
use mls_rs_core::crypto::{HpkePublicKey, HpkeSecretKey};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"NKO1";
const VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = V3_NONCE_LEN; // 12
const AEAD_ALGO: &str = "AES-256-GCM";

/// Upper bound on a serialized HPKE encapsulation. X-Wing enc is
/// X25519 (32 B) ‖ ML-KEM-768 ct (1088 B) = 1120 B; the cap rejects bogus
/// lengths well before allocating.
const MAX_ENC_LEN: usize = 4 * 1024;

/// Upper bound on a whole envelope, matching the inbox transport cap so a
/// crafted envelope cannot make `open` allocate beyond what the delivery
/// layer would already accept.
const MAX_ENVELOPE: usize = inbox::MAX_PAYLOAD;

/// What to do when the recipient has no One-Time Prekey to fetch. Decided by
/// the operator's security profile (`PQFS_DESIGN.md` §確定事項 #3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsProfile {
    /// Availability first: seal with the static key only (no PQ-FS) and warn.
    DefaultFallback,
    /// Forward secrecy first: refuse to seal rather than downgrade.
    StrictPqFs,
}

/// Errors from sealing or opening a one-shot PQ-FS envelope.
#[derive(thiserror::Error, Debug)]
pub enum OneShotError {
    #[error("prekey: {0}")]
    Prekey(#[from] PrekeyError),
    #[error("inbox: {0}")]
    Inbox(#[from] inbox::InboxError),
    #[error("aead/crypto: {0}")]
    Crypto(#[from] crate::error::CryptoError),
    #[error("envelope format: {0}")]
    Format(String),
    #[error("fetched prekey signature does not verify against the recipient identity")]
    PrekeyUntrusted,
    #[error("strict PQ-FS profile: no prekey available for recipient (depleted or throttled)")]
    NoPrekeyStrict,
    #[error("strict PQ-FS profile: refusing a static-only (no forward secrecy) envelope")]
    DowngradeRejected,
    #[error("prekey {0} not in store (consumed, replayed, or unknown) — cannot decrypt")]
    PrekeyMissing(u32),
    #[error(
        "static-only envelope has already been opened by this recipient \
         (re-delivered by the delivery service) — refusing to return the plaintext twice"
    )]
    StaticOnlyReplay,
    #[error("recipient bundle: {0}")]
    Bundle(String),
    #[error("recipient bundle self-signature does not verify (corrupt or tampered)")]
    BundleUntrusted,
    #[error("recipient fingerprint mismatch: bundle is {got}, expected {want}")]
    FingerprintMismatch { got: String, want: String },
}

type Result<T> = std::result::Result<T, OneShotError>;

/// The output of a seal: the envelope bytes to deliver (e.g. via
/// [`inbox::deposit`]) and which key-schedule mode was used, so the caller
/// can tell whether full PQ-FS was achieved or it fell back to static-only.
#[derive(Debug)]
pub struct Sealed {
    pub envelope: Vec<u8>,
    pub mode: u8,
}

/// The AAD that authenticates the schedule mode (and prekey id, for full
/// mode). Recomputed identically on open; binding the mode here is
/// belt-and-suspenders over the domain-separated HKDF `info` that already
/// makes the two modes' session keys independent.
fn build_aad(mode: u8, prekey_id: Option<u32>) -> Vec<u8> {
    let mut aad = Vec::with_capacity(MAGIC.len() + 1 + 1 + 4);
    aad.extend_from_slice(MAGIC);
    aad.push(VERSION);
    aad.push(mode);
    if let Some(id) = prekey_id {
        aad.extend_from_slice(&id.to_be_bytes());
    }
    aad
}

/// Seal `payload` to the recipient's static X-Wing key, blending a verified
/// One-Time Prekey when supplied (`Some((prekey_id, prekey_pub))`) for full
/// PQ-FS, or sealing static-only when `None`. Pure (no I/O); the network
/// orchestration lives in [`seal_via_inbox`].
pub fn seal(
    static_pk: &HpkePublicKey,
    prekey: Option<(u32, &HpkePublicKey)>,
    payload: &[u8],
) -> Result<Sealed> {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let sched = sender_key_schedule(static_pk, prekey.map(|(_, pk)| pk), &salt)?;
    let prekey_id = prekey.map(|(id, _)| id);

    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let aad = build_aad(sched.mode, prekey_id);
    let ct = aead_encrypt_chunk(AEAD_ALGO, sched.session_key.as_slice(), &nonce, &aad, payload)?;

    let mut env = Vec::new();
    env.extend_from_slice(MAGIC);
    env.push(VERSION);
    env.push(sched.mode);
    if sched.mode == MODE_FULL {
        let (id, pk) = prekey.expect("full mode implies a prekey");
        env.extend_from_slice(&id.to_be_bytes());
        put_vec(&mut env, pk.as_ref());
    }
    put_vec(&mut env, &sched.enc_static);
    if let Some(enc_prekey) = sched.enc_prekey.as_deref() {
        put_vec(&mut env, enc_prekey);
    }
    env.extend_from_slice(&salt);
    env.extend_from_slice(&nonce);
    env.extend_from_slice(&ct);
    Ok(Sealed { envelope: env, mode: sched.mode })
}

/// Fetch a prekey for `recipient`, verify it against the recipient's
/// `identity_dsa_pub`, and seal `payload` for full PQ-FS — or apply the
/// `profile`'s fallback when the prekey pool is depleted/throttled.
///
/// Exactly **one** FETCH is issued per call, whatever the answer. A throttle
/// (the per-NodeId FETCH bucket, or the delivery service's per-recipient prekey
/// reserve) is transient and a retry would sometimes recover full PQ-FS, but
/// the server charges the *fetcher's* own bucket before it consults the
/// recipient's reserve, so retrying would let one throttled recipient drain
/// this sender's budget and downgrade its later, unrelated messages. A
/// throttled FETCH therefore takes the same branch as a depleted pool, and the
/// `profile` decides: [`FsProfile::DefaultFallback`] seals static-only and
/// sends (availability first), [`FsProfile::StrictPqFs`] aborts.
///
/// `static_pk` is the recipient's long-term X-Wing public key (the caller
/// supplies it; long-term key management is out of this module's scope).
#[allow(clippy::too_many_arguments)]
pub async fn seal_via_inbox(
    endpoint: &dyn P2pEndpoint,
    server: &PeerAddr,
    recipient: PeerId,
    identity_dsa_pub: &[u8],
    static_pk: &HpkePublicKey,
    payload: &[u8],
    profile: FsProfile,
) -> Result<Sealed> {
    match inbox::fetch_prekey(endpoint, server, recipient).await? {
        FetchOutcome::Prekey(blob) => {
            let (sp, _) = SignedPrekey::from_bytes(&blob)?;
            // Keep the untrusted DS honest: a substituted prekey fails here.
            if !sp.verify(identity_dsa_pub)? {
                return Err(OneShotError::PrekeyUntrusted);
            }
            let pk = HpkePublicKey::from(sp.xwing_pub);
            seal(static_pk, Some((sp.prekey_id, &pk)), payload)
        }
        FetchOutcome::Depleted | FetchOutcome::RateLimited => match profile {
            FsProfile::StrictPqFs => Err(OneShotError::NoPrekeyStrict),
            FsProfile::DefaultFallback => {
                eprintln!(
                    "[pqfs] WARNING: no One-Time Prekey for recipient \
                     (pool depleted or fetch throttled); sealing STATIC-ONLY \
                     — this message has NO post-quantum forward secrecy"
                );
                seal(static_pk, None, payload)
            }
        },
    }
}

struct Parsed {
    mode: u8,
    prekey_id: Option<u32>,
    prekey_pub: Option<Vec<u8>>,
    enc_static: Vec<u8>,
    enc_prekey: Option<Vec<u8>>,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    ct: Vec<u8>,
}

/// Open an envelope produced by [`seal`]. For full mode, loads the matching
/// prekey private key from `store`, decrypts, and — only on a verified
/// decrypt — deletes that one-time key so it can never be reused. For
/// static-only mode, which has no key to consume, the verified envelope is
/// instead recorded in `store`'s seen-envelope cache, so a re-delivered copy
/// is refused with [`OneShotError::StaticOnlyReplay`] rather than decrypted
/// again. Returns the plaintext in a `Zeroizing` buffer.
///
/// `profile` is the *recipient's* policy: under [`FsProfile::StrictPqFs`] a
/// static-only (no forward secrecy) envelope is refused
/// ([`OneShotError::DowngradeRejected`]) rather than silently accepted — the
/// receive-side backstop against a sender being forced to downgrade by a
/// prekey-depletion attack. [`FsProfile::DefaultFallback`] accepts both, but
/// warns on stderr when an accepted static-only envelope contradicts our own
/// still-stocked pool (see `warn_static_only_with_stocked_pool`).
pub fn open(
    static_sk: &HpkeSecretKey,
    static_pk: &HpkePublicKey,
    store: &PrekeyStore,
    envelope: &[u8],
    profile: FsProfile,
) -> Result<Zeroizing<Vec<u8>>> {
    let p = parse(envelope)?;
    if profile == FsProfile::StrictPqFs && p.mode == MODE_STATIC_ONLY {
        return Err(OneShotError::DowngradeRejected);
    }
    let aad = build_aad(p.mode, p.prekey_id);

    let session_key = match p.mode {
        // Replay note (audit L5): static-only has no per-message prekey to
        // consume, so — unlike MODE_FULL, where a second open finds the prekey
        // already deleted — nothing in the key schedule stops a re-delivery.
        // The equivalent single-use gate is the store's seen-envelope cache,
        // applied after the AEAD verifies (see the end of this fn). It still
        // provides no forward secrecy: that remains policy
        // (`FsProfile::StrictPqFs` refuses static-only outright).
        MODE_STATIC_ONLY => recipient_key_schedule(
            MODE_STATIC_ONLY,
            static_sk,
            static_pk,
            &p.enc_static,
            None,
            &p.salt,
        )?,
        MODE_FULL => {
            let prekey_id = p
                .prekey_id
                .ok_or_else(|| OneShotError::Format("full mode missing prekey_id".into()))?;
            let enc_prekey = p
                .enc_prekey
                .as_deref()
                .ok_or_else(|| OneShotError::Format("full mode missing enc_prekey".into()))?;
            let prekey_pub = p
                .prekey_pub
                .clone()
                .ok_or_else(|| OneShotError::Format("full mode missing prekey_pub".into()))?;
            // The private key is loaded read-only; it is deleted below only
            // after a successful AEAD verify (PQFS_DESIGN.md §4.2).
            let psk = store
                .load(prekey_id)?
                .ok_or(OneShotError::PrekeyMissing(prekey_id))?;
            let ppk = HpkePublicKey::from(prekey_pub);
            recipient_key_schedule(
                MODE_FULL,
                static_sk,
                static_pk,
                &p.enc_static,
                Some((&psk, &ppk, enc_prekey)),
                &p.salt,
            )?
            // `psk` (ZeroizeOnDrop) is wiped from the heap at end of this arm.
        }
        other => return Err(OneShotError::Format(format!("unknown mode {other}"))),
    };

    // A tag failure returns Err here, *before* the delete below, so a forged
    // ciphertext can neither drain the pool nor be replayed-and-deleted.
    let plaintext = aead_decrypt_chunk(AEAD_ALGO, session_key.as_slice(), &p.nonce, &aad, &p.ct)?;

    // Retire the one-time prekey now that the message has verified. The DELETE
    // is the serialization point against a replay race: if two opens of the
    // same envelope run concurrently (e.g. via two PrekeyStore connections on
    // one DB file), both may load+decrypt, but SQLite serializes the writes so
    // only one DELETE removes a row. A 0-row delete means another open already
    // consumed this single-use key, so we refuse to return a replayed plaintext
    // rather than accept the message twice.
    if let Some(id) = p.prekey_id {
        if !store.delete(id)? {
            return Err(OneShotError::PrekeyMissing(id));
        }
    }

    // Static-only mode consumes no prekey, so the delete above never runs for
    // it and an untrusted delivery service — which chooses, with one
    // unauthenticated FETCH reply byte, whether the sender downgrades at all —
    // could otherwise re-deliver the same envelope indefinitely and have it
    // accepted every time. Give it the equivalent single-use gate. Recorded
    // only *now*, after the AEAD tag has verified, so a forged envelope cannot
    // put junk in the cache; the check-and-insert is one redb write
    // transaction, so concurrent opens of the same envelope serialize and only
    // the first returns its plaintext.
    if p.mode == MODE_STATIC_ONLY {
        if store.record_static_only_seen(envelope)? {
            return Err(OneShotError::StaticOnlyReplay);
        }
        // We are the only party holding both facts: the sender was told no
        // prekey was available, and we know what our own pool holds. Propagate a
        // `count` failure like every other store call here rather than
        // swallowing it — the same handle committed the write above, so a
        // failure now is a broken store the recipient needs to hear about, not a
        // diagnostic to skip.
        let remaining = store.count()?;
        if remaining > 0 {
            warn_static_only_with_stocked_pool(remaining);
        }
    }
    Ok(plaintext)
}

/// Warn that an accepted static-only envelope arrived while our own prekey pool
/// still holds unused keys.
///
/// A sender falls back to static-only only when the delivery service answers its
/// prekey FETCH `REPLY_PREKEY_NONE` (depleted) or `REPLY_RATE_LIMITED`
/// (throttled), so the two facts together — a downgraded envelope, and
/// `remaining` unused prekeys of ours — say the DS served no prekey for a pool
/// we had stocked. That makes the forward-secrecy downgrade — which remains the
/// DS's to force, and which only [`FsProfile::StrictPqFs`] refuses — *visible*
/// to the one party holding both facts, instead of silent.
///
/// It does **not** establish that the DS lied, and deliberately no longer says
/// so. The pool it draws from is the *server-side* one, and that can empty
/// while our local secret keys stay untouched: every FETCH hands out a
/// published prekey before the sender knows its DEPOSIT will be accepted, so
/// each send whose deposit then fails — a network error, or a deposit the relay
/// **refused** because the recipient's slot was full or a byte budget was spent
/// (see [`crate::group::redb_storage::RedbInboxStore::deposit`]) — burns one
/// prekey and delivers nothing. An attacker holding a victim's slot can drive
/// exactly that, until the server's pool is genuinely empty and the DS's
/// `REPLY_PREKEY_NONE` is honest.
///
/// A warning and not a refusal, because every reading of it is one an honest
/// exchange also produces: the pool genuinely ran dry, the sender fell back, and
/// we restocked before polling; the server's per-recipient reserve throttled the
/// sender precisely *because* the pool had been drawn into its reserve band; or
/// the burn-without-delivery above. Turning it into an error would drop
/// legitimate mail on all of them.
fn warn_static_only_with_stocked_pool(remaining: u64) {
    // Local data only (a count from our own store); no peer-controlled text
    // reaches the terminal here.
    eprintln!(
        "[pqfs] WARNING: accepted a STATIC-ONLY envelope (no post-quantum forward \
         secrecy) while {remaining} One-Time Prekey(s) remain in the local pool. \
         The delivery service served the sender no prekey though we had stocked \
         one. It may have lied to force this downgrade; it may have throttled \
         the sender while our server-side pool sat in its per-recipient reserve \
         band; the pool may have been restocked after the message was sealed; or \
         published prekeys may have been drawn by senders whose deposits then \
         failed or were refused, which empties the server's pool without \
         consuming ours. Worth investigating, not proof of a lie. Use \
         --strict-pqfs to refuse downgraded envelopes outright."
    );
    #[cfg(test)]
    STOCKED_POOL_WARNINGS.with(|c| c.set(c.get() + 1));
}

// Test-only observation point for `warn_static_only_with_stocked_pool`, so the
// unit tests can assert the warning fires on a stocked pool and stays quiet on
// a genuinely depleted one. Thread-local: each `#[test]` runs on its own
// thread, so a parallel test run cannot cross-count.
#[cfg(test)]
thread_local! {
    static STOCKED_POOL_WARNINGS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Generate `count` fresh One-Time Prekeys, persist their private keys in
/// `store` (continuing the monotonic id sequence), and return the signed
/// public bundle ready to hand to [`inbox::publish_prekeys`]. The recipient
/// calls this to (re)stock its pool.
pub fn generate_and_store(
    store: &PrekeyStore,
    dsa_priv: &[u8],
    count: u32,
) -> Result<Vec<Vec<u8>>> {
    let start = store.reserve_ids(count)?;
    let batch = prekey::generate(count, start, dsa_priv)?;
    let mut bundle = Vec::with_capacity(batch.len());
    for g in &batch {
        store.insert(g.signed.prekey_id, g.xwing_priv.as_ref())?;
        bundle.push(g.signed.to_bytes());
    }
    Ok(bundle)
}

/// Outcome of [`replenish_to_target`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplenishReport {
    /// Prekeys the server reported holding for us *before* this top-up.
    pub server_before: u32,
    /// Fresh prekeys generated, stored, and published this call (the deficit).
    pub published: u32,
    /// The (clamped) target pool size aimed for.
    pub target: u32,
}

/// Auto-replenish: top the recipient's **server-side** prekey pool back up to
/// `target`. Queries the inbox for how many of our prekeys remain (the
/// semi-trusted COUNT hint — [`inbox::count_prekeys`]), generates and stores
/// the deficit locally, then PUBLISHes it, chunked to respect
/// [`inbox::MAX_PUBLISH_BATCH`].
///
/// `target` is clamped to [`inbox::MAX_PREKEYS_STORED`]: the server evicts
/// beyond that, so aiming higher would only orphan local private keys whose
/// public was dropped server-side and can never be fetched.
///
/// Idempotent in steady state — when the pool already meets `target` nothing
/// is generated or published. This availability mechanism deliberately trusts
/// the COUNT hint; the *downgrade* defense does not (a lying or hostile server
/// is bounded by sender-side FETCH rate limiting + the Strict profile, and can
/// already drain the pool outright). See `PQFS_DESIGN.md` §4.1.
pub async fn replenish_to_target(
    endpoint: &dyn P2pEndpoint,
    inbox_server: &PeerAddr,
    store: &PrekeyStore,
    dsa_priv: &[u8],
    target: u32,
) -> Result<ReplenishReport> {
    let target = target.min(inbox::MAX_PREKEYS_STORED as u32);
    let server_before = inbox::count_prekeys(endpoint, inbox_server).await?;
    let deficit = target.saturating_sub(server_before);
    if deficit == 0 {
        return Ok(ReplenishReport { server_before, published: 0, target });
    }
    // Generate + store the whole deficit locally first, then PUBLISH in batches
    // the server will accept. If a later chunk's publish fails, the earlier
    // chunks are already up and the unsent privates are simply stored locally
    // (orphaned, harmless) — never a half-built prekey.
    let bundle = generate_and_store(store, dsa_priv, deficit)?;
    for chunk in bundle.chunks(inbox::MAX_PUBLISH_BATCH as usize) {
        inbox::publish_prekeys(endpoint, inbox_server, chunk).await?;
    }
    Ok(ReplenishReport { server_before, published: deficit, target })
}

// ----- recipient bundle (discovery) ------------------------------------------

const BUNDLE_MAGIC: &[u8; 4] = b"NKB1";
const BUNDLE_VERSION: u8 = 1;
/// FIPS 204 **native** signature context for the recipient-bundle self-signature
/// (KEY_EXCHANGE_DESIGN.md §11). Migrated from a byte-prefix mixed into the
/// message to a native ML-DSA ctx (same reason as prekey, §11.1): a byte-prefix
/// under `ctx=""` does not separate this identity-key signature from the still-
/// `ctx=""` file signature, so a file signature over crafted bytes could be
/// replayed as a recipient bundle. A distinct native ctx closes that. Do NOT
/// also prepend it to the message (that would re-mix the two mechanisms).
const BUNDLE_CTX: &[u8] = b"nkct-recipient-bundle-v1";
/// ML-DSA-65 public keys are 1952 B; the cap rejects a bogus length before
/// any large copy.
const MAX_DSA_PUB_LEN: usize = 4 * 1024;
/// A `nkct1…` ticket is well under this; the cap bounds the parse.
const MAX_TICKET_LEN: usize = 4 * 1024;
/// ML-DSA-65 signatures are 3309 B.
const MAX_BUNDLE_SIG_LEN: usize = 8 * 1024;

/// Everything a sender needs to address and encrypt to a recipient, bound
/// together and self-signed under the recipient's ML-DSA-65 identity:
///
/// * `dsa_pub` — the identity key; verifies fetched prekeys and is the
///   thing the sender pins by fingerprint.
/// * `static_xwing_pub` — the long-term reachability/fallback KEM key.
/// * `node_id` — the recipient's stable iroh NodeId, i.e. its inbox slot.
/// * `inbox_ticket` — the (semi-trusted) inbox Delivery Service to use.
///
/// The self-signature binds these four together so a substituted
/// `static_xwing_pub` (which would let an attacker read a static-only
/// fallback envelope) or a redirected `node_id`/`inbox_ticket` cannot be
/// forged without the identity key. It does **not** by itself establish
/// that `dsa_pub` is the identity you mean to reach — for that the sender
/// compares [`fingerprint`](Self::fingerprint) against an out-of-band
/// trusted value (see `seal` in the CLI).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecipientBundle {
    pub dsa_pub: Vec<u8>,
    pub static_xwing_pub: Vec<u8>,
    pub node_id: [u8; 32],
    pub inbox_ticket: String,
}

impl RecipientBundle {
    /// Build and self-sign a bundle. `dsa_priv` is the raw ML-DSA-65 private
    /// key (as [`prekey::generate`] consumes); the matching public key is
    /// derived here so the signed identity always agrees with the signer.
    pub fn build_signed(
        dsa_priv: &[u8],
        static_xwing_pub: &HpkePublicKey,
        node_id: [u8; 32],
        inbox_ticket: &str,
    ) -> Result<Vec<u8>> {
        let static_pk = static_xwing_pub.as_ref();
        if static_pk.len() != XWING_PK_LEN {
            return Err(OneShotError::Bundle(format!(
                "static X-Wing pub is {} B, expected {XWING_PK_LEN}",
                static_pk.len()
            )));
        }
        // Bound the variable-length fields *before* the u16 length-prefix
        // casts so an over-long input is rejected cleanly rather than
        // silently truncating the prefix into a corrupt (unparseable)
        // bundle. The same caps are enforced on parse.
        if inbox_ticket.len() > MAX_TICKET_LEN {
            return Err(OneShotError::Bundle(format!(
                "inbox ticket is {} B, exceeds max {MAX_TICKET_LEN}",
                inbox_ticket.len()
            )));
        }
        let dsa_pub = crate::backend::pqc_pub_from_priv_dsa(prekey::PREKEY_SIGN_ALGO, dsa_priv)
            .map_err(OneShotError::Crypto)?;
        if dsa_pub.is_empty() || dsa_pub.len() > MAX_DSA_PUB_LEN {
            return Err(OneShotError::Bundle(format!(
                "identity public key is {} B, out of range 1..={MAX_DSA_PUB_LEN}",
                dsa_pub.len()
            )));
        }
        let payload = Self::payload_bytes(&dsa_pub, static_pk, &node_id, inbox_ticket);
        // Domain separation is the native BUNDLE_CTX; the payload is signed directly.
        let sig = crate::backend::pqc_sign(prekey::PREKEY_SIGN_ALGO, dsa_priv, &payload, BUNDLE_CTX)
            .map_err(OneShotError::Crypto)?;
        let mut out = payload;
        out.extend_from_slice(&(sig.len() as u32).to_le_bytes());
        out.extend_from_slice(&sig);
        Ok(out)
    }

    /// Parse a bundle and verify its self-signature. A bad signature yields
    /// [`OneShotError::BundleUntrusted`]. The caller should additionally pin
    /// [`fingerprint`](Self::fingerprint) against a trusted value.
    pub fn parse_and_verify(buf: &[u8]) -> Result<Self> {
        let mut o = 0usize;
        let take = |o: &mut usize, n: usize| -> Result<&[u8]> {
            let end = o
                .checked_add(n)
                .ok_or_else(|| OneShotError::Bundle("length overflow".into()))?;
            if end > buf.len() {
                return Err(OneShotError::Bundle("truncated bundle".into()));
            }
            let s = &buf[*o..end];
            *o = end;
            Ok(s)
        };
        if take(&mut o, 4)? != BUNDLE_MAGIC {
            return Err(OneShotError::Bundle("bad magic".into()));
        }
        let version = take(&mut o, 1)?[0];
        if version != BUNDLE_VERSION {
            return Err(OneShotError::Bundle(format!("unsupported version {version}")));
        }
        let dsa_len = u16::from_le_bytes(take(&mut o, 2)?.try_into().unwrap()) as usize;
        if dsa_len == 0 || dsa_len > MAX_DSA_PUB_LEN {
            return Err(OneShotError::Bundle(format!("dsa pub len {dsa_len} out of range")));
        }
        let dsa_pub = take(&mut o, dsa_len)?.to_vec();
        let static_xwing_pub = take(&mut o, XWING_PK_LEN)?.to_vec();
        let mut node_id = [0u8; 32];
        node_id.copy_from_slice(take(&mut o, 32)?);
        let ticket_len = u16::from_le_bytes(take(&mut o, 2)?.try_into().unwrap()) as usize;
        if ticket_len == 0 || ticket_len > MAX_TICKET_LEN {
            return Err(OneShotError::Bundle(format!("ticket len {ticket_len} out of range")));
        }
        let ticket_bytes = take(&mut o, ticket_len)?.to_vec();
        let inbox_ticket = String::from_utf8(ticket_bytes)
            .map_err(|_| OneShotError::Bundle("inbox ticket is not UTF-8".into()))?;

        // The signed region is exactly the bytes parsed so far (everything
        // before sig_len), prefixed by the domain separator.
        let payload = &buf[..o];
        let sig_len = u32::from_le_bytes(take(&mut o, 4)?.try_into().unwrap()) as usize;
        if sig_len == 0 || sig_len > MAX_BUNDLE_SIG_LEN {
            return Err(OneShotError::Bundle(format!("sig len {sig_len} out of range")));
        }
        let sig = take(&mut o, sig_len)?;
        // Reject trailing bytes: the signature covers only `payload`, so any
        // appended data would otherwise ride along as a second valid encoding
        // of the same bundle (malleability). A well-formed bundle ends here.
        if o != buf.len() {
            return Err(OneShotError::Bundle(format!(
                "{} trailing byte(s) after bundle signature",
                buf.len() - o
            )));
        }
        // Domain separation is the native BUNDLE_CTX; the payload is verified directly.
        let ok = crate::backend::pqc_verify(prekey::PREKEY_SIGN_ALGO, &dsa_pub, payload, sig, BUNDLE_CTX)
            .map_err(OneShotError::Crypto)?;
        if !ok {
            return Err(OneShotError::BundleUntrusted);
        }
        Ok(Self { dsa_pub, static_xwing_pub, node_id, inbox_ticket })
    }

    fn payload_bytes(
        dsa_pub: &[u8],
        static_xwing_pub: &[u8],
        node_id: &[u8; 32],
        inbox_ticket: &str,
    ) -> Vec<u8> {
        let mut p = Vec::with_capacity(
            4 + 1 + 2 + dsa_pub.len() + XWING_PK_LEN + 32 + 2 + inbox_ticket.len(),
        );
        p.extend_from_slice(BUNDLE_MAGIC);
        p.push(BUNDLE_VERSION);
        p.extend_from_slice(&(dsa_pub.len() as u16).to_le_bytes());
        p.extend_from_slice(dsa_pub);
        p.extend_from_slice(static_xwing_pub);
        p.extend_from_slice(node_id);
        p.extend_from_slice(&(inbox_ticket.len() as u16).to_le_bytes());
        p.extend_from_slice(inbox_ticket.as_bytes());
        p
    }

    /// The recipient identity fingerprint, `SHA3-256(dsa_pub)` as lowercase
    /// hex — the value a sender pins out-of-band (matches the P2P PeerId and
    /// `--fingerprint`).
    pub fn fingerprint(&self) -> String {
        HEXLOWER.encode(&peer_id_from_dsa_pub(&self.dsa_pub))
    }

    /// The recipient's inbox slot address (its stable iroh NodeId).
    pub fn recipient_peer_id(&self) -> PeerId {
        PeerId::new(self.node_id)
    }

    /// The recipient's long-term static X-Wing public key.
    pub fn static_pk(&self) -> HpkePublicKey {
        HpkePublicKey::from(self.static_xwing_pub.clone())
    }

    /// The inbox Delivery Service address parsed from the embedded ticket.
    pub fn inbox_addr(&self) -> Result<PeerAddr> {
        let ticket: Ticket = self
            .inbox_ticket
            .parse()
            .map_err(|e| OneShotError::Bundle(format!("invalid inbox ticket: {e}")))?;
        Ok(ticket.peer_addr())
    }
}

// ----- end-to-end orchestration ----------------------------------------------

/// Fetch a prekey, seal `payload` for the recipient described by `bundle`,
/// and deposit the envelope into the recipient's inbox slot — the complete
/// sender side. `bundle` must already be verified
/// ([`RecipientBundle::parse_and_verify`]) and fingerprint-pinned by the
/// caller. Returns the [`Sealed`] so the caller can report whether full
/// PQ-FS was achieved or it fell back to static-only.
pub async fn seal_and_deposit(
    endpoint: &dyn P2pEndpoint,
    bundle: &RecipientBundle,
    payload: &[u8],
    profile: FsProfile,
) -> Result<Sealed> {
    let inbox_server = bundle.inbox_addr()?;
    let recipient = bundle.recipient_peer_id();
    let static_pk = bundle.static_pk();
    let sealed = seal_via_inbox(
        endpoint,
        &inbox_server,
        recipient,
        &bundle.dsa_pub,
        &static_pk,
        payload,
        profile,
    )
    .await?;
    inbox::deposit(endpoint, &inbox_server, recipient, &sealed.envelope).await?;
    Ok(sealed)
}

/// One opened (or failed) inbox envelope, paired with its poll cursor so the
/// caller can persist progress even across a mix of successes and failures.
pub struct Received {
    pub cursor: u64,
    pub result: Result<Zeroizing<Vec<u8>>>,
}

/// Poll the inbox once from `since_cursor` and attempt to [`open`] every
/// envelope addressed to us — the complete receiver side. Each envelope is
/// opened independently (a bad/foreign/replayed one does not abort the
/// batch); the returned new cursor should be persisted
/// ([`PrekeyStore::set_inbox_cursor`]) so the next poll resumes after it.
pub async fn receive(
    endpoint: &dyn P2pEndpoint,
    inbox_server: &PeerAddr,
    static_sk: &HpkeSecretKey,
    static_pk: &HpkePublicKey,
    store: &PrekeyStore,
    since_cursor: u64,
    profile: FsProfile,
) -> Result<(u64, Vec<Received>)> {
    let (cursor, envelopes) = inbox::poll(endpoint, inbox_server, since_cursor).await?;
    let mut out = Vec::with_capacity(envelopes.len());
    for env in &envelopes {
        let result = open(static_sk, static_pk, store, env, profile);
        // The per-envelope cursor is not returned by `poll`; the batch cursor
        // is monotonic, so on a resume from `cursor` any unprocessed envelope
        // is re-polled. Pair each result with the batch cursor for the
        // caller's bookkeeping.
        out.push(Received { cursor, result });
    }
    Ok((cursor, out))
}

// ----- wire helpers ----------------------------------------------------------

fn put_vec(out: &mut Vec<u8>, v: &[u8]) {
    out.extend_from_slice(&(v.len() as u32).to_le_bytes());
    out.extend_from_slice(v);
}

fn parse(buf: &[u8]) -> Result<Parsed> {
    if buf.len() > MAX_ENVELOPE {
        return Err(OneShotError::Format(format!(
            "envelope {} B exceeds max {MAX_ENVELOPE}",
            buf.len()
        )));
    }
    let mut o = 0usize;
    let take = |o: &mut usize, n: usize| -> Result<&[u8]> {
        let end = o
            .checked_add(n)
            .ok_or_else(|| OneShotError::Format("length overflow".into()))?;
        if end > buf.len() {
            return Err(OneShotError::Format("truncated envelope".into()));
        }
        let s = &buf[*o..end];
        *o = end;
        Ok(s)
    };
    let take_vec = |o: &mut usize| -> Result<Vec<u8>> {
        let len = u32::from_le_bytes(take(o, 4)?.try_into().unwrap()) as usize;
        if len > MAX_ENC_LEN {
            return Err(OneShotError::Format(format!(
                "field len {len} exceeds max {MAX_ENC_LEN}"
            )));
        }
        Ok(take(o, len)?.to_vec())
    };

    if take(&mut o, 4)? != MAGIC {
        return Err(OneShotError::Format("bad magic".into()));
    }
    let version = take(&mut o, 1)?[0];
    if version != VERSION {
        return Err(OneShotError::Format(format!("unsupported version {version}")));
    }
    let mode = take(&mut o, 1)?[0];

    let (prekey_id, prekey_pub) = if mode == MODE_FULL {
        let id = u32::from_be_bytes(take(&mut o, 4)?.try_into().unwrap());
        let pub_len = u32::from_le_bytes(take(&mut o, 4)?.try_into().unwrap()) as usize;
        if pub_len != XWING_PK_LEN {
            return Err(OneShotError::Format(format!(
                "prekey pub is {pub_len} B, expected {XWING_PK_LEN}"
            )));
        }
        (Some(id), Some(take(&mut o, pub_len)?.to_vec()))
    } else {
        (None, None)
    };

    let enc_static = take_vec(&mut o)?;
    let enc_prekey = if mode == MODE_FULL { Some(take_vec(&mut o)?) } else { None };

    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(take(&mut o, SALT_LEN)?);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(take(&mut o, NONCE_LEN)?);
    let ct = buf[o..].to_vec();

    Ok(Parsed {
        mode,
        prekey_id,
        prekey_pub,
        enc_static,
        enc_prekey,
        salt,
        nonce,
        ct,
    })
}

#[cfg(all(test, feature = "mls"))]
mod tests {
    use super::*;
    use crate::group::crypto_adapter::build_at_rest_suite;
    use crate::p2p::backend::mock::MockNetwork;
    use crate::p2p::P2pProtocol;
    use crate::network::ALPN_INBOX;
    use crate::network::inbox::InboxServer;
    use mls_rs::CipherSuiteProvider;
    use std::sync::Arc;
    use tempfile::tempdir;

    /// A recipient: ML-DSA identity, long-term static X-Wing keypair, and a
    /// SQLCipher prekey store, plus the bundle published to the inbox.
    struct Recipient {
        dsa_priv: Zeroizing<Vec<u8>>,
        dsa_pub: Vec<u8>,
        peer_id: PeerId,
        static_sk: HpkeSecretKey,
        static_pk: HpkePublicKey,
        store: PrekeyStore,
    }

    fn make_recipient(dir: &std::path::Path) -> Recipient {
        let (dsa_priv, dsa_pub, _) = crate::backend::pqc_keygen_dsa("ML-DSA-65").unwrap();
        let peer_id = PeerId::new(prekey::peer_id_from_dsa_pub(&dsa_pub));
        let suite = build_at_rest_suite().unwrap();
        let (static_sk, static_pk) = suite.kem_generate().unwrap();
        let store = PrekeyStore::open(&dir.join("prekeys.db"), &[0x33u8; 32]).unwrap();
        Recipient { dsa_priv, dsa_pub, peer_id, static_sk, static_pk, store }
    }

    fn passphrase() -> Zeroizing<String> {
        Zeroizing::new("nkct-one-shot-test".to_string())
    }

    async fn spawn_inbox(
        net: &Arc<MockNetwork>,
        dir: &std::path::Path,
    ) -> (tokio::task::JoinHandle<()>, PeerAddr) {
        let ep =
            Arc::new(net.register(PeerId::new([99u8; 32]), vec![P2pProtocol(ALPN_INBOX)]))
                as Arc<dyn P2pEndpoint>;
        let server =
            Arc::new(InboxServer::open(dir.join("inbox.db"), &passphrase()).expect("open inbox"));
        let task = tokio::spawn(async move {
            let _ = server.run(ep).await;
        });
        (task, PeerAddr::new(PeerId::new([99u8; 32])))
    }

    /// Full happy path: recipient stocks prekeys → publishes → sender seals
    /// (full mode) → recipient opens → plaintext matches; the prekey is
    /// consumed (a replay of the same envelope can no longer be opened).
    #[tokio::test]
    async fn full_pqfs_roundtrip_via_inbox() {
        let net = MockNetwork::new();
        let dir = tempdir().unwrap();
        let r = make_recipient(dir.path());
        let (task, srv) = spawn_inbox(&net, dir.path()).await;

        let sender =
            Arc::new(net.register(PeerId::new([1u8; 32]), vec![P2pProtocol(ALPN_INBOX)]))
                as Arc<dyn P2pEndpoint>;

        // Recipient stocks 5 prekeys and publishes the signed bundle. It must
        // publish through its *own* NodeId (= peer_id), since PUBLISH keys the
        // slot by the handshake NodeId — that is the slot a FETCH addresses.
        let recipient_ep =
            Arc::new(net.register(r.peer_id, vec![P2pProtocol(ALPN_INBOX)])) as Arc<dyn P2pEndpoint>;
        let bundle = generate_and_store(&r.store, &r.dsa_priv, 5).unwrap();
        assert_eq!(r.store.count().unwrap(), 5);
        inbox::publish_prekeys(recipient_ep.as_ref(), &srv, &bundle).await.unwrap();

        let msg = b"forward-secret one-shot payload";
        let sealed = seal_via_inbox(
            sender.as_ref(),
            &srv,
            r.peer_id,
            &r.dsa_pub,
            &r.static_pk,
            msg,
            FsProfile::StrictPqFs,
        )
        .await
        .unwrap();
        assert_eq!(sealed.mode, MODE_FULL);

        let opened =
            open(&r.static_sk, &r.static_pk, &r.store, &sealed.envelope, FsProfile::StrictPqFs)
                .unwrap();
        assert_eq!(opened.as_slice(), msg);
        // One-time: the prekey is gone, and the same envelope can't reopen.
        assert_eq!(r.store.count().unwrap(), 4);
        match open(&r.static_sk, &r.static_pk, &r.store, &sealed.envelope, FsProfile::StrictPqFs) {
            Err(OneShotError::PrekeyMissing(_)) => {}
            other => panic!("replay must fail with PrekeyMissing, got {other:?}"),
        }

        task.abort();
    }

    /// Auto-replenish tops the server pool up to the target, is idempotent
    /// once full, and after consumption refills exactly the deficit.
    #[tokio::test]
    async fn replenish_tops_up_to_target() {
        let net = MockNetwork::new();
        let dir = tempdir().unwrap();
        let r = make_recipient(dir.path());
        let (task, srv) = spawn_inbox(&net, dir.path()).await;
        let recipient_ep =
            Arc::new(net.register(r.peer_id, vec![P2pProtocol(ALPN_INBOX)])) as Arc<dyn P2pEndpoint>;
        let sender =
            Arc::new(net.register(PeerId::new([1u8; 32]), vec![P2pProtocol(ALPN_INBOX)]))
                as Arc<dyn P2pEndpoint>;

        // Empty pool → publishes the full target.
        let rep = replenish_to_target(recipient_ep.as_ref(), &srv, &r.store, &r.dsa_priv, 5)
            .await
            .unwrap();
        assert_eq!((rep.server_before, rep.published, rep.target), (0, 5, 5));
        assert_eq!(inbox::count_prekeys(recipient_ep.as_ref(), &srv).await.unwrap(), 5);

        // Already at target → idempotent, nothing generated or published.
        let rep = replenish_to_target(recipient_ep.as_ref(), &srv, &r.store, &r.dsa_priv, 5)
            .await
            .unwrap();
        assert_eq!((rep.server_before, rep.published), (5, 0));

        // Consume two from the server, then replenish refills exactly the gap.
        for _ in 0..2 {
            assert!(matches!(
                inbox::fetch_prekey(sender.as_ref(), &srv, r.peer_id).await.unwrap(),
                FetchOutcome::Prekey(_)
            ));
        }
        let rep = replenish_to_target(recipient_ep.as_ref(), &srv, &r.store, &r.dsa_priv, 5)
            .await
            .unwrap();
        assert_eq!((rep.server_before, rep.published), (3, 2));
        assert_eq!(inbox::count_prekeys(recipient_ep.as_ref(), &srv).await.unwrap(), 5);

        task.abort();
    }

    /// With an empty pool, DefaultFallback seals static-only (openable, no
    /// FS) while StrictPqFs refuses outright.
    #[tokio::test]
    async fn depletion_fallback_vs_strict() {
        let net = MockNetwork::new();
        let dir = tempdir().unwrap();
        let r = make_recipient(dir.path());
        let (task, srv) = spawn_inbox(&net, dir.path()).await;
        let sender =
            Arc::new(net.register(PeerId::new([1u8; 32]), vec![P2pProtocol(ALPN_INBOX)]))
                as Arc<dyn P2pEndpoint>;

        // No prekeys published → pool depleted.
        let msg = b"availability-first payload";
        let sealed = seal_via_inbox(
            sender.as_ref(),
            &srv,
            r.peer_id,
            &r.dsa_pub,
            &r.static_pk,
            msg,
            FsProfile::DefaultFallback,
        )
        .await
        .unwrap();
        assert_eq!(sealed.mode, MODE_STATIC_ONLY);
        // A DefaultFallback recipient accepts the static-only envelope...
        let opened =
            open(&r.static_sk, &r.static_pk, &r.store, &sealed.envelope, FsProfile::DefaultFallback)
                .unwrap();
        assert_eq!(opened.as_slice(), msg);
        // ...but a StrictPqFs recipient refuses the downgrade.
        match open(&r.static_sk, &r.static_pk, &r.store, &sealed.envelope, FsProfile::StrictPqFs) {
            Err(OneShotError::DowngradeRejected) => {}
            other => panic!("strict recipient must reject static-only, got {other:?}"),
        }

        // Strict refuses rather than downgrade.
        match seal_via_inbox(
            sender.as_ref(),
            &srv,
            r.peer_id,
            &r.dsa_pub,
            &r.static_pk,
            msg,
            FsProfile::StrictPqFs,
        )
        .await
        {
            Err(OneShotError::NoPrekeyStrict) => {}
            other => panic!("strict must refuse, got {other:?}"),
        }

        task.abort();
    }

    /// Stock `recipient`'s **server-side** pool with `stock` opaque blobs and
    /// draw it down until the delivery service answers RateLimited — i.e. the
    /// pool is inside its per-recipient reserve band and the reserve budget is
    /// spent, with real prekeys still in the pool.
    ///
    /// Every draw spends a *fresh* NodeId, so nothing here is the per-NodeId
    /// FETCH bucket; and the blobs are opaque because the server stores them
    /// verbatim and never parses them — the seal under test is throttled, so it
    /// never receives one.
    async fn drain_into_spent_reserve(
        net: &Arc<MockNetwork>,
        srv: &PeerAddr,
        recipient_ep: &dyn P2pEndpoint,
        recipient: PeerId,
        stock: usize,
    ) {
        let blobs: Vec<Vec<u8>> = (0..stock).map(|i| format!("pk-{i}").into_bytes()).collect();
        inbox::publish_prekeys(recipient_ep, srv, &blobs).await.expect("publish");
        let mut minted = Vec::new();
        for i in 0..(stock as u16 * 2) {
            let mut raw = [0u8; 32];
            raw[0] = 0xA5;
            raw[1] = (i >> 8) as u8;
            raw[2] = i as u8;
            let ep = Arc::new(net.register(PeerId::new(raw), vec![P2pProtocol(ALPN_INBOX)]))
                as Arc<dyn P2pEndpoint>;
            match inbox::fetch_prekey(ep.as_ref(), srv, recipient).await.unwrap() {
                FetchOutcome::Prekey(_) => minted.push(ep),
                FetchOutcome::RateLimited => return,
                FetchOutcome::Depleted => panic!("the reserve must not let the pool reach empty"),
            }
        }
        panic!("pool of {stock} never entered a spent reserve band");
    }

    /// Under the default profile a sender that meets the per-recipient reserve
    /// throttle still **sends**: one FETCH, then a static-only seal —
    /// availability first, exactly as when the pool is genuinely depleted,
    /// which is the pre-existing behaviour this must not change. The reserve
    /// costs the forward secrecy of messages sent while the pool is under
    /// attack; it never costs the user the message.
    #[tokio::test]
    async fn throttled_reserve_still_sends_static_only_under_default_profile() {
        let net = MockNetwork::new();
        let dir = tempdir().unwrap();
        let r = make_recipient(dir.path());
        let (task, srv) = spawn_inbox(&net, dir.path()).await;
        let recipient_ep =
            Arc::new(net.register(r.peer_id, vec![P2pProtocol(ALPN_INBOX)])) as Arc<dyn P2pEndpoint>;
        drain_into_spent_reserve(&net, &srv, recipient_ep.as_ref(), r.peer_id, 40).await;

        let sender = Arc::new(net.register(PeerId::new([1u8; 32]), vec![P2pProtocol(ALPN_INBOX)]))
            as Arc<dyn P2pEndpoint>;
        let msg = b"availability-first payload under a throttle";
        let sealed = seal_via_inbox(
            sender.as_ref(),
            &srv,
            r.peer_id,
            &r.dsa_pub,
            &r.static_pk,
            msg,
            FsProfile::DefaultFallback,
        )
        .await
        .unwrap();
        assert_eq!(sealed.mode, MODE_STATIC_ONLY);
        // The throttle was not depletion: the reserve is still holding keys, so
        // the next replenishment (or refill token) restores full PQ-FS.
        assert!(inbox::count_prekeys(recipient_ep.as_ref(), &srv).await.unwrap() > 0);

        task.abort();
    }

    /// A throttled recipient must not cost the **sender** more than a healthy
    /// one does. The server charges the fetcher's own per-NodeId bucket
    /// (`FETCH_RL_CAPACITY` = 8, refill 1/30 s) *before* it consults the
    /// recipient's reserve, so a send that issued more than one FETCH would let
    /// a few messages to one throttled victim empty the sender's own budget and
    /// downgrade its next message to an entirely unrelated, healthy recipient.
    /// Three sends to the victim below cost three tokens at one FETCH each,
    /// leaving five — but nine, i.e. an empty bucket, at three each. So the
    /// fourth send, to a fully stocked third party, must still get full PQ-FS.
    #[tokio::test]
    async fn throttled_recipient_does_not_spend_the_senders_budget() {
        let net = MockNetwork::new();
        let dir = tempdir().unwrap();
        let victim = make_recipient(dir.path());
        let (task, srv) = spawn_inbox(&net, dir.path()).await;
        let victim_ep = Arc::new(net.register(victim.peer_id, vec![P2pProtocol(ALPN_INBOX)]))
            as Arc<dyn P2pEndpoint>;
        drain_into_spent_reserve(&net, &srv, victim_ep.as_ref(), victim.peer_id, 40).await;

        // An unrelated third party, stocked with real signed prekeys. Its own
        // dir, so it gets its own prekey store.
        let healthy_dir = tempdir().unwrap();
        let healthy = make_recipient(healthy_dir.path());
        let healthy_ep = Arc::new(net.register(healthy.peer_id, vec![P2pProtocol(ALPN_INBOX)]))
            as Arc<dyn P2pEndpoint>;
        replenish_to_target(healthy_ep.as_ref(), &srv, &healthy.store, &healthy.dsa_priv, 5)
            .await
            .unwrap();

        let sender = Arc::new(net.register(PeerId::new([2u8; 32]), vec![P2pProtocol(ALPN_INBOX)]))
            as Arc<dyn P2pEndpoint>;
        for _ in 0..3 {
            let sealed = seal_via_inbox(
                sender.as_ref(),
                &srv,
                victim.peer_id,
                &victim.dsa_pub,
                &victim.static_pk,
                b"to the throttled recipient",
                FsProfile::DefaultFallback,
            )
            .await
            .unwrap();
            assert_eq!(sealed.mode, MODE_STATIC_ONLY);
        }

        let sealed = seal_via_inbox(
            sender.as_ref(),
            &srv,
            healthy.peer_id,
            &healthy.dsa_pub,
            &healthy.static_pk,
            b"to an unrelated healthy recipient",
            FsProfile::DefaultFallback,
        )
        .await
        .unwrap();
        assert_eq!(
            sealed.mode, MODE_FULL,
            "sends to a throttled recipient must not downgrade sends to others"
        );

        task.abort();
    }

    /// The Strict profile aborts instead of downgrading when the reserve
    /// throttles it — the same refusal it gives for a depleted pool, so a
    /// throttle can no more be used to force a no-forward-secrecy envelope on a
    /// Strict sender than an emptied pool can.
    #[tokio::test]
    async fn throttled_reserve_aborts_under_strict_profile() {
        let net = MockNetwork::new();
        let dir = tempdir().unwrap();
        let r = make_recipient(dir.path());
        let (task, srv) = spawn_inbox(&net, dir.path()).await;
        let recipient_ep =
            Arc::new(net.register(r.peer_id, vec![P2pProtocol(ALPN_INBOX)])) as Arc<dyn P2pEndpoint>;
        drain_into_spent_reserve(&net, &srv, recipient_ep.as_ref(), r.peer_id, 40).await;

        let sender = Arc::new(net.register(PeerId::new([1u8; 32]), vec![P2pProtocol(ALPN_INBOX)]))
            as Arc<dyn P2pEndpoint>;
        match seal_via_inbox(
            sender.as_ref(),
            &srv,
            r.peer_id,
            &r.dsa_pub,
            &r.static_pk,
            b"strict payload under a throttle",
            FsProfile::StrictPqFs,
        )
        .await
        {
            Err(OneShotError::NoPrekeyStrict) => {}
            other => panic!("strict must refuse a throttled seal, got {other:?}"),
        }

        task.abort();
    }

    /// A static-only envelope opens exactly **once**. A hostile delivery
    /// service that forced the downgrade (by answering every FETCH
    /// `REPLY_PREKEY_NONE`) can re-deliver the very same bytes; the
    /// recipient's seen-envelope cache refuses the second open — the
    /// single-use gate MODE_FULL already gets for free from consuming its
    /// one-time prekey.
    ///
    /// Both sides are asserted: the replay is refused, AND a genuine
    /// depletion still works — a *different* static-only envelope opens
    /// normally, so this is a per-envelope gate and not a blanket refusal of
    /// the availability-first fallback.
    #[test]
    fn static_only_envelope_opens_once_then_replay_is_refused() {
        let dir = tempdir().unwrap();
        let r = make_recipient(dir.path());

        // The replay cache is a sidecar DB, not a table in prekeys.db: that
        // file is fully compacted on every consumed one-time prekey and holds
        // the static identity, and this cache is the one artifact an
        // unauthenticated depositor can grow. It is created lazily.
        let seen_db = dir.path().join("prekeys.db.seen");
        assert!(!seen_db.exists(), "sidecar must not exist before a static-only open");

        let msg = b"availability-first payload";
        let sealed = seal(&r.static_pk, None, msg).unwrap();
        assert_eq!(sealed.mode, MODE_STATIC_ONLY);

        // First delivery decrypts.
        let opened = open(
            &r.static_sk,
            &r.static_pk,
            &r.store,
            &sealed.envelope,
            FsProfile::DefaultFallback,
        )
        .unwrap();
        assert_eq!(opened.as_slice(), msg);
        assert!(seen_db.exists(), "the gate must record into the sidecar DB");

        // The same envelope re-delivered is refused, not decrypted again.
        match open(
            &r.static_sk,
            &r.static_pk,
            &r.store,
            &sealed.envelope,
            FsProfile::DefaultFallback,
        ) {
            Err(OneShotError::StaticOnlyReplay) => {}
            other => panic!("replayed static-only envelope must be refused, got {other:?}"),
        }

        // A genuinely depleted pool still delivers new messages...
        let msg2 = b"second availability-first payload";
        let sealed2 = seal(&r.static_pk, None, msg2).unwrap();
        assert_eq!(sealed2.mode, MODE_STATIC_ONLY);
        let opened2 = open(
            &r.static_sk,
            &r.static_pk,
            &r.store,
            &sealed2.envelope,
            FsProfile::DefaultFallback,
        )
        .unwrap();
        assert_eq!(opened2.as_slice(), msg2);

        // ...and each of them is itself single-use.
        match open(
            &r.static_sk,
            &r.static_pk,
            &r.store,
            &sealed2.envelope,
            FsProfile::DefaultFallback,
        ) {
            Err(OneShotError::StaticOnlyReplay) => {}
            other => panic!("replayed static-only envelope must be refused, got {other:?}"),
        }

        // The gate is durable, not process-local: a store reopened from the
        // same file still refuses the replay (the DS can simply wait).
        drop(r.store);
        let reopened = PrekeyStore::open(&dir.path().join("prekeys.db"), &[0x33u8; 32]).unwrap();
        match open(
            &r.static_sk,
            &r.static_pk,
            &reopened,
            &sealed.envelope,
            FsProfile::DefaultFallback,
        ) {
            Err(OneShotError::StaticOnlyReplay) => {}
            other => panic!("replay must stay refused across reopen, got {other:?}"),
        }
        // The gate never touched the one-time prekey pool.
        assert_eq!(reopened.count().unwrap(), 0);
    }

    fn warn_count() -> usize {
        STOCKED_POOL_WARNINGS.with(|c| c.get())
    }

    /// The recipient catches the delivery service lying about depletion — and
    /// only then. A sender downgrades to static-only exactly when the DS
    /// answers its prekey FETCH `REPLY_PREKEY_NONE`; if our *own* pool still
    /// holds keys when that envelope lands, the pool the DS called depleted
    /// was not depleted. We are the only party holding both facts.
    ///
    /// Both directions are asserted, because a detector that always fires
    /// detects nothing: a genuinely empty pool must stay silent, a stocked
    /// one must warn.
    #[test]
    fn static_only_warns_only_when_our_prekey_pool_is_stocked() {
        let dir = tempdir().unwrap();
        let r = make_recipient(dir.path());
        let base = warn_count();

        // Direction 1 — honest depletion: our pool really is empty, so the
        // DS's "depleted" was the truth and there is nothing to report.
        assert_eq!(r.store.count().unwrap(), 0);
        let honest = seal(&r.static_pk, None, b"honest fallback").unwrap();
        assert_eq!(honest.mode, MODE_STATIC_ONLY);
        let opened = open(
            &r.static_sk,
            &r.static_pk,
            &r.store,
            &honest.envelope,
            FsProfile::DefaultFallback,
        )
        .unwrap();
        assert_eq!(opened.as_slice(), b"honest fallback");
        assert_eq!(warn_count(), base, "a genuinely depleted pool must not warn");

        // Direction 2 — the lie: same envelope shape, but our pool is stocked.
        generate_and_store(&r.store, &r.dsa_priv, 3).unwrap();
        assert_eq!(r.store.count().unwrap(), 3);
        let lied = seal(&r.static_pk, None, b"downgrade forced by a lying DS").unwrap();
        assert_eq!(lied.mode, MODE_STATIC_ONLY);
        let opened = open(
            &r.static_sk,
            &r.static_pk,
            &r.store,
            &lied.envelope,
            FsProfile::DefaultFallback,
        )
        .unwrap();
        // Detection warns; it does not refuse. The message is still delivered
        // (availability-first stays the default; --strict-pqfs is the refusal).
        assert_eq!(opened.as_slice(), b"downgrade forced by a lying DS");
        assert_eq!(warn_count(), base + 1, "a stocked pool must flag the DS's lie");

        // Per envelope, not once per store...
        let lied2 = seal(&r.static_pk, None, b"second forced downgrade").unwrap();
        open(
            &r.static_sk,
            &r.static_pk,
            &r.store,
            &lied2.envelope,
            FsProfile::DefaultFallback,
        )
        .unwrap();
        assert_eq!(warn_count(), base + 2);

        // ...and it neither consumed a prekey nor displaced the replay gate:
        // a re-delivery is still refused, and refusing does not warn again.
        assert_eq!(r.store.count().unwrap(), 3);
        match open(
            &r.static_sk,
            &r.static_pk,
            &r.store,
            &lied.envelope,
            FsProfile::DefaultFallback,
        ) {
            Err(OneShotError::StaticOnlyReplay) => {}
            other => panic!("replay must still be refused, got {other:?}"),
        }
        assert_eq!(warn_count(), base + 2, "a refused replay must not warn again");
    }

    /// A prekey signed under a *different* identity is rejected before use —
    /// the untrusted DS cannot substitute one.
    #[tokio::test]
    async fn substituted_prekey_is_rejected() {
        let net = MockNetwork::new();
        let dir = tempdir().unwrap();
        let r = make_recipient(dir.path());
        let (task, srv) = spawn_inbox(&net, dir.path()).await;
        let sender =
            Arc::new(net.register(PeerId::new([1u8; 32]), vec![P2pProtocol(ALPN_INBOX)]))
                as Arc<dyn P2pEndpoint>;

        let recipient_ep =
            Arc::new(net.register(r.peer_id, vec![P2pProtocol(ALPN_INBOX)])) as Arc<dyn P2pEndpoint>;
        let bundle = generate_and_store(&r.store, &r.dsa_priv, 1).unwrap();
        inbox::publish_prekeys(recipient_ep.as_ref(), &srv, &bundle).await.unwrap();

        // Verify against a *wrong* identity public key → PrekeyUntrusted.
        let (_other_priv, other_pub, _) = crate::backend::pqc_keygen_dsa("ML-DSA-65").unwrap();
        match seal_via_inbox(
            sender.as_ref(),
            &srv,
            r.peer_id,
            &other_pub,
            &r.static_pk,
            b"x",
            FsProfile::DefaultFallback,
        )
        .await
        {
            Err(OneShotError::PrekeyUntrusted) => {}
            other => panic!("expected PrekeyUntrusted, got {other:?}"),
        }

        task.abort();
    }

    /// Flipping the authenticated mode byte breaks the open (anti-downgrade):
    /// the static-only schedule + AAD can't recover a full-mode ciphertext.
    #[test]
    fn tampered_mode_byte_fails_open() {
        let dir = tempdir().unwrap();
        let r = make_recipient(dir.path());
        let bundle = generate_and_store(&r.store, &r.dsa_priv, 1).unwrap();
        let (sp, _) = SignedPrekey::from_bytes(&bundle[0]).unwrap();
        let pk = HpkePublicKey::from(sp.xwing_pub);
        let sealed = seal(&r.static_pk, Some((sp.prekey_id, &pk)), b"secret").unwrap();

        // mode byte sits right after magic(4) + version(1).
        let mut tampered = sealed.envelope.clone();
        tampered[5] = MODE_STATIC_ONLY;
        // DefaultFallback so the open reaches the crypto path (not the
        // recipient-profile gate) — we are asserting the *cryptographic*
        // rejection of a downgraded envelope.
        assert!(
            open(&r.static_sk, &r.static_pk, &r.store, &tampered, FsProfile::DefaultFallback)
                .is_err()
        );
        // The legit prekey was never consumed by the failed open.
        assert_eq!(r.store.count().unwrap(), 1);
    }

    fn inbox_ticket_for(peer: PeerId) -> String {
        crate::ticket::Ticket::new(PeerAddr::new(peer), None, None).to_string()
    }

    // §11 (increment 4): a ctx="" (file-style) signature over the exact recipient-
    // bundle payload must NOT verify as a bundle. The native BUNDLE_CTX separates
    // them, closing the file->recipient-bundle cross-replay — the signature the §11
    // inventory originally missed. Message bytes are identical; only the ctx differs.
    #[test]
    fn file_ctx_signature_does_not_verify_as_recipient_bundle() {
        let dir = tempdir().unwrap();
        let r = make_recipient(dir.path());
        let node_id = *r.peer_id.as_bytes();
        let ticket = inbox_ticket_for(PeerId::new([99u8; 32]));
        let payload = RecipientBundle::payload_bytes(&r.dsa_pub, r.static_pk.as_ref(), &node_id, &ticket);
        // Forge a "file-style" ctx="" signature over the exact bundle payload.
        let forged =
            crate::backend::pqc_sign(prekey::PREKEY_SIGN_ALGO, &r.dsa_priv, &payload, &[]).unwrap();
        let mut blob = payload.clone();
        blob.extend_from_slice(&(forged.len() as u32).to_le_bytes());
        blob.extend_from_slice(&forged);
        match RecipientBundle::parse_and_verify(&blob) {
            Err(OneShotError::BundleUntrusted) => {}
            other => panic!("a ctx=\"\" signature must not verify as a bundle, got {other:?}"),
        }
        // Sanity: the real build_signed (native BUNDLE_CTX) verifies.
        let good = RecipientBundle::build_signed(&r.dsa_priv, &r.static_pk, node_id, &ticket).unwrap();
        assert!(RecipientBundle::parse_and_verify(&good).is_ok());
    }

    /// A signed bundle round-trips, exposes the right fingerprint, and any
    /// single-byte tamper (here: the static X-Wing key) breaks verification.
    #[test]
    fn bundle_roundtrips_and_detects_tamper() {
        let dir = tempdir().unwrap();
        let r = make_recipient(dir.path());
        let node_id = *r.peer_id.as_bytes();
        let ticket = inbox_ticket_for(PeerId::new([99u8; 32]));

        let bytes =
            RecipientBundle::build_signed(&r.dsa_priv, &r.static_pk, node_id, &ticket).unwrap();
        let parsed = RecipientBundle::parse_and_verify(&bytes).unwrap();
        assert_eq!(parsed.dsa_pub, r.dsa_pub);
        assert_eq!(parsed.static_xwing_pub, r.static_pk.as_ref());
        assert_eq!(parsed.node_id, node_id);
        assert_eq!(parsed.inbox_ticket, ticket);
        assert_eq!(parsed.recipient_peer_id(), r.peer_id);
        // Fingerprint is SHA3-256(dsa_pub) hex — the value pinned out-of-band.
        assert_eq!(parsed.fingerprint(), HEXLOWER.encode(&prekey::peer_id_from_dsa_pub(&r.dsa_pub)));

        // Flip a byte inside the signed static-key region → BundleUntrusted.
        let mut tampered = bytes.clone();
        let off = 4 + 1 + 2 + r.dsa_pub.len() + 5; // into static_xwing_pub
        tampered[off] ^= 0xff;
        match RecipientBundle::parse_and_verify(&tampered) {
            Err(OneShotError::BundleUntrusted) | Err(OneShotError::Bundle(_)) => {}
            other => panic!("tampered bundle must not verify, got {other:?}"),
        }

        // Appended trailing bytes are rejected (no malleable second encoding).
        let mut trailing = bytes.clone();
        trailing.push(0x00);
        match RecipientBundle::parse_and_verify(&trailing) {
            Err(OneShotError::Bundle(_)) => {}
            other => panic!("trailing data must be rejected, got {other:?}"),
        }
    }

    /// Full sender→receiver E2E over the inbox using only the bundle and the
    /// store-managed identity: generate identity + prekeys, publish, build a
    /// bundle, `seal_and_deposit`, then `receive` and match the plaintext.
    #[tokio::test]
    async fn e2e_seal_and_deposit_then_receive() {
        let net = MockNetwork::new();
        let dir = tempdir().unwrap();
        let (dsa_priv, dsa_pub, _) = crate::backend::pqc_keygen_dsa("ML-DSA-65").unwrap();
        let node_id = prekey::peer_id_from_dsa_pub(&dsa_pub); // recipient's stable id
        let peer_id = PeerId::new(node_id);
        let store = PrekeyStore::open(&dir.path().join("prekeys.db"), &[0x44u8; 32]).unwrap();

        let (task, srv) = spawn_inbox(&net, dir.path()).await;
        let inbox_ticket = inbox_ticket_for(PeerId::new([99u8; 32]));

        // Recipient sets up: long-term static key + a prekey + publish.
        let static_pk = store.generate_identity().unwrap();
        let recipient_ep =
            Arc::new(net.register(peer_id, vec![P2pProtocol(ALPN_INBOX)])) as Arc<dyn P2pEndpoint>;
        let prekey_bundle = generate_and_store(&store, &dsa_priv, 3).unwrap();
        inbox::publish_prekeys(recipient_ep.as_ref(), &srv, &prekey_bundle).await.unwrap();

        // Recipient hands out a signed discovery bundle.
        let bundle_bytes =
            RecipientBundle::build_signed(&dsa_priv, &static_pk, node_id, &inbox_ticket).unwrap();

        // Sender: verify the bundle, then seal + deposit.
        let sender =
            Arc::new(net.register(PeerId::new([7u8; 32]), vec![P2pProtocol(ALPN_INBOX)]))
                as Arc<dyn P2pEndpoint>;
        let bundle = RecipientBundle::parse_and_verify(&bundle_bytes).unwrap();
        let msg = b"end-to-end forward-secret message";
        let sealed =
            seal_and_deposit(sender.as_ref(), &bundle, msg, FsProfile::StrictPqFs).await.unwrap();
        assert_eq!(sealed.mode, MODE_FULL);

        // Recipient: poll + open via the store-managed identity.
        let (static_sk, static_pk2) = store.load_identity().unwrap().unwrap();
        let (cursor, received) = receive(
            recipient_ep.as_ref(),
            &srv,
            &static_sk,
            &static_pk2,
            &store,
            store.inbox_cursor().unwrap(),
            FsProfile::StrictPqFs,
        )
        .await
        .unwrap();
        store.set_inbox_cursor(cursor).unwrap();

        assert_eq!(received.len(), 1);
        let plaintext = received[0].result.as_ref().unwrap();
        assert_eq!(plaintext.as_slice(), msg);
        // The prekey was consumed (2 of the original 3 remain).
        assert_eq!(store.count().unwrap(), 2);

        task.abort();
    }

    // §10(B) fuzz: deterministic (fixed-seed) malformed bytes must never panic
    // the recipient-bundle (NKB1) parser (attacker-controlled lengths → Err).
    #[test]
    fn recipient_bundle_parse_fuzz_no_panic() {
        let mut state: u64 = 0xF00D_BABE_5EED_C0DE;
        let mut next = || {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        };
        for i in 0..2000u32 {
            // Half start from the NKB1 magic to reach the deeper length parsing.
            let mut bytes = if i % 2 == 0 { b"NKB1".to_vec() } else { Vec::new() };
            let n = (next() % 4096) as usize;
            bytes.extend((0..n).map(|_| (next() >> 33) as u8));
            let _ = RecipientBundle::parse_and_verify(&bytes);
        }
    }
}
