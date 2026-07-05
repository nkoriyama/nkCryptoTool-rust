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
/// decrypt — deletes that one-time key so it can never be reused. Returns
/// the plaintext in a `Zeroizing` buffer.
///
/// `profile` is the *recipient's* policy: under [`FsProfile::StrictPqFs`] a
/// static-only (no forward secrecy) envelope is refused
/// ([`OneShotError::DowngradeRejected`]) rather than silently accepted — the
/// receive-side backstop against a sender being forced to downgrade by a
/// prekey-depletion attack. [`FsProfile::DefaultFallback`] accepts both.
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
        // already deleted — this envelope decrypts successfully every time it is
        // (re)delivered. It provides confidentiality and no forward secrecy, but
        // no replay protection at this layer. The mitigation is policy:
        // `FsProfile::StrictPqFs` refuses static-only outright; a
        // `DefaultFallback` recipient that needs replay protection must dedup on
        // an upper layer (e.g. a seen-message cache). This is intentional
        // availability-first behaviour, documented rather than silently relied on.
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
    Ok(plaintext)
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
/// Domain separator so a bundle self-signature can never be mistaken for a
/// signature over a prekey, a handshake transcript, or a file header.
const BUNDLE_SIG_CONTEXT: &[u8] = b"nkct-recipient-bundle-v1";
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
        let mut msg = Vec::with_capacity(BUNDLE_SIG_CONTEXT.len() + payload.len());
        msg.extend_from_slice(BUNDLE_SIG_CONTEXT);
        msg.extend_from_slice(&payload);
        let sig = crate::backend::pqc_sign(prekey::PREKEY_SIGN_ALGO, dsa_priv, &msg, &[])
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
        let mut msg = Vec::with_capacity(BUNDLE_SIG_CONTEXT.len() + payload.len());
        msg.extend_from_slice(BUNDLE_SIG_CONTEXT);
        msg.extend_from_slice(payload);
        let ok = crate::backend::pqc_verify(prekey::PREKEY_SIGN_ALGO, &dsa_pub, &msg, sig, &[])
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
}
