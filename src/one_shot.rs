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
    self, recipient_key_schedule, sender_key_schedule, PrekeyError, PrekeyStore, SignedPrekey,
    MODE_FULL, MODE_STATIC_ONLY, XWING_PK_LEN,
};
use crate::strategy::streaming_aead::{aead_decrypt_chunk, aead_encrypt_chunk, V3_NONCE_LEN};
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
}
