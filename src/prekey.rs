/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

//! One-Time Prekey (PQXDH-style) primitives for post-quantum forward
//! secrecy on the one-shot / async path. See `PQFS_DESIGN.md`.
//!
//! Background: the live P2P handshake already has PQ-FS (it encapsulates
//! to a *per-connection ephemeral* KEM key). The remaining gap is the
//! one-shot / inbox-async path, where the sender encapsulates to the
//! recipient's *static* KEM key — so a future CRQC that recovers the
//! long-term key can decrypt harvested ciphertexts. One-Time Prekeys
//! restore FS for the inbox path: the recipient pre-publishes signed,
//! single-use X-Wing public keys; the sender blends a prekey
//! encapsulation into the session key, and the recipient deletes the
//! prekey private key the instant it has decrypted with it.
//!
//! ## Phase 1 (this module)
//!
//! * [`SignedPrekey`] — a single X-Wing public key signed under the
//!   recipient's ML-DSA-65 identity key, so the semi-trusted inbox
//!   Delivery Service that stores/serves prekeys cannot substitute one.
//! * [`generate`] — produce a batch of prekeys (keypair + signature).
//! * [`PrekeyStore`] — an SQLCipher table holding the *private* keys,
//!   with [`consume`](PrekeyStore::consume) deleting a key on use.
//!
//! The blended key schedule (double encapsulation static ‖ prekey) and
//! the inbox `PUBLISH` / `FETCH` wire ops are phase 2.

use crate::group::crypto_adapter::build_at_rest_suite;
use data_encoding::HEXLOWER;
use mls_rs::CipherSuiteProvider;
use mls_rs_core::crypto::{HpkeContextR, HpkeContextS, HpkePublicKey, HpkeSecretKey};
use rusqlite::Connection;
use sha3::{Digest, Sha3_256};
use std::path::Path;
use std::time::Duration;
use zeroize::Zeroizing;

/// X-Wing public key length: X25519 (32 B) ‖ ML-KEM-768 encap key (1184 B).
pub const XWING_PK_LEN: usize = 32 + 1184;
/// X-Wing secret key length: X25519 (32 B) ‖ ML-KEM-768 decap key (2400 B).
pub const XWING_SK_LEN: usize = 32 + 2400;

/// ML-DSA algorithm that signs prekeys. Matches the identity signing key.
pub const PREKEY_SIGN_ALGO: &str = "ML-DSA-65";

/// Domain-separation prefix mixed into the signed message so a prekey
/// signature can never be confused with a signature over anything else
/// (handshake transcript, file header, …).
const PREKEY_SIG_CONTEXT: &[u8] = b"nkct-onetime-prekey-v1";

/// Upper bound accepted for a serialized signature length. ML-DSA-65
/// signatures are 3309 B; the generous cap rejects malformed wire data
/// while leaving headroom for any context/encoding overhead.
const MAX_SIG_LEN: usize = 8 * 1024;

/// Errors from prekey generation, verification, or storage.
#[derive(thiserror::Error, Debug)]
pub enum PrekeyError {
    #[error("X-Wing suite construction failed (OpenSSL missing X25519/ML-KEM-768?)")]
    Suite,
    #[error("KEM keygen: {0}")]
    Keygen(String),
    #[error("signing backend: {0}")]
    Sign(#[from] crate::error::CryptoError),
    #[error("prekey {0}: public key is {1} B, expected {XWING_PK_LEN}")]
    BadPublicKeyLen(u32, usize),
    #[error("prekey wire format: {0}")]
    Wire(String),
    #[error("prekey store: {0}")]
    Storage(#[from] rusqlite::Error),
    #[error("HPKE: {0}")]
    Hpke(String),
}

type Result<T> = std::result::Result<T, PrekeyError>;

/// Derive the 32-byte recipient peer id from an ML-DSA identity public
/// key — `SHA3-256(dsa_pub)`, the same identifier the P2P handshake pins
/// (`PeerId::Pubkey`). Binding prekeys to this id stops a prekey signed
/// for one identity from being replayed under another.
pub fn peer_id_from_dsa_pub(dsa_pub: &[u8]) -> [u8; 32] {
    Sha3_256::digest(dsa_pub).into()
}

/// The exact byte string signed for (and verified against) a prekey:
/// `context ‖ recipient_peer_id ‖ prekey_id(BE) ‖ xwing_pub`.
fn signed_message(recipient_peer_id: &[u8; 32], prekey_id: u32, xwing_pub: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(PREKEY_SIG_CONTEXT.len() + 32 + 4 + xwing_pub.len());
    msg.extend_from_slice(PREKEY_SIG_CONTEXT);
    msg.extend_from_slice(recipient_peer_id);
    msg.extend_from_slice(&prekey_id.to_be_bytes());
    msg.extend_from_slice(xwing_pub);
    msg
}

/// A single One-Time Prekey as published to the inbox Delivery Service:
/// an X-Wing public key signed under the recipient's ML-DSA-65 identity.
///
/// Only the public half travels. The matching private key never leaves
/// the recipient's [`PrekeyStore`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedPrekey {
    pub prekey_id: u32,
    pub xwing_pub: Vec<u8>,
    pub signature: Vec<u8>,
}

impl SignedPrekey {
    /// Verify the signature against the recipient's ML-DSA-65 identity
    /// public key. The sender MUST call this after `FETCH` and before
    /// using the prekey — it is what keeps the storing server honest.
    ///
    /// The bound peer id is derived from `dsa_pub` itself
    /// (`SHA3-256(dsa_pub)`), not taken as a separate argument, so there is
    /// no way to verify against a peer id that disagrees with the key.
    pub fn verify(&self, dsa_pub: &[u8]) -> Result<bool> {
        if self.xwing_pub.len() != XWING_PK_LEN {
            return Err(PrekeyError::BadPublicKeyLen(self.prekey_id, self.xwing_pub.len()));
        }
        let peer_id = peer_id_from_dsa_pub(dsa_pub);
        let msg = signed_message(&peer_id, self.prekey_id, &self.xwing_pub);
        Ok(crate::backend::pqc_verify(PREKEY_SIGN_ALGO, dsa_pub, &msg, &self.signature)?)
    }

    /// Serialize to the wire form:
    /// `prekey_id(4 BE) ‖ pub_len(4 BE) ‖ xwing_pub ‖ sig_len(4 BE) ‖ signature`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 4 + self.xwing_pub.len() + 4 + self.signature.len());
        out.extend_from_slice(&self.prekey_id.to_be_bytes());
        out.extend_from_slice(&(self.xwing_pub.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.xwing_pub);
        out.extend_from_slice(&(self.signature.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.signature);
        out
    }

    /// Parse one [`SignedPrekey`] from the front of `buf`, returning it
    /// and the number of bytes consumed (so a batch can be parsed in a
    /// loop).
    pub fn from_bytes(buf: &[u8]) -> Result<(Self, usize)> {
        let mut o = 0;
        let take = |o: &mut usize, n: usize| -> Result<&[u8]> {
            let end = o.checked_add(n).ok_or_else(|| PrekeyError::Wire("length overflow".into()))?;
            if end > buf.len() {
                return Err(PrekeyError::Wire("truncated".into()));
            }
            let s = &buf[*o..end];
            *o = end;
            Ok(s)
        };
        let prekey_id = u32::from_be_bytes(take(&mut o, 4)?.try_into().unwrap());
        let pub_len = u32::from_be_bytes(take(&mut o, 4)?.try_into().unwrap()) as usize;
        // Reject the wrong public-key size up front: a well-formed X-Wing
        // prekey is always XWING_PK_LEN. `take` already bounds the slice
        // to the buffer, so this is a value check, not an alloc guard.
        if pub_len != XWING_PK_LEN {
            return Err(PrekeyError::Wire(format!(
                "public key is {pub_len} B, expected {XWING_PK_LEN}"
            )));
        }
        let xwing_pub = take(&mut o, pub_len)?.to_vec();
        let sig_len = u32::from_be_bytes(take(&mut o, 4)?.try_into().unwrap()) as usize;
        // ML-DSA-65 signatures are 3309 B; cap well above that so a bogus
        // length is rejected before the (already buffer-bounded) copy.
        if sig_len > MAX_SIG_LEN {
            return Err(PrekeyError::Wire(format!(
                "signature is {sig_len} B, exceeds max {MAX_SIG_LEN}"
            )));
        }
        let signature = take(&mut o, sig_len)?.to_vec();
        Ok((Self { prekey_id, xwing_pub, signature }, o))
    }
}

/// A freshly generated prekey: the public, signed half plus the private
/// key the recipient must store. The private key is kept as an
/// [`HpkeSecretKey`], which is `ZeroizeOnDrop`, so it is wiped from the
/// heap if dropped before being persisted — and no intermediate plain
/// `Vec<u8>` copy of it is ever made.
pub struct GeneratedPrekey {
    pub signed: SignedPrekey,
    pub xwing_priv: HpkeSecretKey,
}

/// Generate `count` prekeys with ids `start_id .. start_id + count`,
/// each an X-Wing keypair signed under `dsa_priv` (raw ML-DSA-65 private
/// key bytes, as produced by `utils::unwrap_pqc_priv_from_pkcs8`).
///
/// The recipient peer id bound into every signature is derived from the
/// public key matching `dsa_priv` (`SHA3-256(dsa_pub)`), computed here, so
/// it always agrees with the signing key.
pub fn generate(count: u32, start_id: u32, dsa_priv: &[u8]) -> Result<Vec<GeneratedPrekey>> {
    let suite = build_at_rest_suite().ok_or(PrekeyError::Suite)?;
    let dsa_pub = crate::backend::pqc_pub_from_priv_dsa(PREKEY_SIGN_ALGO, dsa_priv)?;
    let recipient_peer_id = peer_id_from_dsa_pub(&dsa_pub);
    let mut out = Vec::with_capacity(count as usize);
    for i in 0..count {
        let prekey_id = start_id
            .checked_add(i)
            .ok_or_else(|| PrekeyError::Wire("prekey_id space exhausted".into()))?;
        let (sk, pk) = suite
            .kem_generate()
            .map_err(|e| PrekeyError::Keygen(e.to_string()))?;
        let xwing_pub = pk.as_ref().to_vec();
        if xwing_pub.len() != XWING_PK_LEN {
            return Err(PrekeyError::BadPublicKeyLen(prekey_id, xwing_pub.len()));
        }
        let msg = signed_message(&recipient_peer_id, prekey_id, &xwing_pub);
        let signature = crate::backend::pqc_sign(PREKEY_SIGN_ALGO, dsa_priv, &msg, None)?;
        out.push(GeneratedPrekey {
            signed: SignedPrekey { prekey_id, xwing_pub, signature },
            xwing_priv: sk,
        });
    }
    Ok(out)
}

/// SQLCipher-backed store for One-Time Prekey *private* keys.
///
/// ## Decrypt lifecycle (why load and delete are separate)
///
/// Deletion is what makes the one-shot path forward-secret, but it must
/// happen **only after** a ciphertext has been successfully decrypted and
/// its AEAD tag verified — never on a failed attempt. Otherwise an
/// attacker who knows a `prekey_id` could send garbage ciphertexts to
/// force-delete every prekey, draining the pool and downgrading the
/// recipient to the no-FS static-key fallback (the depletion attack in
/// `PQFS_DESIGN.md` §4.1).
///
/// So the correct order is:
/// 1. [`load`](Self::load) the private key (read-only, no delete),
/// 2. decapsulate and verify the AEAD tag,
/// 3. **on success only**, [`delete`](Self::delete) the prekey.
///
/// A single combined "consume" call is deliberately *not* offered,
/// because it would force step 3 to happen before step 2 can run.
pub struct PrekeyStore {
    conn: Connection,
}

impl PrekeyStore {
    /// Open (or create) the SQLCipher database at `path`, unlocked with a
    /// raw 256-bit `dek` (the at-rest layer's derived key — SQLCipher
    /// skips PBKDF2 for a raw key), and ensure the `onetime_prekeys`
    /// table exists.
    pub fn open(path: &Path, dek: &[u8; 32]) -> Result<Self> {
        let conn = Connection::open(path)?;
        // `PRAGMA key` must be the first statement on the connection.
        // The key string embeds the raw DEK as an x'<hex>' literal (SQLite
        // has no parameter binding for PRAGMA), so build it in a pre-sized
        // Zeroizing String: pre-sizing avoids a `format!`-grown temporary
        // that could leave DEK fragments in freed, un-zeroized heap, and
        // the Zeroizing wrapper wipes the final buffer on drop.
        const PRE: &str = "PRAGMA key = \"x'";
        const POST: &str = "'\";";
        let hex = Zeroizing::new(HEXLOWER.encode(dek));
        let mut stmt = Zeroizing::new(String::with_capacity(PRE.len() + hex.len() + POST.len()));
        stmt.push_str(PRE);
        stmt.push_str(hex.as_str());
        stmt.push_str(POST);
        conn.execute_batch(stmt.as_str())?;
        conn.busy_timeout(Duration::from_millis(5_000))?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        // Keep the rollback journal in DELETE mode (the default) rather than
        // WAL: a retired prekey secret must not linger in a -wal sidecar
        // that secure_delete does not cover. Set explicitly so the FS
        // guarantee does not depend on the ambient default.
        conn.pragma_update(None, "journal_mode", "DELETE")?;
        // secure_delete = ON makes SQLite overwrite deleted content with
        // zeros instead of just marking the page free. This is load-bearing
        // here: `delete` retiring a used One-Time Prekey must physically
        // destroy the private key, else it survives in the freelist and an
        // attacker with the DB file + DEK could recover it and defeat the
        // forward secrecy that single-use deletion is meant to provide.
        conn.pragma_update(None, "secure_delete", "ON")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS onetime_prekeys (
                 prekey_id   INTEGER PRIMARY KEY,
                 xwing_priv  BLOB NOT NULL,
                 created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now'))
             );
             -- Persistent monotonic id high-water mark. Single row (id=0).
             -- Keeps prekey ids from ever being reused, even after the
             -- onetime_prekeys table is fully drained.
             CREATE TABLE IF NOT EXISTS prekey_seq (
                 id    INTEGER PRIMARY KEY CHECK (id = 0),
                 next  INTEGER NOT NULL
             );
             INSERT OR IGNORE INTO prekey_seq (id, next) VALUES (0, 0);",
        )?;
        // Tighten the DB file to owner-only — it holds (SQLCipher-encrypted)
        // prekey private keys; 0600 matches how the at-rest key files are
        // handled and keeps other local users from reading or clobbering it.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(path) {
                let mut perms = meta.permissions();
                perms.set_mode(0o600);
                let _ = std::fs::set_permissions(path, perms);
            }
        }
        Ok(Self { conn })
    }

    /// Atomically reserve `count` consecutive prekey ids, returning the
    /// first. The counter is a persistent high-water mark that never
    /// rewinds — even when every prekey has been consumed and the table is
    /// empty — so an id is never reused for a different keypair.
    pub fn reserve_ids(&self, count: u32) -> Result<u32> {
        let tx = self.conn.unchecked_transaction()?;
        // UPDATE before reading back: the write takes the lock immediately,
        // so two concurrent reservers serialize on it and can never read
        // the same pre-increment value (a SELECT-then-UPDATE order would
        // race and hand out a duplicate start id).
        let changed = tx.execute(
            "UPDATE prekey_seq SET next = next + ?1 WHERE id = 0",
            rusqlite::params![i64::from(count)],
        )?;
        if changed != 1 {
            return Err(PrekeyError::Wire("prekey_seq row missing".into()));
        }
        let new_next: i64 =
            tx.query_row("SELECT next FROM prekey_seq WHERE id = 0", [], |r| r.get(0))?;
        let start = new_next - i64::from(count);
        // Reject overflow of the u32 id space (checked before commit so the
        // transaction rolls back on error).
        let start_u32 = u32::try_from(start)
            .map_err(|_| PrekeyError::Wire("prekey id space exhausted".into()))?;
        u32::try_from(new_next)
            .map_err(|_| PrekeyError::Wire("prekey id space exhausted".into()))?;
        tx.commit()?;
        Ok(start_u32)
    }

    /// Persist one prekey private key under its id.
    pub fn insert(&self, prekey_id: u32, xwing_priv: &[u8]) -> Result<()> {
        self.conn.execute(
            "INSERT INTO onetime_prekeys (prekey_id, xwing_priv) VALUES (?1, ?2)",
            rusqlite::params![prekey_id, xwing_priv],
        )?;
        Ok(())
    }

    /// Number of unused prekeys still held. Drives auto-refill (phase 2).
    pub fn count(&self) -> Result<u64> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM onetime_prekeys", [], |r| r.get(0))?;
        Ok(n as u64)
    }

    /// Ids of every unused prekey, ascending. The lowest unused id is the
    /// natural `start_id` for the next [`generate`] batch.
    pub fn list_ids(&self) -> Result<Vec<u32>> {
        let mut stmt = self
            .conn
            .prepare("SELECT prekey_id FROM onetime_prekeys ORDER BY prekey_id")?;
        let ids = stmt
            .query_map([], |r| r.get::<_, i64>(0).map(|v| v as u32))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(ids)
    }

    /// Read (without deleting) the private key for `prekey_id`, returning
    /// it as an [`HpkeSecretKey`] for decapsulation. Returns `None` if the
    /// id is unknown or already deleted.
    ///
    /// Read-only by design: the matching [`delete`](Self::delete) must be
    /// called separately, and only after the ciphertext's AEAD tag has
    /// verified, so a forged ciphertext cannot drain the pool. See the
    /// struct-level lifecycle note.
    pub fn load(&self, prekey_id: u32) -> Result<Option<HpkeSecretKey>> {
        let row: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT xwing_priv FROM onetime_prekeys WHERE prekey_id = ?1",
                rusqlite::params![prekey_id],
                |r| r.get(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })?;
        // `priv_bytes` is moved into HpkeSecretKey::from, whose inner Vec
        // is ZeroizeOnDrop — no separate unprotected copy is left behind.
        Ok(row.map(HpkeSecretKey::from))
    }

    /// Delete `prekey_id`. Call this after a successful decrypt+verify to
    /// retire the single-use key, or for operator revocation. Returns
    /// `true` if a row was removed.
    pub fn delete(&self, prekey_id: u32) -> Result<bool> {
        let n = self.conn.execute(
            "DELETE FROM onetime_prekeys WHERE prekey_id = ?1",
            rusqlite::params![prekey_id],
        )?;
        Ok(n > 0)
    }

    /// Delete every prekey (operator revocation). Returns the number removed.
    pub fn delete_all(&self) -> Result<u64> {
        let n = self.conn.execute("DELETE FROM onetime_prekeys", [])?;
        Ok(n as u64)
    }
}

// -----------------------------------------------------------------------------
// Blended key schedule (phase 2): static ‖ one-time prekey
// -----------------------------------------------------------------------------

/// Derived session-key length (AES-256).
pub const SESSION_KEY_LEN: usize = 32;

/// Which key schedule produced a ciphertext. Stored in the envelope and
/// (by the payload layer, phase 2c) bound into the AEAD AAD, so a full-FS
/// ciphertext can never be opened — or silently downgraded — as a
/// static-only one. The two modes also derive keys under different HKDF
/// `info`, so even without the AAD tag the keys are independent.
pub const MODE_FULL: u8 = 1;
pub const MODE_STATIC_ONLY: u8 = 2;

// Domain separation. Each encapsulation target gets its own HPKE `info`,
// and each mode its own final-HKDF `info`, so the static and prekey
// secrets — and the full vs fallback session keys — can never collide.
const HPKE_INFO_STATIC: &[u8] = b"nkct-pqfs-hpke-static-v1";
const HPKE_INFO_PREKEY: &[u8] = b"nkct-pqfs-hpke-prekey-v1";
const EXPORT_LABEL: &[u8] = b"nkct-pqfs-export-v1";
const HKDF_INFO_FULL: &str = "nkct-pqfs-session-full-v1";
const HKDF_INFO_STATIC: &str = "nkct-pqfs-session-static-fallback-v1";

/// Blend the per-encapsulation HPKE-exported secrets into the final
/// session key. Full mode requires both secrets; static-only mode uses
/// just the static one under a distinct `info`.
fn derive_session_key(
    mode: u8,
    ss_static: &[u8],
    ss_prekey: Option<&[u8]>,
    salt: &[u8],
) -> Result<Zeroizing<[u8; SESSION_KEY_LEN]>> {
    let (ikm, info): (Zeroizing<Vec<u8>>, &str) = match mode {
        MODE_FULL => {
            let p = ss_prekey
                .ok_or_else(|| PrekeyError::Wire("full mode requires the prekey secret".into()))?;
            let mut ikm = Zeroizing::new(Vec::with_capacity(ss_static.len() + p.len()));
            ikm.extend_from_slice(ss_static);
            ikm.extend_from_slice(p);
            (ikm, HKDF_INFO_FULL)
        }
        MODE_STATIC_ONLY => (Zeroizing::new(ss_static.to_vec()), HKDF_INFO_STATIC),
        other => return Err(PrekeyError::Wire(format!("unknown prekey mode {other}"))),
    };
    // Wrap the HKDF output so the session-key material is wiped from the
    // heap on drop rather than lingering in a plain Vec.
    let okm = Zeroizing::new(crate::backend::hkdf(&ikm, SESSION_KEY_LEN, salt, info, "SHA3-256")?);
    let mut key = Zeroizing::new([0u8; SESSION_KEY_LEN]);
    key.copy_from_slice(&okm);
    Ok(key)
}

/// The sender's output of the key schedule: the encapsulations to ship
/// alongside the ciphertext, the chosen mode, and the session key used to
/// AEAD-encrypt the payload (the payload AEAD itself is the caller's job).
pub struct SenderKeySchedule {
    pub mode: u8,
    pub enc_static: Vec<u8>,
    pub enc_prekey: Option<Vec<u8>>,
    pub session_key: Zeroizing<[u8; SESSION_KEY_LEN]>,
}

/// Sender side: encapsulate to the recipient's static X-Wing key and, when
/// a One-Time Prekey is available, also to the prekey, blending both into
/// the session key (full PQ-FS). With no prekey, falls back to static-only
/// (no PQ-FS) under a distinct schedule — the caller decides whether that
/// fallback is allowed (the Strict profile refuses it; see PQFS_DESIGN.md
/// §未決定の論点 c).
pub fn sender_key_schedule(
    static_pk: &HpkePublicKey,
    prekey_pk: Option<&HpkePublicKey>,
    salt: &[u8],
) -> Result<SenderKeySchedule> {
    let suite = build_at_rest_suite().ok_or(PrekeyError::Suite)?;
    let (enc_static, ctx_s) = suite
        .hpke_setup_s(static_pk, HPKE_INFO_STATIC)
        .map_err(|e| PrekeyError::Hpke(format!("setup_s static: {e}")))?;
    let ss_static = ctx_s
        .export(EXPORT_LABEL, SESSION_KEY_LEN)
        .map_err(|e| PrekeyError::Hpke(format!("export static: {e}")))?;

    match prekey_pk {
        Some(pk) => {
            let (enc_prekey, ctx_p) = suite
                .hpke_setup_s(pk, HPKE_INFO_PREKEY)
                .map_err(|e| PrekeyError::Hpke(format!("setup_s prekey: {e}")))?;
            let ss_prekey = ctx_p
                .export(EXPORT_LABEL, SESSION_KEY_LEN)
                .map_err(|e| PrekeyError::Hpke(format!("export prekey: {e}")))?;
            let session_key =
                derive_session_key(MODE_FULL, &ss_static, Some(&ss_prekey), salt)?;
            Ok(SenderKeySchedule {
                mode: MODE_FULL,
                enc_static,
                enc_prekey: Some(enc_prekey),
                session_key,
            })
        }
        None => {
            let session_key = derive_session_key(MODE_STATIC_ONLY, &ss_static, None, salt)?;
            Ok(SenderKeySchedule {
                mode: MODE_STATIC_ONLY,
                enc_static,
                enc_prekey: None,
                session_key,
            })
        }
    }
}

/// Recipient side: recover the same session key from the encapsulations.
/// For [`MODE_FULL`], `prekey` (the matching prekey secret/public key and
/// its encapsulation) is required — and since the prekey secret is deleted
/// right after a successful decrypt, a later compromise of the static key
/// alone cannot reconstruct it. That is the forward secrecy guarantee.
pub fn recipient_key_schedule(
    mode: u8,
    static_sk: &HpkeSecretKey,
    static_pk: &HpkePublicKey,
    enc_static: &[u8],
    prekey: Option<(&HpkeSecretKey, &HpkePublicKey, &[u8])>,
    salt: &[u8],
) -> Result<Zeroizing<[u8; SESSION_KEY_LEN]>> {
    let suite = build_at_rest_suite().ok_or(PrekeyError::Suite)?;
    let ctx_rs = suite
        .hpke_setup_r(enc_static, static_sk, static_pk, HPKE_INFO_STATIC)
        .map_err(|e| PrekeyError::Hpke(format!("setup_r static: {e}")))?;
    let ss_static = ctx_rs
        .export(EXPORT_LABEL, SESSION_KEY_LEN)
        .map_err(|e| PrekeyError::Hpke(format!("export static: {e}")))?;

    match mode {
        MODE_FULL => {
            let (psk, ppk, penc) = prekey.ok_or_else(|| {
                PrekeyError::Wire("full mode requires the prekey secret to decrypt".into())
            })?;
            let ctx_rp = suite
                .hpke_setup_r(penc, psk, ppk, HPKE_INFO_PREKEY)
                .map_err(|e| PrekeyError::Hpke(format!("setup_r prekey: {e}")))?;
            let ss_prekey = ctx_rp
                .export(EXPORT_LABEL, SESSION_KEY_LEN)
                .map_err(|e| PrekeyError::Hpke(format!("export prekey: {e}")))?;
            derive_session_key(MODE_FULL, &ss_static, Some(&ss_prekey), salt)
        }
        MODE_STATIC_ONLY => derive_session_key(MODE_STATIC_ONLY, &ss_static, None, salt),
        other => Err(PrekeyError::Wire(format!("unknown prekey mode {other}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A throwaway ML-DSA-65 identity for signing test prekeys.
    fn test_identity() -> (Zeroizing<Vec<u8>>, Vec<u8>) {
        let (priv_raw, pub_raw, _) = crate::backend::pqc_keygen_dsa(PREKEY_SIGN_ALGO).unwrap();
        (priv_raw, pub_raw)
    }

    #[test]
    fn generate_then_verify_roundtrips() {
        let (priv_raw, pub_raw) = test_identity();
        let batch = generate(3, 0, &priv_raw).unwrap();
        assert_eq!(batch.len(), 3);
        for (i, g) in batch.iter().enumerate() {
            assert_eq!(g.signed.prekey_id, i as u32);
            assert_eq!(g.signed.xwing_pub.len(), XWING_PK_LEN);
            assert_eq!(g.xwing_priv.as_ref().len(), XWING_SK_LEN);
            assert!(g.signed.verify(&pub_raw).unwrap());
        }
    }

    #[test]
    fn tampered_prekey_fails_verify() {
        let (priv_raw, pub_raw) = test_identity();
        let mut g = generate(1, 7, &priv_raw).unwrap().pop().unwrap();
        // Flip a public-key byte: the signature no longer matches.
        g.signed.xwing_pub[0] ^= 0xFF;
        assert!(!g.signed.verify(&pub_raw).unwrap());
    }

    #[test]
    fn signature_bound_to_identity() {
        let (priv_raw, _pub_raw) = test_identity();
        let g = generate(1, 0, &priv_raw).unwrap().pop().unwrap();
        // A different identity (hence different derived peer id) must
        // reject the same signed prekey.
        let (_other_priv, other_pub) = test_identity();
        assert!(!g.signed.verify(&other_pub).unwrap());
    }

    #[test]
    fn wire_roundtrip() {
        let (priv_raw, _pub_raw) = test_identity();
        let g = generate(1, 42, &priv_raw).unwrap().pop().unwrap();
        let bytes = g.signed.to_bytes();
        let (parsed, consumed) = SignedPrekey::from_bytes(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed, g.signed);
    }

    #[test]
    fn store_load_then_delete_lifecycle() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("prekeys.db");
        let dek = [0x11u8; 32];
        let (priv_raw, _pub_raw) = test_identity();
        let store = PrekeyStore::open(&path, &dek).unwrap();

        let batch = generate(2, 0, &priv_raw).unwrap();
        for g in &batch {
            store.insert(g.signed.prekey_id, g.xwing_priv.as_ref()).unwrap();
        }
        assert_eq!(store.count().unwrap(), 2);
        assert_eq!(store.list_ids().unwrap(), vec![0, 1]);

        // load() returns the key WITHOUT deleting — a failed decrypt must
        // not drain the pool, so the row survives a bare load.
        let sk = store.load(0).unwrap().expect("present");
        assert_eq!(sk.as_ref(), batch[0].xwing_priv.as_ref());
        assert_eq!(store.count().unwrap(), 2);

        // delete() retires the single-use key after a successful decrypt.
        assert!(store.delete(0).unwrap());
        assert_eq!(store.count().unwrap(), 1);
        assert!(store.load(0).unwrap().is_none());
        // Deleting an already-gone id is a no-op.
        assert!(!store.delete(0).unwrap());

        assert_eq!(store.delete_all().unwrap(), 1);
        assert_eq!(store.count().unwrap(), 0);
    }

    #[test]
    fn reserve_ids_is_monotonic_across_drain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("prekeys.db");
        let store = PrekeyStore::open(&path, &[0x22u8; 32]).unwrap();

        assert_eq!(store.reserve_ids(5).unwrap(), 0); // ids 0..=4
        assert_eq!(store.reserve_ids(3).unwrap(), 5); // ids 5..=7

        // Drain everything, then reserving again must NOT restart at 0.
        store.delete_all().unwrap();
        assert_eq!(store.reserve_ids(1).unwrap(), 8);

        // The high-water mark survives reopening the store.
        drop(store);
        let store = PrekeyStore::open(&path, &[0x22u8; 32]).unwrap();
        assert_eq!(store.reserve_ids(1).unwrap(), 9);
    }

    #[test]
    fn from_bytes_rejects_wrong_pubkey_len() {
        // A buffer claiming a 16 MB public key must be rejected on the
        // value check, not by allocating it.
        let mut buf = Vec::new();
        buf.extend_from_slice(&7u32.to_be_bytes()); // prekey_id
        buf.extend_from_slice(&(16u32 * 1024 * 1024).to_be_bytes()); // pub_len
        assert!(SignedPrekey::from_bytes(&buf).is_err());
    }

    // ---- blended key schedule -------------------------------------------

    fn xwing_keypair() -> (HpkeSecretKey, HpkePublicKey) {
        build_at_rest_suite().unwrap().kem_generate().unwrap()
    }

    const SALT: &[u8] = b"prekey-key-schedule-test-salt";

    #[test]
    fn full_mode_sender_and_recipient_agree() {
        let (s_sk, s_pk) = xwing_keypair();
        let (p_sk, p_pk) = xwing_keypair();

        let s = sender_key_schedule(&s_pk, Some(&p_pk), SALT).unwrap();
        assert_eq!(s.mode, MODE_FULL);
        let enc_prekey = s.enc_prekey.as_ref().unwrap();

        let r = recipient_key_schedule(
            MODE_FULL,
            &s_sk,
            &s_pk,
            &s.enc_static,
            Some((&p_sk, &p_pk, enc_prekey)),
            SALT,
        )
        .unwrap();
        assert_eq!(s.session_key.as_slice(), r.as_slice());
    }

    #[test]
    fn static_only_mode_sender_and_recipient_agree() {
        let (s_sk, s_pk) = xwing_keypair();
        let s = sender_key_schedule(&s_pk, None, SALT).unwrap();
        assert_eq!(s.mode, MODE_STATIC_ONLY);
        assert!(s.enc_prekey.is_none());

        let r = recipient_key_schedule(MODE_STATIC_ONLY, &s_sk, &s_pk, &s.enc_static, None, SALT)
            .unwrap();
        assert_eq!(s.session_key.as_slice(), r.as_slice());
    }

    #[test]
    fn full_and_static_keys_are_independent() {
        // Same static key, both modes — the domain-separated schedules
        // must not produce the same session key.
        let (_s_sk, s_pk) = xwing_keypair();
        let (_p_sk, p_pk) = xwing_keypair();
        let full = sender_key_schedule(&s_pk, Some(&p_pk), SALT).unwrap();
        let stat = sender_key_schedule(&s_pk, None, SALT).unwrap();
        assert_ne!(full.session_key.as_slice(), stat.session_key.as_slice());
    }

    #[test]
    fn fs_static_compromise_cannot_recover_full_key() {
        // The forward-secrecy claim: an attacker holding only the static
        // secret (the prekey secret has been deleted) cannot reconstruct a
        // full-mode session key.
        let (s_sk, s_pk) = xwing_keypair();
        let (_p_sk, p_pk) = xwing_keypair();
        let s = sender_key_schedule(&s_pk, Some(&p_pk), SALT).unwrap();

        // (a) Recovering in full mode without the prekey secret is impossible.
        let no_prekey =
            recipient_key_schedule(MODE_FULL, &s_sk, &s_pk, &s.enc_static, None, SALT);
        assert!(no_prekey.is_err());

        // (b) Even what the attacker *can* compute from the static key —
        // a static-only schedule — does not match the full session key.
        let attacker = recipient_key_schedule(
            MODE_STATIC_ONLY,
            &s_sk,
            &s_pk,
            &s.enc_static,
            None,
            SALT,
        )
        .unwrap();
        assert_ne!(s.session_key.as_slice(), attacker.as_slice());
    }

    #[test]
    fn wrong_prekey_secret_yields_different_key() {
        let (s_sk, s_pk) = xwing_keypair();
        let (_p_sk, p_pk) = xwing_keypair();
        let (wrong_sk, wrong_pk) = xwing_keypair();
        let s = sender_key_schedule(&s_pk, Some(&p_pk), SALT).unwrap();
        let enc_prekey = s.enc_prekey.as_ref().unwrap();

        // Decapsulating the prekey slot with the wrong keypair yields a
        // different shared secret, hence a different (useless) session key.
        let r = recipient_key_schedule(
            MODE_FULL,
            &s_sk,
            &s_pk,
            &s.enc_static,
            Some((&wrong_sk, &wrong_pk, enc_prekey)),
            SALT,
        );
        match r {
            Ok(k) => assert_ne!(s.session_key.as_slice(), k.as_slice()),
            Err(_) => {} // some KEMs reject the mismatch outright — also fine
        }
    }
}
