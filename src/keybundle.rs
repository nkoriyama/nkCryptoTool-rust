/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

//! **keybind (§5) + KeyBundle (§6)** — the non-interactive key-distribution unit
//! of the ML-DSA single-anchor key-exchange feature (see `KEY_EXCHANGE_DESIGN.md`
//! §5/§6). A `KeyBundle` (`b"NKKB"`) is a self-signed unit that hangs a set of
//! encryption / hybrid public keys off the owner's ML-DSA identity: each key is
//! bound by a **keybind** signature, and the whole bundle by a self-signature.
//! The recipient pins the owner fingerprint out-of-band (phone), so a tampered
//! transport cannot substitute a key — the identity anchor authenticates every
//! bound key transitively.
//!
//! Not to be confused with `one_shot.rs`'s recipient bundle (`b"NKB1"`), which is
//! an unrelated inbox/async-path structure. This module is default (it needs only
//! the signing backend + SHA3), so its context separation is exercised by the
//! default test suite.
//!
//! This commit implements §5 (keybind); §6 (KeyBundle) builds on it.

use crate::backend;
use crate::error::CryptoError;

/// FIPS 204 native signature context for a **keybind** signature (§2.1). A
/// keybind signature can never be confused with a handshake / prekey / bundle /
/// file signature — each uses a distinct native ctx (or, for file, `ctx=""`,
/// which is now the only `ctx=""` identity context — §11.2).
const KEYBIND_CTX: &[u8] = b"nkct-keybind-v1";

/// `key_usage` discriminants (§5): the role of the bound `target_pubkey`.
pub const KEY_USAGE_ENC: u8 = 0x01; // ML-KEM encryption key
pub const KEY_USAGE_HYBRID: u8 = 0x02; // P-256 hybrid key

/// Errors from keybind / KeyBundle building, parsing, or verification.
#[derive(thiserror::Error, Debug)]
pub enum KeyBundleError {
    #[error("keybundle wire format: {0}")]
    Wire(String),
    #[error("keybundle signing backend: {0}")]
    Crypto(#[from] CryptoError),
    #[error("keybundle: unknown key_usage {0:#04x}")]
    BadUsage(u8),
}

type BResult<T> = std::result::Result<T, KeyBundleError>;

// -- length-prefix (LP) helpers: u32 little-endian length ‖ bytes -------------
// A private local implementation so this default module carries no dependency on
// the network transcript helpers. All reads are bounds-checked and never panic
// (attacker-controlled bytes must be a clean Err, not a remote DoS) — §10(B).

pub(crate) fn put_lp(buf: &mut Vec<u8>, b: &[u8]) {
    buf.extend_from_slice(&(b.len() as u32).to_le_bytes());
    buf.extend_from_slice(b);
}

/// Read one LP field starting at `*off`, advancing `*off` past it. Returns `Err`
/// on truncation or an over-large length (never panics, never over-allocates).
pub(crate) fn read_lp(buf: &[u8], off: &mut usize) -> BResult<Vec<u8>> {
    if buf.len() < *off + 4 {
        return Err(KeyBundleError::Wire("truncated LP length prefix".into()));
    }
    let len = u32::from_le_bytes(buf[*off..*off + 4].try_into().unwrap()) as usize;
    *off += 4;
    if buf.len() < *off + len {
        return Err(KeyBundleError::Wire(format!(
            "LP length {len} exceeds the {} remaining bytes",
            buf.len() - *off
        )));
    }
    let v = buf[*off..*off + len].to_vec();
    *off += len;
    Ok(v)
}

/// The exact byte string a keybind signature covers (§5):
/// `LP(owner_pk) ‖ u8(key_usage) ‖ LP(target_pk) ‖ LP(handle) ‖ u64_be(created_at)
///  ‖ u8(has_expiry) ‖ [u64_be(expires_at) if has_expiry]`.
///
/// Every field the verifier will trust is inside the signed bytes, so tampering
/// with any of them fails verification. `owner_pk` is included **self-referentially**
/// (anti-transplant, §3.2/§6.2): a keybind signed by one owner cannot be lifted
/// into another owner's bundle. **Field provenance for §6 reconstruction**: on
/// verify the caller passes `owner_pk` = the PINNED value (not a wire-trusted one),
/// `handle` = the bundle-level handle, and `created_at` = the per-entry value —
/// see §6.2 (E). This function is the single source of the signed layout so §6's
/// reconstruction rebuilds exactly these bytes.
fn keybind_blob(
    owner_pk: &[u8],
    key_usage: u8,
    target_pk: &[u8],
    handle: &str,
    created_at: u64,
    expires_at: Option<u64>,
) -> Vec<u8> {
    let mut b = Vec::new();
    put_lp(&mut b, owner_pk);
    b.push(key_usage);
    put_lp(&mut b, target_pk);
    put_lp(&mut b, handle.as_bytes());
    b.extend_from_slice(&created_at.to_be_bytes());
    match expires_at {
        Some(e) => {
            b.push(1);
            b.extend_from_slice(&e.to_be_bytes());
        }
        None => b.push(0),
    }
    b
}

/// Sign a **keybind**: bind `target_pk` (role `key_usage`) to the owner identity
/// under the native `nkct-keybind-v1` ctx. `sk_owner` is the owner's ML-DSA
/// private key; `owner_pk` its public key (self-referenced in the signed blob).
pub fn sign_keybind(
    dsa_algo: &str,
    sk_owner: &[u8],
    owner_pk: &[u8],
    key_usage: u8,
    target_pk: &[u8],
    handle: &str,
    created_at: u64,
    expires_at: Option<u64>,
) -> BResult<Vec<u8>> {
    if key_usage != KEY_USAGE_ENC && key_usage != KEY_USAGE_HYBRID {
        return Err(KeyBundleError::BadUsage(key_usage));
    }
    let blob = keybind_blob(owner_pk, key_usage, target_pk, handle, created_at, expires_at);
    Ok(backend::pqc_sign(dsa_algo, sk_owner, &blob, KEYBIND_CTX)?)
}

/// Verify a **keybind** signature. The blob is reconstructed from the supplied
/// fields and verified with `owner_pk` under `nkct-keybind-v1`. The caller MUST
/// pass `owner_pk` = the value it has PINNED (§6.2) — never a wire-trusted key —
/// so the signature is checked against the anchored identity, not a substitute.
pub fn verify_keybind(
    dsa_algo: &str,
    owner_pk: &[u8],
    key_usage: u8,
    target_pk: &[u8],
    handle: &str,
    created_at: u64,
    expires_at: Option<u64>,
    sig: &[u8],
) -> BResult<bool> {
    let blob = keybind_blob(owner_pk, key_usage, target_pk, handle, created_at, expires_at);
    Ok(backend::pqc_verify(dsa_algo, owner_pk, &blob, sig, KEYBIND_CTX)?)
}

// -- §6 KeyBundle -------------------------------------------------------------

/// KeyBundle magic (§6): `b"NKKB"` (NK KeyBundle). Distinct from every other
/// 4-byte magic — in particular NOT `b"NKB1"` (the unrelated `one_shot` recipient
/// bundle) nor `b"NKCB"` (the MLS credential binding).
const BUNDLE_MAGIC: &[u8; 4] = b"NKKB";
const BUNDLE_VERSION: u8 = 1;
/// FIPS 204 native signature context for the KeyBundle self-signature (§2.1).
const BUNDLE_CTX: &[u8] = b"nkct-bundle-v1";
/// Upper bound on the bound-key count `n`: a malformed/huge count is rejected
/// before allocating (§10(B)). A real bundle carries a handful of keys.
const MAX_BUNDLE_KEYS: usize = 64;

/// Upper bound on any single LP field written by `build_signed` (§10(B)). Far
/// above any real key/handle (ML-DSA pub ≈ 2 KiB, ML-KEM ek ≈ 1.2 KiB), but well
/// below `u32::MAX` so the `len as u32` LP cast can never truncate and corrupt
/// the frame. On parse, `read_lp` already bounds each field by the remaining buffer.
const MAX_FIELD_LEN: usize = 64 * 1024;

/// One key bound into a KeyBundle: `target_pk` in role `key_usage`, with its own
/// timestamps. On a verified bundle every field here was covered by BOTH the
/// per-key keybind signature and the bundle self-signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundKey {
    pub key_usage: u8,
    pub target_pk: Vec<u8>,
    pub created_at: u64,
    /// Authenticated (untampered) but **not enforced** by `parse_and_verify`: the
    /// caller MUST compare it to its clock and reject an expired key (see
    /// `parse_and_verify`). Entry-point enforcement lives in the CLI increment.
    pub expires_at: Option<u64>,
    /// The §5 keybind signature over this key (carried in the wire bundle).
    pub keybind_sig: Vec<u8>,
}

/// A parsed-and-verified KeyBundle. Every field is authenticated: the owner
/// fingerprint matched the pin, the self-signature covered the whole body, and
/// each `keys[i]` carried a valid keybind signature under the owner identity.
#[derive(Clone, Debug)]
pub struct VerifiedKeyBundle {
    pub owner_pk: Vec<u8>,
    pub handle: String,
    pub created_at: u64,
    pub keys: Vec<BoundKey>,
}

/// Serialize the bundle **body** — everything the self-signature covers: magic,
/// version, owner, handle, created_at, count, and each entry. `LP(self_sig)` is
/// appended by the caller. This is the single source of the signed layout, so
/// `parse_and_verify` verifies the self-signature over exactly these bytes.
fn bundle_body(owner_pk: &[u8], handle: &str, created_at: u64, keys: &[BoundKey]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(BUNDLE_MAGIC);
    b.push(BUNDLE_VERSION);
    put_lp(&mut b, owner_pk);
    put_lp(&mut b, handle.as_bytes());
    b.extend_from_slice(&created_at.to_be_bytes());
    b.extend_from_slice(&(keys.len() as u16).to_le_bytes());
    for k in keys {
        b.push(k.key_usage);
        put_lp(&mut b, &k.target_pk);
        b.extend_from_slice(&k.created_at.to_be_bytes());
        match k.expires_at {
            Some(e) => {
                b.push(1);
                b.extend_from_slice(&e.to_be_bytes());
            }
            None => b.push(0),
        }
        put_lp(&mut b, &k.keybind_sig);
    }
    b
}

/// Build a signed KeyBundle: sign a keybind over each `(usage, target_pk,
/// created_at, expires_at)`, assemble the body, then self-sign it under
/// `nkct-bundle-v1`. `handle` is bundle-level and is signed into every keybind.
pub fn build_signed(
    dsa_algo: &str,
    sk_owner: &[u8],
    owner_pk: &[u8],
    handle: &str,
    created_at: u64,
    keys: &[(u8, Vec<u8>, u64, Option<u64>)],
) -> BResult<Vec<u8>> {
    if keys.len() > MAX_BUNDLE_KEYS {
        return Err(KeyBundleError::Wire(format!(
            "{} keys exceeds the {MAX_BUNDLE_KEYS} bound",
            keys.len()
        )));
    }
    // §10(B): guard every caller-provided field that goes through a u32 LP length,
    // so an over-large input cannot truncate on the `as u32` cast and corrupt the
    // frame. (owner_pk / handle here; internally-generated sigs are ML-DSA-sized.)
    if owner_pk.len() > MAX_FIELD_LEN || handle.len() > MAX_FIELD_LEN {
        return Err(KeyBundleError::Wire("owner_pk or handle exceeds MAX_FIELD_LEN".into()));
    }
    if let Some((_, big, _, _)) = keys.iter().find(|(_, t, _, _)| t.len() > MAX_FIELD_LEN) {
        return Err(KeyBundleError::Wire(format!("target_pk of {} bytes exceeds MAX_FIELD_LEN", big.len())));
    }
    let mut bound = Vec::with_capacity(keys.len());
    for (usage, target_pk, k_created, k_exp) in keys {
        let sig = sign_keybind(dsa_algo, sk_owner, owner_pk, *usage, target_pk, handle, *k_created, *k_exp)?;
        bound.push(BoundKey {
            key_usage: *usage,
            target_pk: target_pk.clone(),
            created_at: *k_created,
            expires_at: *k_exp,
            keybind_sig: sig,
        });
    }
    let body = bundle_body(owner_pk, handle, created_at, &bound);
    let self_sig = backend::pqc_sign(dsa_algo, sk_owner, &body, BUNDLE_CTX)?;
    let mut out = body;
    put_lp(&mut out, &self_sig);
    Ok(out)
}

/// Parse and fully verify a KeyBundle against a **pinned owner fingerprint**
/// (`SHA3-256(owner_pk_raw)`, obtained out-of-band). Verification (§6):
/// (1) the wire owner pub hashes to the pin; (2) the self-signature verifies with
/// that owner pub over the body; (3) each keybind reconstructs (§5) and verifies.
/// §6.2: the owner is the pin-anchored value, the handle is bundle-level, and each
/// keybind is reconstructed with its own per-entry `created_at` (E) — no
/// signature-uncovered plaintext is trusted. §10(B): every LP is bounds-checked,
/// `n` is capped and must match, trailing bytes are rejected, nothing panics.
///
/// **Expiry is NOT enforced here (authenticity vs policy — deliberate layering).**
/// This function verifies *authenticity* only: it guarantees each `expires_at` is
/// the value the owner signed (untampered, since it is inside the covered blob),
/// but it does **not** compare it to a clock — verification stays time-independent
/// so it is reproducible and KAT-testable, and each caller keeps its own policy.
/// `BoundKey.expires_at` is returned; **the caller MUST reject an expired key
/// against its own current time before using it.** The actual entry-point
/// enforcement lands in the CLI increment (a `--recipient-bundle` past its expiry
/// is rejected with a message) — expiry is enforced *there*, not silently dropped.
pub fn parse_and_verify(
    bytes: &[u8],
    dsa_algo: &str,
    pinned_owner_fp: &[u8; 32],
) -> BResult<VerifiedKeyBundle> {
    use sha3::{Digest, Sha3_256};

    let mut off = 0usize;
    if bytes.len() < 5 || &bytes[0..4] != BUNDLE_MAGIC {
        return Err(KeyBundleError::Wire("bad magic (not an NKKB KeyBundle)".into()));
    }
    off += 4;
    let version = read_u8(bytes, &mut off)?;
    if version != BUNDLE_VERSION {
        return Err(KeyBundleError::Wire(format!("unsupported version {version}")));
    }
    let owner_pk = read_lp(bytes, &mut off)?;
    let handle = String::from_utf8(read_lp(bytes, &mut off)?)
        .map_err(|_| KeyBundleError::Wire("handle is not valid UTF-8".into()))?;
    let created_at = read_u64_be(bytes, &mut off)?;
    let n = read_u16_le(bytes, &mut off)? as usize;
    if n > MAX_BUNDLE_KEYS {
        return Err(KeyBundleError::Wire(format!("{n} keys exceeds the {MAX_BUNDLE_KEYS} bound")));
    }

    let mut keys = Vec::with_capacity(n);
    for _ in 0..n {
        let key_usage = read_u8(bytes, &mut off)?;
        let target_pk = read_lp(bytes, &mut off)?;
        let k_created = read_u64_be(bytes, &mut off)?;
        let expires_at = match read_u8(bytes, &mut off)? {
            0 => None,
            1 => Some(read_u64_be(bytes, &mut off)?),
            other => return Err(KeyBundleError::Wire(format!("has_expiry must be 0/1, got {other}"))),
        };
        let keybind_sig = read_lp(bytes, &mut off)?;
        keys.push(BoundKey { key_usage, target_pk, created_at: k_created, expires_at, keybind_sig });
    }

    // The self-signature covers exactly the body (magic .. last entry).
    let body_end = off;
    let self_sig = read_lp(bytes, &mut off)?;
    if off != bytes.len() {
        return Err(KeyBundleError::Wire(format!("{} trailing byte(s) after the bundle", bytes.len() - off)));
    }

    // (1) wire owner pub must hash to the pinned fingerprint.
    let owner_fp: [u8; 32] = Sha3_256::digest(&owner_pk).into();
    if &owner_fp != pinned_owner_fp {
        return Err(KeyBundleError::Wire("owner fingerprint does not match the pinned identity".into()));
    }
    // (2) self-signature must verify with the pin-anchored owner pub over the body.
    if !backend::pqc_verify(dsa_algo, &owner_pk, &bytes[..body_end], &self_sig, BUNDLE_CTX)? {
        return Err(KeyBundleError::Wire("bundle self-signature failed".into()));
    }
    // (3) each keybind reconstructs (§5) with the pin-anchored owner, the
    //     bundle-level handle, and its own per-entry created_at (§6.2 / (E)).
    for k in &keys {
        let ok = verify_keybind(
            dsa_algo, &owner_pk, k.key_usage, &k.target_pk, &handle, k.created_at, k.expires_at, &k.keybind_sig,
        )?;
        if !ok {
            return Err(KeyBundleError::Wire("a keybind signature failed".into()));
        }
    }

    Ok(VerifiedKeyBundle { owner_pk, handle, created_at, keys })
}

// Fixed-width readers — bounds-checked, never panic (§10(B)).
fn read_u8(buf: &[u8], off: &mut usize) -> BResult<u8> {
    if buf.len() < *off + 1 {
        return Err(KeyBundleError::Wire("truncated u8".into()));
    }
    let v = buf[*off];
    *off += 1;
    Ok(v)
}
fn read_u16_le(buf: &[u8], off: &mut usize) -> BResult<u16> {
    if buf.len() < *off + 2 {
        return Err(KeyBundleError::Wire("truncated u16".into()));
    }
    let v = u16::from_le_bytes(buf[*off..*off + 2].try_into().unwrap());
    *off += 2;
    Ok(v)
}
fn read_u64_be(buf: &[u8], off: &mut usize) -> BResult<u64> {
    if buf.len() < *off + 8 {
        return Err(KeyBundleError::Wire("truncated u64".into()));
    }
    let v = u64::from_be_bytes(buf[*off..*off + 8].try_into().unwrap());
    *off += 8;
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DSA: &str = "ML-DSA-65";

    fn owner() -> (Vec<u8>, Vec<u8>) {
        let (sk, pk, _) = backend::pqc_keygen_dsa(DSA).unwrap();
        (sk.to_vec(), pk)
    }

    #[test]
    fn keybind_roundtrips_and_detects_field_tamper() {
        let (sk, pk) = owner();
        let target = vec![9u8; 1184]; // stand-in ML-KEM ek
        let sig = sign_keybind(DSA, &sk, &pk, KEY_USAGE_ENC, &target, "alice", 1000, None).unwrap();
        // Correct fields verify.
        assert!(verify_keybind(DSA, &pk, KEY_USAGE_ENC, &target, "alice", 1000, None, &sig).unwrap());
        // Any field change (each is inside the signed blob) fails.
        assert!(!verify_keybind(DSA, &pk, KEY_USAGE_HYBRID, &target, "alice", 1000, None, &sig).unwrap(), "usage");
        assert!(!verify_keybind(DSA, &pk, KEY_USAGE_ENC, &vec![8u8; 1184], "alice", 1000, None, &sig).unwrap(), "target");
        assert!(!verify_keybind(DSA, &pk, KEY_USAGE_ENC, &target, "bob", 1000, None, &sig).unwrap(), "handle");
        assert!(!verify_keybind(DSA, &pk, KEY_USAGE_ENC, &target, "alice", 1001, None, &sig).unwrap(), "created_at");
        assert!(!verify_keybind(DSA, &pk, KEY_USAGE_ENC, &target, "alice", 1000, Some(5), &sig).unwrap(), "expiry");
    }

    #[test]
    fn keybind_transplant_to_other_owner_fails() {
        // A keybind signed by owner A cannot be lifted under owner B: owner_pk is
        // self-referenced in the signed blob, so reconstructing with B's pk (and
        // verifying with B's pk) fails.
        let (sk_a, pk_a) = owner();
        let (_sk_b, pk_b) = owner();
        let target = vec![7u8; 1184];
        let sig = sign_keybind(DSA, &sk_a, &pk_a, KEY_USAGE_ENC, &target, "svc", 1, None).unwrap();
        assert!(verify_keybind(DSA, &pk_a, KEY_USAGE_ENC, &target, "svc", 1, None, &sig).unwrap());
        assert!(!verify_keybind(DSA, &pk_b, KEY_USAGE_ENC, &target, "svc", 1, None, &sig).unwrap());
    }

    #[test]
    fn file_ctx_signature_does_not_verify_as_keybind() {
        // §11.2: a ctx="" (file-style) signature over the exact keybind blob must
        // not verify as a keybind. The native KEYBIND_CTX separates them; the
        // message bytes are identical, only the ctx differs.
        let (sk, pk) = owner();
        let target = vec![3u8; 1184];
        let blob = keybind_blob(&pk, KEY_USAGE_ENC, &target, "x", 42, None);
        let forged = backend::pqc_sign(DSA, &sk, &blob, &[]).unwrap();
        assert!(
            !verify_keybind(DSA, &pk, KEY_USAGE_ENC, &target, "x", 42, None, &forged).unwrap(),
            "a ctx=\"\" signature must not pass keybind verification"
        );
    }

    #[test]
    fn read_lp_rejects_truncation_and_overlong_without_panic() {
        // §10(B): the LP reader returns Err, never panics.
        let mut off = 0;
        assert!(read_lp(&[0u8; 2], &mut off).is_err(), "truncated length");
        let mut off = 0;
        // length says 100 but only 4 bytes follow the prefix
        let mut bad = (100u32).to_le_bytes().to_vec();
        bad.extend_from_slice(&[0u8; 4]);
        assert!(read_lp(&bad, &mut off).is_err(), "overlong length");
        // a well-formed LP round-trips.
        let mut good = Vec::new();
        put_lp(&mut good, b"hello");
        let mut off = 0;
        assert_eq!(read_lp(&good, &mut off).unwrap(), b"hello");
        assert_eq!(off, good.len());
    }

    // -- §6 KeyBundle ------------------------------------------------------

    fn sample_bundle(sk: &[u8], pk: &[u8]) -> (Vec<u8>, [u8; 32]) {
        use sha3::{Digest, Sha3_256};
        let bytes = build_signed(
            DSA, sk, pk, "alice", 1000,
            &[
                (KEY_USAGE_ENC, vec![1u8; 1184], 1000, None),
                (KEY_USAGE_HYBRID, vec![4u8; 91], 1001, Some(9999)),
            ],
        )
        .unwrap();
        let fp: [u8; 32] = Sha3_256::digest(pk).into();
        (bytes, fp)
    }

    #[test]
    fn bundle_roundtrips_and_verifies() {
        let (sk, pk) = owner();
        let (bytes, fp) = sample_bundle(&sk, &pk);
        let vb = parse_and_verify(&bytes, DSA, &fp).unwrap();
        assert_eq!(vb.owner_pk, pk);
        assert_eq!(vb.handle, "alice");
        assert_eq!(vb.keys.len(), 2);
        assert_eq!(vb.keys[0].key_usage, KEY_USAGE_ENC);
        assert_eq!(vb.keys[1].expires_at, Some(9999));
    }

    #[test]
    fn bundle_wrong_pin_rejected() {
        let (sk, pk) = owner();
        let (bytes, _fp) = sample_bundle(&sk, &pk);
        assert!(parse_and_verify(&bytes, DSA, &[0u8; 32]).is_err(), "owner fp must match the pin");
    }

    #[test]
    fn bundle_body_tamper_rejected() {
        let (sk, pk) = owner();
        let (mut bytes, fp) = sample_bundle(&sk, &pk);
        // Flip a byte well past owner_pk (so the fp check passes) but inside the
        // signed body — the self-signature (and the covering keybind) must catch it.
        let at = bytes.len() / 3;
        bytes[at] ^= 0xff;
        assert!(parse_and_verify(&bytes, DSA, &fp).is_err(), "body tamper must be caught");
    }

    #[test]
    fn bundle_keybind_transplant_across_owners_rejected() {
        // §6.2 transplant: a keybind signed under owner A cannot be presented in a
        // bundle whose owner is B. Splice A's keybind_sig into a bundle B self-signs;
        // parse must reject — the keybind reconstructs under B's owner_pk and fails.
        use sha3::{Digest, Sha3_256};
        let (sk_a, pk_a) = owner();
        let (sk_b, pk_b) = owner();
        let enc = vec![2u8; 1184];
        let a_sig = sign_keybind(DSA, &sk_a, &pk_a, KEY_USAGE_ENC, &enc, "svc", 5, None).unwrap();
        let bound = vec![BoundKey {
            key_usage: KEY_USAGE_ENC,
            target_pk: enc,
            created_at: 5,
            expires_at: None,
            keybind_sig: a_sig,
        }];
        let body = bundle_body(&pk_b, "svc", 5, &bound);
        let self_sig = backend::pqc_sign(DSA, &sk_b, &body, BUNDLE_CTX).unwrap();
        let mut bytes = body;
        put_lp(&mut bytes, &self_sig);
        let fp_b: [u8; 32] = Sha3_256::digest(&pk_b).into();
        assert!(parse_and_verify(&bytes, DSA, &fp_b).is_err(), "A's keybind must not verify under owner B");
    }

    #[test]
    fn bundle_file_ctx_self_sig_rejected() {
        // A ctx="" (file-style) self-signature over the body must not verify — the
        // native BUNDLE_CTX separates the bundle self-sig from a file signature.
        use sha3::{Digest, Sha3_256};
        let (sk, pk) = owner();
        let kb = sign_keybind(DSA, &sk, &pk, KEY_USAGE_ENC, &vec![1u8; 1184], "h", 1, None).unwrap();
        let bound = vec![BoundKey {
            key_usage: KEY_USAGE_ENC,
            target_pk: vec![1u8; 1184],
            created_at: 1,
            expires_at: None,
            keybind_sig: kb,
        }];
        let body = bundle_body(&pk, "h", 1, &bound);
        let forged = backend::pqc_sign(DSA, &sk, &body, &[]).unwrap(); // ctx=""
        let mut bytes = body;
        put_lp(&mut bytes, &forged);
        let fp: [u8; 32] = Sha3_256::digest(&pk).into();
        assert!(parse_and_verify(&bytes, DSA, &fp).is_err(), "ctx=\"\" self-sig must not verify");
    }

    #[test]
    fn bundle_parser_rejects_malformed_without_panic() {
        let (sk, pk) = owner();
        let (bytes, fp) = sample_bundle(&sk, &pk);
        let mut bad_magic = bytes.clone();
        bad_magic[0] = b'X';
        assert!(parse_and_verify(&bad_magic, DSA, &fp).is_err(), "bad magic");
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(parse_and_verify(&trailing, DSA, &fp).is_err(), "trailing byte");
        assert!(parse_and_verify(&bytes[..bytes.len() / 2], DSA, &fp).is_err(), "truncated");
        assert!(parse_and_verify(&[], DSA, &fp).is_err(), "empty");
    }
}
