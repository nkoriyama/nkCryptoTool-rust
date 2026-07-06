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
// Rationale: the read side of the shared LP codec, defined here alongside put_lp.
// Future plan: consumed by §6 KeyBundle parsing (parse_and_verify) in the next
// commit; already exercised by read_lp_rejects_* (§10(B) robustness) here.
#[allow(dead_code)]
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
}
