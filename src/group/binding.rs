/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

//! Phase 0 of the MLS <-> P2P transport sync (see `MLS_P2P_SYNC_DESIGN.md` §2):
//! a domain-separated, epoch-scoped, **bidirectional binding signature** that
//! ties an MLS member's hybrid signing identity to its transport (ML-DSA-65)
//! identity.
//!
//! The two identities are independent keys — the MLS identity is a hybrid
//! `Ed25519 ‖ ML-DSA-65` key (redb), the transport identity is a standalone
//! `ML-DSA-65` key (a PKCS#8 file). A member links them by signing **one**
//! message with **both** keys:
//!
//! ```text
//! msg = CONTEXT ‖ epoch ‖ len(mls_pub) ‖ mls_pub ‖ len(transport_pub) ‖ transport_pub
//! binding = { mls_sig = Sign_MLS(msg), transport_sig = Sign_transport(msg) }
//! ```
//!
//! Both signatures must verify. This addresses the review findings:
//! - **Bidirectional / proof-of-possession**: a malicious member cannot bind a
//!   *victim's* transport key, because creating `transport_sig` requires the
//!   transport private key (it can only bind a key it actually controls).
//! - **Freshness / rotation**: the `epoch` scopes the binding, so a binding for
//!   a rotated-away transport key does not stay valid forever.
//! - **Key-commitment (anti-DSKS)**: the signer's MLS public key is inside the
//!   signed message, naming the binding's subject explicitly.
//!
//! Combined with the MLS roster (membership authority) and the transport
//! handshake (live proof of control of the transport key), this yields the
//! authenticated "MLS member ↔ transport fingerprint" mapping the allowlist is
//! projected from.

use mls_rs_core::crypto::{CipherSuiteProvider, SignaturePublicKey, SignatureSecretKey};
use sha3::{Digest, Sha3_256};

/// Domain-separation context. A binding signature is valid only for this
/// purpose and is never interchangeable with an MLS framing signature (which
/// uses RFC 9420's own labels) or a transport-handshake signature.
pub const BINDING_CONTEXT: &[u8] = b"nkct-mls-transport-binding-v1";

/// Signature scheme of the transport identity key.
pub const TRANSPORT_DSA_ALGO: &str = "ML-DSA-65";

/// A member's MLS↔transport binding: the same message signed by both keys.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MemberBinding {
    /// Hybrid signature by the MLS identity key.
    pub mls_sig: Vec<u8>,
    /// ML-DSA-65 signature by the transport identity key (proof of possession).
    pub transport_sig: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum BindingError {
    #[error("MLS binding signature failed: {0}")]
    MlsSign(String),
    #[error("transport binding signature failed: {0}")]
    TransportSign(String),
}

/// Exact bytes both keys sign: `CONTEXT ‖ epoch ‖ lp(mls_pub) ‖ lp(transport_pub) ‖ peer_id`
/// where `lp(x) = len(x) as be64 ‖ x`. The length prefixes and the embedded MLS
/// public key remove field-boundary ambiguity and pin the binding's subject.
fn binding_message(epoch: u64, mls_pub: &[u8], transport_dsa_pub: &[u8], peer_id: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(
        BINDING_CONTEXT.len() + 8 + 8 + mls_pub.len() + 8 + transport_dsa_pub.len() + 32,
    );
    m.extend_from_slice(BINDING_CONTEXT);
    m.extend_from_slice(&epoch.to_be_bytes());
    m.extend_from_slice(&(mls_pub.len() as u64).to_be_bytes());
    m.extend_from_slice(mls_pub);
    m.extend_from_slice(&(transport_dsa_pub.len() as u64).to_be_bytes());
    m.extend_from_slice(transport_dsa_pub);
    m.extend_from_slice(peer_id);
    m
}

/// Create a binding. Requires control of **both** the MLS identity key and the
/// transport identity private key (the member binds only keys it owns).
pub fn create_binding<P: CipherSuiteProvider>(
    suite: &P,
    mls_sk: &SignatureSecretKey,
    mls_pub: &SignaturePublicKey,
    transport_algo: &str,
    transport_dsa_priv: &[u8],
    transport_dsa_pub: &[u8],
    epoch: u64,
    peer_id: &[u8; 32],
) -> Result<MemberBinding, BindingError> {
    let msg = binding_message(epoch, mls_pub.as_bytes(), transport_dsa_pub, peer_id);
    let mls_sig = suite
        .sign(mls_sk, &msg)
        .map_err(|e| BindingError::MlsSign(format!("{e:?}")))?;
    let transport_sig = crate::backend::pqc_sign(transport_algo, transport_dsa_priv, &msg, None)
        .map_err(|e| BindingError::TransportSign(e.to_string()))?;
    Ok(MemberBinding {
        mls_sig,
        transport_sig,
    })
}

/// Verify a binding: **both** the MLS-side and transport-side signatures must
/// be valid for exactly this `(epoch, mls_pub, transport_pub, peer_id)` tuple.
pub fn verify_binding<P: CipherSuiteProvider>(
    suite: &P,
    mls_pub: &SignaturePublicKey,
    transport_algo: &str,
    transport_dsa_pub: &[u8],
    epoch: u64,
    peer_id: &[u8; 32],
    binding: &MemberBinding,
) -> bool {
    let msg = binding_message(epoch, mls_pub.as_bytes(), transport_dsa_pub, peer_id);
    let mls_ok = suite.verify(mls_pub, &binding.mls_sig, &msg).is_ok();
    let transport_ok = matches!(
        crate::backend::pqc_verify(transport_algo, transport_dsa_pub, &msg, &binding.transport_sig),
        Ok(true)
    );
    mls_ok && transport_ok
}

/// Allowlist / `PeerId` key for a transport identity: SHA3-256 of its
/// ML-DSA-65 public key. Matches the existing `cached_allowlist` entries and
/// the ticket `pqc_sign_fp` form, so a verified binding projects directly onto
/// the transport allowlist.
pub fn transport_fingerprint(transport_dsa_pub: &[u8]) -> [u8; 32] {
    Sha3_256::digest(transport_dsa_pub).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::crypto_adapter::{hybrid_cipher_suite, HybridCryptoProvider};
    use mls_rs_core::crypto::CryptoProvider;

    fn suite() -> impl CipherSuiteProvider {
        HybridCryptoProvider::new()
            .cipher_suite_provider(hybrid_cipher_suite())
            .expect("hybrid cipher suite")
    }

    // (mls_sk, mls_pub, transport_priv, transport_pub)
    fn member(s: &impl CipherSuiteProvider) -> (SignatureSecretKey, SignaturePublicKey, Vec<u8>, Vec<u8>) {
        let (msk, mpk) = s.signature_key_generate().unwrap();
        let (tsk, tpk, _) = crate::backend::pqc_keygen_dsa(TRANSPORT_DSA_ALGO).unwrap();
        (msk, mpk, tsk.to_vec(), tpk)
    }

    #[test]
    fn binding_roundtrip_verifies() {
        let s = suite();
        let (msk, mpk, tsk, tpk) = member(&s);
        let pid = [1u8; 32];
        let b = create_binding(&s, &msk, &mpk, TRANSPORT_DSA_ALGO, &tsk, &tpk, 7, &pid).unwrap();
        assert!(verify_binding(&s, &mpk, TRANSPORT_DSA_ALGO, &tpk, 7, &pid, &b));
    }

    #[test]
    fn wrong_epoch_rejected() {
        let s = suite();
        let (msk, mpk, tsk, tpk) = member(&s);
        let pid = [1u8; 32];
        let b = create_binding(&s, &msk, &mpk, TRANSPORT_DSA_ALGO, &tsk, &tpk, 7, &pid).unwrap();
        assert!(
            !verify_binding(&s, &mpk, TRANSPORT_DSA_ALGO, &tpk, 8, &pid, &b),
            "a binding must not verify under a different epoch"
        );
    }

    #[test]
    fn wrong_mls_key_rejected() {
        let s = suite();
        let (msk, mpk, tsk, tpk) = member(&s);
        let (_msk2, mpk2) = s.signature_key_generate().unwrap();
        let pid = [1u8; 32];
        let b = create_binding(&s, &msk, &mpk, TRANSPORT_DSA_ALGO, &tsk, &tpk, 1, &pid).unwrap();
        assert!(!verify_binding(&s, &mpk2, TRANSPORT_DSA_ALGO, &tpk, 1, &pid, &b));
    }

    #[test]
    fn wrong_peer_id_rejected() {
        let s = suite();
        let (msk, mpk, tsk, tpk) = member(&s);
        let pid1 = [1u8; 32];
        let pid2 = [2u8; 32];
        let b = create_binding(&s, &msk, &mpk, TRANSPORT_DSA_ALGO, &tsk, &tpk, 1, &pid1).unwrap();
        assert!(!verify_binding(&s, &mpk, TRANSPORT_DSA_ALGO, &tpk, 1, &pid2, &b));
    }

    #[test]
    fn malicious_member_cannot_bind_a_victims_transport_key() {
        // A member (mpk) tries to bind a *victim's* transport public key that
        // it does not control. Without the victim's transport private key it
        // cannot produce a valid transport_sig, so verification fails — the
        // bidirectional proof-of-possession defeats the insider-bind attack.
        let s = suite();
        let (msk, mpk, attacker_tsk, _attacker_tpk) = member(&s);
        let (_victim_tsk, victim_tpk, _) = crate::backend::pqc_keygen_dsa(TRANSPORT_DSA_ALGO).unwrap();
        let pid = [1u8; 32];
        // Forge a binding claiming victim_tpk, but sign the transport half with
        // the attacker's own transport key (the best they can do).
        let msg = binding_message(1, mpk.as_bytes(), &victim_tpk, &pid);
        let mls_sig = s.sign(&msk, &msg).unwrap();
        let transport_sig =
            crate::backend::pqc_sign(TRANSPORT_DSA_ALGO, &attacker_tsk, &msg, None).unwrap();
        let forged = MemberBinding { mls_sig, transport_sig };
        assert!(
            !verify_binding(&s, &mpk, TRANSPORT_DSA_ALGO, &victim_tpk, 1, &pid, &forged),
            "binding a transport key without its private key must not verify"
        );
    }

    #[test]
    fn tampered_transport_pub_rejected() {
        let s = suite();
        let (msk, mpk, tsk, tpk) = member(&s);
        let (_o, other_tpk, _) = crate::backend::pqc_keygen_dsa(TRANSPORT_DSA_ALGO).unwrap();
        let pid = [1u8; 32];
        let b = create_binding(&s, &msk, &mpk, TRANSPORT_DSA_ALGO, &tsk, &tpk, 1, &pid).unwrap();
        assert!(!verify_binding(&s, &mpk, TRANSPORT_DSA_ALGO, &other_tpk, 1, &pid, &b));
    }

    #[test]
    fn fingerprint_is_sha3_256() {
        let fp = transport_fingerprint(b"abc");
        assert_eq!(fp.len(), 32);
        assert_eq!(&fp[..], Sha3_256::digest(b"abc").as_slice());
    }
}
