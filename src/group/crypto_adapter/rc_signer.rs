// Pure-Rust Ed25519 signer for the OpenSSL-free MLS cipher suite — the
// classical half of the hybrid Ed25519‖ML-DSA-65 signature. Mirrors
// `mls_rs_crypto_openssl::ec_signer::EcSigner` for Ed25519:
//   * secret key = `seed(32) || public(32)` = 64 bytes (OpenSSL's expanded
//     form, = ed25519-dalek `to_keypair_bytes()`), matching the hybrid
//     wrapper's `ED25519_SK_LEN = 64`;
//   * public key = raw 32 bytes;
//   * signature = 64 bytes (RFC 8032 PureEdDSA, deterministic → byte-identical
//     to OpenSSL).
// `verify_strict` matches OpenSSL's strict verification.

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use ed25519_dalek::Signer;
use mls_rs_core::crypto::{SignaturePublicKey, SignatureSecretKey};
use mls_rs_core::error::IntoAnyError;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const SEED_LEN: usize = 32;

#[derive(Debug, Error)]
pub enum RcSignerError {
    #[error("invalid Ed25519 secret key length {0} (expected >= 32)")]
    InvalidSecretLen(usize),
    #[error("invalid Ed25519 public key length {0} (expected 32)")]
    InvalidPublicLen(usize),
    #[error("invalid Ed25519 signature length {0} (expected 64)")]
    InvalidSignatureLen(usize),
    #[error("invalid Ed25519 public key")]
    InvalidPublicKey,
    #[error("signature verification failed")]
    InvalidSignature,
}

impl IntoAnyError for RcSignerError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(self.into())
    }
}

/// Reconstruct a `SigningKey` from a stored secret key. We use the first 32
/// bytes (the seed); the trailing 32 (the public component, present in the
/// 64-byte OpenSSL form) are ignored, exactly as OpenSSL does on import.
fn signing_key_from_secret(secret_key: &SignatureSecretKey) -> Result<SigningKey, RcSignerError> {
    let bytes = secret_key.as_ref();
    if bytes.len() < SEED_LEN {
        return Err(RcSignerError::InvalidSecretLen(bytes.len()));
    }
    // Wrap the copied seed so the stack scratch is wiped on drop. `SigningKey`
    // itself is `ZeroizeOnDrop`.
    let seed: Zeroizing<[u8; SEED_LEN]> = Zeroizing::new(
        bytes[..SEED_LEN]
            .try_into()
            .map_err(|_| RcSignerError::InvalidSecretLen(bytes.len()))?,
    );
    Ok(SigningKey::from_bytes(&seed))
}

#[derive(Clone, Debug, Default)]
pub struct RcEd25519Signer;

impl RcEd25519Signer {
    pub fn new() -> Self {
        Self
    }

    pub fn signature_key_generate(
        &self,
    ) -> Result<(SignatureSecretKey, SignaturePublicKey), RcSignerError> {
        // Draw the seed ourselves rather than calling `SigningKey::generate`,
        // which takes the RNG through ed25519-dalek's own `rand_core`
        // re-export. That couples this one line to whichever `rand_core` major
        // the dalek release happens to use, and the two go out of step (dalek
        // 3.0 moved on while the RustCrypto crates here are still on 0.6),
        // which turns a version bump into a build break for no cryptographic
        // reason. `generate` is exactly fill_bytes-into-32-then-from_bytes, so
        // this is the same key from the same entropy source.
        let mut seed: Zeroizing<[u8; SEED_LEN]> = Zeroizing::new([0u8; SEED_LEN]);
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, seed.as_mut());
        let signing = SigningKey::from_bytes(&seed);
        // `to_keypair_bytes` returns a fresh [u8; 64] copy of the secret; wipe
        // that stack scratch once it has been moved into the secret-key Vec.
        let mut kp = signing.to_keypair_bytes(); // seed(32) || pub(32)
        let secret = kp.to_vec();
        kp.zeroize();
        let public = signing.verifying_key().to_bytes().to_vec(); // 32
        Ok((SignatureSecretKey::from(secret), SignaturePublicKey::from(public)))
    }

    pub fn signature_key_derive_public(
        &self,
        secret_key: &SignatureSecretKey,
    ) -> Result<SignaturePublicKey, RcSignerError> {
        let signing = signing_key_from_secret(secret_key)?;
        Ok(SignaturePublicKey::from(
            signing.verifying_key().to_bytes().to_vec(),
        ))
    }

    pub fn sign(&self, secret_key: &SignatureSecretKey, data: &[u8]) -> Result<Vec<u8>, RcSignerError> {
        let signing = signing_key_from_secret(secret_key)?;
        Ok(signing.sign(data).to_bytes().to_vec())
    }

    pub fn verify(
        &self,
        public_key: &SignaturePublicKey,
        signature: &[u8],
        data: &[u8],
    ) -> Result<(), RcSignerError> {
        let pk_bytes: [u8; 32] = public_key
            .as_ref()
            .try_into()
            .map_err(|_| RcSignerError::InvalidPublicLen(public_key.as_ref().len()))?;
        let verifying =
            VerifyingKey::from_bytes(&pk_bytes).map_err(|_| RcSignerError::InvalidPublicKey)?;
        let sig_bytes: [u8; 64] = signature
            .try_into()
            .map_err(|_| RcSignerError::InvalidSignatureLen(signature.len()))?;
        let sig = Signature::from_bytes(&sig_bytes);
        verifying
            .verify_strict(data, &sig)
            .map_err(|_| RcSignerError::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8032 §7.1 TEST 1. Ed25519 is deterministic, so this is a fixed
    /// answer, not a property — which makes it the check that actually matters
    /// when the ed25519-dalek major version moves: MLS group state persisted by
    /// an older build carries keys and signatures produced by the previous
    /// release, and a roundtrip test would happily pass while silently
    /// agreeing with itself on a different curve convention.
    const RFC8032_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
        0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
        0x1c, 0xae, 0x7f, 0x60,
    ];
    const RFC8032_PUBLIC: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
        0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
        0xf7, 0x07, 0x51, 0x1a,
    ];
    /// Signature over the empty message.
    const RFC8032_SIG: [u8; 64] = [
        0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e,
        0x82, 0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65,
        0x22, 0x49, 0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e,
        0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
        0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
    ];

    /// The stored secret is `seed(32) || public(32)`; only the seed is read
    /// back, so build the full form the way the signer persists it.
    fn stored_secret() -> SignatureSecretKey {
        let mut v = RFC8032_SEED.to_vec();
        v.extend_from_slice(&RFC8032_PUBLIC);
        SignatureSecretKey::from(v)
    }

    #[test]
    fn public_key_derivation_matches_rfc8032() {
        let signer = RcEd25519Signer::new();
        let pk = signer
            .signature_key_derive_public(&stored_secret())
            .expect("derive");
        assert_eq!(pk.as_ref(), &RFC8032_PUBLIC);
    }

    #[test]
    fn signature_matches_rfc8032() {
        let signer = RcEd25519Signer::new();
        let sig = signer.sign(&stored_secret(), b"").expect("sign");
        assert_eq!(sig, RFC8032_SIG.to_vec());
    }

    /// Verification must accept a signature this build did not produce — the
    /// direction that breaks when an old peer or an old on-disk group meets a
    /// new binary.
    #[test]
    fn verify_accepts_rfc8032_signature() {
        let signer = RcEd25519Signer::new();
        let pk = SignaturePublicKey::from(RFC8032_PUBLIC.to_vec());
        signer.verify(&pk, &RFC8032_SIG, b"").expect("verify");
    }

    #[test]
    fn verify_rejects_a_tampered_signature() {
        let signer = RcEd25519Signer::new();
        let pk = SignaturePublicKey::from(RFC8032_PUBLIC.to_vec());
        let mut bad = RFC8032_SIG;
        bad[0] ^= 1;
        assert!(signer.verify(&pk, &bad, b"").is_err());
    }

    /// Generated keys must round-trip through the same stored form, and the
    /// seed-drawing path must not have changed what `generate` produced: a
    /// 64-byte secret whose trailing half is the public key.
    #[test]
    fn generated_key_has_the_stored_seed_public_layout() {
        let signer = RcEd25519Signer::new();
        let (sk, pk) = signer.signature_key_generate().expect("generate");
        assert_eq!(sk.as_ref().len(), 64);
        assert_eq!(pk.as_ref().len(), 32);
        assert_eq!(&sk.as_ref()[32..], pk.as_ref());
        let derived = signer.signature_key_derive_public(&sk).expect("derive");
        assert_eq!(derived.as_ref(), pk.as_ref());
    }
}
