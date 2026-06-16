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
        let signing = SigningKey::generate(&mut rand_core::OsRng);
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
