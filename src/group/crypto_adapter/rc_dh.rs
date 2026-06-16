// Pure-Rust X25519 Diffie-Hellman for the OpenSSL-free MLS cipher suite.
//
// Mirrors `mls_rs_crypto_openssl::ecdh::Ecdh` for the X25519 curve only (the
// hybrid KEM never uses X448 or the NIST curves). Interop with files written by
// the OpenSSL provider is preserved because:
//   * stored secret-key bytes are kept RAW (x25519-dalek 2.x `StaticSecret`
//     stores the seed as-is and clamps internally at DH/`to_public` time, just
//     like OpenSSL's `raw_private_key`), and
//   * X25519 uses `SamplingMethod::HpkeWithoutBitmask` (no rejection sampling),
//     matching OpenSSL, so `DhKem::derive` produces identical (sk, pk) bytes.

use mls_rs_core::crypto::{HpkePublicKey, HpkeSecretKey};
use mls_rs_core::error::IntoAnyError;
use mls_rs_crypto_traits::{DhType, SamplingMethod};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

const X25519_KEY_LEN: usize = 32;

#[derive(Debug, Error)]
pub enum RcDhError {
    #[error("invalid X25519 key length {0} (expected 32)")]
    InvalidKeyLen(usize),
}

impl IntoAnyError for RcDhError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(self.into())
    }
}

fn array32(bytes: &[u8]) -> Result<[u8; 32], RcDhError> {
    <[u8; 32]>::try_from(bytes).map_err(|_| RcDhError::InvalidKeyLen(bytes.len()))
}

#[derive(Clone, Debug)]
pub struct RcEcdh;

impl RcEcdh {
    pub fn new() -> Self {
        Self
    }
}

impl Default for RcEcdh {
    fn default() -> Self {
        Self::new()
    }
}

impl DhType for RcEcdh {
    type Error = RcDhError;

    fn dh(
        &self,
        secret_key: &HpkeSecretKey,
        public_key: &HpkePublicKey,
    ) -> Result<Vec<u8>, RcDhError> {
        // `StaticSecret::from` copies the array in (it is `Copy`); wipe the
        // stack scratch once consumed. `StaticSecret` is `ZeroizeOnDrop`.
        let mut sk_bytes = array32(secret_key.as_ref())?;
        let sk = StaticSecret::from(sk_bytes);
        sk_bytes.zeroize();
        let pk = PublicKey::from(array32(public_key.as_ref())?);
        // dalek clamps the scalar internally before the multiplication, so the
        // raw shared secret matches OpenSSL's `private_key_ecdh` output.
        Ok(sk.diffie_hellman(&pk).to_bytes().to_vec())
    }

    fn to_public(&self, secret_key: &HpkeSecretKey) -> Result<HpkePublicKey, RcDhError> {
        let mut sk_bytes = array32(secret_key.as_ref())?;
        let sk = StaticSecret::from(sk_bytes);
        sk_bytes.zeroize();
        Ok(HpkePublicKey::from(PublicKey::from(&sk).to_bytes().to_vec()))
    }

    fn generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), RcDhError> {
        let sk = StaticSecret::random_from_rng(rand_core::OsRng);
        let pk = PublicKey::from(&sk);
        // `to_bytes` hands back a fresh [u8; 32] copy of the secret; wipe it
        // after it has been moved into the secret-key Vec.
        let mut sk_bytes = sk.to_bytes();
        let sk_vec = sk_bytes.to_vec();
        sk_bytes.zeroize();
        Ok((
            HpkeSecretKey::from(sk_vec),
            HpkePublicKey::from(pk.to_bytes().to_vec()),
        ))
    }

    fn bitmask_for_rejection_sampling(&self) -> SamplingMethod {
        // Curve25519 needs no rejection sampling (matches OpenSSL's
        // `Curve::X25519` arm).
        SamplingMethod::HpkeWithoutBitmask
    }

    fn secret_key_size(&self) -> usize {
        X25519_KEY_LEN
    }

    fn public_key_size(&self) -> usize {
        X25519_KEY_LEN
    }

    fn public_key_validate(&self, key: &HpkePublicKey) -> Result<(), RcDhError> {
        // OpenSSL accepts any 32-byte string as an X25519 point; do the same so
        // we never reject a key the OpenSSL provider would have accepted.
        (key.as_ref().len() == X25519_KEY_LEN)
            .then_some(())
            .ok_or(RcDhError::InvalidKeyLen(key.as_ref().len()))
    }
}
