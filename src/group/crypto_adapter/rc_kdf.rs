// Pure-Rust HKDF for the OpenSSL-free MLS cipher suite.
//
// Mirrors `mls_rs_crypto_openssl::kdf::Kdf`. HKDF labeling lives in the
// provider-agnostic `mls-rs-crypto-hpke` crate, so interop only requires this
// to be a standards-correct HKDF (RFC 5869). The two OpenSSL guards are
// replicated: `extract` rejects empty ikm; `expand` rejects a prk shorter than
// the hash output. Empty salt is handled identically to OpenSSL (HMAC with an
// empty/zero key), so `Some(salt)` is passed unconditionally.

use hkdf::Hkdf;
use mls_rs_core::crypto::CipherSuite;
use mls_rs_core::error::IntoAnyError;
use mls_rs_crypto_traits::{KdfId, KdfType};
use sha2::{Sha256, Sha512};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RcKdfError {
    #[error("the provided length of the key {0} is shorter than the minimum length {1}")]
    TooShortKey(usize, usize),
    #[error("requested expand length {0} is invalid")]
    InvalidLength(usize),
    #[error("unsupported cipher suite")]
    UnsupportedCipherSuite,
}

impl IntoAnyError for RcKdfError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(self.into())
    }
}

#[derive(Clone, Debug)]
pub struct RcKdf {
    kdf_id: KdfId,
}

impl RcKdf {
    pub fn new(cipher_suite: CipherSuite) -> Option<Self> {
        let kdf_id = KdfId::new(cipher_suite)?;
        match kdf_id {
            KdfId::HkdfSha256 | KdfId::HkdfSha512 => Some(Self { kdf_id }),
            _ => None,
        }
    }
}

impl KdfType for RcKdf {
    type Error = RcKdfError;

    fn kdf_id(&self) -> u16 {
        self.kdf_id as u16
    }

    fn extract(&self, salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>, RcKdfError> {
        // Match OpenSSL: empty ikm is rejected.
        if ikm.is_empty() {
            return Err(RcKdfError::TooShortKey(0, 1));
        }
        // `Some(salt)` (salt possibly empty) reproduces RFC 5869 / OpenSSL: an
        // empty salt becomes an all-zero HMAC key, same PRK as `None`.
        let prk = match self.kdf_id {
            KdfId::HkdfSha256 => Hkdf::<Sha256>::extract(Some(salt), ikm).0.to_vec(),
            KdfId::HkdfSha512 => Hkdf::<Sha512>::extract(Some(salt), ikm).0.to_vec(),
            _ => return Err(RcKdfError::UnsupportedCipherSuite),
        };
        Ok(prk)
    }

    fn expand(&self, prk: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, RcKdfError> {
        // Match OpenSSL: prk shorter than the hash output is rejected.
        if prk.len() < self.extract_size() {
            return Err(RcKdfError::TooShortKey(prk.len(), self.extract_size()));
        }
        let mut out = vec![0u8; len];
        let res = match self.kdf_id {
            KdfId::HkdfSha256 => Hkdf::<Sha256>::from_prk(prk)
                .map_err(|_| RcKdfError::TooShortKey(prk.len(), self.extract_size()))?
                .expand(info, &mut out),
            KdfId::HkdfSha512 => Hkdf::<Sha512>::from_prk(prk)
                .map_err(|_| RcKdfError::TooShortKey(prk.len(), self.extract_size()))?
                .expand(info, &mut out),
            _ => return Err(RcKdfError::UnsupportedCipherSuite),
        };
        res.map_err(|_| RcKdfError::InvalidLength(len))?;
        Ok(out)
    }

    fn extract_size(&self) -> usize {
        self.kdf_id.extract_size()
    }
}
