// Pure-Rust AEAD for the OpenSSL-free MLS cipher suite.
//
// Mirrors `mls_rs_crypto_openssl::aead::Aead` byte-for-byte so HPKE/at-rest
// ciphertexts stay interoperable: output is `ciphertext || tag(16)`, 12-byte
// nonce, AAD defaults to empty, and empty plaintext is rejected (matching the
// OpenSSL provider's `EmptyPlaintext`). Built on the RustCrypto `aes-gcm` crate.

use aes_gcm::aead::{Aead as _, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit, Nonce};
use mls_rs_core::crypto::CipherSuite;
use mls_rs_core::error::IntoAnyError;
use mls_rs_crypto_traits::{AeadId, AeadType, AES_TAG_LEN};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RcAeadError {
    #[error("AEAD ciphertext of length {0} is too short to fit the tag")]
    InvalidCipherLen(usize),
    #[error("encrypted message cannot be empty")]
    EmptyPlaintext,
    #[error("invalid key length {0}")]
    InvalidKeyLen(usize),
    #[error("invalid nonce length {0} (expected 12)")]
    InvalidNonceLen(usize),
    #[error("AEAD operation failed")]
    CryptoError,
    #[error("unsupported cipher suite")]
    UnsupportedCipherSuite,
}

impl IntoAnyError for RcAeadError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(self.into())
    }
}

#[derive(Clone, Debug)]
pub struct RcAead {
    aead_id: AeadId,
}

impl RcAead {
    pub fn new(cipher_suite: CipherSuite) -> Option<Self> {
        let aead_id = AeadId::new(cipher_suite)?;
        // We only support the AES-GCM suites the hybrid stack uses.
        match aead_id {
            AeadId::Aes128Gcm | AeadId::Aes256Gcm => Some(Self { aead_id }),
            _ => None,
        }
    }

    fn check_nonce(nonce: &[u8]) -> Result<&Nonce<aes_gcm::aes::cipher::consts::U12>, RcAeadError> {
        (nonce.len() == 12)
            .then(|| Nonce::from_slice(nonce))
            .ok_or(RcAeadError::InvalidNonceLen(nonce.len()))
    }
}

impl AeadType for RcAead {
    type Error = RcAeadError;

    fn aead_id(&self) -> u16 {
        self.aead_id as u16
    }

    fn seal(
        &self,
        key: &[u8],
        data: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, RcAeadError> {
        // Match OpenSSL: refuse to seal empty plaintext.
        (!data.is_empty())
            .then_some(())
            .ok_or(RcAeadError::EmptyPlaintext)?;
        let nonce = Self::check_nonce(nonce)?;
        let payload = Payload {
            msg: data,
            aad: aad.unwrap_or_default(),
        };
        // `aes-gcm`'s `encrypt` already returns `ciphertext || tag(16)`, the
        // same wire layout as the OpenSSL provider's `[&ciphertext, &tag]`.
        match self.aead_id {
            AeadId::Aes128Gcm => Aes128Gcm::new_from_slice(key)
                .map_err(|_| RcAeadError::InvalidKeyLen(key.len()))?
                .encrypt(nonce, payload)
                .map_err(|_| RcAeadError::CryptoError),
            AeadId::Aes256Gcm => Aes256Gcm::new_from_slice(key)
                .map_err(|_| RcAeadError::InvalidKeyLen(key.len()))?
                .encrypt(nonce, payload)
                .map_err(|_| RcAeadError::CryptoError),
            _ => Err(RcAeadError::UnsupportedCipherSuite),
        }
    }

    fn open(
        &self,
        key: &[u8],
        ciphertext: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, RcAeadError> {
        (ciphertext.len() > AES_TAG_LEN)
            .then_some(())
            .ok_or(RcAeadError::InvalidCipherLen(ciphertext.len()))?;
        let nonce = Self::check_nonce(nonce)?;
        let payload = Payload {
            msg: ciphertext,
            aad: aad.unwrap_or_default(),
        };
        // `aes-gcm`'s `decrypt` expects `ciphertext || tag(16)` and verifies
        // the tag — identical to the OpenSSL split-then-verify path.
        match self.aead_id {
            AeadId::Aes128Gcm => Aes128Gcm::new_from_slice(key)
                .map_err(|_| RcAeadError::InvalidKeyLen(key.len()))?
                .decrypt(nonce, payload)
                .map_err(|_| RcAeadError::CryptoError),
            AeadId::Aes256Gcm => Aes256Gcm::new_from_slice(key)
                .map_err(|_| RcAeadError::InvalidKeyLen(key.len()))?
                .decrypt(nonce, payload)
                .map_err(|_| RcAeadError::CryptoError),
            _ => Err(RcAeadError::UnsupportedCipherSuite),
        }
    }

    fn key_size(&self) -> usize {
        self.aead_id.key_size()
    }

    fn nonce_size(&self) -> usize {
        self.aead_id.nonce_size()
    }
}
