// Pure-Rust hash + HMAC for the OpenSSL-free MLS cipher suite's
// `CipherSuiteProvider::{hash, mac}`. Mirrors `mls_rs_crypto_openssl::mac::Hash`
// (SHA-256 for the 25519/AES-128 param suite, SHA-512 for the AES-256 at-rest
// suite). Distinct from `hash_adapter::Sha256Hasher`, which implements the
// `mls_rs_crypto_traits::Hash` trait consumed by the X-Wing combiner.

use hmac::{Hmac, Mac};
use mls_rs_core::crypto::CipherSuite;
use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RcHashError {
    #[error("unsupported cipher suite")]
    UnsupportedCipherSuite,
}

#[derive(Clone, Copy, Debug)]
enum HashId {
    Sha256,
    Sha512,
}

#[derive(Clone, Debug)]
pub struct RcHash {
    id: HashId,
}

impl RcHash {
    pub fn new(cipher_suite: CipherSuite) -> Result<Self, RcHashError> {
        let id = match cipher_suite {
            CipherSuite::CURVE25519_AES128
            | CipherSuite::P256_AES128
            | CipherSuite::CURVE25519_CHACHA => HashId::Sha256,
            CipherSuite::CURVE448_CHACHA
            | CipherSuite::CURVE448_AES256
            | CipherSuite::P521_AES256 => HashId::Sha512,
            _ => return Err(RcHashError::UnsupportedCipherSuite),
        };
        Ok(Self { id })
    }

    pub fn hash(&self, data: &[u8]) -> Vec<u8> {
        match self.id {
            HashId::Sha256 => Sha256::digest(data).to_vec(),
            HashId::Sha512 => Sha512::digest(data).to_vec(),
        }
    }

    pub fn mac(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        // HMAC accepts any key length (RFC 2104 pads/hashes as needed), so
        // `new_from_slice` never fails here — identical to OpenSSL's `PKey::hmac`.
        match self.id {
            HashId::Sha256 => {
                let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key)
                    .expect("HMAC accepts any key length");
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }
            HashId::Sha512 => {
                let mut m = <Hmac<Sha512> as Mac>::new_from_slice(key)
                    .expect("HMAC accepts any key length");
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }
        }
    }
}
