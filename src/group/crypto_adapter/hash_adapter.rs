//! Hash and variable-length hash adapters used by the hybrid KEM
//! combiner (`mls_rs_crypto_hpke::kem_combiner::xwing::CombinedKem`).
//!
//! `CombinedKem<KEM1, KEM2, H, VH, F>` requires its `H` to implement
//! [`mls_rs_crypto_traits::Hash`] and its `VH` to implement
//! [`mls_rs_crypto_traits::VariableLengthHash`]. The `mls-rs-crypto-openssl`
//! crate carries an internal `Hash` *struct* tied to its
//! `OpensslCipherSuite`, but it deliberately does not implement the
//! trait directly — its `CipherSuiteProvider` impl wraps the call instead.
//! So we provide our own trait-bearing adapters here.
//!
//! ## Choices
//! - **Fixed-length hash**: SHA-256 via the `sha2` crate. This is what
//!   the base classical suite (`CURVE25519_AES128`) uses internally for
//!   its KDF/HMAC, so it stays consistent.
//! - **Variable-length hash**: SHAKE-256 via the `sha3` crate. SHAKE-256
//!   is the natural XOF pairing for ML-KEM-based hybrids — it is what
//!   `draft-ietf-hpke-pq` and the X-Wing draft point at, and using it
//!   keeps the hash family of the PQC half (SHA-3 / Keccak) self-consistent
//!   even though the classical half uses SHA-256.
//!
//! The two adapters are stateless and trivially clonable.

use mls_rs_core::error::IntoAnyError;
use mls_rs_crypto_traits::{Hash, VariableLengthHash};
use sha2::Digest as _;
use sha3::digest::{ExtendableOutput, Update, XofReader};

/// SHA-256 fixed-length hash adapter.
///
/// Wraps the `sha2::Sha256` digest behind the `Hash` trait that
/// `CombinedKem` requires. Stateless.
#[derive(Clone, Debug, Default)]
pub struct Sha256Hasher;

impl Sha256Hasher {
    pub const fn new() -> Self {
        Self
    }
}

impl Hash for Sha256Hasher {
    type Error = HashAdapterError;

    fn hash(&self, input: &[u8]) -> Result<Vec<u8>, Self::Error> {
        // `Sha256::digest` returns a `GenericArray<u8, U32>`; we copy
        // into a `Vec` to match the trait surface. Allocation is the
        // shape the trait demands — not optimising it here.
        Ok(sha2::Sha256::digest(input).to_vec())
    }
}

/// SHAKE-256 variable-length hash adapter.
///
/// SHAKE-256 is a Keccak-derived XOF, so a single absorb / squeeze pair
/// can produce arbitrary `out_len` bytes. `CombinedKem` calls this when
/// deriving the per-KEM IKM out of a single composite seed during
/// `generate_deterministic`.
#[derive(Clone, Debug, Default)]
pub struct Shake256Vlh;

impl Shake256Vlh {
    pub const fn new() -> Self {
        Self
    }
}

impl VariableLengthHash for Shake256Vlh {
    type Error = HashAdapterError;

    fn hash(&self, input: &[u8], out_len: usize) -> Result<Vec<u8>, Self::Error> {
        let mut hasher = sha3::Shake256::default();
        hasher.update(input);
        let mut reader = hasher.finalize_xof();
        let mut out = vec![0u8; out_len];
        reader.read(&mut out);
        Ok(out)
    }
}

/// Unified error type for both adapters. Both adapters are pure
/// computations over byte slices and cannot actually fail on this
/// platform — the variant exists only to satisfy the trait surface.
#[derive(Debug, thiserror::Error)]
pub enum HashAdapterError {
    /// Placeholder; never constructed by current adapters but lets
    /// future replacements (e.g. an openssl-backed variant) return a
    /// real error without breaking the enum's API.
    #[error("hash adapter: {0}")]
    Other(String),
}

impl IntoAnyError for HashAdapterError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(Box::new(self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SHA-256 of the empty string is well-known; pin it to make sure
    /// the adapter is wired to the right digest. (NIST FIPS-180-4 §A.1)
    #[test]
    fn sha256_empty_known_answer() {
        let got = Sha256Hasher.hash(b"").expect("sha256");
        let want =
            hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .expect("hex");
        assert_eq!(got, want);
    }

    /// SHA-256 produces 32-byte digests regardless of input length.
    /// This is the property `CombinedKem` relies on when hashing the
    /// composite shared secret down to a single MLS HPKE shared secret.
    #[test]
    fn sha256_output_is_32_bytes() {
        let got = Sha256Hasher.hash(&[7u8; 100]).expect("sha256");
        assert_eq!(got.len(), 32);
    }

    /// SHAKE-256 must honour `out_len` exactly. `CombinedKem` calls it
    /// with `seed_length_for_derive()` (96B for our hybrid: X25519's 32 +
    /// ML-KEM-768's 64), so non-32-byte outputs must work.
    #[test]
    fn shake256_honours_requested_length() {
        for len in [16usize, 32, 64, 96, 128] {
            let got = Shake256Vlh.hash(b"sample input", len).expect("shake256");
            assert_eq!(got.len(), len, "out_len {len} not honoured");
        }
    }

    /// SHAKE-256 is deterministic: the same input must produce the same
    /// output across calls. Required for `generate_deterministic` to be
    /// a useful primitive.
    #[test]
    fn shake256_is_deterministic() {
        let a = Shake256Vlh.hash(b"abc", 64).expect("shake1");
        let b = Shake256Vlh.hash(b"abc", 64).expect("shake2");
        assert_eq!(a, b);
    }

    /// Same input, different lengths — the shorter output must be a
    /// prefix of the longer one (SHAKE is an XOF; one continuous stream).
    /// `CombinedKem` doesn't rely on this property, but the test catches
    /// accidental wiring to a non-XOF hash with truncation.
    #[test]
    fn shake256_length_extension_is_a_prefix() {
        let short = Shake256Vlh.hash(b"abc", 32).expect("short");
        let long = Shake256Vlh.hash(b"abc", 96).expect("long");
        assert_eq!(&long[..32], short.as_slice());
    }
}
