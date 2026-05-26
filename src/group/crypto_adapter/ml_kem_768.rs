//! ML-KEM-768 wrapper that implements `mls_rs_crypto_traits::KemType`.
//!
//! This is the **foundation piece** for P1.5.b. By itself it does not
//! change any visible behaviour — its purpose is to expose ML-KEM-768
//! (FIPS-204 ... oops, FIPS-203 — Module-Lattice-Based KEM) through
//! the `KemType` trait so that the next step can plug it into
//! `mls_rs_crypto_hpke::kem_combiner::CombinedKem` together with
//! X25519 DhKem to produce the hybrid KEM the plan calls for.
//!
//! All real cryptography is delegated to the `fips203` crate (pure
//! Rust FIPS-203 implementation already in the workspace deps).
//!
//! ## Trait notes
//!
//! `KemType` declares its async methods through `maybe_async`. In the
//! project's default (non-`mls_build_async`) build the methods are
//! actually synchronous; this impl therefore uses plain `fn` and no
//! `.await`, mirroring the convention of `mls-rs-crypto-openssl` /
//! `mls-rs-crypto-rustcrypto`.
//!
//! ## Sizes
//!
//! | Field | Bytes |
//! |---|---|
//! | Encapsulation (public) key  | 1184 (`fips203::ml_kem_768::EK_LEN`) |
//! | Decapsulation (secret) key  | 2400 (`fips203::ml_kem_768::DK_LEN`) |
//! | Ciphertext                  | 1088 (`fips203::ml_kem_768::CT_LEN`) |
//! | Shared secret               | 32   (`fips203::SSK_LEN`)            |
//! | Seed for deterministic keygen | 64 (32 B `d` + 32 B `z`)           |

use fips203::ml_kem_768;
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
use mls_rs_core::crypto::{HpkePublicKey, HpkeSecretKey};
use mls_rs_core::error::IntoAnyError;
use mls_rs_crypto_hpke::kem_combiner::FixedLengthKemType;
use mls_rs_crypto_traits::{KemResult, KemType};

/// Provisional KEM identifier for ML-KEM-768. The IETF has not yet
/// assigned a final ID; this matches the value currently used in
/// draft-ietf-hpke-pq experiments. It is only meaningful internally
/// — `CombinedKem` re-computes its own combined KEM id.
const ML_KEM_768_KEM_ID: u16 = 0x0042;

/// Seed length expected by `generate_deterministic`. `fips203` takes
/// two 32-byte halves (`d`, `z`); together they form a 64-byte seed.
const ML_KEM_768_SEED_LEN: usize = 64;

/// `KemType` implementation for ML-KEM-768 (FIPS-203). Stateless and
/// trivially clonable.
#[derive(Clone, Debug, Default)]
pub struct MlKem768Kem;

impl MlKem768Kem {
    pub const fn new() -> Self {
        Self
    }
}

impl KemType for MlKem768Kem {
    type Error = MlKem768Error;

    fn kem_id(&self) -> u16 {
        ML_KEM_768_KEM_ID
    }

    fn generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        let (ek, dk) = ml_kem_768::KG::try_keygen()
            .map_err(|e| MlKem768Error::Backend(format!("keygen: {e}")))?;
        Ok((
            HpkeSecretKey::from(dk.into_bytes().to_vec()),
            HpkePublicKey::from(ek.into_bytes().to_vec()),
        ))
    }

    fn generate_deterministic(
        &self,
        seed: &[u8],
    ) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        if seed.len() != ML_KEM_768_SEED_LEN {
            return Err(MlKem768Error::BadSeedLength {
                expected: ML_KEM_768_SEED_LEN,
                got: seed.len(),
            });
        }
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];
        d.copy_from_slice(&seed[..32]);
        z.copy_from_slice(&seed[32..]);
        let (ek, dk) = ml_kem_768::KG::keygen_from_seed(d, z);
        Ok((
            HpkeSecretKey::from(dk.into_bytes().to_vec()),
            HpkePublicKey::from(ek.into_bytes().to_vec()),
        ))
    }

    fn public_key_validate(&self, key: &HpkePublicKey) -> Result<(), Self::Error> {
        let bytes: [u8; ml_kem_768::EK_LEN] = key
            .as_ref()
            .try_into()
            .map_err(|_| MlKem768Error::BadKeyLength {
                what: "encapsulation key",
                expected: ml_kem_768::EK_LEN,
                got: key.as_ref().len(),
            })?;
        // `try_from_bytes` performs the structural validation FIPS-203
        // §7.2 requires; we discard the parsed value because the caller
        // wanted only validation.
        let _ek = ml_kem_768::EncapsKey::try_from_bytes(bytes)
            .map_err(|e| MlKem768Error::Backend(format!("parse ek: {e}")))?;
        Ok(())
    }

    fn encap(&self, remote_key: &HpkePublicKey) -> Result<KemResult, Self::Error> {
        let bytes: [u8; ml_kem_768::EK_LEN] = remote_key.as_ref().try_into().map_err(|_| {
            MlKem768Error::BadKeyLength {
                what: "encapsulation key",
                expected: ml_kem_768::EK_LEN,
                got: remote_key.as_ref().len(),
            }
        })?;
        let ek = ml_kem_768::EncapsKey::try_from_bytes(bytes)
            .map_err(|e| MlKem768Error::Backend(format!("parse ek: {e}")))?;
        let (ssk, ct) = ek
            .try_encaps()
            .map_err(|e| MlKem768Error::Backend(format!("encaps: {e}")))?;
        Ok(KemResult {
            shared_secret: ssk.into_bytes().to_vec(),
            enc: ct.into_bytes().to_vec(),
        })
    }

    fn decap(
        &self,
        enc: &[u8],
        secret_key: &HpkeSecretKey,
        _local_public: &HpkePublicKey,
    ) -> Result<Vec<u8>, Self::Error> {
        let dk_bytes: [u8; ml_kem_768::DK_LEN] =
            secret_key
                .as_ref()
                .try_into()
                .map_err(|_| MlKem768Error::BadKeyLength {
                    what: "decapsulation key",
                    expected: ml_kem_768::DK_LEN,
                    got: secret_key.as_ref().len(),
                })?;
        let dk = ml_kem_768::DecapsKey::try_from_bytes(dk_bytes)
            .map_err(|e| MlKem768Error::Backend(format!("parse dk: {e}")))?;
        let ct_bytes: [u8; ml_kem_768::CT_LEN] =
            enc.try_into().map_err(|_| MlKem768Error::BadKeyLength {
                what: "ciphertext",
                expected: ml_kem_768::CT_LEN,
                got: enc.len(),
            })?;
        let ct = ml_kem_768::CipherText::try_from_bytes(ct_bytes)
            .map_err(|e| MlKem768Error::Backend(format!("parse ct: {e}")))?;
        let ssk = dk
            .try_decaps(&ct)
            .map_err(|e| MlKem768Error::Backend(format!("decaps: {e}")))?;
        Ok(ssk.into_bytes().to_vec())
    }

    fn seed_length_for_derive(&self) -> usize {
        ML_KEM_768_SEED_LEN
    }
}

/// `FixedLengthKemType` is required by `CombinedKem` so it can split
/// concatenated keys / ciphertexts back into their per-KEM halves at
/// `decap` time. ML-KEM-768 has fixed-length encodings (FIPS-203 §7),
/// so the sizes are constants.
impl FixedLengthKemType for MlKem768Kem {
    fn public_key_size(&self) -> usize {
        ml_kem_768::EK_LEN
    }

    fn secret_key_size(&self) -> usize {
        ml_kem_768::DK_LEN
    }

    fn enc_size(&self) -> usize {
        // Unlike `DhKem` (whose ciphertext is the ephemeral public key,
        // i.e. `public_key_size()`), ML-KEM-768 ciphertexts are 1088 B
        // — distinct from the 1184 B public key. We must override the
        // default which equals `public_key_size()`.
        ml_kem_768::CT_LEN
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MlKem768Error {
    #[error("seed length: expected {expected}, got {got}")]
    BadSeedLength { expected: usize, got: usize },
    #[error("{what} length: expected {expected}, got {got}")]
    BadKeyLength {
        what: &'static str,
        expected: usize,
        got: usize,
    },
    #[error("fips203 backend: {0}")]
    Backend(String),
}

impl IntoAnyError for MlKem768Error {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(Box::new(self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vanilla roundtrip: keygen → encap → decap and verify shared
    /// secrets agree. This is the load-bearing property we need from
    /// any KEM that goes into MLS.
    #[test]
    fn encap_decap_roundtrip() {
        let kem = MlKem768Kem;
        let (sk, pk) = kem.generate().expect("generate");
        kem.public_key_validate(&pk).expect("pk validates");

        let kr = kem.encap(&pk).expect("encap");
        assert_eq!(kr.shared_secret.len(), 32, "ML-KEM-768 shared secret is 32 B");
        assert_eq!(kr.enc.len(), ml_kem_768::CT_LEN);

        let ss = kem.decap(&kr.enc, &sk, &pk).expect("decap");
        assert_eq!(ss, kr.shared_secret, "encap/decap shared secrets must agree");
    }

    /// Deterministic keygen: same seed must produce identical keys
    /// across calls. Required for `KemType::generate_deterministic`
    /// to be a useful primitive (e.g. for MLS proposal commit replay).
    #[test]
    fn deterministic_keygen_is_stable() {
        let kem = MlKem768Kem;
        let seed = [7u8; 64];
        let (sk1, pk1) = kem.generate_deterministic(&seed).expect("deterministic 1");
        let (sk2, pk2) = kem.generate_deterministic(&seed).expect("deterministic 2");
        assert_eq!(sk1.as_ref(), sk2.as_ref(), "deterministic SK must be stable");
        assert_eq!(pk1.as_ref(), pk2.as_ref(), "deterministic PK must be stable");
    }

    #[test]
    fn deterministic_keygen_rejects_wrong_seed_length() {
        let kem = MlKem768Kem;
        let res = kem.generate_deterministic(&[0u8; 63]);
        assert!(matches!(res, Err(MlKem768Error::BadSeedLength { .. })));
    }

    #[test]
    fn public_key_validate_rejects_malformed_input() {
        let kem = MlKem768Kem;
        let bogus = HpkePublicKey::from(vec![0u8; 10]); // wrong length
        assert!(kem.public_key_validate(&bogus).is_err());
    }

    #[test]
    fn key_id_and_sizes_match_spec() {
        let kem = MlKem768Kem;
        assert_eq!(kem.kem_id(), ML_KEM_768_KEM_ID);
        assert_eq!(kem.seed_length_for_derive(), 64);
        // Sanity-check FIPS-203 sizes against our public-facing
        // expectations (these are also relied on by the hybrid
        // KEM layout calculations).
        assert_eq!(ml_kem_768::EK_LEN, 1184);
        assert_eq!(ml_kem_768::DK_LEN, 2400);
        assert_eq!(ml_kem_768::CT_LEN, 1088);
    }

    /// `FixedLengthKemType` sizes must match the FIPS-203 constants;
    /// `CombinedKem::decap` uses these to split concatenated buffers
    /// — getting any of them wrong silently produces wrong keys.
    #[test]
    fn fixed_length_sizes() {
        let kem = MlKem768Kem;
        assert_eq!(kem.public_key_size(), 1184);
        assert_eq!(kem.secret_key_size(), 2400);
        assert_eq!(kem.enc_size(), 1088);
        // The default-impl of `enc_size` equals `public_key_size`; for
        // ML-KEM the ciphertext is *smaller* than the public key, so
        // ensure we have overridden it.
        assert_ne!(kem.enc_size(), kem.public_key_size());
    }
}
