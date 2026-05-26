//! Hybrid PQC crypto adapter for `mls-rs`.
//!
//! ## Phases
//! - **P1**: passthrough only — every method delegated to base.
//! - **P1.5.a**: signature methods overridden to use
//!   `Ed25519 || ML-DSA-65` concatenated keys/signatures.
//! - **P1.5.b (this revision)**: KEM/HPKE override via a
//!   `CombinedKem<X25519 DhKem, ML-KEM-768, SHA-256, SHAKE-256>` plugged
//!   into a freshly-built `OpensslCipherSuite`. The hybrid cipher suite
//!   is now a fully-self-standing cipher suite — not a thin wrapper
//!   around the classical one.
//!
//! ## Hybrid Cipher Suite
//!
//! A private-use identifier `0xF101` (RFC 9420 reserves the
//! `0xF000..=0xFFFF` range for private experiments) is used to
//! distinguish the hybrid suite. The provider supports *only* this
//! suite — `supported_cipher_suites()` returns `[0xF101]` and any other
//! `CipherSuite` value yields `None` from `cipher_suite_provider()`.
//!
//! ## Construction
//!
//! `cipher_suite_provider(0xF101)` builds:
//!
//! ```text
//! OpensslCipherSuite<
//!     CombinedKem<
//!         DhKem<Ecdh, Kdf>,         // X25519 (from base)
//!         MlKem768Kem,              // ML-KEM-768 (fips203)
//!         Sha256Hasher,             // SHA-256 (sha2)
//!         Shake256Vlh,              // SHAKE-256 (sha3)
//!         XWingSharedSecretHashInput, // X-Wing combiner SS mixing
//!     >,
//!     Kdf,                          // SHA-256 HKDF (from base)
//!     Aead,                         // AES-128-GCM (from base)
//! >
//! ```
//!
//! and wraps it in [`HybridCipherSuiteProvider`] which overrides the
//! four signature trait methods to perform `Ed25519 || ML-DSA-65`.
//!
//! ## Composite Layout Reference
//!
//! ### Signatures (P1.5.a)
//! | Field | Bytes |
//! |---|---|
//! | Hybrid SK | `Ed25519 SK (64)` ‖ `ML-DSA-65 SK (4032)` = 4096 |
//! | Hybrid PK | `Ed25519 PK (32)` ‖ `ML-DSA-65 PK (1952)` = 1984 |
//! | Hybrid signature | `Ed25519 sig (64)` ‖ `ML-DSA-65 sig (3309)` = 3373 |
//!
//! ### KEM (P1.5.b)
//! | Field | Bytes |
//! |---|---|
//! | Hybrid SK | `X25519 SK (32)` ‖ `ML-KEM-768 DK (2400)` = 2432 |
//! | Hybrid PK | `X25519 PK (32)` ‖ `ML-KEM-768 EK (1184)` = 1216 |
//! | Hybrid enc | `X25519 enc (32)` ‖ `ML-KEM-768 CT (1088)` = 1120 |
//! | Shared secret | SHA-256(X-Wing-mix(ss1, ss2, ct2, pk2)) = 32 |

// Note on async: mls-rs's `CipherSuiteProvider` trait is declared with
// `maybe_async::must_be_sync` for default (non-`mls_build_async`)
// builds, so every method is *synchronous* despite the `async fn`
// notation in the source. Our impl therefore uses plain `fn` methods
// and no `.await` (the same pattern the OpenSSL provider follows).

pub mod hash_adapter;
pub mod ml_kem_768;

use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer, Verifier};
use mls_rs::CipherSuite;
use mls_rs_core::crypto::{
    CipherSuiteProvider, CryptoProvider, HpkeCiphertext, HpkePublicKey, HpkeSecretKey,
    SignaturePublicKey, SignatureSecretKey,
};
use mls_rs_core::error::IntoAnyError;
use mls_rs_crypto_hpke::dhkem::DhKem;
use mls_rs_crypto_hpke::kem_combiner::xwing::{CombinedKem, XWingSharedSecretHashInput};
use mls_rs_crypto_openssl::aead::Aead;
use mls_rs_crypto_openssl::ecdh::Ecdh;
use mls_rs_crypto_openssl::kdf::Kdf;
use mls_rs_crypto_openssl::{OpensslCipherSuite, OpensslCryptoError};
use mls_rs_crypto_traits::KemId;

use self::hash_adapter::{Sha256Hasher, Shake256Vlh};
use self::ml_kem_768::MlKem768Kem;

// -----------------------------------------------------------------------------
// Cipher-suite identifiers.
// -----------------------------------------------------------------------------

/// Private-use cipher suite ID for our hybrid suite. Constructed via
/// `CipherSuite::from(HYBRID_SUITE_ID)` where needed (the underlying
/// type has no `const fn` constructor exposed publicly).
pub const HYBRID_SUITE_ID: u16 = 0xF101;

/// Base classical suite used as the *parameter source* for the hybrid
/// suite's KDF/AEAD/X25519 halves. We never expose this suite to MLS;
/// it is only consulted to fetch `Ecdh`, `Kdf`, `Aead`, `KemId` values
/// configured for X25519 / SHA-256 / AES-128-GCM.
const PARAM_SOURCE_SUITE: CipherSuite = CipherSuite::CURVE25519_AES128;

/// Returns the hybrid `CipherSuite` value as a runtime constant. Use
/// this wherever a `CipherSuite` value is needed (mls-rs APIs).
pub fn hybrid_cipher_suite() -> CipherSuite {
    CipherSuite::from(HYBRID_SUITE_ID)
}

// -----------------------------------------------------------------------------
// Signature layout constants (P1.5.a).
// -----------------------------------------------------------------------------

/// Ed25519 secret-key length as the base provider emits it. mls-rs's
/// OpenSSL provider returns the *expanded* 64-byte form
/// (`32-byte seed || 32-byte derived public component`), not the 32-byte
/// raw seed of RFC 8032. We accept the base's convention verbatim so
/// `sign` / `verify` can hand the bytes straight back to the base.
const ED25519_SK_LEN: usize = 64;
/// Ed25519 raw public key length.
const ED25519_PK_LEN: usize = 32;
/// Ed25519 signature length.
const ED25519_SIG_LEN: usize = 64;

const HYBRID_SK_LEN: usize = ED25519_SK_LEN + ml_dsa_65::SK_LEN;
const HYBRID_PK_LEN: usize = ED25519_PK_LEN + ml_dsa_65::PK_LEN;
const HYBRID_SIG_LEN: usize = ED25519_SIG_LEN + ml_dsa_65::SIG_LEN;

// -----------------------------------------------------------------------------
// Type aliases for the composed hybrid cipher suite.
// -----------------------------------------------------------------------------

/// The hybrid KEM: X25519 (from the base provider) combined with
/// ML-KEM-768 via the X-Wing shared-secret combiner.
pub type HybridKem = CombinedKem<
    DhKem<Ecdh, Kdf>,
    MlKem768Kem,
    Sha256Hasher,
    Shake256Vlh,
    XWingSharedSecretHashInput,
>;

/// The bare hybrid cipher suite (KEM/KDF/AEAD only — signatures still
/// come from the base Ed25519 path). [`HybridCipherSuiteProvider`]
/// wraps this to add the hybrid signature scheme on top.
pub type HybridSuite = OpensslCipherSuite<HybridKem, Kdf, Aead>;

// -----------------------------------------------------------------------------
// HybridCryptoProvider — exposes only the hybrid suite.
// -----------------------------------------------------------------------------

/// `CryptoProvider` that exposes a single cipher suite: the hybrid
/// `Ed25519+ML-DSA-65 / X25519+ML-KEM-768 / SHA-256 / AES-128-GCM` suite
/// at private-use ID `0xF101`.
///
/// Construction is parameterless — the provider builds the underlying
/// primitives itself by consulting the OpenSSL provider's parameter
/// constants for `CURVE25519_AES128`.
#[derive(Clone, Debug, Default)]
pub struct HybridCryptoProvider;

impl HybridCryptoProvider {
    pub fn new() -> Self {
        Self
    }

    /// Builds a fresh hybrid cipher suite provider. Factored out so
    /// tests can call it directly and so `cipher_suite_provider()` and
    /// `supported_cipher_suites()` agree on a single construction path.
    ///
    /// Returns `None` only if the underlying OpenSSL provider is unable
    /// to build a `CURVE25519_AES128` provider (the parameter source).
    /// In practice this is reachable only on builds where libssl was
    /// compiled without X25519, which is exceedingly rare.
    fn build_hybrid_suite() -> Option<HybridCipherSuiteProvider<HybridSuite>> {
        let kdf = Kdf::new(PARAM_SOURCE_SUITE)?;
        let ecdh = Ecdh::new(PARAM_SOURCE_SUITE)?;
        let kem_id = KemId::new(PARAM_SOURCE_SUITE)?;
        // X25519 DhKem with SHA-256 KDF — identical to what the base
        // provider builds for `CURVE25519_AES128`, just kept separately
        // so we can hand it to `CombinedKem`.
        let x25519 = DhKem::new(ecdh, kdf.clone(), kem_id as u16, kem_id.n_secret());
        // X-Wing combiner: the IETF draft's recommended shared-secret
        // mixing for X25519 + ML-KEM-768. See
        // draft-connolly-cfrg-xwing-kem-01.
        let hybrid_kem = CombinedKem::new_xwing(x25519, MlKem768Kem, Sha256Hasher, Shake256Vlh);
        let aead = Aead::new(PARAM_SOURCE_SUITE)?;

        // OpensslCipherSuite::new internally constructs `Hash::new` and
        // `EcSigner::new` against the passed cipher_suite — both reject
        // unknown IDs, so we cannot pass `0xF101` here. We pass the
        // parameter-source suite (`CURVE25519_AES128`) which configures
        // the inner Hash to SHA-256 and the inner EcSigner to Ed25519
        // — exactly what we want for the hybrid suite's non-PQC halves.
        // `HybridCipherSuiteProvider::cipher_suite()` overrides the
        // reported ID back to `0xF101` so mls-rs serialises the right
        // suite into KeyPackages / GroupContext.
        let inner = OpensslCipherSuite::new(PARAM_SOURCE_SUITE, hybrid_kem, kdf, aead)?;
        Some(HybridCipherSuiteProvider::new(inner))
    }
}

impl CryptoProvider for HybridCryptoProvider {
    type CipherSuiteProvider = HybridCipherSuiteProvider<HybridSuite>;

    fn supported_cipher_suites(&self) -> Vec<CipherSuite> {
        // We expose only the hybrid suite. Classical-only peers cannot
        // talk to us; that is by design — the whole point of P1.5 is
        // PQC-mandatory group chat.
        if Self::build_hybrid_suite().is_some() {
            vec![hybrid_cipher_suite()]
        } else {
            Vec::new()
        }
    }

    fn cipher_suite_provider(
        &self,
        cipher_suite: CipherSuite,
    ) -> Option<Self::CipherSuiteProvider> {
        if cipher_suite == hybrid_cipher_suite() {
            Self::build_hybrid_suite()
        } else {
            None
        }
    }
}

// -----------------------------------------------------------------------------
// HybridCipherSuiteProvider — wraps a bare cipher suite provider and
// overrides only the signature methods to perform Ed25519 ‖ ML-DSA-65.
// -----------------------------------------------------------------------------

/// Wraps a bare cipher suite provider `B` and overrides its signature
/// surface to use the hybrid `Ed25519 || ML-DSA-65` scheme. Every other
/// method (hash, KDF, AEAD, HPKE, KEM, MAC, random) is delegated to `B`
/// verbatim.
///
/// Generic in `B` so the same wrapper works for any base
/// `CipherSuiteProvider` — in practice we only instantiate it on
/// [`HybridSuite`] (i.e. `OpensslCipherSuite<HybridKem, Kdf, Aead>`),
/// but the generic shape makes unit-testing against the bare classical
/// `OpensslCipherSuite` straightforward.
#[derive(Clone)]
pub struct HybridCipherSuiteProvider<B> {
    inner: B,
}

impl<B> HybridCipherSuiteProvider<B>
where
    B: CipherSuiteProvider + Send + Sync,
    B::Error: Send + Sync,
{
    pub fn new(inner: B) -> Self {
        Self { inner }
    }

    /// Access the wrapped provider. Used by tests; not part of the
    /// public surface for ordinary callers.
    #[cfg(test)]
    pub fn inner(&self) -> &B {
        &self.inner
    }
}

impl<B> CipherSuiteProvider for HybridCipherSuiteProvider<B>
where
    B: CipherSuiteProvider + Send + Sync + Clone,
    B::Error: Send + Sync,
{
    type Error = HybridSuiteError<B::Error>;
    type HpkeContextS = B::HpkeContextS;
    type HpkeContextR = B::HpkeContextR;

    fn cipher_suite(&self) -> CipherSuite {
        // We *always* report the hybrid ID, regardless of what the
        // inner provider was constructed against. mls-rs serialises
        // this into KeyPackages and the GroupContext, so peers see
        // 0xF101 and know to wire up a hybrid provider on their end.
        hybrid_cipher_suite()
    }

    // ----- pass-through: hash / mac ---------------------------------

    fn hash(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.inner.hash(data).map_err(HybridSuiteError::Base)
    }

    fn mac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.inner.mac(key, data).map_err(HybridSuiteError::Base)
    }

    // ----- pass-through: AEAD --------------------------------------

    fn aead_seal(
        &self,
        key: &[u8],
        data: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        self.inner
            .aead_seal(key, data, aad, nonce)
            .map_err(HybridSuiteError::Base)
    }

    fn aead_open(
        &self,
        key: &[u8],
        ciphertext: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, Self::Error> {
        self.inner
            .aead_open(key, ciphertext, aad, nonce)
            .map_err(HybridSuiteError::Base)
    }

    fn aead_key_size(&self) -> usize {
        self.inner.aead_key_size()
    }

    fn aead_nonce_size(&self) -> usize {
        self.inner.aead_nonce_size()
    }

    // ----- pass-through: KDF ---------------------------------------

    fn kdf_extract(
        &self,
        salt: &[u8],
        ikm: &[u8],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, Self::Error> {
        self.inner
            .kdf_extract(salt, ikm)
            .map_err(HybridSuiteError::Base)
    }

    fn kdf_expand(
        &self,
        prk: &[u8],
        info: &[u8],
        len: usize,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, Self::Error> {
        self.inner
            .kdf_expand(prk, info, len)
            .map_err(HybridSuiteError::Base)
    }

    fn kdf_extract_size(&self) -> usize {
        self.inner.kdf_extract_size()
    }

    // ----- pass-through: HPKE single-shot --------------------------

    fn hpke_seal(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        pt: &[u8],
    ) -> Result<HpkeCiphertext, Self::Error> {
        self.inner
            .hpke_seal(remote_key, info, aad, pt)
            .map_err(HybridSuiteError::Base)
    }

    fn hpke_seal_psk(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        pt: &[u8],
        psk: mls_rs_core::crypto::HpkePsk<'_>,
    ) -> Result<HpkeCiphertext, Self::Error> {
        self.inner
            .hpke_seal_psk(remote_key, info, aad, pt, psk)
            .map_err(HybridSuiteError::Base)
    }

    fn hpke_open(
        &self,
        ciphertext: &HpkeCiphertext,
        local_secret: &HpkeSecretKey,
        local_public: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, Self::Error> {
        self.inner
            .hpke_open(ciphertext, local_secret, local_public, info, aad)
            .map_err(HybridSuiteError::Base)
    }

    fn hpke_open_psk(
        &self,
        ciphertext: &HpkeCiphertext,
        local_secret: &HpkeSecretKey,
        local_public: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        psk: mls_rs_core::crypto::HpkePsk<'_>,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, Self::Error> {
        self.inner
            .hpke_open_psk(ciphertext, local_secret, local_public, info, aad, psk)
            .map_err(HybridSuiteError::Base)
    }

    // ----- pass-through: HPKE streaming setup ----------------------

    fn hpke_setup_s(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
    ) -> Result<(Vec<u8>, Self::HpkeContextS), Self::Error> {
        self.inner
            .hpke_setup_s(remote_key, info)
            .map_err(HybridSuiteError::Base)
    }

    fn hpke_setup_r(
        &self,
        kem_output: &[u8],
        local_secret: &HpkeSecretKey,
        local_public: &HpkePublicKey,
        info: &[u8],
    ) -> Result<Self::HpkeContextR, Self::Error> {
        self.inner
            .hpke_setup_r(kem_output, local_secret, local_public, info)
            .map_err(HybridSuiteError::Base)
    }

    // ----- pass-through: KEM ---------------------------------------

    fn kem_derive(&self, ikm: &[u8]) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        self.inner.kem_derive(ikm).map_err(HybridSuiteError::Base)
    }

    fn kem_generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        self.inner.kem_generate().map_err(HybridSuiteError::Base)
    }

    fn kem_public_key_validate(&self, key: &HpkePublicKey) -> Result<(), Self::Error> {
        self.inner
            .kem_public_key_validate(key)
            .map_err(HybridSuiteError::Base)
    }

    // ----- pass-through: random ------------------------------------

    fn random_bytes(&self, out: &mut [u8]) -> Result<(), Self::Error> {
        self.inner.random_bytes(out).map_err(HybridSuiteError::Base)
    }

    // ----- override: signatures ------------------------------------

    fn signature_key_generate(
        &self,
    ) -> Result<(SignatureSecretKey, SignaturePublicKey), Self::Error> {
        // Ed25519 portion via the base provider (Ed25519 is the
        // PARAM_SOURCE_SUITE signature scheme there).
        let (ed_sk, ed_pk) = self
            .inner
            .signature_key_generate()
            .map_err(HybridSuiteError::Base)?;
        let ed_sk_bytes: &[u8] = ed_sk.as_bytes();
        let ed_pk_bytes: &[u8] = ed_pk.as_bytes();
        if ed_sk_bytes.len() != ED25519_SK_LEN || ed_pk_bytes.len() != ED25519_PK_LEN {
            return Err(HybridSuiteError::Layout(format!(
                "base Ed25519 key shape unexpected (sk={}, pk={})",
                ed_sk_bytes.len(),
                ed_pk_bytes.len()
            )));
        }

        // ML-DSA-65 portion via `fips204` (pure-Rust FIPS-204 impl).
        let (mldsa_pk, mldsa_sk) = ml_dsa_65::try_keygen()
            .map_err(|e| HybridSuiteError::Pqc(format!("ml-dsa-65 keygen: {e}")))?;
        let mldsa_sk_bytes = mldsa_sk.into_bytes();
        let mldsa_pk_bytes = mldsa_pk.into_bytes();

        let mut sk = Vec::with_capacity(HYBRID_SK_LEN);
        sk.extend_from_slice(ed_sk_bytes);
        sk.extend_from_slice(&mldsa_sk_bytes);

        let mut pk = Vec::with_capacity(HYBRID_PK_LEN);
        pk.extend_from_slice(ed_pk_bytes);
        pk.extend_from_slice(&mldsa_pk_bytes);

        Ok((SignatureSecretKey::new(sk), SignaturePublicKey::new(pk)))
    }

    fn signature_key_derive_public(
        &self,
        secret_key: &SignatureSecretKey,
    ) -> Result<SignaturePublicKey, Self::Error> {
        let bytes: &[u8] = secret_key.as_bytes();
        if bytes.len() != HYBRID_SK_LEN {
            return Err(HybridSuiteError::Layout(format!(
                "hybrid SK length {} (expected {})",
                bytes.len(),
                HYBRID_SK_LEN
            )));
        }
        let (ed_sk_bytes, mldsa_sk_bytes) = bytes.split_at(ED25519_SK_LEN);

        let ed_sk = SignatureSecretKey::new(ed_sk_bytes.to_vec());
        let ed_pk = self
            .inner
            .signature_key_derive_public(&ed_sk)
            .map_err(HybridSuiteError::Base)?;
        let ed_pk_bytes: &[u8] = ed_pk.as_bytes();
        if ed_pk_bytes.len() != ED25519_PK_LEN {
            return Err(HybridSuiteError::Layout(format!(
                "Ed25519 derive_public returned {} bytes (expected {})",
                ed_pk_bytes.len(),
                ED25519_PK_LEN
            )));
        }

        let mldsa_sk_arr: [u8; ml_dsa_65::SK_LEN] = mldsa_sk_bytes
            .try_into()
            .map_err(|_| HybridSuiteError::Layout("ml-dsa-65 SK slice".to_string()))?;
        let mldsa_sk = ml_dsa_65::PrivateKey::try_from_bytes(mldsa_sk_arr)
            .map_err(|e| HybridSuiteError::Pqc(format!("ml-dsa-65 SK parse: {e}")))?;
        let mldsa_pk_bytes = mldsa_sk.get_public_key().into_bytes();

        let mut pk = Vec::with_capacity(HYBRID_PK_LEN);
        pk.extend_from_slice(ed_pk_bytes);
        pk.extend_from_slice(&mldsa_pk_bytes);
        Ok(SignaturePublicKey::new(pk))
    }

    fn sign(
        &self,
        secret_key: &SignatureSecretKey,
        data: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        let bytes: &[u8] = secret_key.as_bytes();
        if bytes.len() != HYBRID_SK_LEN {
            return Err(HybridSuiteError::Layout(format!(
                "hybrid SK length {} (expected {})",
                bytes.len(),
                HYBRID_SK_LEN
            )));
        }
        let (ed_sk_bytes, mldsa_sk_bytes) = bytes.split_at(ED25519_SK_LEN);

        let ed_sk = SignatureSecretKey::new(ed_sk_bytes.to_vec());
        let ed_sig = self
            .inner
            .sign(&ed_sk, data)
            .map_err(HybridSuiteError::Base)?;
        if ed_sig.len() != ED25519_SIG_LEN {
            return Err(HybridSuiteError::Layout(format!(
                "Ed25519 signature length {} (expected {})",
                ed_sig.len(),
                ED25519_SIG_LEN
            )));
        }

        let mldsa_sk_arr: [u8; ml_dsa_65::SK_LEN] = mldsa_sk_bytes
            .try_into()
            .map_err(|_| HybridSuiteError::Layout("ml-dsa-65 SK slice".to_string()))?;
        let mldsa_sk = ml_dsa_65::PrivateKey::try_from_bytes(mldsa_sk_arr)
            .map_err(|e| HybridSuiteError::Pqc(format!("ml-dsa-65 SK parse: {e}")))?;
        // Empty context is the standard "no ctx" choice from FIPS-204
        // §5.2; binds nothing extra into the signature.
        let mldsa_sig = mldsa_sk
            .try_sign(data, &[])
            .map_err(|e| HybridSuiteError::Pqc(format!("ml-dsa-65 sign: {e}")))?;

        let mut out = Vec::with_capacity(HYBRID_SIG_LEN);
        out.extend_from_slice(&ed_sig);
        out.extend_from_slice(&mldsa_sig);
        Ok(out)
    }

    fn verify(
        &self,
        public_key: &SignaturePublicKey,
        signature: &[u8],
        data: &[u8],
    ) -> Result<(), Self::Error> {
        let pk_bytes: &[u8] = public_key.as_bytes();
        if pk_bytes.len() != HYBRID_PK_LEN {
            return Err(HybridSuiteError::Layout(format!(
                "hybrid PK length {} (expected {})",
                pk_bytes.len(),
                HYBRID_PK_LEN
            )));
        }
        if signature.len() != HYBRID_SIG_LEN {
            return Err(HybridSuiteError::Layout(format!(
                "hybrid signature length {} (expected {})",
                signature.len(),
                HYBRID_SIG_LEN
            )));
        }
        let (ed_pk_bytes, mldsa_pk_bytes) = pk_bytes.split_at(ED25519_PK_LEN);
        let (ed_sig, mldsa_sig_bytes) = signature.split_at(ED25519_SIG_LEN);

        let ed_pk = SignaturePublicKey::new(ed_pk_bytes.to_vec());
        // Ed25519 half — base verifies; any failure short-circuits.
        self.inner
            .verify(&ed_pk, ed_sig, data)
            .map_err(HybridSuiteError::Base)?;

        // ML-DSA-65 half — verifies independently. Both halves must
        // pass for the hybrid signature to be considered valid.
        let mldsa_pk_arr: [u8; ml_dsa_65::PK_LEN] = mldsa_pk_bytes
            .try_into()
            .map_err(|_| HybridSuiteError::Layout("ml-dsa-65 PK slice".to_string()))?;
        let mldsa_pk = ml_dsa_65::PublicKey::try_from_bytes(mldsa_pk_arr)
            .map_err(|e| HybridSuiteError::Pqc(format!("ml-dsa-65 PK parse: {e}")))?;
        let mldsa_sig_arr: [u8; ml_dsa_65::SIG_LEN] = mldsa_sig_bytes
            .try_into()
            .map_err(|_| HybridSuiteError::Layout("ml-dsa-65 sig slice".to_string()))?;
        if !mldsa_pk.verify(data, &mldsa_sig_arr, &[]) {
            return Err(HybridSuiteError::SignatureVerify);
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Error type. Carries either a base provider error or a hybrid-layer
// error (layout / PQC primitive failure).
// -----------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum HybridSuiteError<E> {
    #[error("base provider error: {0:?}")]
    Base(E),
    #[error("hybrid layout: {0}")]
    Layout(String),
    #[error("PQC primitive: {0}")]
    Pqc(String),
    #[error("hybrid signature verification failed")]
    SignatureVerify,
}

impl<E: IntoAnyError> IntoAnyError for HybridSuiteError<E> {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        match self {
            Self::Base(e) => e.into_dyn_error().map_err(HybridSuiteError::Base),
            // IntoAnyError only requires `Debug`, not `Display`, so build
            // the boxed error from the Debug representation. (`E` here
            // does not necessarily implement `Display`.)
            other => Ok(Box::new(SimpleStringError(format!("{other:?}")))),
        }
    }
}

#[derive(Debug)]
struct SimpleStringError(String);
impl std::fmt::Display for SimpleStringError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for SimpleStringError {}

// -----------------------------------------------------------------------------
// Convenience alias for callers that just want "the" hybrid error.
// -----------------------------------------------------------------------------

/// Canonical concrete error type emitted by the hybrid suite as wired
/// in production (i.e. on top of [`HybridSuite`]).
pub type HybridProductionError = HybridSuiteError<OpensslCryptoError>;

#[cfg(test)]
mod tests {
    use super::*;

    /// `HybridCryptoProvider` exposes exactly one cipher suite — the
    /// hybrid one. No other suites leak out.
    #[test]
    fn provider_advertises_only_hybrid_suite() {
        let p = HybridCryptoProvider::new();
        let suites = p.supported_cipher_suites();
        assert_eq!(suites, vec![hybrid_cipher_suite()]);
        assert!(p.cipher_suite_provider(hybrid_cipher_suite()).is_some());
        assert!(
            p.cipher_suite_provider(CipherSuite::CURVE25519_AES128)
                .is_none()
        );
    }

    /// End-to-end signature round-trip through the hybrid wrapper:
    /// keygen → sign → verify must succeed; mutating either half of
    /// the signature must make it fail.
    #[test]
    fn hybrid_signature_roundtrip_and_tamper_detection() {
        let p = HybridCryptoProvider::new();
        let suite = p.cipher_suite_provider(hybrid_cipher_suite()).expect("ok");

        let msg = b"the quick brown fox jumps over the lazy dog";
        let (sk, pk) = suite.signature_key_generate().expect("keygen");
        assert_eq!(sk.as_bytes().len(), HYBRID_SK_LEN);
        assert_eq!(pk.as_bytes().len(), HYBRID_PK_LEN);

        let sig = suite.sign(&sk, msg).expect("sign");
        assert_eq!(sig.len(), HYBRID_SIG_LEN);
        suite.verify(&pk, &sig, msg).expect("verify");

        // Flip a bit in the Ed25519 half (first 64 bytes).
        let mut tampered = sig.clone();
        tampered[0] ^= 0x01;
        assert!(suite.verify(&pk, &tampered, msg).is_err());

        // Flip a bit in the ML-DSA-65 half (after byte 64).
        let mut tampered = sig.clone();
        tampered[ED25519_SIG_LEN + 1] ^= 0x01;
        assert!(suite.verify(&pk, &tampered, msg).is_err());
    }

    /// Hybrid KEM round-trip: kem_generate → hpke_seal → hpke_open must
    /// recover the plaintext, and tampering with the ciphertext must
    /// make `hpke_open` fail. This is the load-bearing property MLS
    /// relies on for Welcome / path-secret encryption.
    #[test]
    fn hybrid_hpke_roundtrip_and_tamper_detection() {
        let p = HybridCryptoProvider::new();
        let suite = p.cipher_suite_provider(hybrid_cipher_suite()).expect("ok");

        let (sk, pk) = suite.kem_generate().expect("kem_generate");
        // The hybrid SK / PK should be the concatenated X25519 + ML-KEM-768
        // byte strings — sanity-check lengths against FIPS-203 + RFC 7748.
        assert_eq!(sk.as_ref().len(), 32 + 2400);
        assert_eq!(pk.as_ref().len(), 32 + 1184);

        let pt = b"hello hybrid HPKE";
        let info = b"unit-test";
        let aad: Option<&[u8]> = Some(b"aad-bytes");

        let ct = suite.hpke_seal(&pk, info, aad, pt).expect("hpke_seal");
        let recovered = suite
            .hpke_open(&ct, &sk, &pk, info, aad)
            .expect("hpke_open");
        assert_eq!(recovered.as_slice(), pt);

        // Tamper with the AEAD ciphertext body; opening must fail.
        let mut tampered_ct = ct.clone();
        if let Some(byte) = tampered_ct.ciphertext.first_mut() {
            *byte ^= 0x01;
        }
        assert!(
            suite
                .hpke_open(&tampered_ct, &sk, &pk, info, aad)
                .is_err(),
            "tampered ciphertext must fail to open"
        );
    }
}
