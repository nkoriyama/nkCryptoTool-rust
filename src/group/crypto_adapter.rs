//! Hybrid PQC crypto adapter for `mls-rs`.
//!
//! ## Phases
//! - **P1**: passthrough only — every method delegated to base.
//! - **P1.5.a (this revision)**: signature methods overridden to use
//!   `Ed25519 || ML-DSA-65` concatenated keys/signatures. KEM / HPKE
//!   still delegate to the base (`CURVE25519_AES128`), so HPKE
//!   operations remain classical for now.
//! - **P1.5.b (TODO)**: KEM/HPKE override with the X25519 + ML-KEM-768
//!   concatenated KEM and shared-secret combining per
//!   draft-ietf-hpke-pq.
//!
//! ## Hybrid Cipher Suite
//!
//! A private-use identifier `0xF101` (RFC 9420 reserves the
//! `0xF000..=0xFFFF` range for private experiments) is used to
//! distinguish the hybrid suite from any base IANA-assigned suite.
//! When the wrapped provider is asked for it, we wrap the base's
//! `CURVE25519_AES128` provider (so AEAD / KDF / hash / HPKE all
//! continue to work) and override only the signature surface.
//!
//! ## Composite Signature Layout
//!
//! | Field | Bytes |
//! |---|---|
//! | Hybrid SK | `Ed25519 SK (32)` ‖ `ML-DSA-65 SK (4032)` = 4064 |
//! | Hybrid PK | `Ed25519 PK (32)` ‖ `ML-DSA-65 PK (1952)` = 1984 |
//! | Hybrid signature | `Ed25519 sig (64)` ‖ `ML-DSA-65 sig (3309)` = 3373 |
//!
//! Verification requires *both* primitives to succeed. The structure
//! follows the draft-ietf-tls-hybrid-design pattern: independent
//! signatures, combined by concatenation.

// Note on async: mls-rs's `CipherSuiteProvider` trait is declared with
// `maybe_async::must_be_sync` for default (non-`mls_build_async`)
// builds, so every method is *synchronous* despite the `async fn`
// notation in the source. Our impl therefore uses plain `fn` methods
// and no `` (the same pattern the OpenSSL provider follows).

/// ML-KEM-768 `KemType` wrapper. Foundation for P1.5.b's hybrid KEM
/// (gets combined with X25519 DhKem in a future revision).
pub mod ml_kem_768;

use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer, Verifier};
use mls_rs::CipherSuite;
use mls_rs_core::crypto::{
    CipherSuiteProvider, CryptoProvider, HpkeCiphertext, HpkePublicKey, HpkeSecretKey,
    SignaturePublicKey, SignatureSecretKey,
};
use mls_rs_core::error::IntoAnyError;

// -----------------------------------------------------------------------------
// Cipher-suite identifiers and layout constants.
// -----------------------------------------------------------------------------

/// Private-use cipher suite ID for our hybrid suite. Constructed via
/// `CipherSuite::from(HYBRID_SUITE_ID)` where needed (the underlying
/// type has no `const fn` constructor exposed publicly).
pub const HYBRID_SUITE_ID: u16 = 0xF101;

/// Base classical suite whose provider we wrap. Provides Ed25519
/// signatures, X25519 KEM, AES-128-GCM AEAD, SHA-256 KDF/Hash.
const BASE_SUITE_FOR_HYBRID: CipherSuite = CipherSuite::CURVE25519_AES128;

/// Returns the hybrid `CipherSuite` value as a runtime constant. Use
/// this wherever a `CipherSuite` value is needed (mls-rs APIs).
pub fn hybrid_cipher_suite() -> CipherSuite {
    CipherSuite::from(HYBRID_SUITE_ID)
}

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

const HYBRID_SK_LEN: usize = ED25519_SK_LEN + ml_dsa_65::SK_LEN; // 4064
const HYBRID_PK_LEN: usize = ED25519_PK_LEN + ml_dsa_65::PK_LEN; // 1984
const HYBRID_SIG_LEN: usize = ED25519_SIG_LEN + ml_dsa_65::SIG_LEN; // 3373

// -----------------------------------------------------------------------------
// HybridCryptoProvider — top-level provider that exposes the hybrid suite
// in addition to whatever the base provider supports.
// -----------------------------------------------------------------------------

#[derive(Clone, Debug, Default)]
pub struct HybridCryptoProvider<B> {
    base: B,
}

impl<B> HybridCryptoProvider<B> {
    pub fn new(base: B) -> Self {
        Self { base }
    }

    pub fn inner(&self) -> &B {
        &self.base
    }
}

impl<B> CryptoProvider for HybridCryptoProvider<B>
where
    B: CryptoProvider + Send + Sync,
    <B::CipherSuiteProvider as CipherSuiteProvider>::Error: Send + Sync,
{
    type CipherSuiteProvider = HybridOrBase<B::CipherSuiteProvider>;

    fn supported_cipher_suites(&self) -> Vec<CipherSuite> {
        let mut suites = self.base.supported_cipher_suites();
        if self.base.cipher_suite_provider(BASE_SUITE_FOR_HYBRID).is_some() {
            suites.push(hybrid_cipher_suite());
        }
        suites
    }

    fn cipher_suite_provider(
        &self,
        cipher_suite: CipherSuite,
    ) -> Option<Self::CipherSuiteProvider> {
        if cipher_suite == hybrid_cipher_suite() {
            // For the hybrid suite, wrap the base's CURVE25519_AES128
            // provider (for AEAD/KDF/HPKE) and override signatures.
            self.base
                .cipher_suite_provider(BASE_SUITE_FOR_HYBRID)
                .map(|inner| HybridOrBase::Hybrid(HybridCipherSuiteProvider::new(inner)))
        } else {
            self.base
                .cipher_suite_provider(cipher_suite)
                .map(HybridOrBase::Base)
        }
    }
}

// -----------------------------------------------------------------------------
// HybridOrBase — enum-dispatch wrapper that exposes a single
// `CipherSuiteProvider` impl while internally delegating to either the
// hybrid wrapper or the base provider as appropriate.
// -----------------------------------------------------------------------------

/// Dispatch enum so `HybridCryptoProvider::CipherSuiteProvider` is a
/// single concrete type that can take either form. Variants are
/// constructed only inside this module; outside callers see only the
/// `CipherSuiteProvider` trait.
#[derive(Clone)]
pub enum HybridOrBase<P> {
    Hybrid(HybridCipherSuiteProvider<P>),
    Base(P),
}


impl<P> CipherSuiteProvider for HybridOrBase<P>
where
    P: CipherSuiteProvider + Send + Sync + Clone,
    P::Error: Send + Sync,
{
    type Error = HybridSuiteError<P::Error>;
    type HpkeContextS = P::HpkeContextS;
    type HpkeContextR = P::HpkeContextR;

    fn cipher_suite(&self) -> CipherSuite {
        match self {
            Self::Hybrid(h) => h.cipher_suite(),
            Self::Base(b) => b.cipher_suite(),
        }
    }

    fn hash(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        match self {
            Self::Hybrid(h) => h.inner.hash(data).map_err(HybridSuiteError::Base),
            Self::Base(b) => b.hash(data).map_err(HybridSuiteError::Base),
        }
    }

    fn mac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        match self {
            Self::Hybrid(h) => h.inner.mac(key, data).map_err(HybridSuiteError::Base),
            Self::Base(b) => b.mac(key, data).map_err(HybridSuiteError::Base),
        }
    }

    fn aead_seal(
        &self,
        key: &[u8],
        data: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        match self {
            Self::Hybrid(h) => h
                .inner
                .aead_seal(key, data, aad, nonce)
                
                .map_err(HybridSuiteError::Base),
            Self::Base(b) => b
                .aead_seal(key, data, aad, nonce)
                
                .map_err(HybridSuiteError::Base),
        }
    }

    fn aead_open(
        &self,
        key: &[u8],
        ciphertext: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, Self::Error> {
        match self {
            Self::Hybrid(h) => h
                .inner
                .aead_open(key, ciphertext, aad, nonce)
                
                .map_err(HybridSuiteError::Base),
            Self::Base(b) => b
                .aead_open(key, ciphertext, aad, nonce)
                
                .map_err(HybridSuiteError::Base),
        }
    }

    fn aead_key_size(&self) -> usize {
        match self {
            Self::Hybrid(h) => h.inner.aead_key_size(),
            Self::Base(b) => b.aead_key_size(),
        }
    }

    fn aead_nonce_size(&self) -> usize {
        match self {
            Self::Hybrid(h) => h.inner.aead_nonce_size(),
            Self::Base(b) => b.aead_nonce_size(),
        }
    }

    fn kdf_extract(
        &self,
        salt: &[u8],
        ikm: &[u8],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, Self::Error> {
        match self {
            Self::Hybrid(h) => h
                .inner
                .kdf_extract(salt, ikm)
                
                .map_err(HybridSuiteError::Base),
            Self::Base(b) => b
                .kdf_extract(salt, ikm)
                
                .map_err(HybridSuiteError::Base),
        }
    }

    fn kdf_expand(
        &self,
        prk: &[u8],
        info: &[u8],
        len: usize,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, Self::Error> {
        match self {
            Self::Hybrid(h) => h
                .inner
                .kdf_expand(prk, info, len)
                
                .map_err(HybridSuiteError::Base),
            Self::Base(b) => b
                .kdf_expand(prk, info, len)
                
                .map_err(HybridSuiteError::Base),
        }
    }

    fn kdf_extract_size(&self) -> usize {
        match self {
            Self::Hybrid(h) => h.inner.kdf_extract_size(),
            Self::Base(b) => b.kdf_extract_size(),
        }
    }

    fn hpke_seal(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        pt: &[u8],
    ) -> Result<HpkeCiphertext, Self::Error> {
        match self {
            Self::Hybrid(h) => h
                .inner
                .hpke_seal(remote_key, info, aad, pt)
                
                .map_err(HybridSuiteError::Base),
            Self::Base(b) => b
                .hpke_seal(remote_key, info, aad, pt)
                
                .map_err(HybridSuiteError::Base),
        }
    }

    fn hpke_seal_psk(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        pt: &[u8],
        psk: mls_rs_core::crypto::HpkePsk<'_>,
    ) -> Result<HpkeCiphertext, Self::Error> {
        match self {
            Self::Hybrid(h) => h
                .inner
                .hpke_seal_psk(remote_key, info, aad, pt, psk)
                
                .map_err(HybridSuiteError::Base),
            Self::Base(b) => b
                .hpke_seal_psk(remote_key, info, aad, pt, psk)
                
                .map_err(HybridSuiteError::Base),
        }
    }

    fn hpke_open(
        &self,
        ciphertext: &HpkeCiphertext,
        local_secret: &HpkeSecretKey,
        local_public: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, Self::Error> {
        match self {
            Self::Hybrid(h) => h
                .inner
                .hpke_open(ciphertext, local_secret, local_public, info, aad)
                
                .map_err(HybridSuiteError::Base),
            Self::Base(b) => b
                .hpke_open(ciphertext, local_secret, local_public, info, aad)
                
                .map_err(HybridSuiteError::Base),
        }
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
        match self {
            Self::Hybrid(h) => h
                .inner
                .hpke_open_psk(ciphertext, local_secret, local_public, info, aad, psk)
                
                .map_err(HybridSuiteError::Base),
            Self::Base(b) => b
                .hpke_open_psk(ciphertext, local_secret, local_public, info, aad, psk)
                
                .map_err(HybridSuiteError::Base),
        }
    }

    fn hpke_setup_s(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
    ) -> Result<(Vec<u8>, Self::HpkeContextS), Self::Error> {
        match self {
            Self::Hybrid(h) => h
                .inner
                .hpke_setup_s(remote_key, info)
                
                .map_err(HybridSuiteError::Base),
            Self::Base(b) => b
                .hpke_setup_s(remote_key, info)
                
                .map_err(HybridSuiteError::Base),
        }
    }

    fn hpke_setup_r(
        &self,
        kem_output: &[u8],
        local_secret: &HpkeSecretKey,
        local_public: &HpkePublicKey,
        info: &[u8],
    ) -> Result<Self::HpkeContextR, Self::Error> {
        match self {
            Self::Hybrid(h) => h
                .inner
                .hpke_setup_r(kem_output, local_secret, local_public, info)
                
                .map_err(HybridSuiteError::Base),
            Self::Base(b) => b
                .hpke_setup_r(kem_output, local_secret, local_public, info)
                
                .map_err(HybridSuiteError::Base),
        }
    }

    fn kem_derive(
        &self,
        ikm: &[u8],
    ) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        match self {
            Self::Hybrid(h) => h.inner.kem_derive(ikm).map_err(HybridSuiteError::Base),
            Self::Base(b) => b.kem_derive(ikm).map_err(HybridSuiteError::Base),
        }
    }

    fn kem_generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        match self {
            Self::Hybrid(h) => h.inner.kem_generate().map_err(HybridSuiteError::Base),
            Self::Base(b) => b.kem_generate().map_err(HybridSuiteError::Base),
        }
    }

    fn kem_public_key_validate(&self, key: &HpkePublicKey) -> Result<(), Self::Error> {
        match self {
            Self::Hybrid(h) => h
                .inner
                .kem_public_key_validate(key)
                .map_err(HybridSuiteError::Base),
            Self::Base(b) => b.kem_public_key_validate(key).map_err(HybridSuiteError::Base),
        }
    }

    fn random_bytes(&self, out: &mut [u8]) -> Result<(), Self::Error> {
        match self {
            Self::Hybrid(h) => h.inner.random_bytes(out).map_err(HybridSuiteError::Base),
            Self::Base(b) => b.random_bytes(out).map_err(HybridSuiteError::Base),
        }
    }

    fn signature_key_generate(
        &self,
    ) -> Result<(SignatureSecretKey, SignaturePublicKey), Self::Error> {
        match self {
            Self::Hybrid(h) => h.signature_key_generate(),
            Self::Base(b) => b
                .signature_key_generate()
                
                .map_err(HybridSuiteError::Base),
        }
    }

    fn signature_key_derive_public(
        &self,
        secret_key: &SignatureSecretKey,
    ) -> Result<SignaturePublicKey, Self::Error> {
        match self {
            Self::Hybrid(h) => h.signature_key_derive_public(secret_key),
            Self::Base(b) => b
                .signature_key_derive_public(secret_key)
                
                .map_err(HybridSuiteError::Base),
        }
    }

    fn sign(
        &self,
        secret_key: &SignatureSecretKey,
        data: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        match self {
            Self::Hybrid(h) => h.sign(secret_key, data),
            Self::Base(b) => b.sign(secret_key, data).map_err(HybridSuiteError::Base),
        }
    }

    fn verify(
        &self,
        public_key: &SignaturePublicKey,
        signature: &[u8],
        data: &[u8],
    ) -> Result<(), Self::Error> {
        match self {
            Self::Hybrid(h) => h.verify(public_key, signature, data),
            Self::Base(b) => b
                .verify(public_key, signature, data)
                
                .map_err(HybridSuiteError::Base),
        }
    }
}

// -----------------------------------------------------------------------------
// HybridCipherSuiteProvider — the actual hybrid override. Implements only
// the signature surface; everything else is reached through the parent
// `HybridOrBase` enum that calls the inner base provider directly.
// -----------------------------------------------------------------------------

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

    fn cipher_suite(&self) -> CipherSuite {
        hybrid_cipher_suite()
    }

    fn signature_key_generate(
        &self,
    ) -> Result<(SignatureSecretKey, SignaturePublicKey), HybridSuiteError<B::Error>> {
        // Ed25519 portion via the base provider (Ed25519 is the
        // CURVE25519_AES128 signature scheme there).
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
    ) -> Result<SignaturePublicKey, HybridSuiteError<B::Error>> {
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
    ) -> Result<Vec<u8>, HybridSuiteError<B::Error>> {
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
    ) -> Result<(), HybridSuiteError<B::Error>> {
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
    #[error("base provider error: {0}")]
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

/// AEAD anchor kept from P1 (silences dead-code warning until P1.5.b
/// wires AEAD-specific instrumentation in for the hybrid HPKE path).
#[allow(dead_code)]
fn _aead_passthrough_anchor<T: mls_rs_crypto_traits::AeadType>(_t: T) {}
