//! Hybrid PQC crypto adapter for `mls-rs`.
//!
//! P1 (this file): **passthrough only**. `HybridCryptoProvider<B>`
//! wraps a base `CryptoProvider` (typically `OpensslCryptoProvider`)
//! and delegates every method unchanged. This establishes the wiring
//! pattern so P1.5 can override `kem_*` and signature methods to use
//! the project's existing PQC primitives without touching call sites.
//!
//! P1.5 (TODO): override KEM (`X25519 + ML-KEM-768` concatenated KEM)
//! and Signature (`ML-DSA-65 + Ed25519` composite signature) to lift
//! this adapter into a true hybrid post-quantum CryptoProvider.

use mls_rs::CipherSuite;
use mls_rs_core::crypto::CryptoProvider;
use mls_rs_crypto_traits::AeadType;

/// `mls-rs` `CryptoProvider` wrapper. In P1 this is a strict
/// passthrough; in P1.5 the cipher-suite-provider it returns gets
/// extra logic for the hybrid PQC ciphersuite.
#[derive(Clone, Debug, Default)]
pub struct HybridCryptoProvider<B> {
    base: B,
}

impl<B> HybridCryptoProvider<B> {
    pub fn new(base: B) -> Self {
        Self { base }
    }

    pub fn into_inner(self) -> B {
        self.base
    }

    pub fn inner(&self) -> &B {
        &self.base
    }
}

impl<B> CryptoProvider for HybridCryptoProvider<B>
where
    B: CryptoProvider + Send + Sync,
{
    type CipherSuiteProvider = B::CipherSuiteProvider;

    fn supported_cipher_suites(&self) -> Vec<CipherSuite> {
        // P1: same suites the base provider offers. P1.5 will append
        // the hybrid PQC suite identifier.
        self.base.supported_cipher_suites()
    }

    fn cipher_suite_provider(
        &self,
        cipher_suite: CipherSuite,
    ) -> Option<Self::CipherSuiteProvider> {
        // P1: pure passthrough.
        // P1.5: branch on `cipher_suite == hybrid_pqc_suite` and return a
        // wrapped CipherSuiteProvider that overrides KEM / Signature.
        self.base.cipher_suite_provider(cipher_suite)
    }
}

/// AEAD passthrough kept here so future per-AEAD instrumentation has a
/// hook point. Currently unused; suppresses dead-code warnings until
/// P1.5 wires it in.
#[allow(dead_code)]
fn _aead_passthrough_anchor<T: AeadType>(_t: T) {}
