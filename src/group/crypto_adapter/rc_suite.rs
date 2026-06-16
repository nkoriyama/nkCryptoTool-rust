// Pure-Rust `CipherSuiteProvider` replacing `mls_rs_crypto_openssl::
// OpensslCipherSuite` as the base suite under `HybridCipherSuiteProvider`.
//
// It is a near-verbatim port of `OpensslCipherSuite` (same composition: an
// `Hpke<KEM, KDF, AEAD>` plus a hash and an Ed25519 signer), with the OpenSSL
// primitives swapped for the in-repo RustCrypto wrappers (`RcAead`, `RcKdf`,
// `RcEcdh`, `RcHash`, `RcEd25519Signer`). Because all HPKE/HKDF labeling lives
// in the provider-agnostic `mls-rs-crypto-hpke` crate, the wire bytes are
// identical to the OpenSSL provider's for the same RFC ciphersuite — so files
// written by the old OpenSSL build keep decrypting.
//
// Like the existing `HybridCipherSuiteProvider` impl, methods are written as
// plain `fn` (the crate is built non-async, so the `CipherSuiteProvider` and
// primitive traits are synchronous after `maybe_async::must_be_sync`).

use mls_rs_core::{
    crypto::{
        CipherSuite, CipherSuiteProvider, HpkeCiphertext, HpkePsk, HpkePublicKey, HpkeSecretKey,
        SignaturePublicKey, SignatureSecretKey,
    },
    error::{AnyError, IntoAnyError},
};
use mls_rs_crypto_hpke::{
    context::{ContextR, ContextS},
    hpke::{Hpke, HpkeError},
};
use mls_rs_crypto_traits::{AeadType, KdfType, KemType};
use thiserror::Error;
use zeroize::Zeroizing;

use super::rc_hash::RcHash;
use super::rc_signer::{RcEd25519Signer, RcSignerError};

#[derive(Debug, Error)]
pub enum RustCryptoSuiteError {
    #[error(transparent)]
    AeadError(AnyError),
    #[error(transparent)]
    KdfError(AnyError),
    #[error(transparent)]
    HpkeError(#[from] HpkeError),
    #[error(transparent)]
    SignerError(#[from] RcSignerError),
    #[error("RNG failure")]
    RngError,
}

impl IntoAnyError for RustCryptoSuiteError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(self.into())
    }
}

#[derive(Clone)]
pub struct RustCryptoSuite<KEM, KDF, AEAD>
where
    KEM: KemType + Clone,
    KDF: KdfType + Clone,
    AEAD: AeadType + Clone,
{
    cipher_suite: CipherSuite,
    aead: AEAD,
    kdf: KDF,
    hash: RcHash,
    hpke: Hpke<KEM, KDF, AEAD>,
    signer: RcEd25519Signer,
}

impl<KEM, KDF, AEAD> RustCryptoSuite<KEM, KDF, AEAD>
where
    KEM: KemType + Clone,
    KDF: KdfType + Clone,
    AEAD: AeadType + Clone,
{
    pub fn new(cipher_suite: CipherSuite, kem: KEM, kdf: KDF, aead: AEAD) -> Option<Self> {
        let hpke = Hpke::new(kem, kdf.clone(), Some(aead.clone()));
        Some(Self {
            cipher_suite,
            aead,
            kdf,
            hash: RcHash::new(cipher_suite).ok()?,
            hpke,
            signer: RcEd25519Signer::new(),
        })
    }
}

impl<KEM, KDF, AEAD> CipherSuiteProvider for RustCryptoSuite<KEM, KDF, AEAD>
where
    KEM: KemType + Clone + Send + Sync,
    KDF: KdfType + Clone + Send + Sync,
    AEAD: AeadType + Clone + Send + Sync,
{
    type Error = RustCryptoSuiteError;
    type HpkeContextS = ContextS<KDF, AEAD>;
    type HpkeContextR = ContextR<KDF, AEAD>;

    fn cipher_suite(&self) -> CipherSuite {
        self.cipher_suite
    }

    fn hash(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Ok(self.hash.hash(data))
    }

    fn mac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Ok(self.hash.mac(key, data))
    }

    fn aead_seal(
        &self,
        key: &[u8],
        data: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        self.aead
            .seal(key, data, aad, nonce)
            .map_err(|e| RustCryptoSuiteError::AeadError(e.into_any_error()))
    }

    fn aead_open(
        &self,
        key: &[u8],
        cipher_text: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        self.aead
            .open(key, cipher_text, aad, nonce)
            .map_err(|e| RustCryptoSuiteError::AeadError(e.into_any_error()))
            .map(Zeroizing::new)
    }

    fn aead_key_size(&self) -> usize {
        self.aead.key_size()
    }

    fn aead_nonce_size(&self) -> usize {
        self.aead.nonce_size()
    }

    fn kdf_expand(
        &self,
        prk: &[u8],
        info: &[u8],
        len: usize,
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        self.kdf
            .expand(prk, info, len)
            .map_err(|e| RustCryptoSuiteError::KdfError(e.into_any_error()))
            .map(Zeroizing::new)
    }

    fn kdf_extract(&self, salt: &[u8], ikm: &[u8]) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        self.kdf
            .extract(salt, ikm)
            .map_err(|e| RustCryptoSuiteError::KdfError(e.into_any_error()))
            .map(Zeroizing::new)
    }

    fn kdf_extract_size(&self) -> usize {
        self.kdf.extract_size()
    }

    fn hpke_seal(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        pt: &[u8],
    ) -> Result<HpkeCiphertext, Self::Error> {
        Ok(self.hpke.seal(remote_key, info, None, aad, pt)?)
    }

    fn hpke_seal_psk(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        pt: &[u8],
        psk: HpkePsk<'_>,
    ) -> Result<HpkeCiphertext, Self::Error> {
        Ok(self.hpke.seal(remote_key, info, Some(psk), aad, pt)?)
    }

    fn hpke_open(
        &self,
        ciphertext: &HpkeCiphertext,
        local_secret: &HpkeSecretKey,
        local_public: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        Ok(self
            .hpke
            .open(ciphertext, local_secret, local_public, info, None, aad)?)
    }

    fn hpke_open_psk(
        &self,
        ciphertext: &HpkeCiphertext,
        local_secret: &HpkeSecretKey,
        local_public: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        psk: HpkePsk<'_>,
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        Ok(self
            .hpke
            .open(ciphertext, local_secret, local_public, info, Some(psk), aad)?)
    }

    fn hpke_setup_r(
        &self,
        enc: &[u8],
        local_secret: &HpkeSecretKey,
        local_public: &HpkePublicKey,
        info: &[u8],
    ) -> Result<Self::HpkeContextR, Self::Error> {
        Ok(self
            .hpke
            .setup_receiver(enc, local_secret, local_public, info, None)?)
    }

    fn hpke_setup_s(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
    ) -> Result<(Vec<u8>, Self::HpkeContextS), Self::Error> {
        Ok(self.hpke.setup_sender(remote_key, info, None)?)
    }

    fn kem_derive(&self, ikm: &[u8]) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        Ok(self.hpke.derive(ikm)?)
    }

    fn kem_generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        Ok(self.hpke.generate()?)
    }

    fn kem_public_key_validate(&self, key: &HpkePublicKey) -> Result<(), Self::Error> {
        Ok(self.hpke.public_key_validate(key)?)
    }

    fn random_bytes(&self, out: &mut [u8]) -> Result<(), Self::Error> {
        use rand_core::RngCore;
        rand_core::OsRng
            .try_fill_bytes(out)
            .map_err(|_| RustCryptoSuiteError::RngError)
    }

    fn sign(&self, secret_key: &SignatureSecretKey, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Ok(self.signer.sign(secret_key, data)?)
    }

    fn verify(
        &self,
        public_key: &SignaturePublicKey,
        signature: &[u8],
        data: &[u8],
    ) -> Result<(), Self::Error> {
        Ok(self.signer.verify(public_key, signature, data)?)
    }

    fn signature_key_generate(
        &self,
    ) -> Result<(SignatureSecretKey, SignaturePublicKey), Self::Error> {
        Ok(self.signer.signature_key_generate()?)
    }

    fn signature_key_derive_public(
        &self,
        secret_key: &SignatureSecretKey,
    ) -> Result<SignaturePublicKey, Self::Error> {
        Ok(self.signer.signature_key_derive_public(secret_key)?)
    }
}
