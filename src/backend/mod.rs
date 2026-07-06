/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

use crate::error::Result;
use zeroize::Zeroizing;

pub mod openssl_impl;
pub mod rustcrypto_impl;

#[cfg(all(feature = "backend-openssl", not(feature = "backend-rustcrypto")))]
pub use openssl_impl as crypto_impl;
#[cfg(all(feature = "backend-openssl", not(feature = "backend-rustcrypto")))]
pub use openssl_impl::OpenSslHash as Hash;

#[cfg(feature = "backend-rustcrypto")]
pub use rustcrypto_impl as crypto_impl;
#[cfg(feature = "backend-rustcrypto")]
pub use rustcrypto_impl::RustCryptoHash as Hash;

pub trait HashBackend {
    fn new(algo: &str) -> Result<Self>
    where
        Self: Sized;
    fn update(&mut self, data: &[u8]) -> Result<()>;
    fn finalize_sign(&mut self, key_der: &[u8]) -> Result<Vec<u8>>;
    fn finalize_verify(&mut self, key_der: &[u8], signature: &[u8]) -> Result<bool>;
    fn init_sign(&mut self, key_der: &[u8], passphrase: Option<&str>) -> Result<()>;
    fn init_verify(&mut self, key_der: &[u8]) -> Result<()>;
}

pub fn new_hash(algo: &str) -> Result<Hash> {
    Hash::new(algo)
}

pub fn generate_ecc_key_pair(curve: &str) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
    crypto_impl::generate_ecc_key_pair(curve)
}

pub fn ecc_dh(
    my_priv_der: &[u8],
    peer_pub_der: &[u8],
    passphrase: Option<&str>,
) -> Result<Zeroizing<Vec<u8>>> {
    crypto_impl::ecc_dh(my_priv_der, peer_pub_der, passphrase)
}

pub fn extract_public_key(priv_der: &[u8], passphrase: Option<&str>) -> Result<Vec<u8>> {
    crypto_impl::extract_public_key(priv_der, passphrase)
}

pub fn pqc_pub_from_priv_dsa(algo: &str, raw_priv: &[u8]) -> Result<Vec<u8>> {
    crypto_impl::pqc_pub_from_priv_dsa(algo, raw_priv)
}

pub fn pqc_pub_from_priv_kem(algo: &str, raw_priv: &[u8]) -> Result<Vec<u8>> {
    crypto_impl::pqc_pub_from_priv_kem(algo, raw_priv)
}

pub fn pqc_keygen_kem(
    algo: &str,
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>, Option<Zeroizing<Vec<u8>>>)> {
    crypto_impl::pqc_keygen_kem(algo)
}

pub fn pqc_keygen_dsa(
    algo: &str,
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>, Option<Zeroizing<Vec<u8>>>)> {
    crypto_impl::pqc_keygen_dsa(algo)
}

/// The FIPS 204 context string is a single length-prefixed byte with a 1-byte
/// length field, so it is capped at 255 bytes. Reject longer values up front
/// (rather than letting a backend truncate or error opaquely) — our own labels
/// are short constants, but this keeps the API honest for any future caller.
const MLDSA_CTX_MAX: usize = 255;

/// Sign `message` with an ML-DSA key under the FIPS 204 **context string** `ctx`
/// (domain separation). `ctx` empty preserves the pre-context behaviour
/// (`ctx=""`); a non-empty `ctx` is prepended per FIPS 204 as
/// `M' = 0x00 ‖ len(ctx) ‖ ctx ‖ message` (pure ML-DSA). See KEY_EXCHANGE_DESIGN.md §2.
pub fn pqc_sign(algo: &str, priv_der: &[u8], message: &[u8], ctx: &[u8]) -> Result<Vec<u8>> {
    if ctx.len() > MLDSA_CTX_MAX {
        return Err(crate::error::CryptoError::Parameter(format!(
            "ML-DSA context string too long: {} > {MLDSA_CTX_MAX}",
            ctx.len()
        )));
    }
    crypto_impl::pqc_sign(algo, priv_der, message, ctx)
}

pub fn pqc_verify(
    algo: &str,
    pub_der: &[u8],
    message: &[u8],
    signature: &[u8],
    ctx: &[u8],
) -> Result<bool> {
    if ctx.len() > MLDSA_CTX_MAX {
        return Err(crate::error::CryptoError::Parameter(format!(
            "ML-DSA context string too long: {} > {MLDSA_CTX_MAX}",
            ctx.len()
        )));
    }
    crypto_impl::pqc_verify(algo, pub_der, message, signature, ctx)
}

pub fn pqc_encap(algo: &str, peer_pub_der: &[u8]) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
    crypto_impl::pqc_encap(algo, peer_pub_der)
}

pub fn pqc_decap(
    algo: &str,
    priv_der: &[u8],
    kem_ct: &[u8],
    passphrase: Option<&str>,
) -> Result<Zeroizing<Vec<u8>>> {
    crypto_impl::pqc_decap(algo, priv_der, kem_ct, passphrase)
}

pub fn hkdf(
    ikm: &[u8],
    length: usize,
    salt: &[u8],
    info: &str,
    md_name: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    crypto_impl::hkdf(ikm, length, salt, info, md_name)
}

// -- Fixed on-wire byte lengths of the handshake crypto objects ---------------
// Single source of truth for the FIPS 203/204 sizes, so the handshake parser can
// reject a length-confused frame at the door rather than relying on the crypto
// backend to error later (KEY_EXCHANGE_DESIGN.md §10(B), parser robustness).
// `None` = unknown algorithm; the caller skips the check and lets the backend
// reject the algorithm.

/// Raw ML-DSA (FIPS 204) **public key** length for `algo`.
pub fn mldsa_pub_len(algo: &str) -> Option<usize> {
    match algo {
        "ML-DSA-44" => Some(1312),
        "ML-DSA-65" => Some(1952),
        "ML-DSA-87" => Some(2592),
        _ => None,
    }
}

/// Raw ML-DSA (FIPS 204) **signature** length for `algo`. Fixed per parameter set
/// even though signing is randomized/hedged (only the value varies, not the size).
pub fn mldsa_sig_len(algo: &str) -> Option<usize> {
    match algo {
        "ML-DSA-44" => Some(2420),
        "ML-DSA-65" => Some(3309),
        "ML-DSA-87" => Some(4627),
        _ => None,
    }
}

/// Raw ML-KEM (FIPS 203) **encapsulation key** length for `algo`.
pub fn mlkem_ek_len(algo: &str) -> Option<usize> {
    match algo {
        "ML-KEM-512" => Some(800),
        "ML-KEM-768" => Some(1184),
        "ML-KEM-1024" => Some(1568),
        _ => None,
    }
}

/// Raw ML-KEM (FIPS 203) **ciphertext** length for `algo`.
pub fn mlkem_ct_len(algo: &str) -> Option<usize> {
    match algo {
        "ML-KEM-512" => Some(768),
        "ML-KEM-768" => Some(1088),
        "ML-KEM-1024" => Some(1568),
        _ => None,
    }
}

/// P-256 public key as it travels in the handshake: `SubjectPublicKeyInfo` DER,
/// **not** the raw 65-byte SEC1 point. Both backends emit SPKI DER here (measured
/// 91 bytes); the design's "P-256=65" assumed raw SEC1, which this code does not use.
pub const P256_SPKI_DER_LEN: usize = 91;
