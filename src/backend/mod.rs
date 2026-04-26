/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

use crate::error::Result;

pub mod openssl_impl;
pub mod rustcrypto_impl;

#[cfg(all(feature = "backend-openssl", not(feature = "backend-rustcrypto")))]
pub use openssl_impl as crypto_impl;
#[cfg(all(feature = "backend-openssl", not(feature = "backend-rustcrypto")))]
pub use openssl_impl::OpenSslAead as Aead;
#[cfg(all(feature = "backend-openssl", not(feature = "backend-rustcrypto")))]
pub use openssl_impl::OpenSslHash as Hash;

#[cfg(feature = "backend-rustcrypto")]
pub use rustcrypto_impl as crypto_impl;
#[cfg(feature = "backend-rustcrypto")]
pub use rustcrypto_impl::RustCryptoAead as Aead;
#[cfg(feature = "backend-rustcrypto")]
pub use rustcrypto_impl::RustCryptoHash as Hash;

/// Common traits and types for all cryptographic backends.
pub trait AeadBackend {
    fn new_encrypt(cipher: &str, key: &[u8], iv: &[u8]) -> Result<Self> where Self: Sized;
    fn new_decrypt(cipher: &str, key: &[u8], iv: &[u8]) -> Result<Self> where Self: Sized;
    fn update(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize>;
    fn finalize(&mut self, output: &mut [u8]) -> Result<usize>;
    fn get_tag(&self, tag: &mut [u8]) -> Result<()>;
    fn set_tag(&mut self, tag: &[u8]) -> Result<()>;
}

pub trait HashBackend {
    fn new(algo: &str) -> Result<Self> where Self: Sized;
    fn update(&mut self, data: &[u8]) -> Result<()>;
    fn finalize_sign(&mut self, key_der: &[u8]) -> Result<Vec<u8>>;
    fn finalize_verify(&mut self, key_der: &[u8], signature: &[u8]) -> Result<bool>;
    fn init_sign(&mut self, key_der: &[u8]) -> Result<()>;
    fn init_verify(&mut self, key_der: &[u8]) -> Result<()>;
}

pub fn new_encrypt(cipher: &str, key: &[u8], iv: &[u8]) -> Result<Aead> {
    Aead::new_encrypt(cipher, key, iv)
}

pub fn new_decrypt(cipher: &str, key: &[u8], iv: &[u8]) -> Result<Aead> {
    Aead::new_decrypt(cipher, key, iv)
}

pub fn new_hash(algo: &str) -> Result<Hash> {
    Hash::new(algo)
}

pub fn generate_ecc_key_pair(curve: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    crypto_impl::generate_ecc_key_pair(curve)
}

pub fn ecc_dh(my_priv_der: &[u8], peer_pub_der: &[u8]) -> Result<Vec<u8>> {
    crypto_impl::ecc_dh(my_priv_der, peer_pub_der)
}
