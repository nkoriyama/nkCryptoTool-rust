/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

use crate::error::{CryptoError, Result};
use crate::backend::{AeadBackend, HashBackend};

#[cfg(feature = "backend-rustcrypto")]
use fips203::traits::{KeyGen as _, SerDes as _, Decaps as _, Encaps as _};
#[cfg(feature = "backend-rustcrypto")]
use fips204::traits::{KeyGen as _, SerDes as _, Signer as _, Verifier as _};

#[cfg(feature = "backend-rustcrypto")]
mod rc_internal {
    pub use p256::{PublicKey, SecretKey};
    pub use p256::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
    pub use sha3::{Digest, Sha3_256, Sha3_512};
    pub use rand_core::{OsRng};
    
    pub use aes::{Aes256, cipher::{KeyInit as _, StreamCipher, BlockEncrypt, KeyIvInit}};
    pub use ctr::Ctr64BE;
    pub use ghash::{GHash, universal_hash::{UniversalHash, KeyInit as _}};
    pub use subtle::ConstantTimeEq;
    pub use generic_array::GenericArray;
    pub use aes_gcm::aead::consts;

    pub use chacha20::ChaCha20;
    pub use poly1305::Poly1305;
    
    pub use p256::ecdsa::{SigningKey, VerifyingKey, Signature, signature::{hazmat::{PrehashSigner, PrehashVerifier}}};
}

pub type Aead = RustCryptoAead;
pub type Hash = RustCryptoHash;

#[cfg(feature = "backend-rustcrypto")]
enum AeadMode {
    AesGcm {
        ctr: rc_internal::Ctr64BE<rc_internal::Aes256>,
        ghash: rc_internal::GHash,
        tag_mask: [u8; 16],
    },
    ChaChaPoly {
        cipher: rc_internal::ChaCha20,
        poly: rc_internal::Poly1305,
    }
}

pub struct RustCryptoAead {
    #[cfg(feature = "backend-rustcrypto")]
    mode: Option<AeadMode>,
    _iv: Vec<u8>,
    _tag: Vec<u8>,
    _is_encrypt: bool,
    _data_len: u64,
}

impl AeadBackend for RustCryptoAead {
    fn new_encrypt(cipher_name: &str, key: &[u8], iv: &[u8]) -> Result<Self> {
        #[cfg(feature = "backend-rustcrypto")]
        {
            use rc_internal::*;
            let normalized = cipher_name.to_lowercase();
            let mode = if normalized == "aes-256-gcm" {
                let aes = Aes256::new_from_slice(key).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
                let mut h = [0u8; 16];
                aes.encrypt_block(GenericArray::from_mut_slice(&mut h));
                let ghash = GHash::new(GenericArray::from_slice(&h));
                let mut j0 = [0u8; 16];
                j0[..12].copy_from_slice(iv);
                j0[15] = 1;
                let mut tag_mask = j0;
                aes.encrypt_block(GenericArray::from_mut_slice(&mut tag_mask));
                let mut ctr_iv = j0;
                ctr_iv[15] = 2;
                let ctr = Ctr64BE::<Aes256>::new(GenericArray::from_slice(key), GenericArray::from_slice(&ctr_iv));
                AeadMode::AesGcm { ctr, ghash, tag_mask }
            } else if normalized == "chacha20-poly1305" {
                let mut cipher = ChaCha20::new(GenericArray::from_slice(key), GenericArray::from_slice(iv));
                let mut poly_key = [0u8; 32];
                cipher.apply_keystream(&mut poly_key);
                let poly = Poly1305::new(GenericArray::from_slice(&poly_key));
                AeadMode::ChaChaPoly { cipher, poly }
            } else {
                return Err(CryptoError::Parameter(format!("Unsupported: {}", cipher_name)));
            };

            Ok(Self { 
                mode: Some(mode), 
                _iv: iv.to_vec(), 
                _tag: vec![0u8; 16],
                _is_encrypt: true,
                _data_len: 0
            })
        }
        #[cfg(not(feature = "backend-rustcrypto"))]
        {
            let _ = (cipher_name, key, iv);
            Err(CryptoError::Parameter("RustCrypto backend not enabled".to_string()))
        }
    }

    fn new_decrypt(cipher_name: &str, key: &[u8], iv: &[u8]) -> Result<Self> {
        let mut me = Self::new_encrypt(cipher_name, key, iv)?;
        me._is_encrypt = false;
        Ok(me)
    }

    fn update(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize> {
        #[cfg(feature = "backend-rustcrypto")]
        {
            use rc_internal::*;
            let mode = self.mode.as_mut().ok_or(CryptoError::Parameter("AEAD not init".to_string()))?;
            match mode {
                AeadMode::AesGcm { ctr, ghash, .. } => {
                    let mut pos = 0;
                    const CHUNK_SIZE: usize = 128;
                    while pos + CHUNK_SIZE <= input.len() {
                        let in_chunk = &input[pos..pos + CHUNK_SIZE];
                        let out_chunk = &mut output[pos..pos + CHUNK_SIZE];
                        out_chunk.copy_from_slice(in_chunk);
                        ctr.apply_keystream(out_chunk);
                        let aad_or_cipher = if self._is_encrypt { out_chunk } else { in_chunk };
                        ghash.update_padded(aad_or_cipher);
                        pos += CHUNK_SIZE;
                    }
                    if pos < input.len() {
                        let in_rem = &input[pos..];
                        let out_rem = &mut output[pos..pos + in_rem.len()];
                        out_rem.copy_from_slice(in_rem);
                        ctr.apply_keystream(out_rem);
                        let aad_or_cipher = if self._is_encrypt { out_rem } else { in_rem };
                        ghash.update_padded(aad_or_cipher);
                    }
                },
                AeadMode::ChaChaPoly { cipher, poly } => {
                    let out_slice = &mut output[..input.len()];
                    out_slice.copy_from_slice(input);
                    cipher.apply_keystream(out_slice);
                    let aad_or_cipher = if self._is_encrypt { out_slice } else { input };
                    poly.update_padded(aad_or_cipher);
                }
            }
            self._data_len += input.len() as u64;
            Ok(input.len())
        }
        #[cfg(not(feature = "backend-rustcrypto"))]
        {
            let _ = (input, output);
            Err(CryptoError::Parameter("RustCrypto backend not enabled".to_string()))
        }
    }

    fn finalize(&mut self, _output: &mut [u8]) -> Result<usize> {
        #[cfg(feature = "backend-rustcrypto")]
        {
            use rc_internal::*;
            let mode = self.mode.take().ok_or(CryptoError::Parameter("AEAD not init".to_string()))?;
            match mode {
                AeadMode::AesGcm { mut ghash, tag_mask, .. } => {
                    let mut len_block = [0u8; 16];
                    len_block[8..16].copy_from_slice(&(self._data_len * 8).to_be_bytes());
                    ghash.update(&[*GenericArray::from_slice(&len_block)]);
                    let mut tag = ghash.finalize();
                    for i in 0..16 { tag[i] ^= tag_mask[i]; }
                    if self._is_encrypt {
                        self._tag = tag.to_vec();
                        Ok(0)
                    } else {
                        let expected_tag = GenericArray::<u8, consts::U16>::from_slice(&self._tag);
                        if tag.ct_eq(expected_tag).unwrap_u8() == 1 { Ok(0) } else { Err(CryptoError::SignatureVerification) }
                    }
                },
                AeadMode::ChaChaPoly { poly, .. } => {
                    let mut len_block = [0u8; 16];
                    len_block[8..16].copy_from_slice(&self._data_len.to_le_bytes());
                    let mut poly = poly;
                    poly.update_padded(&len_block);
                    let tag = poly.finalize();
                    if self._is_encrypt {
                        self._tag = tag.to_vec();
                        Ok(0)
                    } else {
                        let expected_tag = GenericArray::<u8, consts::U16>::from_slice(&self._tag);
                        if tag.ct_eq(expected_tag).unwrap_u8() == 1 { Ok(0) } else { Err(CryptoError::SignatureVerification) }
                    }
                }
            }
        }
        #[cfg(not(feature = "backend-rustcrypto"))]
        {
            let _ = _output;
            Err(CryptoError::Parameter("RustCrypto backend not enabled".to_string()))
        }
    }

    fn get_tag(&self, tag: &mut [u8]) -> Result<()> {
        tag.copy_from_slice(&self._tag);
        Ok(())
    }

    fn set_tag(&mut self, tag: &[u8]) -> Result<()> {
        self._tag = tag.to_vec();
        Ok(())
    }
}

pub struct RustCryptoHash {
    #[cfg(feature = "backend-rustcrypto")]
    digest_256: Option<rc_internal::Sha3_256>,
    #[cfg(feature = "backend-rustcrypto")]
    digest_512: Option<rc_internal::Sha3_512>,
}

impl HashBackend for RustCryptoHash {
    fn new(algo: &str) -> Result<Self> {
        #[cfg(feature = "backend-rustcrypto")]
        {
            use rc_internal::*;
            match algo {
                "SHA3-256" => Ok(Self { digest_256: Some(Sha3_256::new()), digest_512: None }),
                "SHA3-512" => Ok(Self { digest_256: None, digest_512: Some(Sha3_512::new()) }),
                _ => Err(CryptoError::Parameter(format!("Unsupported digest: {}", algo))),
            }
        }
        #[cfg(not(feature = "backend-rustcrypto"))]
        {
            let _ = algo;
            Err(CryptoError::Parameter("RustCrypto backend not enabled".to_string()))
        }
    }

    fn update(&mut self, data: &[u8]) -> Result<()> {
        #[cfg(feature = "backend-rustcrypto")]
        {
            if let Some(d) = &mut self.digest_256 { rc_internal::Digest::update(d, data); }
            if let Some(d) = &mut self.digest_512 { rc_internal::Digest::update(d, data); }
            Ok(())
        }
        #[cfg(not(feature = "backend-rustcrypto"))]
        {
            let _ = data;
            Err(CryptoError::Parameter("RustCrypto backend not enabled".to_string()))
        }
    }

    fn finalize_sign(&mut self, key_der: &[u8]) -> Result<Vec<u8>> {
        #[cfg(feature = "backend-rustcrypto")]
        {
            use rc_internal::*;
            let hash_bytes = if let Some(d) = self.digest_256.take() { d.finalize().to_vec() }
                            else if let Some(d) = self.digest_512.take() { d.finalize().to_vec() }
                            else { return Err(CryptoError::Parameter("Digest not init".to_string())); };
            
            let sk_raw = SecretKey::from_pkcs8_der(key_der).or_else(|_| SecretKey::from_sec1_der(key_der))
                .map_err(|e| CryptoError::PrivateKeyLoad(e.to_string()))?;
            let sig_key = SigningKey::from(&sk_raw);
            let signature: Signature = sig_key.sign_prehash(&hash_bytes).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
            Ok(signature.to_der().to_bytes().to_vec())
        }
        #[cfg(not(feature = "backend-rustcrypto"))]
        {
            let _ = key_der;
            Err(CryptoError::Parameter("RustCrypto backend not enabled".to_string()))
        }
    }

    fn finalize_verify(&mut self, key_der: &[u8], signature: &[u8]) -> Result<bool> {
        #[cfg(feature = "backend-rustcrypto")]
        {
            use rc_internal::*;
            let hash_bytes = if let Some(d) = self.digest_256.take() { d.finalize().to_vec() }
                            else if let Some(d) = self.digest_512.take() { d.finalize().to_vec() }
                            else { return Err(CryptoError::Parameter("Digest not init".to_string())); };
            
            let vk = VerifyingKey::from_public_key_der(key_der).map_err(|e| CryptoError::PublicKeyLoad(e.to_string()))?;
            let sig = Signature::from_der(signature).map_err(|e| CryptoError::Parameter(e.to_string()))?;
            Ok(vk.verify_prehash(&hash_bytes, &sig).is_ok())
        }
        #[cfg(not(feature = "backend-rustcrypto"))]
        {
            let _ = (key_der, signature);
            Err(CryptoError::Parameter("RustCrypto backend not enabled".to_string()))
        }
    }

    fn init_sign(&mut self, _key_der: &[u8], _passphrase: Option<&str>) -> Result<()> {
        Ok(())
    }

    fn init_verify(&mut self, _key_der: &[u8]) -> Result<()> {
        Ok(())
    }
}

pub fn generate_ecc_key_pair(curve_name: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    #[cfg(feature = "backend-rustcrypto")]
    {
        use rc_internal::*;
        if curve_name != "prime256v1" {
            return Err(CryptoError::Parameter(format!("Unsupported curve: {}", curve_name)));
        }
        let secret_key = SecretKey::random(&mut OsRng);
        let public_key = secret_key.public_key();
        
        let priv_der = secret_key.to_pkcs8_der().map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        let pub_der = public_key.to_public_key_der().map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        
        Ok((priv_der.to_bytes().to_vec(), pub_der.as_bytes().to_vec()))
    }
    #[cfg(not(feature = "backend-rustcrypto"))]
    {
        let _ = curve_name;
        Err(CryptoError::Parameter("RustCrypto backend not enabled".to_string()))
    }
}

pub fn ecc_dh(my_priv_der: &[u8], peer_pub_der: &[u8], _passphrase: Option<&str>) -> Result<Vec<u8>> {
    #[cfg(feature = "backend-rustcrypto")]
    {
        use rc_internal::*;
        let sk = SecretKey::from_pkcs8_der(my_priv_der).or_else(|_| SecretKey::from_sec1_der(my_priv_der))
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        let pk = PublicKey::from_public_key_der(peer_pub_der).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        let shared_secret = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
        Ok(shared_secret.raw_secret_bytes().to_vec())
    }
    #[cfg(not(feature = "backend-rustcrypto"))]
    {
        let _ = (my_priv_der, peer_pub_der, _passphrase);
        Err(CryptoError::Parameter("RustCrypto backend not enabled".to_string()))
    }
}

pub fn extract_public_key(priv_der: &[u8], _passphrase: Option<&str>) -> Result<Vec<u8>> {
    #[cfg(feature = "backend-rustcrypto")]
    {
        use rc_internal::*;
        let sk = SecretKey::from_pkcs8_der(priv_der).or_else(|_| SecretKey::from_sec1_der(priv_der))
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        let pk = sk.public_key();
        pk.to_public_key_der().map_err(|e| CryptoError::OpenSSL(e.to_string())).map(|d| d.as_bytes().to_vec())
    }
    #[cfg(not(feature = "backend-rustcrypto"))]
    {
        let _ = (priv_der, _passphrase);
        Err(CryptoError::Parameter("RustCrypto backend not enabled".to_string()))
    }
}

#[cfg(feature = "backend-rustcrypto")]
fn read_asn1_len(der: &[u8], pos: &mut usize) -> usize {
    if *pos >= der.len() { return 0; }
    let b = der[*pos];
    *pos += 1;
    if b < 128 { return b as usize; }
    let n = (b & 0x7F) as usize;
    if *pos + n > der.len() || n > 4 { return 0; }
    let mut res = 0usize;
    for _ in 0..n {
        res = (res << 8) | (der[*pos] as usize);
        *pos += 1;
    }
    res
}

#[cfg(feature = "backend-rustcrypto")]
fn unwrap_pqc_der_internal(der: &[u8], is_public: bool) -> Vec<u8> {
    if der.is_empty() || der[0] != 0x30 { return der.to_vec(); }
    let mut best = Vec::new();
    for i in 0..der.len().saturating_sub(4) {
        let tag = der[i];
        if tag == 0x04 || (is_public && tag == 0x03) {
            let mut pos = i + 1;
            let o_len = read_asn1_len(der, &mut pos);
            if o_len > 0 && pos + o_len <= der.len() {
                let mut actual_len = o_len;
                let mut data_start = pos;
                if tag == 0x03 {
                    if actual_len > 1 && der[data_start] == 0x00 { data_start += 1; actual_len -= 1; }
                    else { continue; }
                }
                if [1632, 2400, 3168, 2560, 4032, 4896, 800, 1184, 1568, 1312, 1952, 2592].contains(&actual_len) {
                    return der[data_start..data_start + actual_len].to_vec();
                }
                if actual_len > 32 && der[data_start] == 0x30 {
                    let inner = unwrap_pqc_der_internal(&der[data_start..data_start + actual_len], is_public);
                    if [1632, 2400, 3168, 2560, 4032, 4896, 800, 1184, 1568, 1312, 1952, 2592].contains(&inner.len()) { return inner; }
                }
                if actual_len > best.len() { best = der[data_start..data_start + actual_len].to_vec(); }
            }
        }
    }
    if best.is_empty() { der.to_vec() } else { best }
}

pub fn pqc_keygen_kem(algo: &str) -> Result<(Vec<u8>, Vec<u8>, Option<Vec<u8>>)> {
    #[cfg(feature = "backend-rustcrypto")]
    {
        use rc_internal::OsRng;
        use rand_core::RngCore;
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];
        OsRng.fill_bytes(&mut d);
        OsRng.fill_bytes(&mut z);
        let mut seeds = Vec::with_capacity(64);
        seeds.extend_from_slice(&d);
        seeds.extend_from_slice(&z);
        match algo {
            "ML-KEM-512" => {
                use fips203::ml_kem_512::KG;
                let (pk, sk) = KG::keygen_from_seed(d, z);
                Ok((sk.into_bytes().to_vec(), pk.into_bytes().to_vec(), Some(seeds)))
            },
            "ML-KEM-768" => {
                use fips203::ml_kem_768::KG;
                let (pk, sk) = KG::keygen_from_seed(d, z);
                Ok((sk.into_bytes().to_vec(), pk.into_bytes().to_vec(), Some(seeds)))
            },
            "ML-KEM-1024" => {
                use fips203::ml_kem_1024::KG;
                let (pk, sk) = KG::keygen_from_seed(d, z);
                Ok((sk.into_bytes().to_vec(), pk.into_bytes().to_vec(), Some(seeds)))
            },
            _ => Err(CryptoError::Parameter(format!("Unsupported KEM: {}", algo))),
        }
    }
    #[cfg(not(feature = "backend-rustcrypto"))]
    { let _ = algo; Err(CryptoError::Parameter("RustCrypto backend not enabled".to_string())) }
}

pub fn pqc_keygen_dsa(algo: &str) -> Result<(Vec<u8>, Vec<u8>, Option<Vec<u8>>)> {
    #[cfg(feature = "backend-rustcrypto")]
    {
        use rc_internal::OsRng;
        use rand_core::RngCore;
        let mut xi = [0u8; 32];
        OsRng.fill_bytes(&mut xi);
        let seed = xi.to_vec();
        match algo {
            "ML-DSA-44" => {
                let (pk, sk) = fips204::ml_dsa_44::KG::keygen_from_seed(&xi);
                Ok((sk.into_bytes().to_vec(), pk.into_bytes().to_vec(), Some(seed)))
            },
            "ML-DSA-65" => {
                let (pk, sk) = fips204::ml_dsa_65::KG::keygen_from_seed(&xi);
                Ok((sk.into_bytes().to_vec(), pk.into_bytes().to_vec(), Some(seed)))
            },
            "ML-DSA-87" => {
                let (pk, sk) = fips204::ml_dsa_87::KG::keygen_from_seed(&xi);
                Ok((sk.into_bytes().to_vec(), pk.into_bytes().to_vec(), Some(seed)))
            },
            _ => Err(CryptoError::Parameter(format!("Unsupported DSA: {}", algo))),
        }
    }
    #[cfg(not(feature = "backend-rustcrypto"))]
    { let _ = algo; Err(CryptoError::Parameter("RustCrypto backend not enabled".to_string())) }
}

pub fn pqc_sign(algo: &str, priv_der: &[u8], message: &[u8], _passphrase: Option<&str>) -> Result<Vec<u8>> {
    #[cfg(feature = "backend-rustcrypto")]
    {
        let raw_priv = unwrap_pqc_der_internal(priv_der, false);
        match algo {
            "ML-DSA-44" => {
                let sk = fips204::ml_dsa_44::PrivateKey::try_from_bytes(raw_priv.try_into().map_err(|_| CryptoError::Parameter("Invalid key size".to_string()))?)
                    .map_err(|_| CryptoError::PrivateKeyLoad("Invalid key".to_string()))?;
                Ok(sk.try_sign(message, &[]).map_err(|_| CryptoError::OpenSSL("Sign failed".to_string()))?.to_vec())
            },
            "ML-DSA-65" => {
                let sk = fips204::ml_dsa_65::PrivateKey::try_from_bytes(raw_priv.try_into().map_err(|_| CryptoError::Parameter("Invalid key size".to_string()))?)
                    .map_err(|_| CryptoError::PrivateKeyLoad("Invalid key".to_string()))?;
                Ok(sk.try_sign(message, &[]).map_err(|_| CryptoError::OpenSSL("Sign failed".to_string()))?.to_vec())
            },
            "ML-DSA-87" => {
                let sk = fips204::ml_dsa_87::PrivateKey::try_from_bytes(raw_priv.try_into().map_err(|_| CryptoError::Parameter("Invalid key size".to_string()))?)
                    .map_err(|_| CryptoError::PrivateKeyLoad("Invalid key".to_string()))?;
                Ok(sk.try_sign(message, &[]).map_err(|_| CryptoError::OpenSSL("Sign failed".to_string()))?.to_vec())
            },
            _ => Err(CryptoError::Parameter(format!("Unsupported DSA: {}", algo))),
        }
    }
    #[cfg(not(feature = "backend-rustcrypto"))]
    { let _ = (algo, priv_der, message, _passphrase); Err(CryptoError::Parameter("RustCrypto backend not enabled".to_string())) }
}

pub fn pqc_verify(algo: &str, pub_der: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
    #[cfg(feature = "backend-rustcrypto")]
    {
        let raw_pub = unwrap_pqc_der_internal(pub_der, true);
        match algo {
            "ML-DSA-44" => {
                let pk = fips204::ml_dsa_44::PublicKey::try_from_bytes(raw_pub.try_into().map_err(|_| CryptoError::Parameter("Invalid key size".to_string()))?)
                    .map_err(|_| CryptoError::PublicKeyLoad("Invalid key".to_string()))?;
                let sig_arr: [u8; 2420] = signature.try_into().map_err(|_| CryptoError::Parameter("Invalid sig size".to_string()))?;
                Ok(pk.verify(message, &sig_arr, &[]))
            },
            "ML-DSA-65" => {
                let pk = fips204::ml_dsa_65::PublicKey::try_from_bytes(raw_pub.try_into().map_err(|_| CryptoError::Parameter("Invalid key size".to_string()))?)
                    .map_err(|_| CryptoError::PublicKeyLoad("Invalid key".to_string()))?;
                let sig_arr: [u8; 3309] = signature.try_into().map_err(|_| CryptoError::Parameter("Invalid sig size".to_string()))?;
                Ok(pk.verify(message, &sig_arr, &[]))
            },
            "ML-DSA-87" => {
                let pk = fips204::ml_dsa_87::PublicKey::try_from_bytes(raw_pub.try_into().map_err(|_| CryptoError::Parameter("Invalid key size".to_string()))?)
                    .map_err(|_| CryptoError::PublicKeyLoad("Invalid key".to_string()))?;
                let sig_arr: [u8; 4627] = signature.try_into().map_err(|_| CryptoError::Parameter("Invalid sig size".to_string()))?;
                Ok(pk.verify(message, &sig_arr, &[]))
            },
            _ => Err(CryptoError::Parameter(format!("Unsupported DSA: {}", algo))),
        }
    }
    #[cfg(not(feature = "backend-rustcrypto"))]
    { let _ = (algo, pub_der, message, signature); Err(CryptoError::Parameter("RustCrypto backend not enabled".to_string())) }
}

pub fn pqc_encap(algo: &str, peer_pub_der: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    #[cfg(feature = "backend-rustcrypto")]
    {
        let raw_pub = unwrap_pqc_der_internal(peer_pub_der, true);
        let actual_len = raw_pub.len();
        if actual_len == 800 {
            use fips203::ml_kem_512::EncapsKey;
            let pk = EncapsKey::try_from_bytes(raw_pub.try_into().map_err(|_| CryptoError::PublicKeyLoad("Invalid key size".to_string()))?)
                .map_err(|_| CryptoError::PublicKeyLoad("Invalid key".to_string()))?;
            let (ss, ct) = pk.try_encaps().map_err(|_| CryptoError::OpenSSL("Encap failed".to_string()))?;
            Ok((ss.into_bytes().to_vec(), ct.into_bytes().to_vec()))
        } else if actual_len == 1184 {
            use fips203::ml_kem_768::EncapsKey;
            let pk = EncapsKey::try_from_bytes(raw_pub.try_into().map_err(|_| CryptoError::PublicKeyLoad("Invalid key size".to_string()))?)
                .map_err(|_| CryptoError::PublicKeyLoad("Invalid key".to_string()))?;
            let (ss, ct) = pk.try_encaps().map_err(|_| CryptoError::OpenSSL("Encap failed".to_string()))?;
            Ok((ss.into_bytes().to_vec(), ct.into_bytes().to_vec()))
        } else if actual_len == 1568 {
            use fips203::ml_kem_1024::EncapsKey;
            let pk = EncapsKey::try_from_bytes(raw_pub.try_into().map_err(|_| CryptoError::PublicKeyLoad("Invalid key size".to_string()))?)
                .map_err(|_| CryptoError::PublicKeyLoad("Invalid key".to_string()))?;
            let (ss, ct) = pk.try_encaps().map_err(|_| CryptoError::OpenSSL("Encap failed".to_string()))?;
            Ok((ss.into_bytes().to_vec(), ct.into_bytes().to_vec()))
        } else {
            Err(CryptoError::Parameter(format!("Unsupported or mismatched KEM key size: {}", actual_len)))
        }
    }
    #[cfg(not(feature = "backend-rustcrypto"))]
    { let _ = (algo, peer_pub_der); Err(CryptoError::Parameter("RustCrypto backend not enabled".to_string())) }
}

pub fn pqc_decap(algo: &str, priv_der: &[u8], kem_ct: &[u8], _passphrase: Option<&str>) -> Result<Vec<u8>> {
    #[cfg(feature = "backend-rustcrypto")]
    {
        let raw_priv = unwrap_pqc_der_internal(priv_der, false);
        let actual_len = raw_priv.len();
        if actual_len == 1632 {
            use fips203::ml_kem_512::{DecapsKey, CipherText};
            let sk = DecapsKey::try_from_bytes(raw_priv.try_into().map_err(|_| CryptoError::PrivateKeyLoad("Invalid key size".to_string()))?)
                .map_err(|_| CryptoError::PrivateKeyLoad("Invalid key".to_string()))?;
            let ct = CipherText::try_from_bytes(kem_ct.try_into().map_err(|_| CryptoError::Parameter("Invalid CT size".to_string()))?)
                .map_err(|_| CryptoError::Parameter("Invalid CT".to_string()))?;
            let ss = sk.try_decaps(&ct).map_err(|_| CryptoError::OpenSSL("Decap failed".to_string()))?;
            Ok(ss.into_bytes().to_vec())
        } else if actual_len == 2400 {
            use fips203::ml_kem_768::{DecapsKey, CipherText};
            let sk = DecapsKey::try_from_bytes(raw_priv.try_into().map_err(|_| CryptoError::PrivateKeyLoad("Invalid key size".to_string()))?)
                .map_err(|_| CryptoError::PrivateKeyLoad("Invalid key".to_string()))?;
            let ct = CipherText::try_from_bytes(kem_ct.try_into().map_err(|_| CryptoError::Parameter("Invalid CT size".to_string()))?)
                .map_err(|_| CryptoError::Parameter("Invalid CT".to_string()))?;
            let ss = sk.try_decaps(&ct).map_err(|_| CryptoError::OpenSSL("Decap failed".to_string()))?;
            Ok(ss.into_bytes().to_vec())
        } else if actual_len == 3168 {
            use fips203::ml_kem_1024::{DecapsKey, CipherText};
            let sk = DecapsKey::try_from_bytes(raw_priv.try_into().map_err(|_| CryptoError::PrivateKeyLoad("Invalid key size".to_string()))?)
                .map_err(|_| CryptoError::PrivateKeyLoad("Invalid key".to_string()))?;
            let ct = CipherText::try_from_bytes(kem_ct.try_into().map_err(|_| CryptoError::Parameter("Invalid CT size".to_string()))?)
                .map_err(|_| CryptoError::Parameter("Invalid CT".to_string()))?;
            let ss = sk.try_decaps(&ct).map_err(|_| CryptoError::OpenSSL("Decap failed".to_string()))?;
            Ok(ss.into_bytes().to_vec())
        } else {
             Err(CryptoError::Parameter(format!("Unsupported or mismatched KEM key size: {}", actual_len)))
        }
    }
    #[cfg(not(feature = "backend-rustcrypto"))]
    { let _ = (algo, priv_der, kem_ct, _passphrase); Err(CryptoError::Parameter("RustCrypto backend not enabled".to_string())) }
}

pub fn hkdf(ikm: &[u8], length: usize, salt: &[u8], info: &str, md_name: &str) -> Result<Vec<u8>> {
    #[cfg(feature = "backend-rustcrypto")]
    {
        use rc_internal::*;
        use hkdf::Hkdf;
        let mut okm = vec![0u8; length];
        if md_name.contains("256") {
            let h = Hkdf::<Sha3_256>::new(Some(salt), ikm);
            h.expand(info.as_bytes(), &mut okm).map_err(|_| CryptoError::Parameter("HKDF expand failed".to_string()))?;
        } else {
            let h = Hkdf::<Sha3_512>::new(Some(salt), ikm);
            h.expand(info.as_bytes(), &mut okm).map_err(|_| CryptoError::Parameter("HKDF expand failed".to_string()))?;
        }
        Ok(okm)
    }
    #[cfg(not(feature = "backend-rustcrypto"))]
    { let _ = (ikm, length, salt, info, md_name); Err(CryptoError::Parameter("RustCrypto backend not enabled".to_string())) }
}

pub fn extract_raw_private_key(priv_der: &[u8], _passphrase: Option<&str>) -> Result<Vec<u8>> {
    Ok(priv_der.to_vec())
}

pub fn new_encrypt(cipher: &str, key: &[u8], iv: &[u8]) -> Result<Aead> {
    AeadBackend::new_encrypt(cipher, key, iv)
}

pub fn new_decrypt(cipher: &str, key: &[u8], iv: &[u8]) -> Result<Aead> {
    AeadBackend::new_decrypt(cipher, key, iv)
}

pub fn new_hash(algo: &str) -> Result<Hash> {
    HashBackend::new(algo)
}
