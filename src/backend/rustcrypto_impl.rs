/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

use crate::error::{CryptoError, Result};
use crate::backend::{AeadBackend, HashBackend};

#[cfg(feature = "backend-rustcrypto")]
mod rc_internal {
    pub use p256::{PublicKey, SecretKey};
    pub use p256::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
    pub use sha3::{Digest, Sha3_256, Sha3_512};
    pub use rand_core::{OsRng};
    
    // Low-level for streaming GCM
    pub use aes::{Aes256, cipher::{KeyInit as _, StreamCipher, BlockEncrypt, KeyIvInit}};
    pub use ctr::Ctr64BE;
    pub use ghash::{GHash, universal_hash::{UniversalHash, KeyInit as _}};
    pub use subtle::ConstantTimeEq;
    pub use generic_array::GenericArray;
    pub use aes_gcm::aead::consts;
    
    // ECDSA
    pub use p256::ecdsa::{SigningKey, VerifyingKey, Signature, signature::{hazmat::{PrehashSigner, PrehashVerifier}}};
}

pub type Aead = RustCryptoAead;
pub type Hash = RustCryptoHash;

pub struct RustCryptoAead {
    #[cfg(feature = "backend-rustcrypto")]
    ctr: Option<rc_internal::Ctr64BE<rc_internal::Aes256>>,
    #[cfg(feature = "backend-rustcrypto")]
    ghash: Option<rc_internal::GHash>,
    #[cfg(feature = "backend-rustcrypto")]
    tag_mask: [u8; 16],
    _iv: Vec<u8>,
    _tag: Vec<u8>,
    _is_encrypt: bool,
    _data_len: u64,
}

impl AeadBackend for RustCryptoAead {
    fn new_encrypt(cipher_name: &str, key: &[u8], iv: &[u8]) -> Result<Self> {
        #[cfg(feature = "backend-rustcrypto")]
        {
            if cipher_name != "AES-256-GCM" {
                return Err(CryptoError::Parameter(format!("Unsupported: {}", cipher_name)));
            }
            use rc_internal::*;
            
            let aes = Aes256::new_from_slice(key).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
            
            // h = E(k, 0^128)
            let mut h = [0u8; 16];
            aes.encrypt_block(GenericArray::from_mut_slice(&mut h));
            let ghash = GHash::new(GenericArray::from_slice(&h));
            
            // tag_mask = E(k, J0) where J0 = iv || 0^31 || 1
            let mut j0 = [0u8; 16];
            j0[..12].copy_from_slice(iv);
            j0[15] = 1;
            let mut tag_mask = j0;
            aes.encrypt_block(GenericArray::from_mut_slice(&mut tag_mask));
            
            // Initial counter for CTR is J0 + 1
            let mut ctr_iv = j0;
            ctr_iv[15] = 2;
            let ctr = Ctr64BE::<Aes256>::new(
                GenericArray::from_slice(key),
                GenericArray::from_slice(&ctr_iv)
            );

            Ok(Self { 
                ctr: Some(ctr), 
                ghash: Some(ghash),
                tag_mask,
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
            let ctr = self.ctr.as_mut().ok_or(CryptoError::Parameter("CTR not init".to_string()))?;
            let ghash = self.ghash.as_mut().ok_or(CryptoError::Parameter("GHASH not init".to_string()))?;
            
            output[..input.len()].copy_from_slice(input);
            ctr.apply_keystream(&mut output[..input.len()]);
            
            let aad_or_cipher = if self._is_encrypt { &output[..input.len()] } else { input };
            ghash.update_padded(aad_or_cipher);
            
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
            let mut ghash = self.ghash.take().ok_or(CryptoError::Parameter("GHASH not init".to_string()))?;
            
            // Final GHASH update with lengths (AAD len || Data len)
            let mut len_block = [0u8; 16];
            len_block[8..16].copy_from_slice(&(self._data_len * 8).to_be_bytes());
            ghash.update(&[*GenericArray::from_slice(&len_block)]);
            
            let mut tag = ghash.finalize();
            for i in 0..16 {
                tag[i] ^= self.tag_mask[i];
            }
            
            if self._is_encrypt {
                self._tag = tag.to_vec();
                Ok(0)
            } else {
                let expected_tag = GenericArray::<u8, consts::U16>::from_slice(&self._tag);
                if tag.ct_eq(expected_tag).unwrap_u8() == 1 {
                    Ok(0)
                } else {
                    Err(CryptoError::SignatureVerification)
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

pub fn pqc_decap(_priv_der: &[u8], _kem_ct: &[u8], _passphrase: Option<&str>) -> Result<Vec<u8>> {
    Err(CryptoError::Parameter("PQC not implemented in RustCrypto backend".to_string()))
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
