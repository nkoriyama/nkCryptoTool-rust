/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

use crate::error::{CryptoError, Result};
use crate::backend::{AeadBackend, HashBackend};

#[cfg(feature = "backend-openssl")]
use openssl::cipher::Cipher;
#[cfg(feature = "backend-openssl")]
use openssl::cipher_ctx::CipherCtx;
#[cfg(feature = "backend-openssl")]
use openssl::hash::MessageDigest;
#[cfg(feature = "backend-openssl")]
use openssl::md_ctx::MdCtx;
#[cfg(feature = "backend-openssl")]
use openssl::pkey::PKey;
#[cfg(feature = "backend-openssl")]
use openssl::derive::Deriver;
#[cfg(feature = "backend-openssl")]
use openssl::ec::{EcGroup, EcKey};
#[cfg(feature = "backend-openssl")]
use openssl::nid::Nid;
#[cfg(feature = "backend-openssl")]
use openssl_sys as ffi;
#[cfg(feature = "backend-openssl")]
use std::ptr;
#[cfg(feature = "backend-openssl")]
use foreign_types::ForeignType;

pub struct OpenSslAead {
    #[cfg(feature = "backend-openssl")]
    ctx: CipherCtx,
}

#[cfg(feature = "backend-openssl")]
fn load_private_key_robust(der: &[u8], passphrase: Option<&str>) -> Result<PKey<openssl::pkey::Private>> {
    // Try auto/unencrypted first
    if let Ok(pkey) = PKey::private_key_from_der(der) {
        return Ok(pkey);
    }
    // If it fails, try with passphrase using FFI if provided
    if let Some(pass) = passphrase {
        let mem = unsafe { ffi::BIO_new_mem_buf(der.as_ptr() as *const _, der.len() as _) };
        if !mem.is_null() {
            let pass_ptr = pass.as_ptr() as *const _;
            // FFI for d2i_PKCS8PrivateKey_bio
            unsafe {
                let pkey_ptr = ffi::d2i_PKCS8PrivateKey_bio(mem, ptr::null_mut(), None, pass_ptr as *mut _);
                ffi::BIO_free_all(mem);
                if !pkey_ptr.is_null() {
                    return Ok(PKey::from_ptr(pkey_ptr));
                }
            }
        }
    }
    Err(CryptoError::PrivateKeyLoad("Failed to load or decrypt private key".to_string()))
}

impl AeadBackend for OpenSslAead {
    fn new_encrypt(cipher_name: &str, key: &[u8], iv: &[u8]) -> Result<Self> {
        #[cfg(feature = "backend-openssl")]
        {
            let mut ctx = CipherCtx::new().map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
            let cipher = match cipher_name {
                "AES-256-GCM" => Cipher::aes_256_gcm(),
                _ => return Err(CryptoError::Parameter(format!("Unsupported cipher: {}", cipher_name))),
            };
            ctx.encrypt_init(Some(cipher), None, None).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
            ctx.set_iv_length(iv.len()).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
            ctx.encrypt_init(None, Some(key), Some(iv)).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
            Ok(Self { ctx })
        }
        #[cfg(not(feature = "backend-openssl"))]
        {
            let _ = (cipher_name, key, iv);
            Err(CryptoError::Parameter("OpenSSL backend not enabled".to_string()))
        }
    }

    fn new_decrypt(cipher_name: &str, key: &[u8], iv: &[u8]) -> Result<Self> {
        #[cfg(feature = "backend-openssl")]
        {
            let mut ctx = CipherCtx::new().map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
            let cipher = match cipher_name {
                "AES-256-GCM" => Cipher::aes_256_gcm(),
                _ => return Err(CryptoError::Parameter(format!("Unsupported cipher: {}", cipher_name))),
            };
            ctx.decrypt_init(Some(cipher), None, None).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
            ctx.set_iv_length(iv.len()).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
            ctx.decrypt_init(None, Some(key), Some(iv)).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
            Ok(Self { ctx })
        }
        #[cfg(not(feature = "backend-openssl"))]
        {
            let _ = (cipher_name, key, iv);
            Err(CryptoError::Parameter("OpenSSL backend not enabled".to_string()))
        }
    }

    fn update(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize> {
        #[cfg(feature = "backend-openssl")]
        {
            return self.ctx.cipher_update(input, Some(output)).map_err(|e| CryptoError::OpenSSL(e.to_string()));
        }
        #[cfg(not(feature = "backend-openssl"))]
        {
            let _ = (input, output);
            Err(CryptoError::Parameter("OpenSSL backend not enabled".to_string()))
        }
    }

    fn finalize(&mut self, output: &mut [u8]) -> Result<usize> {
        #[cfg(feature = "backend-openssl")]
        {
            return self.ctx.cipher_final(output).map_err(|e| CryptoError::OpenSSL(e.to_string()));
        }
        #[cfg(not(feature = "backend-openssl"))]
        {
            let _ = output;
            Err(CryptoError::Parameter("OpenSSL backend not enabled".to_string()))
        }
    }

    fn get_tag(&self, tag: &mut [u8]) -> Result<()> {
        #[cfg(feature = "backend-openssl")]
        {
            return self.ctx.tag(tag).map_err(|e| CryptoError::OpenSSL(e.to_string()));
        }
        #[cfg(not(feature = "backend-openssl"))]
        {
            let _ = tag;
            Err(CryptoError::Parameter("OpenSSL backend not enabled".to_string()))
        }
    }

    fn set_tag(&mut self, tag: &[u8]) -> Result<()> {
        #[cfg(feature = "backend-openssl")]
        {
            return self.ctx.set_tag(tag).map_err(|e| CryptoError::OpenSSL(e.to_string()));
        }
        #[cfg(not(feature = "backend-openssl"))]
        {
            let _ = tag;
            Err(CryptoError::Parameter("OpenSSL backend not enabled".to_string()))
        }
    }
}

pub struct OpenSslHash {
    #[cfg(feature = "backend-openssl")]
    ctx: MdCtx,
    #[cfg(feature = "backend-openssl")]
    md: MessageDigest,
}

impl HashBackend for OpenSslHash {
    fn new(algo: &str) -> Result<Self> {
        #[cfg(feature = "backend-openssl")]
        {
            let md = MessageDigest::from_name(algo)
                .ok_or(CryptoError::Parameter(format!("Unsupported digest: {}", algo)))?;
            let ctx = MdCtx::new().map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
            Ok(Self { ctx, md })
        }
        #[cfg(not(feature = "backend-openssl"))]
        {
            let _ = algo;
            Err(CryptoError::Parameter("OpenSSL backend not enabled".to_string()))
        }
    }

    fn update(&mut self, data: &[u8]) -> Result<()> {
        #[cfg(feature = "backend-openssl")]
        {
            return self.ctx.digest_sign_update(data).map_err(|e| CryptoError::OpenSSL(e.to_string()));
        }
        #[cfg(not(feature = "backend-openssl"))]
        {
            let _ = data;
            Err(CryptoError::Parameter("OpenSSL backend not enabled".to_string()))
        }
    }

    fn finalize_sign(&mut self, _key_der: &[u8]) -> Result<Vec<u8>> {
        #[cfg(feature = "backend-openssl")]
        {
            let mut sig_len = 0;
            unsafe {
                if ffi::EVP_DigestSignFinal(self.ctx.as_ptr(), ptr::null_mut(), &mut sig_len) != 1 {
                    return Err(CryptoError::OpenSSL("EVP_DigestSignFinal failed to get length".to_string()));
                }
            }
            let mut sig = vec![0u8; sig_len as usize];
            unsafe {
                if ffi::EVP_DigestSignFinal(self.ctx.as_ptr(), sig.as_mut_ptr(), &mut sig_len) != 1 {
                    return Err(CryptoError::OpenSSL("EVP_DigestSignFinal failed".to_string()));
                }
            }
            sig.truncate(sig_len as usize);
            Ok(sig)
        }
        #[cfg(not(feature = "backend-openssl"))]
        Err(CryptoError::Parameter("OpenSSL backend not enabled".to_string()))
    }

    fn finalize_verify(&mut self, _key_der: &[u8], signature: &[u8]) -> Result<bool> {
        #[cfg(feature = "backend-openssl")]
        {
            unsafe {
                let r = ffi::EVP_DigestVerifyFinal(self.ctx.as_ptr(), signature.as_ptr(), signature.len());
                if r == 1 { Ok(true) }
                else if r == 0 { Ok(false) }
                else { Err(CryptoError::SignatureVerification) }
            }
        }
        #[cfg(not(feature = "backend-openssl"))]
        {
            let _ = (signature, _key_der);
            Err(CryptoError::Parameter("OpenSSL backend not enabled".to_string()))
        }
    }

    fn init_sign(&mut self, key_der: &[u8], passphrase: Option<&str>) -> Result<()> {
        #[cfg(feature = "backend-openssl")]
        {
            let pkey = load_private_key_robust(key_der, passphrase)?;
            unsafe {
                if ffi::EVP_DigestSignInit(self.ctx.as_ptr(), ptr::null_mut(), self.md.as_ptr(), ptr::null_mut(), pkey.as_ptr()) != 1 {
                    return Err(CryptoError::OpenSSL("EVP_DigestSignInit failed".to_string()));
                }
            }
            Ok(())
        }
        #[cfg(not(feature = "backend-openssl"))]
        {
            let _ = (key_der, passphrase);
            Err(CryptoError::Parameter("OpenSSL backend not enabled".to_string()))
        }
    }

    fn init_verify(&mut self, key_der: &[u8]) -> Result<()> {
        #[cfg(feature = "backend-openssl")]
        {
            let pkey = PKey::public_key_from_der(key_der).map_err(|e| CryptoError::PublicKeyLoad(e.to_string()))?;
            unsafe {
                if ffi::EVP_DigestVerifyInit(self.ctx.as_ptr(), ptr::null_mut(), self.md.as_ptr(), ptr::null_mut(), pkey.as_ptr()) != 1 {
                    return Err(CryptoError::OpenSSL("EVP_DigestVerifyInit failed".to_string()));
                }
            }
            Ok(())
        }
        #[cfg(not(feature = "backend-openssl"))]
        {
            let _ = key_der;
            Err(CryptoError::Parameter("OpenSSL backend not enabled".to_string()))
        }
    }
}

pub fn ecc_dh(my_priv_der: &[u8], peer_pub_der: &[u8], passphrase: Option<&str>) -> Result<Vec<u8>> {
    #[cfg(feature = "backend-openssl")]
    {
        let my_priv = load_private_key_robust(my_priv_der, passphrase)?;
        let peer_pub = PKey::public_key_from_der(peer_pub_der).map_err(|e| CryptoError::PublicKeyLoad(e.to_string()))?;
        let mut deriver = Deriver::new(&my_priv).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        deriver.set_peer(&peer_pub).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        deriver.derive_to_vec().map_err(|e| CryptoError::OpenSSL(e.to_string()))
    }
    #[cfg(not(feature = "backend-openssl"))]
    {
        let _ = (my_priv_der, peer_pub_der, passphrase);
        Err(CryptoError::Parameter("OpenSSL backend not enabled".to_string()))
    }
}

pub fn extract_public_key(priv_der: &[u8], passphrase: Option<&str>) -> Result<Vec<u8>> {
    #[cfg(feature = "backend-openssl")]
    {
        let pkey = load_private_key_robust(priv_der, passphrase)?;
        pkey.public_key_to_der().map_err(|e| CryptoError::OpenSSL(e.to_string()))
    }
    #[cfg(not(feature = "backend-openssl"))]
    {
        let _ = (priv_der, passphrase);
        Err(CryptoError::Parameter("OpenSSL backend not enabled".to_string()))
    }
}

pub fn pqc_decap(priv_der: &[u8], kem_ct: &[u8], passphrase: Option<&str>) -> Result<Vec<u8>> {
    #[cfg(feature = "backend-openssl")]
    {
        let pkey = load_private_key_robust(priv_der, passphrase)?;
        
        // PKey -> EVP_PKEY_CTX -> Decapsulate
        unsafe {
            let ctx = ffi::EVP_PKEY_CTX_new(pkey.as_ptr(), ptr::null_mut());
            if ctx.is_null() { return Err(CryptoError::OpenSSL("EVP_PKEY_CTX_new failed".to_string())); }
            
            if ffi::EVP_PKEY_decapsulate_init(ctx, ptr::null_mut()) <= 0 {
                ffi::EVP_PKEY_CTX_free(ctx);
                return Err(CryptoError::OpenSSL("EVP_PKEY_decapsulate_init failed".to_string()));
            }

            let mut ss_len = 0;
            if ffi::EVP_PKEY_decapsulate(ctx, ptr::null_mut(), &mut ss_len, kem_ct.as_ptr(), kem_ct.len()) <= 0 {
                ffi::EVP_PKEY_CTX_free(ctx);
                return Err(CryptoError::OpenSSL("EVP_PKEY_decapsulate (length) failed".to_string()));
            }

            let mut ss = vec![0u8; ss_len as usize];
            if ffi::EVP_PKEY_decapsulate(ctx, ss.as_mut_ptr(), &mut ss_len, kem_ct.as_ptr(), kem_ct.len()) <= 0 {
                ffi::EVP_PKEY_CTX_free(ctx);
                return Err(CryptoError::OpenSSL("EVP_PKEY_decapsulate (execution) failed".to_string()));
            }
            
            ffi::EVP_PKEY_CTX_free(ctx);
            ss.truncate(ss_len as usize);
            Ok(ss)
        }
    }
    #[cfg(not(feature = "backend-openssl"))]
    {
        let _ = (priv_der, kem_ct, passphrase);
        Err(CryptoError::Parameter("OpenSSL backend not enabled".to_string()))
    }
}

pub fn extract_raw_private_key(priv_der: &[u8], passphrase: Option<&str>) -> Result<Vec<u8>> {
    #[cfg(feature = "backend-openssl")]
    {
        let pkey = load_private_key_robust(priv_der, passphrase)?;
        pkey.private_key_to_der().map_err(|e| CryptoError::OpenSSL(e.to_string()))
    }
    #[cfg(not(feature = "backend-openssl"))]
    {
        let _ = (priv_der, passphrase);
        Err(CryptoError::Parameter("OpenSSL backend not enabled".to_string()))
    }
}

pub fn generate_ecc_key_pair(curve_name: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    #[cfg(feature = "backend-openssl")]
    {
        let nid = match curve_name {
            "prime256v1" => Nid::X9_62_PRIME256V1,
            _ => return Err(CryptoError::Parameter(format!("Unsupported curve: {}", curve_name))),
        };
        let group = EcGroup::from_curve_name(nid).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        let ec_key = EcKey::generate(&group).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        let pkey = PKey::from_ec_key(ec_key).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        
        let priv_der = pkey.private_key_to_der().map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        let pub_der = pkey.public_key_to_der().map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        
        Ok((priv_der, pub_der))
    }
    #[cfg(not(feature = "backend-openssl"))]
    {
        let _ = curve_name;
        Err(CryptoError::Parameter("OpenSSL backend not enabled".to_string()))
    }
}
