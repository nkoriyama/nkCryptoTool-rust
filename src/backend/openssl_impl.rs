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

#[cfg(feature = "backend-openssl")]
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

#[cfg(feature = "backend-openssl")]
fn load_private_key_robust(der: &[u8], passphrase: Option<&str>) -> Result<PKey<openssl::pkey::Private>> {
    if let Ok(pkey) = PKey::private_key_from_der(der) { return Ok(pkey); }
    if let Some(pass) = passphrase {
        let mem = unsafe { ffi::BIO_new_mem_buf(der.as_ptr() as *const _, der.len() as _) };
        if !mem.is_null() {
            let pass_ptr = pass.as_ptr() as *const _;
            unsafe {
                let pkey_ptr = ffi::d2i_PKCS8PrivateKey_bio(mem, ptr::null_mut(), None, pass_ptr as *mut _);
                ffi::BIO_free_all(mem);
                if !pkey_ptr.is_null() { return Ok(PKey::from_ptr(pkey_ptr)); }
            }
        }
    }
    // Fallback: extract raw and try (though OpenSSL might need more context for PQC)
    let raw = unwrap_pqc_der_internal(der, false);
    if raw.len() != der.len() {
        if let Ok(pkey) = PKey::private_key_from_der(&raw) { return Ok(pkey); }
    }
    Err(CryptoError::PrivateKeyLoad("Failed to load or decrypt private key".to_string()))
}

#[cfg(feature = "backend-openssl")]
fn load_public_key_robust(der: &[u8]) -> Result<PKey<openssl::pkey::Public>> {
    if let Ok(pkey) = PKey::public_key_from_der(der) { return Ok(pkey); }
    let raw = unwrap_pqc_der_internal(der, true);
    if let Ok(pkey) = PKey::public_key_from_der(&raw) { return Ok(pkey); }
    Err(CryptoError::PublicKeyLoad("Failed to load public key".to_string()))
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
        return self.ctx.cipher_update(input, Some(output)).map_err(|e| CryptoError::OpenSSL(e.to_string()));
        #[cfg(not(feature = "backend-openssl"))]
        { let _ = (input, output); Err(CryptoError::Parameter("OpenSSL backend not enabled".to_string())) }
    }

    fn finalize(&mut self, output: &mut [u8]) -> Result<usize> {
        #[cfg(feature = "backend-openssl")]
        return self.ctx.cipher_final(output).map_err(|e| CryptoError::OpenSSL(e.to_string()));
        #[cfg(not(feature = "backend-openssl"))]
        { let _ = output; Err(CryptoError::Parameter("OpenSSL backend not enabled".to_string())) }
    }

    fn get_tag(&self, tag: &mut [u8]) -> Result<()> {
        #[cfg(feature = "backend-openssl")]
        return self.ctx.tag(tag).map_err(|e| CryptoError::OpenSSL(e.to_string()));
        #[cfg(not(feature = "backend-openssl"))]
        { let _ = tag; Err(CryptoError::Parameter("OpenSSL backend not enabled".to_string())) }
    }

    fn set_tag(&mut self, tag: &[u8]) -> Result<()> {
        #[cfg(feature = "backend-openssl")]
        return self.ctx.set_tag(tag).map_err(|e| CryptoError::OpenSSL(e.to_string()));
        #[cfg(not(feature = "backend-openssl"))]
        { let _ = tag; Err(CryptoError::Parameter("OpenSSL backend not enabled".to_string())) }
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
        { let _ = algo; Err(CryptoError::Parameter("OpenSSL backend not enabled".to_string())) }
    }

    fn update(&mut self, data: &[u8]) -> Result<()> {
        #[cfg(feature = "backend-openssl")]
        return self.ctx.digest_sign_update(data).map_err(|e| CryptoError::OpenSSL(e.to_string()));
        #[cfg(not(feature = "backend-openssl"))]
        { let _ = data; Err(CryptoError::Parameter("OpenSSL backend not enabled".to_string())) }
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
        unsafe {
            let r = ffi::EVP_DigestVerifyFinal(self.ctx.as_ptr(), signature.as_ptr(), signature.len());
            if r == 1 { Ok(true) }
            else if r == 0 { Ok(false) }
            else { Err(CryptoError::SignatureVerification) }
        }
        #[cfg(not(feature = "backend-openssl"))]
        { let _ = (signature, _key_der); Err(CryptoError::Parameter("OpenSSL backend not enabled".to_string())) }
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
        { let _ = (key_der, passphrase); Err(CryptoError::Parameter("OpenSSL backend not enabled".to_string())) }
    }

    fn init_verify(&mut self, key_der: &[u8]) -> Result<()> {
        #[cfg(feature = "backend-openssl")]
        {
            let pkey = load_public_key_robust(key_der)?;
            unsafe {
                if ffi::EVP_DigestVerifyInit(self.ctx.as_ptr(), ptr::null_mut(), self.md.as_ptr(), ptr::null_mut(), pkey.as_ptr()) != 1 {
                    return Err(CryptoError::OpenSSL("EVP_DigestVerifyInit failed".to_string()));
                }
            }
            Ok(())
        }
        #[cfg(not(feature = "backend-openssl"))]
        { let _ = key_der; Err(CryptoError::Parameter("OpenSSL backend not enabled".to_string())) }
    }
}

pub fn ecc_dh(my_priv_der: &[u8], peer_pub_der: &[u8], passphrase: Option<&str>) -> Result<Vec<u8>> {
    #[cfg(feature = "backend-openssl")]
    {
        let my_priv = load_private_key_robust(my_priv_der, passphrase)?;
        let peer_pub = load_public_key_robust(peer_pub_der)?;
        let mut deriver = Deriver::new(&my_priv).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        deriver.set_peer(&peer_pub).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        deriver.derive_to_vec().map_err(|e| CryptoError::OpenSSL(e.to_string()))
    }
    #[cfg(not(feature = "backend-openssl"))]
    { let _ = (my_priv_der, peer_pub_der, passphrase); Err(CryptoError::Parameter("OpenSSL backend not enabled".to_string())) }
}

pub fn extract_public_key(priv_der: &[u8], passphrase: Option<&str>) -> Result<Vec<u8>> {
    #[cfg(feature = "backend-openssl")]
    {
        let pkey = load_private_key_robust(priv_der, passphrase)?;
        pkey.public_key_to_der().map_err(|e| CryptoError::OpenSSL(e.to_string()))
    }
    #[cfg(not(feature = "backend-openssl"))]
    { let _ = (priv_der, passphrase); Err(CryptoError::Parameter("OpenSSL backend not enabled".to_string())) }
}

pub fn pqc_keygen_kem(_algo: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    Err(CryptoError::Parameter("PQC keygen not supported in this OpenSSL version".to_string()))
}

pub fn pqc_keygen_dsa(_algo: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    Err(CryptoError::Parameter("PQC keygen not supported in this OpenSSL version".to_string()))
}

pub fn pqc_sign(_algo: &str, priv_der: &[u8], message: &[u8], passphrase: Option<&str>) -> Result<Vec<u8>> {
    #[cfg(feature = "backend-openssl")]
    {
        let pkey = load_private_key_robust(priv_der, passphrase)?;
        let ctx = MdCtx::new().map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        // PQC DSA in OpenSSL uses DigestSign with NULL digest
        unsafe {
            if ffi::EVP_DigestSignInit(ctx.as_ptr(), ptr::null_mut(), ptr::null(), ptr::null_mut(), pkey.as_ptr()) != 1 {
                return Err(CryptoError::OpenSSL("EVP_DigestSignInit failed".to_string()));
            }
        }
        let mut sig_len = 0;
        unsafe {
            if ffi::EVP_DigestSign(ctx.as_ptr(), ptr::null_mut(), &mut sig_len, message.as_ptr(), message.len()) != 1 {
                return Err(CryptoError::OpenSSL("EVP_DigestSign (length) failed".to_string()));
            }
        }
        let mut sig = vec![0u8; sig_len as usize];
        unsafe {
            if ffi::EVP_DigestSign(ctx.as_ptr(), sig.as_mut_ptr(), &mut sig_len, message.as_ptr(), message.len()) != 1 {
                return Err(CryptoError::OpenSSL("EVP_DigestSign failed".to_string()));
            }
        }
        sig.truncate(sig_len as usize);
        Ok(sig)
    }
    #[cfg(not(feature = "backend-openssl"))]
    { let _ = (priv_der, message, passphrase, _algo); Err(CryptoError::Parameter("OpenSSL backend not enabled".to_string())) }
}

pub fn pqc_verify(_algo: &str, pub_der: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
    #[cfg(feature = "backend-openssl")]
    {
        let pkey = load_public_key_robust(pub_der)?;
        let ctx = MdCtx::new().map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        unsafe {
            if ffi::EVP_DigestVerifyInit(ctx.as_ptr(), ptr::null_mut(), ptr::null(), ptr::null_mut(), pkey.as_ptr()) != 1 {
                return Err(CryptoError::OpenSSL("EVP_DigestVerifyInit failed".to_string()));
            }
            let r = ffi::EVP_DigestVerify(ctx.as_ptr(), signature.as_ptr(), signature.len(), message.as_ptr(), message.len());
            if r == 1 { Ok(true) }
            else if r == 0 { Ok(false) }
            else { Err(CryptoError::SignatureVerification) }
        }
    }
    #[cfg(not(feature = "backend-openssl"))]
    { let _ = (pub_der, message, signature, _algo); Err(CryptoError::Parameter("OpenSSL backend not enabled".to_string())) }
}

pub fn pqc_encap(_algo: &str, peer_pub_der: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    #[cfg(feature = "backend-openssl")]
    {
        let pkey = load_public_key_robust(peer_pub_der)?;
        unsafe {
            let ctx = ffi::EVP_PKEY_CTX_new(pkey.as_ptr(), ptr::null_mut());
            if ctx.is_null() { return Err(CryptoError::OpenSSL("EVP_PKEY_CTX_new failed".to_string())); }
            if ffi::EVP_PKEY_encapsulate_init(ctx, ptr::null_mut()) <= 0 {
                ffi::EVP_PKEY_CTX_free(ctx);
                return Err(CryptoError::OpenSSL("EVP_PKEY_encapsulate_init failed".to_string()));
            }
            let mut ss_len = 0;
            let mut ct_len = 0;
            if ffi::EVP_PKEY_encapsulate(ctx, ptr::null_mut(), &mut ct_len, ptr::null_mut(), &mut ss_len) <= 0 {
                ffi::EVP_PKEY_CTX_free(ctx);
                return Err(CryptoError::OpenSSL("EVP_PKEY_encapsulate (length) failed".to_string()));
            }
            let mut ss = vec![0u8; ss_len as usize];
            let mut ct = vec![0u8; ct_len as usize];
            if ffi::EVP_PKEY_encapsulate(ctx, ct.as_mut_ptr(), &mut ct_len, ss.as_mut_ptr(), &mut ss_len) <= 0 {
                ffi::EVP_PKEY_CTX_free(ctx);
                return Err(CryptoError::OpenSSL("EVP_PKEY_encapsulate (execution) failed".to_string()));
            }
            ffi::EVP_PKEY_CTX_free(ctx);
            ss.truncate(ss_len as usize);
            ct.truncate(ct_len as usize);
            Ok((ss, ct))
        }
    }
    #[cfg(not(feature = "backend-openssl"))]
    { let _ = (peer_pub_der, _algo); Err(CryptoError::Parameter("OpenSSL backend not enabled".to_string())) }
}

pub fn pqc_decap(_algo: &str, priv_der: &[u8], kem_ct: &[u8], passphrase: Option<&str>) -> Result<Vec<u8>> {
    #[cfg(feature = "backend-openssl")]
    {
        let pkey = load_private_key_robust(priv_der, passphrase)?;
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
    { let _ = (priv_der, kem_ct, passphrase, _algo); Err(CryptoError::Parameter("OpenSSL backend not enabled".to_string())) }
}

pub fn extract_raw_private_key(priv_der: &[u8], passphrase: Option<&str>) -> Result<Vec<u8>> {
    #[cfg(feature = "backend-openssl")]
    {
        let pkey = load_private_key_robust(priv_der, passphrase)?;
        pkey.private_key_to_der().map_err(|e| CryptoError::OpenSSL(e.to_string()))
    }
    #[cfg(not(feature = "backend-openssl"))]
    { let _ = (priv_der, passphrase); Err(CryptoError::Parameter("OpenSSL backend not enabled".to_string())) }
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
    { let _ = curve_name; Err(CryptoError::Parameter("OpenSSL backend not enabled".to_string())) }
}
