/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

use crate::backend::{AeadBackend, HashBackend};
use crate::error::{CryptoError, Result};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[cfg(feature = "backend-openssl")]
use foreign_types::ForeignType;
#[cfg(feature = "backend-openssl")]
use openssl::cipher::Cipher;
#[cfg(feature = "backend-openssl")]
use openssl::cipher_ctx::CipherCtx;
#[cfg(feature = "backend-openssl")]
use openssl::derive::Deriver;
#[cfg(feature = "backend-openssl")]
use openssl::ec::{EcGroup, EcKey};
#[cfg(feature = "backend-openssl")]
use openssl::hash::MessageDigest;
#[cfg(feature = "backend-openssl")]
use openssl::md_ctx::MdCtx;
#[cfg(feature = "backend-openssl")]
use openssl::nid::Nid;
#[cfg(feature = "backend-openssl")]
use openssl::pkey::PKey;
#[cfg(feature = "backend-openssl")]
use openssl_sys as ffi;
#[cfg(feature = "backend-openssl")]
use std::ptr;

pub struct OpenSslAead {
    #[cfg(feature = "backend-openssl")]
    ctx: CipherCtx,
    _is_encrypt: bool,
}

impl Zeroize for OpenSslAead {
    fn zeroize(&mut self) {
        // OpenSSL CipherCtx is automatically cleared on drop (EVP_CIPHER_CTX_free).
        // No explicit zeroize method is provided by the openssl crate for CipherCtx.
    }
}

impl ZeroizeOnDrop for OpenSslAead {}

#[cfg(feature = "backend-openssl")]
fn load_private_key_robust(
    der: &[u8],
    passphrase: Option<&str>,
) -> Result<PKey<openssl::pkey::Private>> {
    if let Ok(pkey) = PKey::private_key_from_der(der) {
        return Ok(pkey);
    }
    if let Some(pass) = passphrase {
        let mem = unsafe { ffi::BIO_new_mem_buf(der.as_ptr() as *const _, der.len() as _) };
        if !mem.is_null() {
            let pass_ptr = pass.as_ptr() as *const _;
            unsafe {
                let pkey_ptr =
                    ffi::d2i_PKCS8PrivateKey_bio(mem, ptr::null_mut(), None, pass_ptr as *mut _);
                ffi::BIO_free_all(mem);
                if !pkey_ptr.is_null() {
                    return Ok(PKey::from_ptr(pkey_ptr));
                }
            }
        }
    }
    Err(CryptoError::PrivateKeyLoad(
        "Failed to load or decrypt private key".to_string(),
    ))
}

#[cfg(feature = "backend-openssl")]
mod ffi_ext {
    use libc;
    use openssl_sys as ffi;

    pub const OSSL_PKEY_PARAM_PRIV_KEY: *const libc::c_char = b"priv\0".as_ptr() as *const _;
    pub const OSSL_PKEY_PARAM_PUB_KEY: *const libc::c_char = b"pub\0".as_ptr() as *const _;
    pub const OSSL_PKEY_PARAM_ML_KEM_SEED: *const libc::c_char = b"seed\0".as_ptr() as *const _;

    pub const EVP_PKEY_KEY_PARAMETERS: libc::c_int = 0x0001;
    pub const EVP_PKEY_PUBLIC_KEY: libc::c_int = 0x0002;
    pub const EVP_PKEY_PRIVATE_KEY: libc::c_int = 0x0004;
    pub const EVP_PKEY_KEYPAIR: libc::c_int =
        EVP_PKEY_KEY_PARAMETERS | EVP_PKEY_PUBLIC_KEY | EVP_PKEY_PRIVATE_KEY;

    extern "C" {
        pub fn EVP_PKEY_Q_keygen(
            libctx: *mut ffi::OSSL_LIB_CTX,
            propq: *const libc::c_char,
            name: *const libc::c_char,
            ...
        ) -> *mut ffi::EVP_PKEY;

        pub fn EVP_PKEY_get_octet_string_param(
            pkey: *const ffi::EVP_PKEY,
            key_name: *const libc::c_char,
            buf: *mut libc::c_uchar,
            max_buflen: libc::size_t,
            out_len: *mut libc::size_t,
        ) -> libc::c_int;

        pub fn OSSL_PARAM_BLD_new() -> *mut libc::c_void;
        pub fn OSSL_PARAM_BLD_to_param(bld: *mut libc::c_void) -> *mut ffi::OSSL_PARAM;
        pub fn OSSL_PARAM_BLD_free(bld: *mut libc::c_void);
        pub fn OSSL_PARAM_free(params: *mut ffi::OSSL_PARAM);
        pub fn OSSL_PARAM_BLD_push_octet_string(
            bld: *mut libc::c_void,
            key: *const libc::c_char,
            buf: *const libc::c_void,
            bsize: libc::size_t,
        ) -> libc::c_int;

        pub fn EVP_PKEY_fromdata_init(ctx: *mut ffi::EVP_PKEY_CTX) -> libc::c_int;
        pub fn EVP_PKEY_fromdata(
            ctx: *mut ffi::EVP_PKEY_CTX,
            ppkey: *mut *mut ffi::EVP_PKEY,
            selection: libc::c_int,
            params: *mut ffi::OSSL_PARAM,
        ) -> libc::c_int;
    }
}

#[cfg(feature = "backend-openssl")]
fn pkey_from_raw(
    algo: &str,
    raw: &[u8],
    is_private: bool,
) -> Result<PKey<openssl::pkey::Private>> {
    use ffi_ext::*;
    unsafe {
        let algo_c =
            std::ffi::CString::new(algo).map_err(|e| CryptoError::Parameter(e.to_string()))?;
        let ctx = ffi::EVP_PKEY_CTX_new_from_name(
            std::ptr::null_mut(),
            algo_c.as_ptr(),
            std::ptr::null(),
        );
        if ctx.is_null() {
            return Err(CryptoError::OpenSSL(
                "EVP_PKEY_CTX_new_from_name failed".to_string(),
            ));
        }

        let mut res = Err(CryptoError::OpenSSL("Failed to reconstruct PKey".to_string()));

        if EVP_PKEY_fromdata_init(ctx) == 1 {
            let bld = OSSL_PARAM_BLD_new();
            if !bld.is_null() {
                let key_param = if is_private {
                    OSSL_PKEY_PARAM_PRIV_KEY
                } else {
                    OSSL_PKEY_PARAM_PUB_KEY
                };
                if OSSL_PARAM_BLD_push_octet_string(
                    bld,
                    key_param,
                    raw.as_ptr() as *const _,
                    raw.len(),
                ) == 1
                {
                    let params = OSSL_PARAM_BLD_to_param(bld);
                    if !params.is_null() {
                        let mut pkey_ptr: *mut ffi::EVP_PKEY = std::ptr::null_mut();
                        let selection = if is_private {
                            EVP_PKEY_KEYPAIR
                        } else {
                            EVP_PKEY_PUBLIC_KEY
                        };
                        if EVP_PKEY_fromdata(ctx, &mut pkey_ptr, selection, params) == 1 {
                            res = Ok(PKey::from_ptr(pkey_ptr));
                        }
                        OSSL_PARAM_free(params);
                    }
                }
                OSSL_PARAM_BLD_free(bld);
            }
        }
        ffi::EVP_PKEY_CTX_free(ctx);
        res
    }
}

#[cfg(feature = "backend-openssl")]
fn load_public_key_robust(der: &[u8]) -> Result<PKey<openssl::pkey::Public>> {
    if let Ok(pkey) = PKey::public_key_from_der(der) {
        return Ok(pkey);
    }
    Err(CryptoError::PublicKeyLoad(
        "Failed to load public key".to_string(),
    ))
}

impl AeadBackend for OpenSslAead {
    fn new_encrypt(cipher_name: &str, key: &[u8], iv: &[u8]) -> Result<Self> {
        #[cfg(feature = "backend-openssl")]
        {
            let mut ctx = CipherCtx::new().map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
            let normalized_name = cipher_name.to_lowercase();
            let cipher = match normalized_name.as_str() {
                "aes-256-gcm" => Cipher::aes_256_gcm(),
                "chacha20-poly1305" => Cipher::chacha20_poly1305(),
                _ => {
                    return Err(CryptoError::Parameter(format!(
                        "Unsupported cipher: {}",
                        cipher_name
                    )))
                }
            };
            ctx.encrypt_init(Some(cipher), None, None)
                .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
            ctx.set_iv_length(iv.len())
                .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
            ctx.encrypt_init(None, Some(key), Some(iv))
                .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
            Ok(Self {
                ctx,
                _is_encrypt: true,
            })
        }
        #[cfg(not(feature = "backend-openssl"))]
        {
            let _ = (cipher_name, key, iv);
            Err(CryptoError::Parameter(
                "OpenSSL backend not enabled".to_string(),
            ))
        }
    }

    fn new_decrypt(cipher_name: &str, key: &[u8], iv: &[u8]) -> Result<Self> {
        #[cfg(feature = "backend-openssl")]
        {
            let mut ctx = CipherCtx::new().map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
            let normalized_name = cipher_name.to_lowercase();
            let cipher = match normalized_name.as_str() {
                "aes-256-gcm" => Cipher::aes_256_gcm(),
                "chacha20-poly1305" => Cipher::chacha20_poly1305(),
                _ => {
                    return Err(CryptoError::Parameter(format!(
                        "Unsupported cipher: {}",
                        cipher_name
                    )))
                }
            };
            ctx.decrypt_init(Some(cipher), None, None)
                .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
            ctx.set_iv_length(iv.len())
                .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
            ctx.decrypt_init(None, Some(key), Some(iv))
                .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
            Ok(Self {
                ctx,
                _is_encrypt: false,
            })
        }
        #[cfg(not(feature = "backend-openssl"))]
        {
            let _ = (cipher_name, key, iv);
            Err(CryptoError::Parameter(
                "OpenSSL backend not enabled".to_string(),
            ))
        }
    }

    fn re_init(&mut self, key: &[u8], iv: &[u8]) -> Result<()> {
        #[cfg(feature = "backend-openssl")]
        {
            if self._is_encrypt {
                self.ctx
                    .encrypt_init(None, Some(key), Some(iv))
                    .map_err(|e| CryptoError::OpenSSL(e.to_string()))
            } else {
                self.ctx
                    .decrypt_init(None, Some(key), Some(iv))
                    .map_err(|e| CryptoError::OpenSSL(e.to_string()))
            }
        }
        #[cfg(not(feature = "backend-openssl"))]
        {
            let _ = (key, iv);
            Err(CryptoError::Parameter(
                "OpenSSL backend not enabled".to_string(),
            ))
        }
    }

    fn update(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize> {
        #[cfg(feature = "backend-openssl")]
        return self
            .ctx
            .cipher_update(input, Some(output))
            .map_err(|e| CryptoError::OpenSSL(e.to_string()));
        #[cfg(not(feature = "backend-openssl"))]
        {
            let _ = (input, output);
            Err(CryptoError::Parameter(
                "OpenSSL backend not enabled".to_string(),
            ))
        }
    }

    fn finalize(&mut self, output: &mut [u8]) -> Result<usize> {
        #[cfg(feature = "backend-openssl")]
        return self
            .ctx
            .cipher_final(output)
            .map_err(|e| CryptoError::OpenSSL(e.to_string()));
        #[cfg(not(feature = "backend-openssl"))]
        {
            let _ = output;
            Err(CryptoError::Parameter(
                "OpenSSL backend not enabled".to_string(),
            ))
        }
    }

    fn get_tag(&self, tag: &mut [u8]) -> Result<()> {
        #[cfg(feature = "backend-openssl")]
        return self
            .ctx
            .tag(tag)
            .map_err(|e| CryptoError::OpenSSL(e.to_string()));
        #[cfg(not(feature = "backend-openssl"))]
        {
            let _ = tag;
            Err(CryptoError::Parameter(
                "OpenSSL backend not enabled".to_string(),
            ))
        }
    }

    fn set_tag(&mut self, tag: &[u8]) -> Result<()> {
        #[cfg(feature = "backend-openssl")]
        return self
            .ctx
            .set_tag(tag)
            .map_err(|e| CryptoError::OpenSSL(e.to_string()));
        #[cfg(not(feature = "backend-openssl"))]
        {
            let _ = tag;
            Err(CryptoError::Parameter(
                "OpenSSL backend not enabled".to_string(),
            ))
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
            let md = MessageDigest::from_name(algo).ok_or(CryptoError::Parameter(format!(
                "Unsupported digest: {}",
                algo
            )))?;
            let ctx = MdCtx::new().map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
            Ok(Self { ctx, md })
        }
        #[cfg(not(feature = "backend-openssl"))]
        {
            let _ = algo;
            Err(CryptoError::Parameter(
                "OpenSSL backend not enabled".to_string(),
            ))
        }
    }

    fn update(&mut self, data: &[u8]) -> Result<()> {
        #[cfg(feature = "backend-openssl")]
        return self
            .ctx
            .digest_sign_update(data)
            .map_err(|e| CryptoError::OpenSSL(e.to_string()));
        #[cfg(not(feature = "backend-openssl"))]
        {
            let _ = data;
            Err(CryptoError::Parameter(
                "OpenSSL backend not enabled".to_string(),
            ))
        }
    }

    fn finalize_sign(&mut self, _key_der: &[u8]) -> Result<Vec<u8>> {
        #[cfg(feature = "backend-openssl")]
        {
            let mut sig_len = 0;
            unsafe {
                if ffi::EVP_DigestSignFinal(self.ctx.as_ptr(), ptr::null_mut(), &mut sig_len) != 1 {
                    return Err(CryptoError::OpenSSL(
                        "EVP_DigestSignFinal failed to get length".to_string(),
                    ));
                }
            }
            let mut sig = vec![0u8; sig_len as usize];
            unsafe {
                if ffi::EVP_DigestSignFinal(self.ctx.as_ptr(), sig.as_mut_ptr(), &mut sig_len) != 1
                {
                    return Err(CryptoError::OpenSSL(
                        "EVP_DigestSignFinal failed".to_string(),
                    ));
                }
            }
            sig.truncate(sig_len as usize);
            Ok(sig)
        }
        #[cfg(not(feature = "backend-openssl"))]
        Err(CryptoError::Parameter(
            "OpenSSL backend not enabled".to_string(),
        ))
    }

    fn finalize_verify(&mut self, _key_der: &[u8], signature: &[u8]) -> Result<bool> {
        #[cfg(feature = "backend-openssl")]
        unsafe {
            let r =
                ffi::EVP_DigestVerifyFinal(self.ctx.as_ptr(), signature.as_ptr(), signature.len());
            if r == 1 {
                Ok(true)
            } else if r == 0 {
                Ok(false)
            } else {
                Err(CryptoError::SignatureVerification)
            }
        }
        #[cfg(not(feature = "backend-openssl"))]
        {
            let _ = (signature, _key_der);
            Err(CryptoError::Parameter(
                "OpenSSL backend not enabled".to_string(),
            ))
        }
    }

    fn init_sign(&mut self, key_der: &[u8], passphrase: Option<&str>) -> Result<()> {
        #[cfg(feature = "backend-openssl")]
        {
            let pkey = load_private_key_robust(key_der, passphrase)?;
            unsafe {
                if ffi::EVP_DigestSignInit(
                    self.ctx.as_ptr(),
                    ptr::null_mut(),
                    self.md.as_ptr(),
                    ptr::null_mut(),
                    pkey.as_ptr(),
                ) != 1
                {
                    return Err(CryptoError::OpenSSL(
                        "EVP_DigestSignInit failed".to_string(),
                    ));
                }
            }
            Ok(())
        }
        #[cfg(not(feature = "backend-openssl"))]
        {
            let _ = (key_der, passphrase);
            Err(CryptoError::Parameter(
                "OpenSSL backend not enabled".to_string(),
            ))
        }
    }

    fn init_verify(&mut self, key_der: &[u8]) -> Result<()> {
        #[cfg(feature = "backend-openssl")]
        {
            let pkey = load_public_key_robust(key_der)?;
            unsafe {
                if ffi::EVP_DigestVerifyInit(
                    self.ctx.as_ptr(),
                    ptr::null_mut(),
                    self.md.as_ptr(),
                    ptr::null_mut(),
                    pkey.as_ptr(),
                ) != 1
                {
                    return Err(CryptoError::OpenSSL(
                        "EVP_DigestVerifyInit failed".to_string(),
                    ));
                }
            }
            Ok(())
        }
        #[cfg(not(feature = "backend-openssl"))]
        {
            let _ = key_der;
            Err(CryptoError::Parameter(
                "OpenSSL backend not enabled".to_string(),
            ))
        }
    }
}

pub fn ecc_dh(
    my_priv_der: &[u8],
    peer_pub_der: &[u8],
    passphrase: Option<&str>,
) -> Result<Zeroizing<Vec<u8>>> {
    #[cfg(feature = "backend-openssl")]
    {
        let my_priv = load_private_key_robust(my_priv_der, passphrase)?;
        let peer_pub = load_public_key_robust(peer_pub_der)?;
        let mut deriver =
            Deriver::new(&my_priv).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        deriver
            .set_peer(&peer_pub)
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        deriver
            .derive_to_vec()
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))
            .map(Zeroizing::new)
    }
    #[cfg(not(feature = "backend-openssl"))]
    {
        let _ = (my_priv_der, peer_pub_der, passphrase);
        Err(CryptoError::Parameter(
            "OpenSSL backend not enabled".to_string(),
        ))
    }
}

pub fn extract_public_key(priv_der: &[u8], passphrase: Option<&str>) -> Result<Vec<u8>> {
    #[cfg(feature = "backend-openssl")]
    {
        let pkey = load_private_key_robust(priv_der, passphrase)?;
        pkey.public_key_to_der()
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))
    }
    #[cfg(not(feature = "backend-openssl"))]
    {
        let _ = (priv_der, passphrase);
        Err(CryptoError::Parameter(
            "OpenSSL backend not enabled".to_string(),
        ))
    }
}

pub fn pqc_keygen_kem(
    algo: &str,
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>, Option<Zeroizing<Vec<u8>>>)> {
    #[cfg(feature = "backend-openssl")]
    {
        use ffi_ext::*;
        unsafe {
            let algo_c = std::ffi::CString::new(algo)
                .map_err(|e| CryptoError::Parameter(e.to_string()))?;
            let pkey_ptr =
                EVP_PKEY_Q_keygen(std::ptr::null_mut(), std::ptr::null(), algo_c.as_ptr());
            if pkey_ptr.is_null() {
                return Err(CryptoError::OpenSSL("EVP_PKEY_Q_keygen failed".to_string()));
            }
            let pkey: PKey<openssl::pkey::Private> = PKey::from_ptr(pkey_ptr);

            let mut sk_len: libc::size_t = 0;
            if EVP_PKEY_get_octet_string_param(
                pkey.as_ptr(),
                OSSL_PKEY_PARAM_PRIV_KEY,
                std::ptr::null_mut(),
                0,
                &mut sk_len,
            ) != 1
            {
                return Err(CryptoError::OpenSSL(
                    "Failed to get SK length".to_string(),
                ));
            }
            let mut sk = Zeroizing::new(vec![0u8; sk_len]);
            if EVP_PKEY_get_octet_string_param(
                pkey.as_ptr(),
                OSSL_PKEY_PARAM_PRIV_KEY,
                sk.as_mut_ptr(),
                sk_len,
                &mut sk_len,
            ) != 1
            {
                return Err(CryptoError::OpenSSL("Failed to get SK".to_string()));
            }

            let mut pk_len: libc::size_t = 0;
            if EVP_PKEY_get_octet_string_param(
                pkey.as_ptr(),
                OSSL_PKEY_PARAM_PUB_KEY,
                std::ptr::null_mut(),
                0,
                &mut pk_len,
            ) != 1
            {
                return Err(CryptoError::OpenSSL(
                    "Failed to get PK length".to_string(),
                ));
            }
            let mut pk = vec![0u8; pk_len];
            if EVP_PKEY_get_octet_string_param(
                pkey.as_ptr(),
                OSSL_PKEY_PARAM_PUB_KEY,
                pk.as_mut_ptr(),
                pk_len,
                &mut pk_len,
            ) != 1
            {
                return Err(CryptoError::OpenSSL("Failed to get PK".to_string()));
            }

            let mut seed_len: libc::size_t = 0;
            let mut seed = None;
            if EVP_PKEY_get_octet_string_param(
                pkey.as_ptr(),
                OSSL_PKEY_PARAM_ML_KEM_SEED,
                std::ptr::null_mut(),
                0,
                &mut seed_len,
            ) == 1
            {
                let mut s = Zeroizing::new(vec![0u8; seed_len]);
                if EVP_PKEY_get_octet_string_param(
                    pkey.as_ptr(),
                    OSSL_PKEY_PARAM_ML_KEM_SEED,
                    s.as_mut_ptr(),
                    seed_len,
                    &mut seed_len,
                ) == 1
                {
                    seed = Some(s);
                }
            }

            Ok((sk, pk, seed))
        }
    }
    #[cfg(not(feature = "backend-openssl"))]
    {
        let _ = algo;
        Err(CryptoError::Parameter(
            "OpenSSL backend not enabled".to_string(),
        ))
    }
}

pub fn pqc_keygen_dsa(
    algo: &str,
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>, Option<Zeroizing<Vec<u8>>>)> {
    #[cfg(feature = "backend-openssl")]
    {
        // DSA version of keygen is the same as KEM in OpenSSL 3.5+
        pqc_keygen_kem(algo)
    }
    #[cfg(not(feature = "backend-openssl"))]
    {
        let _ = algo;
        Err(CryptoError::Parameter(
            "OpenSSL backend not enabled".to_string(),
        ))
    }
}

pub fn pqc_sign(
    algo: &str,
    raw_priv: &[u8],
    message: &[u8],
    passphrase: Option<&str>,
) -> Result<Vec<u8>> {
    #[cfg(feature = "backend-openssl")]
    {
        let _ = passphrase;
        let pkey = pkey_from_raw(algo, raw_priv, true)?;
        let ctx = MdCtx::new().map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        // PQC DSA in OpenSSL uses DigestSign with NULL digest
        unsafe {
            if ffi::EVP_DigestSignInit(
                ctx.as_ptr(),
                ptr::null_mut(),
                ptr::null(),
                ptr::null_mut(),
                pkey.as_ptr(),
            ) != 1
            {
                return Err(CryptoError::OpenSSL(
                    "EVP_DigestSignInit failed".to_string(),
                ));
            }
        }
        let mut sig_len = 0;
        unsafe {
            if ffi::EVP_DigestSign(
                ctx.as_ptr(),
                ptr::null_mut(),
                &mut sig_len,
                message.as_ptr(),
                message.len(),
            ) != 1
            {
                return Err(CryptoError::OpenSSL(
                    "EVP_DigestSign (length) failed".to_string(),
                ));
            }
        }
        let mut sig = vec![0u8; sig_len as usize];
        unsafe {
            if ffi::EVP_DigestSign(
                ctx.as_ptr(),
                sig.as_mut_ptr(),
                &mut sig_len,
                message.as_ptr(),
                message.len(),
            ) != 1
            {
                return Err(CryptoError::OpenSSL("EVP_DigestSign failed".to_string()));
            }
        }
        sig.truncate(sig_len as usize);
        Ok(sig)
    }
    #[cfg(not(feature = "backend-openssl"))]
    {
        let _ = (raw_priv, message, passphrase, algo);
        Err(CryptoError::Parameter(
            "OpenSSL backend not enabled".to_string(),
        ))
    }
}

pub fn pqc_verify(
    algo: &str,
    raw_pub: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool> {
    #[cfg(feature = "backend-openssl")]
    {
        let pkey = pkey_from_raw(algo, raw_pub, false)?;
        let ctx = MdCtx::new().map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        unsafe {
            if ffi::EVP_DigestVerifyInit(
                ctx.as_ptr(),
                ptr::null_mut(),
                ptr::null(),
                ptr::null_mut(),
                pkey.as_ptr(),
            ) != 1
            {
                return Err(CryptoError::OpenSSL(
                    "EVP_DigestVerifyInit failed".to_string(),
                ));
            }
            let r = ffi::EVP_DigestVerify(
                ctx.as_ptr(),
                signature.as_ptr(),
                signature.len(),
                message.as_ptr(),
                message.len(),
            );
            if r == 1 {
                Ok(true)
            } else if r == 0 {
                Ok(false)
            } else {
                Err(CryptoError::SignatureVerification)
            }
        }
    }
    #[cfg(not(feature = "backend-openssl"))]
    {
        let _ = (raw_pub, message, signature, algo);
        Err(CryptoError::Parameter(
            "OpenSSL backend not enabled".to_string(),
        ))
    }
}

pub fn pqc_encap(algo: &str, peer_pub_raw: &[u8]) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
    #[cfg(feature = "backend-openssl")]
    {
        let pkey = pkey_from_raw(algo, peer_pub_raw, false)?;
        unsafe {
            let ctx = ffi::EVP_PKEY_CTX_new(pkey.as_ptr(), ptr::null_mut());
            if ctx.is_null() {
                return Err(CryptoError::OpenSSL("EVP_PKEY_CTX_new failed".to_string()));
            }
            if ffi::EVP_PKEY_encapsulate_init(ctx, ptr::null_mut()) <= 0 {
                ffi::EVP_PKEY_CTX_free(ctx);
                return Err(CryptoError::OpenSSL(
                    "EVP_PKEY_encapsulate_init failed".to_string(),
                ));
            }
            let mut ss_len = 0;
            let mut ct_len = 0;
            if ffi::EVP_PKEY_encapsulate(
                ctx,
                ptr::null_mut(),
                &mut ct_len,
                ptr::null_mut(),
                &mut ss_len,
            ) <= 0
            {
                ffi::EVP_PKEY_CTX_free(ctx);
                return Err(CryptoError::OpenSSL(
                    "EVP_PKEY_encapsulate (length) failed".to_string(),
                ));
            }
            let mut ss = Zeroizing::new(vec![0u8; ss_len as usize]);
            let mut ct = vec![0u8; ct_len as usize];
            if ffi::EVP_PKEY_encapsulate(
                ctx,
                ct.as_mut_ptr(),
                &mut ct_len,
                ss.as_mut_ptr(),
                &mut ss_len,
            ) <= 0
            {
                ffi::EVP_PKEY_CTX_free(ctx);
                return Err(CryptoError::OpenSSL(
                    "EVP_PKEY_encapsulate (execution) failed".to_string(),
                ));
            }
            ffi::EVP_PKEY_CTX_free(ctx);
            ss.truncate(ss_len as usize);
            ct.truncate(ct_len as usize);
            Ok((ss, ct))
        }
    }
    #[cfg(not(feature = "backend-openssl"))]
    {
        let _ = (peer_pub_raw, algo);
        Err(CryptoError::Parameter(
            "OpenSSL backend not enabled".to_string(),
        ))
    }
}

pub fn pqc_decap(
    algo: &str,
    raw_priv: &[u8],
    kem_ct: &[u8],
    _passphrase: Option<&str>,
) -> Result<Zeroizing<Vec<u8>>> {
    #[cfg(feature = "backend-openssl")]
    {
        let pkey = pkey_from_raw(algo, raw_priv, true)?;
        unsafe {
            let ctx = ffi::EVP_PKEY_CTX_new(pkey.as_ptr(), ptr::null_mut());
            if ctx.is_null() {
                return Err(CryptoError::OpenSSL("EVP_PKEY_CTX_new failed".to_string()));
            }
            if ffi::EVP_PKEY_decapsulate_init(ctx, ptr::null_mut()) <= 0 {
                ffi::EVP_PKEY_CTX_free(ctx);
                return Err(CryptoError::OpenSSL(
                    "EVP_PKEY_decapsulate_init failed".to_string(),
                ));
            }
            let mut ss_len = 0;
            if ffi::EVP_PKEY_decapsulate(
                ctx,
                ptr::null_mut(),
                &mut ss_len,
                kem_ct.as_ptr(),
                kem_ct.len(),
            ) <= 0
            {
                ffi::EVP_PKEY_CTX_free(ctx);
                return Err(CryptoError::OpenSSL(
                    "EVP_PKEY_decapsulate (length) failed".to_string(),
                ));
            }
            let mut ss = Zeroizing::new(vec![0u8; ss_len as usize]);
            if ffi::EVP_PKEY_decapsulate(
                ctx,
                ss.as_mut_ptr(),
                &mut ss_len,
                kem_ct.as_ptr(),
                kem_ct.len(),
            ) <= 0
            {
                ffi::EVP_PKEY_CTX_free(ctx);
                return Err(CryptoError::OpenSSL(
                    "EVP_PKEY_decapsulate (execution) failed".to_string(),
                ));
            }
            ffi::EVP_PKEY_CTX_free(ctx);
            ss.truncate(ss_len as usize);
            Ok(ss)
        }
    }
    #[cfg(not(feature = "backend-openssl"))]
    {
        let _ = (raw_priv, kem_ct, _passphrase, algo);
        Err(CryptoError::Parameter(
            "OpenSSL backend not enabled".to_string(),
        ))
    }
}

pub fn extract_raw_private_key(
    priv_der: &[u8],
    passphrase: Option<&str>,
) -> Result<Zeroizing<Vec<u8>>> {
    #[cfg(feature = "backend-openssl")]
    {
        use pkcs8::der::Decode;
        if let Some(pass) = passphrase {
            if let Ok(pki) = pkcs8::EncryptedPrivateKeyInfo::from_der(priv_der) {
                let decrypted = pki
                    .decrypt(pass)
                    .map_err(|e| CryptoError::PrivateKeyLoad(format!("Decryption failed: {}", e)))?;
                return Ok(Zeroizing::new(decrypted.as_bytes().to_vec()));
            }
        }

        // If not encrypted or decryption failed (and we want to try loading as is), return original
        Ok(Zeroizing::new(priv_der.to_vec()))
    }
    #[cfg(not(feature = "backend-openssl"))]
    {
        let _ = (priv_der, passphrase);
        Err(CryptoError::Parameter(
            "OpenSSL backend not enabled".to_string(),
        ))
    }
}

pub fn hkdf(
    ikm: &[u8],
    length: usize,
    salt: &[u8],
    info: &str,
    md_name: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    #[cfg(feature = "backend-openssl")]
    {
        use hkdf::Hkdf;
        use sha3::{Sha3_256, Sha3_512};

        let mut okm = Zeroizing::new(vec![0u8; length]);
        if md_name.contains("256") {
            let h = Hkdf::<Sha3_256>::new(Some(salt), ikm);
            h.expand(info.as_bytes(), &mut *okm)
                .map_err(|_| CryptoError::Parameter("HKDF expand failed".to_string()))?;
            drop(h);
        } else {
            let h = Hkdf::<Sha3_512>::new(Some(salt), ikm);
            h.expand(info.as_bytes(), &mut *okm)
                .map_err(|_| CryptoError::Parameter("HKDF expand failed".to_string()))?;
            drop(h);
        }
        Ok(okm)
    }
    #[cfg(not(feature = "backend-openssl"))]
    {
        let _ = (ikm, length, salt, info, md_name);
        Err(CryptoError::Parameter(
            "OpenSSL backend not enabled".to_string(),
        ))
    }
}

pub fn generate_ecc_key_pair(curve_name: &str) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
    #[cfg(feature = "backend-openssl")]
    {
        let nid = match curve_name {
            "prime256v1" => Nid::X9_62_PRIME256V1,
            _ => {
                return Err(CryptoError::Parameter(format!(
                    "Unsupported curve: {}",
                    curve_name
                )))
            }
        };
        let group =
            EcGroup::from_curve_name(nid).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        let ec_key = EcKey::generate(&group).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        let pkey = PKey::from_ec_key(ec_key).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        let priv_der = pkey
            .private_key_to_der()
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        let pub_der = pkey
            .public_key_to_der()
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        Ok((Zeroizing::new(priv_der), pub_der))
    }
    #[cfg(not(feature = "backend-openssl"))]
    {
        let _ = curve_name;
        Err(CryptoError::Parameter(
            "OpenSSL backend not enabled".to_string(),
        ))
    }
}
