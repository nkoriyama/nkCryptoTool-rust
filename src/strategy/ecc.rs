/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

use crate::error::{CryptoError, Result};
use crate::key::SharedKeyProvider;
use crate::strategy::{CryptoStrategy, StrategyType};
use crate::backend::{self, AeadBackend, HashBackend};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use hkdf::Hkdf;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EccStrategy {
    #[zeroize(skip)]
    key_provider: Option<SharedKeyProvider>,
    #[zeroize(skip)]
    curve_name: String,
    #[zeroize(skip)]
    digest_algo: String,
    #[zeroize(skip)]
    aead_algo: String,
    
    // Abstract context for streaming
    #[zeroize(skip)]
    aead_ctx: Option<backend::Aead>,
    #[zeroize(skip)]
    hash_ctx: Option<backend::Hash>,
    
    // Key states
    encryption_key: Zeroizing<Vec<u8>>,
    iv: Vec<u8>,
    salt: Vec<u8>,
    shared_secret: Zeroizing<Vec<u8>>,
    ephemeral_pubkey: Vec<u8>,
    
    // Signing keys (stored as DER to be backend-agnostic)
    sign_key_der: Option<Zeroizing<Vec<u8>>>,
    verify_key_der: Option<Zeroizing<Vec<u8>>>,
}

impl EccStrategy {
    pub fn new() -> Self {
        Self {
            key_provider: None,
            curve_name: "prime256v1".to_string(),
            digest_algo: "SHA3-512".to_string(),
            aead_algo: "AES-256-GCM".to_string(),
            aead_ctx: None,
            hash_ctx: None,
            encryption_key: Zeroizing::new(Vec::new()),
            iv: Vec::new(),
            salt: Vec::new(),
            shared_secret: Zeroizing::new(Vec::new()),
            ephemeral_pubkey: Vec::new(),
            sign_key_der: None,
            verify_key_der: None,
        }
    }

    fn hkdf_derive(&self, secret: &[u8], out_len: usize, salt: &[u8], info: &str) -> Result<Zeroizing<Vec<u8>>> {
        let mut okm = Zeroizing::new(vec![0u8; out_len]);
        use sha3::Sha3_256;
        let hk = Hkdf::<Sha3_256>::new(Some(salt), secret);
        hk.expand(info.as_bytes(), &mut *okm).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        drop(hk); // #15 Fix: Explicitly drop Hkdf object to minimize PRK lifetime
        Ok(okm)
    }
    pub fn take_shared_secret(&mut self) -> Zeroizing<Vec<u8>> {
        std::mem::take(&mut self.shared_secret)
    }

    pub fn prepare_shared_secret_encryption(&mut self, key_paths: &HashMap<String, String>) -> Result<()> {
        if let Some(algo) = key_paths.get("digest-algo") {
            self.digest_algo = algo.clone();
        }
        if let Some(algo) = key_paths.get("aead-algo") {
            self.aead_algo = algo.clone();
        }

        let pubkey_path = key_paths.get("recipient-pubkey")
            .or_else(|| key_paths.get("recipient-ecdh-pubkey"))
            .ok_or(CryptoError::PublicKeyLoad("Missing recipient public key".to_string()))?;

        let pubkey_pem = fs::read_to_string(pubkey_path)?;
        let recipient_pub_der = crate::utils::unwrap_from_pem(&pubkey_pem, "PUBLIC KEY")?;

        let (ephem_priv, ephem_pub) = backend::generate_ecc_key_pair(&self.curve_name)?;
        self.shared_secret = backend::ecc_dh(&ephem_priv, &recipient_pub_der, None)?;
        self.ephemeral_pubkey = ephem_pub;

        self.salt = vec![0u8; 16];
        self.iv = vec![0u8; 12];
        
        #[cfg(feature = "backend-openssl")]
        openssl::rand::rand_bytes(&mut self.salt).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        #[cfg(feature = "backend-openssl")]
        openssl::rand::rand_bytes(&mut self.iv).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        
        #[cfg(feature = "backend-rustcrypto")]
        {
            use rand_core::{RngCore, OsRng};
            OsRng.fill_bytes(&mut self.salt);
            OsRng.fill_bytes(&mut self.iv);
        }
        Ok(())
    }

    pub fn prepare_shared_secret_decryption(&mut self, key_paths: &HashMap<String, String>, passphrase: &mut Option<Zeroizing<String>>) -> Result<()> {
        let privkey_path = key_paths.get("user-privkey")
            .or_else(|| key_paths.get("recipient-ecdh-privkey"))
            .ok_or(CryptoError::PrivateKeyLoad("Missing private key path".to_string()))?;

        let priv_bytes = Zeroizing::new(fs::read(privkey_path)?);
        let pem_str = Zeroizing::new(
            std::str::from_utf8(&*priv_bytes)
                .map_err(|_| CryptoError::Parameter("Invalid UTF-8 in key".to_string()))?
                .to_string()
        );

        let priv_key_der = if pem_str.contains("-----BEGIN TPM WRAPPED BLOB-----") {
            let provider = self.key_provider.as_ref().ok_or(CryptoError::ProviderNotAvailable)?;
            provider.unwrap_raw(&pem_str, passphrase.as_deref().map(|x| x.as_str()))?
        } else {
            let pass = crate::utils::get_passphrase_if_needed(&pem_str, passphrase.as_deref().map(|x| x.as_str()))?;
            if let Some(p) = pass {
                *passphrase = Some(p);
            }
            crate::utils::unwrap_from_pem(&pem_str, "PRIVATE KEY")?
        };

        self.shared_secret = backend::ecc_dh(&priv_key_der, &self.ephemeral_pubkey, passphrase.as_deref().map(|x| x.as_str()))?;
        Ok(())
    }
}

impl CryptoStrategy for EccStrategy {
    fn get_strategy_type(&self) -> StrategyType {
        StrategyType::ECC
    }

    fn set_key_provider(&mut self, provider: SharedKeyProvider) {
        self.key_provider = Some(provider);
    }

    fn generate_encryption_key_pair(&self, key_paths: &HashMap<String, String>, passphrase: Option<&str>) -> Result<()> {
        let pub_path = key_paths.get("public-key")
            .or_else(|| key_paths.get("signing-public-key"))
            .ok_or(CryptoError::Parameter("Missing public key path".to_string()))?;
        let priv_path = key_paths.get("private-key")
            .or_else(|| key_paths.get("signing-private-key"))
            .ok_or(CryptoError::Parameter("Missing private key path".to_string()))?;

        let use_tpm = key_paths.get("use-tpm").map(|s| s == "true").unwrap_or(false);

        let (priv_der, pub_der) = backend::generate_ecc_key_pair(&self.curve_name)?;

        if use_tpm {
            let provider = self.key_provider.as_ref().ok_or(CryptoError::ProviderNotAvailable)?;
            let wrapped = provider.wrap_raw(&priv_der, passphrase)?;
            fs::write(priv_path, wrapped)?;
        } else {
            let priv_pem = crate::utils::wrap_to_pem_zeroizing(&priv_der, "PRIVATE KEY");
            fs::write(priv_path, priv_pem.as_bytes())?;
        }

        let pub_pem = crate::utils::wrap_to_pem_zeroizing(&pub_der, "PUBLIC KEY");
        fs::write(pub_path, pub_pem.as_bytes())?;
        Ok(())
    }

    fn generate_signing_key_pair(&self, key_paths: &HashMap<String, String>, passphrase: Option<&str>) -> Result<()> {
        self.generate_encryption_key_pair(key_paths, passphrase)
    }

    fn regenerate_public_key(&self, priv_path: &Path, pub_path: &Path, passphrase: &mut Option<Zeroizing<String>>) -> Result<()> {
        let priv_bytes = Zeroizing::new(fs::read(priv_path)?);
        let pem_str = Zeroizing::new(
            std::str::from_utf8(&*priv_bytes)
                .map_err(|_| CryptoError::Parameter("Invalid UTF-8 in key".to_string()))?
                .to_string()
        );
        
        let priv_key_der = if pem_str.contains("-----BEGIN TPM WRAPPED BLOB-----") {
            let provider = self.key_provider.as_ref().ok_or(CryptoError::ProviderNotAvailable)?;
            provider.unwrap_raw(&pem_str, passphrase.as_deref().map(|x| x.as_str()))?
        } else {
            let pass = crate::utils::get_passphrase_if_needed(&pem_str, passphrase.as_deref().map(|x| x.as_str()))?;
            if let Some(p) = pass {
                *passphrase = Some(p);
            }
            crate::utils::unwrap_from_pem(&pem_str, "PRIVATE KEY")?
        };

        let pub_der = backend::extract_public_key(&priv_key_der, passphrase.as_deref().map(|x| x.as_str()))?;
        fs::write(pub_path, crate::utils::wrap_to_pem(&pub_der, "PUBLIC KEY"))?;
        Ok(())
    }

    fn prepare_encryption(&mut self, key_paths: &HashMap<String, String>) -> Result<()> {
        self.prepare_shared_secret_encryption(key_paths)?;

        self.encryption_key = self.hkdf_derive(
            &self.shared_secret, 
            32, 
            &self.salt, 
            "ecc-encryption"
        )?;

        let ctx = backend::new_encrypt(&self.aead_algo, &self.encryption_key, &self.iv)?;
        self.aead_ctx = Some(ctx);

        Ok(())
    }

    fn prepare_decryption(&mut self, key_paths: &HashMap<String, String>, passphrase: &mut Option<Zeroizing<String>>) -> Result<()> {
        self.prepare_shared_secret_decryption(key_paths, passphrase)?;

        self.encryption_key = self.hkdf_derive(
            &self.shared_secret, 
            32, 
            &self.salt, 
            "ecc-encryption"
        )?;

        let ctx = backend::new_decrypt(&self.aead_algo, &self.encryption_key, &self.iv)?;
        self.aead_ctx = Some(ctx);

        Ok(())
    }

    fn encrypt_transform(&mut self, data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let ctx = self.aead_ctx.as_mut().ok_or(CryptoError::Parameter("AEAD context not initialized".to_string()))?;
        let mut out = Zeroizing::new(vec![0u8; data.len()]);
        let n = ctx.update(data, &mut out)?;
        out.truncate(n);
        Ok(out)
    }

    fn decrypt_transform(&mut self, data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let ctx = self.aead_ctx.as_mut().ok_or(CryptoError::Parameter("AEAD context not initialized".to_string()))?;
        let mut out = Zeroizing::new(vec![0u8; data.len()]);
        let n = ctx.update(data, &mut out)?;
        out.truncate(n);
        Ok(out)
    }

    fn finalize_encryption(&mut self) -> Result<Vec<u8>> {
        let ctx = self.aead_ctx.as_mut().ok_or(CryptoError::Parameter("AEAD context not initialized".to_string()))?;
        let mut out = vec![0u8; 16];
        let n = ctx.finalize(&mut out)?;
        out.truncate(n);
        
        let mut tag = vec![0u8; 16];
        ctx.get_tag(&mut tag)?;
        out.extend_from_slice(&tag);
        
        Ok(out)
    }

    fn finalize_decryption(&mut self, tag: &[u8]) -> Result<()> {
        let ctx = self.aead_ctx.as_mut().ok_or(CryptoError::Parameter("AEAD context not initialized".to_string()))?;
        ctx.set_tag(tag)?;
        let mut out = vec![0u8; 16];
        ctx.finalize(&mut out).map_err(|_| CryptoError::SignatureVerification)?;
        Ok(())
    }

    fn prepare_signing(&mut self, priv_key_path: &Path, passphrase: &mut Option<Zeroizing<String>>, digest_algo: &str) -> Result<()> {
        let priv_bytes = Zeroizing::new(fs::read(priv_key_path)?);
        let pem_str = Zeroizing::new(
            std::str::from_utf8(&*priv_bytes)
                .map_err(|_| CryptoError::Parameter("Invalid UTF-8 in key".to_string()))?
                .to_string()
        );

        let priv_key_der = if pem_str.contains("-----BEGIN TPM WRAPPED BLOB-----") {
            let provider = self.key_provider.as_ref().ok_or(CryptoError::ProviderNotAvailable)?;
            provider.unwrap_raw(&pem_str, passphrase.as_deref().map(|x| x.as_str()))?
        } else {
            let pass = crate::utils::get_passphrase_if_needed(&pem_str, passphrase.as_deref().map(|x| x.as_str()))?;
            if let Some(p) = pass {
                *passphrase = Some(p);
            }
            crate::utils::unwrap_from_pem(&pem_str, "PRIVATE KEY")?
        };

        let mut ctx = backend::new_hash(digest_algo)?;
        ctx.init_sign(&priv_key_der, passphrase.as_deref().map(|x| x.as_str()))?;
        
        self.sign_key_der = Some(priv_key_der);
        self.hash_ctx = Some(ctx);
        self.digest_algo = digest_algo.to_string();
        Ok(())
    }

    fn prepare_verification(&mut self, pub_key_path: &Path, digest_algo: &str) -> Result<()> {
        let pub_bytes = fs::read(pub_key_path)?;
        let pub_der = crate::utils::unwrap_from_pem(&String::from_utf8_lossy(&pub_bytes), "PUBLIC KEY")?;

        let mut ctx = backend::new_hash(digest_algo)?;
        ctx.init_verify(&pub_der)?;
        
        self.verify_key_der = Some(pub_der);
        self.hash_ctx = Some(ctx);
        self.digest_algo = digest_algo.to_string();
        Ok(())
    }

    fn update_hash(&mut self, data: &[u8]) -> Result<()> {
        let ctx = self.hash_ctx.as_mut().ok_or(CryptoError::Parameter("Hash context not initialized".to_string()))?;
        ctx.update(data)
    }

    fn sign_hash(&mut self) -> Result<Vec<u8>> {
        let ctx = self.hash_ctx.as_mut().ok_or(CryptoError::Parameter("Hash context not initialized".to_string()))?;
        let key_der = self.sign_key_der.as_ref().ok_or(CryptoError::Parameter("Sign key missing".to_string()))?;
        ctx.finalize_sign(key_der)
    }

    fn verify_hash(&mut self, signature: &[u8]) -> Result<bool> {
        let ctx = self.hash_ctx.as_mut().ok_or(CryptoError::Parameter("Hash context not initialized".to_string()))?;
        let key_der = self.verify_key_der.as_ref().ok_or(CryptoError::Parameter("Verify key missing".to_string()))?;
        ctx.finalize_verify(key_der, signature)
    }

    fn serialize_signature_header(&self) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(b"NKCS");
        header.extend_from_slice(&1u16.to_le_bytes());
        header.push(self.get_strategy_type() as u8);

        header.extend_from_slice(&(self.curve_name.len() as u32).to_le_bytes());
        header.extend_from_slice(self.curve_name.as_bytes());
        
        header.extend_from_slice(&(self.digest_algo.len() as u32).to_le_bytes());
        header.extend_from_slice(self.digest_algo.as_bytes());
        
        header
    }

    fn deserialize_signature_header(&mut self, data: &[u8]) -> Result<usize> {
        if data.len() < 7 { return Err(CryptoError::FileRead("Signature header too short".to_string())); }
        if &data[0..4] != b"NKCS" { return Err(CryptoError::FileRead("Invalid signature magic".to_string())); }
        
        let mut pos = 4;
        let version = u16::from_le_bytes(data[pos..pos+2].try_into().map_err(|_| CryptoError::FileRead("Invalid version".to_string()))?);
        pos += 2;
        if version != 1 { return Err(CryptoError::FileRead("Unsupported signature version".to_string())); }
        
        let strategy_type = data[pos];
        pos += 1;
        if strategy_type != self.get_strategy_type() as u8 {
            return Err(CryptoError::FileRead("Signature strategy mismatch".to_string()));
        }

        let read_string = |p: &mut usize| -> Result<String> {
            if data.len() < *p + 4 { return Err(CryptoError::FileRead("Incomplete string header".to_string())); }
            let len = u32::from_le_bytes(data[*p..*p+4].try_into().map_err(|_| CryptoError::FileRead("Invalid length".to_string()))?) as usize;
            *p += 4;
            if data.len() < *p + len { return Err(CryptoError::FileRead("Incomplete string data".to_string())); }
            let s = String::from_utf8_lossy(&data[*p..*p+len]).to_string();
            *p += len;
            Ok(s)
        };

        self.curve_name = read_string(&mut pos)?;
        self.digest_algo = read_string(&mut pos)?;
        Ok(pos)
    }

    fn get_metadata(&self, _magic: &str) -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("Strategy".to_string(), "ECC".to_string());
        m.insert("Curve-Name".to_string(), self.curve_name.clone());
        m.insert("Digest-Algorithm".to_string(), self.digest_algo.clone());
        m
    }

    fn get_header_size(&self) -> usize {
        4 + 2 + 1 + 
        4 + self.curve_name.len() + 
        4 + self.digest_algo.len() + 
        4 + self.ephemeral_pubkey.len() + 4 + self.salt.len() + 4 + self.iv.len() +
        4 + self.aead_algo.len()
    }

    fn serialize_header(&self) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(b"NKCT");
        header.extend_from_slice(&2u16.to_le_bytes());
        header.push(self.get_strategy_type() as u8);

        header.extend_from_slice(&(self.curve_name.len() as u32).to_le_bytes());
        header.extend_from_slice(self.curve_name.as_bytes());
        
        header.extend_from_slice(&(self.digest_algo.len() as u32).to_le_bytes());
        header.extend_from_slice(self.digest_algo.as_bytes());
        
        header.extend_from_slice(&(self.ephemeral_pubkey.len() as u32).to_le_bytes());
        header.extend_from_slice(&self.ephemeral_pubkey);
        
        header.extend_from_slice(&(self.salt.len() as u32).to_le_bytes());
        header.extend_from_slice(&self.salt);
        
        header.extend_from_slice(&(self.iv.len() as u32).to_le_bytes());
        header.extend_from_slice(&self.iv);

        header.extend_from_slice(&(self.aead_algo.len() as u32).to_le_bytes());
        header.extend_from_slice(self.aead_algo.as_bytes());
        
        header
    }

    fn deserialize_header(&mut self, data: &[u8]) -> Result<usize> {
        if data.len() < 7 { return Err(CryptoError::FileRead("Header too short".to_string())); }
        if &data[0..4] != b"NKCT" { return Err(CryptoError::FileRead("Invalid magic".to_string())); }
        
        let mut pos = 4;
        let version = u16::from_le_bytes(data[pos..pos+2].try_into().map_err(|_| CryptoError::FileRead("Invalid version".to_string()))?);
        pos += 2;
        
        let strategy_type = data[pos];
        pos += 1;
        if strategy_type != self.get_strategy_type() as u8 {
            return Err(CryptoError::FileRead("Strategy mismatch".to_string()));
        }

        let read_string = |p: &mut usize| -> Result<String> {
            if data.len() < *p + 4 { return Err(CryptoError::FileRead("Incomplete string header".to_string())); }
            let len = u32::from_le_bytes(data[*p..*p+4].try_into().map_err(|_| CryptoError::FileRead("Invalid length".to_string()))?) as usize;
            *p += 4;
            if data.len() < *p + len { return Err(CryptoError::FileRead("Incomplete string data".to_string())); }
            let s = String::from_utf8_lossy(&data[*p..*p+len]).to_string();
            *p += len;
            Ok(s)
        };

        let read_vec = |p: &mut usize| -> Result<Vec<u8>> {
            if data.len() < *p + 4 { return Err(CryptoError::FileRead("Incomplete vec header".to_string())); }
            let len = u32::from_le_bytes(data[*p..*p+4].try_into().map_err(|_| CryptoError::FileRead("Invalid length".to_string()))?) as usize;
            *p += 4;
            if data.len() < *p + len { return Err(CryptoError::FileRead("Incomplete string data".to_string())); }
            let v = data[*p..*p+len].to_vec();
            *p += len;
            Ok(v)
        };

        self.curve_name = read_string(&mut pos)?;
        self.digest_algo = read_string(&mut pos)?;
        self.ephemeral_pubkey = read_vec(&mut pos)?;
        self.salt = read_vec(&mut pos)?;
        self.iv = read_vec(&mut pos)?;

        if version >= 2 {
            self.aead_algo = read_string(&mut pos)?;
        } else {
            self.aead_algo = "AES-256-GCM".to_string();
        }

        Ok(pos)
    }

    fn get_tag_size(&self) -> usize {
        16
    }

    fn get_shared_secret(&self) -> Zeroizing<Vec<u8>> {
        self.shared_secret.clone()
    }

    fn get_salt(&self) -> Vec<u8> {
        self.salt.clone()
    }

    fn get_iv(&self) -> Vec<u8> {
        self.iv.clone()
    }
}
