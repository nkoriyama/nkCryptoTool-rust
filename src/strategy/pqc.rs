/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

use crate::error::{CryptoError, Result};
use crate::key::SharedKeyProvider;
use crate::strategy::{CryptoStrategy, StrategyType};
use crate::backend::{self, AeadBackend};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use hkdf::Hkdf;
use sha3::Sha3_256;
use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PqcStrategy {
    #[zeroize(skip)]
    key_provider: Option<SharedKeyProvider>,
    #[zeroize(skip)]
    kem_algo: String,
    #[zeroize(skip)]
    dsa_algo: String,
    #[zeroize(skip)]
    digest_algo: String,
    
    // Abstract contexts
    #[zeroize(skip)]
    aead_ctx: Option<backend::Aead>,
    
    // Message buffer for ML-DSA (no pre-hash in Pure-mode)
    message_buffer: Vec<u8>,
    
    // Key states
    encryption_key: Vec<u8>,
    iv: Vec<u8>,
    salt: Vec<u8>,
    kem_ct: Vec<u8>,
    shared_secret: Vec<u8>,

    // Signing keys (stored as DER to be backend-agnostic)
    sign_key_der: Option<Vec<u8>>,
    verify_key_der: Option<Vec<u8>>,
}

impl PqcStrategy {
    pub fn new() -> Self {
        Self {
            key_provider: None,
            kem_algo: "ML-KEM-768".to_string(),
            dsa_algo: "ML-DSA-65".to_string(),
            digest_algo: "SHA3-512".to_string(),
            aead_ctx: None,
            message_buffer: Vec::new(),
            encryption_key: Vec::new(),
            iv: Vec::new(),
            salt: Vec::new(),
            kem_ct: Vec::new(),
            shared_secret: Vec::new(),
            sign_key_der: None,
            verify_key_der: None,
        }
    }

    fn hkdf_derive(&self, secret: &[u8], out_len: usize, salt: &[u8], info: &str) -> Result<Vec<u8>> {
        let mut okm = vec![0u8; out_len];
        let hk = Hkdf::<Sha3_256>::new(Some(salt), secret);
        hk.expand(info.as_bytes(), &mut okm).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        Ok(okm)
    }
}

impl CryptoStrategy for PqcStrategy {
    fn get_strategy_type(&self) -> StrategyType {
        StrategyType::PQC
    }

    fn set_key_provider(&mut self, provider: SharedKeyProvider) {
        self.key_provider = Some(provider);
    }

    fn generate_encryption_key_pair(&self, key_paths: &HashMap<String, String>, passphrase: Option<&str>) -> Result<()> {
        let kem_algo = key_paths.get("kem-algo").cloned().unwrap_or_else(|| self.kem_algo.clone());
        let pub_path = key_paths.get("public-key")
            .ok_or(CryptoError::Parameter("Missing public key path".to_string()))?;
        let priv_path = key_paths.get("private-key")
            .ok_or(CryptoError::Parameter("Missing private key path".to_string()))?;

        let use_tpm = key_paths.get("use-tpm").map(|s| s == "true").unwrap_or(false);

        let (sk_bytes, pk_bytes, seed) = backend::pqc_keygen_kem(&kem_algo)?;

        let spki = crate::utils::wrap_pqc_pub_to_spki(&pk_bytes, &kem_algo)?;
        let pub_pem = crate::utils::wrap_to_pem(&spki, "PUBLIC KEY");
        fs::write(pub_path, pub_pem)?;

        if use_tpm {
            let provider = self.key_provider.as_ref().ok_or(CryptoError::ProviderNotAvailable)?;
            let wrapped = provider.wrap_raw(&sk_bytes, passphrase)?;
            fs::write(priv_path, wrapped)?;
        } else {
            let pkcs8 = crate::utils::wrap_pqc_priv_to_pkcs8(&sk_bytes, &kem_algo, seed.as_deref())?;
            let priv_pem = crate::utils::wrap_to_pem(&pkcs8, "PRIVATE KEY");
            fs::write(priv_path, priv_pem)?;
        }

        Ok(())
    }


    fn generate_signing_key_pair(&self, key_paths: &HashMap<String, String>, passphrase: Option<&str>) -> Result<()> {
        let dsa_algo = key_paths.get("dsa-algo").cloned().unwrap_or_else(|| self.dsa_algo.clone());
        let pub_path = key_paths.get("signing-public-key")
            .ok_or(CryptoError::Parameter("Missing public key path".to_string()))?;
        let priv_path = key_paths.get("signing-private-key")
            .ok_or(CryptoError::Parameter("Missing private key path".to_string()))?;

        let use_tpm = key_paths.get("use-tpm").map(|s| s == "true").unwrap_or(false);

        let (sk_bytes, pk_bytes, seed) = backend::pqc_keygen_dsa(&dsa_algo)?;

        let spki = crate::utils::wrap_pqc_pub_to_spki(&pk_bytes, &dsa_algo)?;
        let pub_pem = crate::utils::wrap_to_pem(&spki, "PUBLIC KEY");
        fs::write(pub_path, pub_pem)?;

        if use_tpm {
            let provider = self.key_provider.as_ref().ok_or(CryptoError::ProviderNotAvailable)?;
            let wrapped = provider.wrap_raw(&sk_bytes, passphrase)?;
            fs::write(priv_path, wrapped)?;
        } else {
            let pkcs8 = crate::utils::wrap_pqc_priv_to_pkcs8(&sk_bytes, &dsa_algo, seed.as_deref())?;
            let priv_pem = crate::utils::wrap_to_pem(&pkcs8, "PRIVATE KEY");
            fs::write(priv_path, priv_pem)?;
        }

        Ok(())
    }


    fn regenerate_public_key(&self, priv_path: &Path, pub_path: &Path, passphrase: &mut Option<String>) -> Result<()> {
        let priv_bytes = fs::read(priv_path)?;
        let pem_str = String::from_utf8_lossy(&priv_bytes);
        
        let priv_key_der = if pem_str.contains("-----BEGIN TPM WRAPPED BLOB-----") {
            let provider = self.key_provider.as_ref().ok_or(CryptoError::ProviderNotAvailable)?;
            provider.unwrap_raw(&pem_str, passphrase.as_deref())?
        } else {
            *passphrase = crate::utils::get_passphrase_if_needed(&pem_str, passphrase.as_deref())?;
            crate::utils::unwrap_from_pem(&pem_str, "PRIVATE KEY")?
        };

        let pub_der = backend::extract_public_key(&priv_key_der, passphrase.as_deref())?;
        fs::write(pub_path, crate::utils::wrap_to_pem(&pub_der, "PUBLIC KEY"))?;
        Ok(())
    }

    fn prepare_encryption(&mut self, key_paths: &HashMap<String, String>) -> Result<()> {
        if let Some(algo) = key_paths.get("kem-algo") { self.kem_algo = algo.clone(); }
        if let Some(algo) = key_paths.get("digest-algo") { self.digest_algo = algo.clone(); }

        let pubkey_path = key_paths.get("recipient-pubkey")
            .or_else(|| key_paths.get("recipient-mlkem-pubkey"))
            .ok_or(CryptoError::PublicKeyLoad("Missing recipient public key".to_string()))?;

        let pem = fs::read_to_string(pubkey_path)?;
        let der = crate::utils::unwrap_from_pem(&pem, "PUBLIC KEY")?;
        
        let (ss_bytes, ct_bytes) = backend::pqc_encap(&self.kem_algo, &der)?;
        
        self.shared_secret = ss_bytes;
        self.kem_ct = ct_bytes;
        self.salt = vec![0u8; 16];
        self.iv = vec![0u8; 12];
        OsRng.fill_bytes(&mut self.salt);
        OsRng.fill_bytes(&mut self.iv);

        self.encryption_key = self.hkdf_derive(&self.shared_secret, 32, &self.salt, "pqc-encryption")?;
        let ctx = backend::new_encrypt("AES-256-GCM", &self.encryption_key, &self.iv)?;
        self.aead_ctx = Some(ctx);
        Ok(())
    }

    fn prepare_decryption(&mut self, key_paths: &HashMap<String, String>, passphrase: &mut Option<String>) -> Result<()> {
        if let Some(algo) = key_paths.get("kem-algo") { self.kem_algo = algo.clone(); }
        if let Some(algo) = key_paths.get("dsa-algo") { self.dsa_algo = algo.clone(); }

        let privkey_path = key_paths.get("user-privkey")
            .or_else(|| key_paths.get("recipient-mlkem-privkey"))
            .ok_or(CryptoError::PrivateKeyLoad("Missing private key path".to_string()))?;

        let priv_bytes = fs::read(privkey_path)?;
        let pem_str = String::from_utf8_lossy(&priv_bytes);
        
        let wrapped_priv = if pem_str.contains("-----BEGIN TPM WRAPPED BLOB-----") {
            let provider = self.key_provider.as_ref().ok_or(CryptoError::ProviderNotAvailable)?;
            provider.unwrap_raw(&pem_str, passphrase.as_deref())?
        } else {
            *passphrase = crate::utils::get_passphrase_if_needed(&pem_str, passphrase.as_deref())?;
            crate::utils::unwrap_from_pem(&pem_str, "PRIVATE KEY")?
        };

        let ss_bytes = backend::pqc_decap(&self.kem_algo, &wrapped_priv, &self.kem_ct, passphrase.as_deref())?;
        
        self.shared_secret = ss_bytes;
        self.encryption_key = self.hkdf_derive(&self.shared_secret, 32, &self.salt, "pqc-encryption")?;
        let ctx = backend::new_decrypt("AES-256-GCM", &self.encryption_key, &self.iv)?;
        self.aead_ctx = Some(ctx);
        Ok(())
    }

    fn encrypt_transform(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let ctx = self.aead_ctx.as_mut().ok_or(CryptoError::Parameter("AEAD context not initialized".to_string()))?;
        let mut out = vec![0u8; data.len()];
        let n = ctx.update(data, &mut out)?;
        out.truncate(n);
        Ok(out)
    }

    fn decrypt_transform(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let ctx = self.aead_ctx.as_mut().ok_or(CryptoError::Parameter("AEAD context not initialized".to_string()))?;
        let mut out = vec![0u8; data.len()];
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

    fn prepare_signing(&mut self, priv_key_path: &Path, passphrase: &mut Option<String>, digest_algo: &str) -> Result<()> {
        let priv_bytes = fs::read(priv_key_path)?;
        let pem_str = String::from_utf8_lossy(&priv_bytes);

        let wrapped_priv = if pem_str.contains("-----BEGIN TPM WRAPPED BLOB-----") {
            let provider = self.key_provider.as_ref().ok_or(CryptoError::ProviderNotAvailable)?;
            provider.unwrap_raw(&pem_str, passphrase.as_deref())?
        } else {
            *passphrase = crate::utils::get_passphrase_if_needed(&pem_str, passphrase.as_deref())?;
            crate::utils::unwrap_from_pem(&pem_str, "PRIVATE KEY")?
        };
        
        self.sign_key_der = Some(wrapped_priv);
        self.digest_algo = digest_algo.to_string();
        self.message_buffer.clear();
        Ok(())
    }

    fn prepare_verification(&mut self, pub_key_path: &Path, digest_algo: &str) -> Result<()> {
        let pub_bytes = fs::read(pub_key_path)?;
        let der = crate::utils::unwrap_from_pem(&String::from_utf8_lossy(&pub_bytes), "PUBLIC KEY")?;

        self.verify_key_der = Some(der);
        self.digest_algo = digest_algo.to_string();
        self.message_buffer.clear();
        Ok(())
    }

    fn update_hash(&mut self, data: &[u8]) -> Result<()> {
        self.message_buffer.extend_from_slice(data);
        Ok(())
    }

    fn sign_hash(&mut self) -> Result<Vec<u8>> {
        let priv_der = self.sign_key_der.as_ref().ok_or(CryptoError::Parameter("Sign key missing".to_string()))?;
        backend::pqc_sign(&self.dsa_algo, priv_der, &self.message_buffer, None)
    }

    fn verify_hash(&mut self, signature: &[u8]) -> Result<bool> {
        let pub_der = self.verify_key_der.as_ref().ok_or(CryptoError::Parameter("Verify key missing".to_string()))?;
        backend::pqc_verify(&self.dsa_algo, pub_der, &self.message_buffer, signature)
    }

    fn sign_full(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        let priv_der = self.sign_key_der.as_ref().ok_or(CryptoError::Parameter("Sign key missing".to_string()))?;
        backend::pqc_sign(&self.dsa_algo, priv_der, message, None)
    }

    fn verify_full(&mut self, message: &[u8], signature: &[u8]) -> Result<bool> {
        let pub_der = self.verify_key_der.as_ref().ok_or(CryptoError::Parameter("Verify key missing".to_string()))?;
        backend::pqc_verify(&self.dsa_algo, pub_der, message, signature)
    }

    fn serialize_signature_header(&self) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(b"NKCS");
        header.extend_from_slice(&1u16.to_le_bytes());
        header.push(self.get_strategy_type() as u8);

        header.extend_from_slice(&(self.kem_algo.len() as u32).to_le_bytes());
        header.extend_from_slice(self.kem_algo.as_bytes());

        header.extend_from_slice(&(self.dsa_algo.len() as u32).to_le_bytes());
        header.extend_from_slice(self.dsa_algo.as_bytes());
        
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

        self.kem_algo = read_string(&mut pos)?;
        self.dsa_algo = read_string(&mut pos)?;
        self.digest_algo = read_string(&mut pos)?;
        Ok(pos)
    }

    fn get_metadata(&self, _magic: &str) -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("Strategy".to_string(), "PQC".to_string());
        m.insert("KEM-Algorithm".to_string(), self.kem_algo.clone());
        m.insert("DSA-Algorithm".to_string(), self.dsa_algo.clone());
        m
    }

    fn get_header_size(&self) -> usize {
        4 + 2 + 1 + 
        4 + self.kem_algo.len() + 
        4 + self.dsa_algo.len() + 
        4 + self.kem_ct.len() + 4 + self.salt.len() + 4 + self.iv.len()
    }

    fn serialize_header(&self) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(b"NKCT");
        header.extend_from_slice(&1u16.to_le_bytes());
        header.push(self.get_strategy_type() as u8);

        header.extend_from_slice(&(self.kem_algo.len() as u32).to_le_bytes());
        header.extend_from_slice(self.kem_algo.as_bytes());
        
        header.extend_from_slice(&(self.dsa_algo.len() as u32).to_le_bytes());
        header.extend_from_slice(self.dsa_algo.as_bytes());
        
        header.extend_from_slice(&(self.kem_ct.len() as u32).to_le_bytes());
        header.extend_from_slice(&self.kem_ct);
        
        header.extend_from_slice(&(self.salt.len() as u32).to_le_bytes());
        header.extend_from_slice(&self.salt);
        
        header.extend_from_slice(&(self.iv.len() as u32).to_le_bytes());
        header.extend_from_slice(&self.iv);
        
        header
    }

    fn deserialize_header(&mut self, data: &[u8]) -> Result<usize> {
        if data.len() < 7 { return Err(CryptoError::FileRead("Header too short".to_string())); }
        if &data[0..4] != b"NKCT" { return Err(CryptoError::FileRead("Invalid magic".to_string())); }
        
        let mut pos = 4;
        let version = u16::from_le_bytes(data[pos..pos+2].try_into().map_err(|_| CryptoError::FileRead("Invalid version".to_string()))?);
        pos += 2;
        if version != 1 { return Err(CryptoError::FileRead("Unsupported version".to_string())); }
        
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

        self.kem_algo = read_string(&mut pos)?;
        self.dsa_algo = read_string(&mut pos)?;
        self.kem_ct = read_vec(&mut pos)?;
        self.salt = read_vec(&mut pos)?;
        self.iv = read_vec(&mut pos)?;

        Ok(pos)
    }

    fn get_tag_size(&self) -> usize {
        16
    }

    fn get_shared_secret(&self) -> Vec<u8> {
        self.shared_secret.clone()
    }

    fn get_salt(&self) -> Vec<u8> {
        self.salt.clone()
    }

    fn get_iv(&self) -> Vec<u8> {
        self.iv.clone()
    }
}
