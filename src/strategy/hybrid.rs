use crate::error::{CryptoError, Result};
use crate::key::SharedKeyProvider;
use crate::strategy::{CryptoStrategy, StrategyType};
use crate::strategy::ecc::EccStrategy;
use crate::strategy::pqc::PqcStrategy;
use openssl::cipher::Cipher;
use openssl::cipher_ctx::CipherCtx;
use std::collections::HashMap;
use std::path::Path;
use hkdf::Hkdf;
use sha3::Sha3_256;
use zeroize::Zeroize;

pub struct HybridStrategy {
    pqc_strategy: PqcStrategy,
    ecc_strategy: EccStrategy,
    
    // Cipher context
    cipher_ctx: Option<CipherCtx>,
    
    // Key states
    encryption_key: Vec<u8>,
    iv: Vec<u8>,
    salt: Vec<u8>,
    shared_secret: Vec<u8>,
}

impl HybridStrategy {
    pub fn new() -> Self {
        Self {
            pqc_strategy: PqcStrategy::new(),
            ecc_strategy: EccStrategy::new(),
            cipher_ctx: None,
            encryption_key: Vec::new(),
            iv: Vec::new(),
            salt: Vec::new(),
            shared_secret: Vec::new(),
        }
    }

    fn hkdf_derive(&self, secret: &[u8], out_len: usize, salt: &[u8], info: &str) -> Result<Vec<u8>> {
        let mut okm = vec![0u8; out_len];
        let hk = Hkdf::<Sha3_256>::new(Some(salt), secret);
        hk.expand(info.as_bytes(), &mut okm).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        Ok(okm)
    }
}

impl CryptoStrategy for HybridStrategy {
    fn get_strategy_type(&self) -> StrategyType {
        StrategyType::Hybrid
    }

    fn set_key_provider(&mut self, provider: SharedKeyProvider) {
        self.pqc_strategy.set_key_provider(provider.clone());
        self.ecc_strategy.set_key_provider(provider);
    }

    fn generate_encryption_key_pair(&self, key_paths: &HashMap<String, String>, passphrase: Option<&str>) -> Result<()> {
        let mut pqc_paths = key_paths.clone();
        let mut ecc_paths = key_paths.clone();

        if let Some(p) = key_paths.get("public-mlkem-key") { pqc_paths.insert("public-key".to_string(), p.clone()); }
        if let Some(p) = key_paths.get("private-mlkem-key") { pqc_paths.insert("private-key".to_string(), p.clone()); }
        if let Some(p) = key_paths.get("public-ecdh-key") { ecc_paths.insert("public-key".to_string(), p.clone()); }
        if let Some(p) = key_paths.get("private-ecdh-key") { ecc_paths.insert("private-key".to_string(), p.clone()); }

        self.pqc_strategy.generate_encryption_key_pair(&pqc_paths, passphrase)?;
        self.ecc_strategy.generate_encryption_key_pair(&ecc_paths, passphrase)?;
        Ok(())
    }

    fn generate_signing_key_pair(&self, key_paths: &HashMap<String, String>, passphrase: Option<&str>) -> Result<()> {
        self.pqc_strategy.generate_signing_key_pair(key_paths, passphrase)
    }

    fn prepare_encryption(&mut self, key_paths: &HashMap<String, String>) -> Result<()> {
        self.pqc_strategy.prepare_encryption(key_paths)?;
        self.ecc_strategy.prepare_encryption(key_paths)?;

        let pqc_ss = self.pqc_strategy.get_shared_secret();
        let ecc_ss = self.ecc_strategy.get_shared_secret();
        
        let mut combined_secret = pqc_ss.clone();
        combined_secret.extend_from_slice(&ecc_ss);
        
        self.salt = self.pqc_strategy.get_salt();
        self.iv = self.pqc_strategy.get_iv();
        
        self.encryption_key = self.hkdf_derive(&combined_secret, 32, &self.salt, "hybrid-encryption")?;
        
        combined_secret.zeroize();
        let mut pqc_ss_mut = pqc_ss;
        let mut ecc_ss_mut = ecc_ss;
        pqc_ss_mut.zeroize();
        ecc_ss_mut.zeroize();

        let mut ctx = CipherCtx::new()
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        ctx.encrypt_init(Some(Cipher::aes_256_gcm()), None, None)
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        ctx.set_iv_length(self.iv.len())
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        ctx.encrypt_init(None, Some(&self.encryption_key), Some(&self.iv))
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;

        self.cipher_ctx = Some(ctx);

        Ok(())
    }

    fn prepare_decryption(&mut self, key_paths: &HashMap<String, String>, passphrase: Option<&str>) -> Result<()> {
        self.pqc_strategy.prepare_decryption(key_paths, passphrase)?;
        self.ecc_strategy.prepare_decryption(key_paths, passphrase)?;

        let pqc_ss = self.pqc_strategy.get_shared_secret();
        let ecc_ss = self.ecc_strategy.get_shared_secret();
        
        let mut combined_secret = pqc_ss.clone();
        combined_secret.extend_from_slice(&ecc_ss);
        
        self.salt = self.pqc_strategy.get_salt();
        self.iv = self.pqc_strategy.get_iv();
        
        self.encryption_key = self.hkdf_derive(&combined_secret, 32, &self.salt, "hybrid-encryption")?;
        
        combined_secret.zeroize();
        let mut pqc_ss_mut = pqc_ss;
        let mut ecc_ss_mut = ecc_ss;
        pqc_ss_mut.zeroize();
        ecc_ss_mut.zeroize();

        let mut ctx = CipherCtx::new()
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        ctx.decrypt_init(Some(Cipher::aes_256_gcm()), None, None)
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        ctx.set_iv_length(self.iv.len())
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        ctx.decrypt_init(None, Some(&self.encryption_key), Some(&self.iv))
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;

        self.cipher_ctx = Some(ctx);

        Ok(())
    }

    fn encrypt_transform(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let ctx = self.cipher_ctx.as_mut().ok_or(CryptoError::OpenSSL("Cipher context not initialized".to_string()))?;
        let mut out = vec![0u8; data.len() + 16];
        let n = ctx.cipher_update(data, Some(&mut out))
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        out.truncate(n);
        Ok(out)
    }

    fn decrypt_transform(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let ctx = self.cipher_ctx.as_mut().ok_or(CryptoError::OpenSSL("Cipher context not initialized".to_string()))?;
        let mut out = vec![0u8; data.len() + 16];
        let n = ctx.cipher_update(data, Some(&mut out))
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        out.truncate(n);
        Ok(out)
    }

    fn finalize_encryption(&mut self) -> Result<Vec<u8>> {
        let ctx = self.cipher_ctx.as_mut().ok_or(CryptoError::OpenSSL("Cipher context not initialized".to_string()))?;
        let mut out = vec![0u8; 16];
        let n = ctx.cipher_final(&mut out)
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        out.truncate(n);
        
        let mut tag = vec![0u8; 16];
        ctx.tag(&mut tag).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        out.extend_from_slice(&tag);
        
        Ok(out)
    }

    fn finalize_decryption(&mut self, tag: &[u8]) -> Result<()> {
        let ctx = self.cipher_ctx.as_mut().ok_or(CryptoError::OpenSSL("Cipher context not initialized".to_string()))?;
        ctx.set_tag(tag).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        let mut out = vec![0u8; 16];
        ctx.cipher_final(&mut out)
            .map_err(|_| CryptoError::SignatureVerification)?;
        Ok(())
    }

    fn prepare_signing(&mut self, priv_key_path: &Path, passphrase: Option<&str>, digest_algo: &str) -> Result<()> {
        self.pqc_strategy.prepare_signing(priv_key_path, passphrase, digest_algo)
    }

    fn prepare_verification(&mut self, pub_key_path: &Path, digest_algo: &str) -> Result<()> {
        self.pqc_strategy.prepare_verification(pub_key_path, digest_algo)
    }

    fn update_hash(&mut self, data: &[u8]) -> Result<()> {
        self.pqc_strategy.update_hash(data)
    }

    fn sign_hash(&mut self) -> Result<Vec<u8>> {
        self.pqc_strategy.sign_hash()
    }

    fn verify_hash(&mut self, signature: &[u8]) -> Result<bool> {
        self.pqc_strategy.verify_hash(signature)
    }

    fn serialize_signature_header(&self) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(b"NKCS");
        header.extend_from_slice(&1u16.to_le_bytes());
        header.push(self.get_strategy_type() as u8);

        let h = self.pqc_strategy.serialize_signature_header();
        header.extend_from_slice(&h[7..]);
        header
    }

    fn deserialize_signature_header(&mut self, data: &[u8]) -> Result<usize> {
        if data.len() < 7 { return Err(CryptoError::FileRead("Signature header too short".to_string())); }
        if &data[0..4] != b"NKCS" { return Err(CryptoError::FileRead("Invalid signature magic".to_string())); }
        
        let mut pos = 7;
        
        let mut pqc_fake_h = b"NKCS".to_vec();
        pqc_fake_h.extend_from_slice(&1u16.to_le_bytes());
        pqc_fake_h.push(StrategyType::PQC as u8);
        pqc_fake_h.extend_from_slice(&data[pos..]);
        let pqc_n = self.pqc_strategy.deserialize_signature_header(&pqc_fake_h)?;
        pos += pqc_n - 7;
        
        Ok(pos)
    }

    fn get_metadata(&self, magic: &str) -> HashMap<String, String> {
        let mut m = self.pqc_strategy.get_metadata(magic);
        m.insert("Strategy".to_string(), "Hybrid".to_string());
        let ecc_meta = self.ecc_strategy.get_metadata(magic);
        m.extend(ecc_meta);
        m
    }

    fn get_header_size(&self) -> usize {
        7 + self.pqc_strategy.get_header_size() + self.ecc_strategy.get_header_size()
    }

    fn serialize_header(&self) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(b"NKCT");
        header.extend_from_slice(&1u16.to_le_bytes());
        header.push(self.get_strategy_type() as u8);

        header.extend_from_slice(&self.pqc_strategy.serialize_header());
        header.extend_from_slice(&self.ecc_strategy.serialize_header());
        
        header
    }

    fn deserialize_header(&mut self, data: &[u8]) -> Result<usize> {
        if data.len() < 7 { return Err(CryptoError::FileRead("Header too short".to_string())); }
        if &data[0..4] != b"NKCT" { return Err(CryptoError::FileRead("Invalid magic".to_string())); }
        
        let mut pos = 7;
        
        let pqc_n = self.pqc_strategy.deserialize_header(&data[pos..])?;
        pos += pqc_n;

        let ecc_n = self.ecc_strategy.deserialize_header(&data[pos..])?;
        pos += ecc_n;

        self.salt = self.pqc_strategy.get_salt();
        self.iv = self.pqc_strategy.get_iv();
        
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
