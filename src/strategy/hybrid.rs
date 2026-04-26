use crate::error::{CryptoError, Result};
use crate::key::SharedKeyProvider;
use crate::strategy::{CryptoStrategy, StrategyType, ecc::EccStrategy, pqc::PqcStrategy};
use crate::backend::AeadBackend;
use std::collections::HashMap;
use std::path::Path;

pub struct HybridStrategy {
    ecc: EccStrategy,
    pqc: PqcStrategy,
    encryption_key: Vec<u8>,
    iv: Vec<u8>,
    salt: Vec<u8>,
    aead_ctx: Option<crate::backend::Aead>,
}

impl HybridStrategy {
    pub fn new() -> Self {
        Self {
            ecc: EccStrategy::new(),
            pqc: PqcStrategy::new(),
            encryption_key: Vec::new(),
            iv: Vec::new(),
            salt: Vec::new(),
            aead_ctx: None,
        }
    }
}

impl CryptoStrategy for HybridStrategy {
    fn get_strategy_type(&self) -> StrategyType {
        StrategyType::Hybrid
    }

    fn set_key_provider(&mut self, provider: SharedKeyProvider) {
        self.ecc.set_key_provider(provider.clone());
        self.pqc.set_key_provider(provider);
    }

    fn generate_encryption_key_pair(&self, key_paths: &HashMap<String, String>, passphrase: Option<&str>) -> Result<()> {
        let mut ecc_paths = key_paths.clone();
        let mut pqc_paths = key_paths.clone();
        
        let ecc_pub = key_paths.get("public-ecdh-key").cloned().unwrap_or_else(|| key_paths.get("public-key").cloned().unwrap_or_default().replace(".key", "_ecdh.key"));
        let ecc_priv = key_paths.get("private-ecdh-key").cloned().unwrap_or_else(|| key_paths.get("private-key").cloned().unwrap_or_default().replace(".key", "_ecdh.key"));
        ecc_paths.insert("public-key".to_string(), ecc_pub);
        ecc_paths.insert("private-key".to_string(), ecc_priv);

        let pqc_pub = key_paths.get("public-mlkem-key").cloned().unwrap_or_else(|| key_paths.get("public-key").cloned().unwrap_or_default().replace(".key", "_mlkem.key"));
        let pqc_priv = key_paths.get("private-mlkem-key").cloned().unwrap_or_else(|| key_paths.get("private-key").cloned().unwrap_or_default().replace(".key", "_mlkem.key"));
        pqc_paths.insert("public-key".to_string(), pqc_pub);
        pqc_paths.insert("private-key".to_string(), pqc_priv);
        
        self.ecc.generate_encryption_key_pair(&ecc_paths, passphrase)?;
        self.pqc.generate_encryption_key_pair(&pqc_paths, passphrase)?;
        Ok(())
    }

    fn generate_signing_key_pair(&self, key_paths: &HashMap<String, String>, passphrase: Option<&str>) -> Result<()> {
        self.pqc.generate_signing_key_pair(key_paths, passphrase)
    }

    fn prepare_encryption(&mut self, key_paths: &HashMap<String, String>) -> Result<()> {
        let mut ecc_paths = key_paths.clone();
        let mut pqc_paths = key_paths.clone();
        if let Some(p) = key_paths.get("recipient-ecdh-pubkey") { ecc_paths.insert("recipient-pubkey".to_string(), p.clone()); }
        if let Some(p) = key_paths.get("recipient-mlkem-pubkey") { pqc_paths.insert("recipient-pubkey".to_string(), p.clone()); }
        
        self.ecc.prepare_encryption(&ecc_paths)?;
        self.pqc.prepare_encryption(&pqc_paths)?;
        
        let ss_ecc = self.ecc.get_shared_secret();
        let ss_pqc = self.pqc.get_shared_secret();
        let mut combined_ss = ss_ecc;
        combined_ss.extend_from_slice(&ss_pqc);
        
        self.salt = self.ecc.get_salt();
        self.iv = self.ecc.get_iv();
        
        use hkdf::Hkdf;
        use sha3::Sha3_256;
        let mut okm = vec![0u8; 32];
        let hk = Hkdf::<Sha3_256>::new(Some(&self.salt), &combined_ss);
        hk.expand(b"hybrid-encryption", &mut okm).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        self.encryption_key = okm;
        
        let ctx = crate::backend::new_encrypt("AES-256-GCM", &self.encryption_key, &self.iv)?;
        self.aead_ctx = Some(ctx);
        Ok(())
    }

    fn prepare_decryption(&mut self, key_paths: &HashMap<String, String>, passphrase: Option<&str>) -> Result<()> {
        let mut ecc_paths = key_paths.clone();
        let mut pqc_paths = key_paths.clone();
        if let Some(p) = key_paths.get("user-ecdh-privkey") { ecc_paths.insert("user-privkey".to_string(), p.clone()); }
        if let Some(p) = key_paths.get("user-mlkem-privkey") { pqc_paths.insert("user-privkey".to_string(), p.clone()); }
        
        self.ecc.prepare_decryption(&ecc_paths, passphrase)?;
        self.pqc.prepare_decryption(&pqc_paths, passphrase)?;
        
        let ss_ecc = self.ecc.get_shared_secret();
        let ss_pqc = self.pqc.get_shared_secret();
        let mut combined_ss = ss_ecc;
        combined_ss.extend_from_slice(&ss_pqc);
        
        use hkdf::Hkdf;
        use sha3::Sha3_256;
        let mut okm = vec![0u8; 32];
        let hk = Hkdf::<Sha3_256>::new(Some(&self.salt), &combined_ss);
        hk.expand(b"hybrid-encryption", &mut okm).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        self.encryption_key = okm;
        
        let ctx = crate::backend::new_decrypt("AES-256-GCM", &self.encryption_key, &self.iv)?;
        self.aead_ctx = Some(ctx);
        Ok(())
    }

    fn encrypt_transform(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let ctx = self.aead_ctx.as_mut().ok_or(CryptoError::Parameter("AEAD context not initialized".to_string()))?;
        let mut out = vec![0u8; data.len() + 16];
        let n = ctx.update(data, &mut out)?;
        out.truncate(n);
        Ok(out)
    }

    fn decrypt_transform(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let ctx = self.aead_ctx.as_mut().ok_or(CryptoError::Parameter("AEAD context not initialized".to_string()))?;
        let mut out = vec![0u8; data.len() + 16];
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

    fn prepare_signing(&mut self, priv_key_path: &Path, passphrase: Option<&str>, digest_algo: &str) -> Result<()> {
        self.pqc.prepare_signing(priv_key_path, passphrase, digest_algo)
    }

    fn prepare_verification(&mut self, pub_key_path: &Path, digest_algo: &str) -> Result<()> {
        self.pqc.prepare_verification(pub_key_path, digest_algo)
    }

    fn update_hash(&mut self, data: &[u8]) -> Result<()> { self.pqc.update_hash(data) }
    fn sign_hash(&mut self) -> Result<Vec<u8>> { self.pqc.sign_hash() }
    fn verify_hash(&mut self, signature: &[u8]) -> Result<bool> { self.pqc.verify_hash(signature) }

    fn serialize_signature_header(&self) -> Vec<u8> { self.pqc.serialize_signature_header() }
    fn deserialize_signature_header(&mut self, data: &[u8]) -> Result<usize> { self.pqc.deserialize_signature_header(data) }

    fn get_metadata(&self, _magic: &str) -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("Strategy".to_string(), "Hybrid".to_string());
        m.extend(self.ecc.get_metadata("NKCT"));
        m.extend(self.pqc.get_metadata("NKCT"));
        m
    }

    fn get_header_size(&self) -> usize {
        4 + 2 + 1 + 4 + self.ecc.get_header_size() + 4 + self.pqc.get_header_size()
    }

    fn serialize_header(&self) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(b"NKCT");
        header.extend_from_slice(&1u16.to_le_bytes());
        header.push(self.get_strategy_type() as u8);
        
        let ecc_h = self.ecc.serialize_header();
        header.extend_from_slice(&(ecc_h.len() as u32).to_le_bytes());
        header.extend_from_slice(&ecc_h);
        
        let pqc_h = self.pqc.serialize_header();
        header.extend_from_slice(&(pqc_h.len() as u32).to_le_bytes());
        header.extend_from_slice(&pqc_h);
        
        header
    }

    fn deserialize_header(&mut self, data: &[u8]) -> Result<usize> {
        if data.len() < 7 { return Err(CryptoError::FileRead("Header too short".to_string())); }
        if &data[0..4] != b"NKCT" { return Err(CryptoError::FileRead("Invalid magic".to_string())); }
        
        let mut pos = 7;
        let ecc_len = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()) as usize;
        pos += 4;
        self.ecc.deserialize_header(&data[pos..pos+ecc_len])?;
        pos += ecc_len;
        
        let pqc_len = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()) as usize;
        pos += 4;
        self.pqc.deserialize_header(&data[pos..pos+pqc_len])?;
        pos += pqc_len;
        
        self.salt = self.ecc.get_salt();
        self.iv = self.ecc.get_iv();
        Ok(pos)
    }

    fn get_tag_size(&self) -> usize { 16 }
    fn get_shared_secret(&self) -> Vec<u8> { Vec::new() }
    fn get_salt(&self) -> Vec<u8> { self.salt.clone() }
    fn get_iv(&self) -> Vec<u8> { self.iv.clone() }
}
