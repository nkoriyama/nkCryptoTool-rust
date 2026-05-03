/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

use crate::error::Result;
use crate::key::SharedKeyProvider;
use std::collections::HashMap;
use std::path::Path;
use zeroize::Zeroizing;

pub mod ecc;
pub mod pqc;
pub mod hybrid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrategyType {
    ECC = 1,
    PQC = 2,
    Hybrid = 3,
}

pub trait CryptoStrategy: Send + Sync {
    fn get_strategy_type(&self) -> StrategyType;
    
    fn set_key_provider(&mut self, provider: SharedKeyProvider);

    // Key Generation
    fn generate_encryption_key_pair(&self, key_paths: &HashMap<String, String>, passphrase: Option<&str>) -> Result<()>;
    fn generate_signing_key_pair(&self, key_paths: &HashMap<String, String>, passphrase: Option<&str>) -> Result<()>;
    fn regenerate_public_key(&self, priv_path: &Path, pub_path: &Path, passphrase: &mut Option<Zeroizing<String>>) -> Result<()> {
        let _ = (priv_path, pub_path, passphrase);
        Err(crate::error::CryptoError::Parameter("Not implemented".to_string()))
    }

    // Encryption / Decryption Pipeline
    fn prepare_encryption(&mut self, key_paths: &HashMap<String, String>) -> Result<()>;
    fn prepare_decryption(&mut self, key_paths: &HashMap<String, String>, passphrase: &mut Option<Zeroizing<String>>) -> Result<()>;
    
    fn encrypt_transform(&mut self, data: &[u8]) -> Result<Vec<u8>>;
    fn decrypt_transform(&mut self, data: &[u8]) -> Result<Vec<u8>>;
    
    fn finalize_encryption(&mut self) -> Result<Vec<u8>>;
    fn finalize_decryption(&mut self, tag: &[u8]) -> Result<()>;

    // Signing / Verification
    fn prepare_signing(&mut self, priv_key_path: &Path, passphrase: &mut Option<Zeroizing<String>>, digest_algo: &str) -> Result<()>;
    fn prepare_verification(&mut self, pub_key_path: &Path, digest_algo: &str) -> Result<()>;
    
    fn update_hash(&mut self, data: &[u8]) -> Result<()>;
    fn sign_hash(&mut self) -> Result<Vec<u8>>;
    fn verify_hash(&mut self, signature: &[u8]) -> Result<bool>;

    fn sign_full(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        self.update_hash(message)?;
        self.sign_hash()
    }
    fn verify_full(&mut self, message: &[u8], signature: &[u8]) -> Result<bool> {
        self.update_hash(message)?;
        self.verify_hash(signature)
    }

    // Header Serialization
    fn serialize_signature_header(&self) -> Vec<u8>;
    fn deserialize_signature_header(&mut self, data: &[u8]) -> Result<usize>;
    
    fn get_metadata(&self, magic: &str) -> HashMap<String, String>;
    fn get_header_size(&self) -> usize;
    fn serialize_header(&self) -> Vec<u8>;
    fn deserialize_header(&mut self, data: &[u8]) -> Result<usize>;
    fn get_tag_size(&self) -> usize;

    // Internal state access for hybrid
    fn get_shared_secret(&self) -> Vec<u8>;
    fn get_salt(&self) -> Vec<u8>;
    fn get_iv(&self) -> Vec<u8>;
}
