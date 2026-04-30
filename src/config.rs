/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

use serde::{Deserialize, Serialize};
use std::fmt;
use clap::ValueEnum;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operation {
    Encrypt,
    Decrypt,
    Sign,
    Verify,
    GenerateEncKey,
    GenerateSignKey,
    RegeneratePubKey,
    WrapKey,
    UnwrapKey,
    Info,
    Listen,
    Connect,
    None,
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
pub enum CryptoMode {
    ECC,
    PQC,
    Hybrid,
}

impl fmt::Display for CryptoMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Default for CryptoMode {
    fn default() -> Self {
        CryptoMode::ECC
    }
}

pub struct CryptoConfig {
    pub operation: Operation,
    pub mode: CryptoMode,

    // Paths
    pub input_files: Vec<String>,
    pub output_file: Option<String>,
    pub input_dir: Option<String>,
    pub output_dir: Option<String>,
    pub key_dir: String,
    pub signature_file: Option<String>,

    // Key paths
    pub recipient_pubkey: Option<String>,
    pub user_privkey: Option<String>,
    pub signing_privkey: Option<String>,
    pub signing_pubkey: Option<String>,
    
    // Hybrid keys
    pub recipient_mlkem_pubkey: Option<String>,
    pub recipient_ecdh_pubkey: Option<String>,
    pub user_mlkem_privkey: Option<String>,
    pub user_ecdh_privkey: Option<String>,

    // Options
    pub passphrase: Option<String>,
    pub use_tpm: bool,
    pub digest_algo: String,
    pub aead_algo: String,
    pub pqc_kem_algo: String,
    pub pqc_dsa_algo: String,
    pub use_parallel: bool,
    pub is_recursive: bool,

    pub listen_addr: Option<String>,
    pub connect_addr: Option<String>,
    pub chat_mode: bool,

    // For regenerate-pubkey
    pub regenerate_privkey_path: Option<String>,
    pub regenerate_pubkey_path: Option<String>,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            operation: Operation::None,
            mode: CryptoMode::ECC,
            input_files: Vec::new(),
            output_file: None,
            input_dir: None,
            output_dir: None,
            key_dir: "keys".to_string(),
            signature_file: None,
            recipient_pubkey: None,
            user_privkey: None,
            signing_privkey: None,
            signing_pubkey: None,
            recipient_mlkem_pubkey: None,
            recipient_ecdh_pubkey: None,
            user_mlkem_privkey: None,
            user_ecdh_privkey: None,
            passphrase: None,
            use_tpm: false,
            digest_algo: "SHA3-512".to_string(),
            aead_algo: "AES-256-GCM".to_string(),
            pqc_kem_algo: "ML-KEM-768".to_string(),
            pqc_dsa_algo: "ML-DSA-65".to_string(),
            use_parallel: false,
            is_recursive: false,
            listen_addr: None,
            connect_addr: None,
            chat_mode: false,
            regenerate_privkey_path: None,
            regenerate_pubkey_path: None,
        }
    }
}
