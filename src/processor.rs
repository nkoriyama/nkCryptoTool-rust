/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

use crate::config::{CryptoConfig, CryptoMode, Operation};
use crate::error::{CryptoError, Result};
use crate::key::SharedKeyProvider;
use crate::strategy::ecc::EccStrategy;
use crate::strategy::hybrid::HybridStrategy;
use crate::strategy::pqc::PqcStrategy;
use crate::strategy::CryptoStrategy;
use rand_core::RngCore;
use std::collections::HashMap;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use zeroize::Zeroizing;

pub type ProgressCallback = Arc<dyn Fn(f64) + Send + Sync>;

const BUF_SIZE: usize = 1024 * 1024;
const AEAD_OVERHEAD: usize = 32;

pub struct CryptoProcessor {
    strategy: Option<Box<dyn CryptoStrategy>>,
    key_provider: Option<SharedKeyProvider>,
}

impl CryptoProcessor {
    pub fn new(mode: CryptoMode) -> Self {
        let strategy: Box<dyn CryptoStrategy> = match mode {
            CryptoMode::ECC => Box::new(EccStrategy::new()),
            CryptoMode::PQC => Box::new(PqcStrategy::new()),
            CryptoMode::Hybrid => Box::new(HybridStrategy::new()),
        };

        Self {
            strategy: Some(strategy),
            key_provider: None,
        }
    }

    pub fn set_key_provider(&mut self, provider: SharedKeyProvider) {
        self.key_provider = Some(provider.clone());
        if let Some(ref mut s) = self.strategy {
            s.set_key_provider(provider);
        }
    }

    pub async fn process(
        &mut self,
        config: &CryptoConfig,
        progress_callback: Option<ProgressCallback>,
    ) -> Result<()> {
        let mut passphrase = config.passphrase.clone();
        match config.operation {
            Operation::Encrypt => self.encrypt_file(config, progress_callback).await,
            Operation::Decrypt => {
                self.decrypt_file(config, &mut passphrase, progress_callback)
                    .await
            }
            Operation::Sign => {
                self.sign_file(config, &mut passphrase, progress_callback)
                    .await
            }
            Operation::Verify => self.verify_file(config, progress_callback).await,
            Operation::GenerateEncKey => self.generate_encryption_key_pair(config),
            Operation::GenerateSignKey => self.generate_signing_key_pair(config),
            Operation::RegeneratePubKey => self.regenerate_pubkey(config, &mut passphrase),
            Operation::Fingerprint => self.calculate_fingerprint(config),
            _ => Err(CryptoError::Parameter("Unsupported operation".to_string())),
        }
    }

    fn calculate_fingerprint(&self, config: &CryptoConfig) -> Result<()> {
        let pub_path = config.recipient_pubkey.as_ref().or(config.signing_pubkey.as_ref())
            .ok_or(CryptoError::Parameter("No public key path specified. Use --recipient-pubkey or --signing-pubkey".to_string()))?;
        
        let pub_bytes = std::fs::read(pub_path).map_err(|e| CryptoError::FileRead(e.to_string()))?;
        let pem_str = std::str::from_utf8(&pub_bytes)
            .map_err(|_| CryptoError::Parameter("Invalid UTF-8 in key".to_string()))?;
        
        let der = crate::utils::unwrap_from_pem(pem_str, "PUBLIC KEY")?;
        
        let raw_pub = match config.mode {
            CryptoMode::PQC => {
                crate::utils::unwrap_pqc_pub_from_spki(&der, "any")?
            }
            _ => {
                return Err(CryptoError::Parameter("Fingerprint calculation only supported for PQC mode for now".to_string()));
            }
        };

        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(&raw_pub);
        let hash = hasher.finalize();
        
        println!("Fingerprint: {}", hex::encode(hash));
        
        Ok(())
    }

    fn regenerate_pubkey(
        &self,
        config: &CryptoConfig,
        passphrase: &mut Option<Zeroizing<String>>,
    ) -> Result<()> {
        let priv_path = config
            .regenerate_privkey_path
            .as_ref()
            .ok_or(CryptoError::Parameter("No private key path".to_string()))?;
        let pub_path = config
            .regenerate_pubkey_path
            .as_ref()
            .ok_or(CryptoError::Parameter("No public key path".to_string()))?;
        let strategy = self.strategy.as_ref().ok_or(CryptoError::Parameter(
            "Strategy not initialized".to_string(),
        ))?;
        strategy.regenerate_public_key(
            Path::new(priv_path),
            Path::new(pub_path),
            passphrase,
            config.force,
        )
    }

    pub async fn sign_file(
        &mut self,
        config: &CryptoConfig,
        passphrase: &mut Option<Zeroizing<String>>,
        progress_callback: Option<ProgressCallback>,
    ) -> Result<()> {
        let input_path = config
            .input_files
            .first()
            .ok_or(CryptoError::Parameter("No input file".to_string()))?
            .clone();
        let signature_path = config
            .signature_file
            .as_ref()
            .ok_or(CryptoError::Parameter(
                "No signature output path".to_string(),
            ))?
            .clone();
        let priv_key_path = config
            .signing_privkey
            .as_ref()
            .ok_or(CryptoError::Parameter("No signing private key".to_string()))?
            .clone();

        let mut strategy = self.strategy.take().ok_or(CryptoError::Parameter(
            "Strategy not initialized".to_string(),
        ))?;
        strategy.prepare_signing(Path::new(&priv_key_path), passphrase, &config.digest_algo)?;

        let cb_clone = progress_callback.clone();
        strategy = tokio::task::spawn_blocking(move || {
            use std::io::Read;
            let mut file = std::fs::File::open(&input_path)
                .map_err(|e| CryptoError::FileRead(e.to_string()))?;
            let total_size = file.metadata()
                .map_err(|e| CryptoError::FileRead(e.to_string()))?
                .len();
            let mut buffer = vec![0u8; BUF_SIZE];
            let mut current_size = 0u64;

            loop {
                let n = file
                    .read(&mut buffer)
                    .map_err(|e| CryptoError::FileRead(e.to_string()))?;
                if n == 0 {
                    break;
                }
                strategy.update_hash(&buffer[..n])?;
                current_size += n as u64;
                if let Some(ref cb) = cb_clone {
                    if total_size > 0 {
                        cb(current_size as f64 / total_size as f64 * 0.9);
                    }
                }
            }
            Ok::<Box<dyn CryptoStrategy>, CryptoError>(strategy)
        })
        .await
        .map_err(|e| CryptoError::Parameter(format!("Blocking task failed: {}", e)))??;

        let signature = strategy.sign_hash()?;
        if let Some(ref cb) = progress_callback {
            cb(1.0);
        }

        let header = strategy.serialize_signature_header();
        self.strategy = Some(strategy);

        crate::utils::secure_write(&signature_path, {
            let mut output = Vec::with_capacity(header.len() + signature.len());
            output.extend_from_slice(&header);
            output.extend_from_slice(&signature);
            output
        }, config.force)?;

        Ok(())
    }

    pub async fn verify_file(
        &mut self,
        config: &CryptoConfig,
        progress_callback: Option<ProgressCallback>,
    ) -> Result<()> {
        let input_path = config
            .input_files
            .first()
            .ok_or(CryptoError::Parameter("No input file".to_string()))?
            .clone();
        let signature_path = config
            .signature_file
            .as_ref()
            .ok_or(CryptoError::Parameter("No signature file".to_string()))?
            .clone();
        let pub_key_path = config
            .signing_pubkey
            .as_ref()
            .ok_or(CryptoError::Parameter("No signing public key".to_string()))?
            .clone();

        let sig_data = std::fs::read(&signature_path)?;
        let mut strategy = self.strategy.take().ok_or(CryptoError::Parameter(
            "Strategy not initialized".to_string(),
        ))?;
        let header_size = strategy.deserialize_signature_header(&sig_data)?;
        let signature = sig_data[header_size..].to_vec();

        strategy.prepare_verification(Path::new(&pub_key_path), &config.digest_algo)?;

        let cb_clone = progress_callback.clone();
        strategy = tokio::task::spawn_blocking(move || {
            use std::io::Read;
            let mut file = std::fs::File::open(&input_path)
                .map_err(|e| CryptoError::FileRead(e.to_string()))?;
            let total_size = file.metadata()
                .map_err(|e| CryptoError::FileRead(e.to_string()))?
                .len();
            let mut buffer = vec![0u8; BUF_SIZE];
            let mut current_size = 0u64;

            loop {
                let n = file
                    .read(&mut buffer)
                    .map_err(|e| CryptoError::FileRead(e.to_string()))?;
                if n == 0 {
                    break;
                }
                strategy.update_hash(&buffer[..n])?;
                current_size += n as u64;
                if let Some(ref cb) = cb_clone {
                    if total_size > 0 {
                        cb(current_size as f64 / total_size as f64 * 0.9);
                    }
                }
            }
            Ok::<Box<dyn CryptoStrategy>, CryptoError>(strategy)
        })
        .await
        .map_err(|e| CryptoError::Parameter(format!("Blocking task failed: {}", e)))??;

        let success = strategy.verify_hash(&signature)?;
        if let Some(ref cb) = progress_callback {
            cb(1.0);
        }

        self.strategy = Some(strategy);

        if success {
            println!("Signature verified successfully.");
            Ok(())
        } else {
            Err(CryptoError::SignatureVerification)
        }
    }

    pub async fn encrypt_file(
        &mut self,
        config: &CryptoConfig,
        progress_callback: Option<ProgressCallback>,
    ) -> Result<()> {
        let input_path = config
            .input_files
            .first()
            .ok_or(CryptoError::Parameter("No input file".to_string()))?;
        let output_path = config
            .output_file
            .as_ref()
            .ok_or(CryptoError::Parameter("No output file".to_string()))?;

        let mut key_paths = HashMap::new();
        if let Some(ref p) = config.recipient_pubkey {
            key_paths.insert("recipient-pubkey".to_string(), p.clone());
        }
        if let Some(ref p) = config.recipient_mlkem_pubkey {
            key_paths.insert("recipient-mlkem-pubkey".to_string(), p.clone());
        }
        if let Some(ref p) = config.recipient_ecdh_pubkey {
            key_paths.insert("recipient-ecdh-pubkey".to_string(), p.clone());
        }
        key_paths.insert("digest-algo".to_string(), config.digest_algo.clone());
        key_paths.insert("kem-algo".to_string(), config.pqc_kem_algo.clone());
        key_paths.insert("dsa-algo".to_string(), config.pqc_dsa_algo.clone());

        let mut strategy = self.strategy.take().ok_or(CryptoError::Parameter(
            "Strategy already in use".to_string(),
        ))?;
        strategy.prepare_encryption(&key_paths)?;

        let header = strategy.serialize_header();
        let total_input_size = tokio::fs::metadata(input_path).await?.len();

        let input_path_str = input_path.to_string();
        let output_path_str = output_path.to_string();

        let result = self
            .run_streaming_encrypt(
                strategy,
                input_path_str,
                output_path_str,
                header,
                total_input_size,
                config.force,
                progress_callback,
            )
            .await;

        match result {
            Ok(s) => {
                self.strategy = Some(s);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    pub async fn decrypt_file(
        &mut self,
        config: &CryptoConfig,
        passphrase: &mut Option<Zeroizing<String>>,
        progress_callback: Option<ProgressCallback>,
    ) -> Result<()> {
        let input_path = config
            .input_files
            .first()
            .ok_or(CryptoError::Parameter("No input file".to_string()))?;
        let output_path = config
            .output_file
            .as_ref()
            .ok_or(CryptoError::Parameter("No output file".to_string()))?;

        let total_size = tokio::fs::metadata(input_path).await?.len();
        let mut strategy = self.strategy.take().ok_or(CryptoError::Parameter(
            "Strategy already in use".to_string(),
        ))?;
        let tag_size = strategy.get_tag_size() as u64;

        if total_size < tag_size {
            return Err(CryptoError::FileRead("File too small".to_string()));
        }

        let mut input_file = File::open(input_path).await?;
        let mut header_peek = vec![0u8; 16384];
        let n = input_file.read(&mut header_peek).await?;
        header_peek.truncate(n);
        let header_size = strategy.deserialize_header(&header_peek)? as u64;

        let mut tag = vec![0u8; tag_size as usize];
        input_file
            .seek(std::io::SeekFrom::End(-(tag_size as i64)))
            .await?;
        input_file.read_exact(&mut tag).await?;

        let mut key_paths = HashMap::new();
        if let Some(ref p) = config.user_privkey {
            key_paths.insert("user-privkey".to_string(), p.clone());
        }
        if let Some(ref p) = config.user_mlkem_privkey {
            key_paths.insert("user-mlkem-privkey".to_string(), p.clone());
        }
        if let Some(ref p) = config.user_ecdh_privkey {
            key_paths.insert("user-ecdh-privkey".to_string(), p.clone());
        }
        key_paths.insert("kem-algo".to_string(), config.pqc_kem_algo.clone());
        key_paths.insert("dsa-algo".to_string(), config.pqc_dsa_algo.clone());

        strategy.prepare_decryption(&key_paths, passphrase)?;

        let input_path_str = input_path.to_string();
        let output_path_str = output_path.to_string();
        let ciphertext_size = total_size
            .checked_sub(header_size)
            .and_then(|s| s.checked_sub(tag_size))
            .ok_or_else(|| {
                CryptoError::FileRead("File too small for header and tag".to_string())
            })?;

        let result = self
            .run_streaming_decrypt(
                strategy,
                input_path_str,
                output_path_str,
                header_size,
                ciphertext_size,
                tag,
                config.force,
                progress_callback,
            )
            .await;

        match result {
            Ok(s) => {
                self.strategy = Some(s);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    async fn run_streaming_encrypt(
        &self,
        mut strategy: Box<dyn CryptoStrategy>,
        input_path: String,
        output_path: String,
        header: Vec<u8>,
        total_input_size: u64,
        force: bool,
        progress_callback: Option<ProgressCallback>,
    ) -> Result<Box<dyn CryptoStrategy>> {
        let cb_clone = progress_callback.clone();
        tokio::task::spawn_blocking(move || {
            use std::fs::OpenOptions;
            use std::io::{BufReader, BufWriter, Read, Write};

            let in_file =
                std::fs::File::open(&input_path).map_err(|e| CryptoError::FileRead(e.to_string()))?;
            let mut reader = BufReader::with_capacity(BUF_SIZE * 4, in_file);

            if force {
                let _ = std::fs::remove_file(&output_path);
            }

            let out_file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&output_path)
                .map_err(|e| CryptoError::FileWrite(e.to_string()))?;
            let mut writer = BufWriter::with_capacity(BUF_SIZE * 4, out_file);

            writer
                .write_all(&header)
                .map_err(|e| CryptoError::FileWrite(e.to_string()))?;

            let mut in_buf = Zeroizing::new(vec![0u8; BUF_SIZE]);
            let mut out_buf = vec![0u8; BUF_SIZE + AEAD_OVERHEAD];
            let mut total_processed = 0u64;

            loop {
                let n = reader
                    .read(&mut in_buf)
                    .map_err(|e| CryptoError::FileRead(e.to_string()))?;
                if n == 0 {
                    break;
                }

                let m = strategy.encrypt_into(&in_buf[..n], &mut out_buf)?;
                writer
                    .write_all(&out_buf[..m])
                    .map_err(|e| CryptoError::FileWrite(e.to_string()))?;

                total_processed += n as u64;
                if let Some(ref cb) = cb_clone {
                    if total_input_size > 0 {
                        cb(total_processed as f64 / total_input_size as f64);
                    }
                }
            }

            let final_block = strategy.finalize_encryption()?;
            if !final_block.is_empty() {
                writer
                    .write_all(&final_block)
                    .map_err(|e| CryptoError::FileWrite(e.to_string()))?;
            }
            writer
                .flush()
                .map_err(|e| CryptoError::FileWrite(e.to_string()))?;

            Ok::<Box<dyn CryptoStrategy>, CryptoError>(strategy)
        })
        .await
        .map_err(|e| CryptoError::OpenSSL(format!("Blocking task failed: {}", e)))?
    }

    async fn run_streaming_decrypt(
        &self,
        mut strategy: Box<dyn CryptoStrategy>,
        input_path: String,
        output_path: String,
        header_size: u64,
        ciphertext_size: u64,
        tag: Vec<u8>,
        force: bool,
        progress_callback: Option<ProgressCallback>,
    ) -> Result<Box<dyn CryptoStrategy>> {
        let temp_output_path = format!("{}.tmp.{}", output_path, rand_core::OsRng.next_u64());
        let temp_output_path_clone = temp_output_path.clone();

        let cb_clone = progress_callback.clone();
        let res = tokio::task::spawn_blocking(move || {
            use std::fs::OpenOptions;
            use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};

            // Pass 1: Verification (no disk writing)
            {
                let mut in_file = std::fs::File::open(&input_path)
                    .map_err(|e| CryptoError::FileRead(e.to_string()))?;
                in_file
                    .seek(SeekFrom::Start(header_size))
                    .map_err(|e| CryptoError::FileRead(e.to_string()))?;
                let mut reader = BufReader::with_capacity(BUF_SIZE * 4, in_file);

                let mut in_buf = vec![0u8; BUF_SIZE];
                // Defense-in-depth: Zeroize Pass 1 dummy buffer to prevent plaintext residue in memory
                let mut out_buf = Zeroizing::new(vec![0u8; BUF_SIZE + AEAD_OVERHEAD]);
                let mut total_read = 0u64;

                while total_read < ciphertext_size {
                    let to_read =
                        std::cmp::min(BUF_SIZE as u64, ciphertext_size - total_read) as usize;
                    reader
                        .read_exact(&mut in_buf[..to_read])
                        .map_err(|e| CryptoError::FileRead(e.to_string()))?;

                    // Decrypt but discard results
                    let _ = strategy.decrypt_into(&in_buf[..to_read], &mut out_buf)?;
                    out_buf.fill(0); // Immediate clear

                    total_read += to_read as u64;
                    if let Some(ref cb) = cb_clone {
                        if ciphertext_size > 0 {
                            // Pass 1 takes 0% -> 50% of progress
                            cb((total_read as f64 / ciphertext_size as f64) * 0.5);
                        }
                    }
                }

                // Verify the final tag
                strategy.finalize_decryption(&tag)?;
            }

            // Pass 1 succeeded. Now Pass 2: Actually writing to temporary file.
            strategy.restart_decryption()?;

            let mut in_file =
                std::fs::File::open(&input_path).map_err(|e| CryptoError::FileRead(e.to_string()))?;
            in_file
                .seek(SeekFrom::Start(header_size))
                .map_err(|e| CryptoError::FileRead(e.to_string()))?;
            let mut reader = BufReader::with_capacity(BUF_SIZE * 4, in_file);

            let out_file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&temp_output_path_clone)
                .map_err(|e| CryptoError::FileWrite(e.to_string()))?;
            let mut writer = BufWriter::with_capacity(BUF_SIZE * 4, out_file);

            let mut in_buf = vec![0u8; BUF_SIZE];
            let mut out_buf = vec![0u8; BUF_SIZE + AEAD_OVERHEAD];
            let mut total_read_pass2 = 0u64;

            while total_read_pass2 < ciphertext_size {
                let to_read = std::cmp::min(BUF_SIZE as u64, ciphertext_size - total_read_pass2) as usize;
                reader
                    .read_exact(&mut in_buf[..to_read])
                    .map_err(|e| CryptoError::FileRead(e.to_string()))?;

                let m = strategy.decrypt_into(&in_buf[..to_read], &mut out_buf)?;
                writer
                    .write_all(&out_buf[..m])
                    .map_err(|e| CryptoError::FileWrite(e.to_string()))?;

                total_read_pass2 += to_read as u64;
                if let Some(ref cb) = cb_clone {
                    if ciphertext_size > 0 {
                        // Pass 2 takes 50% -> 100% of progress
                        cb(0.5 + (total_read_pass2 as f64 / ciphertext_size as f64) * 0.5);
                    }
                }
            }

            // Optional: Re-verify in Pass 2
            strategy.finalize_decryption(&tag)?;

            writer
                .flush()
                .map_err(|e| CryptoError::FileWrite(e.to_string()))?;

            Ok::<Box<dyn CryptoStrategy>, CryptoError>(strategy)
        })
        .await
        .map_err(|e| {
            let _ = std::fs::remove_file(&temp_output_path);
            CryptoError::OpenSSL(format!("Blocking task failed: {}", e))
        })?;

        match res {
            Ok(s) => {
                if !force && Path::new(&output_path).exists() {
                    let _ = std::fs::remove_file(&temp_output_path);
                    return Err(CryptoError::FileWrite("File exists".to_string()));
                }
                std::fs::rename(&temp_output_path, &output_path)
                    .map_err(|e| {
                        let _ = std::fs::remove_file(&temp_output_path);
                        CryptoError::FileWrite(e.to_string())
                    })?;
                Ok(s)
            }
            Err(e) => {
                let _ = std::fs::remove_file(&temp_output_path);
                Err(e)
            }
        }
    }

    pub fn generate_encryption_key_pair(&self, config: &CryptoConfig) -> Result<()> {
        let mut key_paths = HashMap::new();
        if config.mode == CryptoMode::Hybrid {
            key_paths.insert(
                "public-mlkem-key".to_string(),
                format!("{}/public_enc_hybrid_mlkem.key", config.key_dir),
            );
            key_paths.insert(
                "private-mlkem-key".to_string(),
                format!("{}/private_enc_hybrid_mlkem.key", config.key_dir),
            );
            key_paths.insert(
                "public-ecdh-key".to_string(),
                format!("{}/public_enc_hybrid_ecdh.key", config.key_dir),
            );
            key_paths.insert(
                "private-ecdh-key".to_string(),
                format!("{}/private_enc_hybrid_ecdh.key", config.key_dir),
            );
        } else {
            key_paths.insert(
                "public-key".to_string(),
                format!(
                    "{}/public_enc_{}.key",
                    config.key_dir,
                    config.mode.to_string().to_lowercase()
                ),
            );
            key_paths.insert(
                "private-key".to_string(),
                format!(
                    "{}/private_enc_{}.key",
                    config.key_dir,
                    config.mode.to_string().to_lowercase()
                ),
            );
        }
        if config.use_tpm {
            key_paths.insert("use-tpm".to_string(), "true".to_string());
        }
        key_paths.insert("kem-algo".to_string(), config.pqc_kem_algo.clone());
        key_paths.insert("dsa-algo".to_string(), config.pqc_dsa_algo.clone());

        std::fs::create_dir_all(&config.key_dir)?;
        if let Some(ref s) = self.strategy {
            s.generate_encryption_key_pair(
                &key_paths,
                config.passphrase.as_deref().map(|x| x.as_str()),
                config.force,
            )
        } else {
            Err(CryptoError::Parameter(
                "Strategy not initialized".to_string(),
            ))
        }
    }

    pub fn generate_signing_key_pair(&self, config: &CryptoConfig) -> Result<()> {
        let mut key_paths = HashMap::new();
        key_paths.insert(
            "public-key".to_string(),
            format!(
                "{}/public_sign_{}.key",
                config.key_dir,
                config.mode.to_string().to_lowercase()
            ),
        );
        key_paths.insert(
            "private-key".to_string(),
            format!(
                "{}/private_sign_{}.key",
                config.key_dir,
                config.mode.to_string().to_lowercase()
            ),
        );
        if config.use_tpm {
            key_paths.insert("use-tpm".to_string(), "true".to_string());
        }
        key_paths.insert("kem-algo".to_string(), config.pqc_kem_algo.clone());
        key_paths.insert("dsa-algo".to_string(), config.pqc_dsa_algo.clone());

        std::fs::create_dir_all(&config.key_dir)?;
        if let Some(ref s) = self.strategy {
            s.generate_signing_key_pair(
                &key_paths,
                config.passphrase.as_deref().map(|x| x.as_str()),
                config.force,
            )
        } else {
            Err(CryptoError::Parameter(
                "Strategy not initialized".to_string(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::strategy::ecc::EccStrategy;
    use tempfile::tempdir;
    use std::fs;
    use std::sync::Arc;
    use crate::config::*;
    use std::collections::HashMap;
    use zeroize::Zeroizing;

    #[tokio::test]
    async fn test_streaming_decrypt_invariant_37_1_internal() {
        let dir = tempdir().unwrap();
        let input_path = dir.path().join("input.txt");
        let encrypted_path = dir.path().join("output.enc");
        let decrypted_path = dir.path().join("output.dec");
        let key_dir = dir.path().join("keys");
        fs::create_dir_all(&key_dir).unwrap();

        let mut processor = CryptoProcessor::new(CryptoMode::ECC);
        let mut key_paths = HashMap::new();
        key_paths.insert("recipient-pubkey".to_string(), key_dir.join("public_enc_ecc.key").to_str().unwrap().to_string());
        key_paths.insert("user-privkey".to_string(), key_dir.join("private_enc_ecc.key").to_str().unwrap().to_string());
        key_paths.insert("public-key".to_string(), key_dir.join("public_enc_ecc.key").to_str().unwrap().to_string());
        key_paths.insert("private-key".to_string(), key_dir.join("private_enc_ecc.key").to_str().unwrap().to_string());
        
        let mut strategy = Box::new(EccStrategy::new());
        // Non-empty dummy bypasses prompt
        strategy.generate_encryption_key_pair(&key_paths, Some("test"), true).unwrap();

        let content = vec![0u8; 1024];
        fs::write(&input_path, &content).unwrap();
        
        let config = CryptoConfig {
            operation: Operation::Encrypt,
            input_files: vec![input_path.to_str().unwrap().to_string()],
            output_file: Some(encrypted_path.to_str().unwrap().to_string()),
            recipient_pubkey: Some(key_dir.join("public_enc_ecc.key").to_str().unwrap().to_string()),
            passphrase: Some(Zeroizing::new("test".to_string())),
            key_dir: key_dir.to_str().unwrap().to_string(),
            force: true,
            mode: CryptoMode::ECC,
            ..CryptoConfig::default()
        };
        processor.process(&config, None).await.expect("Encryption failed");

        let mut dec_processor = CryptoProcessor::new(CryptoMode::ECC);
        let dec_config = CryptoConfig {
            operation: Operation::Decrypt,
            input_files: vec![encrypted_path.to_str().unwrap().to_string()],
            output_file: Some(decrypted_path.to_str().unwrap().to_string()),
            user_privkey: Some(key_dir.join("private_enc_ecc.key").to_str().unwrap().to_string()),
            passphrase: Some(Zeroizing::new("test".to_string())),
            key_dir: key_dir.to_str().unwrap().to_string(),
            force: true,
            mode: CryptoMode::ECC,
            ..CryptoConfig::default()
        };

        let dec_path_clone = decrypted_path.clone();
        let check_callback = Arc::new(move |progress| {
            let parent = dec_path_clone.parent().unwrap();
            let file_name = dec_path_clone.file_name().unwrap().to_str().unwrap();
            let prefix = format!("{}.tmp.", file_name);
            
            if progress < 0.5 {
                for entry in fs::read_dir(parent).unwrap() {
                    let entry = entry.unwrap();
                    if entry.file_name().to_str().unwrap().starts_with(&prefix) {
                        panic!("SECURITY VIOLATION (37-1): Temp file exists during Pass 1!");
                    }
                }
            }
        });

        dec_processor.process(&dec_config, Some(check_callback)).await.expect("Decryption failed");
        assert_eq!(fs::read(&decrypted_path).unwrap(), content);
    }
}
