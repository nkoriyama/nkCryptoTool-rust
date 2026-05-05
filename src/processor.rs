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
use std::path::Path;
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

pub type ProgressCallback = Arc<dyn Fn(f64) + Send + Sync>;

const BUF_SIZE: usize = 1024 * 1024;

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
            _ => Err(CryptoError::Parameter("Unsupported operation".to_string())),
        }
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
            .ok_or(CryptoError::Parameter("No input file".to_string()))?;
        let signature_path = config
            .signature_file
            .as_ref()
            .ok_or(CryptoError::Parameter(
                "No signature output path".to_string(),
            ))?;
        let priv_key_path = config
            .signing_privkey
            .as_ref()
            .ok_or(CryptoError::Parameter("No signing private key".to_string()))?;

        let mut strategy = self.strategy.take().ok_or(CryptoError::Parameter(
            "Strategy not initialized".to_string(),
        ))?;
        strategy.prepare_signing(Path::new(priv_key_path), passphrase, &config.digest_algo)?;

        let mut file = tokio::fs::File::open(input_path)
            .await
            .map_err(|e| CryptoError::FileRead(e.to_string()))?;
        let metadata = file
            .metadata()
            .await
            .map_err(|e| CryptoError::FileRead(e.to_string()))?;
        let total_size = metadata.len();
        let mut buffer = vec![0u8; BUF_SIZE];
        let mut current_size = 0u64;

        loop {
            let n = file
                .read(&mut buffer)
                .await
                .map_err(|e| CryptoError::FileRead(e.to_string()))?;
            if n == 0 {
                break;
            }
            strategy.update_hash(&buffer[..n])?;
            current_size += n as u64;
            if let Some(ref cb) = progress_callback {
                if total_size > 0 {
                    cb(current_size as f64 / total_size as f64 * 0.9);
                }
            }
        }

        let signature = strategy.sign_hash()?;
        if let Some(ref cb) = progress_callback {
            cb(1.0);
        }

        let header = strategy.serialize_signature_header();
        self.strategy = Some(strategy);

        crate::utils::secure_write(signature_path, {
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
            .ok_or(CryptoError::Parameter("No input file".to_string()))?;
        let signature_path = config
            .signature_file
            .as_ref()
            .ok_or(CryptoError::Parameter("No signature file".to_string()))?;
        let pub_key_path = config
            .signing_pubkey
            .as_ref()
            .ok_or(CryptoError::Parameter("No signing public key".to_string()))?;

        let sig_data = std::fs::read(signature_path)?;
        let mut strategy = self.strategy.take().ok_or(CryptoError::Parameter(
            "Strategy not initialized".to_string(),
        ))?;
        let header_size = strategy.deserialize_signature_header(&sig_data)?;
        let signature = sig_data[header_size..].to_vec();

        strategy.prepare_verification(Path::new(pub_key_path), &config.digest_algo)?;

        let mut file = tokio::fs::File::open(input_path)
            .await
            .map_err(|e| CryptoError::FileRead(e.to_string()))?;
        let metadata = file
            .metadata()
            .await
            .map_err(|e| CryptoError::FileRead(e.to_string()))?;
        let total_size = metadata.len();
        let mut buffer = vec![0u8; BUF_SIZE];
        let mut current_size = 0u64;

        loop {
            let n = file
                .read(&mut buffer)
                .await
                .map_err(|e| CryptoError::FileRead(e.to_string()))?;
            if n == 0 {
                break;
            }
            strategy.update_hash(&buffer[..n])?;
            current_size += n as u64;
            if let Some(ref cb) = progress_callback {
                if total_size > 0 {
                    cb(current_size as f64 / total_size as f64 * 0.9);
                }
            }
        }

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
            .run_pipelined_encrypt(
                strategy,
                input_path_str,
                output_path_str,
                header,
                total_input_size,
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
            .run_pipelined_decrypt(
                strategy,
                input_path_str,
                output_path_str,
                header_size,
                ciphertext_size,
                tag,
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

    async fn run_pipelined_encrypt(
        &self,
        mut strategy: Box<dyn CryptoStrategy>,
        input_path: String,
        output_path: String,
        header: Vec<u8>,
        total_input_size: u64,
        progress_callback: Option<ProgressCallback>,
    ) -> Result<Box<dyn CryptoStrategy>> {
        let (tx_crypto, mut rx_crypto) = mpsc::channel::<(u64, Zeroizing<Vec<u8>>)>(32);
        let (tx_writer, mut rx_writer) = mpsc::channel::<(u64, Zeroizing<Vec<u8>>)>(32);

        let reader_handle = tokio::spawn(async move {
            let file = File::open(&input_path)
                .await
                .map_err(|e| CryptoError::FileRead(e.to_string()))?;
            let mut reader = BufReader::with_capacity(BUF_SIZE, file);
            let mut total_read = 0u64;
            let mut chunk_idx = 0u64;

            loop {
                let mut buffer = Zeroizing::new(vec![0u8; BUF_SIZE]);
                let n = reader
                    .read(&mut buffer)
                    .await
                    .map_err(|e| CryptoError::FileRead(e.to_string()))?;
                if n == 0 {
                    break;
                }
                if n < BUF_SIZE {
                    buffer.truncate(n);
                }
                if tx_crypto.send((chunk_idx, buffer)).await.is_err() {
                    break;
                }
                total_read += n as u64;
                chunk_idx += 1;
                if total_read >= total_input_size {
                    break;
                }
            }
            Ok::<(), CryptoError>(())
        });

        let crypto_task = tokio::spawn(async move {
            while let Some((idx, data)) = rx_crypto.recv().await {
                let out = strategy.encrypt_transform(&data)?;
                if tx_writer.send((idx, out)).await.is_err() {
                    break;
                }
            }
            let final_block = strategy.finalize_encryption()?;
            if !final_block.is_empty() {
                tx_writer
                    .send((u64::MAX, Zeroizing::new(final_block)))
                    .await
                    .ok();
            }
            Ok::<Box<dyn CryptoStrategy>, CryptoError>(strategy)
        });

        let output_path_clone = output_path.clone();
        let writer_handle = tokio::spawn(async move {
            let mut file = tokio::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&output_path_clone)
                .await
                .map_err(|e| CryptoError::FileWrite(e.to_string()))?;
            file.write_all(&header)
                .await
                .map_err(|e| CryptoError::FileWrite(e.to_string()))?;

            let mut total_written = 0u64;
            while let Some((_, data)) = rx_writer.recv().await {
                file.write_all(&data)
                    .await
                    .map_err(|e| CryptoError::FileWrite(e.to_string()))?;
                total_written += data.len() as u64;
                if let Some(ref cb) = progress_callback {
                    cb(total_written as f64 / total_input_size as f64);
                }
            }
            file.flush()
                .await
                .map_err(|e| CryptoError::FileWrite(e.to_string()))?;
            Ok::<(), CryptoError>(())
        });

        let (r1, r2, r3) = tokio::try_join!(reader_handle, crypto_task, writer_handle)
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;

        if let Err(e) = r1.and(r3) {
            tokio::fs::remove_file(&output_path).await.ok();
            return Err(e);
        }

        match r2 {
            Ok(s) => Ok(s),
            Err(e) => {
                tokio::fs::remove_file(&output_path).await.ok();
                Err(e)
            }
        }
    }

    async fn run_pipelined_decrypt(
        &self,
        mut strategy: Box<dyn CryptoStrategy>,
        input_path: String,
        output_path: String,
        header_size: u64,
        ciphertext_size: u64,
        tag: Vec<u8>,
        progress_callback: Option<ProgressCallback>,
    ) -> Result<Box<dyn CryptoStrategy>> {
        let (tx_crypto, mut rx_crypto) = mpsc::channel::<(u64, Zeroizing<Vec<u8>>)>(32);
        let (tx_writer, mut rx_writer) = mpsc::channel::<(u64, Zeroizing<Vec<u8>>)>(32);

        let reader_handle = tokio::spawn(async move {
            let mut file = File::open(&input_path)
                .await
                .map_err(|e| CryptoError::FileRead(e.to_string()))?;
            file.seek(std::io::SeekFrom::Start(header_size))
                .await
                .map_err(|e| CryptoError::FileRead(e.to_string()))?;
            let mut reader = BufReader::with_capacity(BUF_SIZE, file);
            let mut total_read = 0u64;
            let mut chunk_idx = 0u64;

            while total_read < ciphertext_size {
                let to_read = std::cmp::min(BUF_SIZE as u64, ciphertext_size - total_read) as usize;
                let mut buffer = Zeroizing::new(vec![0u8; to_read]);
                let n = reader
                    .read_exact(&mut buffer)
                    .await
                    .map_err(|e| CryptoError::FileRead(e.to_string()))?;
                if tx_crypto.send((chunk_idx, buffer)).await.is_err() {
                    break;
                }
                total_read += n as u64;
                chunk_idx += 1;
            }
            Ok::<(), CryptoError>(())
        });

        let crypto_task = tokio::spawn(async move {
            while let Some((idx, data)) = rx_crypto.recv().await {
                let out = strategy.decrypt_transform(&data)?;
                if tx_writer.send((idx, out)).await.is_err() {
                    break;
                }
            }
            strategy.finalize_decryption(&tag)?;
            Ok::<Box<dyn CryptoStrategy>, CryptoError>(strategy)
        });

        let temp_output_path = format!("{}.tmp.{}", output_path, rand_core::OsRng.next_u64());
        let temp_output_path_clone = temp_output_path.clone();
        let writer_handle = tokio::spawn(async move {
            let mut file = tokio::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&temp_output_path_clone)
                .await
                .map_err(|e| CryptoError::FileWrite(e.to_string()))?;
            let mut total_written = 0u64;
            while let Some((_, data)) = rx_writer.recv().await {
                file.write_all(&data)
                    .await
                    .map_err(|e| CryptoError::FileWrite(e.to_string()))?;
                total_written += data.len() as u64;
                if let Some(ref cb) = progress_callback {
                    cb(total_written as f64 / ciphertext_size as f64);
                }
            }
            file.flush()
                .await
                .map_err(|e| CryptoError::FileWrite(e.to_string()))?;
            Ok::<(), CryptoError>(())
        });

        let (r1, r2, r3) =
            tokio::try_join!(reader_handle, crypto_task, writer_handle).map_err(|e| {
                let _ = std::fs::remove_file(&temp_output_path);
                CryptoError::OpenSSL(e.to_string())
            })?;

        if let Err(e) = r1.and(r3) {
            let _ = std::fs::remove_file(&temp_output_path);
            return Err(e);
        }

        match r2 {
            Ok(s) => {
                tokio::fs::rename(&temp_output_path, &output_path)
                    .await
                    .map_err(|e| CryptoError::FileWrite(e.to_string()))?;
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
            "signing-public-key".to_string(),
            format!(
                "{}/public_sign_{}.key",
                config.key_dir,
                config.mode.to_string().to_lowercase()
            ),
        );
        key_paths.insert(
            "signing-private-key".to_string(),
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
