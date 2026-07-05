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
use crate::strategy::streaming_aead as v3;
use crate::strategy::CryptoStrategy;
use rand_core::RngCore;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use zeroize::Zeroizing;

pub type ProgressCallback = Arc<dyn Fn(f64) + Send + Sync>;

const BUF_SIZE: usize = 1024 * 1024;

/// Open an output file for exclusive creation with owner-only permissions and
/// symlink protection. unix: 0600 + `O_NOFOLLOW`; on Windows those flags do not
/// exist, so it falls back to a plain exclusive create — the output directory's
/// ACLs provide owner access, but the symlink-swap TOCTOU guard is weaker there
/// (documented limitation).
fn open_secure_create<P: AsRef<Path>>(path: P) -> std::io::Result<std::fs::File> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    o.open(path)
}

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

        // All encryptions use the v3 chunked-AEAD format.
        // NKCT_V3_CHUNK_SIZE lets tests pick a small chunk size so the
        // boundary cases (file size = chunk_size etc.) stay cheap.
        let chunk_size = std::env::var("NKCT_V3_CHUNK_SIZE")
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(v3::V3_DEFAULT_CHUNK_SIZE);
        strategy.set_chunk_size(chunk_size);

        strategy.prepare_encryption(&key_paths)?;

        let header = strategy.serialize_header();
        let total_input_size = tokio::fs::metadata(input_path).await?.len();

        let input_path_str = input_path.to_string();
        let output_path_str = output_path.to_string();

        let sid = v3::compute_session_id(&header);
        strategy.set_file_session_id(sid);
        let chunk_size = strategy.chunk_size();
        let result = self
            .run_chunked_encrypt(
                strategy,
                input_path_str,
                output_path_str,
                header,
                total_input_size,
                chunk_size,
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

        let mut input_file = File::open(input_path).await?;
        let mut header_peek = vec![0u8; 16384];
        let n = input_file.read(&mut header_peek).await?;
        header_peek.truncate(n);
        let header_size_usize = strategy.deserialize_header(&header_peek)?;
        let header_size = header_size_usize as u64;

        // Compute file session id from the exact header bytes (v3).
        let sid = v3::compute_session_id(&header_peek[..header_size_usize]);
        strategy.set_file_session_id(sid);

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

        let chunk_size = strategy.chunk_size();
        let body_size = total_size
            .checked_sub(header_size)
            .ok_or_else(|| CryptoError::FileRead("File too small for header".to_string()))?;
        let result = self
            .run_chunked_decrypt(
                strategy,
                input_path_str,
                output_path_str,
                header_size,
                body_size,
                chunk_size,
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

    // allow(clippy::too_many_arguments): each parameter is a distinct, required
    // crypto input (strategy/paths/sizes/tag/flags); bundling into a struct adds
    // field-swap risk in security-critical code for no functional benefit.
    // Future: revisit only if a cohesive context type emerges naturally.
    #[allow(clippy::too_many_arguments)]
    async fn run_chunked_encrypt(
        &self,
        mut strategy: Box<dyn CryptoStrategy>,
        input_path: String,
        output_path: String,
        header: Vec<u8>,
        total_input_size: u64,
        chunk_size: u32,
        force: bool,
        progress_callback: Option<ProgressCallback>,
    ) -> Result<Box<dyn CryptoStrategy>> {
        let cb_clone = progress_callback.clone();
        tokio::task::spawn_blocking(move || {
            use std::io::{BufReader, BufWriter, Write};

            if chunk_size == 0 {
                return Err(CryptoError::Parameter("chunk_size must be > 0".to_string()));
            }
            let chunk_size_usize = chunk_size as usize;

            let in_file = std::fs::File::open(&input_path)
                .map_err(|e| CryptoError::FileRead(e.to_string()))?;
            let mut reader = BufReader::with_capacity(BUF_SIZE * 4, in_file);

            if force {
                let _ = std::fs::remove_file(&output_path);
            }
            let out_file = open_secure_create(&output_path)
                .map_err(|e| CryptoError::FileWrite(e.to_string()))?;
            let mut writer = BufWriter::with_capacity(BUF_SIZE * 4, out_file);

            writer
                .write_all(&header)
                .map_err(|e| CryptoError::FileWrite(e.to_string()))?;

            // One-chunk lookahead with two reusable buffers: we read the
            // *next* chunk to learn whether the current one is final, then
            // swap the buffers instead of copying. This avoids a per-chunk
            // heap allocation and a per-chunk plaintext memcpy/zeroize, which
            // dominate v3's overhead on large files. Both buffers are
            // `Zeroizing`, so any plaintext tail left in spare capacity is
            // wiped on drop. For empty input we emit one empty final chunk.
            let mut cur: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; chunk_size_usize]);
            let mut nxt: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; chunk_size_usize]);
            let mut total_processed: u64 = 0;

            // Fills `buf` from `reader` up to its length, returning the number
            // of bytes read (short only at EOF).
            fn fill_chunk<R: std::io::Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize> {
                let mut filled = 0usize;
                while filled < buf.len() {
                    let n = reader
                        .read(&mut buf[filled..])
                        .map_err(|e| CryptoError::FileRead(e.to_string()))?;
                    if n == 0 {
                        break;
                    }
                    filled += n;
                }
                Ok(filled)
            }

            let mut cur_len = fill_chunk(&mut reader, &mut cur)?;
            loop {
                let nxt_len = fill_chunk(&mut reader, &mut nxt)?;
                let is_final = nxt_len == 0;

                let ct = strategy.encrypt_chunk_v3(&cur[..cur_len], is_final)?;
                writer
                    .write_all(&ct)
                    .map_err(|e| CryptoError::FileWrite(e.to_string()))?;

                total_processed += cur_len as u64;
                if let Some(ref cb) = cb_clone {
                    if total_input_size > 0 {
                        cb(total_processed as f64 / total_input_size as f64);
                    }
                }

                if is_final {
                    break;
                }
                std::mem::swap(&mut cur, &mut nxt);
                cur_len = nxt_len;
            }

            writer
                .flush()
                .map_err(|e| CryptoError::FileWrite(e.to_string()))?;
            Ok::<Box<dyn CryptoStrategy>, CryptoError>(strategy)
        })
        .await
        .map_err(|e| CryptoError::OpenSSL(format!("Blocking task failed: {}", e)))?
    }

    // allow(clippy::too_many_arguments): each parameter is a distinct, required
    // crypto input (strategy/paths/sizes/tag/flags); bundling into a struct adds
    // field-swap risk in security-critical code for no functional benefit.
    // Future: revisit only if a cohesive context type emerges naturally.
    #[allow(clippy::too_many_arguments)]
    async fn run_chunked_decrypt(
        &self,
        mut strategy: Box<dyn CryptoStrategy>,
        input_path: String,
        output_path: String,
        header_size: u64,
        body_size: u64,
        chunk_size: u32,
        force: bool,
        progress_callback: Option<ProgressCallback>,
    ) -> Result<Box<dyn CryptoStrategy>> {
        let temp_output_path = format!("{}.tmp.{}", output_path, rand_core::OsRng.next_u64());
        let temp_output_path_clone = temp_output_path.clone();

        let cb_clone = progress_callback.clone();
        let res = tokio::task::spawn_blocking(move || {
            use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};

            if chunk_size == 0 {
                return Err(CryptoError::Parameter("chunk_size must be > 0".to_string()));
            }
            let chunk_size_usize = chunk_size as usize;
            let tag_len = v3::V3_TAG_LEN;
            let max_chunk_wire = chunk_size_usize.saturating_add(tag_len);
            if body_size < tag_len as u64 {
                return Err(CryptoError::FileRead(
                    "v3 body too small for even one tag".to_string(),
                ));
            }

            // Pass 1: verify every chunk, write nothing to disk.
            // Then Pass 2: re-derive, write decrypted plaintext to a temp
            // file under the AEAD authentication.
            // Open the input exactly once and rewind between passes. Reusing a
            // single file descriptor guarantees Pass 2 decrypts the very bytes
            // Pass 1 authenticated: a file swapped on disk between the passes
            // cannot affect an already-open fd (it keeps referencing the
            // original inode), so the TOCTOU window a second open() would
            // create is eliminated.
            let mut in_file = std::fs::File::open(&input_path)
                .map_err(|e| CryptoError::FileRead(e.to_string()))?;

            let run_pass = |verify_only: bool,
                            strategy: &mut Box<dyn CryptoStrategy>,
                            cb_offset: f64,
                            in_file: &mut std::fs::File|
             -> Result<()> {
                in_file
                    .seek(SeekFrom::Start(header_size))
                    .map_err(|e| CryptoError::FileRead(e.to_string()))?;
                let mut reader = BufReader::with_capacity(BUF_SIZE * 4, &*in_file);

                let mut writer: Option<BufWriter<std::fs::File>> = if verify_only {
                    None
                } else {
                    let out_file = open_secure_create(&temp_output_path_clone)
                        .map_err(|e| CryptoError::FileWrite(e.to_string()))?;
                    Some(BufWriter::with_capacity(BUF_SIZE * 4, out_file))
                };

                let mut buf: Vec<u8> = vec![0u8; max_chunk_wire];
                // Reused across chunks so we pay one allocation + one
                // drop-time zeroize per pass instead of per chunk. Holds the
                // decrypted plaintext of the current chunk only.
                let mut pt: Zeroizing<Vec<u8>> =
                    Zeroizing::new(Vec::with_capacity(chunk_size_usize));
                let mut bytes_remaining = body_size;
                let mut final_seen = false;
                let mut total_read: u64 = 0;

                while bytes_remaining > 0 {
                    let to_read =
                        std::cmp::min(bytes_remaining, max_chunk_wire as u64) as usize;
                    reader
                        .read_exact(&mut buf[..to_read])
                        .map_err(|e| CryptoError::FileRead(e.to_string()))?;
                    bytes_remaining -= to_read as u64;

                    let is_final_chunk = bytes_remaining == 0;
                    if !is_final_chunk && to_read != max_chunk_wire {
                        return Err(CryptoError::FileRead(
                            "v3 intermediate chunk has wrong length".to_string(),
                        ));
                    }
                    if to_read < tag_len {
                        return Err(CryptoError::FileRead(
                            "v3 chunk shorter than AEAD tag".to_string(),
                        ));
                    }

                    strategy
                        .decrypt_chunk_v3_into(&buf[..to_read], is_final_chunk, &mut pt)?;
                    if is_final_chunk {
                        final_seen = true;
                    }
                    if let Some(w) = writer.as_mut() {
                        w.write_all(&pt)
                            .map_err(|e| CryptoError::FileWrite(e.to_string()))?;
                    }

                    total_read += to_read as u64;
                    if let Some(ref cb) = cb_clone {
                        if body_size > 0 {
                            let frac = total_read as f64 / body_size as f64;
                            cb(cb_offset + frac * 0.5);
                        }
                    }
                }

                if !final_seen {
                    return Err(CryptoError::TruncationDetected);
                }
                if let Some(mut w) = writer {
                    w.flush().map_err(|e| CryptoError::FileWrite(e.to_string()))?;
                }
                Ok(())
            };

            // Pass 1: verify only (no temp file is created yet — this
            // preserves the THREAT 37-1 invariant that disk writes never
            // start before AEAD authentication has succeeded end-to-end).
            run_pass(true, &mut strategy, 0.0, &mut in_file)?;
            // Pass 2: replay with chunk counter reset to 0, writing the
            // authenticated plaintext to the temporary output file.
            strategy.reset_chunk_counter();
            run_pass(false, &mut strategy, 0.5, &mut in_file)?;

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
                std::fs::rename(&temp_output_path, &output_path).map_err(|e| {
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
        
        let strategy = Box::new(EccStrategy::new());
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
