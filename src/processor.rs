use crate::config::{CryptoConfig, CryptoMode, Operation};
use crate::error::{CryptoError, Result};
use crate::strategy::CryptoStrategy;
use crate::strategy::ecc::EccStrategy;
use crate::strategy::pqc::PqcStrategy;
use crate::strategy::hybrid::HybridStrategy;
use crate::pipeline::ProgressCallback;
use crate::key::SharedKeyProvider;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt, AsyncSeekExt, BufReader};
use tokio::sync::mpsc;
use std::collections::HashMap;
use std::path::Path;

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

    pub async fn process(&mut self, config: &CryptoConfig, progress_callback: Option<ProgressCallback>) -> Result<()> {
        match config.operation {
            Operation::Encrypt => self.encrypt_file(config, progress_callback).await,
            Operation::Decrypt => self.decrypt_file(config, progress_callback).await,
            Operation::Sign => self.sign_file(config, progress_callback).await,
            Operation::Verify => self.verify_file(config, progress_callback).await,
            Operation::GenerateEncKey => self.generate_encryption_key_pair(config),
            Operation::GenerateSignKey => self.generate_signing_key_pair(config),
            _ => Err(CryptoError::Parameter("Unsupported operation".to_string())),
        }
    }

    pub async fn sign_file(&mut self, config: &CryptoConfig, progress_callback: Option<ProgressCallback>) -> Result<()> {
        let input_path = config.input_files.first().ok_or(CryptoError::Parameter("No input file".to_string()))?;
        let signature_path = config.signature_file.as_ref().ok_or(CryptoError::Parameter("No signature output path".to_string()))?;
        let priv_key_path = config.signing_privkey.as_ref().ok_or(CryptoError::Parameter("No signing private key".to_string()))?;

        let strategy = self.strategy.as_mut().ok_or(CryptoError::Parameter("Strategy not initialized".to_string()))?;
        strategy.prepare_signing(Path::new(priv_key_path), config.passphrase.as_deref(), &config.digest_algo)?;

        let total_size = tokio::fs::metadata(input_path).await?.len();
        let input_file = File::open(input_path).await?;
        let mut reader = BufReader::new(input_file);
        let mut buffer = vec![0u8; 64 * 1024];
        let mut total_read = 0u64;

        while total_read < total_size {
            let n = reader.read(&mut buffer).await?;
            if n == 0 { break; }
            strategy.update_hash(&buffer[..n])?;
            total_read += n as u64;
            if let Some(ref cb) = progress_callback {
                cb(total_read as f64 / total_size as f64);
            }
        }

        let signature = strategy.sign_hash()?;
        let header = strategy.serialize_signature_header();

        let mut output_file = std::fs::File::create(signature_path)?;
        use std::io::Write;
        output_file.write_all(&header)?;
        output_file.write_all(&signature)?;

        Ok(())
    }

    pub async fn verify_file(&mut self, config: &CryptoConfig, progress_callback: Option<ProgressCallback>) -> Result<()> {
        let input_path = config.input_files.first().ok_or(CryptoError::Parameter("No input file".to_string()))?;
        let signature_path = config.signature_file.as_ref().ok_or(CryptoError::Parameter("No signature file".to_string()))?;
        let pub_key_path = config.signing_pubkey.as_ref().ok_or(CryptoError::Parameter("No signing public key".to_string()))?;

        let sig_data = std::fs::read(signature_path)?;
        let strategy = self.strategy.as_mut().ok_or(CryptoError::Parameter("Strategy not initialized".to_string()))?;
        let header_size = strategy.deserialize_signature_header(&sig_data)?;
        let signature = &sig_data[header_size..];

        strategy.prepare_verification(Path::new(pub_key_path), &config.digest_algo)?;

        let total_size = tokio::fs::metadata(input_path).await?.len();
        let input_file = File::open(input_path).await?;
        let mut reader = BufReader::new(input_file);
        let mut buffer = vec![0u8; 64 * 1024];
        let mut total_read = 0u64;

        while total_read < total_size {
            let n = reader.read(&mut buffer).await?;
            if n == 0 { break; }
            strategy.update_hash(&buffer[..n])?;
            total_read += n as u64;
            if let Some(ref cb) = progress_callback {
                cb(total_read as f64 / total_size as f64);
            }
        }

        if strategy.verify_hash(signature)? {
            println!("Signature verified successfully.");
            Ok(())
        } else {
            Err(CryptoError::SignatureVerification)
        }
    }

    pub async fn encrypt_file(&mut self, config: &CryptoConfig, progress_callback: Option<ProgressCallback>) -> Result<()> {
        let input_path = config.input_files.first().ok_or(CryptoError::Parameter("No input file".to_string()))?;
        let output_path = config.output_file.as_ref().ok_or(CryptoError::Parameter("No output file".to_string()))?;
        
        let mut key_paths = HashMap::new();
        if let Some(ref p) = config.recipient_pubkey { key_paths.insert("recipient-pubkey".to_string(), p.clone()); }
        if let Some(ref p) = config.recipient_mlkem_pubkey { key_paths.insert("recipient-mlkem-pubkey".to_string(), p.clone()); }
        if let Some(ref p) = config.recipient_ecdh_pubkey { key_paths.insert("recipient-ecdh-pubkey".to_string(), p.clone()); }
        key_paths.insert("digest-algo".to_string(), config.digest_algo.clone());

        let mut strategy = self.strategy.take().ok_or(CryptoError::Parameter("Strategy already in use".to_string()))?;
        strategy.prepare_encryption(&key_paths)?;

        let header = strategy.serialize_header();
        let total_input_size = tokio::fs::metadata(input_path).await?.len();
        
        let input_path_str = input_path.to_string();
        let output_path_str = output_path.to_string();
        
        // Pipelined Implementation
        let result = self.run_pipelined_op(
            strategy, 
            input_path_str, 
            output_path_str, 
            Some(header), 
            total_input_size, 
            true, 
            progress_callback
        ).await;

        match result {
            Ok(s) => {
                self.strategy = Some(s);
                Ok(())
            },
            Err(e) => Err(e)
        }
    }

    pub async fn decrypt_file(&mut self, config: &CryptoConfig, progress_callback: Option<ProgressCallback>) -> Result<()> {
        let input_path = config.input_files.first().ok_or(CryptoError::Parameter("No input file".to_string()))?;
        let output_path = config.output_file.as_ref().ok_or(CryptoError::Parameter("No output file".to_string()))?;

        let total_size = tokio::fs::metadata(input_path).await?.len();
        let mut strategy = self.strategy.take().ok_or(CryptoError::Parameter("Strategy already in use".to_string()))?;
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
        input_file.seek(std::io::SeekFrom::End(-(tag_size as i64))).await?;
        input_file.read_exact(&mut tag).await?;

        let mut key_paths = HashMap::new();
        if let Some(ref p) = config.user_privkey { key_paths.insert("user-privkey".to_string(), p.clone()); }
        if let Some(ref p) = config.user_mlkem_privkey { key_paths.insert("recipient-mlkem-privkey".to_string(), p.clone()); }
        if let Some(ref p) = config.user_ecdh_privkey { key_paths.insert("recipient-ecdh-privkey".to_string(), p.clone()); }
        
        strategy.prepare_decryption(&key_paths, config.passphrase.as_deref())?;

        let input_path_str = input_path.to_string();
        let output_path_str = output_path.to_string();
        let ciphertext_size = total_size - header_size - tag_size;

        let result = self.run_pipelined_decrypt(
            strategy,
            input_path_str,
            output_path_str,
            header_size,
            ciphertext_size,
            tag,
            progress_callback
        ).await;

        match result {
            Ok(s) => {
                self.strategy = Some(s);
                Ok(())
            },
            Err(e) => Err(e)
        }
    }

    async fn run_pipelined_op(
        &self,
        mut strategy: Box<dyn CryptoStrategy>,
        input_path: String,
        output_path: String,
        header: Option<Vec<u8>>,
        total_input_size: u64,
        is_encrypt: bool,
        progress_callback: Option<ProgressCallback>
    ) -> Result<Box<dyn CryptoStrategy>> {
        let (tx_crypto, mut rx_crypto) = mpsc::channel::<(u64, Vec<u8>)>(32);
        let (tx_writer, mut rx_writer) = mpsc::channel::<(u64, Vec<u8>)>(32);

        // 1. Reader Task
        let reader_handle = tokio::spawn(async move {
            let file = File::open(&input_path).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
            let mut reader = BufReader::new(file);
            let mut total_read = 0u64;
            let mut chunk_idx = 0u64;
            
            loop {
                let mut buffer = vec![0u8; 64 * 1024];
                let n = reader.read(&mut buffer).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
                if n == 0 { break; }
                buffer.truncate(n);
                if tx_crypto.send((chunk_idx, buffer)).await.is_err() { break; }
                total_read += n as u64;
                chunk_idx += 1;
                if total_read >= total_input_size { break; }
            }
            Ok::<(), CryptoError>(())
        });

        // 2. Crypto Task
        let crypto_task = tokio::spawn(async move {
            while let Some((idx, data)) = rx_crypto.recv().await {
                let out = if is_encrypt {
                    strategy.encrypt_transform(&data)?
                } else {
                    strategy.decrypt_transform(&data)?
                };
                if tx_writer.send((idx, out)).await.is_err() { break; }
            }
            
            // Finalize
            let final_block = if is_encrypt {
                strategy.finalize_encryption()?
            } else {
                // Decryption finalization happens in the writer with the tag
                Vec::new()
            };
            if !final_block.is_empty() {
                tx_writer.send((u64::MAX, final_block)).await.ok();
            }
            Ok::<Box<dyn CryptoStrategy>, CryptoError>(strategy)
        });

        // 3. Writer Task
        let writer_handle = tokio::spawn(async move {
            let mut file = File::create(&output_path).await.map_err(|e| CryptoError::FileWrite(e.to_string()))?;
            if let Some(h) = header {
                file.write_all(&h).await.map_err(|e| CryptoError::FileWrite(e.to_string()))?;
            }
            
            let mut total_written = 0u64;
            while let Some((_, data)) = rx_writer.recv().await {
                file.write_all(&data).await.map_err(|e| CryptoError::FileWrite(e.to_string()))?;
                total_written += data.len() as u64;
                if let Some(ref cb) = progress_callback {
                    cb(total_written as f64 / total_input_size as f64);
                }
            }
            file.flush().await.map_err(|e| CryptoError::FileWrite(e.to_string()))?;
            Ok::<(), CryptoError>(())
        });

        let (r1, r2, r3) = tokio::try_join!(reader_handle, crypto_task, writer_handle)
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;

        r1?; r3?;
        Ok(r2?)
    }

    async fn run_pipelined_decrypt(
        &self,
        mut strategy: Box<dyn CryptoStrategy>,
        input_path: String,
        output_path: String,
        header_size: u64,
        ciphertext_size: u64,
        tag: Vec<u8>,
        progress_callback: Option<ProgressCallback>
    ) -> Result<Box<dyn CryptoStrategy>> {
        let (tx_crypto, mut rx_crypto) = mpsc::channel::<(u64, Vec<u8>)>(32);
        let (tx_writer, mut rx_writer) = mpsc::channel::<(u64, Vec<u8>)>(32);

        let reader_handle = tokio::spawn(async move {
            let mut file = File::open(&input_path).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
            file.seek(std::io::SeekFrom::Start(header_size)).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
            let mut reader = BufReader::new(file);
            let mut total_read = 0u64;
            let mut chunk_idx = 0u64;
            
            while total_read < ciphertext_size {
                let to_read = std::cmp::min(64 * 1024, ciphertext_size - total_read) as usize;
                let mut buffer = vec![0u8; to_read];
                let n = reader.read_exact(&mut buffer).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
                if tx_crypto.send((chunk_idx, buffer)).await.is_err() { break; }
                total_read += n as u64;
                chunk_idx += 1;
            }
            Ok::<(), CryptoError>(())
        });

        let crypto_task = tokio::spawn(async move {
            while let Some((idx, data)) = rx_crypto.recv().await {
                let out = strategy.decrypt_transform(&data)?;
                if tx_writer.send((idx, out)).await.is_err() { break; }
            }
            // Tag verification
            strategy.finalize_decryption(&tag)?;
            Ok::<Box<dyn CryptoStrategy>, CryptoError>(strategy)
        });

        let writer_handle = tokio::spawn(async move {
            let mut file = File::create(&output_path).await.map_err(|e| CryptoError::FileWrite(e.to_string()))?;
            let mut total_written = 0u64;
            while let Some((_, data)) = rx_writer.recv().await {
                file.write_all(&data).await.map_err(|e| CryptoError::FileWrite(e.to_string()))?;
                total_written += data.len() as u64;
                if let Some(ref cb) = progress_callback {
                    cb(total_written as f64 / ciphertext_size as f64);
                }
            }
            file.flush().await.map_err(|e| CryptoError::FileWrite(e.to_string()))?;
            Ok::<(), CryptoError>(())
        });

        let (r1, r2, r3) = tokio::try_join!(reader_handle, crypto_task, writer_handle)
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;

        r1?; r3?;
        Ok(r2?)
    }

    pub fn generate_encryption_key_pair(&self, config: &CryptoConfig) -> Result<()> {
        let mut key_paths = HashMap::new();
        if config.mode == CryptoMode::Hybrid {
            key_paths.insert("public-mlkem-key".to_string(), format!("{}/public_enc_hybrid_mlkem.key", config.key_dir));
            key_paths.insert("private-mlkem-key".to_string(), format!("{}/private_enc_hybrid_mlkem.key", config.key_dir));
            key_paths.insert("public-ecdh-key".to_string(), format!("{}/public_enc_hybrid_ecdh.key", config.key_dir));
            key_paths.insert("private-ecdh-key".to_string(), format!("{}/private_enc_hybrid_ecdh.key", config.key_dir));
        } else {
            key_paths.insert("public-key".to_string(), format!("{}/public_enc_{}.key", config.key_dir, config.mode.to_string().to_lowercase()));
            key_paths.insert("private-key".to_string(), format!("{}/private_enc_{}.key", config.key_dir, config.mode.to_string().to_lowercase()));
        }
        if config.use_tpm { key_paths.insert("use-tpm".to_string(), "true".to_string()); }

        std::fs::create_dir_all(&config.key_dir)?;
        if let Some(ref s) = self.strategy {
            s.generate_encryption_key_pair(&key_paths, config.passphrase.as_deref())
        } else {
            Err(CryptoError::Parameter("Strategy not initialized".to_string()))
        }
    }

    pub fn generate_signing_key_pair(&self, config: &CryptoConfig) -> Result<()> {
        let mut key_paths = HashMap::new();
        key_paths.insert("signing-public-key".to_string(), format!("{}/public_sign_{}.key", config.key_dir, config.mode.to_string().to_lowercase()));
        key_paths.insert("signing-private-key".to_string(), format!("{}/private_sign_{}.key", config.key_dir, config.mode.to_string().to_lowercase()));
        if config.use_tpm { key_paths.insert("use-tpm".to_string(), "true".to_string()); }

        std::fs::create_dir_all(&config.key_dir)?;
        if let Some(ref s) = self.strategy {
            s.generate_signing_key_pair(&key_paths, config.passphrase.as_deref())
        } else {
            Err(CryptoError::Parameter("Strategy not initialized".to_string()))
        }
    }
}
