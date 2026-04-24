use crate::config::{CryptoConfig, CryptoMode, Operation};
use crate::error::{CryptoError, Result};
use crate::strategy::CryptoStrategy;
use crate::strategy::ecc::EccStrategy;
use crate::strategy::pqc::PqcStrategy;
use crate::strategy::hybrid::HybridStrategy;
use crate::pipeline::ProgressCallback;
use crate::key::SharedKeyProvider;
use tokio::fs::File;
use std::collections::HashMap;
use std::path::Path;

pub struct CryptoProcessor {
    strategy: Box<dyn CryptoStrategy>,
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
            strategy,
            key_provider: None,
        }
    }

    pub fn set_key_provider(&mut self, provider: SharedKeyProvider) {
        self.key_provider = Some(provider.clone());
        self.strategy.set_key_provider(provider);
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

        self.strategy.prepare_signing(Path::new(priv_key_path), config.passphrase.as_deref(), &config.digest_algo)?;

        let total_size = tokio::fs::metadata(input_path).await?.len();
        let input_file = File::open(input_path).await?;
        let mut reader = tokio::io::BufReader::new(input_file);
        let mut buffer = vec![0u8; 64 * 1024];
        let mut total_read = 0u64;

        while total_read < total_size {
            let n = tokio::io::AsyncReadExt::read(&mut reader, &mut buffer).await?;
            if n == 0 { break; }
            self.strategy.update_hash(&buffer[..n])?;
            total_read += n as u64;
            if let Some(ref cb) = progress_callback {
                cb(total_read as f64 / total_size as f64);
            }
        }

        let signature = self.strategy.sign_hash()?;
        let header = self.strategy.serialize_signature_header();

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
        let header_size = self.strategy.deserialize_signature_header(&sig_data)?;
        let signature = &sig_data[header_size..];

        self.strategy.prepare_verification(Path::new(pub_key_path), &config.digest_algo)?;

        let total_size = tokio::fs::metadata(input_path).await?.len();
        let input_file = File::open(input_path).await?;
        let mut reader = tokio::io::BufReader::new(input_file);
        let mut buffer = vec![0u8; 64 * 1024];
        let mut total_read = 0u64;

        while total_read < total_size {
            let n = tokio::io::AsyncReadExt::read(&mut reader, &mut buffer).await?;
            if n == 0 { break; }
            self.strategy.update_hash(&buffer[..n])?;
            total_read += n as u64;
            if let Some(ref cb) = progress_callback {
                cb(total_read as f64 / total_size as f64);
            }
        }

        if self.strategy.verify_hash(signature)? {
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

        self.strategy.prepare_encryption(&key_paths)?;

        let output_file = File::create(output_path).await?;
        let header = self.strategy.serialize_header();
        
        let mut file = output_file;
        tokio::io::AsyncWriteExt::write_all(&mut file, &header).await?;

        let total_input_size = tokio::fs::metadata(input_path).await?.len();
        
        self.run_encryption_pipeline(input_path, file, total_input_size, progress_callback).await
    }

    async fn run_encryption_pipeline(&mut self, input_path: &str, mut output_file: File, total_input_size: u64, progress_callback: Option<ProgressCallback>) -> Result<()> {
        let input_file = File::open(input_path).await?;
        let mut reader = tokio::io::BufReader::new(input_file);
        let mut buffer = vec![0u8; 64 * 1024];
        let mut total_read = 0u64;

        while total_read < total_input_size {
            let n = tokio::io::AsyncReadExt::read(&mut reader, &mut buffer).await?;
            if n == 0 { break; }
            
            let encrypted = self.strategy.encrypt_transform(&buffer[..n])?;
            tokio::io::AsyncWriteExt::write_all(&mut output_file, &encrypted).await?;
            
            total_read += n as u64;
            if let Some(ref cb) = progress_callback {
                cb(total_read as f64 / total_input_size as f64);
            }
        }

        let final_block = self.strategy.finalize_encryption()?;
        if !final_block.is_empty() {
            tokio::io::AsyncWriteExt::write_all(&mut output_file, &final_block).await?;
        }
        
        Ok(())
    }

    pub async fn decrypt_file(&mut self, config: &CryptoConfig, progress_callback: Option<ProgressCallback>) -> Result<()> {
        let input_path = config.input_files.first().ok_or(CryptoError::Parameter("No input file".to_string()))?;
        let output_path = config.output_file.as_ref().ok_or(CryptoError::Parameter("No output file".to_string()))?;

        let total_size = tokio::fs::metadata(input_path).await?.len();
        let tag_size = self.strategy.get_tag_size() as u64;
        
        if total_size < tag_size {
            return Err(CryptoError::FileRead("File too small".to_string()));
        }

        let mut input_file = File::open(input_path).await?;
        
        // Read header to deserialize
        let mut header_peek = vec![0u8; 16384];
        let n = tokio::io::AsyncReadExt::read(&mut input_file, &mut header_peek).await?;
        header_peek.truncate(n);
        let header_size = self.strategy.deserialize_header(&header_peek)? as u64;

        // Read tag from the end
        let mut tag = vec![0u8; tag_size as usize];
        tokio::io::AsyncSeekExt::seek(&mut input_file, std::io::SeekFrom::End(-(tag_size as i64))).await?;
        tokio::io::AsyncReadExt::read_exact(&mut input_file, &mut tag).await?;

        let mut key_paths = HashMap::new();
        if let Some(ref p) = config.user_privkey { key_paths.insert("user-privkey".to_string(), p.clone()); }
        if let Some(ref p) = config.user_mlkem_privkey { key_paths.insert("recipient-mlkem-privkey".to_string(), p.clone()); }
        if let Some(ref p) = config.user_ecdh_privkey { key_paths.insert("recipient-ecdh-privkey".to_string(), p.clone()); }
        
        self.strategy.prepare_decryption(&key_paths, config.passphrase.as_deref())?;

        let mut output_file = File::create(output_path).await?;
        
        tokio::io::AsyncSeekExt::seek(&mut input_file, std::io::SeekFrom::Start(header_size)).await?;
        let ciphertext_size = total_size - header_size - tag_size;
        
        let mut reader = tokio::io::BufReader::new(input_file);
        let mut buffer = vec![0u8; 64 * 1024];
        let mut total_read = 0u64;

        while total_read < ciphertext_size {
            let to_read = std::cmp::min(buffer.len() as u64, ciphertext_size - total_read) as usize;
            let n = tokio::io::AsyncReadExt::read(&mut reader, &mut buffer[..to_read]).await?;
            if n == 0 { break; }
            
            let decrypted = self.strategy.decrypt_transform(&buffer[..n])?;
            tokio::io::AsyncWriteExt::write_all(&mut output_file, &decrypted).await?;
            
            total_read += n as u64;
            if let Some(ref cb) = progress_callback {
                cb(total_read as f64 / total_size as f64);
            }
        }

        self.strategy.finalize_decryption(&tag)?;
        tokio::io::AsyncWriteExt::flush(&mut output_file).await?;

        Ok(())
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
        self.strategy.generate_encryption_key_pair(&key_paths, config.passphrase.as_deref())
    }

    pub fn generate_signing_key_pair(&self, config: &CryptoConfig) -> Result<()> {
        let mut key_paths = HashMap::new();
        key_paths.insert("signing-public-key".to_string(), format!("{}/public_sign_{}.key", config.key_dir, config.mode.to_string().to_lowercase()));
        key_paths.insert("signing-private-key".to_string(), format!("{}/private_sign_{}.key", config.key_dir, config.mode.to_string().to_lowercase()));
        if config.use_tpm { key_paths.insert("use-tpm".to_string(), "true".to_string()); }

        std::fs::create_dir_all(&config.key_dir)?;
        self.strategy.generate_signing_key_pair(&key_paths, config.passphrase.as_deref())
    }
}
