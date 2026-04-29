/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

use crate::config::{CryptoConfig, CryptoMode};
use crate::error::{CryptoError, Result};
use crate::backend;
use crate::backend::AeadBackend;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::io::Write;
use hkdf::Hkdf;
use sha3::Sha3_256;

const BUF_SIZE: usize = 1024 * 1024;
const MAGIC_CT: &[u8; 4] = b"NKCT";
const PROTOCOL_VERSION: u16 = 2;

pub struct NetworkProcessor;

impl NetworkProcessor {
    pub async fn listen(config: &CryptoConfig) -> Result<()> {
        let addr = config.listen_addr.as_ref().ok_or(CryptoError::Parameter("Missing listen address".to_string()))?;
        let listener = TcpListener::bind(addr).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
        println!("Listening on {}...", addr);

        let (mut stream, peer) = listener.accept().await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
        println!("Connection accepted from {}", peer);

        // 1. Receive Client Hello
        let mut magic = [0u8; 4];
        stream.read_exact(&mut magic).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
        if &magic != MAGIC_CT { return Err(CryptoError::FileRead("Invalid protocol magic".to_string())); }
        
        let mut version_bytes = [0u8; 2];
        stream.read_exact(&mut version_bytes).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
        let _version = u16::from_le_bytes(version_bytes);

        let aead_name = Self::read_string(&mut stream).await?;
        let client_ecc_pub = Self::read_vec(&mut stream).await?;
        let client_kem_pub = Self::read_vec(&mut stream).await?;

        // 2. Server Key Generation & Handshake
        let (server_ecc_priv, server_ecc_pub) = backend::generate_ecc_key_pair("prime256v1")?;
        let ss_ecc = backend::ecc_dh(&server_ecc_priv, &client_ecc_pub, None)?;
        
        let (kem_ss, kem_ct) = backend::pqc_encap(&config.pqc_kem_algo, &client_kem_pub)?;
        
        let mut combined_ss = ss_ecc;
        combined_ss.extend_from_slice(&kem_ss);
        
        let mut salt = vec![0u8; 16];
        let mut iv = vec![0u8; 12];
        #[cfg(feature = "backend-openssl")]
        openssl::rand::rand_bytes(&mut salt).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        #[cfg(feature = "backend-openssl")]
        openssl::rand::rand_bytes(&mut iv).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        #[cfg(feature = "backend-rustcrypto")]
        {
            use rand_core::{RngCore, OsRng};
            OsRng.fill_bytes(&mut salt);
            OsRng.fill_bytes(&mut iv);
        }

        let mut encryption_key = vec![0u8; 32];
        let hk = Hkdf::<Sha3_256>::new(Some(&salt), &combined_ss);
        hk.expand(b"hybrid-encryption", &mut encryption_key).map_err(|e| CryptoError::Parameter(e.to_string()))?;

        // 3. Send Server Hello
        Self::write_vec(&mut stream, &server_ecc_pub).await?;
        Self::write_vec(&mut stream, &kem_ct).await?;
        stream.write_all(&salt).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
        stream.write_all(&iv).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;

        println!("Handshake completed. Using AEAD: {}", aead_name);

        // 4. Data Transfer (Receive)
        let mut aead = backend::new_decrypt(&aead_name, &encryption_key, &iv)?;
        let mut buffer = vec![0u8; BUF_SIZE];
        let mut out_buffer = vec![0u8; BUF_SIZE + 16];
        let mut stdout = tokio::io::stdout();

        loop {
            // Read chunk length
            let mut len_bytes = [0u8; 4];
            match stream.read_exact(&mut len_bytes).await {
                Ok(_) => {},
                Err(_) => break, // Connection closed
            }
            let chunk_len = u32::from_le_bytes(len_bytes) as usize;
            if chunk_len == 0 { break; }

            let mut encrypted_chunk = vec![0u8; chunk_len];
            stream.read_exact(&mut encrypted_chunk).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;

            // Decrypt
            let n = aead.update(&encrypted_chunk, &mut out_buffer)?;
            stdout.write_all(&out_buffer[..n]).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
            stdout.flush().await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
        }
        
        // Finalize (ignore tag for now in this simple pipe, but should verify in production)
        let _ = aead.finalize(&mut out_buffer);

        Ok(())
    }

    pub async fn connect(config: &CryptoConfig) -> Result<()> {
        let addr = config.connect_addr.as_ref().ok_or(CryptoError::Parameter("Missing connect address".to_string()))?;
        let mut stream = TcpStream::connect(addr).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
        println!("Connected to {}", addr);

        // 1. Client Key Generation
        let (client_ecc_priv, client_ecc_pub) = backend::generate_ecc_key_pair("prime256v1")?;
        let (client_kem_priv, client_kem_pub, _) = backend::pqc_keygen_kem(&config.pqc_kem_algo)?;

        // 2. Send Client Hello
        stream.write_all(MAGIC_CT).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
        stream.write_all(&PROTOCOL_VERSION.to_le_bytes()).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
        Self::write_string(&mut stream, &config.aead_algo).await?;
        Self::write_vec(&mut stream, &client_ecc_pub).await?;
        Self::write_vec(&mut stream, &client_kem_pub).await?;

        // 3. Receive Server Hello
        let server_ecc_pub = Self::read_vec(&mut stream).await?;
        let kem_ct = Self::read_vec(&mut stream).await?;
        let mut salt = [0u8; 16];
        let mut iv = [0u8; 12];
        stream.read_exact(&mut salt).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
        stream.read_exact(&mut iv).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;

        // 4. Finalize Handshake
        let ss_ecc = backend::ecc_dh(&client_ecc_priv, &server_ecc_pub, None)?;
        let kem_ss = backend::pqc_decap(&config.pqc_kem_algo, &client_kem_priv, &kem_ct, None)?;
        
        let mut combined_ss = ss_ecc;
        combined_ss.extend_from_slice(&kem_ss);

        let mut encryption_key = vec![0u8; 32];
        let hk = Hkdf::<Sha3_256>::new(Some(&salt), &combined_ss);
        hk.expand(b"hybrid-encryption", &mut encryption_key).map_err(|e| CryptoError::Parameter(e.to_string()))?;

        println!("Handshake completed. Sending data...");

        // 5. Data Transfer (Send)
        let mut aead = backend::new_encrypt(&config.aead_algo, &encryption_key, &iv)?;
        let mut buffer = vec![0u8; BUF_SIZE];
        let mut out_buffer = vec![0u8; BUF_SIZE + 16];
        let mut stdin = tokio::io::stdin();

        loop {
            let n = stdin.read(&mut buffer).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
            if n == 0 { break; }

            let enc_n = aead.update(&buffer[..n], &mut out_buffer)?;
            
            // Send chunk length and data
            stream.write_all(&(enc_n as u32).to_le_bytes()).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
            stream.write_all(&out_buffer[..enc_n]).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
        }

        // Send EOF
        stream.write_all(&0u32.to_le_bytes()).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;

        Ok(())
    }

    // Helper functions
    async fn read_vec(stream: &mut TcpStream) -> Result<Vec<u8>> {
        let mut len_bytes = [0u8; 4];
        stream.read_exact(&mut len_bytes).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
        let len = u32::from_le_bytes(len_bytes) as usize;
        let mut v = vec![0u8; len];
        stream.read_exact(&mut v).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
        Ok(v)
    }

    async fn write_vec(stream: &mut TcpStream, v: &[u8]) -> Result<()> {
        stream.write_all(&(v.len() as u32).to_le_bytes()).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
        stream.write_all(v).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
        Ok(())
    }

    async fn read_string(stream: &mut TcpStream) -> Result<String> {
        let v = Self::read_vec(stream).await?;
        Ok(String::from_utf8_lossy(&v).to_string())
    }

    async fn write_string(stream: &mut TcpStream, s: &str) -> Result<()> {
        Self::write_vec(stream, s.as_bytes()).await
    }
}
