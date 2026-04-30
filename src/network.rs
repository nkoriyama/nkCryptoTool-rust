/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

use crate::config::CryptoConfig;
use crate::error::{CryptoError, Result};
use crate::backend;
use crate::backend::AeadBackend;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt, AsyncBufReadExt, BufReader};
use std::io::Write;
use hkdf::Hkdf;
use sha3::Sha3_256;

const BUF_SIZE: usize = 1024 * 1024;
const MAGIC_CT: &[u8; 4] = b"NKCT";
const PROTOCOL_VERSION: u16 = 3;

pub struct NetworkProcessor;

impl NetworkProcessor {
    pub async fn listen(config: &CryptoConfig) -> Result<()> {
        let addr = config.listen_addr.as_ref().ok_or(CryptoError::Parameter("Missing listen address".to_string()))?;
        let listener = TcpListener::bind(addr).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
        eprintln!("Listening on {}...", addr);

        let (mut stream, peer) = listener.accept().await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
        eprintln!("Connection accepted from {}", peer);

        // 1. Receive Client Hello
        let mut magic = [0u8; 4];
        stream.read_exact(&mut magic).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
        if &magic != MAGIC_CT { return Err(CryptoError::FileRead("Invalid protocol magic".to_string())); }
        
        let mut version_bytes = [0u8; 2];
        stream.read_exact(&mut version_bytes).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
        let version = u16::from_le_bytes(version_bytes);
        if version < 2 { return Err(CryptoError::Parameter("Unsupported protocol version".to_string())); }

        let mut transcript = Vec::new();
        transcript.extend_from_slice(MAGIC_CT);
        transcript.extend_from_slice(&version.to_le_bytes());

        let aead_name = Self::read_string(&mut stream).await?;
        transcript.extend_from_slice(&(aead_name.len() as u32).to_le_bytes());
        transcript.extend_from_slice(aead_name.as_bytes());

        let client_ecc_pub = Self::read_vec(&mut stream).await?;
        transcript.extend_from_slice(&(client_ecc_pub.len() as u32).to_le_bytes());
        transcript.extend_from_slice(&client_ecc_pub);

        let client_kem_pub = Self::read_vec(&mut stream).await?;
        transcript.extend_from_slice(&(client_kem_pub.len() as u32).to_le_bytes());
        transcript.extend_from_slice(&client_kem_pub);

        // 1.5 Handle Client Authentication
        let mut auth_flag = [0u8; 1];
        stream.read_exact(&mut auth_flag).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
        if auth_flag[0] == 1 {
            let client_sig = Self::read_vec(&mut stream).await?;
            let pubkey_path = config.signing_pubkey.as_ref().ok_or(CryptoError::Parameter("Client sent signature but no peer public key provided for verification".to_string()))?;
            let pubkey_pem = std::fs::read_to_string(pubkey_path).map_err(|e| CryptoError::FileRead(e.to_string()))?;
            let pubkey_der = crate::utils::unwrap_from_pem(&pubkey_pem, "PUBLIC KEY")?;
            
            if !backend::pqc_verify(&config.pqc_dsa_algo, &pubkey_der, &transcript, &client_sig)? {
                return Err(CryptoError::SignatureVerification);
            }
            eprintln!("Client authenticated successfully.");
        } else if config.signing_pubkey.is_some() {
            return Err(CryptoError::Parameter("Server requires authentication but client did not provide signature".to_string()));
        }

        // 2. Server Key Generation & Handshake
        let (server_ecc_priv, server_ecc_pub) = backend::generate_ecc_key_pair("prime256v1")?;
        let ss_ecc = backend::ecc_dh(&server_ecc_priv, &client_ecc_pub, None)?;
        let (kem_ss, kem_ct) = backend::pqc_encap(&config.pqc_kem_algo, &client_kem_pub)?;
        
        let mut combined_ss = ss_ecc;
        combined_ss.extend_from_slice(&kem_ss);
        
        let mut salt = vec![0u8; 16];
        #[cfg(feature = "backend-openssl")]
        openssl::rand::rand_bytes(&mut salt).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        #[cfg(feature = "backend-rustcrypto")]
        {
            use rand_core::{RngCore, OsRng};
            OsRng.fill_bytes(&mut salt);
        }

        let hk = Hkdf::<Sha3_256>::new(Some(&salt), &combined_ss);
        let mut s2c_key = vec![0u8; 32];
        let mut s2c_iv = vec![0u8; 12];
        let mut c2s_key = vec![0u8; 32];
        let mut c2s_iv = vec![0u8; 12];
        
        hk.expand(b"s2c-key", &mut s2c_key).map_err(|e| CryptoError::Parameter(e.to_string()))?;
        hk.expand(b"s2c-iv", &mut s2c_iv).map_err(|e| CryptoError::Parameter(e.to_string()))?;
        hk.expand(b"c2s-key", &mut c2s_key).map_err(|e| CryptoError::Parameter(e.to_string()))?;
        hk.expand(b"c2s-iv", &mut c2s_iv).map_err(|e| CryptoError::Parameter(e.to_string()))?;

        // 3. Send Server Hello
        let mut server_transcript = transcript.clone();
        let mut server_hello_data = Vec::new();
        server_hello_data.extend_from_slice(&(server_ecc_pub.len() as u32).to_le_bytes());
        server_hello_data.extend_from_slice(&server_ecc_pub);
        server_hello_data.extend_from_slice(&(kem_ct.len() as u32).to_le_bytes());
        server_hello_data.extend_from_slice(&kem_ct);
        server_hello_data.extend_from_slice(&salt);
        server_transcript.extend_from_slice(&server_hello_data);

        stream.write_all(&server_hello_data).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;

        // 3.5 Server Authentication
        if let Some(privkey_path) = &config.signing_privkey {
            let privkey_pem = std::fs::read_to_string(privkey_path).map_err(|e| CryptoError::FileRead(e.to_string()))?;
            let privkey_der = crate::utils::unwrap_from_pem(&privkey_pem, "PRIVATE KEY")?;
            let pass = config.passphrase.as_deref();
            let sig = backend::pqc_sign(&config.pqc_dsa_algo, &privkey_der, &server_transcript, pass)?;
            stream.write_all(&[1u8]).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
            Self::write_vec(&mut stream, &sig).await?;
            eprintln!("Sent server signature for authentication.");
        } else {
            stream.write_all(&[0u8]).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
        }

        eprintln!("Handshake completed. Using AEAD: {}", aead_name);

        if config.chat_mode {
            Self::chat_loop(stream, &aead_name, &s2c_key, &s2c_iv, &c2s_key, &c2s_iv, true).await?;
        } else {
            let mut aead = backend::new_decrypt(&aead_name, &c2s_key, &c2s_iv)?;
            let mut out_buffer = vec![0u8; BUF_SIZE + 16];
            let mut stdout = tokio::io::stdout();
            loop {
                let mut len_bytes = [0u8; 4];
                match stream.read_exact(&mut len_bytes).await {
                    Ok(_) => {},
                    Err(_) => break,
                }
                let chunk_len = u32::from_le_bytes(len_bytes) as usize;
                if chunk_len == 0 { break; }
                let mut encrypted_chunk = vec![0u8; chunk_len];
                stream.read_exact(&mut encrypted_chunk).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
                let n = aead.update(&encrypted_chunk, &mut out_buffer)?;
                stdout.write_all(&out_buffer[..n]).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
                stdout.flush().await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
            }
            let _ = aead.finalize(&mut out_buffer);
            eprintln!("Connection closed. Data transfer complete.");
        }
        Ok(())
    }

    pub async fn connect(config: &CryptoConfig) -> Result<()> {
        let addr = config.connect_addr.as_ref().ok_or(CryptoError::Parameter("Missing connect address".to_string()))?;
        let mut stream = TcpStream::connect(addr).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
        eprintln!("Connected to {}", addr);

        let (client_ecc_priv, client_ecc_pub) = backend::generate_ecc_key_pair("prime256v1")?;
        let (client_kem_priv, client_kem_pub, _) = backend::pqc_keygen_kem(&config.pqc_kem_algo)?;

        let mut transcript = Vec::new();
        transcript.extend_from_slice(MAGIC_CT);
        transcript.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        transcript.extend_from_slice(&(config.aead_algo.len() as u32).to_le_bytes());
        transcript.extend_from_slice(config.aead_algo.as_bytes());
        transcript.extend_from_slice(&(client_ecc_pub.len() as u32).to_le_bytes());
        transcript.extend_from_slice(&client_ecc_pub);
        transcript.extend_from_slice(&(client_kem_pub.len() as u32).to_le_bytes());
        transcript.extend_from_slice(&client_kem_pub);

        stream.write_all(MAGIC_CT).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
        stream.write_all(&PROTOCOL_VERSION.to_le_bytes()).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
        Self::write_string(&mut stream, &config.aead_algo).await?;
        Self::write_vec(&mut stream, &client_ecc_pub).await?;
        Self::write_vec(&mut stream, &client_kem_pub).await?;

        if let Some(privkey_path) = &config.signing_privkey {
            let privkey_pem = std::fs::read_to_string(privkey_path).map_err(|e| CryptoError::FileRead(e.to_string()))?;
            let privkey_der = crate::utils::unwrap_from_pem(&privkey_pem, "PRIVATE KEY")?;
            let pass = config.passphrase.as_deref();
            let sig = backend::pqc_sign(&config.pqc_dsa_algo, &privkey_der, &transcript, pass)?;
            stream.write_all(&[1u8]).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
            Self::write_vec(&mut stream, &sig).await?;
            eprintln!("Sent client signature for authentication.");
        } else {
            stream.write_all(&[0u8]).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
        }

        let mut server_hello_data = Vec::new();
        let server_ecc_pub = Self::read_vec(&mut stream).await?;
        server_hello_data.extend_from_slice(&(server_ecc_pub.len() as u32).to_le_bytes());
        server_hello_data.extend_from_slice(&server_ecc_pub);
        let kem_ct = Self::read_vec(&mut stream).await?;
        server_hello_data.extend_from_slice(&(kem_ct.len() as u32).to_le_bytes());
        server_hello_data.extend_from_slice(&kem_ct);
        let mut salt = [0u8; 16];
        stream.read_exact(&mut salt).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
        server_hello_data.extend_from_slice(&salt);

        let mut server_transcript = transcript.clone();
        server_transcript.extend_from_slice(&server_hello_data);

        let mut auth_flag = [0u8; 1];
        stream.read_exact(&mut auth_flag).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
        if auth_flag[0] == 1 {
            let server_sig = Self::read_vec(&mut stream).await?;
            let pubkey_path = config.signing_pubkey.as_ref().ok_or(CryptoError::Parameter("Server sent signature but no peer public key provided for verification".to_string()))?;
            let pubkey_pem = std::fs::read_to_string(pubkey_path).map_err(|e| CryptoError::FileRead(e.to_string()))?;
            let pubkey_der = crate::utils::unwrap_from_pem(&pubkey_pem, "PUBLIC KEY")?;
            if !backend::pqc_verify(&config.pqc_dsa_algo, &pubkey_der, &server_transcript, &server_sig)? {
                return Err(CryptoError::SignatureVerification);
            }
            eprintln!("Server authenticated successfully.");
        } else if config.signing_pubkey.is_some() {
            return Err(CryptoError::Parameter("Client requires authentication but server did not provide signature".to_string()));
        }

        let ss_ecc = backend::ecc_dh(&client_ecc_priv, &server_ecc_pub, None)?;
        let kem_ss = backend::pqc_decap(&config.pqc_kem_algo, &client_kem_priv, &kem_ct, None)?;
        let mut combined_ss = ss_ecc;
        combined_ss.extend_from_slice(&kem_ss);

        let hk = Hkdf::<Sha3_256>::new(Some(&salt), &combined_ss);
        let mut s2c_key = vec![0u8; 32];
        let mut s2c_iv = vec![0u8; 12];
        let mut c2s_key = vec![0u8; 32];
        let mut c2s_iv = vec![0u8; 12];
        hk.expand(b"s2c-key", &mut s2c_key).map_err(|e| CryptoError::Parameter(e.to_string()))?;
        hk.expand(b"s2c-iv", &mut s2c_iv).map_err(|e| CryptoError::Parameter(e.to_string()))?;
        hk.expand(b"c2s-key", &mut c2s_key).map_err(|e| CryptoError::Parameter(e.to_string()))?;
        hk.expand(b"c2s-iv", &mut c2s_iv).map_err(|e| CryptoError::Parameter(e.to_string()))?;

        eprintln!("Handshake completed. Ready for communication.");

        if config.chat_mode {
            Self::chat_loop(stream, &config.aead_algo, &s2c_key, &s2c_iv, &c2s_key, &c2s_iv, false).await?;
        } else {
            let mut aead = backend::new_encrypt(&config.aead_algo, &c2s_key, &c2s_iv)?;
            let mut buffer = vec![0u8; BUF_SIZE];
            let mut out_buffer = vec![0u8; BUF_SIZE + 16];
            let mut stdin = tokio::io::stdin();
            loop {
                let n = stdin.read(&mut buffer).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
                if n == 0 { break; }
                let enc_n = aead.update(&buffer[..n], &mut out_buffer)?;
                stream.write_all(&(enc_n as u32).to_le_bytes()).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
                stream.write_all(&out_buffer[..enc_n]).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
            }
            stream.write_all(&0u32.to_le_bytes()).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
            eprintln!("Data transfer complete.");
        }
        Ok(())
    }

    async fn chat_loop(stream: TcpStream, aead_name: &str, s2c_key: &[u8], s2c_iv: &[u8], c2s_key: &[u8], c2s_iv: &[u8], is_server: bool) -> Result<()> {
        let (rx_key, rx_iv, tx_key, tx_iv) = if is_server {
            (c2s_key.to_vec(), c2s_iv.to_vec(), s2c_key.to_vec(), s2c_iv.to_vec())
        } else {
            (s2c_key.to_vec(), s2c_iv.to_vec(), c2s_key.to_vec(), c2s_iv.to_vec())
        };

        let aead_name_str = aead_name.to_string();
        let (mut stream_rx, mut stream_tx) = stream.into_split();

        // 1. Receiver Task (Spawned)
        let rx_task = tokio::spawn(async move {
            let mut rx_aead = match backend::new_decrypt(&aead_name_str, &rx_key, &rx_iv) {
                Ok(a) => a,
                Err(e) => return Err(e),
            };
            let mut out_buf = vec![0u8; 65536 + 16];
            loop {
                let mut len_bytes = [0u8; 4];
                if stream_rx.read_exact(&mut len_bytes).await.is_err() { break; }
                let chunk_len = u32::from_le_bytes(len_bytes) as usize;
                if chunk_len == 0 { break; }
                
                let mut encrypted_chunk = vec![0u8; chunk_len];
                if stream_rx.read_exact(&mut encrypted_chunk).await.is_err() { break; }
                
                let n = rx_aead.update(&encrypted_chunk, &mut out_buf)?;
                let msg = String::from_utf8_lossy(&out_buf[..n]);
                println!("\r[Peer]: {}", msg);
                print!("> ");
                let _ = std::io::stdout().flush();
            }
            eprintln!("\r--- Peer disconnected ---");
            Ok::<(), CryptoError>(())
        });

        // 2. Sender Loop (Main Task)
        let mut tx_aead = backend::new_encrypt(aead_name, &tx_key, &tx_iv)?;
        let mut stdin_reader = BufReader::new(tokio::io::stdin()).lines();
        let mut out_buffer = vec![0u8; 65536 + 16];

        eprintln!("--- Chat mode started (Type message and Enter) ---");
        print!("> ");
        let _ = std::io::stdout().flush();

        while let Some(line) = stdin_reader.next_line().await.map_err(|e| CryptoError::FileRead(e.to_string()))? {
            if line.is_empty() { 
                print!("> ");
                let _ = std::io::stdout().flush();
                continue; 
            }
            let data = line.as_bytes();
            let enc_n = tx_aead.update(data, &mut out_buffer)?;
            stream_tx.write_all(&(enc_n as u32).to_le_bytes()).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
            stream_tx.write_all(&out_buffer[..enc_n]).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
            print!("> ");
            let _ = std::io::stdout().flush();
        }

        rx_task.abort();
        eprintln!("--- Chat ended ---");
        Ok(())
    }

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
