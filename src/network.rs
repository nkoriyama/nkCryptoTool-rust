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
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, AsyncBufReadExt};
use std::io::Write;
use hkdf::Hkdf;
use sha3::Sha3_256;
use zeroize::Zeroizing;
use tokio::sync::{Semaphore, Mutex, OwnedSemaphorePermit};
use std::sync::Arc;
use once_cell::sync::Lazy;
use std::time::Duration;

const BUF_SIZE: usize = 1024 * 1024;
const MAX_CHUNK_SIZE: usize = 1024 * 1024; // #1 Fix: limit chunk size to buffer size
const MAGIC_CT: &[u8; 4] = b"NKCT";
const PROTOCOL_VERSION: u16 = 4;
const IDLE_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes

static STDOUT_MUTEX: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

pub struct NetworkProcessor;

impl NetworkProcessor {
    fn validate_aead(name: &str) -> Result<()> {
        match name {
            "AES-256-GCM" | "ChaCha20-Poly1305" => Ok(()),
            _ => Err(CryptoError::Parameter(format!("Unsupported or insecure AEAD: {}", name))),
        }
    }

    fn update_transcript(transcript: &mut Vec<u8>, data: &[u8]) {
        transcript.extend_from_slice(&(data.len() as u32).to_le_bytes());
        transcript.extend_from_slice(data);
    }

    pub async fn listen(config: &CryptoConfig) -> Result<()> {
        let addr = config.listen_addr.as_ref().ok_or(CryptoError::Parameter("Missing listen address".to_string()))?;
        let listener = TcpListener::bind(addr).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
        eprintln!("Listening on {}...", addr);

        let semaphore = Arc::new(Semaphore::new(100)); // #1 Fix: limit to 100 concurrent connections

        loop {
            // #2 Fix: Acquire semaphore permit BEFORE accept to avoid blocking next accepts
            let permit = semaphore.clone().acquire_owned().await.unwrap();

            let accept_res = listener.accept().await;
            let (stream, peer) = match accept_res {
                Ok(res) => res,
                Err(e) => {
                    eprintln!("accept error: {}", e);
                    // #4 Fix: Classification of accept errors
                    match e.kind() {
                        std::io::ErrorKind::ConnectionAborted |
                        std::io::ErrorKind::ConnectionReset |
                        std::io::ErrorKind::TimedOut => {
                            continue; 
                        }
                        _ => {
                            if let Some(os_err) = e.raw_os_error() {
                                if os_err == libc::EMFILE || os_err == libc::ENFILE {
                                    tokio::time::sleep(Duration::from_millis(100)).await;
                                    continue;
                                }
                            }
                            return Err(CryptoError::FileRead(format!("Fatal accept error: {}", e)));
                        }
                    }
                }
            };
            eprintln!("Connection accepted from {}", peer);

            let config_clone = config.clone();
            tokio::spawn(async move {
                let mut permit_owned = Some(permit);
                if let Err(e) = Self::handle_server_connection(stream, &config_clone, &mut permit_owned).await {
                    eprintln!("Connection error with {}: {}", peer, e);
                }
                eprintln!("Connection with {} closed.", peer);
            });
        }
    }

    async fn handle_server_connection(mut stream: TcpStream, config: &CryptoConfig, permit: &mut Option<OwnedSemaphorePermit>) -> Result<()> {
        // #1 fix: Limit timeout to handshake only
        let handshake_data = tokio::time::timeout(Duration::from_secs(15), async {
            // 1. Receive Client Hello
            let mut magic = [0u8; 4];
            stream.read_exact(&mut magic).await.map_err(|_| CryptoError::Parameter("Handshake failed".to_string()))?;
            if &magic != MAGIC_CT { return Err(CryptoError::Parameter("Handshake failed".to_string())); }
            
            let mut version_bytes = [0u8; 2];
            stream.read_exact(&mut version_bytes).await.map_err(|_| CryptoError::Parameter("Handshake failed".to_string()))?;
            let version = u16::from_le_bytes(version_bytes);
            if version != PROTOCOL_VERSION { 
                return Err(CryptoError::Parameter("Handshake failed".to_string())); 
            }

            let mut transcript = Vec::new();
            transcript.extend_from_slice(MAGIC_CT);
            transcript.extend_from_slice(&version.to_le_bytes());

            let aead_name = Self::read_string(&mut stream).await.map_err(|_| CryptoError::Parameter("Handshake failed".to_string()))?;
            Self::validate_aead(&aead_name)?;
            Self::update_transcript(&mut transcript, aead_name.as_bytes());

            let client_ecc_pub = Self::read_vec(&mut stream).await.map_err(|_| CryptoError::Parameter("Handshake failed".to_string()))?;
            Self::update_transcript(&mut transcript, &client_ecc_pub);

            let client_kem_pub = Self::read_vec(&mut stream).await.map_err(|_| CryptoError::Parameter("Handshake failed".to_string()))?;
            Self::update_transcript(&mut transcript, &client_kem_pub);

            // 1.5 Handle Client Authentication
            let mut client_auth_flag = [0u8; 1];
            stream.read_exact(&mut client_auth_flag).await.map_err(|_| CryptoError::Parameter("Handshake failed".to_string()))?;
            transcript.extend_from_slice(&client_auth_flag); 

            if client_auth_flag[0] == 1 {
                let client_sig = Self::read_vec(&mut stream).await.map_err(|_| CryptoError::Parameter("Handshake failed".to_string()))?;
                let pubkey_path = config.signing_pubkey.as_ref().ok_or(CryptoError::Parameter("Handshake failed".to_string()))?;
                let pubkey_pem = std::fs::read_to_string(pubkey_path).map_err(|_| CryptoError::Parameter("Handshake failed".to_string()))?;
                let pubkey_der = crate::utils::unwrap_from_pem(&pubkey_pem, "PUBLIC KEY")?;
                
                if !backend::pqc_verify(&config.pqc_dsa_algo, &pubkey_der, &transcript, &client_sig)? {
                    return Err(CryptoError::Parameter("Handshake failed".to_string()));
                }
                eprintln!("Client authenticated successfully.");
            } else if config.signing_pubkey.is_some() || !config.allow_unauth {
                return Err(CryptoError::Parameter("Handshake failed".to_string()));
            }

            // 2. Server Key Generation & Handshake
            let (server_ecc_priv, server_ecc_pub) = backend::generate_ecc_key_pair("prime256v1")?;
            let ss_ecc = backend::ecc_dh(&server_ecc_priv, &client_ecc_pub, None)?;
            let (kem_ss, kem_ct) = backend::pqc_encap(&config.pqc_kem_algo, &client_kem_pub)?;
            
            let mut combined_ss = ss_ecc;
            combined_ss.extend_from_slice(&kem_ss);
            
            // 3. Prepare Server Hello
            let mut server_transcript = transcript.clone();
            Self::update_transcript(&mut server_transcript, &server_ecc_pub);
            Self::update_transcript(&mut server_transcript, &kem_ct);

            let server_auth_flag = if config.signing_privkey.is_some() { [1u8] } else { [0u8] };
            server_transcript.extend_from_slice(&server_auth_flag);

            // Derive salt from full handshake transcript (#5 fix)
            use sha3::{Digest, Sha3_256};
            let salt = Sha3_256::digest(&server_transcript).to_vec();

            let hk = Hkdf::<Sha3_256>::new(Some(&salt), &combined_ss);
            let mut s2c_key = Zeroizing::new(vec![0u8; 32]);
            let mut s2c_iv = Zeroizing::new(vec![0u8; 12]);
            let mut c2s_key = Zeroizing::new(vec![0u8; 32]);
            let mut c2s_iv = Zeroizing::new(vec![0u8; 12]);
            
            hk.expand(b"s2c-key", &mut s2c_key).map_err(|e| CryptoError::Parameter(e.to_string()))?;
            hk.expand(b"s2c-iv", &mut s2c_iv).map_err(|e| CryptoError::Parameter(e.to_string()))?;
            hk.expand(b"c2s-key", &mut c2s_key).map_err(|e| CryptoError::Parameter(e.to_string()))?;
            hk.expand(b"c2s-iv", &mut c2s_iv).map_err(|e| CryptoError::Parameter(e.to_string()))?;

            // Send Server Hello data
            Self::write_vec(&mut stream, &server_ecc_pub).await?;
            Self::write_vec(&mut stream, &kem_ct).await?;
            stream.write_all(&server_auth_flag).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;

            // 3.5 Server Authentication
            if let Some(privkey_path) = &config.signing_privkey {
                let privkey_pem = Zeroizing::new(std::fs::read_to_string(privkey_path).map_err(|e| CryptoError::FileRead(e.to_string()))?);
                let privkey_der = Zeroizing::new(crate::utils::unwrap_from_pem(&privkey_pem, "PRIVATE KEY")?);
                let pass = config.passphrase.as_deref().map(|x| x.as_str());
                let sig = backend::pqc_sign(&config.pqc_dsa_algo, &privkey_der, &server_transcript, pass)?;
                Self::write_vec(&mut stream, &sig).await?;
                eprintln!("Sent server signature for authentication.");
            }
            Ok::<(String, Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>), CryptoError>((aead_name, s2c_key, s2c_iv, c2s_key, c2s_iv))
        }).await;

        let (aead_name, s2c_key, _s2c_iv, c2s_key, c2s_iv) = match handshake_data {
            Ok(Ok(data)) => data,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(CryptoError::Parameter("Handshake failed".to_string())), 
        };

        eprintln!("Handshake completed. Using AEAD: {}", aead_name);

        if config.chat_mode {
            Self::chat_loop(stream, &aead_name, &s2c_key, &c2s_key, true).await?;
        } else {
            let mut aead = backend::new_decrypt(&aead_name, &c2s_key, &c2s_iv)?;
            let mut out_buffer = vec![0u8; BUF_SIZE + 32];
            
            use tempfile::NamedTempFile;
            let mut temp_file = NamedTempFile::new().map_err(|e| CryptoError::FileWrite(e.to_string()))?;
            
            let mut total_received: u64 = 0;
            const MAX_TOTAL_SIZE: u64 = 4 * 1024 * 1024 * 1024; // #2: 4GB Limit

            loop {
                let mut len_bytes = [0u8; 4];
                // #1: Add idle timeout for data phase
                let read_res = tokio::time::timeout(IDLE_TIMEOUT, stream.read_exact(&mut len_bytes)).await;
                match read_res {
                    Ok(Ok(_)) => {},
                    Ok(Err(_)) | Err(_) => break, // Error or Timeout
                }
                
                let chunk_len = u32::from_le_bytes(len_bytes) as usize;
                if chunk_len == 0 { break; }
                if chunk_len > MAX_CHUNK_SIZE { return Err(CryptoError::Parameter(format!("Chunk too large: {}", chunk_len))); }

                total_received += chunk_len as u64;
                if total_received > MAX_TOTAL_SIZE {
                    return Err(CryptoError::Parameter("Total file size limit exceeded".to_string()));
                }

                let mut encrypted_chunk = vec![0u8; chunk_len];
                stream.read_exact(&mut encrypted_chunk).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
                let n = aead.update(&encrypted_chunk, &mut out_buffer)?;
                use std::io::Write as _;
                temp_file.write_all(&out_buffer[..n]).map_err(|e| CryptoError::FileWrite(e.to_string()))?;
            }
            
            let mut tag = [0u8; 16];
            stream.read_exact(&mut tag).await.map_err(|e| CryptoError::FileRead(format!("Failed to read GCM tag: {}", e)))?;
            aead.set_tag(&tag)?;

            let final_n = aead.finalize(&mut out_buffer)?;
            if final_n > 0 {
                use std::io::Write as _;
                temp_file.write_all(&out_buffer[..final_n]).map_err(|e| CryptoError::FileWrite(e.to_string()))?;
            }

            eprintln!("GCM verification successful. Releasing data...");
            
            // #2 Fix: Early permit drop to allow other handshakes while writing to stdout
            permit.take(); 

            // #4 Fix: Serialize stdout access for parallel file transfers
            let _stdout_lock = STDOUT_MUTEX.lock().await;
            let mut stdout = tokio::io::stdout();
            let mut reader = tokio::fs::File::open(temp_file.path()).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
            tokio::io::copy(&mut reader, &mut stdout).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
            stdout.flush().await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
            eprintln!("Connection closed. Data transfer complete and verified.");
        }
        Ok(())
    }

    pub async fn connect(config: &CryptoConfig) -> Result<()> {
        let addr = config.connect_addr.as_ref().ok_or(CryptoError::Parameter("Missing connect address".to_string()))?;
        let mut stream = TcpStream::connect(addr).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
        eprintln!("Connected to {}", addr);

        Self::validate_aead(&config.aead_algo)?;

        let (client_ecc_priv, client_ecc_pub) = backend::generate_ecc_key_pair("prime256v1")?;
        let (client_kem_priv, client_kem_pub, _) = backend::pqc_keygen_kem(&config.pqc_kem_algo)?;

        let mut transcript = Vec::new();
        transcript.extend_from_slice(MAGIC_CT);
        transcript.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        Self::update_transcript(&mut transcript, config.aead_algo.as_bytes());
        Self::update_transcript(&mut transcript, &client_ecc_pub);
        Self::update_transcript(&mut transcript, &client_kem_pub);

        stream.write_all(MAGIC_CT).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
        stream.write_all(&PROTOCOL_VERSION.to_le_bytes()).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
        Self::write_string(&mut stream, &config.aead_algo).await?;
        Self::write_vec(&mut stream, &client_ecc_pub).await?;
        Self::write_vec(&mut stream, &client_kem_pub).await?;

        let client_auth_flag = if config.signing_privkey.is_some() { [1u8] } else { [0u8] };
        transcript.extend_from_slice(&client_auth_flag); 

        if let Some(privkey_path) = &config.signing_privkey {
            let privkey_pem = Zeroizing::new(std::fs::read_to_string(privkey_path).map_err(|e| CryptoError::FileRead(e.to_string()))?);
            let privkey_der = Zeroizing::new(crate::utils::unwrap_from_pem(&privkey_pem, "PRIVATE KEY")?);
            let pass = config.passphrase.as_deref().map(|x| x.as_str());
            let sig = backend::pqc_sign(&config.pqc_dsa_algo, &privkey_der, &transcript, pass)?;
            stream.write_all(&[1u8]).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
            Self::write_vec(&mut stream, &sig).await?;
            eprintln!("Sent client signature for authentication.");
        } else {
            if !config.allow_unauth {
                return Err(CryptoError::Parameter("Unauthenticated connections are disabled by default. Use --allow-unauth to enable.".to_string()));
            }
            stream.write_all(&[0u8]).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
        }

        let server_ecc_pub = Self::read_vec(&mut stream).await?;
        let kem_ct = Self::read_vec(&mut stream).await?;
        let mut server_auth_flag = [0u8; 1];
        stream.read_exact(&mut server_auth_flag).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;

        let mut server_transcript = transcript.clone();
        Self::update_transcript(&mut server_transcript, &server_ecc_pub);
        Self::update_transcript(&mut server_transcript, &kem_ct);
        server_transcript.extend_from_slice(&server_auth_flag);

        if server_auth_flag[0] == 1 {
            let server_sig = Self::read_vec(&mut stream).await?;
            let pubkey_path = config.signing_pubkey.as_ref().ok_or(CryptoError::Parameter("Server authentication required but no peer public key provided".to_string()))?;
            let pubkey_pem = std::fs::read_to_string(pubkey_path).map_err(|e| CryptoError::FileRead(e.to_string()))?;
            let pubkey_der = crate::utils::unwrap_from_pem(&pubkey_pem, "PUBLIC KEY")?;
            if !backend::pqc_verify(&config.pqc_dsa_algo, &pubkey_der, &server_transcript, &server_sig)? {
                return Err(CryptoError::SignatureVerification);
            }
            eprintln!("Server authenticated successfully.");
        } else if config.signing_pubkey.is_some() {
            return Err(CryptoError::Parameter("Client requires authentication but server did not provide signature".to_string()));
        } else if !config.allow_unauth {
            return Err(CryptoError::Parameter("Unauthenticated connections are disabled by default. Use --allow-unauth to enable.".to_string()));
        }

        let ss_ecc = backend::ecc_dh(&client_ecc_priv, &server_ecc_pub, None)?;
        let kem_ss = backend::pqc_decap(&config.pqc_kem_algo, &client_kem_priv, &kem_ct, None)?;
        let mut combined_ss = ss_ecc;
        combined_ss.extend_from_slice(&kem_ss);

        use sha3::{Digest, Sha3_256};
        let salt = Sha3_256::digest(&server_transcript).to_vec();

        let hk = Hkdf::<Sha3_256>::new(Some(&salt), &combined_ss);
        let mut s2c_key = Zeroizing::new(vec![0u8; 32]);
        let mut s2c_iv = Zeroizing::new(vec![0u8; 12]);
        let mut c2s_key = Zeroizing::new(vec![0u8; 32]);
        let mut c2s_iv = Zeroizing::new(vec![0u8; 12]);
        hk.expand(b"s2c-key", &mut s2c_key).map_err(|e| CryptoError::Parameter(e.to_string()))?;
        hk.expand(b"s2c-iv", &mut s2c_iv).map_err(|e| CryptoError::Parameter(e.to_string()))?;
        hk.expand(b"c2s-key", &mut c2s_key).map_err(|e| CryptoError::Parameter(e.to_string()))?;
        hk.expand(b"c2s-iv", &mut c2s_iv).map_err(|e| CryptoError::Parameter(e.to_string()))?;

        eprintln!("Handshake completed. Ready for communication.");

        if config.chat_mode {
            Self::chat_loop(stream, &config.aead_algo, &s2c_key, &c2s_key, false).await?;
        } else {
            let mut aead = backend::new_encrypt(&config.aead_algo, &c2s_key, &c2s_iv)?;
            let mut buffer = vec![0u8; BUF_SIZE];
            let mut out_buffer = vec![0u8; BUF_SIZE + 32];
            let mut stdin = tokio::io::stdin();
            loop {
                let n = stdin.read(&mut buffer).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
                if n == 0 { break; }
                let enc_n = aead.update(&buffer[..n], &mut out_buffer)?;
                stream.write_all(&(enc_n as u32).to_le_bytes()).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
                stream.write_all(&out_buffer[..enc_n]).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
            }
            let final_n = aead.finalize(&mut out_buffer)?;
            if final_n > 0 {
                stream.write_all(&(final_n as u32).to_le_bytes()).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
                stream.write_all(&out_buffer[..final_n]).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
            }
            stream.write_all(&0u32.to_le_bytes()).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
            let mut tag = [0u8; 16];
            aead.get_tag(&mut tag)?;
            stream.write_all(&tag).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
            eprintln!("Data transfer complete and tag sent.");
        }
        Ok(())
    }

    async fn chat_loop(stream: TcpStream, aead_name: &str, s2c_key: &[u8], c2s_key: &[u8], is_server: bool) -> Result<()> {
        let (rx_key, tx_key) = if is_server {
            (Zeroizing::new(c2s_key.to_vec()), Zeroizing::new(s2c_key.to_vec()))
        } else {
            (Zeroizing::new(s2c_key.to_vec()), Zeroizing::new(c2s_key.to_vec()))
        };

        let aead_name_str = aead_name.to_string();
        let (mut stream_rx, mut stream_tx) = stream.into_split();

        let mut rx_task = tokio::spawn(async move {
            let mut out_buf = vec![0u8; 70000]; // #2 Fix: Match MAX packet size
            let mut seen_nonces = std::collections::HashSet::new(); // #4 Fix: Replay protection
            loop {
                let mut len_bytes = [0u8; 4];
                // #1: Add idle timeout for data phase
                let read_res = tokio::time::timeout(IDLE_TIMEOUT, stream_rx.read_exact(&mut len_bytes)).await;
                match read_res {
                    Ok(Ok(_)) => {},
                    Ok(Err(_)) | Err(_) => break, // Error or Timeout
                }

                let chunk_len = u32::from_le_bytes(len_bytes) as usize;
                if chunk_len == 0 { break; }
                if chunk_len < 28 || chunk_len > 70000 { 
                    return Err(CryptoError::Parameter("Invalid packet size".to_string()));
                }
                
                let mut packet = vec![0u8; chunk_len];
                stream_rx.read_exact(&mut packet).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
                
                let (nonce, rest) = packet.split_at(12);
                let (ciphertext, tag) = rest.split_at(rest.len() - 16);
                
                if !seen_nonces.insert(nonce.to_vec()) {
                    return Err(CryptoError::Parameter("Replayed nonce detected".to_string()));
                }

                if seen_nonces.len() > 10000 {
                    return Err(CryptoError::Parameter("Nonce history limit exceeded".to_string()));
                }
                
                let mut rx_aead = backend::new_decrypt(&aead_name_str, &rx_key, nonce)?;
                rx_aead.set_tag(tag)?;
                
                let n = rx_aead.update(ciphertext, &mut out_buf)?;
                let final_n = rx_aead.finalize(&mut out_buf[n..])?; 
                
                let msg_raw = String::from_utf8_lossy(&out_buf[..n + final_n]);
                let msg = msg_raw.chars().filter(|c| !c.is_control() || *c == '\n' || *c == '\t').collect::<String>();
                println!("\r[Peer]: {}", msg);
                print!("> ");
                let _ = std::io::stdout().flush();
            }
            Ok::<(), CryptoError>(())
        });

        let mut stdin_reader = BufReader::new(tokio::io::stdin()).lines();

        eprintln!("--- Chat mode started ---");
        print!("> ");
        let _ = std::io::stdout().flush();

        loop {
            tokio::select! {
                line_opt = stdin_reader.next_line() => {
                    let line = match line_opt {
                        Ok(Some(l)) => l,
                        Ok(None) => break,
                        Err(e) => return Err(CryptoError::FileRead(e.to_string())),
                    };
                    if line.is_empty() { 
                        print!("> ");
                        let _ = std::io::stdout().flush();
                        continue; 
                    }
                    let mut data = line.as_bytes();
                    if data.len() > 65000 {
                        data = &data[..65000];
                        eprintln!("Warning: Message truncated to 65000 bytes.");
                    }
                    
                    let mut nonce = vec![0u8; 12];
                    #[cfg(feature = "backend-openssl")]
                    openssl::rand::rand_bytes(&mut nonce).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
                    #[cfg(feature = "backend-rustcrypto")]
                    {
                        use rand_core::{RngCore, OsRng};
                        OsRng.fill_bytes(&mut nonce);
                    }

                    let mut tx_aead = backend::new_encrypt(aead_name, &tx_key, &nonce)?;
                    let mut encrypted = vec![0u8; data.len() + 32];
                    let n = tx_aead.update(data, &mut encrypted)?;
                    let final_n = tx_aead.finalize(&mut encrypted[n..])?;
                    
                    let mut tag = vec![0u8; 16];
                    tx_aead.get_tag(&mut tag)?;

                    let mut packet = Vec::with_capacity(12 + n + final_n + 16);
                    packet.extend_from_slice(&nonce);
                    packet.extend_from_slice(&encrypted[..n + final_n]);
                    packet.extend_from_slice(&tag);

                    stream_tx.write_all(&(packet.len() as u32).to_le_bytes()).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
                    stream_tx.write_all(&packet).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
                    
                    print!("> ");
                    let _ = std::io::stdout().flush();
                }
                res = &mut rx_task => {
                    match res {
                        Ok(Ok(_)) => eprintln!("\r--- Peer disconnected gracefully ---"),
                        Ok(Err(e)) => eprintln!("\r--- Receiver task failed: {} ---", e),
                        Err(e) => eprintln!("\r--- Receiver task panicked: {} ---", e),
                    }
                    break;
                }
            }
        }

        rx_task.abort();
        eprintln!("--- Chat ended ---");
        Ok(())
    }

    async fn read_vec(stream: &mut TcpStream) -> Result<Vec<u8>> {
        let mut len_bytes = [0u8; 4];
        stream.read_exact(&mut len_bytes).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
        let len = u32::from_le_bytes(len_bytes) as usize;
        if len > MAX_CHUNK_SIZE {
            return Err(CryptoError::Parameter(format!("Incoming vector too large: {}", len)));
        }
        let mut v = vec![0u8; len];
        stream.read_exact(&mut v).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
        Ok(v)
    }

    async fn read_string(stream: &mut TcpStream) -> Result<String> {
        let v = Self::read_vec(stream).await?;
        Ok(String::from_utf8_lossy(&v).to_string())
    }

    async fn write_vec(stream: &mut TcpStream, v: &[u8]) -> Result<()> {
        stream.write_all(&(v.len() as u32).to_le_bytes()).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
        stream.write_all(v).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
        Ok(())
    }

    async fn write_string(stream: &mut TcpStream, s: &str) -> Result<()> {
        Self::write_vec(stream, s.as_bytes()).await
    }
}
