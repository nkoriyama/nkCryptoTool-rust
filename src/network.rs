/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

use crate::backend;
use crate::backend::{Aead, AeadBackend};
use crate::config::CryptoConfig;
use crate::error::{CryptoError, Result};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use zeroize::{Zeroize, Zeroizing};

const BUF_SIZE: usize = 1024 * 1024;
const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024 * 1024; // 10GB
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const CUMULATIVE_TIMEOUT: Duration = Duration::from_secs(7200);
const CHAT_SESSION_TIMEOUT: Duration = Duration::from_secs(7200); // 2 hours

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum PeerId {
    Ip(std::net::IpAddr),
    Pubkey([u8; 32]),
}

static CHAT_ACTIVE: Lazy<std::sync::atomic::AtomicBool> =
    Lazy::new(|| std::sync::atomic::AtomicBool::new(false));

static PEER_COOLDOWNS: Lazy<Mutex<std::collections::HashMap<PeerId, std::time::Instant>>> =
    Lazy::new(|| Mutex::new(std::collections::HashMap::new()));

struct ChatActiveGuard {
    peer_id: PeerId,
    _start_time: std::time::Instant,
}

impl Drop for ChatActiveGuard {
    fn drop(&mut self) {
        // F-51-1 Fix: Record cooldown for the specific peer identity (pubkey or IP)
        let mut cooldowns = PEER_COOLDOWNS.lock();
        cooldowns.insert(self.peer_id.clone(), std::time::Instant::now());

        CHAT_ACTIVE.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

pub struct NetworkProcessor {
    config: CryptoConfig,
    semaphore: Arc<Semaphore>,
    cached_allowlist: Option<Arc<std::collections::HashSet<[u8; 32]>>>,
}

impl NetworkProcessor {
    pub fn new(config: CryptoConfig) -> Self {
        Self {
            config,
            semaphore: Arc::new(Semaphore::new(100)),
            cached_allowlist: None,
        }
    }

    async fn preload_allowlist(&mut self) -> Result<()> {
        if let Some(ref path) = self.config.peer_allowlist {
            let content =
                std::fs::read_to_string(path).map_err(|e| CryptoError::FileRead(e.to_string()))?;
            let mut set = std::collections::HashSet::new();
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let bytes = hex::decode(line).map_err(|_| {
                    CryptoError::Parameter(format!("Invalid hex in allowlist: {}", line))
                })?;
                if bytes.len() != 32 {
                    return Err(CryptoError::Parameter(format!(
                        "Invalid fingerprint length in allowlist: {}",
                        line
                    )));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                set.insert(arr);
            }
            self.cached_allowlist = Some(Arc::new(set));
        }
        Ok(())
    }

    pub async fn listen(config: &CryptoConfig) -> Result<()> {
        let mut processor = Self::new(config.clone());
        processor.preload_allowlist().await?;
        processor.start().await
    }

    pub async fn connect(config: &CryptoConfig) -> Result<()> {
        let mut processor = Self::new(config.clone());
        processor.preload_allowlist().await?;
        processor.run_connect().await
    }

    pub async fn start(&self) -> Result<()> {
        let addr = self
            .config
            .listen_addr
            .as_deref()
            .ok_or(CryptoError::Parameter("Missing listen address".to_string()))?;
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| CryptoError::FileRead(e.to_string()))?;
        eprintln!("Listening on {}", addr);

        loop {
            let permit = self
                .semaphore
                .clone()
                .acquire_owned()
                .await
                .map_err(|e| CryptoError::Parameter(e.to_string()))?;
            let (stream, _peer) = listener
                .accept()
                .await
                .map_err(|e| CryptoError::FileRead(e.to_string()))?;

            if self.config.chat_mode {
                // F-52-3 Fix: Move early IP check BEFORE spawn to save resources
                let mut cooldowns = PEER_COOLDOWNS.lock();
                cooldowns.retain(|_, last_seen| last_seen.elapsed() < Duration::from_secs(120));

                let peer_ip = _peer.ip();
                if let Some(last_seen) = cooldowns.get(&PeerId::Ip(peer_ip)) {
                    if last_seen.elapsed() < Duration::from_secs(2) {
                        eprintln!("Flood protection active for {}. Rejecting.", _peer);
                        continue;
                    }
                }
            }

            let config_clone = self.config.clone();
            let cached_list = self.cached_allowlist.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    Self::handle_server_connection(stream, _peer, &config_clone, permit, cached_list)
                        .await
                {
                    eprintln!("Connection error with {}: {}", _peer, e);
                }
                eprintln!("Connection with {} closed.", _peer);
            });
        }
    }

    async fn handle_server_connection(
        mut stream: TcpStream,
        _peer: std::net::SocketAddr,
        config: &CryptoConfig,
        _permit: OwnedSemaphorePermit,
        cached_allowlist: Option<Arc<std::collections::HashSet<[u8; 32]>>>,
    ) -> Result<()> {
        let handshake_timeout = Duration::from_secs(config.handshake_timeout);
        let mut peer_id_opt: Option<PeerId> = None;

        let (s2c_key, _s2c_iv, c2s_key, c2s_iv) = tokio::time::timeout(handshake_timeout, async {
            // 1. Receive Client Hello
            let client_ecc_pub = Self::read_vec(&mut stream).await?;
            let client_kem_pub = Self::read_vec(&mut stream).await?;
            let mut transcript = Vec::new();
            Self::update_transcript(&mut transcript, &client_ecc_pub);
            Self::update_transcript(&mut transcript, &client_kem_pub);

            let mut client_auth_flag = [0u8; 1];
            stream
                .read_exact(&mut client_auth_flag)
                .await
                .map_err(|e| CryptoError::FileRead(e.to_string()))?;
            transcript.extend_from_slice(&client_auth_flag);

            if client_auth_flag[0] == 1 {
                let sig = Self::read_vec(&mut stream).await?;
                if let Some(ref pubkey_path) = config.signing_pubkey {
                    let pubkey_bytes = Zeroizing::new(
                        std::fs::read(pubkey_path)
                            .map_err(|e| CryptoError::FileRead(e.to_string()))?,
                    );
                    let pubkey_pem = Zeroizing::new(
                        std::str::from_utf8(&*pubkey_bytes)
                            .map_err(|_| {
                                CryptoError::Parameter("Invalid UTF-8 in key".to_string())
                            })?
                            .to_string(),
                    );
                    let pubkey_der = crate::utils::unwrap_from_pem(&pubkey_pem, "PUBLIC KEY")?;
                    let raw_pub =
                        crate::utils::unwrap_pqc_pub_from_spki(&pubkey_der, &config.pqc_dsa_algo)?;

                    let algo = config.pqc_dsa_algo.clone();
                    if !backend::pqc_verify(&algo, &raw_pub, &transcript, &sig)? {
                        // F-54 Fix: Removed short IP cooldown on handshake failure to prevent Attack D
                        return Err(CryptoError::SignatureVerification);
                    }

                    // F-52-1 Fix: Peer identified by LONG-TERM signing public key fingerprint
                    use sha3::{Digest, Sha3_256};
                    let mut hasher = Sha3_256::new();
                    hasher.update(&raw_pub);
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(&hasher.finalize());
                    let peer_id = PeerId::Pubkey(hash);
                    peer_id_opt = Some(peer_id.clone());
                } else if !config.allow_unauth {
                    return Err(CryptoError::Parameter(
                        "Client authentication required but no public key provided".to_string(),
                    ));
                }
                eprintln!("Client authenticated successfully.");
            } else if config.signing_pubkey.is_some() || !config.allow_unauth {
                return Err(CryptoError::Parameter("Handshake failed".to_string()));
            }

            if peer_id_opt.is_none() {
                peer_id_opt = Some(PeerId::Ip(_peer.ip()));
            }

            // F-51-1: Check and acquire session slot
            if config.chat_mode {
                let peer_id = peer_id_opt.as_ref().unwrap();

                // F-54-6 Fix: Enforce allowlist if provided
                if let Some(ref allowlist) = cached_allowlist {
                    match peer_id {
                        PeerId::Pubkey(hash) => {
                            if !allowlist.contains(hash) {
                                return Err(CryptoError::Parameter(
                                    "Peer not in allowlist".to_string(),
                                ));
                            }
                        }
                        PeerId::Ip(_) => {
                            // If we have an allowlist, we usually don't want anonymous users
                            if !config.allow_unauth {
                                return Err(CryptoError::Parameter(
                                    "Anonymous peers not allowed when allowlist is active"
                                        .to_string(),
                                ));
                            }
                        }
                    }
                }

                let cooldowns = PEER_COOLDOWNS.lock();
                if let Some(last_seen) = cooldowns.get(peer_id) {
                    if last_seen.elapsed() < Duration::from_secs(60) {
                        return Err(CryptoError::Parameter("Peer cooldown active".to_string()));
                    }
                }
                drop(cooldowns);

                if std::sync::atomic::AtomicBool::compare_exchange(
                    &CHAT_ACTIVE,
                    false,
                    true,
                    std::sync::atomic::Ordering::SeqCst,
                    std::sync::atomic::Ordering::SeqCst,
                )
                .is_err()
                {
                    return Err(CryptoError::Parameter(
                        "Chat session already active".to_string(),
                    ));
                }
            }

            // 2. Server Key Generation & Handshake
            let kem_algo = config.pqc_kem_algo.clone();
            let client_ecc_pub_clone = client_ecc_pub.clone();
            let client_kem_pub_clone = client_kem_pub.clone();

            let (server_ecc_pub, ss_ecc, kem_ss, kem_ct) = tokio::task::spawn_blocking(move || {
                let (ecc_priv, ecc_pub) = backend::generate_ecc_key_pair("prime256v1")?;
                let ss_ecc = backend::ecc_dh(&ecc_priv, &client_ecc_pub_clone, None)?;
                let (k_ss, k_ct) = backend::pqc_encap(&kem_algo, &client_kem_pub_clone)?;
                Ok::<(Vec<u8>, Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>, Vec<u8>), CryptoError>((
                    ecc_pub, ss_ecc, k_ss, k_ct,
                ))
            })
            .await
            .map_err(|e| CryptoError::Parameter(format!("Blocking task failed: {}", e)))??;

            let mut combined_ss = crate::utils::SecureBuffer::new(ss_ecc.len() + kem_ss.len())?;
            combined_ss[..ss_ecc.len()].copy_from_slice(&ss_ecc);
            combined_ss[ss_ecc.len()..].copy_from_slice(&kem_ss);

            // 3. Prepare Server Hello
            let mut server_transcript = transcript.clone();
            Self::update_transcript(&mut server_transcript, &server_ecc_pub);
            Self::update_transcript(&mut server_transcript, &kem_ct);

            let server_auth_flag = if config.signing_privkey.is_some() {
                [1u8]
            } else {
                [0u8]
            };
            server_transcript.extend_from_slice(&server_auth_flag);

            let mut server_hello = Vec::new();
            if server_auth_flag[0] == 1 {
                // F-49-10 Fix: Lazy load signing key for improved security
                let raw_priv = {
                    let privkey_path = config.signing_privkey.as_ref().unwrap();
                    let privkey_bytes = Zeroizing::new(
                        std::fs::read(privkey_path)
                            .map_err(|e| CryptoError::FileRead(e.to_string()))?,
                    );
                    let privkey_pem = Zeroizing::new(
                        std::str::from_utf8(&*privkey_bytes)
                            .map_err(|_| {
                                CryptoError::Parameter("Invalid UTF-8 in key".to_string())
                            })?
                            .to_string(),
                    );
                    if privkey_pem.contains("-----BEGIN TPM WRAPPED BLOB-----") {
                        return Err(CryptoError::Parameter(
                            "TPM not supported in network mode yet".to_string(),
                        ));
                    } else {
                        let der = crate::utils::unwrap_from_pem(&privkey_pem, "PRIVATE KEY")?;
                        let decrypted_der = crate::utils::extract_raw_private_key(
                            &der,
                            config.passphrase.as_deref().map(|s| s.as_str()),
                        )?;
                        crate::utils::unwrap_pqc_priv_from_pkcs8(&decrypted_der, &config.pqc_dsa_algo)?
                    }
                };

                let sig =
                    backend::pqc_sign(&config.pqc_dsa_algo, &raw_priv, &server_transcript, None)?;
                server_hello = sig;
            }

            // 4. Derive Keys
            use sha3::{Digest, Sha3_256};
            let salt = Sha3_256::digest(&server_transcript).to_vec();

            let okm = backend::hkdf(&combined_ss, 88, &salt, "nk-auth-v2", "SHA3-256")?;
            let mut s2c_key = Zeroizing::new(vec![0u8; 32]);
            let mut s2c_iv = Zeroizing::new(vec![0u8; 12]);
            let mut c2s_key = Zeroizing::new(vec![0u8; 32]);
            let mut c2s_iv = Zeroizing::new(vec![0u8; 12]);

            s2c_key.copy_from_slice(&okm[0..32]);
            s2c_iv.copy_from_slice(&okm[32..44]);
            c2s_key.copy_from_slice(&okm[44..76]);
            c2s_iv.copy_from_slice(&okm[76..88]);

            // 5. Send Server Hello
            Self::write_vec(&mut stream, &server_ecc_pub).await?;
            Self::write_vec(&mut stream, &kem_ct).await?;
            stream
                .write_all(&server_auth_flag)
                .await
                .map_err(|e| CryptoError::FileRead(e.to_string()))?;
            if server_auth_flag[0] == 1 {
                Self::write_vec(&mut stream, &server_hello).await?;
            }
            Ok::<
                (
                    Zeroizing<Vec<u8>>,
                    Zeroizing<Vec<u8>>,
                    Zeroizing<Vec<u8>>,
                    Zeroizing<Vec<u8>>,
                ),
                CryptoError,
            >((s2c_key, s2c_iv, c2s_key, c2s_iv))
        })
        .await
        .map_err(|_| CryptoError::Parameter("Handshake timed out".to_string()))??;

        let peer_id = peer_id_opt.unwrap();
        let _chat_guard = if config.chat_mode {
            Some(ChatActiveGuard {
                peer_id,
                _start_time: std::time::Instant::now(),
            })
        } else {
            None
        };

        // 6. Data Transfer or Chat
        if config.chat_mode {
            // 2.4 (d) Fix: Chat sessions are NOT bound by CUMULATIVE_TIMEOUT but by CHAT_SESSION_TIMEOUT
            tokio::time::timeout(
                CHAT_SESSION_TIMEOUT,
                Self::chat_loop(stream, &config.aead_algo, &s2c_key, &c2s_key, true),
            )
            .await
            .map_err(|_| CryptoError::Parameter("Chat session timed out".to_string()))??;
        } else {
            tokio::time::timeout(CUMULATIVE_TIMEOUT, async {
                let mut aead = backend::new_decrypt(&config.aead_algo, &c2s_key, &c2s_iv)?;
                let mut out_buffer = Zeroizing::new(vec![0u8; BUF_SIZE + 32]);

                let mut total_received = 0u64;
                let mut stdout = tokio::io::stdout();
                loop {
                    let mut len_bytes = [0u8; 4];
                    // #1: Add idle timeout for data phase
                    let read_res =
                        tokio::time::timeout(IDLE_TIMEOUT, stream.read_exact(&mut len_bytes)).await;
                    match read_res {
                        Ok(Ok(_)) => {}
                        Ok(Err(_)) | Err(_) => break, // Error or Timeout
                    }

                    let chunk_len = u32::from_le_bytes(len_bytes) as usize;
                    if chunk_len == 0 {
                        break;
                    }
                    if chunk_len > BUF_SIZE + 256 {
                        return Err(CryptoError::Parameter(format!(
                            "Chunk size {} exceeds limit",
                            chunk_len
                        )));
                    }
                    total_received += chunk_len as u64;
                    if total_received > MAX_FILE_SIZE {
                        return Err(CryptoError::Parameter(
                            "File size limit exceeded".to_string(),
                        ));
                    }

                    let mut encrypted_chunk = Zeroizing::new(vec![0u8; chunk_len]); // #22 Fix: Wrap in Zeroizing
                    tokio::time::timeout(IDLE_TIMEOUT, stream.read_exact(&mut encrypted_chunk))
                        .await
                        .map_err(|_| {
                            CryptoError::Parameter("Idle timeout while reading chunk".to_string())
                        })?
                        .map_err(|e| CryptoError::FileRead(e.to_string()))?;

                    let n = aead.update(&encrypted_chunk, &mut out_buffer)?;
                    stdout
                        .write_all(&out_buffer[..n])
                        .await
                        .map_err(|e| CryptoError::FileRead(e.to_string()))?;
                }

                let mut tag = [0u8; 16];
                tokio::time::timeout(IDLE_TIMEOUT, stream.read_exact(&mut tag))
                    .await
                    .map_err(|_| {
                        CryptoError::Parameter("Idle timeout while reading tag".to_string())
                    })?
                    .map_err(|e| CryptoError::FileRead(format!("Failed to read GCM tag: {}", e)))?;

                aead.set_tag(&tag)?;

                let final_n = aead.finalize(&mut out_buffer)?;
                let mut stdout = tokio::io::stdout();
                stdout
                    .write_all(&out_buffer[..final_n])
                    .await
                    .map_err(|e| CryptoError::FileRead(e.to_string()))?;
                stdout
                    .flush()
                    .await
                    .map_err(|e| CryptoError::FileRead(e.to_string()))?;

                eprintln!("File received and decrypted successfully.");
                Ok::<(), CryptoError>(())
            })
            .await
            .map_err(|e| {
                CryptoError::Parameter(format!("Data transfer timed out or failed: {}", e))
            })??;
        }
        Ok(())
    }

    pub async fn run_connect(&self) -> Result<()> {
        let addr = self
            .config
            .connect_addr
            .as_deref()
            .ok_or(CryptoError::Parameter(
                "Missing connect address".to_string(),
            ))?;
        let mut stream = TcpStream::connect(addr)
            .await
            .map_err(|e| CryptoError::FileRead(e.to_string()))?;
        eprintln!("Connected to {}", addr);

        let handshake_timeout = Duration::from_secs(self.config.handshake_timeout);
        let (s2c_key, _s2c_iv, c2s_key, c2s_iv) = tokio::time::timeout(handshake_timeout, async {
            // 1. Generate and Send Client Hello
            let kem_algo = self.config.pqc_kem_algo.clone();
            let (client_ecc_priv, client_ecc_pub, client_kem_priv, client_kem_pub) =
                tokio::task::spawn_blocking(move || {
                    let (ecc_priv, ecc_pub) = backend::generate_ecc_key_pair("prime256v1")?;
                    let (kem_priv, kem_pub, _) = backend::pqc_keygen_kem(&kem_algo)?;
                    Ok::<(Zeroizing<Vec<u8>>, Vec<u8>, Zeroizing<Vec<u8>>, Vec<u8>), CryptoError>((
                        ecc_priv, ecc_pub, kem_priv, kem_pub,
                    ))
                })
                .await
                .map_err(|e| CryptoError::Parameter(format!("Blocking task failed: {}", e)))??;

            Self::write_vec(&mut stream, &client_ecc_pub).await?;
            Self::write_vec(&mut stream, &client_kem_pub).await?;

            let mut transcript = Vec::new();
            Self::update_transcript(&mut transcript, &client_ecc_pub);
            Self::update_transcript(&mut transcript, &client_kem_pub);

            let client_auth_flag = if self.config.signing_privkey.is_some() {
                [1u8]
            } else {
                [0u8]
            };
            stream
                .write_all(&client_auth_flag)
                .await
                .map_err(|e| CryptoError::FileRead(e.to_string()))?;
            transcript.extend_from_slice(&client_auth_flag);

            if client_auth_flag[0] == 1 {
                // F-49-10 Fix: Lazy load signing key
                let raw_priv = {
                    let privkey_path = self.config.signing_privkey.as_ref().unwrap();
                    let privkey_bytes = Zeroizing::new(
                        std::fs::read(privkey_path)
                            .map_err(|e| CryptoError::FileRead(e.to_string()))?,
                    );
                    let privkey_pem = Zeroizing::new(
                        std::str::from_utf8(&*privkey_bytes)
                            .map_err(|_| {
                                CryptoError::Parameter("Invalid UTF-8 in key".to_string())
                            })?
                            .to_string(),
                    );
                    if privkey_pem.contains("-----BEGIN TPM WRAPPED BLOB-----") {
                        return Err(CryptoError::Parameter(
                            "TPM not supported in network mode yet".to_string(),
                        ));
                    } else {
                        let der = crate::utils::unwrap_from_pem(&privkey_pem, "PRIVATE KEY")?;
                        let decrypted_der = crate::utils::extract_raw_private_key(
                            &der,
                            self.config.passphrase.as_deref().map(|s| s.as_str()),
                        )?;
                        crate::utils::unwrap_pqc_priv_from_pkcs8(&decrypted_der, &self.config.pqc_dsa_algo)?
                    }
                };

                let sig =
                    backend::pqc_sign(&self.config.pqc_dsa_algo, &raw_priv, &transcript, None)?;
                Self::write_vec(&mut stream, &sig).await?;
            }

            // 2. Receive Server Hello
            let server_ecc_pub = Self::read_vec(&mut stream).await?;
            let kem_ct = Self::read_vec(&mut stream).await?;
            let mut server_auth_flag = [0u8; 1];
            stream
                .read_exact(&mut server_auth_flag)
                .await
                .map_err(|e| CryptoError::FileRead(e.to_string()))?;

            let mut server_transcript = transcript.clone();
            Self::update_transcript(&mut server_transcript, &server_ecc_pub);
            Self::update_transcript(&mut server_transcript, &kem_ct);
            server_transcript.extend_from_slice(&server_auth_flag);

            if server_auth_flag[0] == 1 {
                let sig = Self::read_vec(&mut stream).await?;
                if let Some(ref pubkey_path) = self.config.signing_pubkey {
                    let pubkey_bytes = Zeroizing::new(
                        std::fs::read(pubkey_path)
                            .map_err(|e| CryptoError::FileRead(e.to_string()))?,
                    );
                    let pubkey_pem = Zeroizing::new(
                        std::str::from_utf8(&*pubkey_bytes)
                            .map_err(|_| {
                                CryptoError::Parameter("Invalid UTF-8 in key".to_string())
                            })?
                            .to_string(),
                    );
                    let pubkey_der = crate::utils::unwrap_from_pem(&pubkey_pem, "PUBLIC KEY")?;
                    let raw_pub = crate::utils::unwrap_pqc_pub_from_spki(
                        &pubkey_der,
                        &self.config.pqc_dsa_algo,
                    )?;

                    let algo = self.config.pqc_dsa_algo.clone();
                    if !backend::pqc_verify(&algo, &raw_pub, &server_transcript, &sig)? {
                        return Err(CryptoError::SignatureVerification);
                    }
                } else if !self.config.allow_unauth {
                    return Err(CryptoError::Parameter(
                        "Server authentication required but no public key provided".to_string(),
                    ));
                }
                eprintln!("Server authenticated successfully.");
            } else if self.config.signing_pubkey.is_some() || !self.config.allow_unauth {
                return Err(CryptoError::Parameter("Handshake failed".to_string()));
            }

            // 3. Derive Keys
            let kem_algo = self.config.pqc_kem_algo.clone();
            let server_ecc_pub_clone = server_ecc_pub.clone();
            let kem_ct_clone = kem_ct.clone();

            let (ss_ecc, kem_ss) = tokio::task::spawn_blocking(move || {
                let ss_ecc = backend::ecc_dh(&client_ecc_priv, &server_ecc_pub_clone, None)?;
                let kem_ss = backend::pqc_decap(&kem_algo, &client_kem_priv, &kem_ct_clone, None)?;
                Ok::<(Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>), CryptoError>((ss_ecc, kem_ss))
            })
            .await
            .map_err(|e| CryptoError::Parameter(format!("Blocking task failed: {}", e)))??;

            let mut combined_ss = crate::utils::SecureBuffer::new(ss_ecc.len() + kem_ss.len())?;
            combined_ss[..ss_ecc.len()].copy_from_slice(&ss_ecc);
            combined_ss[ss_ecc.len()..].copy_from_slice(&kem_ss);

            use sha3::{Digest, Sha3_256};
            let salt = Sha3_256::digest(&server_transcript).to_vec();

            let okm = backend::hkdf(&combined_ss, 88, &salt, "nk-auth-v2", "SHA3-256")?;
            let mut s2c_key = Zeroizing::new(vec![0u8; 32]);
            let mut s2c_iv = Zeroizing::new(vec![0u8; 12]);
            let mut c2s_key = Zeroizing::new(vec![0u8; 32]);
            let mut c2s_iv = Zeroizing::new(vec![0u8; 12]);

            s2c_key.copy_from_slice(&okm[0..32]);
            s2c_iv.copy_from_slice(&okm[32..44]);
            c2s_key.copy_from_slice(&okm[44..76]);
            c2s_iv.copy_from_slice(&okm[76..88]);

            eprintln!("Handshake completed. Ready for communication.");
            Ok::<
                (
                    Zeroizing<Vec<u8>>,
                    Zeroizing<Vec<u8>>,
                    Zeroizing<Vec<u8>>,
                    Zeroizing<Vec<u8>>,
                ),
                CryptoError,
            >((s2c_key, s2c_iv, c2s_key, c2s_iv))
        })
        .await
        .map_err(|_| CryptoError::Parameter("Handshake timed out".to_string()))??;

        // 4. Data Transfer or Chat
        if self.config.chat_mode {
            tokio::time::timeout(
                CHAT_SESSION_TIMEOUT,
                Self::chat_loop(stream, &self.config.aead_algo, &s2c_key, &c2s_key, false),
            )
            .await
            .map_err(|_| CryptoError::Parameter("Chat session timed out".to_string()))??;
        } else {
            tokio::time::timeout(CUMULATIVE_TIMEOUT, async {
                let mut aead = backend::new_encrypt(&self.config.aead_algo, &c2s_key, &c2s_iv)?;
                let mut buffer = Zeroizing::new(vec![0u8; BUF_SIZE]); // #18 Fix: Wrap in Zeroizing
                let mut out_buffer = Zeroizing::new(vec![0u8; BUF_SIZE + 32]); // #18 Fix: Wrap in Zeroizing
                let mut stdin = tokio::io::stdin();

                loop {
                    let n = stdin
                        .read(&mut buffer)
                        .await
                        .map_err(|e| CryptoError::FileRead(e.to_string()))?;
                    if n == 0 {
                        break;
                    }
                    let enc_n = aead.update(&buffer[..n], &mut out_buffer)?;

                    tokio::time::timeout(
                        IDLE_TIMEOUT,
                        stream.write_all(&(enc_n as u32).to_le_bytes()),
                    )
                    .await
                    .map_err(|_| {
                        CryptoError::Parameter(
                            "Idle timeout while sending chunk header".to_string(),
                        )
                    })?
                    .map_err(|e| CryptoError::FileRead(e.to_string()))?;
                    tokio::time::timeout(IDLE_TIMEOUT, stream.write_all(&out_buffer[..enc_n]))
                        .await
                        .map_err(|_| {
                            CryptoError::Parameter("Idle timeout while sending chunk".to_string())
                        })?
                        .map_err(|e| CryptoError::FileRead(e.to_string()))?;
                }

                let final_n = aead.finalize(&mut out_buffer)?;
                let mut tag = vec![0u8; 16];
                aead.get_tag(&mut tag)?;

                tokio::time::timeout(
                    IDLE_TIMEOUT,
                    stream.write_all(&(final_n as u32).to_le_bytes()),
                )
                .await
                .map_err(|_| {
                    CryptoError::Parameter(
                        "Idle timeout while sending final chunk header".to_string(),
                    )
                })?
                .map_err(|e| CryptoError::FileRead(e.to_string()))?;
                tokio::time::timeout(IDLE_TIMEOUT, stream.write_all(&out_buffer[..final_n]))
                    .await
                    .map_err(|_| {
                        CryptoError::Parameter("Idle timeout while sending final chunk".to_string())
                    })?
                    .map_err(|e| CryptoError::FileRead(e.to_string()))?;
                tokio::time::timeout(IDLE_TIMEOUT, stream.write_all(&tag))
                    .await
                    .map_err(|_| {
                        CryptoError::Parameter("Idle timeout while sending tag".to_string())
                    })?
                    .map_err(|e| CryptoError::FileRead(e.to_string()))?;

                stream
                    .flush()
                    .await
                    .map_err(|e| CryptoError::FileRead(e.to_string()))?;
                eprintln!("File sent successfully.");
                Ok::<(), CryptoError>(())
            })
            .await
            .map_err(|e| {
                CryptoError::Parameter(format!("Data transfer timed out or failed: {}", e))
            })??;
        }
        Ok(())
    }

    async fn chat_loop(
        stream: TcpStream,
        aead_name: &str,
        s2c_key: &[u8],
        c2s_key: &[u8],
        is_server: bool,
    ) -> Result<()> {
        let (rx_key, tx_key) = if is_server {
            (
                Zeroizing::new(c2s_key.to_vec()),
                Zeroizing::new(s2c_key.to_vec()),
            )
        } else {
            (
                Zeroizing::new(s2c_key.to_vec()),
                Zeroizing::new(c2s_key.to_vec()),
            )
        };

        let aead_name_str = aead_name.to_string();
        let (mut stream_rx, mut stream_tx) = stream.into_split();
        let (rx_done_tx, mut rx_done_rx) = tokio::sync::mpsc::channel(1);

        let rx_task = tokio::spawn(async move {
            let mut out_buf = Zeroizing::new(vec![0u8; 70000]); // #16 Fix: Wrap in Zeroizing to prevent plaintext residue
            let mut seen_nonces: std::collections::HashSet<Vec<u8>> =
                std::collections::HashSet::new();
            let mut nonce_history = std::collections::VecDeque::new();
            let mut rx_aead_opt: Option<Aead> = None;
            let result = async {
                loop {
                    let mut len_bytes = [0u8; 4];
                    // #1: Add idle timeout for data phase
                    let read_res =
                        tokio::time::timeout(IDLE_TIMEOUT, stream_rx.read_exact(&mut len_bytes))
                            .await;
                    match read_res {
                        Ok(Ok(_)) => {}
                        Ok(Err(_)) | Err(_) => break, // Error or Timeout
                    }

                    let chunk_len = u32::from_le_bytes(len_bytes) as usize;
                    if chunk_len == 0 {
                        break;
                    }
                    if chunk_len < 29 || chunk_len > 70000 {
                        return Err(CryptoError::Parameter("Invalid packet size".to_string()));
                    }

                    let mut packet = Zeroizing::new(vec![0u8; chunk_len]); // #21 Fix: Wrap in Zeroizing
                    tokio::time::timeout(IDLE_TIMEOUT, stream_rx.read_exact(&mut packet))
                        .await
                        .map_err(|_| {
                            CryptoError::Parameter(
                                "Idle timeout while reading chat packet".to_string(),
                            )
                        })?
                        .map_err(|e| CryptoError::FileRead(e.to_string()))?;

                    let (nonce, rest) = packet.split_at(12);
                    let (ciphertext, tag) = rest.split_at(rest.len() - 16);

                    if seen_nonces.contains(nonce) {
                        return Err(CryptoError::Parameter(
                            "Replayed nonce detected".to_string(),
                        ));
                    }
                    let nonce_vec = nonce.to_vec();
                    seen_nonces.insert(nonce_vec.clone());
                    nonce_history.push_back(nonce_vec);
                    if nonce_history.len() > 100000 {
                        if let Some(oldest) = nonce_history.pop_front() {
                            seen_nonces.remove(&oldest);
                        }
                    }

                    if rx_aead_opt.is_none() {
                        rx_aead_opt = Some(backend::new_decrypt(&aead_name_str, &rx_key, nonce)?);
                    } else {
                        rx_aead_opt.as_mut().unwrap().re_init(&rx_key, nonce)?;
                    }
                    let rx_aead = rx_aead_opt.as_mut().unwrap();
                    rx_aead.set_tag(tag)?;

                    let n = rx_aead.update(ciphertext, &mut out_buf)?;
                    let final_n = rx_aead.finalize(&mut out_buf[n..])?;
                    let used = n + final_n;

                    // #21 Fix: Use std::str::from_utf8 to avoid Cow::Owned (non-Zeroizing String) from lossy conversion
                    let msg_content =
                        std::str::from_utf8(&out_buf[..used]).unwrap_or("[Invalid UTF-8 Message]");
                    // F-41-6 Fix: Filter out Unicode direction control characters and other dangerous characters
                    let msg = Zeroizing::new(
                        msg_content
                            .chars()
                            .filter(|c| {
                                let is_dangerous = match *c {
                                    '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' => true, // Bidi
                                    '\u{200B}'..='\u{200D}' | '\u{FEFF}' => true, // ZWS / BOM
                                    '\u{061C}' => true,                           // Arabic Letter Mark
                                    '\u{180E}' => true, // Mongolian Vowel Separator
                                    '\u{E0000}'..='\u{E007F}' => true, // Tags
                                    '\u{115F}' | '\u{1160}' | '\u{3164}' | '\u{FFA0}' => true, // Hangul fillers
                                    _ => false,
                                };
                                (!c.is_control() || *c == '\n' || *c == '\t') && !is_dangerous
                            })
                            .collect::<String>(),
                    );
                    let mut stdout = tokio::io::stdout();
                    let _ = stdout.write_all(b"\r[Peer]: ").await;
                    let _ = stdout.write_all(msg.as_bytes()).await;
                    let _ = stdout.write_all(b"\n> ").await;
                    let _ = stdout.flush().await;

                    // 2.5 (e) Fix: Clear the whole out_buf to prevent message residue (F-41-10)
                    out_buf.fill(0);
                }
                Ok::<(), CryptoError>(())
            }
            .await;
            let _ = rx_done_tx.send(result).await;
        });

        let _rx_guard = AbortGuard(rx_task.abort_handle());

        let mut stdin = tokio::io::stdin();
        let mut line_buf = Zeroizing::new(Vec::new());

        eprintln!("--- Chat mode started ---");
        {
            let mut stdout = tokio::io::stdout();
            let _ = stdout.write_all(b"> ").await;
            let _ = stdout.flush().await;
        }

        let mut tx_aead_opt: Option<Aead> = None;
        loop {
            tokio::select! {
                // F-54 Fix: Monitor rx_task for fatal errors to prevent half-duplex chat (Attack F)
                rx_result = rx_done_rx.recv() => {
                    if let Some(Err(e)) = rx_result {
                        eprintln!("\r\n[System]: Connection closed due to error: {}", e);
                        return Err(e);
                    }
                    eprintln!("\r\n[System]: Connection closed by peer.");
                    break Ok(());
                }
                res = Self::read_line_secure(&mut stdin, &mut line_buf) => {
                    res?;
                    if line_buf.is_empty() {
                        let mut stdout = tokio::io::stdout();
                        let _ = stdout.write_all(b"> ").await;
                        let _ = stdout.flush().await;
                        continue;
                    }
                    let line = Zeroizing::new(
                        std::str::from_utf8(&line_buf)
                            .unwrap_or("[Invalid UTF-8]")
                            .to_string()
                    );
                    line_buf.zeroize();
                    line_buf.clear();

                    let mut data = line.as_bytes();
                    if data.len() > 65000 {
                        data = &data[..65000];
                        eprintln!("Warning: Message truncated to 65000 bytes.");
                    }

                    let mut nonce = Zeroizing::new(vec![0u8; 12]); // #23 Fix: Wrap in Zeroizing for consistency
                    #[cfg(feature = "backend-openssl")]
                    openssl::rand::rand_bytes(&mut nonce).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
                    #[cfg(feature = "backend-rustcrypto")]
                    {
                        use rand_core::{RngCore, OsRng};
                        OsRng.fill_bytes(&mut *nonce);
                    }

                    if tx_aead_opt.is_none() {
                        tx_aead_opt = Some(backend::new_encrypt(aead_name, &tx_key, &nonce)?);
                    } else {
                        tx_aead_opt.as_mut().unwrap().re_init(&tx_key, &nonce)?;
                    }
                    let tx_aead = tx_aead_opt.as_mut().unwrap();
                    let mut encrypted = Zeroizing::new(vec![0u8; data.len() + 32]); // #22 Fix: Wrap in Zeroizing
                    let n = tx_aead.update(data, &mut encrypted)?;
                    let final_n = tx_aead.finalize(&mut encrypted[n..])?;

                    let mut tag = Zeroizing::new(vec![0u8; 16]); // #23 Fix: Wrap in Zeroizing for consistency
                    tx_aead.get_tag(&mut tag)?;

                    let mut packet = Zeroizing::new(Vec::with_capacity(12 + n + final_n + 16));
                    packet.extend_from_slice(&nonce);
                    packet.extend_from_slice(&encrypted[..n + final_n]);
                    packet.extend_from_slice(&tag);

                    // #3 Fix: Add idle timeout to chat packet transmission
                    tokio::time::timeout(IDLE_TIMEOUT, stream_tx.write_all(&(packet.len() as u32).to_le_bytes())).await
                        .map_err(|_| CryptoError::Parameter("Idle timeout while sending chat header".to_string()))?
                        .map_err(|e| CryptoError::FileRead(e.to_string()))?;
                    tokio::time::timeout(IDLE_TIMEOUT, stream_tx.write_all(&packet)).await
                        .map_err(|_| CryptoError::Parameter("Idle timeout while sending chat packet".to_string()))?
                        .map_err(|e| CryptoError::FileRead(e.to_string()))?;

                    let mut stdout = tokio::io::stdout();
                    let _ = stdout.write_all(b"> ").await;
                    let _ = stdout.flush().await;
                }
            }
        }
    }

    async fn read_line_secure<R: AsyncReadExt + Unpin>(
        reader: &mut R,
        buf: &mut Vec<u8>,
    ) -> Result<usize> {
        let mut b = [0u8; 1];
        let mut total = 0;
        const MAX_LINE_LEN: usize = 65536;
        loop {
            match reader.read(&mut b).await {
                Ok(0) => return Ok(total),
                Ok(1) => {
                    if b[0] == b'\n' {
                        return Ok(total);
                    }
                    if b[0] != b'\r' {
                        if total >= MAX_LINE_LEN {
                            return Err(CryptoError::Parameter("Line too long".to_string()));
                        }
                        buf.push(b[0]);
                        total += 1;
                    }
                }
                _ => return Err(CryptoError::FileRead("Unexpected read result".to_string())),
            }
        }
    }

    fn update_transcript(transcript: &mut Vec<u8>, data: &[u8]) {
        transcript.extend_from_slice(&(data.len() as u32).to_le_bytes());
        transcript.extend_from_slice(data);
    }

    async fn read_vec(stream: &mut TcpStream) -> Result<Vec<u8>> {
        let mut len_bytes = [0u8; 4];
        stream
            .read_exact(&mut len_bytes)
            .await
            .map_err(|e| CryptoError::FileRead(e.to_string()))?;
        let len = u32::from_le_bytes(len_bytes) as usize;
        // F-54 Fix: Restrict max length to 8KB (Attack E)
        if len > 8192 {
            return Err(CryptoError::Parameter("Vector too large".to_string()));
        }
        let mut v = vec![0u8; len];
        stream
            .read_exact(&mut v)
            .await
            .map_err(|e| CryptoError::FileRead(e.to_string()))?;
        Ok(v)
    }

    async fn write_vec(stream: &mut TcpStream, v: &[u8]) -> Result<()> {
        stream
            .write_all(&(v.len() as u32).to_le_bytes())
            .await
            .map_err(|e| CryptoError::FileRead(e.to_string()))?;
        stream
            .write_all(v)
            .await
            .map_err(|e| CryptoError::FileRead(e.to_string()))?;
        Ok(())
    }
}

struct AbortGuard(tokio::task::AbortHandle);
impl Drop for AbortGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_rx_task_abort_on_drop() {
        use tokio::time::{timeout, Duration};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let rx_handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            // Read until EOF
            while let Ok(n) = stream.read(&mut buf).await {
                if n == 0 {
                    break;
                }
            }
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let (stream_rx, stream_tx) = stream.into_split();

        let rx_task = tokio::spawn(async move {
            let mut stream_rx = stream_rx;
            let mut buf = [0u8; 1024];
            loop {
                // This will be aborted
                let _ = stream_rx.read_exact(&mut buf).await;
            }
        });

        let abort_handle = rx_task.abort_handle();
        {
            let _guard = AbortGuard(abort_handle.clone());
            // Drop stream_tx explicitly to signal EOF to server
            drop(stream_tx);
        }

        // Wait for task to be aborted
        let _ = timeout(Duration::from_millis(500), rx_task).await;

        // Server side should now finish because stream_tx and stream_rx (in rx_task) are dropped
        timeout(Duration::from_secs(1), rx_handle)
            .await
            .expect("Server task should have finished")
            .expect("Server task panicked");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_cooldown_logic_non_blocking() {
        use tokio::time::Duration;
        let ip = "127.0.0.1".parse::<std::net::IpAddr>().unwrap();
        let peer_id = PeerId::Ip(ip);

        // 1. First user connects and acquires flag
        CHAT_ACTIVE.store(true, Ordering::SeqCst);

        // 2. Second user attempts to connect while first is active
        // This should NOT record a cooldown for the second user (simulated)
        {
            let cooldowns = PEER_COOLDOWNS.lock();
            if let Some(last_seen) = cooldowns.get(&peer_id) {
                assert!(
                    last_seen.elapsed() > Duration::from_secs(60),
                    "Should not have fresh cooldown"
                );
            }
        }

        // 3. First user disconnects
        CHAT_ACTIVE.store(false, Ordering::SeqCst);

        // 4. Second user should now be able to connect immediately
        let success = CHAT_ACTIVE
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok();
        assert!(success, "Second user should be able to acquire flag");

        CHAT_ACTIVE.store(false, Ordering::SeqCst);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_short_session_triggers_cooldown() {
        let ip = "127.0.0.2".parse::<std::net::IpAddr>().unwrap();
        let peer_id = PeerId::Ip(ip);

        // Simulate a short session
        {
            let _guard = ChatActiveGuard {
                peer_id: peer_id.clone(),
                _start_time: std::time::Instant::now(),
            };
            CHAT_ACTIVE.store(true, Ordering::SeqCst);
            // Session ends almost immediately
        }

        let cooldowns = PEER_COOLDOWNS.lock();
        assert!(
            cooldowns.contains_key(&peer_id),
            "Short session should trigger cooldown"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_long_session_also_triggers_cooldown() {
        use tokio::time::Duration;
        let ip = "127.0.0.3".parse::<std::net::IpAddr>().unwrap();
        let peer_id = PeerId::Ip(ip);

        // Ensure fresh state for this IP
        {
            let mut cooldowns = PEER_COOLDOWNS.lock();
            cooldowns.remove(&peer_id);
        }

        // Simulate a long session
        {
            let _guard = ChatActiveGuard {
                peer_id: peer_id.clone(),
                _start_time: std::time::Instant::now() - Duration::from_secs(61),
            };
            CHAT_ACTIVE.store(true, Ordering::SeqCst);
        }

        let cooldowns = PEER_COOLDOWNS.lock();
        // F-50-3: Now even long sessions trigger cooldown
        assert!(
            cooldowns.contains_key(&peer_id),
            "Long session should ALSO record cooldown now"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_peer_cooldown_uses_long_term_pubkey() {
        use sha3::{Digest, Sha3_256};
        let long_term_pubkey = vec![0x42u8; 1952]; // ML-DSA-65 pubkey size
        let mut hasher = Sha3_256::new();
        hasher.update(&long_term_pubkey);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hasher.finalize());
        let peer_id = PeerId::Pubkey(hash);

        // 1. First session ends
        {
            let _guard = ChatActiveGuard {
                peer_id: peer_id.clone(),
                _start_time: std::time::Instant::now(),
            };
            CHAT_ACTIVE.store(true, Ordering::SeqCst);
        }

        // 2. Second session attempts to start with SAME long-term identity
        // even if it would use DIFFERENT ephemeral keys (simulated here by PeerId reuse)
        let cooldowns = PEER_COOLDOWNS.lock();
        assert!(
            cooldowns.contains_key(&peer_id),
            "Cooldown should be active for the long-term identity"
        );
    }
}
