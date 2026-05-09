/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

use crate::backend;
use crate::backend::AeadBackend;
use crate::config::CryptoConfig;
use crate::error::{CryptoError, Result};
use super::{
    ChatActiveGuard, NetworkProcessor as CommonProcessor, PeerId, BUF_SIZE, CHAT_ACTIVE,
    CHAT_SESSION_TIMEOUT, CUMULATIVE_TIMEOUT, IDLE_TIMEOUT, MAX_FILE_SIZE, PEER_COOLDOWNS,
    IOProvider, DefaultIOProvider,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroizing;

pub struct NetworkProcessor {
    config: CryptoConfig,
    semaphore: Arc<Semaphore>,
    cached_allowlist: Option<Arc<std::collections::HashSet<[u8; 32]>>>,
    io_provider: Arc<dyn IOProvider>,
}

impl NetworkProcessor {
    pub fn new(config: CryptoConfig) -> Self {
        Self {
            config,
            semaphore: Arc::new(Semaphore::new(100)),
            cached_allowlist: None,
            io_provider: Arc::new(DefaultIOProvider),
        }
    }

    pub fn with_io(config: CryptoConfig, io_provider: Arc<dyn IOProvider>) -> Self {
        Self {
            config,
            semaphore: Arc::new(Semaphore::new(100)),
            cached_allowlist: None,
            io_provider,
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
            let io_provider = self.io_provider.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    Self::handle_server_connection(stream, _peer, &config_clone, permit, cached_list, io_provider)
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
        io_provider: Arc<dyn IOProvider>,
    ) -> Result<()> {
        let handshake_timeout = Duration::from_secs(config.handshake_timeout);
        let mut peer_id_opt: Option<PeerId> = None;

        let (s2c_key, _s2c_iv, c2s_key, c2s_iv) = tokio::time::timeout(handshake_timeout, async {
            // 1. Receive Client Hello
            let client_ecc_pub = CommonProcessor::read_vec(&mut stream).await?;
            let client_kem_pub = CommonProcessor::read_vec(&mut stream).await?;
            let mut transcript = Vec::new();
            CommonProcessor::update_transcript(&mut transcript, &client_ecc_pub);
            CommonProcessor::update_transcript(&mut transcript, &client_kem_pub);

            let mut client_auth_flag = [0u8; 1];
            stream
                .read_exact(&mut client_auth_flag)
                .await
                .map_err(|e| CryptoError::FileRead(e.to_string()))?;
            transcript.extend_from_slice(&client_auth_flag);

            if client_auth_flag[0] == 1 {
                let sig = CommonProcessor::read_vec(&mut stream).await?;
                let client_dsa_pub = CommonProcessor::read_vec(&mut stream).await?; // Read client's public key
                CommonProcessor::update_transcript(&mut transcript, &client_dsa_pub);

                // Verify signature regardless of whether we have a pinned key
                let algo = config.pqc_dsa_algo.clone();
                if !backend::pqc_verify(&algo, &client_dsa_pub, &transcript, &sig)? {
                    return Err(CryptoError::SignatureVerification);
                }

                let hash: [u8; 32] = Sha3_256::digest(&client_dsa_pub).into();
                peer_id_opt = Some(PeerId::Pubkey(hash));

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
                    let pinned_raw_pub =
                        crate::utils::unwrap_pqc_pub_from_spki(&pubkey_der, &config.pqc_dsa_algo)?;

                    if pinned_raw_pub != client_dsa_pub {
                        return Err(CryptoError::Parameter("Client public key mismatch with pinned key".to_string()));
                    }
                    eprintln!("Client authenticated successfully (pinned key).");
                } else {
                    eprintln!("Client authenticated successfully (allowlist-only mode).");
                }
            } else if !config.allow_unauth || config.signing_pubkey.is_some() {
                return Err(CryptoError::Parameter(
                    "Handshake failed: Client authentication required".to_string(),
                ));
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
                        PeerId::Node(_) => {
                            return Err(CryptoError::Parameter(
                                "Iroh nodes not supported in TCP mode".to_string(),
                            ));
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
            CommonProcessor::update_transcript(&mut server_transcript, &server_ecc_pub);
            CommonProcessor::update_transcript(&mut server_transcript, &kem_ct);

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
            CommonProcessor::write_vec(&mut stream, &server_ecc_pub).await?;
            CommonProcessor::write_vec(&mut stream, &kem_ct).await?;
            stream
                .write_all(&server_auth_flag)
                .await
                .map_err(|e| CryptoError::FileRead(e.to_string()))?;
            if server_auth_flag[0] == 1 {
                CommonProcessor::write_vec(&mut stream, &server_hello).await?;
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
            let (rx, tx) = stream.into_split();
            let stdin = io_provider.stdin();
            let stdout = Arc::new(tokio::sync::Mutex::new(io_provider.stdout()));

            tokio::time::timeout(
                CHAT_SESSION_TIMEOUT,
                CommonProcessor::chat_loop(rx, tx, stdin, stdout, &config.aead_algo, &s2c_key, &c2s_key, true),
            )
            .await
            .map_err(|_| CryptoError::Parameter("Chat session timed out".to_string()))??;
        } else {
            tokio::time::timeout(CUMULATIVE_TIMEOUT, async {
                CommonProcessor::receive_file(
                    stream,
                    io_provider.stdout(),
                    &config.aead_algo,
                    &c2s_key,
                    &c2s_iv,
                )
                .await
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

            CommonProcessor::write_vec(&mut stream, &client_ecc_pub).await?;
            CommonProcessor::write_vec(&mut stream, &client_kem_pub).await?;

            let mut transcript = Vec::new();
            CommonProcessor::update_transcript(&mut transcript, &client_ecc_pub);
            CommonProcessor::update_transcript(&mut transcript, &client_kem_pub);

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

                let client_dsa_pub = backend::pqc_pub_from_priv_dsa(&self.config.pqc_dsa_algo, &raw_priv)?;
                let sig =
                    backend::pqc_sign(&self.config.pqc_dsa_algo, &raw_priv, &transcript, None)?;
                CommonProcessor::write_vec(&mut stream, &sig).await?;
                CommonProcessor::write_vec(&mut stream, &client_dsa_pub).await?;
            }
            // 2. Receive Server Hello
            let server_ecc_pub = CommonProcessor::read_vec(&mut stream).await?;
            let kem_ct = CommonProcessor::read_vec(&mut stream).await?;
            let mut server_auth_flag = [0u8; 1];
            stream
                .read_exact(&mut server_auth_flag)
                .await
                .map_err(|e| CryptoError::FileRead(e.to_string()))?;

            let mut server_transcript = transcript.clone();
            CommonProcessor::update_transcript(&mut server_transcript, &server_ecc_pub);
            CommonProcessor::update_transcript(&mut server_transcript, &kem_ct);
            server_transcript.extend_from_slice(&server_auth_flag);

            if server_auth_flag[0] == 1 {
                let sig = CommonProcessor::read_vec(&mut stream).await?;
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

        let res = async {
            // 4. Data Transfer or Chat
            if self.config.chat_mode {
                let (rx, tx) = stream.into_split();
                let stdin = self.io_provider.stdin();
                let stdout = Arc::new(tokio::sync::Mutex::new(self.io_provider.stdout()));

                tokio::time::timeout(
                    CHAT_SESSION_TIMEOUT,
                    CommonProcessor::chat_loop(rx, tx, stdin, stdout, &self.config.aead_algo, &s2c_key, &c2s_key, false),
                )
                .await
                .map_err(|_| CryptoError::Parameter("Chat session timed out".to_string()))??;
            } else {

                tokio::time::timeout(CUMULATIVE_TIMEOUT, async {
                    CommonProcessor::send_file(
                        self.io_provider.stdin(),
                        stream,
                        &self.config.aead_algo,
                        &c2s_key,
                        &c2s_iv,
                    )
                    .await
                })
                .await
                .map_err(|e| {
                    CryptoError::Parameter(format!("Data transfer timed out or failed: {}", e))
                })??;
            }
            Ok(())
        };

        tokio::select! {
            r = res => r,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\r\n[nkct] Interrupted by user.");
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;
    use tokio::net::TcpListener;
    use crate::network::AbortGuard;
    use serial_test::serial;

    fn reset_state() {
        CHAT_ACTIVE.store(false, Ordering::SeqCst);
        PEER_COOLDOWNS.lock().clear();
    }

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
    #[serial]
    async fn test_cooldown_logic_non_blocking() {
        reset_state();
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
    #[serial]
    async fn test_short_session_triggers_cooldown() {
        reset_state();
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
    #[serial]
    async fn test_long_session_also_triggers_cooldown() {
        reset_state();
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
    #[serial]
    async fn test_peer_cooldown_uses_long_term_pubkey() {
        reset_state();
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
