/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

use crate::backend;
use crate::config::CryptoConfig;
use crate::error::{CryptoError, Result};
use crate::network::{
    NetworkProcessor as CommonProcessor, PeerId, CHAT_ACTIVE, PEER_COOLDOWNS, ChatActiveGuard,
    ALPN_CHAT, ALPN_FILE, IOProvider,
};
use crate::p2p::{P2pEndpoint, P2pProtocol, PeerId as P2pPeerId, P2pStream};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;
use zeroize::Zeroizing;
use std::time::Duration;
use std::str::FromStr;
use crate::ticket::Ticket;
use sha3::{Digest, Sha3_256};

pub struct NetworkProcessor {
    config: CryptoConfig,
    endpoint: Arc<dyn P2pEndpoint>,
    semaphore: Arc<Semaphore>,
    cached_allowlist: Option<Arc<std::collections::HashSet<[u8; 32]>>>,
    io_provider: Arc<dyn IOProvider>,
}

impl NetworkProcessor {
    pub fn new(
        config: CryptoConfig,
        endpoint: Arc<dyn P2pEndpoint>,
        io_provider: Arc<dyn IOProvider>,
    ) -> Self {
        Self {
            config,
            endpoint,
            semaphore: Arc::new(Semaphore::new(10)),
            cached_allowlist: None,
            io_provider,
        }
    }

    pub async fn preload_allowlist(&mut self) -> Result<()> {
        if let Some(ref path) = self.config.peer_allowlist {
            let content = std::fs::read_to_string(path)
                .map_err(|e| CryptoError::FileRead(format!("Allowlist: {}", e)))?;
            let mut set = std::collections::HashSet::new();
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let bytes = hex::decode(line)
                    .map_err(|_| CryptoError::Parameter("Invalid hex in allowlist".to_string()))?;
                if bytes.len() != 32 {
                    return Err(CryptoError::Parameter("Invalid fingerprint length".to_string()));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                set.insert(arr);
            }
            self.cached_allowlist = Some(Arc::new(set));
        }
        Ok(())
    }

    fn get_pqc_fingerprint(&self, path: &str, algo: &str, is_dsa: bool) -> Result<[u8; 32]> {
        let bytes = std::fs::read(path).map_err(|e| CryptoError::FileRead(format!("Key read failed ({}): {}", path, e)))?;
        let pem = std::str::from_utf8(&bytes).map_err(|_| CryptoError::Parameter("Invalid UTF-8 in key".to_string()))?;
        let der = crate::utils::unwrap_from_pem(pem, "PRIVATE KEY")?;
        let decrypted = crate::utils::extract_raw_private_key(&der, self.config.passphrase.as_deref().map(|s| s.as_str()))?;
        
        let raw_pub = if is_dsa {
            let raw_priv = crate::utils::unwrap_pqc_priv_from_pkcs8(&decrypted, algo)?;
            backend::pqc_pub_from_priv_dsa(algo, &raw_priv)?
        } else {
            let raw_priv = crate::utils::unwrap_pqc_priv_from_pkcs8(&decrypted, algo)?;
            backend::pqc_pub_from_priv_kem(algo, &raw_priv)?
        };
        
        Ok(Sha3_256::digest(&raw_pub).into())
    }

    pub async fn start(&self) -> Result<()> {
        self.start_with_ticket_callback(|ticket| {
            eprintln!("[nkct] Ticket: {}", ticket);
            if let Ok(code) = qrcode::QrCode::new(ticket.to_string().as_bytes()) {
                let image = code.render::<qrcode::render::unicode::Dense1x2>()
                    .dark_color(qrcode::render::unicode::Dense1x2::Light)
                    .light_color(qrcode::render::unicode::Dense1x2::Dark)
                    .build();
                eprintln!("\n[nkct] Scan QR to connect:\n{}", image);
            }
        }).await
    }

    pub async fn start_with_ticket_callback<F>(&self, on_ticket: F) -> Result<()>
    where
        F: FnOnce(&Ticket),
    {
        let local_addr = self.endpoint.local_addr().await
            .map_err(|e| CryptoError::Parameter(format!("Local addr: {}", e)))?;
        eprintln!("[nkct] Listening as NodeId: {}", local_addr.peer_id);

        let sign_fp = self.config.signing_privkey.as_ref()
            .map(|path| self.get_pqc_fingerprint(path, &self.config.pqc_dsa_algo, true))
            .transpose()?;

        let enc_fp = self.config.user_privkey.as_ref()
            .map(|path| self.get_pqc_fingerprint(path, &self.config.pqc_kem_algo, false))
            .transpose()?;

        let ticket = Ticket::new(local_addr, sign_fp, enc_fp);
        on_ticket(&ticket);

        let res = tokio::select! {
            r = self.run_listen_loop() => r,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\r\n[nkct] Interrupted by user. Closing...");
                Ok(())
            }
        };
        let _ = self.endpoint.close().await;
        res
    }

    async fn run_listen_loop(&self) -> Result<()> {
        while let Ok(incoming) = self.endpoint.accept().await {
            let config_clone = self.config.clone();
            let semaphore = self.semaphore.clone();
            let cached_allowlist = self.cached_allowlist.clone();
            let local_peer_id = self.endpoint.local_id();
            let io_provider = self.io_provider.clone();

            tokio::spawn(async move {
                let mut config = config_clone;
                // Only a node started with `--serve-shell` (which validated
                // authz and refused root at startup) may serve a shell; a peer
                // requesting the shell ALPN must not be able to turn an ordinary
                // chat/file node — or a shell *client* — into a shell server.
                // Set the mode exclusively from the ALPN.
                let shell_allowed = config.serve_shell;
                config.shell_mode = false;
                config.chat_mode = false;
                if incoming.protocol.0 == ALPN_CHAT {
                    config.chat_mode = true;
                } else if incoming.protocol.0 == ALPN_FILE {
                    // file receive: both modes false
                } else if incoming.protocol.0 == crate::network::ALPN_SHELL {
                    if !shell_allowed {
                        eprintln!("Rejecting nkct/shell/1: this node is not a shell server");
                        return;
                    }
                    config.shell_mode = true;
                } else {
                    eprintln!("Unknown ALPN: {:?}", String::from_utf8_lossy(incoming.protocol.0));
                    return;
                }

                let _permit = match semaphore.acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => return,
                };

                let remote_peer_id = incoming.peer_id;
                if let Err(e) = Self::handle_server_connection(
                    incoming.stream,
                    &config,
                    local_peer_id,
                    remote_peer_id,
                    cached_allowlist,
                    io_provider,
                    None,
                    None,
                )
                .await
                {
                    eprintln!("Connection failed: {}", e);
                }
            });
        }
        Ok(())
    }

    pub async fn run_listen_once<F1, F2>(
        &self,
        on_ticket: F1,
        on_handshake_done: F2,
    ) -> Result<()>
    where
        F1: FnOnce(&Ticket),
        F2: FnOnce() + Send + 'static,
    {
        self.run_listen_once_with_progress(on_ticket, on_handshake_done, None).await
    }

    pub async fn run_listen_once_with_progress<F1, F2>(
        &self,
        on_ticket: F1,
        on_handshake_done: F2,
        on_progress: Option<crate::network::ProgressCallback>,
    ) -> Result<()>
    where
        F1: FnOnce(&Ticket),
        F2: FnOnce() + Send + 'static,
    {
        let local_addr = self.endpoint.local_addr().await
            .map_err(|e| CryptoError::Parameter(format!("Local addr: {}", e)))?;
        eprintln!("[nkct] Listening (single-shot) as NodeId: {}", local_addr.peer_id);

        let sign_fp = self.config.signing_privkey.as_ref()
            .map(|path| self.get_pqc_fingerprint(path, &self.config.pqc_dsa_algo, true))
            .transpose()?;

        let enc_fp = self.config.user_privkey.as_ref()
            .map(|path| self.get_pqc_fingerprint(path, &self.config.pqc_kem_algo, false))
            .transpose()?;

        let ticket = Ticket::new(local_addr, sign_fp, enc_fp);
        on_ticket(&ticket);

        let res = tokio::select! {
            r = self.run_listen_once_inner(on_handshake_done, on_progress) => r,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\r\n[nkct] Interrupted by user. Closing...");
                Ok(())
            }
        };
        let _ = self.endpoint.close().await;
        res
    }

    async fn run_listen_once_inner<F>(
        &self,
        on_handshake_done: F,
        on_progress: Option<crate::network::ProgressCallback>,
    ) -> Result<()>
    where
        F: FnOnce() + Send + 'static,
    {
        let incoming = self.endpoint.accept().await
            .map_err(|e| CryptoError::Parameter(format!("Accept failed: {}", e)))?;

        let mut config = self.config.clone();
        let shell_allowed = config.serve_shell;
        config.shell_mode = false;
        config.chat_mode = false;
        if incoming.protocol.0 == ALPN_CHAT {
            config.chat_mode = true;
        } else if incoming.protocol.0 == ALPN_FILE {
            // file receive: both modes false
        } else if incoming.protocol.0 == crate::network::ALPN_SHELL {
            if !shell_allowed {
                return Err(CryptoError::Parameter(
                    "shell (nkct/shell/1) is not enabled on this node".to_string(),
                ));
            }
            config.shell_mode = true;
        } else {
            return Err(CryptoError::Parameter(format!(
                "Unknown ALPN: {:?}", String::from_utf8_lossy(incoming.protocol.0)
            )));
        }

        let _permit = self.semaphore.clone().acquire_owned().await
            .map_err(|_| CryptoError::Parameter("Semaphore closed".to_string()))?;

        let local_peer_id = self.endpoint.local_id();
        let remote_peer_id = incoming.peer_id;

        Self::handle_server_connection(
            incoming.stream,
            &config,
            local_peer_id,
            remote_peer_id,
            self.cached_allowlist.clone(),
            self.io_provider.clone(),
            Some(Box::new(on_handshake_done)),
            on_progress,
        ).await
    }

    // allow(clippy::too_many_arguments): each parameter is a distinct, required
    // handshake input (stream/config/keys/permit/allowlist/io); bundling into a
    // struct adds field-swap risk in this security-critical path for no benefit.
    // Future: revisit only if a cohesive context type emerges naturally.
    #[allow(clippy::too_many_arguments)]
    async fn handle_server_connection(
        stream: Box<dyn P2pStream>,
        config: &CryptoConfig,
        local_peer_id: P2pPeerId,
        remote_peer_id: P2pPeerId,
        cached_allowlist: Option<Arc<std::collections::HashSet<[u8; 32]>>>,
        io_provider: Arc<dyn IOProvider>,
        on_handshake_done: Option<Box<dyn FnOnce() + Send>>,
        on_progress: Option<crate::network::ProgressCallback>,
    ) -> Result<()> {
        let (mut reader, mut writer) = tokio::io::split(stream);
        let mut peer_id_opt: Option<PeerId> = None;
        let handshake_timeout = Duration::from_secs(config.handshake_timeout);
        
        let handshake_result = tokio::time::timeout(handshake_timeout, async {
            let mut transcript = Vec::new();
            transcript.extend_from_slice(remote_peer_id.as_bytes()); // Client
            transcript.extend_from_slice(local_peer_id.as_bytes());  // Server

            let client_ecc_pub = CommonProcessor::read_vec(&mut reader).await?;
            let client_kem_pub = CommonProcessor::read_vec(&mut reader).await?;

            CommonProcessor::update_transcript(&mut transcript, &client_ecc_pub);
            CommonProcessor::update_transcript(&mut transcript, &client_kem_pub);

            let mut client_auth_flag = [0u8; 1];
            reader.read_exact(&mut client_auth_flag).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
            transcript.extend_from_slice(&client_auth_flag);

            if client_auth_flag[0] == 1 {
                let client_dsa_pub = CommonProcessor::read_vec(&mut reader).await?;
                CommonProcessor::update_transcript(&mut transcript, &client_dsa_pub);

                let sig = CommonProcessor::read_vec(&mut reader).await?;
                
                // Verify signature regardless of whether we have a pinned key
                if !backend::pqc_verify(&config.pqc_dsa_algo, &client_dsa_pub, &transcript, &sig)? {
                    return Err(CryptoError::SignatureVerification);
                }

                let hash: [u8; 32] = Sha3_256::digest(&client_dsa_pub).into();
                peer_id_opt = Some(PeerId::Pubkey(hash));

                if let Some(ref pubkey_path) = config.signing_pubkey {
                    let pubkey_bytes = Zeroizing::new(std::fs::read(pubkey_path).map_err(|e| CryptoError::FileRead(e.to_string()))?);
                    let pubkey_pem = std::str::from_utf8(&pubkey_bytes).map_err(|_| CryptoError::Parameter("Invalid UTF-8 in key".to_string()))?;
                    let pubkey_der = crate::utils::unwrap_from_pem(pubkey_pem, "PUBLIC KEY")?;
                    let pinned_raw_pub = crate::utils::unwrap_pqc_pub_from_spki(&pubkey_der, &config.pqc_dsa_algo)?;
                    
                    if pinned_raw_pub != client_dsa_pub {
                        return Err(CryptoError::Parameter("Client public key mismatch with pinned key".to_string()));
                    }
                    eprintln!("Client authenticated successfully (pinned key).");
                } else {
                    eprintln!("Client authenticated successfully (allowlist-only mode).");
                }
            } else if !config.allow_unauth || config.signing_pubkey.is_some() {
                return Err(CryptoError::Parameter("Handshake failed: Client authentication required".to_string()));
            }

            if peer_id_opt.is_none() {
                peer_id_opt = Some(PeerId::Node(*remote_peer_id.as_bytes()));
            }
            let peer_id = peer_id_opt.unwrap();

            if let Some(ref allowlist) = cached_allowlist {
                match peer_id {
                    PeerId::Pubkey(hash) => {
                        if !allowlist.contains(&hash) {
                            return Err(CryptoError::Parameter("Peer not in allowlist".to_string()));
                        }
                    }
                    _ => {
                        return Err(CryptoError::Parameter("Anonymous peer not allowed when allowlist is active".to_string()));
                    }
                }
            }

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
            }).await.map_err(|e| CryptoError::Parameter(e.to_string()))??;

            let mut combined_ss = crate::utils::SecureBuffer::new(ss_ecc.len() + kem_ss.len())?;
            combined_ss[..ss_ecc.len()].copy_from_slice(&ss_ecc);
            combined_ss[ss_ecc.len()..].copy_from_slice(&kem_ss);

            let mut server_transcript = transcript.clone();
            CommonProcessor::update_transcript(&mut server_transcript, &server_ecc_pub);
            CommonProcessor::update_transcript(&mut server_transcript, &kem_ct);

            let server_auth_flag = if config.signing_privkey.is_some() { [1u8] } else { [0u8] };
            server_transcript.extend_from_slice(&server_auth_flag);

            let mut server_sig = Vec::new();
            let mut server_dsa_pub = Vec::new();
            let mut server_kem_pub = Vec::new();
            if server_auth_flag[0] == 1 {
                let (raw_priv_dsa, raw_pub_kem) = {
                    let dsa_priv_path = config.signing_privkey.as_ref().unwrap();
                    let dsa_bytes = Zeroizing::new(std::fs::read(dsa_priv_path).map_err(|e| CryptoError::FileRead(e.to_string()))?);
                    let dsa_pem = std::str::from_utf8(&dsa_bytes).map_err(|_| CryptoError::Parameter("Invalid UTF-8 in key".to_string()))?;
                    let dsa_der = crate::utils::unwrap_from_pem(dsa_pem, "PRIVATE KEY")?;
                    let dsa_decrypted = crate::utils::extract_raw_private_key(&dsa_der, config.passphrase.as_deref().map(|s| s.as_str()))?;
                    let raw_dsa_priv = crate::utils::unwrap_pqc_priv_from_pkcs8(&dsa_decrypted, &config.pqc_dsa_algo)?;
                    
                    let mut raw_kem_pub = Vec::new();
                    if let Some(ref kem_priv_path) = config.user_privkey {
                        let kem_bytes = Zeroizing::new(std::fs::read(kem_priv_path).map_err(|e| CryptoError::FileRead(e.to_string()))?);
                        let kem_pem = std::str::from_utf8(&kem_bytes).map_err(|_| CryptoError::Parameter("Invalid UTF-8 in key".to_string()))?;
                        let kem_der = crate::utils::unwrap_from_pem(kem_pem, "PRIVATE KEY")?;
                        let kem_decrypted = crate::utils::extract_raw_private_key(&kem_der, config.passphrase.as_deref().map(|s| s.as_str()))?;
                        let raw_kem_priv = crate::utils::unwrap_pqc_priv_from_pkcs8(&kem_decrypted, &config.pqc_kem_algo)?;
                        raw_kem_pub = backend::pqc_pub_from_priv_kem(&config.pqc_kem_algo, &raw_kem_priv)?;
                    }
                    (raw_dsa_priv, raw_kem_pub)
                };
                
                server_dsa_pub = backend::pqc_pub_from_priv_dsa(&config.pqc_dsa_algo, &raw_priv_dsa)?;
                CommonProcessor::update_transcript(&mut server_transcript, &server_dsa_pub);
                
                server_kem_pub = raw_pub_kem;
                CommonProcessor::update_transcript(&mut server_transcript, &server_kem_pub);

                server_sig = backend::pqc_sign(&config.pqc_dsa_algo, &raw_priv_dsa, &server_transcript, None)?;
            }

            use sha3::Digest as Sha3Digest;
            let salt = Sha3_256::digest(&server_transcript).to_vec();
            let okm = backend::hkdf(&combined_ss, 88, &salt, "nk-auth-v3", "SHA3-256")?;
            
            let keys = (
                Zeroizing::new(okm[0..32].to_vec()),
                Zeroizing::new(okm[32..44].to_vec()),
                Zeroizing::new(okm[44..76].to_vec()),
                Zeroizing::new(okm[76..88].to_vec()),
                peer_id,
            );

            CommonProcessor::write_vec(&mut writer, &server_ecc_pub).await?;
            CommonProcessor::write_vec(&mut writer, &kem_ct).await?;
            writer.write_all(&server_auth_flag).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
            if server_auth_flag[0] == 1 {
                CommonProcessor::write_vec(&mut writer, &server_dsa_pub).await?;
                CommonProcessor::write_vec(&mut writer, &server_sig).await?;
                CommonProcessor::write_vec(&mut writer, &server_kem_pub).await?;
            }

            Ok::<_, CryptoError>(keys)
        }).await.map_err(|_| CryptoError::Parameter("Handshake timed out".to_string()))??;

        let (s2c_key, _s2c_iv, c2s_key, c2s_iv, peer_id) = handshake_result;

        // For a shell session the peer must be cryptographically authenticated
        // (PeerId::Pubkey = SHA3-256 of its ML-DSA key); that fingerprint keys
        // the authorization policy / audit / rate limit. Captured (Copy) before
        // `peer_id` may be moved into the chat guard below.
        let shell_peer_fp: Option<[u8; 32]> = match peer_id {
            PeerId::Pubkey(hash) => Some(hash),
            _ => None,
        };

        let mut on_handshake_done = on_handshake_done;
        if let Some(cb) = on_handshake_done.take() {
            cb();
        }

        let _chat_guard = if config.chat_mode {
            let cooldowns = PEER_COOLDOWNS.lock();
            if let Some(last_seen) = cooldowns.get(&peer_id) {
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
            ).is_err() {
                return Err(CryptoError::Parameter("Chat session already active".to_string()));
            }
            Some(ChatActiveGuard {
                peer_id,
                _start_time: std::time::Instant::now(),
            })
        } else {
            None
        };

        if config.shell_mode {
            // Phase 1/2a: bridge a real PTY/shell to the authenticated peer.
            let fp = shell_peer_fp.ok_or_else(|| {
                CryptoError::Parameter("shell requires an authenticated peer".to_string())
            })?;
            crate::shell::run_pty_server(
                reader,
                writer,
                &config.aead_algo,
                &s2c_key,
                &c2s_key,
                fp,
                config.shell_policy_path.as_deref(),
                config.audit_log_path.as_deref(),
            )
            .await?;
        } else if config.chat_mode {
            let stdin = io_provider.stdin();
            let stdout = Arc::new(tokio::sync::Mutex::new(io_provider.stdout()));

            let res = CommonProcessor::chat_loop(reader, writer, stdin, stdout, &config.aead_algo, &s2c_key, &c2s_key, true).await;
            CHAT_ACTIVE.store(false, std::sync::atomic::Ordering::SeqCst);
            res?;
        } else {
            let recv_res = tokio::time::timeout(crate::network::CUMULATIVE_TIMEOUT, async {
                CommonProcessor::receive_file_with_progress(
                    reader,
                    io_provider.stdout(),
                    &config.aead_algo,
                    &c2s_key,
                    &c2s_iv,
                    on_progress,
                ).await
            }).await;
            // Publish the staged file only when the transfer completed AND the
            // trailing AEAD tag verified; otherwise discard it so unauthenticated
            // plaintext is never left at the destination path.
            let committed = recv_res.as_ref().map(|r| r.is_ok()).unwrap_or(false);
            io_provider
                .finalize_recv(committed)
                .map_err(|e| CryptoError::FileWrite(e.to_string()))?;
            recv_res
                .map_err(|e| CryptoError::Parameter(format!("File receive failed: {}", e)))??;
        }
        Ok(())
    }

    pub async fn run_connect(&self) -> Result<()> {
        self.run_connect_with_handshake_callback(|| {}).await
    }

    pub async fn run_connect_with_handshake_callback<F>(
        &self,
        on_handshake_done: F,
    ) -> Result<()>
    where
        F: FnOnce() + Send + 'static,
    {
        self.run_connect_with_handshake_callback_and_progress(on_handshake_done, None).await
    }

    pub async fn run_connect_with_handshake_callback_and_progress<F>(
        &self,
        on_handshake_done: F,
        on_progress: Option<crate::network::ProgressCallback>,
    ) -> Result<()>
    where
        F: FnOnce() + Send + 'static,
    {
        let mut on_handshake_done = Some(on_handshake_done);
        let ticket_str = self.config.connect_addr.as_ref().ok_or(CryptoError::Parameter("Missing ticket".to_string()))?;
        
        let ticket = Ticket::from_str(ticket_str)?;
        let remote_peer_addr = ticket.peer_addr();
        let remote_peer_id = remote_peer_addr.peer_id;

        let mut config = self.config.clone();
        if ticket.pqc_fp_algo & 1 != 0 {
            config.target_sign_fp = Some(ticket.pqc_sign_fp);
        }
        if ticket.pqc_fp_algo & 2 != 0 {
            config.target_enc_fp = Some(ticket.pqc_enc_fp);
        }

        let alpn = if config.shell_mode {
            crate::network::ALPN_SHELL
        } else if config.chat_mode {
            ALPN_CHAT
        } else {
            ALPN_FILE
        };
        let protocol = P2pProtocol(alpn);

        let res = tokio::select! {
            r = async {
                let local_peer_id = self.endpoint.local_id();
                eprintln!("[nkct] Connecting to NodeId: {}", remote_peer_id);
                let stream = self.endpoint.connect(&remote_peer_addr, protocol).await
                    .map_err(|e| CryptoError::Parameter(e.to_string()))?;
                let (mut reader, mut writer) = tokio::io::split(stream);

                let handshake_timeout = Duration::from_secs(config.handshake_timeout);
                let handshake_result = tokio::time::timeout(handshake_timeout, async {
                    let mut transcript = Vec::new();
                    transcript.extend_from_slice(local_peer_id.as_bytes());  // Client
                    transcript.extend_from_slice(remote_peer_id.as_bytes()); // Server

                    let kem_algo = config.pqc_kem_algo.clone();
                    let (client_ecc_priv, client_ecc_pub, client_kem_priv, client_kem_pub) = {
                        let kem_algo_clone = kem_algo.clone();
                        tokio::task::spawn_blocking(move || {
                            let (ecc_priv, ecc_pub) = backend::generate_ecc_key_pair("prime256v1")?;
                            let (kem_priv, kem_pub, _) = backend::pqc_keygen_kem(&kem_algo_clone)?;
                            Ok::<(Zeroizing<Vec<u8>>, Vec<u8>, Zeroizing<Vec<u8>>, Vec<u8>), CryptoError>((
                                ecc_priv, ecc_pub, kem_priv, kem_pub,
                            ))
                        }).await.map_err(|e| CryptoError::Parameter(e.to_string()))??
                    };

                    CommonProcessor::write_vec(&mut writer, &client_ecc_pub).await?;
                    CommonProcessor::write_vec(&mut writer, &client_kem_pub).await?;

                    CommonProcessor::update_transcript(&mut transcript, &client_ecc_pub);
                    CommonProcessor::update_transcript(&mut transcript, &client_kem_pub);

                    let client_auth_flag = if config.signing_privkey.is_some() { [1u8] } else { [0u8] };
                    writer.write_all(&client_auth_flag).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
                    transcript.extend_from_slice(&client_auth_flag);

                    if client_auth_flag[0] == 1 {
                        let raw_priv = {
                            let privkey_path = config.signing_privkey.as_ref().unwrap();
                            let privkey_bytes = Zeroizing::new(std::fs::read(privkey_path).map_err(|e| CryptoError::FileRead(e.to_string()))?);
                            let privkey_pem = std::str::from_utf8(&privkey_bytes).map_err(|_| CryptoError::Parameter("Invalid UTF-8 in key".to_string()))?;
                            let der = crate::utils::unwrap_from_pem(privkey_pem, "PRIVATE KEY")?;
                            let decrypted_der = crate::utils::extract_raw_private_key(&der, config.passphrase.as_deref().map(|s| s.as_str()))?;
                            crate::utils::unwrap_pqc_priv_from_pkcs8(&decrypted_der, &config.pqc_dsa_algo)?
                        };
                        let client_dsa_pub = backend::pqc_pub_from_priv_dsa(&config.pqc_dsa_algo, &raw_priv)?;
                        CommonProcessor::write_vec(&mut writer, &client_dsa_pub).await?;
                        CommonProcessor::update_transcript(&mut transcript, &client_dsa_pub);

                        let sig = backend::pqc_sign(&config.pqc_dsa_algo, &raw_priv, &transcript, None)?;
                        CommonProcessor::write_vec(&mut writer, &sig).await?;
                    }

                    let server_ecc_pub = CommonProcessor::read_vec(&mut reader).await?;
                    let kem_ct = CommonProcessor::read_vec(&mut reader).await?;
                    let mut server_auth_flag = [0u8; 1];
                    reader.read_exact(&mut server_auth_flag).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;

                    let mut server_transcript = transcript.clone();
                    CommonProcessor::update_transcript(&mut server_transcript, &server_ecc_pub);
                    CommonProcessor::update_transcript(&mut server_transcript, &kem_ct);
                    server_transcript.extend_from_slice(&server_auth_flag);

                    if server_auth_flag[0] == 1 {
                        let server_dsa_pub = CommonProcessor::read_vec(&mut reader).await?;
                        CommonProcessor::update_transcript(&mut server_transcript, &server_dsa_pub);

                        let sig = CommonProcessor::read_vec(&mut reader).await?;
                        
                        let server_kem_pub = CommonProcessor::read_vec(&mut reader).await?;
                        CommonProcessor::update_transcript(&mut server_transcript, &server_kem_pub);

                        if let Some(ref pubkey_path) = config.signing_pubkey {
                            let pubkey_bytes = Zeroizing::new(std::fs::read(pubkey_path).map_err(|e| CryptoError::FileRead(e.to_string()))?);
                            let pubkey_pem = std::str::from_utf8(&pubkey_bytes).map_err(|_| CryptoError::Parameter("Invalid UTF-8 in key".to_string()))?;
                            let pubkey_der = crate::utils::unwrap_from_pem(pubkey_pem, "PUBLIC KEY")?;
                            let pinned_raw_pub = crate::utils::unwrap_pqc_pub_from_spki(&pubkey_der, &config.pqc_dsa_algo)?;
                            
                            if pinned_raw_pub != server_dsa_pub {
                                return Err(CryptoError::Parameter("Server public key mismatch with pinned key".to_string()));
                            }
                        }

                        if let Some(expected_fp) = config.target_sign_fp {
                            let actual_fp: [u8; 32] = Sha3_256::digest(&server_dsa_pub).into();
                            if actual_fp != expected_fp {
                                return Err(CryptoError::Parameter("Server PQC public key fingerprint mismatch (MITM detected!)".to_string()));
                            }
                        }

                        if let Some(expected_fp) = config.target_enc_fp {
                            let actual_fp: [u8; 32] = Sha3_256::digest(&server_kem_pub).into();
                            if actual_fp != expected_fp {
                                return Err(CryptoError::Parameter("Server PQC encryption public key fingerprint mismatch (MITM detected!)".to_string()));
                            }
                        }

                        if !backend::pqc_verify(&config.pqc_dsa_algo, &server_dsa_pub, &server_transcript, &sig)? {
                            return Err(CryptoError::SignatureVerification);
                        }
                        eprintln!("Server authenticated successfully.");
                        
                        if let Some(ref allowlist) = self.cached_allowlist {
                            let hash: [u8; 32] = Sha3_256::digest(&server_dsa_pub).into();
                            if !allowlist.contains(&hash) {
                                return Err(CryptoError::Parameter("Server not in allowlist".to_string()));
                            }
                        }
                    } else if config.signing_pubkey.is_some() || !config.allow_unauth {
                        return Err(CryptoError::Parameter("Handshake failed: Server authentication required".to_string()));
                    }

                    let client_ecc_priv_clone = client_ecc_priv.clone();
                    let client_kem_priv_clone = client_kem_priv.clone();
                    let server_ecc_pub_clone = server_ecc_pub.clone();
                    let kem_ct_clone = kem_ct.clone();
                    let passphrase = config.passphrase.clone();
                    let kem_algo_clone = kem_algo.clone();

                    let (ss_ecc, kem_ss) = tokio::task::spawn_blocking(move || {
                        let ss_ecc = backend::ecc_dh(&client_ecc_priv_clone, &server_ecc_pub_clone, None)?;
                        let p_str = passphrase.as_deref().map(|s| s.as_str());
                        let kem_ss = backend::pqc_decap(&kem_algo_clone, &client_kem_priv_clone, &kem_ct_clone, p_str)?;
                        Ok::<(Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>), CryptoError>((ss_ecc, kem_ss))
                    }).await.map_err(|e| CryptoError::Parameter(e.to_string()))??;

                    let mut combined_ss = crate::utils::SecureBuffer::new(ss_ecc.len() + kem_ss.len())?;
                    combined_ss[..ss_ecc.len()].copy_from_slice(&ss_ecc);
                    combined_ss[ss_ecc.len()..].copy_from_slice(&kem_ss);

                    use sha3::Digest as Sha3Digest;
                    let salt = Sha3_256::digest(&server_transcript).to_vec();
                    let okm = backend::hkdf(&combined_ss, 88, &salt, "nk-auth-v3", "SHA3-256")?;

                    let keys = (
                        Zeroizing::new(okm[0..32].to_vec()),
                        Zeroizing::new(okm[32..44].to_vec()),
                        Zeroizing::new(okm[44..76].to_vec()),
                        Zeroizing::new(okm[76..88].to_vec()),
                    );

                    Ok::<_, CryptoError>(keys)
                }).await.map_err(|_| CryptoError::Parameter("Handshake timed out".to_string()))??;

                let (s2c_key, _s2c_iv, c2s_key, c2s_iv) = handshake_result;

                if let Some(cb) = on_handshake_done.take() {
                    cb();
                }

                if config.shell_mode {
                    // Phase 1: drive the local terminal against the remote PTY.
                    crate::shell::run_pty_client(
                        reader,
                        writer,
                        &config.aead_algo,
                        &s2c_key,
                        &c2s_key,
                        config.shell_command.as_deref().unwrap_or(""),
                    )
                    .await
                } else if config.chat_mode {
                    let stdin = self.io_provider.stdin();
                    let stdout = Arc::new(tokio::sync::Mutex::new(self.io_provider.stdout()));

                    let res = CommonProcessor::chat_loop(reader, writer, stdin, stdout, &config.aead_algo, &s2c_key, &c2s_key, false).await;
                    CHAT_ACTIVE.store(false, std::sync::atomic::Ordering::SeqCst);
                    res
                } else {
                    tokio::time::timeout(crate::network::CUMULATIVE_TIMEOUT, async {
                        CommonProcessor::send_file_with_progress(
                            self.io_provider.stdin(),
                            writer,
                            &config.aead_algo,
                            &c2s_key,
                            &c2s_iv,
                            on_progress,
                        ).await
                    }).await.map_err(|e| CryptoError::Parameter(format!("File send failed: {}", e)))??;

                    let mut reader = reader;
                    let _ = tokio::time::timeout(
                        Duration::from_secs(5),
                        async {
                            let mut buf = [0u8; 1];
                            while let Ok(n) = reader.read(&mut buf).await {
                                if n == 0 {
                                    break;
                                }
                            }
                        }
                    ).await;

                    Ok(())
                }
            } => r,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\r\n[nkct] Interrupted by user. Closing...");
                Ok(())
            }
        };

        let _ = self.endpoint.close().await;
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p::backend::mock::MockNetwork;
    use crate::network::TestIOProvider;

    #[tokio::test]
    async fn test_mock_processor_handshake_unauth() {
        let net = MockNetwork::new();
        let server_id = P2pPeerId::new([1; 32]);
        let client_id = P2pPeerId::new([2; 32]);

        let proto_chat = P2pProtocol(ALPN_CHAT);
        let proto_file = P2pProtocol(ALPN_FILE);

        let server_ep = Arc::new(net.register(server_id, vec![proto_chat, proto_file]));
        let client_ep = Arc::new(net.register(client_id, vec![proto_chat, proto_file]));

        let mut server_config = CryptoConfig::default();
        server_config.chat_mode = false;
        server_config.allow_unauth = true;
        server_config.handshake_timeout = 2;

        let mut client_config = CryptoConfig::default();
        client_config.chat_mode = false;
        client_config.allow_unauth = true;
        client_config.handshake_timeout = 2;

        let server_addr = server_ep.local_addr().await.unwrap();
        client_config.connect_addr = Some(Ticket::new(server_addr, None, None).to_string());

        let server_proc = NetworkProcessor::new(server_config, server_ep, Arc::new(TestIOProvider));
        let client_proc = NetworkProcessor::new(client_config, client_ep, Arc::new(TestIOProvider));

        let server_task = tokio::spawn(async move {
            server_proc.run_listen_once_with_progress(|_| {}, || {}, None).await
        });

        let client_res = client_proc.run_connect().await;

        assert!(client_res.is_ok(), "Client connection failed: {:?}", client_res.err());
        assert!(server_task.await.unwrap().is_ok(), "Server listening failed");
    }
}
