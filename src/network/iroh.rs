use crate::backend;
use crate::config::CryptoConfig;
use crate::error::{CryptoError, Result};
use crate::network::{
    NetworkProcessor as CommonProcessor, PeerId, CHAT_ACTIVE, PEER_COOLDOWNS, ChatActiveGuard,
    ALPN_CHAT, ALPN_FILE, IOProvider, DefaultIOProvider,
};
use iroh::{Endpoint, NodeId, Watcher};
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
    semaphore: Arc<Semaphore>,
    cached_allowlist: Option<Arc<std::collections::HashSet<[u8; 32]>>>,
    io_provider: Arc<dyn IOProvider>,
}

pub struct EndpointGuard(pub Endpoint);
impl Drop for EndpointGuard {
    fn drop(&mut self) {
        let endpoint = self.0.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                // Best effort close
                let _ = endpoint.close().await;
            });
        }
    }
}

impl NetworkProcessor {
    pub fn new(config: CryptoConfig) -> Self {
        Self {
            config,
            semaphore: Arc::new(Semaphore::new(10)),
            cached_allowlist: None,
            io_provider: Arc::new(DefaultIOProvider),
        }
    }

    pub fn with_io(config: CryptoConfig, io_provider: Arc<dyn IOProvider>) -> Self {
        Self {
            config,
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

    async fn create_endpoint(&self, is_test: bool) -> Result<Endpoint> {
        let mut builder = Endpoint::builder()
            .alpns(vec![ALPN_CHAT.to_vec(), ALPN_FILE.to_vec()]);

        if is_test || self.config.no_relay {
            builder = builder.relay_mode(iroh::RelayMode::Disabled);
        } else if let Some(ref url) = self.config.relay_url {
            let relay_url = iroh::RelayUrl::from_str(url)
                .map_err(|e| CryptoError::Parameter(format!("Invalid RelayUrl: {}", e)))?;
            builder = builder.relay_mode(iroh::RelayMode::Custom(
                iroh_relay::RelayMap::from(relay_url)
            ));
        }

        builder.bind()
            .await
            .map_err(|e| CryptoError::Parameter(e.to_string()))
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
        let endpoint = self.create_endpoint(false).await?;
        let _guard = EndpointGuard(endpoint.clone());

        let node_addr = endpoint.node_addr().initialized().await;
        eprintln!("[nkct] Listening as NodeId: {}", node_addr.node_id);

        let sign_fp = self.config.signing_privkey.as_ref()
            .map(|path| self.get_pqc_fingerprint(path, &self.config.pqc_dsa_algo, true))
            .transpose()?;

        let enc_fp = self.config.user_privkey.as_ref()
            .map(|path| self.get_pqc_fingerprint(path, &self.config.pqc_kem_algo, false))
            .transpose()?;

        let ticket = Ticket::new(node_addr, sign_fp, enc_fp);
        eprintln!("[nkct] Ticket: {}", ticket);
        
        if let Ok(code) = qrcode::QrCode::new(ticket.to_string().as_bytes()) {
            let image = code.render::<qrcode::render::unicode::Dense1x2>()
                .dark_color(qrcode::render::unicode::Dense1x2::Light)
                .light_color(qrcode::render::unicode::Dense1x2::Dark)
                .build();
            eprintln!("\n[nkct] Scan QR to connect:\n{}", image);
        }

        let endpoint_clone = endpoint.clone();
        let res = tokio::select! {
            r = self.run_listen_loop(endpoint) => r,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\r\n[nkct] Interrupted by user. Closing...");
                Ok(())
            }
        };
        let _ = endpoint_clone.close().await;
        res
    }

    async fn run_listen_loop(&self, endpoint: Endpoint) -> Result<()> {
        while let Some(incoming) = endpoint.accept().await {
            let config_clone = self.config.clone();
            let semaphore = self.semaphore.clone();
            let cached_allowlist = self.cached_allowlist.clone();
            let local_node_id = endpoint.node_id();
            let io_provider = self.io_provider.clone();
            tokio::spawn(async move {
                let mut connecting = match incoming.accept() {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("Accept failed: {}", e);
                        return;
                    }
                };

                let alpn = match connecting.alpn().await {
                    Ok(a) => a,
                    Err(e) => {
                        eprintln!("ALPN detection failed: {}", e);
                        return;
                    }
                };
                
                let mut config = config_clone;
                if alpn.as_slice() == ALPN_CHAT {
                    config.chat_mode = true;
                } else if alpn.as_slice() == ALPN_FILE {
                    config.chat_mode = false;
                } else {
                    eprintln!("Unknown ALPN: {:?}", String::from_utf8_lossy(alpn.as_slice()));
                    return;
                }

                let connection = match connecting.await {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("Connection failed: {}", e);
                        return;
                    }
                };
                let _permit = match semaphore.acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => return,
                };

                let (send, recv) = match connection.accept_bi().await {
                    Ok(bi) => bi,
                    Err(e) => {
                        eprintln!("Accept bi failed: {}", e);
                        return;
                    }
                };

                let remote_node_id = match connection.remote_node_id() {
                    Ok(id) => id,
                    Err(_) => return,
                };

                if let Err(e) = Self::handle_server_connection(
                    recv,
                    send,
                    &config,
                    local_node_id,
                    remote_node_id,
                    cached_allowlist,
                    io_provider,
                )
                .await
                {
                    eprintln!("Connection failed: {}", e);
                }
            });
        }
        Ok(())
    }

    async fn handle_server_connection<R, W>(
        mut reader: R,
        mut writer: W,
        config: &CryptoConfig,
        local_node_id: NodeId,
        remote_node_id: NodeId,
        cached_allowlist: Option<Arc<std::collections::HashSet<[u8; 32]>>>,
        io_provider: Arc<dyn IOProvider>,
    ) -> Result<()>
    where
        R: AsyncReadExt + Unpin + Send + 'static,
        W: AsyncWriteExt + Unpin + Send + 'static,
    {
        let mut peer_id_opt: Option<PeerId> = None;
        let handshake_timeout = Duration::from_secs(config.handshake_timeout);
        
        let handshake_result = tokio::time::timeout(handshake_timeout, async {
            let mut transcript = Vec::new();
            transcript.extend_from_slice(remote_node_id.as_bytes()); // Client
            transcript.extend_from_slice(local_node_id.as_bytes());  // Server

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
                    let pubkey_pem = std::str::from_utf8(&*pubkey_bytes).map_err(|_| CryptoError::Parameter("Invalid UTF-8 in key".to_string()))?;
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
                peer_id_opt = Some(PeerId::Node(*remote_node_id.as_bytes()));
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
                    let dsa_pem = std::str::from_utf8(&*dsa_bytes).map_err(|_| CryptoError::Parameter("Invalid UTF-8 in key".to_string()))?;
                    let dsa_der = crate::utils::unwrap_from_pem(dsa_pem, "PRIVATE KEY")?;
                    let dsa_decrypted = crate::utils::extract_raw_private_key(&dsa_der, config.passphrase.as_deref().map(|s| s.as_str()))?;
                    let raw_dsa_priv = crate::utils::unwrap_pqc_priv_from_pkcs8(&dsa_decrypted, &config.pqc_dsa_algo)?;
                    
                    let mut raw_kem_pub = Vec::new();
                    if let Some(ref kem_priv_path) = config.user_privkey {
                        let kem_bytes = Zeroizing::new(std::fs::read(kem_priv_path).map_err(|e| CryptoError::FileRead(e.to_string()))?);
                        let kem_pem = std::str::from_utf8(&*kem_bytes).map_err(|_| CryptoError::Parameter("Invalid UTF-8 in key".to_string()))?;
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

            use sha3::{Digest, Sha3_256};
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

        if config.chat_mode {
            let stdin = io_provider.stdin();
            let stdout = Arc::new(tokio::sync::Mutex::new(io_provider.stdout()));

            CommonProcessor::chat_loop(reader, writer, stdin, stdout, &config.aead_algo, &s2c_key, &c2s_key, true).await?;
        } else {            tokio::time::timeout(crate::network::CUMULATIVE_TIMEOUT, async {
                CommonProcessor::receive_file(reader, io_provider.stdout(), &config.aead_algo, &c2s_key, &c2s_iv).await
            }).await.map_err(|e| CryptoError::Parameter(format!("File receive failed: {}", e)))??;
        }
        Ok(())
    }

    pub async fn run_connect(&self) -> Result<()> {
        let ticket_str = self.config.connect_addr.as_ref().ok_or(CryptoError::Parameter("Missing ticket".to_string()))?;
        
        let ticket = Ticket::from_str(ticket_str)?;
        let node_addr = ticket.node_addr()?;
        let remote_node_id = node_addr.node_id;

        let mut config = self.config.clone();
        if ticket.pqc_fp_algo & 1 != 0 {
            config.target_sign_fp = Some(ticket.pqc_sign_fp);
        }
        if ticket.pqc_fp_algo & 2 != 0 {
            config.target_enc_fp = Some(ticket.pqc_enc_fp);
        }

        let endpoint = self.create_endpoint(false).await?;
        let endpoint_cleanup = endpoint.clone();
        let _guard = EndpointGuard(endpoint.clone());
        let alpn = if config.chat_mode { ALPN_CHAT } else { ALPN_FILE };

        let res = tokio::select! {
            r = async {
                let local_node_id = endpoint.node_id();
                eprintln!("[nkct] Connecting to NodeId: {}", remote_node_id);
                let connection = endpoint.connect(node_addr, alpn).await.map_err(|e| CryptoError::Parameter(e.to_string()))?;
                let (mut writer, mut reader) = connection.open_bi().await.map_err(|e| CryptoError::Parameter(e.to_string()))?;

                let handshake_timeout = Duration::from_secs(config.handshake_timeout);
                let handshake_result = tokio::time::timeout(handshake_timeout, async {
                    let mut transcript = Vec::new();
                    transcript.extend_from_slice(local_node_id.as_bytes());  // Client
                    transcript.extend_from_slice(remote_node_id.as_bytes()); // Server

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
                            let privkey_pem = std::str::from_utf8(&*privkey_bytes).map_err(|_| CryptoError::Parameter("Invalid UTF-8 in key".to_string()))?;
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
                            let pubkey_pem = std::str::from_utf8(&*pubkey_bytes).map_err(|_| CryptoError::Parameter("Invalid UTF-8 in key".to_string()))?;
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
                    let passphrase = config.passphrase.as_ref().map(|s| s.clone());
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

                let (s2c_key, s2c_iv, c2s_key, c2s_iv) = handshake_result;

                if config.chat_mode {
                    let stdin = self.io_provider.stdin();
                    let stdout = Arc::new(tokio::sync::Mutex::new(self.io_provider.stdout()));

                    CommonProcessor::chat_loop(reader, writer, stdin, stdout, &config.aead_algo, &s2c_key, &c2s_key, false).await
                } else {
                    tokio::time::timeout(crate::network::CUMULATIVE_TIMEOUT, async {
                        CommonProcessor::send_file(self.io_provider.stdin(), writer, &config.aead_algo, &c2s_key, &c2s_iv).await
                    }).await.map_err(|e| CryptoError::Parameter(format!("File send failed: {}", e)))??;
                    Ok(())
                }
            } => r,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\r\n[nkct] Interrupted by user. Closing...");
                Ok(())
            }
        };

        let _ = endpoint_cleanup.close().await;
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;
    use crate::utils;
    use std::sync::atomic::Ordering;
    use serial_test::serial;
    use crate::network::TestIOProvider;

    fn reset_state() {
        CHAT_ACTIVE.store(false, Ordering::SeqCst);
        PEER_COOLDOWNS.lock().clear();
    }

    fn make_ticket(addr: &iroh::NodeAddr, sign_fp: Option<[u8; 32]>, enc_fp: Option<[u8; 32]>) -> String {
        Ticket::new(addr.clone(), sign_fp, enc_fp).to_string()
    }

    #[tokio::test]
    #[serial]
    async fn test_iroh_handshake_unauth() {
        reset_state();
        let (node_id_tx, node_id_rx) = tokio::sync::oneshot::channel();
        let mut server_config = CryptoConfig::default();
        server_config.transport = crate::config::TransportKind::Iroh;
        server_config.chat_mode = false;
        server_config.allow_unauth = true;
        server_config.handshake_timeout = 2;
        let server_task = tokio::spawn(async move {
            let mut processor = NetworkProcessor::with_io(server_config, Arc::new(TestIOProvider));
            processor.preload_allowlist().await.unwrap();
            let endpoint = processor.create_endpoint(true).await.unwrap();
            let _guard = EndpointGuard(endpoint.clone());
            let _ = node_id_tx.send((endpoint.node_addr().initialized().await, endpoint.clone()));
            let _ = processor.run_listen_loop(endpoint).await;
        });
        let (node_addr, _server_endpoint) = tokio::time::timeout(Duration::from_secs(2), node_id_rx).await.unwrap().unwrap();
        let mut client_config = CryptoConfig::default();
        client_config.transport = crate::config::TransportKind::Iroh;
        client_config.connect_addr = Some(make_ticket(&node_addr, None, None));
        client_config.chat_mode = false;
        client_config.allow_unauth = true;
        client_config.handshake_timeout = 2;
        let client_res = tokio::time::timeout(Duration::from_secs(2), async {
            let processor = NetworkProcessor::with_io(client_config, Arc::new(TestIOProvider));
            processor.run_connect().await
        }).await;
        server_task.abort();
        assert!(client_res.unwrap().is_ok());
    }

    #[tokio::test]
    #[serial]
    async fn test_iroh_handshake_auth_success() {
        reset_state();
        let dir = tempdir().unwrap();
        let s_key_path = dir.path().join("s.priv.pem");
        let s_pub_path = dir.path().join("s.pub.pem");
        let c_key_path = dir.path().join("c.priv.pem");
        let c_pub_path = dir.path().join("c.pub.pem");
        let (s_priv, s_pub, _) = backend::pqc_keygen_dsa("ML-DSA-65").unwrap();
        let (c_priv, c_pub, _) = backend::pqc_keygen_dsa("ML-DSA-65").unwrap();
        fs::write(&s_key_path, utils::wrap_to_pem(&utils::wrap_pqc_priv_to_pkcs8(&s_priv, "ML-DSA-65").unwrap(), "PRIVATE KEY")).unwrap();
        fs::write(&s_pub_path, utils::wrap_to_pem(&utils::wrap_pqc_pub_to_spki(&s_pub, "ML-DSA-65").unwrap(), "PUBLIC KEY")).unwrap();
        fs::write(&c_key_path, utils::wrap_to_pem(&utils::wrap_pqc_priv_to_pkcs8(&c_priv, "ML-DSA-65").unwrap(), "PRIVATE KEY")).unwrap();
        fs::write(&c_pub_path, utils::wrap_to_pem(&utils::wrap_pqc_pub_to_spki(&c_pub, "ML-DSA-65").unwrap(), "PUBLIC KEY")).unwrap();
        let s_fp = Sha3_256::digest(&s_pub).into();
        let (node_id_tx, node_id_rx) = tokio::sync::oneshot::channel();
        let mut server_config = CryptoConfig::default();
        server_config.transport = crate::config::TransportKind::Iroh;
        server_config.chat_mode = false;
        server_config.allow_unauth = false;
        server_config.signing_privkey = Some(s_key_path.to_str().unwrap().to_string());
        server_config.signing_pubkey = Some(c_pub_path.to_str().unwrap().to_string());
        server_config.handshake_timeout = 2;
        let _server_task = tokio::spawn(async move {
            let mut processor = NetworkProcessor::with_io(server_config, Arc::new(TestIOProvider));
            processor.preload_allowlist().await.unwrap();
            let endpoint = processor.create_endpoint(true).await.unwrap();
            let _guard = EndpointGuard(endpoint.clone());
            let _ = node_id_tx.send((endpoint.node_addr().initialized().await, endpoint.clone()));
            let _ = processor.run_listen_loop(endpoint).await;
        });
        let (node_addr, _server_endpoint) = node_id_rx.await.unwrap();
        let mut client_config = CryptoConfig::default();
        client_config.transport = crate::config::TransportKind::Iroh;
        client_config.connect_addr = Some(make_ticket(&node_addr, Some(s_fp), None));
        client_config.chat_mode = false;
        client_config.allow_unauth = false;
        client_config.signing_privkey = Some(c_key_path.to_str().unwrap().to_string());
        client_config.signing_pubkey = Some(s_pub_path.to_str().unwrap().to_string());
        client_config.handshake_timeout = 2;
        let client_res = tokio::time::timeout(Duration::from_secs(2), async {
            let processor = NetworkProcessor::with_io(client_config, Arc::new(TestIOProvider));
            processor.run_connect().await
        }).await;
        assert!(client_res.unwrap().is_ok());
    }

    #[tokio::test]
    #[serial]
    async fn test_iroh_handshake_auth_fail_fingerprint_mismatch() {
        reset_state();
        let dir = tempdir().unwrap();
        let s_key_path = dir.path().join("s.priv.pem");
        let c_pub_path = dir.path().join("c.pub.pem");
        let (s_priv, s_pub, _) = backend::pqc_keygen_dsa("ML-DSA-65").unwrap();
        let (_, c_pub, _) = backend::pqc_keygen_dsa("ML-DSA-65").unwrap();
        fs::write(&s_key_path, utils::wrap_to_pem(&utils::wrap_pqc_priv_to_pkcs8(&s_priv, "ML-DSA-65").unwrap(), "PRIVATE KEY")).unwrap();
        fs::write(&c_pub_path, utils::wrap_to_pem(&utils::wrap_pqc_pub_to_spki(&c_pub, "ML-DSA-65").unwrap(), "PUBLIC KEY")).unwrap();
        let wrong_fp = [0u8; 32];
        let (node_id_tx, node_id_rx) = tokio::sync::oneshot::channel();
        let mut server_config = CryptoConfig::default();
        server_config.transport = crate::config::TransportKind::Iroh;
        server_config.chat_mode = false;
        server_config.allow_unauth = true;
        server_config.signing_privkey = Some(s_key_path.to_str().unwrap().to_string());
        server_config.handshake_timeout = 2;
        let _server_task = tokio::spawn(async move {
            let mut processor = NetworkProcessor::with_io(server_config, Arc::new(TestIOProvider));
            processor.preload_allowlist().await.unwrap();
            let endpoint = processor.create_endpoint(true).await.unwrap();
            let _guard = EndpointGuard(endpoint.clone());
            let _ = node_id_tx.send((endpoint.node_addr().initialized().await, endpoint.clone()));
            let _ = processor.run_listen_loop(endpoint).await;
        });
        let (node_addr, _server_endpoint) = node_id_rx.await.unwrap();
        let mut client_config = CryptoConfig::default();
        client_config.transport = crate::config::TransportKind::Iroh;
        client_config.connect_addr = Some(make_ticket(&node_addr, Some(wrong_fp), None));
        client_config.chat_mode = false;
        client_config.allow_unauth = true;
        client_config.handshake_timeout = 2;
        let client_res = tokio::time::timeout(Duration::from_secs(2), async {
            let processor = NetworkProcessor::with_io(client_config, Arc::new(TestIOProvider));
            processor.run_connect().await
        }).await;
        assert!(client_res.unwrap().is_err());
    }

    #[tokio::test]
    #[serial]
    async fn test_iroh_handshake_auth_fail_invalid_sig() {
        reset_state();
        let dir = tempdir().unwrap();
        let s_key_path = dir.path().join("s.priv.pem");
        let c_pub_path = dir.path().join("c.pub.pem");
        let (s_priv, _, _) = backend::pqc_keygen_dsa("ML-DSA-65").unwrap();
        let (_, c_pub, _) = backend::pqc_keygen_dsa("ML-DSA-65").unwrap();
        let (_, wrong_c_pub, _) = backend::pqc_keygen_dsa("ML-DSA-65").unwrap();
        fs::write(&s_key_path, utils::wrap_to_pem(&utils::wrap_pqc_priv_to_pkcs8(&s_priv, "ML-DSA-65").unwrap(), "PRIVATE KEY")).unwrap();
        fs::write(&c_pub_path, utils::wrap_to_pem(&utils::wrap_pqc_pub_to_spki(&wrong_c_pub, "ML-DSA-65").unwrap(), "PUBLIC KEY")).unwrap();
        let (node_id_tx, node_id_rx) = tokio::sync::oneshot::channel();
        let mut server_config = CryptoConfig::default();
        server_config.transport = crate::config::TransportKind::Iroh;
        server_config.chat_mode = false;
        server_config.allow_unauth = false;
        server_config.signing_privkey = Some(s_key_path.to_str().unwrap().to_string());
        server_config.signing_pubkey = Some(c_pub_path.to_str().unwrap().to_string());
        server_config.handshake_timeout = 2;
        let _server_task = tokio::spawn(async move {
            let mut processor = NetworkProcessor::with_io(server_config, Arc::new(TestIOProvider));
            processor.preload_allowlist().await.unwrap();
            let endpoint = processor.create_endpoint(true).await.unwrap();
            let _guard = EndpointGuard(endpoint.clone());
            let _ = node_id_tx.send((endpoint.node_addr().initialized().await, endpoint.clone()));
            let _ = processor.run_listen_loop(endpoint).await;
        });
        let (node_addr, _server_endpoint) = node_id_rx.await.unwrap();
        let mut client_config = CryptoConfig::default();
        client_config.transport = crate::config::TransportKind::Iroh;
        client_config.connect_addr = Some(make_ticket(&node_addr, None, None));
        client_config.chat_mode = false;
        client_config.allow_unauth = true;
        let client_res = tokio::time::timeout(Duration::from_secs(2), async {
            let processor = NetworkProcessor::with_io(client_config, Arc::new(TestIOProvider));
            processor.run_connect().await
        }).await;
        assert!(client_res.unwrap().is_err());
    }

    #[tokio::test]
    #[serial]
    async fn test_iroh_handshake_allowlist_reject() {
        reset_state();
        let dir = tempdir().unwrap();
        let allowlist_path = dir.path().join("allowlist.txt");
        fs::write(&allowlist_path, "0000000000000000000000000000000000000000000000000000000000000000\n").unwrap();
        let (node_id_tx, node_id_rx) = tokio::sync::oneshot::channel();
        let mut server_config = CryptoConfig::default();
        server_config.transport = crate::config::TransportKind::Iroh;
        server_config.chat_mode = false;
        server_config.allow_unauth = true;
        server_config.peer_allowlist = Some(allowlist_path.to_str().unwrap().to_string());
        server_config.handshake_timeout = 2;
        let _server_task = tokio::spawn(async move {
            let mut processor = NetworkProcessor::with_io(server_config, Arc::new(TestIOProvider));
            processor.preload_allowlist().await.unwrap();
            let endpoint = processor.create_endpoint(true).await.unwrap();
            let _guard = EndpointGuard(endpoint.clone());
            let _ = node_id_tx.send((endpoint.node_addr().initialized().await, endpoint.clone()));
            let _ = processor.run_listen_loop(endpoint).await;
        });
        let (node_addr, _server_endpoint) = node_id_rx.await.unwrap();
        let mut client_config = CryptoConfig::default();
        client_config.transport = crate::config::TransportKind::Iroh;
        client_config.connect_addr = Some(make_ticket(&node_addr, None, None));
        client_config.chat_mode = false;
        client_config.allow_unauth = true;
        let client_res = tokio::time::timeout(Duration::from_secs(2), async {
            let processor = NetworkProcessor::with_io(client_config, Arc::new(TestIOProvider));
            processor.run_connect().await
        }).await;
        assert!(client_res.unwrap().is_err());
    }

    #[tokio::test]
    #[serial]
    async fn test_iroh_handshake_multi_client_auth_success() {
        reset_state();
        let dir = tempdir().unwrap();
        let s_key_path = dir.path().join("s.priv.pem");
        let c_key_path = dir.path().join("c.priv.pem");
        let allowlist_path = dir.path().join("allowlist.txt");
        let (s_priv, _, _) = backend::pqc_keygen_dsa("ML-DSA-65").unwrap();
        let (c_priv, c_pub, _) = backend::pqc_keygen_dsa("ML-DSA-65").unwrap();
        fs::write(&s_key_path, utils::wrap_to_pem(&utils::wrap_pqc_priv_to_pkcs8(&s_priv, "ML-DSA-65").unwrap(), "PRIVATE KEY")).unwrap();
        fs::write(&c_key_path, utils::wrap_to_pem(&utils::wrap_pqc_priv_to_pkcs8(&c_priv, "ML-DSA-65").unwrap(), "PRIVATE KEY")).unwrap();
        fs::write(&allowlist_path, format!("{}\n", hex::encode(Sha3_256::digest(&c_pub)))).unwrap();
        let (node_id_tx, node_id_rx) = tokio::sync::oneshot::channel();
        let mut server_config = CryptoConfig::default();
        server_config.transport = crate::config::TransportKind::Iroh;
        server_config.chat_mode = false;
        server_config.allow_unauth = false;
        server_config.signing_privkey = Some(s_key_path.to_str().unwrap().to_string());
        server_config.peer_allowlist = Some(allowlist_path.to_str().unwrap().to_string());
        server_config.handshake_timeout = 2;
        let _server_task = tokio::spawn(async move {
            let mut processor = NetworkProcessor::with_io(server_config, Arc::new(TestIOProvider));
            processor.preload_allowlist().await.unwrap();
            let endpoint = processor.create_endpoint(true).await.unwrap();
            let _guard = EndpointGuard(endpoint.clone());
            let _ = node_id_tx.send((endpoint.node_addr().initialized().await, endpoint.clone()));
            let _ = processor.run_listen_loop(endpoint).await;
        });
        let (node_addr, _server_endpoint) = node_id_rx.await.unwrap();
        let mut client_config = CryptoConfig::default();
        client_config.transport = crate::config::TransportKind::Iroh;
        client_config.connect_addr = Some(make_ticket(&node_addr, None, None));
        client_config.chat_mode = false;
        client_config.allow_unauth = false;
        client_config.signing_privkey = Some(c_key_path.to_str().unwrap().to_string());
        let client_res = tokio::time::timeout(Duration::from_secs(2), async {
            let processor = NetworkProcessor::with_io(client_config, Arc::new(TestIOProvider));
            processor.run_connect().await
        }).await;
        assert!(client_res.unwrap().is_ok());
    }

    #[tokio::test]
    #[serial]
    async fn test_iroh_chat_loop_smoke() {
        reset_state();
        let (node_id_tx, node_id_rx) = tokio::sync::oneshot::channel();
        let mut server_config = CryptoConfig::default();
        server_config.transport = crate::config::TransportKind::Iroh;
        server_config.chat_mode = true;
        server_config.allow_unauth = true;
        let _server_task = tokio::spawn(async move {
            let mut processor = NetworkProcessor::with_io(server_config, Arc::new(TestIOProvider));
            processor.preload_allowlist().await.unwrap();
            let endpoint = processor.create_endpoint(true).await.unwrap();
            let _guard = EndpointGuard(endpoint.clone());
            let _ = node_id_tx.send((endpoint.node_addr().initialized().await, endpoint.clone()));
            let _ = processor.run_listen_loop(endpoint).await;
        });
        let (node_addr, _server_endpoint) = tokio::time::timeout(Duration::from_secs(2), node_id_rx).await.unwrap().unwrap();
        let mut client_config = CryptoConfig::default();
        client_config.transport = crate::config::TransportKind::Iroh;
        client_config.connect_addr = Some(make_ticket(&node_addr, None, None));
        client_config.chat_mode = true;
        client_config.allow_unauth = true;
        let client_res = tokio::time::timeout(Duration::from_secs(5), async {
            let processor = NetworkProcessor::with_io(client_config, Arc::new(TestIOProvider));
            processor.run_connect().await
        }).await;
        // After F-IROH-39 fix, stdin EOF should lead to a clean exit, not a timeout.
        match client_res {
            Ok(res) => assert!(res.is_ok(), "Chat loop should exit cleanly on stdin EOF"),
            Err(_) => panic!("Chat loop timed out unexpectedly"),
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_iroh_file_transfer_smoke() {
        reset_state();
        let (node_id_tx, node_id_rx) = tokio::sync::oneshot::channel();
        let mut server_config = CryptoConfig::default();
        server_config.transport = crate::config::TransportKind::Iroh;
        server_config.chat_mode = false;
        server_config.allow_unauth = true;
        let _server_task = tokio::spawn(async move {
            let mut processor = NetworkProcessor::with_io(server_config, Arc::new(TestIOProvider));
            processor.preload_allowlist().await.unwrap();
            let endpoint = processor.create_endpoint(true).await.unwrap();
            let _guard = EndpointGuard(endpoint.clone());
            let _ = node_id_tx.send((endpoint.node_addr().initialized().await, endpoint.clone()));
            let _ = processor.run_listen_loop(endpoint).await;
        });
        let (node_addr, _server_endpoint) = tokio::time::timeout(Duration::from_secs(2), node_id_rx).await.unwrap().unwrap();
        let mut client_config = CryptoConfig::default();
        client_config.transport = crate::config::TransportKind::Iroh;
        client_config.connect_addr = Some(make_ticket(&node_addr, None, None));
        client_config.chat_mode = false;
        client_config.allow_unauth = true;
        let client_res = tokio::time::timeout(Duration::from_secs(2), async {
            let processor = NetworkProcessor::with_io(client_config, Arc::new(TestIOProvider));
            processor.run_connect().await
        }).await;
        assert!(client_res.unwrap().is_ok());
    }
}
