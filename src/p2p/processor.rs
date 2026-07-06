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

/// Handshake presence-flag bits (KEY_EXCHANGE_DESIGN.md §4.0). Each is a single
/// raw byte placed in the signed transcript BEFORE the fields it gates, so the
/// peer reads it first and the presence of later fields is wire-deterministic.
/// Any bit outside the per-direction "allowed" set is reserved and MUST be
/// rejected (a non-zero reserved bit is a malformed / future-version frame).
mod hs_flags {
    /// `#5` bit0: the initiator authenticates itself (gates `#6` initiator
    /// ML-DSA pub + sig_I over the initiator transcript).
    pub const INITIATOR_SELF_AUTH: u8 = 0x01;
    /// `#5` bit1: the initiator requires the responder to authenticate. Gates
    /// `#7` (expected-responder-fingerprint pre-commit, raw32) and, on the
    /// initiator, the both-sided pin verification of sig_R (A-init). Set iff the
    /// initiator holds a responder pin it will verify against.
    pub const EXPECTS_RESPONDER_AUTH: u8 = 0x02;
    /// `#10` bit0: the responder authenticates itself (gates `#11`/`#12` + sig_R).
    pub const RESPONDER_SELF_AUTH: u8 = 0x01;
    /// Initiator-flags bits currently honoured; others → reject as reserved.
    pub const INITIATOR_ALLOWED: u8 = INITIATOR_SELF_AUTH | EXPECTS_RESPONDER_AUTH;
    /// Responder-flags bits currently honoured; others → reject as reserved.
    pub const RESPONDER_ALLOWED: u8 = RESPONDER_SELF_AUTH;
}

/// FIPS 204 signature context for the iroh handshake (KEY_EXCHANGE_DESIGN.md
/// §2.1). iroh is the only transport (the TCP transport was removed). Binds
/// sig_I / sig_R to this purpose, so a handshake signature cannot be replayed
/// into another identity-key context (prekey, keybind, bundle, file). Both sign
/// and verify sides use it — flipping from `""` is a wire break, paired with the
/// ALPN bump below so old/new peers fail cleanly.
const HANDSHAKE_CTX_IROH: &[u8] = b"nkct-handshake-iroh-v1";

/// Reject a handshake field whose length is not the fixed size expected for the
/// negotiated algorithm (KEY_EXCHANGE_DESIGN.md §10(B), parser robustness B):
/// closes length-confusion at the parser door instead of trusting the crypto
/// backend to error later. Returns `Err` — never panics — so an attacker-
/// controlled length is a clean handshake failure, not a remote DoS (this
/// project has a peer-id-parse remote-panic history; "assert" here is semantic,
/// not the `assert!` macro). `expected == None` (unknown algorithm) skips the
/// check and lets the backend reject the algorithm.
fn ensure_field_len(field: &str, got: usize, expected: Option<usize>) -> Result<()> {
    if let Some(n) = expected {
        if got != n {
            return Err(CryptoError::Parameter(format!(
                "handshake field {field}: expected {n} bytes for the negotiated algorithm, got {got}"
            )));
        }
    }
    Ok(())
}

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
            if let Some(image) = crate::utils::render_qr_unicode(&ticket.to_string()) {
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

    /// Neutralize terminal-spoofing characters in a message that may embed
    /// remote-supplied bytes (an unknown ALPN, a peer-influenced error string):
    /// strips control chars and bidi/zero-width marks that would otherwise inject
    /// escape sequences or reorder an operator's terminal / log display.
    fn sanitize_for_terminal(msg: &str) -> String {
        let unsafe_char = |c: char| {
            c.is_control()
                || ('\u{200B}'..='\u{200F}').contains(&c) // zero-width + bidi marks
                || ('\u{202A}'..='\u{202E}').contains(&c) // bidi embed/override
                || ('\u{2066}'..='\u{2069}').contains(&c) // bidi isolates
        };
        msg.chars()
            .map(|c| if unsafe_char(c) { ' ' } else { c })
            .collect()
    }

    async fn run_listen_loop(&self) -> Result<()> {
        // Accept is now cheap: the backend `accept()` returns a `P2pPending`
        // WITHOUT running the per-connection setup (ALPN negotiation + `accept_bi`),
        // so a peer that stalls mid-handshake can no longer hold up new accepts.
        // Each accepted connection reserves a concurrency permit, then runs
        // `establish` — bounded by `P2P_SETUP_TIMEOUT` — in its own spawned task,
        // off this loop. This fixes the head-of-line stall this note previously
        // described as future work. The permit is acquired BEFORE spawning so a
        // flood of half-open peers cannot spawn unbounded setup tasks. Because each
        // iteration does only one cheap accept, we must NOT add any fixed delay on
        // error (a backoff sleep would itself become a DoS an attacker could trigger
        // by forcing errors) — on error we only `yield_now` to stay cooperative.
        loop {
            // One inbound connection per iteration. A per-connection failure
            // (dropped mid-handshake, unknown ALPN, `accept_bi` error — all common
            // over relay/NAT) must NOT tear down a long-running server: log it and
            // keep accepting. Only a closed endpoint (shutdown / ctrl-c) ends the
            // loop. (Previously `while let Ok(..)` exited on the first such error,
            // so the server died after a single connection.)
            let pending = match self.endpoint.accept().await {
                Ok(inc) => inc,
                Err(crate::p2p::P2pError::Closed) => break,
                Err(e) => {
                    let msg = Self::sanitize_for_terminal(&e.to_string());
                    eprintln!("[nkct] accept error (continuing to serve): {msg}");
                    // Cooperative yield only — no fixed delay (see the serial-accept
                    // note above). Should `accept()` ever return errors without
                    // blocking (e.g. fd exhaustion), this keeps the loop from
                    // starving the spawned connection handlers without handing an
                    // attacker a delay to weaponize.
                    tokio::task::yield_now().await;
                    continue;
                }
            };
            // Reserve a concurrency slot BEFORE spawning the per-connection setup:
            // a flood of half-open peers then cannot spawn unbounded setup tasks.
            // A stalling peer's `establish` times out within P2P_SETUP_TIMEOUT,
            // freeing its slot, so the accept loop is never permanently starved.
            let permit = match self.semaphore.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => break, // semaphore closed → endpoint shutting down
            };
            let config_clone = self.config.clone();
            let cached_allowlist = self.cached_allowlist.clone();
            let local_peer_id = self.endpoint.local_id();
            let io_provider = self.io_provider.clone();

            tokio::spawn(async move {
                let _permit = permit; // held for the connection's lifetime

                // Protocol negotiation + stream open run HERE, off the accept loop,
                // bounded by the timeout — a peer that stalls this cannot block
                // other connections from being accepted and served.
                let incoming = match pending.establish(crate::p2p::P2P_SETUP_TIMEOUT).await {
                    Ok(inc) => inc,
                    Err(e) => {
                        eprintln!(
                            "[nkct] connection setup failed (continuing to serve): {}",
                            Self::sanitize_for_terminal(&e.to_string())
                        );
                        return;
                    }
                };

                let mut config = config_clone;
                // Only a node started with `--serve-shell` (which validated
                // authz and refused root at startup) may serve a shell; a peer
                // requesting the shell ALPN must not be able to turn an ordinary
                // chat/file node — or a shell *client* — into a shell server.
                // Set the mode exclusively from the ALPN.
                let shell_allowed = config.serve_shell;
                let forward_allowed = config.serve_forward;
                let scp_allowed = config.serve_scp;
                config.shell_mode = false;
                config.chat_mode = false;
                config.forward_mode = false;
                config.scp_mode = false;
                if incoming.protocol.0 == ALPN_CHAT {
                    config.chat_mode = true;
                } else if incoming.protocol.0 == ALPN_FILE {
                    // file receive: both modes false
                } else if incoming.protocol.0 == crate::network::ALPN_SHELL {
                    if !shell_allowed {
                        eprintln!("Rejecting nkct/shell/2: this node is not a shell server");
                        return;
                    }
                    config.shell_mode = true;
                } else if incoming.protocol.0 == crate::network::ALPN_FWD {
                    if !forward_allowed {
                        eprintln!("Rejecting nkct/fwd/2: this node is not a forward server");
                        return;
                    }
                    config.forward_mode = true;
                } else if incoming.protocol.0 == crate::network::ALPN_SCP {
                    if !scp_allowed {
                        eprintln!("Rejecting nkct/scp/2: this node is not an scp server");
                        return;
                    }
                    config.scp_mode = true;
                } else {
                    eprintln!("Unknown ALPN: {:?}", String::from_utf8_lossy(incoming.protocol.0));
                    return;
                }

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
        let pending = self.endpoint.accept().await
            .map_err(|e| CryptoError::Parameter(format!("Accept failed: {}", e)))?;
        // Single-shot: run the per-connection setup inline, but still bound it so
        // a peer that completes the QUIC handshake then never opens a stream
        // cannot hang the listener forever.
        let incoming = pending.establish(crate::p2p::P2P_SETUP_TIMEOUT).await
            .map_err(|e| CryptoError::Parameter(format!("Connection setup failed: {}", e)))?;

        let mut config = self.config.clone();
        let shell_allowed = config.serve_shell;
        let forward_allowed = config.serve_forward;
        let scp_allowed = config.serve_scp;
        config.shell_mode = false;
        config.chat_mode = false;
        config.forward_mode = false;
        config.scp_mode = false;
        if incoming.protocol.0 == ALPN_CHAT {
            config.chat_mode = true;
        } else if incoming.protocol.0 == ALPN_FILE {
            // file receive: both modes false
        } else if incoming.protocol.0 == crate::network::ALPN_SHELL {
            if !shell_allowed {
                return Err(CryptoError::Parameter(
                    "shell (nkct/shell/2) is not enabled on this node".to_string(),
                ));
            }
            config.shell_mode = true;
        } else if incoming.protocol.0 == crate::network::ALPN_FWD {
            if !forward_allowed {
                return Err(CryptoError::Parameter(
                    "forward (nkct/fwd/2) is not enabled on this node".to_string(),
                ));
            }
            config.forward_mode = true;
        } else if incoming.protocol.0 == crate::network::ALPN_SCP {
            if !scp_allowed {
                return Err(CryptoError::Parameter(
                    "scp (nkct/scp/2) is not enabled on this node".to_string(),
                ));
            }
            config.scp_mode = true;
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

        // Auth-failure throttle (keyed by the transport NodeId, which we have
        // before app-auth runs): if this peer has failed too many handshakes
        // recently, refuse before doing any handshake work. Distinct from any
        // limit on *authenticated* operations — see `crate::shell`.
        let remote_node = *remote_peer_id.as_bytes();
        if crate::shell::auth_failure_blocked(&remote_node) {
            return Err(CryptoError::Parameter(
                "too many failed authentication attempts from this peer; try again shortly".to_string(),
            ));
        }

        let handshake_outcome = tokio::time::timeout(handshake_timeout, async {
            let mut tb = TranscriptBuilder::new();
            tb.append_raw(remote_peer_id.as_bytes()); // #1 client id
            tb.append_raw(local_peer_id.as_bytes()); // #2 server id

            let client_ecc_pub = CommonProcessor::read_vec(&mut reader).await?;
            ensure_field_len("#3 initiator P-256", client_ecc_pub.len(), Some(backend::P256_SPKI_DER_LEN))?;
            let client_kem_pub = CommonProcessor::read_vec(&mut reader).await?;
            ensure_field_len("#4 initiator ML-KEM ek", client_kem_pub.len(), backend::mlkem_ek_len(&config.pqc_kem_algo))?;

            tb.append_lp(&client_ecc_pub); // #3
            tb.append_lp(&client_kem_pub); // #4

            let mut client_auth_flag = [0u8; 1];
            reader.read_exact(&mut client_auth_flag).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
            tb.append_raw(&client_auth_flag); // #5 initiator flags
            if client_auth_flag[0] & !hs_flags::INITIATOR_ALLOWED != 0 {
                return Err(CryptoError::Parameter(
                    "Handshake failed: reserved bit set in initiator flags (#5)".to_string(),
                ));
            }

            // #6 initiator ML-DSA pub (if self-auth) — read and append; defer sig_I
            // verification until #7 is appended so it is checked over #1–#7.
            let mut client_dsa_pub: Option<Vec<u8>> = None;
            if client_auth_flag[0] & hs_flags::INITIATOR_SELF_AUTH != 0 {
                let pk = CommonProcessor::read_vec(&mut reader).await?;
                ensure_field_len("#6 initiator ML-DSA pub", pk.len(), backend::mldsa_pub_len(&config.pqc_dsa_algo))?;
                tb.append_lp(&pk); // #6
                client_dsa_pub = Some(pk);
            }

            // #7 expected-responder-fingerprint pre-commit (raw32, if bit1). Read and
            // append so it is bound into sig_I (verified below) and later sig_R. The
            // A-resp cross-check (#7 == fingerprint(own identity)) is applied once the
            // responder's own pub is known, just before signing sig_R.
            let expects_responder_auth = client_auth_flag[0] & hs_flags::EXPECTS_RESPONDER_AUTH != 0;
            let mut expected_responder_fp = [0u8; 32];
            if expects_responder_auth {
                reader.read_exact(&mut expected_responder_fp).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
                tb.append_raw(&expected_responder_fp); // #7 expected responder fingerprint
            }

            // sig_I over the initiator transcript #1–#7 (if self-auth).
            if let Some(ref pk) = client_dsa_pub {
                // A-init (server side, §4.2 / §6.2): when a single client identity is
                // pinned, bind the wire #6 to it BEFORE verifying sig_I, so the signature
                // is checked against the pinned key — not a self-consistent wire key a
                // MITM could substitute. Symmetric with the initiator's A-init: never
                // trust the wire key. (The allowlist is a SET, so it stays an exact
                // membership check applied after verify — there is no single key to bind.)
                if let Some(ref pubkey_path) = config.signing_pubkey {
                    let pubkey_bytes = Zeroizing::new(std::fs::read(pubkey_path).map_err(|e| CryptoError::FileRead(e.to_string()))?);
                    let pubkey_pem = std::str::from_utf8(&pubkey_bytes).map_err(|_| CryptoError::Parameter("Invalid UTF-8 in key".to_string()))?;
                    let pubkey_der = crate::utils::unwrap_from_pem(pubkey_pem, "PUBLIC KEY")?;
                    let pinned_raw_pub = crate::utils::unwrap_pqc_pub_from_spki(&pubkey_der, &config.pqc_dsa_algo)?;
                    if pinned_raw_pub != *pk {
                        return Err(CryptoError::Parameter("Client public key mismatch with pinned key".to_string()));
                    }
                }

                let sig = CommonProcessor::read_vec(&mut reader).await?;
                ensure_field_len("sig_I", sig.len(), backend::mldsa_sig_len(&config.pqc_dsa_algo))?;
                if !backend::pqc_verify(&config.pqc_dsa_algo, pk, tb.snapshot(), &sig, HANDSHAKE_CTX_IROH)? {
                    return Err(CryptoError::SignatureVerification);
                }

                let hash: [u8; 32] = Sha3_256::digest(pk).into();
                peer_id_opt = Some(PeerId::Pubkey(hash));
                eprintln!("Client authenticated successfully (auth: {}).", config.pqc_dsa_algo);
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

            tb.append_lp(&server_ecc_pub); // #8
            tb.append_lp(&kem_ct); // #9

            let server_auth_flag = if config.signing_privkey.is_some() { [hs_flags::RESPONDER_SELF_AUTH] } else { [0u8] };
            tb.append_raw(&server_auth_flag); // #10 responder flags

            // A-resp (§4.2): if the initiator required responder auth (#5.bit1), this
            // node MUST actually self-authenticate. Without a signing key it cannot, so
            // abort now rather than send an unauthenticated hello the initiator would
            // (correctly) reject as a downgrade.
            if expects_responder_auth && server_auth_flag[0] & hs_flags::RESPONDER_SELF_AUTH == 0 {
                return Err(CryptoError::Parameter(
                    "Handshake failed: initiator requires responder authentication but this node has no signing key".to_string(),
                ));
            }

            let mut server_sig = Vec::new();
            let mut server_dsa_pub = Vec::new();
            let mut server_kem_pub = Vec::new();
            if server_auth_flag[0] & hs_flags::RESPONDER_SELF_AUTH != 0 {
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
                tb.append_lp(&server_dsa_pub); // #11

                // A-resp (§4.2, invariant b): if the initiator pre-committed #7, it must
                // name THIS responder. Re-derive our OWN fingerprint and compare — #7 is a
                // comparison target, never a trust input. This closes the relay/misbinding
                // face (a MITM relaying the initiator's handshake to a different responder
                // fails here).
                //
                // Works regardless of whether #7 was covered by sig_I. For an anonymous
                // initiator (#5.bit0 = 0) #7 is NOT in sig_I, but misbinding is still
                // closed by two independent facts: (i) A-resp only compares #7 to our own
                // fingerprint, so #7's origin is irrelevant — a tampered #7 that does not
                // equal our identity just aborts; (ii) the initiator verifies sig_R against
                // its pinned P (A-init), so a responder != P is rejected on the initiator
                // side. Tampering with an unsigned #7 is therefore at worst an availability
                // issue (abort), never a misbinding. (Do NOT "optimise" this to only run
                // when sig_I covered #7 — that would drop the anonymous-initiator guarantee.)
                if expects_responder_auth {
                    let own_fp: [u8; 32] = Sha3_256::digest(&server_dsa_pub).into();
                    if own_fp != expected_responder_fp {
                        return Err(CryptoError::Parameter(
                            "Handshake failed: initiator's expected-responder fingerprint (#7) does not match this node's identity".to_string(),
                        ));
                    }
                }

                server_kem_pub = raw_pub_kem;
                tb.append_lp(&server_kem_pub); // #12

                // Sign the full transcript (#1–#12) — the same builder.
                server_sig = backend::pqc_sign(&config.pqc_dsa_algo, &raw_priv_dsa, tb.snapshot(), HANDSHAKE_CTX_IROH)?;
            }

            // Salt = SHA3-256(full transcript) via the SAME builder — no separate
            // digest path that could drift from the bound bytes.
            let salt = tb.finalize_salt();
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
        }).await;

        // Record any handshake/auth failure (or timeout) against this NodeId so a
        // brute-force / retry storm is throttled at the next connection.
        let handshake_result = match handshake_outcome {
            Ok(Ok(keys)) => keys,
            Ok(Err(e)) => {
                crate::shell::note_auth_failure(&remote_node);
                return Err(e);
            }
            Err(_) => {
                crate::shell::note_auth_failure(&remote_node);
                return Err(CryptoError::Parameter("Handshake timed out".to_string()));
            }
        };

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
        } else if config.forward_mode {
            // Phase 3: port-forward server. The authenticated fingerprint keys the
            // forward policy / audit; default deny without a policy.
            let fp = shell_peer_fp.ok_or_else(|| {
                CryptoError::Parameter("forward requires an authenticated peer".to_string())
            })?;
            crate::forward::run_forward_server(
                reader,
                writer,
                &config.aead_algo,
                &s2c_key,
                &c2s_key,
                fp,
                config.forward_policy_path.as_deref(),
                config.audit_log_path.as_deref(),
            )
            .await?;
        } else if config.scp_mode {
            // P2P scp server: policy-gated, path-confined file transfer. The
            // authenticated fingerprint keys the scp policy / audit.
            let fp = shell_peer_fp.ok_or_else(|| {
                CryptoError::Parameter("scp requires an authenticated peer".to_string())
            })?;
            crate::scp::run_scp_server(
                reader,
                writer,
                &config.aead_algo,
                &s2c_key,
                &c2s_key,
                fp,
                config.scp_policy_path.as_deref(),
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
        } else if config.forward_mode {
            crate::network::ALPN_FWD
        } else if config.scp_mode {
            crate::network::ALPN_SCP
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
                // Hole punching across NAT/CGNAT is probabilistic — a single
                // `connect` often times out before a path is found even though the
                // peer is reachable. Bound EACH attempt to a short deadline and
                // retry: a path that can be established is usually found within a
                // few seconds (the relay fallback especially), so cutting a stuck
                // attempt short and restarting converges much faster than waiting
                // out iroh's full ~30 s handshake timeout once per try.
                // Warm up our own relay home first: a fresh endpoint discovers
                // local direct addresses immediately but assigns its home relay a
                // beat later, and connecting before that means the relay fallback
                // path isn't available yet — so the first attempt often times out
                // and only a retry succeeds. Waiting here (bounded inside
                // `local_addr`) lets the very first connect use the relay, usually
                // removing the retry entirely.
                let _ = self.endpoint.local_addr().await;
                const CONNECT_ATTEMPTS: u32 = 5;
                const PER_ATTEMPT: Duration = Duration::from_secs(12);
                let stream = {
                    let mut attempt = 1;
                    loop {
                        let res = tokio::time::timeout(
                            PER_ATTEMPT,
                            self.endpoint.connect(&remote_peer_addr, protocol),
                        )
                        .await;
                        // Flatten timeout(Ok/Err) and the inner connect Result.
                        let outcome = match res {
                            Ok(Ok(s)) => Ok(s),
                            Ok(Err(e)) => Err(e.to_string()),
                            Err(_) => Err("attempt timed out".to_string()),
                        };
                        match outcome {
                            Ok(s) => break s,
                            Err(e) if attempt < CONNECT_ATTEMPTS => {
                                eprintln!(
                                    "[nkct] connect attempt {attempt}/{CONNECT_ATTEMPTS} failed \
                                     ({e}); retrying…"
                                );
                                attempt += 1;
                                tokio::time::sleep(Duration::from_secs(1)).await;
                            }
                            Err(e) => return Err(CryptoError::Parameter(e)),
                        }
                    }
                };
                // Capture live connection metrics (relay/direct + RTT) before the
                // stream is split, for the shell status bar (`--tui`). `None` on
                // backends that don't report them.
                let conn_metrics = self.endpoint.last_connect_metrics();
                let (mut reader, mut writer) = tokio::io::split(stream);

                let handshake_timeout = Duration::from_secs(config.handshake_timeout);
                let handshake_result = tokio::time::timeout(handshake_timeout, async {
                    let mut tb = TranscriptBuilder::new();
                    tb.append_raw(local_peer_id.as_bytes()); // #1 client id
                    tb.append_raw(remote_peer_id.as_bytes()); // #2 server id

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

                    tb.append_lp(&client_ecc_pub); // #3
                    tb.append_lp(&client_kem_pub); // #4

                    // #5 initiator flags: bit0 = self-auth (we hold a signing key);
                    // bit1 = expects_responder_auth (we hold a responder pin and WILL
                    // verify sig_R against it — A-init). §4.4: requiring responder auth
                    // without a pin cannot be satisfied, so refuse rather than trust any
                    // signer — this closes the `--allow-unauth` + no-pin node_id-only path
                    // (the one behaviour change vs the pre-#7 handshake; everything else is
                    // preserved).
                    let has_responder_pin =
                        config.signing_pubkey.is_some() || config.target_sign_fp.is_some();
                    if !config.allow_unauth && !has_responder_pin {
                        return Err(CryptoError::Parameter(
                            "Handshake failed: responder authentication required but no pinned \
                             identity to verify against (provide --signing-pubkey or a ticket \
                             fingerprint, or set --allow-unauth for an anonymous connection)"
                                .to_string(),
                        ));
                    }
                    let expects_responder_auth = has_responder_pin;

                    // #7 pre-commit = the pinned responder fingerprint (raw32 =
                    // SHA3-256(dsa_pub_raw), no prefix — §3). Prefer the ticket fingerprint;
                    // else derive it from the pinned pubkey file. Committing to it inside
                    // sig_I lets the responder cross-check it is the intended peer (A-resp);
                    // it is the same value A-init checks #11 against.
                    let expected_responder_fp: Option<[u8; 32]> = if expects_responder_auth {
                        if let Some(fp) = config.target_sign_fp {
                            Some(fp)
                        } else if let Some(ref pubkey_path) = config.signing_pubkey {
                            let pubkey_bytes = Zeroizing::new(std::fs::read(pubkey_path).map_err(|e| CryptoError::FileRead(e.to_string()))?);
                            let pubkey_pem = std::str::from_utf8(&pubkey_bytes).map_err(|_| CryptoError::Parameter("Invalid UTF-8 in key".to_string()))?;
                            let pubkey_der = crate::utils::unwrap_from_pem(pubkey_pem, "PUBLIC KEY")?;
                            let pinned_raw_pub = crate::utils::unwrap_pqc_pub_from_spki(&pubkey_der, &config.pqc_dsa_algo)?;
                            Some(Sha3_256::digest(&pinned_raw_pub).into())
                        } else {
                            None // unreachable: expects_responder_auth ⇒ has_responder_pin
                        }
                    } else {
                        None
                    };

                    let mut client_flags = 0u8;
                    if config.signing_privkey.is_some() { client_flags |= hs_flags::INITIATOR_SELF_AUTH; }
                    if expects_responder_auth { client_flags |= hs_flags::EXPECTS_RESPONDER_AUTH; }
                    let client_auth_flag = [client_flags];
                    writer.write_all(&client_auth_flag).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
                    tb.append_raw(&client_auth_flag); // #5 initiator flags

                    // #6 initiator ML-DSA pub (if self-auth). Load the signing key but
                    // defer signing until after #7 is appended so sig_I covers #1–#7.
                    let mut sign_priv: Option<Zeroizing<Vec<u8>>> = None;
                    if client_auth_flag[0] & hs_flags::INITIATOR_SELF_AUTH != 0 {
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
                        tb.append_lp(&client_dsa_pub); // #6
                        sign_priv = Some(raw_priv);
                    }

                    // #7 expected-responder-fingerprint pre-commit (raw32), if bit1.
                    if client_auth_flag[0] & hs_flags::EXPECTS_RESPONDER_AUTH != 0 {
                        let fp = expected_responder_fp.expect("bit1 set ⇒ responder fingerprint present");
                        writer.write_all(&fp).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
                        tb.append_raw(&fp); // #7 expected responder fingerprint
                    }

                    // sig_I over the initiator transcript #1–#7 (if self-auth).
                    if let Some(raw_priv) = sign_priv {
                        let sig = backend::pqc_sign(&config.pqc_dsa_algo, &raw_priv, tb.snapshot(), HANDSHAKE_CTX_IROH)?;
                        CommonProcessor::write_vec(&mut writer, &sig).await?;
                    }

                    let server_ecc_pub = CommonProcessor::read_vec(&mut reader).await?;
                    ensure_field_len("#8 responder P-256", server_ecc_pub.len(), Some(backend::P256_SPKI_DER_LEN))?;
                    let kem_ct = CommonProcessor::read_vec(&mut reader).await?;
                    ensure_field_len("#9 ML-KEM ct", kem_ct.len(), backend::mlkem_ct_len(&config.pqc_kem_algo))?;
                    let mut server_auth_flag = [0u8; 1];
                    reader.read_exact(&mut server_auth_flag).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;

                    tb.append_lp(&server_ecc_pub); // #8
                    tb.append_lp(&kem_ct); // #9
                    tb.append_raw(&server_auth_flag); // #10 responder flags
                    if server_auth_flag[0] & !hs_flags::RESPONDER_ALLOWED != 0 {
                        return Err(CryptoError::Parameter(
                            "Handshake failed: reserved bit set in responder flags (#10)".to_string(),
                        ));
                    }

                    if server_auth_flag[0] & hs_flags::RESPONDER_SELF_AUTH != 0 {
                        let server_dsa_pub = CommonProcessor::read_vec(&mut reader).await?;
                        ensure_field_len("#11 responder ML-DSA pub", server_dsa_pub.len(), backend::mldsa_pub_len(&config.pqc_dsa_algo))?;
                        tb.append_lp(&server_dsa_pub); // #11

                        let sig = CommonProcessor::read_vec(&mut reader).await?;
                        ensure_field_len("sig_R", sig.len(), backend::mldsa_sig_len(&config.pqc_dsa_algo))?;

                        let server_kem_pub = CommonProcessor::read_vec(&mut reader).await?;
                        // #12 is OPTIONAL: empty when the responder publishes no static
                        // ML-KEM key (ephemeral #9 still provides FS). Length-check it only
                        // when present; an enc-key pin (target_enc_fp) separately rejects a
                        // stripped/empty #12 via the fingerprint mismatch below.
                        if !server_kem_pub.is_empty() {
                            ensure_field_len("#12 responder ML-KEM ek", server_kem_pub.len(), backend::mlkem_ek_len(&config.pqc_kem_algo))?;
                        }
                        tb.append_lp(&server_kem_pub); // #12

                        // A-init (§4.2): chain sig_R to the PINNED identity. Every pin
                        // input path is checked against the wire responder pub (#11)
                        // BEFORE verifying sig_R, so a MITM presenting its own #11 cannot
                        // pass by having its own key verify its own signature. bit1 ⇒
                        // has_responder_pin, so at least one of these branches runs.
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

                        // Verify sig_R over the full transcript (#1–#12) with the
                        // pin-checked #11 (server_dsa_pub).
                        if !backend::pqc_verify(&config.pqc_dsa_algo, &server_dsa_pub, tb.snapshot(), &sig, HANDSHAKE_CTX_IROH)? {
                            return Err(CryptoError::SignatureVerification);
                        }
                        eprintln!("Server authenticated successfully (auth: {}).", config.pqc_dsa_algo);
                        
                        if let Some(ref allowlist) = self.cached_allowlist {
                            let hash: [u8; 32] = Sha3_256::digest(&server_dsa_pub).into();
                            if !allowlist.contains(&hash) {
                                return Err(CryptoError::Parameter("Server not in allowlist".to_string()));
                            }
                        }
                    } else if expects_responder_auth || config.target_enc_fp.is_some() {
                        // Downgrade detection (§4.2/§4.3): we required responder auth
                        // (#5.bit1, or an enc-key pin) but the responder returned
                        // #10.bit0 = 0 (declined to self-auth). The pin checks live in the
                        // self-auth arm above, so a responder returning flag 0 must not be
                        // able to bypass the pin — abort on the ABSENCE of the demanded
                        // signature.
                        return Err(CryptoError::Parameter("Handshake failed: Server authentication required (pinned key/fingerprint or auth policy)".to_string()));
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

                    // Salt = SHA3-256(full transcript) via the SAME builder — no
                    // separate digest path that could drift from the bound bytes.
                    let salt = tb.finalize_salt();
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

                if config.print_conn_metrics {
                    // Connection-metrics probe (`--conn-metrics`): the handshake is
                    // done, so let the path settle (hole-punch upgrade from relay to
                    // direct can take a moment), then report the selected path kind
                    // and RTT in a parseable line and exit without opening a shell.
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    match conn_metrics.as_ref().and_then(|m| m.snapshot()) {
                        Some(s) => eprintln!(
                            "nkct-metrics relay={} rtt_ms={}",
                            s.relay,
                            s.rtt_ms
                                .map(|v| v.to_string())
                                .unwrap_or_else(|| "na".into())
                        ),
                        None => eprintln!("nkct-metrics relay=na rtt_ms=na"),
                    }
                    return Ok(());
                }

                if config.shell_mode {
                    // Phase 1: drive the local terminal against the remote PTY.
                    // Status bar (`--tui`) only for the interactive shell, not for
                    // a one-shot `--shell-cmd`. v1 shows the cipher suite + NodeId
                    // statically; the path kind (Direct/Relay) and live latency are
                    // filled in by v2 once iroh connection metrics are threaded here.
                    let tui_status = (config.shell_tui && config.shell_command.is_none())
                        .then(|| {
                            // NodeId renders as ASCII hex, but slice on char
                            // boundaries defensively so any future encoding can't
                            // panic.
                            let nid = remote_peer_id.to_string();
                            let node_short = if nid.chars().count() > 12 {
                                let head: String = nid.chars().take(6).collect();
                                let tail: String = {
                                    let t: Vec<char> = nid.chars().collect();
                                    t[t.len() - 4..].iter().collect()
                                };
                                format!("{head}…{tail}")
                            } else {
                                nid
                            };
                            // Live-channel secrecy stack, from the session's real
                            // primitives that are all in hand at this point: the KEM
                            // is the hybrid P-256 ECDH (the hardcoded "prime256v1"
                            // used above) ‖ config.pqc_kem_algo, sealed under
                            // config.aead_algo. Authentication (ML-DSA) is NOT shown
                            // here — its real outcome (server_auth_flag) lives inside
                            // the handshake block and is reported by the
                            // "Server authenticated" log there, so the bar never has
                            // to guess it or carry it out of the handshake.
                            crate::shell::ConnStatus {
                                conn: crate::shell::ConnKind::P2p,
                                latency_ms: None,
                                crypto: format!("P-256+{} / {}", config.pqc_kem_algo, config.aead_algo),
                                node_short,
                                stable: true,
                            }
                        });
                    // Live metrics only matter when the bar is shown.
                    let metrics = tui_status.as_ref().and(conn_metrics);
                    crate::shell::run_pty_client(
                        reader,
                        writer,
                        &config.aead_algo,
                        &s2c_key,
                        &c2s_key,
                        config.shell_command.as_deref().unwrap_or(""),
                        tui_status,
                        metrics,
                    )
                    .await
                } else if config.forward_mode {
                    // Phase 3/4: local (`-L`) and remote (`-R`) port forwards.
                    let mut specs = config
                        .forward_specs
                        .iter()
                        .map(|s| crate::forward::ForwardSpec::parse_local(s))
                        .collect::<std::result::Result<Vec<_>, _>>()
                        .map_err(CryptoError::Parameter)?;
                    for s in &config.remote_forward_specs {
                        specs.push(
                            crate::forward::ForwardSpec::parse_remote(s)
                                .map_err(CryptoError::Parameter)?,
                        );
                    }
                    crate::forward::run_forward_client(
                        reader,
                        writer,
                        &config.aead_algo,
                        &s2c_key,
                        &c2s_key,
                        &specs,
                    )
                    .await
                } else if config.scp_mode {
                    // P2P scp client: one put or get, then return.
                    let op = if let Some((local, remote)) = &config.scp_put {
                        crate::scp::ScpOp::Put { local: local.clone(), remote: remote.clone(), recursive: config.scp_recursive }
                    } else if let Some((remote, local)) = &config.scp_get {
                        crate::scp::ScpOp::Get { remote: remote.clone(), local: local.clone(), recursive: config.scp_recursive }
                    } else {
                        return Err(CryptoError::Parameter(
                            "scp client requires --scp-put or --scp-get".to_string(),
                        ));
                    };
                    crate::scp::run_scp_client(
                        reader,
                        writer,
                        &config.aead_algo,
                        &s2c_key,
                        &c2s_key,
                        &op,
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

/// Accumulates the canonical handshake transcript so the client and server build
/// the identical byte sequence from one source of truth (field order + encoding),
/// instead of two hand-duplicated sequences that could drift.
///
/// `append_lp` delegates to [`CommonProcessor::update_transcript`] so the
/// length-prefix encoding (u32 little-endian — the v3 wire format) is provably
/// unchanged from the legacy inline construction. `snapshot()` returns the bytes
/// so far (the client-signature view is a genuine *prefix* of the full
/// transcript), and `finalize_salt()` is the HKDF salt = SHA3-256(full transcript).
#[derive(Default)]
struct TranscriptBuilder {
    buf: Vec<u8>,
}

impl TranscriptBuilder {
    fn new() -> Self {
        Self::default()
    }

    /// Raw bytes with no length prefix (NodeIds, auth flags).
    fn append_raw(&mut self, b: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(b);
        self
    }

    /// Length-prefixed field (public keys, KEM ciphertext, signatures' targets).
    /// Same encoding as the legacy `update_transcript`.
    fn append_lp(&mut self, b: &[u8]) -> &mut Self {
        CommonProcessor::update_transcript(&mut self.buf, b);
        self
    }

    /// The transcript accumulated so far — a true prefix of any later state.
    fn snapshot(&self) -> &[u8] {
        &self.buf
    }

    /// HKDF salt: SHA3-256 over the full accumulated transcript.
    fn finalize_salt(&self) -> [u8; 32] {
        use sha3::Digest as _;
        Sha3_256::digest(&self.buf).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p::backend::mock::MockNetwork;
    use crate::network::TestIOProvider;

    // Parser robustness (§10(B)): the fixed-length gate must REJECT a wrong length
    // via Result — never panic — and must not fire on a match or an unknown algo.
    #[test]
    fn ensure_field_len_rejects_wrong_length_without_panic() {
        // Match → Ok.
        assert!(ensure_field_len("#6", 1952, backend::mldsa_pub_len("ML-DSA-65")).is_ok());
        assert!(ensure_field_len("sig", 3309, backend::mldsa_sig_len("ML-DSA-65")).is_ok());
        assert!(ensure_field_len("#3", 91, Some(backend::P256_SPKI_DER_LEN)).is_ok());
        // Mismatch (incl. attacker-controlled 0 / oversize) → Err, not panic.
        assert!(ensure_field_len("#6", 1951, backend::mldsa_pub_len("ML-DSA-65")).is_err());
        assert!(ensure_field_len("#6", 0, backend::mldsa_pub_len("ML-DSA-65")).is_err());
        assert!(ensure_field_len("sig", 100_000, backend::mldsa_sig_len("ML-DSA-65")).is_err());
        // Unknown algorithm → None → skip (let the backend reject the algo).
        assert!(ensure_field_len("#6", 7, backend::mldsa_pub_len("ML-DSA-999")).is_ok());
    }

    // ------------------------------------------------------------------
    // Handshake transcript KAT (known-answer test).
    //
    // Pins the EXACT canonical byte layout of the v3 handshake transcript, so a
    // later refactor (extracting a shared `TranscriptBuilder`) — or any accidental
    // change to field order / length encoding — is caught at the byte level
    // instead of only end-to-end. This golden is a faithful replica of the current
    // hand-written construction (it uses the same `update_transcript` primitive,
    // u32-LE length-prefix); each field is annotated with the source lines it
    // mirrors on the server (listen) and client (connect) paths.
    // ------------------------------------------------------------------
    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Build the canonical transcript for fixed inputs via `TranscriptBuilder`.
    /// `full=false` stops after the client-auth block (#1–#6) — the slice the
    /// client signs (returned as the builder's prefix snapshot).
    fn kat_builder(client_auth: bool, server_auth: bool, full: bool) -> TranscriptBuilder {
        const CID: [u8; 32] = [0x11; 32];
        const SID: [u8; 32] = [0x22; 32];
        let mut tb = TranscriptBuilder::new();
        tb.append_raw(&CID); // #1 raw  server:369 / client:723
        tb.append_raw(&SID); // #2 raw  server:370 / client:724
        tb.append_lp(b"CECC"); // #3 lp server:375/client:741
        tb.append_lp(b"CKEM"); // #4 lp server:376/client:742
        tb.append_raw(&[client_auth as u8]); // #5 raw server:380 / client:746
        if client_auth {
            tb.append_lp(b"CDSA"); // #6 lp server:384/client:759
        }
        if !full {
            return tb; // client-signature view ends at #6
        }
        tb.append_lp(b"SECC"); // #7 lp server:448/client:771
        tb.append_lp(b"KEMCT"); // #8 lp server:449/client:772
        tb.append_raw(&[server_auth as u8]); // #9 raw server:452 / client:773
        if server_auth {
            tb.append_lp(b"SDSA"); // #10 lp server:479/client:777
            tb.append_lp(b"SKEM"); // #11 lp server:482/client:782
        }
        tb
    }

    fn kat_transcript(client_auth: bool, server_auth: bool, full: bool) -> Vec<u8> {
        kat_builder(client_auth, server_auth, full).snapshot().to_vec()
    }

    // Golden bytes of the canonical v3 transcript for the fixed KAT inputs above.
    // Decoded layout (auth mode): client_id(32 raw) ‖ server_id(32 raw) ‖
    // u32LE(4)"CECC" ‖ u32LE(4)"CKEM" ‖ 01 ‖ u32LE(4)"CDSA" ‖ u32LE(4)"SECC" ‖
    // u32LE(5)"KEMCT" ‖ 01 ‖ u32LE(4)"SDSA" ‖ u32LE(4)"SKEM". The length prefix is
    // u32 little-endian (the v3 wire format); changing it would break compat.
    const KAT_FULL_AUTH: &str = "11111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222040000004345434304000000434b454d0104000000434453410400000053454343050000004b454d435401040000005344534104000000534b454d";
    const KAT_PARTIAL_AUTH: &str = "11111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222040000004345434304000000434b454d010400000043445341";
    const KAT_FULL_NOAUTH: &str = "11111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222040000004345434304000000434b454d000400000053454343050000004b454d435400";
    const KAT_SALT_AUTH: &str =
        "31a595b0ad7dbdb582a31d2d4d72e5f249e7be7e02523b46d61bd017318e479e";

    #[test]
    fn handshake_transcript_kat() {
        use sha3::Digest as _;
        // Full transcript bound into the salt (auth mode) — #1..#11.
        assert_eq!(hex(&kat_transcript(true, true, true)), KAT_FULL_AUTH);
        // Partial transcript the client signs — #1..#6.
        assert_eq!(hex(&kat_transcript(true, true, false)), KAT_PARTIAL_AUTH);
        // Unauthenticated mode still binds the KEM ciphertext (#8).
        assert_eq!(hex(&kat_transcript(false, false, true)), KAT_FULL_NOAUTH);
        // Salt = SHA3-256(full transcript), via the builder's finalize_salt().
        assert_eq!(hex(&kat_builder(true, true, true).finalize_salt()), KAT_SALT_AUTH);
        // The KEM ciphertext ("KEMCT") and both public keys MUST appear in the
        // salt's preimage — the property the hybrid combiner relies on.
        assert!(KAT_FULL_AUTH.contains(&hex(b"KEMCT")));
        assert!(KAT_FULL_AUTH.contains(&hex(b"CECC")) && KAT_FULL_AUTH.contains(&hex(b"SECC")));
        // The client-signature view MUST be a strict prefix of the full transcript
        // (it is the same buffer up to #6). This pins the invariant that a future
        // `TranscriptBuilder::snapshot()` returns a genuine prefix of the buffer —
        // not a separately built / trailing-padded value, which the three equality
        // checks above would not catch on their own.
        assert!(
            KAT_FULL_AUTH.starts_with(KAT_PARTIAL_AUTH)
                && KAT_PARTIAL_AUTH.len() < KAT_FULL_AUTH.len()
        );
    }

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
