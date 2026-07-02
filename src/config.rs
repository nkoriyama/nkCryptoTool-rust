/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operation {
    Encrypt,
    Decrypt,
    Sign,
    Verify,
    GenerateEncKey,
    GenerateSignKey,
    RegeneratePubKey,
    WrapKey,
    UnwrapKey,
    Info,
    Listen,
    Connect,
    Fingerprint,
    None,
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
pub enum CryptoMode {
    ECC,
    PQC,
    Hybrid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
pub enum TransportKind {
    Iroh,
    Tcp,
}

impl Default for TransportKind {
    fn default() -> Self {
        TransportKind::Iroh
    }
}

/// Dynamic peer discovery mode for the iroh transport. Controls whether a
/// NodeId can be resolved to *current* network addresses beyond those baked
/// into a ticket — and whether this node advertises its own presence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
pub enum DiscoveryMode {
    /// No discovery (default, historical behaviour): a node is reachable only
    /// via the direct addresses / relay URL embedded in its ticket. Nothing
    /// is advertised anywhere — the most private option, but ticket addresses
    /// that go stale (e.g. after an IP change) cannot self-heal.
    None,
    /// Local-network (mDNS) discovery: advertise and resolve NodeId↔address on
    /// the local segment via multicast DNS. Stale ticket addresses self-heal
    /// on the LAN with no external infrastructure, which fits the `--no-relay`
    /// posture. Presence is broadcast on the local network only — never to a
    /// public DNS/DHT service.
    ///
    /// NOTE: temporarily unsupported on the iroh 1.0 transport (1.0 removed
    /// local-network discovery from core and no iroh-1.0 mDNS adapter exists
    /// yet). Selecting it currently fails loudly at endpoint construction;
    /// re-implementation over `swarm-discovery` is tracked as a follow-up.
    Local,
    /// n0 public discovery (DNS/pkarr): publish this node's address to, and
    /// resolve peers from, Number 0's public DNS server (`iroh.link`). This is
    /// what makes reachability work across real NATs / cloud firewalls: relay
    /// and hole-punch coordination need the node to be discoverable, which the
    /// ticket-only `None` mode does not provide beyond a shared LAN (verified on
    /// an OCI VPS — `None` could not be reached, `n0` connects with a direct
    /// hole-punch).
    ///
    /// TRADE-OFF: presence is published to a third-party (n0) DNS service, so
    /// this is NOT the "zero third-party observation point" posture of `None`.
    /// Choose `n0` for reachability across networks, `none` for maximum privacy
    /// on a shared LAN / with out-of-band ticket exchange.
    #[value(name = "n0")]
    N0,
}

impl Default for DiscoveryMode {
    fn default() -> Self {
        DiscoveryMode::None
    }
}

impl fmt::Display for CryptoMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Default for CryptoMode {
    fn default() -> Self {
        CryptoMode::ECC
    }
}

#[derive(Debug, Clone)]
pub struct CryptoConfig {
    pub operation: Operation,
    pub mode: CryptoMode,

    // Paths
    pub input_files: Vec<String>,
    pub output_file: Option<String>,
    pub input_dir: Option<String>,
    pub output_dir: Option<String>,
    pub key_dir: String,
    pub signature_file: Option<String>,

    // Key paths
    pub recipient_pubkey: Option<String>,
    pub user_privkey: Option<String>,
    pub signing_privkey: Option<String>,
    pub signing_pubkey: Option<String>,

    // Hybrid keys
    pub recipient_mlkem_pubkey: Option<String>,
    pub recipient_ecdh_pubkey: Option<String>,
    pub user_mlkem_privkey: Option<String>,
    pub user_ecdh_privkey: Option<String>,

    // Options
    pub passphrase: Option<Zeroizing<String>>,
    pub use_tpm: bool,
    pub digest_algo: String,
    pub aead_algo: String,
    pub pqc_kem_algo: String,
    pub pqc_dsa_algo: String,
    pub use_parallel: bool,
    pub is_recursive: bool,

    pub listen_addr: Option<String>,
    pub connect_addr: Option<String>,
    pub chat_mode: bool,
    /// P2P shell mode (ALPN_SHELL). Mutually exclusive with chat/file; when set,
    /// the post-handshake path runs the shell session instead of chat/file.
    /// True for both the shell client and server.
    pub shell_mode: bool,
    /// This node will *serve* shells (`--serve-shell`). Only when this is true
    /// does an inbound shell-ALPN connection spawn a PTY — so a node running as a
    /// shell *client* never serves a shell even if a peer dials its shell ALPN.
    /// Startup validates authz (allowlist/pinned key) and refuses root for this.
    pub serve_shell: bool,
    /// Optional single command for the shell client (`--shell-cmd`): runs it on
    /// the remote and exits (ssh-style), instead of an interactive login shell.
    pub shell_command: Option<String>,
    /// Show a status bar under the interactive shell (`--tui`): connection kind,
    /// cipher suite, NodeId, hint. Client-side only; ignored for `--shell-cmd`.
    pub shell_tui: bool,
    /// Connection-metrics probe (`--conn-metrics`): as a shell client, connect and
    /// complete the handshake, let the path settle, print the selected path kind
    /// (direct/relay) and RTT in a parseable line, then exit without opening a
    /// shell. Used to measure NAT-traversal / relay-fallback / latency.
    pub print_conn_metrics: bool,
    /// Shell server authorization policy file (`--shell-policy`): maps peer
    /// fingerprints to a user and an optional command allowlist.
    pub shell_policy_path: Option<String>,
    /// Shell server audit log path (`--audit-log`): one line per session event.
    /// Also used by the port-forward server for its allow/deny records.
    pub audit_log_path: Option<String>,
    /// P2P port-forward mode (ALPN_FWD). Mutually exclusive with chat/file/shell.
    /// True for both the forward client and server.
    pub forward_mode: bool,
    /// This node will *serve* forwards (`--serve-forward`). Only when true does an
    /// inbound forward-ALPN connection open onward TCP connections (per policy).
    pub serve_forward: bool,
    /// Local-forward client specs (`--forward localport:host:remoteport`,
    /// repeatable), parsed by [`crate::forward::ForwardSpec::parse_local`].
    pub forward_specs: Vec<String>,
    /// Remote-forward client specs (`--remote-forward bindport:host:destport`,
    /// repeatable), parsed by [`crate::forward::ForwardSpec::parse_remote`].
    pub remote_forward_specs: Vec<String>,
    /// Forward server authorization policy file (`--forward-policy`): maps peer
    /// fingerprints to allowed `host:port` targets. Default deny.
    pub forward_policy_path: Option<String>,
    /// P2P scp mode (ALPN_SCP). Mutually exclusive with chat/file/shell/forward.
    /// True for both the scp client (`--scp-put`/`--scp-get`) and server.
    pub scp_mode: bool,
    /// This node will *serve* file transfer (`--serve-scp`). Only when true does
    /// an inbound scp-ALPN connection read/write files (per policy). Requires
    /// `--scp-policy` and refuses to run as root.
    pub serve_scp: bool,
    /// scp client upload spec: `(local, remote)` from `--scp-put LOCAL REMOTE`.
    pub scp_put: Option<(std::path::PathBuf, String)>,
    /// scp client download spec: `(remote, local)` from `--scp-get REMOTE LOCAL`.
    pub scp_get: Option<(String, std::path::PathBuf)>,
    /// scp server authorization policy file (`--scp-policy`): maps peer
    /// fingerprints to allowed read/write roots. Default deny.
    pub scp_policy_path: Option<String>,
    /// scp client recursive mode (`-r`/`--recursive`): `--scp-put`/`--scp-get`
    /// operate on a directory tree instead of a single file.
    pub scp_recursive: bool,
    pub allow_unauth: bool,
    pub force: bool,
    pub handshake_timeout: u64,
    pub peer_allowlist: Option<String>,
    pub transport: TransportKind,

    // MITM verification fingerprints
    pub target_sign_fp: Option<[u8; 32]>,
    pub target_enc_fp: Option<[u8; 32]>,

    // Relay settings
    pub no_relay: bool,
    pub relay_url: Option<String>,

    // Dynamic peer discovery (iroh transport). `None` keeps the historical
    // ticket-only reachability; `Local` enables mDNS so stale ticket
    // addresses self-heal on the LAN.
    pub discovery: DiscoveryMode,

    // Persistent iroh node secret key. When `Some`, the iroh endpoint
    // loads (or creates, 0600) a stable ed25519 secret key from this path
    // so our NodeId survives across process runs — required for the
    // asynchronous inbox/prekey flow, where a recipient PUBLISHes prekeys
    // in one run and POLLs in another and must address the same slot.
    // `None` keeps the historical ephemeral-NodeId behaviour.
    pub node_key_path: Option<std::path::PathBuf>,

    // For regenerate-pubkey
    pub regenerate_privkey_path: Option<String>,
    pub regenerate_pubkey_path: Option<String>,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            operation: Operation::None,
            mode: CryptoMode::ECC,
            input_files: Vec::new(),
            output_file: None,
            input_dir: None,
            output_dir: None,
            key_dir: "keys".to_string(),
            signature_file: None,
            recipient_pubkey: None,
            user_privkey: None,
            signing_privkey: None,
            signing_pubkey: None,
            recipient_mlkem_pubkey: None,
            recipient_ecdh_pubkey: None,
            user_mlkem_privkey: None,
            user_ecdh_privkey: None,
            passphrase: None,
            use_tpm: false,
            digest_algo: "SHA3-512".to_string(),
            aead_algo: "AES-256-GCM".to_string(),
            pqc_kem_algo: "ML-KEM-768".to_string(),
            pqc_dsa_algo: "ML-DSA-65".to_string(),
            use_parallel: false,
            is_recursive: false,
            listen_addr: None,
            connect_addr: None,
            chat_mode: false,
            shell_mode: false,
            serve_shell: false,
            shell_command: None,
            shell_tui: false,
            print_conn_metrics: false,
            shell_policy_path: None,
            audit_log_path: None,
            forward_mode: false,
            serve_forward: false,
            forward_specs: Vec::new(),
            remote_forward_specs: Vec::new(),
            forward_policy_path: None,
            scp_mode: false,
            serve_scp: false,
            scp_put: None,
            scp_get: None,
            scp_policy_path: None,
            scp_recursive: false,
            allow_unauth: false,
            force: false,
            handshake_timeout: 15,
            peer_allowlist: None,
            transport: TransportKind::default(),
            target_sign_fp: None,
            target_enc_fp: None,
            no_relay: false,
            relay_url: None,
            discovery: DiscoveryMode::default(),
            node_key_path: None,
            regenerate_privkey_path: None,
            regenerate_pubkey_path: None,
        }
    }
}
