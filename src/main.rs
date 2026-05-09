/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

use clap::Parser;
use nk_crypto_tool::config::{CryptoConfig, CryptoMode, Operation};
use nk_crypto_tool::key::create_best_provider;
use nk_crypto_tool::processor::CryptoProcessor;
use std::sync::Arc;
use zeroize::Zeroizing;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long, value_enum)]
    mode: CryptoMode,

    #[arg(long)]
    encrypt: bool,

    #[arg(long)]
    decrypt: bool,

    #[arg(long)]
    sign: bool,

    #[arg(long)]
    verify: bool,

    #[arg(long, help = "Calculate and display the SHA3-256 fingerprint of a public key")]
    fingerprint: bool,

    #[arg(long)]
    gen_enc_key: bool,

    #[arg(long)]
    gen_sign_key: bool,

    #[arg(long)]
    key_dir: Option<String>,

    #[arg(long)]
    recipient_pubkey: Option<String>,

    #[arg(long)]
    recipient_mlkem_pubkey: Option<String>,

    #[arg(long)]
    recipient_ecdh_pubkey: Option<String>,

    #[arg(long, alias = "my-enc-key")]
    user_privkey: Option<String>,

    #[arg(long)]
    user_mlkem_privkey: Option<String>,

    #[arg(long)]
    user_ecdh_privkey: Option<String>,

    #[arg(long, alias = "my-sign-key")]
    signing_privkey: Option<String>,

    #[arg(long)]
    signing_pubkey: Option<String>,

    #[arg(long)]
    signature: Option<String>,

    #[arg(long)]
    listen: Option<String>,

    #[arg(long)]
    connect: Option<String>,

    #[arg(long)]
    chat: bool,

    #[arg(
        long,
        help = "Allow unauthenticated connections (SECURITY WARNING: Default is false since v49)"
    )]
    allow_unauth: bool,

    #[arg(long, help = "Force overwrite of existing files")]
    force: bool,

    #[arg(long, help = "Start the graphical user interface (Slint)")]
    gui: bool,

    #[arg(long, default_value = "15", help = "Handshake timeout in seconds")]
    handshake_timeout: u64,

    #[arg(long, help = "Path to file containing allowed peer public key fingerprints")]
    peer_allowlist: Option<String>,

    #[arg(long, default_value = "SHA3-512")]
    digest_algo: String,

    #[arg(long, default_value = "AES-256-GCM")]
    aead_algo: String,

    #[arg(long, default_value = "ML-KEM-768")]
    kem_algo: String,

    #[arg(long, default_value = "ML-DSA-65")]
    dsa_algo: String,

    #[arg(long, value_enum, default_value = "iroh")]
    transport: nk_crypto_tool::config::TransportKind,

    #[arg(long, help = "Disable Iroh relay (only direct connections)")]
    no_relay: bool,

    #[arg(long, help = "Custom Iroh relay URL")]
    relay_url: Option<String>,

    #[arg(long)]
    use_tpm: bool,

    #[arg(num_args = 1..)]
    input_files: Vec<String>,

    #[arg(long)]
    output_file: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    nk_crypto_tool::utils::disable_core_dumps();

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if std::is_x86_feature_detected!("aes") {
        eprintln!("AES-NI is available!");
    }

    let args = Args::parse();

    #[cfg(feature = "gui")]
    if args.gui {
        return nk_crypto_tool::gui::run_gui().await.map_err(|e| anyhow::anyhow!(e));
    }

    let operation = if args.encrypt {
        Operation::Encrypt
    } else if args.decrypt {
        Operation::Decrypt
    } else if args.sign {
        Operation::Sign
    } else if args.verify {
        Operation::Verify
    } else if args.fingerprint {
        Operation::Fingerprint
    } else if args.gen_enc_key {
        Operation::GenerateEncKey
    } else if args.gen_sign_key {
        Operation::GenerateSignKey
    } else if args.listen.is_some() {
        Operation::Listen
    } else if args.connect.is_some() {
        Operation::Connect
    } else {
        anyhow::bail!("No operation specified")
    };

    // Initial passphrase from CLI args is now removed for security.
    let mut passphrase = if let Ok(p) = std::env::var("NK_PASSPHRASE") {
        if p.is_empty() {
            None
        } else {
            eprintln!("WARNING: Using passphrase from NK_PASSPHRASE environment variable. This is less secure than interactive entry.");
            Some(Zeroizing::new(p))
        }
    } else {
        None
    };

    // If it's a key generation operation, we should ask for one by default
    // to protect the new private key, UNLESS it's already in the environment.
    if (operation == Operation::GenerateEncKey || operation == Operation::GenerateSignKey)
        && passphrase.is_none()
    {
        passphrase = nk_crypto_tool::utils::get_and_verify_passphrase(
            "Generate new key pair",
        )?;
    }

    let mut config = CryptoConfig::default();
    config.mode = args.mode;
    config.operation = operation;
    config.input_files = args.input_files;
    config.output_file = args.output_file;
    config.key_dir = args.key_dir.unwrap_or_else(|| "keys".to_string());
    config.recipient_pubkey = args.recipient_pubkey;
    config.recipient_mlkem_pubkey = args.recipient_mlkem_pubkey;
    config.recipient_ecdh_pubkey = args.recipient_ecdh_pubkey;
    config.user_privkey = args.user_privkey;
    config.user_mlkem_privkey = args.user_mlkem_privkey;
    config.user_ecdh_privkey = args.user_ecdh_privkey;
    config.signing_privkey = args.signing_privkey;
    config.signing_pubkey = args.signing_pubkey;
    config.signature_file = args.signature;
    config.digest_algo = args.digest_algo;
    config.aead_algo = args.aead_algo;
    config.pqc_kem_algo = args.kem_algo;
    config.pqc_dsa_algo = args.dsa_algo;
    config.transport = args.transport;
    if config.transport == nk_crypto_tool::config::TransportKind::Tcp {
        eprintln!("[WARNING] TCP transport is deprecated and will be removed in a future version. Please use Iroh transport for better security and NAT traversal.");
    }
    config.no_relay = args.no_relay;
    config.relay_url = args.relay_url;
    config.passphrase = passphrase;
    config.use_tpm = args.use_tpm;
    config.listen_addr = args.listen;
    config.connect_addr = args.connect;
    config.chat_mode = args.chat;
    config.allow_unauth = args.allow_unauth;
    config.force = args.force;
    config.handshake_timeout = args.handshake_timeout;
    config.peer_allowlist = args.peer_allowlist;

    if config.chat_mode
        && !config.allow_unauth
        && config.signing_privkey.is_none()
        && config.signing_pubkey.is_none()
    {
        eprintln!("WARNING: --allow-unauth is false (default) and no signing keys are provided.");
        eprintln!(
            "This may prevent connections from succeeding. Use --allow-unauth if you want anonymous chat."
        );
    }

    if operation == Operation::Listen {
        nk_crypto_tool::network::NetworkProcessor::listen(&config).await?;
        return Ok(());
    } else if operation == Operation::Connect {
        nk_crypto_tool::network::NetworkProcessor::connect(&config).await?;
        return Ok(());
    }

    // Add paths for regenerate-pubkey (if you decide to expose it in CLI)
    // For now, it's used internally or for interop.

    let mut processor = match config.mode {
        CryptoMode::ECC => CryptoProcessor::new(CryptoMode::ECC),
        CryptoMode::PQC => CryptoProcessor::new(CryptoMode::PQC),
        CryptoMode::Hybrid => CryptoProcessor::new(CryptoMode::Hybrid),
    };

    let provider = create_best_provider();
    processor.set_key_provider(provider);

    processor
        .process(
            &config,
            Some(Arc::new(|progress| {
                print!(
                    "\rProgress: [{:<50}] {:.1}%",
                    "#".repeat((progress * 50.0) as usize),
                    progress * 100.0
                );
                use std::io::Write;
                std::io::stdout().flush().unwrap();
                if progress >= 1.0 {
                    println!();
                }
            })),
        )
        .await?;

    println!("Operation completed successfully.");
    Ok(())
}
