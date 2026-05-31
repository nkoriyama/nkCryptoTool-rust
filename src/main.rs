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
    mode: Option<CryptoMode>,

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

    // -------------------------------------------------------------
    // MLS group chat flags (P7). All gated behind `--features mls`;
    // when the feature is off the flags are accepted but rejected
    // at runtime with a clear error so the binary stays usable in
    // its 1:1 chat / file-transfer form.
    // -------------------------------------------------------------
    /// MLS subcommand selector. Valid values:
    /// `create-group`, `list-groups`, `list-members`,
    /// `export-key-package`, `add-member`, `remove-member`,
    /// `accept-one`, `listen`, `send`, `chat-group`,
    /// `print-local-address`.
    #[arg(long, help = "MLS subcommand to run (see --help for the list)")]
    mls_cmd: Option<String>,

    /// Path to the MLS sqlite database. Defaults to
    /// `$HOME/.local/share/nkct/groups.db` (directory auto-created).
    #[arg(long)]
    mls_storage: Option<String>,

    /// Display name placed in the BasicCredential. Only used for UI
    /// — peers verify by fingerprint of the hybrid public key.
    #[arg(long, default_value = "nkct-user")]
    mls_display_name: String,

    /// Group name (for `--mls-cmd create-group`). Stored on the
    /// client side only; not transmitted as part of the MLS state.
    #[arg(long)]
    mls_name: Option<String>,

    /// Hex-encoded 32-byte GroupId (for any command that targets a
    /// specific group).
    #[arg(long)]
    mls_group_id: Option<String>,

    /// Output path for `--mls-cmd export-key-package`.
    #[arg(long)]
    mls_output: Option<String>,

    /// Input path of a peer's KeyPackage file (for
    /// `--mls-cmd add-member`).
    #[arg(long)]
    mls_key_package: Option<String>,

    /// Recipient ticket(s) — accepts `print-local-address` output.
    /// Pass multiple times to broadcast to several recipients
    /// (e.g. `--mls-recipient-ticket A --mls-recipient-ticket B`).
    #[arg(long)]
    mls_recipient_ticket: Vec<String>,

    /// Existing-member tickets to receive a Commit alongside a Welcome
    /// (for `--mls-cmd add-member` against a group ≥ 2). Pass
    /// multiple times. Use the same flag for every existing member;
    /// the removed/new member is NOT included here.
    #[arg(long)]
    mls_existing_member_ticket: Vec<String>,

    /// Application message body (for `--mls-cmd send`).
    #[arg(long)]
    mls_body: Option<String>,

    /// Leaf index to remove (for `--mls-cmd remove-member`).
    #[arg(long)]
    mls_index: Option<u32>,

    /// Launch the MLS group chat GUI (requires `gui-mls` cargo feature).
    /// Bypasses `--mls-cmd`; the GUI window owns the processor for the
    /// duration of the session.
    #[arg(long, help = "Launch the Slint-based MLS group chat window")]
    mls_gui: bool,

    /// Run as a standalone `nkct/inbox/1` store-and-forward server.
    /// Binds an iroh endpoint, opens an inbox sqlite at `--mls-storage`
    /// (or `~/.local/share/nkct/inbox.db`), prints our ticket, and
    /// serves DEPOSIT/POLL forever. Untrusted — never reads payloads.
    #[arg(long, help = "Run as an MLS inbox (store-and-forward) server")]
    inbox_server: bool,

    /// Ticket of an inbox server to use for store-and-forward fallback.
    /// When set, every `--mls-cmd` outbound send tries the direct
    /// connect first and falls back to the inbox if it fails or times
    /// out. The listen REPL also runs a background poll task.
    #[arg(long)]
    inbox_url: Option<String>,

    // -------------------------------------------------------------
    // One-Time Prekey flags (PQ-FS for the one-shot / inbox-async
    // path; see PQFS_DESIGN.md). Gated behind `--features mls`.
    // -------------------------------------------------------------
    /// One-Time Prekey subcommand: `generate`, `list`, or `revoke`.
    #[arg(long, help = "One-Time Prekey subcommand (generate|list|revoke)")]
    prekey_cmd: Option<String>,

    /// SQLCipher database holding prekey private keys. Defaults to
    /// `prekeys.db` beside the MLS storage (directory auto-created).
    #[arg(long)]
    prekey_storage: Option<String>,

    /// Number of prekeys to generate (for `--prekey-cmd generate`).
    #[arg(long, default_value_t = 100)]
    prekey_count: u32,

    /// Optional path to write the signed public prekey bundle produced
    /// by `--prekey-cmd generate` (for later upload / PUBLISH).
    #[arg(long)]
    prekey_output: Option<String>,

    /// Prekey id to revoke (for `--prekey-cmd revoke`).
    #[arg(long)]
    prekey_id: Option<u32>,

    /// Revoke every prekey (for `--prekey-cmd revoke`).
    #[arg(long)]
    prekey_all: bool,
}

/// Resolve a key-file argument against `--key-dir`. A bare filename (no
/// path separator) is taken as living in `key_dir`; anything with a `/`
/// or an absolute path is used verbatim. This lets
/// `--key-dir D --user-mlkem-privkey foo.key` find `D/foo.key` without
/// forcing the user to repeat the directory, while leaving explicit
/// relative/absolute paths untouched.
fn resolve_key_path(key_dir: &str, p: Option<String>) -> Option<String> {
    p.map(|v| {
        let path = std::path::Path::new(&v);
        // "Bare filename" = no directory component and not absolute. Using
        // Path (not a manual '/' check) makes this correct on every
        // platform's separator.
        let is_bare = !path.is_absolute()
            && path.parent().map_or(true, |parent| parent.as_os_str().is_empty());
        if is_bare {
            std::path::Path::new(key_dir).join(&v).to_string_lossy().into_owned()
        } else {
            v
        }
    })
}

/// True if `path` points to a PEM file holding a passphrase-encrypted
/// private key (a `BEGIN ENCRYPTED PRIVATE KEY` block), i.e. one that
/// needs a passphrase to load. Missing/unreadable/plaintext keys → false.
fn private_key_file_is_encrypted(path: &Option<String>) -> bool {
    match path {
        Some(p) => nk_crypto_tool::utils::private_key_file_is_encrypted(p),
        None => false,
    }
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
        return nk_crypto_tool::gui::run_gui().await.map_err(|e| anyhow::anyhow!(e.to_string()));
    }

    // ----------------------------------------------------------------
    // MLS subcommand dispatch (P7). Fires only if `--mls-cmd` is set.
    // Gated by `--features mls`; on the default build the flag is
    // accepted by clap but rejected here so the user sees a clear
    // message rather than a clap-derived "unknown subcommand".
    // ----------------------------------------------------------------
    if args.inbox_server {
        #[cfg(feature = "mls")]
        {
            return run_inbox_server(args).await;
        }
        #[cfg(not(feature = "mls"))]
        {
            anyhow::bail!(
                "--inbox-server requires the `mls` cargo feature; rebuild with `--features mls`"
            );
        }
    }

    if args.mls_cmd.is_some() {
        #[cfg(feature = "mls")]
        {
            return run_mls_command(args).await;
        }
        #[cfg(not(feature = "mls"))]
        {
            anyhow::bail!(
                "--mls-cmd requires the `mls` cargo feature; rebuild with `--features mls`"
            );
        }
    }

    if args.mls_gui {
        #[cfg(feature = "gui-mls")]
        {
            return run_mls_gui(args).await;
        }
        #[cfg(not(feature = "gui-mls"))]
        {
            anyhow::bail!(
                "--mls-gui requires the `gui-mls` cargo feature; rebuild with `--features gui-mls`"
            );
        }
    }

    if args.prekey_cmd.is_some() {
        #[cfg(feature = "mls")]
        {
            return run_prekey_command(args).await;
        }
        #[cfg(not(feature = "mls"))]
        {
            anyhow::bail!(
                "--prekey-cmd requires the `mls` cargo feature; rebuild with `--features mls`"
            );
        }
    }

    let mode = match args.mode {
        Some(m) => m,
        None => return Err(anyhow::anyhow!("--mode is required for CLI operations")),
    };

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
    config.mode = mode;
    config.operation = operation;
    config.input_files = args.input_files;
    config.output_file = args.output_file;
    config.key_dir = args.key_dir.unwrap_or_else(|| "keys".to_string());
    // Bare key filenames resolve under --key-dir; explicit relative/
    // absolute paths are left as given.
    config.recipient_pubkey = resolve_key_path(&config.key_dir, args.recipient_pubkey);
    config.recipient_mlkem_pubkey = resolve_key_path(&config.key_dir, args.recipient_mlkem_pubkey);
    config.recipient_ecdh_pubkey = resolve_key_path(&config.key_dir, args.recipient_ecdh_pubkey);
    config.user_privkey = resolve_key_path(&config.key_dir, args.user_privkey);
    config.user_mlkem_privkey = resolve_key_path(&config.key_dir, args.user_mlkem_privkey);
    config.user_ecdh_privkey = resolve_key_path(&config.key_dir, args.user_ecdh_privkey);
    config.signing_privkey = resolve_key_path(&config.key_dir, args.signing_privkey);
    config.signing_pubkey = resolve_key_path(&config.key_dir, args.signing_pubkey);
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

    // If this operation reads a private key, that key is passphrase-
    // encrypted, and no passphrase was supplied via NK_PASSPHRASE, prompt
    // for one now — rather than failing deep in the strategy with
    // "Encrypted private key requires a passphrase". Plaintext keys are
    // left alone (no prompt).
    if config.passphrase.is_none() {
        let reads_private_key = matches!(
            operation,
            Operation::Decrypt | Operation::Sign | Operation::Connect | Operation::Listen
        );
        let encrypted_key_present = [
            &config.user_privkey,
            &config.user_mlkem_privkey,
            &config.user_ecdh_privkey,
            &config.signing_privkey,
        ]
        .into_iter()
        .any(|p| private_key_file_is_encrypted(p));
        if reads_private_key && encrypted_key_present {
            config.passphrase = Some(
                nk_crypto_tool::utils::get_masked_passphrase()
                    .map_err(|e| anyhow::anyhow!("read private-key passphrase: {e}"))?,
            );
        }
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

// -----------------------------------------------------------------------------
// MLS CLI bridge.
//
// This translates argv-style flags into a typed `MlsCommand`, builds an
// `IrohEndpoint` configured per the existing `--transport` / relay
// flags, opens a `GroupStorage` at the user-specified (or default)
// sqlite path, and hands everything to `nk_crypto_tool::group::cli::run`.
// -----------------------------------------------------------------------------

/// Load the raw ML-DSA-65 identity private key from a PEM file, mirroring
/// the P2P handshake's key path (unwrap PEM → decrypt if encrypted →
/// unwrap PKCS#8). `passphrase` decrypts an encrypted key; an empty
/// passphrase is treated as "key is not encrypted".
#[cfg(feature = "mls")]
fn load_raw_dsa_priv(
    path: &str,
    passphrase: &zeroize::Zeroizing<String>,
) -> anyhow::Result<zeroize::Zeroizing<Vec<u8>>> {
    use nk_crypto_tool::utils;
    let bytes = zeroize::Zeroizing::new(
        std::fs::read(path).map_err(|e| anyhow::anyhow!("read signing key {path}: {e}"))?,
    );
    let pem = std::str::from_utf8(&bytes)
        .map_err(|_| anyhow::anyhow!("signing key {path} is not UTF-8 PEM"))?;
    let der = utils::unwrap_from_pem(pem, "PRIVATE KEY")?;
    let pass = if passphrase.is_empty() {
        None
    } else {
        Some(passphrase.as_str())
    };
    let decrypted = utils::extract_raw_private_key(&der, pass)?;
    Ok(utils::unwrap_pqc_priv_from_pkcs8(&decrypted, "ML-DSA-65")?)
}

/// One-Time Prekey maintenance (PQFS_DESIGN.md phase 1): `generate`,
/// `list`, `revoke`. Purely local — no network endpoint needed. The
/// prekey private keys live in their own SQLCipher DB, unlocked by the
/// same PQC at-rest DEK mechanism as the MLS storage.
#[cfg(feature = "mls")]
async fn run_prekey_command(args: Args) -> anyhow::Result<()> {
    use nk_crypto_tool::group::cli::default_storage_path;
    use nk_crypto_tool::group::{resolve_dek, AtRestPaths};
    use nk_crypto_tool::prekey::{self, PrekeyStore};
    use std::path::PathBuf;

    let cmd = args.prekey_cmd.as_deref().unwrap();

    let store_path: PathBuf = match args.prekey_storage.as_deref() {
        Some(p) => PathBuf::from(p),
        None => default_storage_path()?.with_file_name("prekeys.db"),
    };

    // The at-rest passphrase unlocks the hybrid key that wraps the DEK
    // protecting the prekey store. `beside_db` keeps a dedicated
    // `prekeys.db.at-rest.key` so it never races the shared `at-rest.key`
    // groups.db uses in the same directory.
    let passphrase = nk_crypto_tool::utils::get_masked_passphrase()
        .map_err(|e| anyhow::anyhow!("read prekey storage passphrase: {e}"))?;
    let at_rest_paths = AtRestPaths::beside_db(&store_path);
    let dek = resolve_dek(&at_rest_paths, &passphrase)
        .map_err(|e| anyhow::anyhow!("resolve prekey at-rest DEK: {e}"))?;
    let store = PrekeyStore::open(&store_path, &dek)
        .map_err(|e| anyhow::anyhow!("open prekey store {store_path:?}: {e}"))?;

    match cmd {
        "generate" => {
            let count = args.prekey_count;
            // A sane upper bound: a huge count would over-allocate and is
            // never operationally useful (each prekey is ~4.5 KB). Reject
            // rather than risk an OOM on a fat-fingered argument.
            const MAX_PREKEY_BATCH: u32 = 100_000;
            if count == 0 || count > MAX_PREKEY_BATCH {
                anyhow::bail!("--prekey-count must be between 1 and {MAX_PREKEY_BATCH}");
            }
            let signing_path = args
                .signing_privkey
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("--signing-privkey is required for prekey generate"))?;
            // The at-rest passphrase doubles as the signing-key passphrase,
            // matching this tool's single-secret (NK_PASSPHRASE) convention.
            // An unencrypted key ignores it; a key under a *different*
            // passphrase fails loudly at decrypt rather than silently.
            let dsa_priv = load_raw_dsa_priv(signing_path, &passphrase)?;
            // Reserve ids from the persistent monotonic counter so a batch
            // never reuses an id, even after the pool was fully drained.
            let start_id = store.reserve_ids(count)?;
            let batch = prekey::generate(count, start_id, &dsa_priv)?;
            let mut bundle = Vec::new();
            for g in &batch {
                store.insert(g.signed.prekey_id, g.xwing_priv.as_ref())?;
                bundle.extend_from_slice(&g.signed.to_bytes());
            }
            let last = start_id + count - 1;
            match args.prekey_output.as_deref() {
                Some(out) => {
                    std::fs::write(out, &bundle)
                        .map_err(|e| anyhow::anyhow!("write prekey bundle {out}: {e}"))?;
                    println!(
                        "Generated {count} prekeys (ids {start_id}..={last}); stored privates and wrote signed bundle to {out}."
                    );
                }
                None => println!(
                    "Generated {count} prekeys (ids {start_id}..={last}); stored privates. Pass --prekey-output to write the signed public bundle for upload."
                ),
            }
            println!("Pool now holds {} unused prekey(s).", store.count()?);
        }
        "list" => {
            let ids = store.list_ids()?;
            println!("{} unused prekey(s).", ids.len());
            if !ids.is_empty() {
                let preview: Vec<String> = ids.iter().take(20).map(|i| i.to_string()).collect();
                let more = if ids.len() > 20 {
                    format!(" … (+{} more)", ids.len() - 20)
                } else {
                    String::new()
                };
                println!("ids: {}{}", preview.join(", "), more);
            }
        }
        "revoke" => {
            if args.prekey_all {
                let n = store.delete_all()?;
                println!("Revoked all {n} prekey(s).");
            } else {
                let id = args.prekey_id.ok_or_else(|| {
                    anyhow::anyhow!("--prekey-id <N> or --prekey-all is required for revoke")
                })?;
                if store.delete(id)? {
                    println!("Revoked prekey {id}.");
                } else {
                    println!("No prekey with id {id}.");
                }
            }
        }
        other => anyhow::bail!(
            "unknown --prekey-cmd {other:?}; expected one of generate, list, revoke"
        ),
    }
    Ok(())
}

#[cfg(feature = "mls")]
async fn run_mls_command(args: Args) -> anyhow::Result<()> {
    use nk_crypto_tool::config::CryptoConfig;
    use nk_crypto_tool::group::cli::{self, MlsCommand};
    use nk_crypto_tool::group::{open_at_rest_storage, AtRestPaths, GroupChatProcessor, GroupId};
    use nk_crypto_tool::p2p::P2pEndpoint;
    use nk_crypto_tool::ticket::Ticket;
    use std::path::PathBuf;
    use std::str::FromStr;
    use std::sync::Arc;

    // --- helpers --------------------------------------------------------
    let require = |opt: &Option<String>, name: &str| -> anyhow::Result<String> {
        opt.clone()
            .ok_or_else(|| anyhow::anyhow!("--{name} is required for this --mls-cmd"))
    };
    let parse_group_id = |hex: &str| -> anyhow::Result<GroupId> {
        let bytes = hex::decode(hex)
            .map_err(|e| anyhow::anyhow!("invalid --mls-group-id hex: {e}"))?;
        if bytes.len() != 32 {
            anyhow::bail!("--mls-group-id must be 32 bytes (64 hex chars), got {}", bytes.len());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(GroupId::new(arr))
    };
    let parse_tickets = |raws: &[String]| -> anyhow::Result<Vec<Ticket>> {
        raws.iter()
            .map(|s| Ticket::from_str(s).map_err(|e| anyhow::anyhow!("invalid ticket: {e}")))
            .collect()
    };

    // --- build the typed command ---------------------------------------
    let cmd_name = args.mls_cmd.as_deref().unwrap();

    // `rekey` is a purely local maintenance op on the at-rest files — it
    // needs neither the network endpoint nor a GroupChatProcessor, so
    // handle it before any of that is built and return early.
    if cmd_name == "rekey" {
        use nk_crypto_tool::group::{rotate_dek, AtRestPaths};
        let storage_path: PathBuf = match args.mls_storage {
            Some(p) => PathBuf::from(p),
            None => cli::default_storage_path()?,
        };
        let passphrase = nk_crypto_tool::utils::get_masked_passphrase()
            .map_err(|e| anyhow::anyhow!("read MLS storage passphrase: {e}"))?;
        let at_rest_paths = AtRestPaths::from_db_path(&storage_path);
        rotate_dek(&at_rest_paths, &passphrase)
            .map_err(|e| anyhow::anyhow!("rekey MLS storage at {storage_path:?}: {e}"))?;
        println!("Rotated at-rest DEK for {storage_path:?} (groups.db re-encrypted, KEK re-wrapped).");
        return Ok(());
    }

    let cmd = match cmd_name {
        "create-group" => MlsCommand::CreateGroup {
            name: require(&args.mls_name, "mls-name")?,
        },
        "list-groups" => MlsCommand::ListGroups,
        "list-members" => MlsCommand::ListMembers {
            group_id: parse_group_id(&require(&args.mls_group_id, "mls-group-id")?)?,
        },
        "export-key-package" => MlsCommand::ExportKeyPackage {
            output: PathBuf::from(require(&args.mls_output, "mls-output")?),
        },
        "add-member" => {
            let tickets = parse_tickets(&args.mls_recipient_ticket)?;
            let recipient = tickets
                .first()
                .ok_or_else(|| anyhow::anyhow!("--mls-recipient-ticket is required"))?
                .clone();
            let existing = parse_tickets(&args.mls_existing_member_ticket)?;
            MlsCommand::AddMember {
                group_id: parse_group_id(&require(&args.mls_group_id, "mls-group-id")?)?,
                key_package_file: PathBuf::from(require(&args.mls_key_package, "mls-key-package")?),
                recipient_ticket: recipient,
                existing_member_tickets: existing,
            }
        }
        "remove-member" => MlsCommand::RemoveMember {
            group_id: parse_group_id(&require(&args.mls_group_id, "mls-group-id")?)?,
            index: args
                .mls_index
                .ok_or_else(|| anyhow::anyhow!("--mls-index is required for remove-member"))?,
            recipient_tickets: parse_tickets(&args.mls_recipient_ticket)?,
        },
        "accept-one" => MlsCommand::AcceptOne,
        "listen" => {
            let group_id = match args.mls_group_id.as_deref() {
                Some(hex) => Some(parse_group_id(hex)?),
                None => None,
            };
            MlsCommand::Listen {
                group_id,
                recipient_tickets: parse_tickets(&args.mls_recipient_ticket)?,
            }
        }
        "send" => MlsCommand::Send {
            group_id: parse_group_id(&require(&args.mls_group_id, "mls-group-id")?)?,
            body: require(&args.mls_body, "mls-body")?,
            recipient_tickets: parse_tickets(&args.mls_recipient_ticket)?,
        },
        "chat-group" => MlsCommand::ChatGroup {
            group_id: parse_group_id(&require(&args.mls_group_id, "mls-group-id")?)?,
            recipient_tickets: parse_tickets(&args.mls_recipient_ticket)?,
        },
        "print-local-address" => MlsCommand::PrintLocalAddress,
        other => anyhow::bail!(
            "unknown --mls-cmd {other:?}; expected one of \
             create-group, list-groups, list-members, export-key-package, \
             add-member, remove-member, accept-one, listen, send, \
             chat-group, print-local-address, rekey"
        ),
    };

    // --- open storage + build endpoint ---------------------------------
    let storage_path: PathBuf = match args.mls_storage {
        Some(p) => PathBuf::from(p),
        None => cli::default_storage_path()?,
    };
    // The MLS sqlite DB is SQLCipher-encrypted with a 256-bit DEK that
    // is itself wrapped by an X25519+ML-KEM-768 hybrid KEM (at-rest PQC
    // layer — see `group::at_rest` and SECURITY_PROFILE.md §7.3). The
    // passphrase decrypts the hybrid private key file (`at-rest.key`);
    // from there the DEK is recovered via HPKE open against the KEK
    // file (`groups.db.kek`).
    let mls_passphrase = nk_crypto_tool::utils::get_masked_passphrase()
        .map_err(|e| anyhow::anyhow!("read MLS storage passphrase: {e}"))?;
    let at_rest_paths = AtRestPaths::from_db_path(&storage_path);
    let storage = open_at_rest_storage(&at_rest_paths, &mls_passphrase)
        .map_err(|e| anyhow::anyhow!("open MLS storage at {storage_path:?}: {e}"))?;

    // Build a CryptoConfig with just the transport-relevant bits.
    let mut transport_config = CryptoConfig::default();
    transport_config.transport = args.transport;
    transport_config.no_relay = args.no_relay;
    transport_config.relay_url = args.relay_url;

    let endpoint: Arc<dyn P2pEndpoint> = match transport_config.transport {
        nk_crypto_tool::config::TransportKind::Iroh => Arc::new(
            nk_crypto_tool::p2p::backend::iroh::IrohEndpoint::new(&transport_config, false)
                .await?,
        ),
        nk_crypto_tool::config::TransportKind::Tcp => {
            anyhow::bail!(
                "MLS over TCP is not supported in this build; pass --transport iroh"
            );
        }
    };

    let mut processor = GroupChatProcessor::new(&args.mls_display_name, endpoint.clone(), storage)
        .map_err(|e| anyhow::anyhow!("build GroupChatProcessor: {e}"))?;
    if let Some(url) = &args.inbox_url {
        let ticket: Ticket = url
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid --inbox-url ticket: {e}"))?;
        let inbox_addr = ticket.peer_addr();
        // Anti-rollback phase 3: when rollback protection is enabled, report
        // our current at-rest epoch to the (semi-trusted) inbox server. A
        // regression flagged here is an online cross-device hint that local
        // storage was rolled back. Advisory only — warn, never block — since
        // the server could equally lie; the local counter is authoritative.
        match nk_crypto_tool::group::current_rollback_epoch(&at_rest_paths) {
            Ok(Some(epoch)) => {
                match nk_crypto_tool::network::inbox::checkpoint(
                    endpoint.as_ref(),
                    &inbox_addr,
                    epoch,
                )
                .await
                {
                    Ok(nk_crypto_tool::network::inbox::CheckpointStatus::RollbackSuspected) => {
                        eprintln!(
                            "[at-rest] WARNING: inbox checkpoint reports a newer epoch than our \
                             local {epoch} — local storage may have been rolled back to an older \
                             snapshot. Verify before trusting this state."
                        );
                    }
                    Ok(_) => {}
                    Err(e) => eprintln!("[at-rest] inbox checkpoint skipped: {e}"),
                }
            }
            Ok(None) => {} // rollback policy off — nothing to report
            Err(e) => eprintln!("[at-rest] could not read rollback epoch: {e}"),
        }
        processor.set_inbox(Some(inbox_addr));
    }
    let processor = processor;
    let result = cli::run(cmd, processor).await;
    // Graceful-shutdown linger. Only required for one-shot commands
    // that opened OUTBOUND QUIC streams (add-member, remove-member,
    // send): iroh's `SendStream::shutdown` only ACK's the FIN at the
    // QUIC layer, not at the application layer. If we exit immediately,
    // `Endpoint::drop` resets the connection and the peer can see a
    // spurious "connection lost" before its stream-read finishes
    // draining. The per-frame ACK byte in `send_mls_message` already
    // confirms application-layer delivery, but the QUIC FIN still
    // needs an RTT or two to flush; 200 ms is enough for loopback/LAN.
    //
    // `accept-one` is a RECEIVER — it needs to stay around long enough
    // for the sender to read the ACK byte we just sent, so it keeps a
    // longer 2.5 s linger (matched to the sender's grace period).
    //
    // Commands that didn't open any stream (create-group, list-groups,
    // list-members, export-key-package, print-local-address) need no
    // linger at all; skipping it saves 2.5 s per invocation, which
    // dominates wall-clock time when scripting many one-shot commands.
    //
    // NB: `endpoint.close()` is intentionally NOT called — it tears
    // down still-draining streams, which is the race we're avoiding.
    let linger_ms: u64 = match cmd_name {
        "add-member" | "remove-member" | "send" => 200,
        "accept-one" => 2_500,
        _ => 0,
    };
    if linger_ms > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(linger_ms)).await;
    }
    let _ = &endpoint; // keep endpoint alive for the linger above
    result
}

// -----------------------------------------------------------------------------
// Inbox store-and-forward server. Long-running process that binds an iroh
// endpoint, opens an inbox sqlite, and serves `nkct/inbox/1` forever.
// -----------------------------------------------------------------------------

#[cfg(feature = "mls")]
async fn run_inbox_server(args: Args) -> anyhow::Result<()> {
    use nk_crypto_tool::config::CryptoConfig;
    use nk_crypto_tool::network::inbox::InboxServer;
    use nk_crypto_tool::p2p::P2pEndpoint;
    use nk_crypto_tool::ticket::Ticket;
    use std::path::PathBuf;
    use std::sync::Arc;

    let db_path: PathBuf = match args.mls_storage.as_deref() {
        Some(p) => PathBuf::from(p),
        None => {
            let home = std::env::var("HOME")
                .map_err(|_| anyhow::anyhow!("$HOME not set; pass --mls-storage <path>"))?;
            let dir = PathBuf::from(home).join(".local/share/nkct");
            std::fs::create_dir_all(&dir)
                .map_err(|e| anyhow::anyhow!("create inbox dir {dir:?}: {e}"))?;
            dir.join("inbox.db")
        }
    };
    eprintln!("[inbox] storage: {db_path:?}");

    // The inbox DB is SQLCipher-encrypted (PQC at-rest layer) so envelope
    // metadata (recipient / sender / timestamps) is never plaintext on the
    // relay's disk. The passphrase decrypts `inbox.db.at-rest.key`.
    let inbox_passphrase = nk_crypto_tool::utils::get_masked_passphrase()
        .map_err(|e| anyhow::anyhow!("read inbox storage passphrase: {e}"))?;

    let mut transport_config = CryptoConfig::default();
    transport_config.transport = args.transport;
    transport_config.no_relay = args.no_relay;
    transport_config.relay_url = args.relay_url;

    let endpoint: Arc<dyn P2pEndpoint> = match transport_config.transport {
        nk_crypto_tool::config::TransportKind::Iroh => Arc::new(
            nk_crypto_tool::p2p::backend::iroh::IrohEndpoint::new(&transport_config, false).await?,
        ),
        nk_crypto_tool::config::TransportKind::Tcp => {
            anyhow::bail!("inbox server requires --transport iroh");
        }
    };

    let local = endpoint
        .local_addr()
        .await
        .map_err(|e| anyhow::anyhow!("local_addr: {e}"))?;
    let ticket = Ticket::new(local, None, None);
    println!("Inbox listening at: {ticket}");
    use std::io::Write as _;
    let _ = std::io::stdout().flush();

    let server = Arc::new(
        InboxServer::open(&db_path, &inbox_passphrase)
            .map_err(|e| anyhow::anyhow!("open inbox: {e}"))?,
    );
    server
        .run(endpoint)
        .await
        .map_err(|e| anyhow::anyhow!("inbox run: {e}"))?;
    Ok(())
}

#[cfg(feature = "gui-mls")]
async fn run_mls_gui(args: Args) -> anyhow::Result<()> {
    use nk_crypto_tool::config::CryptoConfig;
    use nk_crypto_tool::group::{cli, open_at_rest_storage, AtRestPaths, GroupChatProcessor};
    use nk_crypto_tool::p2p::P2pEndpoint;
    use std::path::PathBuf;
    use std::sync::Arc;

    let storage_path: PathBuf = match args.mls_storage {
        Some(p) => PathBuf::from(p),
        None => cli::default_storage_path()?,
    };
    // PQC at-rest layer: passphrase → hybrid SK (at-rest.key) → DEK
    // (groups.db.kek) → SQLCipher. See SECURITY_PROFILE.md §7.3.
    let mls_passphrase = nk_crypto_tool::utils::get_masked_passphrase()
        .map_err(|e| anyhow::anyhow!("read MLS storage passphrase: {e}"))?;
    let at_rest_paths = AtRestPaths::from_db_path(&storage_path);
    let storage = open_at_rest_storage(&at_rest_paths, &mls_passphrase)
        .map_err(|e| anyhow::anyhow!("open MLS storage at {storage_path:?}: {e}"))?;

    // Build transport endpoint per --transport / --no-relay / --relay-url.
    let mut transport_config = CryptoConfig::default();
    transport_config.transport = args.transport;
    transport_config.no_relay = args.no_relay;
    transport_config.relay_url = args.relay_url;

    let endpoint: Arc<dyn P2pEndpoint> = match transport_config.transport {
        nk_crypto_tool::config::TransportKind::Iroh => Arc::new(
            nk_crypto_tool::p2p::backend::iroh::IrohEndpoint::new(&transport_config, false)
                .await?,
        ),
        nk_crypto_tool::config::TransportKind::Tcp => {
            anyhow::bail!(
                "MLS over TCP is not supported in this build; pass --transport iroh"
            );
        }
    };

    let processor = Arc::new(
        GroupChatProcessor::new(&args.mls_display_name, endpoint, storage)
            .map_err(|e| anyhow::anyhow!("build GroupChatProcessor: {e}"))?,
    );

    nk_crypto_tool::gui::group_chat::run_group_gui(processor)
        .await
        .map_err(|e| anyhow::anyhow!("GUI loop: {e}"))
}

#[cfg(test)]
mod tests {
    use super::resolve_key_path;

    #[test]
    fn bare_filename_resolves_under_key_dir() {
        assert_eq!(
            resolve_key_path("keys", Some("foo.key".into())),
            Some("keys/foo.key".into())
        );
        // Trailing slash on key_dir is normalised by Path::join.
        assert_eq!(
            resolve_key_path("/a/b/", Some("foo.key".into())),
            Some("/a/b/foo.key".into())
        );
    }

    #[test]
    fn paths_with_a_directory_component_are_left_alone() {
        assert_eq!(
            resolve_key_path("keys", Some("sub/foo.key".into())),
            Some("sub/foo.key".into())
        );
        assert_eq!(
            resolve_key_path("keys", Some("./foo.key".into())),
            Some("./foo.key".into())
        );
    }

    #[test]
    fn absolute_paths_are_left_alone() {
        assert_eq!(
            resolve_key_path("keys", Some("/etc/foo.key".into())),
            Some("/etc/foo.key".into())
        );
    }

    #[test]
    fn none_stays_none() {
        assert_eq!(resolve_key_path("keys", None), None);
    }
}
