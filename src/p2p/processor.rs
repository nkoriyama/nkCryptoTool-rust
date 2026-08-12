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

/// The grant bit a connecting service requires, or `None` for services without a
/// per-service grant (chat, file receive) — those authorize on keyring-allowlist
/// membership alone (any grant bit set).
fn required_grant_bit(config: &CryptoConfig) -> Option<u8> {
    if config.shell_mode {
        Some(crate::keyring::GRANT_SHELL)
    } else if config.scp_mode {
        Some(crate::keyring::GRANT_SCP)
    } else if config.forward_mode {
        Some(crate::keyring::GRANT_FORWARD)
    } else if config.chat_mode || config.file_mode {
        // Chat and file-receive have no bit of their own: adding one would
        // deny both services to every peer already stored under the current
        // GRANT_ALL, since a legacy row cannot be told apart from a deliberate
        // narrow grant. Requiring the full grant set instead keeps existing
        // fully-trusted peers working while ensuring a peer paired for exactly
        // one service (`--pairing-grant scp`) cannot reach the operator's
        // stdin/stdout through the chat or file ALPN.
        Some(crate::keyring::GRANT_ALL)
    } else {
        None
    }
}

/// Whether this node has a handshake signing identity: an explicit
/// `--signing-privkey` file or a keyring-injected encrypted PEM (auto-match).
/// Drives the SELF_AUTH handshake flags.
fn has_signing_identity(config: &CryptoConfig) -> bool {
    config.signing_privkey.is_some() || config.signing_privkey_pem.is_some()
}

/// The signing key's (still passphrase-encrypted) PKCS#8 PEM bytes, from
/// whichever source holds it: the keyring-injected PEM is preferred, else the
/// `--signing-privkey` file is read. `None` when the node has no signing
/// identity (anonymous operation).
fn signing_pem_bytes(config: &CryptoConfig) -> Result<Option<Zeroizing<Vec<u8>>>> {
    if let Some(ref pem) = config.signing_privkey_pem {
        return Ok(Some(Zeroizing::new(pem.as_bytes().to_vec())));
    }
    match config.signing_privkey {
        Some(ref path) => Ok(Some(Zeroizing::new(std::fs::read(path).map_err(
            |e| CryptoError::FileRead(format!("Key read failed ({path}): {e}")),
        )?))),
        None => Ok(None),
    }
}

/// Concurrency budget for connections whose peer is **not yet authenticated**:
/// transport setup plus the nkct handshake.
///
/// Sized separately from [`DEFAULT_MAX_SESSIONS`] on purpose. A single pool covering
/// both is exhaustible by peers that connect and stall: nothing about them is
/// verified yet, but each holds a slot for up to `P2P_SETUP_TIMEOUT +
/// handshake_timeout` — and because the accept throttle keys on the transport
/// NodeId, which is free to mint, rotating identities evades it. With one pool
/// that starves *everything*, including established sessions' successors; with
/// two, an unauthenticated flood is confined to this budget and cannot take a
/// session slot.
///
/// It is much larger than the session cap because the per-slot cost is small
/// (a few round trips and one signature verify, all bounded by timeouts) and a
/// bigger pool directly raises the number of concurrent connections an attacker
/// must sustain to deny service.
const DEFAULT_MAX_UNAUTHENTICATED: usize = 32;

/// Concurrency budget for **authenticated** sessions (chat / file / shell /
/// forward / scp / pairing). Much smaller than [`DEFAULT_MAX_UNAUTHENTICATED`]
/// because a slot is held for the session's whole lifetime, which for an
/// interactive shell or a large transfer is unbounded. Only peers that passed
/// the handshake — and the allowlist / grant checks, when configured — reach
/// this pool.
const DEFAULT_MAX_SESSIONS: usize = 10;

/// How long a freshly-authenticated connection may wait for a session slot
/// before the server refuses it as at-capacity.
///
/// Bounded on purpose, and short. The connection is still holding its pre-auth
/// permit while it waits (the handover takes the session permit first — see
/// [`Admission`]), so an unbounded wait would let the whole pre-auth pool be
/// pinned by post-handshake connections for as long as the session pool stays
/// full, halting the accept loop. A short grace absorbs the normal case — a
/// session ending moments later — while keeping the worst-case pre-auth hold
/// bounded at `P2P_SETUP_TIMEOUT + handshake_timeout + this`. Zero is a valid
/// setting: refuse immediately rather than wait at all.
const DEFAULT_SESSION_ADMISSION_GRACE_SECS: u64 = 5;

/// The shipped pre-auth pool must be the larger of the two: its slots are cheap
/// and timeout-bounded, so a bigger pool directly raises the concurrent-
/// connection count an attacker has to sustain, while session slots are held
/// indefinitely. Inverting them would make the scarce resource the one anyone
/// can take. (An operator can still invert them via the environment; that path
/// warns rather than refuses — see [`AdmissionLimits::from_env`].)
const _: () = assert!(DEFAULT_MAX_UNAUTHENTICATED > DEFAULT_MAX_SESSIONS);

/// Read a `usize` tuning override, falling back to `default` when the variable
/// is unset or unparseable. A bad value is reported rather than silently
/// ignored: a typo in a systemd unit should not quietly leave the server on
/// defaults the operator believes they changed.
fn env_usize(var: &str, default: usize) -> usize {
    parse_limit(var, std::env::var(var).ok().as_deref(), default)
}

/// The parsing half of [`env_usize`], split out so it is testable without
/// mutating process-global environment state from a threaded test runner.
fn parse_limit(var: &str, raw: Option<&str>, default: usize) -> usize {
    match raw {
        None => default,
        Some(s) => s.trim().parse::<usize>().unwrap_or_else(|_| {
            eprintln!("[nkct] ignoring {var}={s:?}: not a non-negative integer; using {default}");
            default
        }),
    }
}

/// Resolved admission-control limits.
///
/// Overrides are environment variables rather than CLI flags because they tune a
/// long-running server process (a systemd unit, a container) rather than express
/// a per-invocation choice — the same reasoning as `NKCT_QUIC_STREAM_WINDOW_MB`.
struct AdmissionLimits {
    unauthenticated: usize,
    sessions: usize,
    grace: Duration,
}

impl AdmissionLimits {
    /// Resolve once per process, so the environment is read (and any complaint
    /// about it printed) a single time no matter how many processors are built.
    fn get() -> &'static Self {
        static LIMITS: std::sync::OnceLock<AdmissionLimits> = std::sync::OnceLock::new();
        LIMITS.get_or_init(Self::from_env)
    }

    fn from_env() -> Self {
        Self::resolve(
            env_usize("NKCT_MAX_UNAUTHENTICATED", DEFAULT_MAX_UNAUTHENTICATED),
            env_usize("NKCT_MAX_SESSIONS", DEFAULT_MAX_SESSIONS),
            env_usize(
                "NKCT_SESSION_ADMISSION_GRACE_SECS",
                DEFAULT_SESSION_ADMISSION_GRACE_SECS as usize,
            ),
        )
    }

    /// Apply the floors and the sanity warning to already-parsed values. Split
    /// from [`Self::from_env`] so the policy is testable without the
    /// environment.
    fn resolve(unauthenticated: usize, sessions: usize, grace_secs: usize) -> Self {
        // Both pools are floored at 1: zero would refuse every connection, which
        // is a typo rather than a policy (a server that should accept nothing
        // simply should not be started). The grace has no floor — see its doc.
        let unauthenticated = unauthenticated.max(1);
        let sessions = sessions.max(1);
        let grace = Duration::from_secs(grace_secs as u64);

        // Warn, but honour it. This is a "you probably did not mean this" guard,
        // not a correctness invariant: an inverted split still runs, it just
        // makes the pre-auth pool — the one any unauthenticated peer can spend —
        // the binding constraint, which is the starvation the split exists to
        // avoid. Refusing to start would be a worse trade for an explicit
        // operator setting.
        if unauthenticated <= sessions {
            eprintln!(
                "[nkct] warning: pre-auth admission pool ({unauthenticated}) <= session pool \
                 ({sessions}). Unauthenticated peers can then exhaust admission before the \
                 session pool is even full, which is what separating the pools avoids. \
                 Raise NKCT_MAX_UNAUTHENTICATED unless this is deliberate."
            );
        }

        Self { unauthenticated, sessions, grace }
    }
}

/// The pre-auth permit plus the session pool to move into, carried across the
/// handshake boundary.
///
/// The handover in [`NetworkProcessor::handle_server_connection`] takes the
/// session permit **before** releasing the pre-auth one, so a connection is
/// always accounted to exactly one pool. Releasing first would open a window in
/// which arbitrarily many connections belong to neither.
struct Admission {
    preauth: tokio::sync::OwnedSemaphorePermit,
    sessions: Arc<Semaphore>,
    /// Bound on the wait below — carried rather than read from a const so the
    /// limit stays configurable and testable.
    grace: Duration,
    /// The session cap, for the at-capacity message only.
    session_cap: usize,
}

impl Admission {
    /// Swap the pre-auth permit for a session permit once the peer is
    /// authenticated, bounded by `grace`.
    ///
    /// The pre-auth permit is released only on the success path, after the
    /// session permit is in hand, so the connection is never unaccounted. On
    /// either failure path it is dropped as this call returns, freeing the slot
    /// for the next peer instead of pinning it while the session pool is full.
    async fn into_session_permit(self) -> Result<tokio::sync::OwnedSemaphorePermit> {
        let Admission { preauth, sessions, grace, session_cap } = self;
        match tokio::time::timeout(grace, sessions.acquire_owned()).await {
            Ok(Ok(permit)) => {
                drop(preauth);
                Ok(permit)
            }
            Ok(Err(_)) => Err(CryptoError::Parameter(
                "Session semaphore closed".to_string(),
            )),
            Err(_) => Err(CryptoError::Parameter(format!(
                "server is at session capacity ({session_cap} active); refusing this connection"
            ))),
        }
    }
}

/// The authorization map (`fingerprint -> grants`) as a **live view** of the
/// keyring, not a snapshot taken at startup.
///
/// A long-running server is the deployment the keyring is for, and
/// `--keyring-cmd revoke` runs in a *separate* process against the same file.
/// A startup snapshot therefore kept admitting a fingerprint whose grants had
/// been revoked or narrowed, for the process's lifetime, while the CLI printed
/// success — a revocation that silently failed open. The shell/scp/forward
/// policy files are already re-read on every connection; this brings the
/// keyring in line with them.
///
/// Re-reading redb on *every* connection would be wasteful and would contend
/// with the operator's own `keyring` commands for the file lock, so the map is
/// cached and invalidated on the file's (mtime, len) — a keyring write is
/// exactly what changes those, and a connection arriving after the write sees
/// the new grants.
pub(crate) struct AllowlistSource {
    db_path: std::path::PathBuf,
    cached: tokio::sync::Mutex<CachedAllowlist>,
}

struct CachedAllowlist {
    map: Arc<std::collections::HashMap<[u8; 32], u8>>,
    /// `(mtime, len)` of the keyring file the cached map was read from; `None`
    /// forces a reload.
    stamp: Option<(std::time::SystemTime, u64)>,
    /// When the cached map was read. Bounds staleness independently of the
    /// stamp — see [`AllowlistSource::MAX_CACHE_AGE`].
    loaded_at: std::time::Instant,
}

impl AllowlistSource {
    /// Ceiling on how long a cached map is trusted even if `(mtime, len)` looks
    /// unchanged.
    ///
    /// The stamp is the primary signal and catches a revocation immediately,
    /// but it is only as good as the filesystem's timestamp granularity: a
    /// revoke landing in the same mtime tick as the previous read, with the
    /// file length unchanged, would otherwise go unnoticed indefinitely. This
    /// bounds that window to seconds instead of to the process's lifetime,
    /// at the cost of at most one redb read every few seconds on a node that
    /// is actually receiving connections.
    const MAX_CACHE_AGE: Duration = Duration::from_secs(5);
    fn stamp_of(path: &std::path::Path) -> Option<(std::time::SystemTime, u64)> {
        let md = std::fs::metadata(path).ok()?;
        Some((md.modified().ok()?, md.len()))
    }

    fn load(path: &std::path::Path) -> Result<std::collections::HashMap<[u8; 32], u8>> {
        let store = crate::keyring::KeyringStore::open(path).map_err(|e| {
            CryptoError::Parameter(format!("open keyring {}: {e}", path.display()))
        })?;
        Ok(store
            .load_authz()
            .map_err(|e| CryptoError::Parameter(format!("load keyring authz: {e}")))?
            .into_iter()
            .collect())
    }

    pub(crate) fn open(path: &std::path::Path) -> Result<Self> {
        // Load once up front so a misconfigured `--keyring-db` fails at startup
        // rather than on the first inbound connection.
        let map = Self::load(path)?;
        Ok(Self {
            db_path: path.to_path_buf(),
            cached: tokio::sync::Mutex::new(CachedAllowlist {
                map: Arc::new(map),
                stamp: Self::stamp_of(path),
                loaded_at: std::time::Instant::now(),
            }),
        })
    }

    /// The authorization map as of now. Reloads if the keyring file changed.
    ///
    /// Fails **closed**: if the keyring changed but cannot be re-read, this
    /// returns an error and the caller refuses the connection rather than
    /// falling back to the superseded map — falling back is precisely the
    /// revoked-but-still-admitted behaviour being fixed here. One retry absorbs
    /// the brief lock contention of a concurrent `keyring` command; a reload is
    /// rare in the first place, since an unchanged file skips it entirely.
    pub(crate) async fn current(&self) -> Result<Arc<std::collections::HashMap<[u8; 32], u8>>> {
        let mut guard = self.cached.lock().await;
        let path = self.db_path.clone();
        let stamp = tokio::task::spawn_blocking(move || Self::stamp_of(&path))
            .await
            .map_err(|e| CryptoError::Parameter(format!("keyring stat task: {e}")))?;

        // Unchanged file (and a stamp we could actually read), still inside the
        // freshness ceiling — serve the cache.
        if stamp.is_some()
            && stamp == guard.stamp
            && guard.loaded_at.elapsed() < Self::MAX_CACHE_AGE
        {
            return Ok(guard.map.clone());
        }

        let mut last_err = None;
        for attempt in 0..2 {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            let path = self.db_path.clone();
            let loaded = tokio::task::spawn_blocking(move || Self::load(&path))
                .await
                .map_err(|e| CryptoError::Parameter(format!("keyring load task: {e}")))?;
            match loaded {
                Ok(map) => {
                    guard.map = Arc::new(map);
                    // Re-stat after the read: if the file changed *during* it,
                    // this stamp will differ from the next connection's and we
                    // reload again rather than pinning a torn view.
                    let path = self.db_path.clone();
                    guard.stamp = tokio::task::spawn_blocking(move || Self::stamp_of(&path))
                        .await
                        .map_err(|e| CryptoError::Parameter(format!("keyring stat task: {e}")))?;
                    guard.loaded_at = std::time::Instant::now();
                    return Ok(guard.map.clone());
                }
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            CryptoError::Parameter("keyring authorization unavailable".to_string())
        }))
    }
}

pub struct NetworkProcessor {
    config: CryptoConfig,
    endpoint: Arc<dyn P2pEndpoint>,
    /// Pre-authentication admission — see [`AdmissionLimits`].
    handshake_semaphore: Arc<Semaphore>,
    /// Post-authentication admission — see [`AdmissionLimits`].
    session_semaphore: Arc<Semaphore>,
    cached_allowlist: Option<Arc<AllowlistSource>>,
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
            handshake_semaphore: Arc::new(Semaphore::new(AdmissionLimits::get().unauthenticated)),
            session_semaphore: Arc::new(Semaphore::new(AdmissionLimits::get().sessions)),
            cached_allowlist: None,
            io_provider,
        }
    }

    /// Build the in-memory authorization map (`fingerprint -> grants`) from the
    /// **redb keyring** (`--keyring-db`, per-service grants) — the canonical
    /// authorization written by pairing / `keyring authorize`.
    ///
    /// Enforcement is activated only when a keyring is configured; without one,
    /// `cached_allowlist` stays `None` and authorization falls to
    /// `--signing-pubkey` pinning alone (unchanged behaviour).
    ///
    /// Despite the name this no longer freezes the map: it opens the keyring
    /// (so a bad path fails at startup) and hands ownership to an
    /// [`AllowlistSource`], which re-reads the file whenever it changes. See
    /// that type for why a startup snapshot was wrong.
    pub async fn preload_allowlist(&mut self) -> Result<()> {
        if let Some(ref db) = self.config.keyring_db {
            let path = std::path::PathBuf::from(db);
            let source = tokio::task::spawn_blocking(move || AllowlistSource::open(&path))
                .await
                .map_err(|e| CryptoError::Parameter(format!("keyring open task: {e}")))??;
            self.cached_allowlist = Some(Arc::new(source));
        }
        Ok(())
    }

    fn get_pqc_fingerprint(&self, path: &str, algo: &str, is_dsa: bool) -> Result<[u8; 32]> {
        let bytes = Zeroizing::new(std::fs::read(path).map_err(|e| CryptoError::FileRead(format!("Key read failed ({}): {}", path, e)))?);
        Self::pqc_fingerprint_from_pem(
            &bytes,
            algo,
            is_dsa,
            self.config.passphrase.as_deref().map(|s| s.as_str()),
        )
    }

    fn pqc_fingerprint_from_pem(
        pem_bytes: &[u8],
        algo: &str,
        is_dsa: bool,
        passphrase: Option<&str>,
    ) -> Result<[u8; 32]> {
        let pem = std::str::from_utf8(pem_bytes).map_err(|_| CryptoError::Parameter("Invalid UTF-8 in key".to_string()))?;
        let der = crate::utils::unwrap_from_pem(pem, "PRIVATE KEY")?;
        let decrypted = crate::utils::extract_raw_private_key(&der, passphrase)?;

        let raw_pub = if is_dsa {
            let raw_priv = crate::utils::unwrap_pqc_priv_from_pkcs8(&decrypted, algo)?;
            backend::pqc_pub_from_priv_dsa(algo, &raw_priv)?
        } else {
            let raw_priv = crate::utils::unwrap_pqc_priv_from_pkcs8(&decrypted, algo)?;
            backend::pqc_pub_from_priv_kem(algo, &raw_priv)?
        };

        Ok(Sha3_256::digest(&raw_pub).into())
    }

    /// This node's handshake signing identity fingerprint, from whichever
    /// source holds the key: the keyring-injected encrypted PEM (auto-match)
    /// or the `--signing-privkey` file. `None` ⇒ the node runs anonymous.
    fn signing_identity_fp(&self) -> Result<Option<[u8; 32]>> {
        signing_pem_bytes(&self.config)?
            .map(|pem| {
                Self::pqc_fingerprint_from_pem(
                    &pem,
                    &self.config.pqc_dsa_algo,
                    true,
                    self.config.passphrase.as_deref().map(|s| s.as_str()),
                )
            })
            .transpose()
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

        let sign_fp = self.signing_identity_fp()?;

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
    /// The implementation now lives in `crate::utils` so every peer-string
    /// print site in the tree shares one filter; this stays as the name the
    /// P2P code already calls.
    pub fn sanitize_for_terminal(msg: &str) -> String {
        crate::utils::sanitize_for_terminal(msg)
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
            // Reserve a PRE-AUTH slot BEFORE spawning the per-connection setup: a
            // flood of half-open peers then cannot spawn unbounded setup tasks.
            // A stalling peer's `establish` times out within P2P_SETUP_TIMEOUT,
            // freeing its slot, so the accept loop is never permanently starved.
            // This budget is separate from the session budget (see
            // `AdmissionLimits::unauthenticated`), so unauthenticated peers can never take a
            // slot away from an authenticated session — and vice versa: a
            // long-running shell or transfer no longer blocks new handshakes.
            let permit = match self.handshake_semaphore.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => break, // semaphore closed → endpoint shutting down
            };
            let config_clone = self.config.clone();
            let cached_allowlist = self.cached_allowlist.clone();
            let local_peer_id = self.endpoint.local_id();
            let io_provider = self.io_provider.clone();
            let session_semaphore = self.session_semaphore.clone();

            tokio::spawn(async move {
                // Held until the handshake authenticates the peer, at which point
                // `handle_server_connection` swaps it for a session permit. Every
                // early return below drops it, freeing the slot immediately.
                let admission = Admission {
                    preauth: permit,
                    sessions: session_semaphore,
                    grace: AdmissionLimits::get().grace,
                    session_cap: AdmissionLimits::get().sessions,
                };

                // Protocol negotiation + stream open run HERE, off the accept loop,
                // bounded by the timeout — a peer that stalls this cannot block
                // other connections from being accepted and served.
                let incoming = match pending.establish(crate::p2p::P2P_SETUP_TIMEOUT).await {
                    Ok(inc) => inc,
                    Err(e) => {
                        // Attribute the stall when the transport got far enough to
                        // prove who the peer is: completing the QUIC handshake and
                        // then never opening a stream costs the peer nothing but
                        // holds a pre-auth slot for the full timeout, so it must
                        // count toward the throttle like any other failed attempt.
                        // Before that point the identity is merely claimed — see
                        // `EstablishError` — and recording it would let anyone get
                        // a third party throttled.
                        if let Some(node) = e.peer_id {
                            crate::shell::note_auth_failure(node.as_bytes());
                        }
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
                let pairing_allowed = config.serve_pairing;
                let chat_allowed = config.serve_chat;
                config.shell_mode = false;
                config.chat_mode = false;
                config.file_mode = false;
                config.forward_mode = false;
                config.scp_mode = false;
                config.pairing_mode = false;
                if incoming.protocol.0 == ALPN_CHAT {
                    // Gated like every other service. Chat is the most
                    // sensitive of them to leave open by default: the server
                    // half of `chat_loop` reads this process's real stdin and
                    // streams it to the peer, so an ungated chat ALPN turns any
                    // listener into a keystroke feed for whoever dials it.
                    if !chat_allowed {
                        eprintln!("Rejecting nkct/chat/2: this node is not a chat server");
                        return;
                    }
                    config.chat_mode = true;
                } else if incoming.protocol.0 == ALPN_FILE {
                    // Same gate: the file-receive arm writes up to MAX_FILE_SIZE
                    // of peer-chosen bytes to this process's stdout.
                    if !chat_allowed {
                        eprintln!("Rejecting nkct/file/1: this node is not a chat/file server");
                        return;
                    }
                    config.file_mode = true;
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
                        eprintln!("Rejecting nkct/scp/3: this node is not an scp server");
                        return;
                    }
                    config.scp_mode = true;
                } else if incoming.protocol.0 == crate::network::ALPN_PAIRING {
                    if !pairing_allowed {
                        eprintln!("Rejecting nkct/pairing/1: this node is not a pairing server");
                        return;
                    }
                    config.pairing_mode = true;
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
                    Some(admission),
                )
                .await
                {
                    // The error text can embed peer-supplied bytes (e.g. the
                    // requested path in an scp denial), so it goes through the
                    // same terminal filter as the two prints above.
                    eprintln!("Connection failed: {}", Self::sanitize_for_terminal(&e.to_string()));
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
        self.run_listen_once_with_progress(on_ticket, |_peer_fp| on_handshake_done(), None).await
    }

    /// `on_handshake_done` receives the peer's authenticated identity: the
    /// SHA3-256 fingerprint of the ML-DSA key it signed the handshake with, or
    /// `None` when the peer connected anonymously (only possible on a node that
    /// allows it — see `CryptoConfig::require_initiator_self_auth`). A caller
    /// with a user in front of it is expected to display it, because on a node
    /// whose only admission control is "holds the ticket" the fingerprint is
    /// the sole means of telling the intended sender from anyone else who saw
    /// the ticket.
    pub async fn run_listen_once_with_progress<F1, F2>(
        &self,
        on_ticket: F1,
        on_handshake_done: F2,
        on_progress: Option<crate::network::ProgressCallback>,
    ) -> Result<()>
    where
        F1: FnOnce(&Ticket),
        F2: FnOnce(Option<[u8; 32]>) + Send + 'static,
    {
        let local_addr = self.endpoint.local_addr().await
            .map_err(|e| CryptoError::Parameter(format!("Local addr: {}", e)))?;
        eprintln!("[nkct] Listening (single-shot) as NodeId: {}", local_addr.peer_id);

        let sign_fp = self.signing_identity_fp()?;

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
        F: FnOnce(Option<[u8; 32]>) + Send + 'static,
    {
        // Both errors below carry the connecting peer's text — its QUIC close
        // reason — and neither is matched on anywhere; they exist to be shown.
        // Unlike the accept *loop* above, which sanitizes at its `eprintln!`,
        // this single-shot path returns them, and `main` prints the returned
        // error through anyhow with no filter of its own. So the gate goes
        // where the peer's bytes enter the message. Bounded like the loop's
        // sibling sinks; our own prefix stays outside the bound.
        let pending = self.endpoint.accept().await.map_err(|e| {
            CryptoError::Parameter(format!(
                "Accept failed: {}",
                crate::utils::sanitize_for_terminal_bounded(&e.to_string(), 256)
            ))
        })?;
        // Single-shot: run the per-connection setup inline, but still bound it so
        // a peer that completes the QUIC handshake then never opens a stream
        // cannot hang the listener forever.
        // Single-shot serves exactly one connection and then returns, so a failure
        // here ends the listener anyway — there is no next accept for a throttle
        // entry to protect, unlike the long-running loop above.
        let incoming = pending
            .establish(crate::p2p::P2P_SETUP_TIMEOUT)
            .await
            .map_err(|e| {
                CryptoError::Parameter(format!(
                    "Connection setup failed: {}",
                    crate::utils::sanitize_for_terminal_bounded(&e.to_string(), 256)
                ))
            })?;

        let mut config = self.config.clone();
        let shell_allowed = config.serve_shell;
        let forward_allowed = config.serve_forward;
        let scp_allowed = config.serve_scp;
        let pairing_allowed = config.serve_pairing;
        let chat_allowed = config.serve_chat;
        config.shell_mode = false;
        config.chat_mode = false;
        config.file_mode = false;
        config.forward_mode = false;
        config.scp_mode = false;
        config.pairing_mode = false;
        // Same gate as `run_listen_loop`. This dispatch is duplicated, so both
        // copies must carry it: without the gate here a `--serve-pairing` node
        // (which serves exactly one connection through this path) would hand a
        // peer that dials `nkct/chat/2` an interactive session against the
        // server's own stdin instead of the pairing exchange it advertises.
        if incoming.protocol.0 == ALPN_CHAT {
            if !chat_allowed {
                return Err(CryptoError::Parameter(
                    "chat (nkct/chat/2) is not enabled on this node".to_string(),
                ));
            }
            config.chat_mode = true;
        } else if incoming.protocol.0 == ALPN_FILE {
            if !chat_allowed {
                return Err(CryptoError::Parameter(
                    "file receive (nkct/file/1) is not enabled on this node".to_string(),
                ));
            }
            config.file_mode = true;
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
                    "scp (nkct/scp/3) is not enabled on this node".to_string(),
                ));
            }
            config.scp_mode = true;
        } else if incoming.protocol.0 == crate::network::ALPN_PAIRING {
            if !pairing_allowed {
                return Err(CryptoError::Parameter(
                    "pairing (nkct/pairing/1) is not enabled on this node".to_string(),
                ));
            }
            config.pairing_mode = true;
        } else {
            return Err(CryptoError::Parameter(format!(
                "Unknown ALPN: {:?}", String::from_utf8_lossy(incoming.protocol.0)
            )));
        }

        // One connection for the lifetime of this call, so the two-pool handover
        // has nothing to arbitrate: take a session permit directly and pass no
        // `Admission`.
        let _permit = self.session_semaphore.clone().acquire_owned().await
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
            None,
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
        cached_allowlist: Option<Arc<AllowlistSource>>,
        io_provider: Arc<dyn IOProvider>,
        on_handshake_done: Option<Box<dyn FnOnce(Option<[u8; 32]>) + Send>>,
        on_progress: Option<crate::network::ProgressCallback>,
        admission: Option<Admission>,
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
            } else if !config.allow_unauth
                || config.require_initiator_self_auth
                || config.signing_pubkey.is_some()
            {
                // `require_initiator_self_auth` is the third, independent reason
                // to refuse an anonymous initiator: an open node (`allow_unauth`,
                // no pin) that still wants every session to carry an identity.
                // Without it the only `peer_id` available below is
                // `PeerId::Node` — the peer's transport key, which it mints per
                // connection and which therefore cannot be shown to an operator
                // as "who connected". See `CryptoConfig::require_initiator_self_auth`.
                return Err(CryptoError::Parameter("Handshake failed: Client authentication required".to_string()));
            }

            if peer_id_opt.is_none() {
                peer_id_opt = Some(PeerId::Node(*remote_peer_id.as_bytes()));
            }
            let peer_id = peer_id_opt.unwrap();

            if config.pairing_mode {
                // Pairing bootstrap: accept a client that self-authenticated but is
                // NOT yet in the allowlist (learning its identity is the whole
                // point). The ONLY relaxation is skipping the membership check — the
                // signature verification above is unchanged, so the client must have
                // proven possession of its key (`PeerId::Pubkey`); an anonymous peer
                // is refused. Registration is gated downstream by the OTP and by
                // (handshake fingerprint == KeyBundle owner fingerprint).
                if !matches!(peer_id, PeerId::Pubkey(_)) {
                    return Err(CryptoError::Parameter(
                        "pairing requires a self-authenticating client".to_string(),
                    ));
                }
            } else if let Some(ref source) = cached_allowlist {
                // Read the keyring as of *now*, not as of startup, so a
                // revocation between then and this connection is honoured.
                let allowlist = source.current().await?;
                match peer_id {
                    PeerId::Pubkey(hash) => {
                        let granted = match allowlist.get(&hash) {
                            Some(g) => *g,
                            None => {
                                return Err(CryptoError::Parameter("Peer not in allowlist".to_string()))
                            }
                        };
                        // Per-service grant. `required_grant_bit` returns a
                        // *mask*: a single bit for shell/scp/forward, and the
                        // full set for chat/file-receive, so the peer must hold
                        // every bit in it. (`& mask != 0` would have accepted a
                        // peer holding any one bit of a multi-bit mask.)
                        if let Some(mask) = required_grant_bit(config) {
                            if granted & mask != mask {
                                return Err(CryptoError::Parameter(format!(
                                    "Peer is in the allowlist but not authorized for this service (grants=0b{granted:03b})"
                                )));
                            }
                        }
                    }
                    _ => {
                        return Err(CryptoError::Parameter("Anonymous peer not allowed when allowlist is active".to_string()));
                    }
                }
            } else if (config.chat_mode || config.file_mode)
                && config.signing_pubkey.is_none()
                && !config.allow_unauth
            {
                // Default-deny for chat / file-receive when the node has NO
                // source of authorization at all.
                //
                // Authentication is not authorization. Reaching here with
                // `allow_unauth == false` means the peer produced a valid
                // sig_I, but that only proves it holds *some* ML-DSA key —
                // one it can mint itself. The membership + grant-mask check
                // above (the only place `required_grant_bit`'s GRANT_ALL for
                // chat/file is ever consulted) runs solely in the
                // `cached_allowlist` arm, so without a keyring
                // (`--keyring-db`) *and* without a pinned client key
                // (`--signing-pubkey`, bound to #6 before sig_I is verified)
                // nothing constrains *which* identity is admitted: every
                // holder of the ticket could open a session against the
                // operator's stdin (chat) or stream up to MAX_FILE_SIZE into
                // its stdout (file-receive).
                //
                // shell / scp / forward already require one of those two
                // sources before they will serve at all (see main.rs); this is
                // the same rule for the two services that lacked it, applied
                // here rather than at startup so it holds for every caller of
                // this function — the persistent listener, the single-shot
                // path, and embedders that build a `NetworkProcessor`
                // directly — not just the CLI.
                //
                // `--allow-unauth` stays the explicit opt-in to an open node,
                // so an operator can still run one deliberately; a bare
                // `--serve-chat` must now name a keyring, a pinned key, or
                // that flag. The refusal happens before any responder field is
                // written, so the peer learns nothing beyond a closed
                // connection (same disclosure posture as the ALPN gate).
                return Err(CryptoError::Parameter(
                    "Peer authorization is not configured for chat/file-receive: this node accepts \
                     no one until it is told who may connect (--keyring-db allowlist and/or \
                     --signing-pubkey pinned peer), or is opened deliberately with --allow-unauth"
                        .to_string(),
                ));
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

            let server_auth_flag = if has_signing_identity(config) { [hs_flags::RESPONDER_SELF_AUTH] } else { [0u8] };
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
                    let dsa_bytes = signing_pem_bytes(&config)?
                        .expect("RESPONDER_SELF_AUTH set ⇒ signing identity present");
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

        // Admission handover: the handshake is done, so this connection stops
        // spending the pre-auth budget and starts spending the session budget.
        // Acquire before releasing — see `Admission` — and do it before the
        // handshake-done callback fires, so the UI does not report a live session
        // while it is still queued for a slot.
        //
        // The wait inside is bounded — see `AdmissionLimits::grace`. An at-capacity
        // refusal is deliberately NOT recorded against the auth-failure throttle:
        // that runs above, on the handshake path, and this connection's handshake
        // succeeded. The fault is the server's, not the peer's.
        let _session_permit = match admission {
            Some(a) => Some(a.into_session_permit().await?),
            None => None,
        };

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
            // Hand the caller the identity that was actually authenticated, so a
            // UI can name the peer it is about to accept bytes from instead of
            // reporting a nameless "connected".
            cb(shell_peer_fp);
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
        } else if config.pairing_mode {
            // Pairing server: register the self-authenticated peer (its handshake
            // fingerprint) + its signed KeyBundle, gated by the one-time token.
            let fp = shell_peer_fp.ok_or_else(|| {
                CryptoError::Parameter("pairing requires an authenticated peer".to_string())
            })?;
            crate::pairing::run_pairing_server(
                reader,
                writer,
                &config.aead_algo,
                &s2c_key,
                &c2s_key,
                fp,
                &config,
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
        } else if config.copy_bundle {
            crate::network::ALPN_PAIRING
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
                // Per-attempt connect timeout, escalating. A server can advertise
                // direct addresses a given client cannot reach — multi-homed hosts,
                // VPN/overlay addresses, or an interface firewalled off from this
                // peer — and iroh may race onto such a dead path and block on it.
                // A short FIRST timeout fast-fails that dead path so the next
                // attempt re-races and usually lands on a working address within a
                // few seconds, instead of burning a flat 12 s five times (~64 s
                // before it finally errors). Later attempts keep the full 12 s so a
                // genuinely slow-but-live path — a WAN relay / hole-punch still
                // coming up — is not cut off prematurely. Total worst case is
                // 3+5+8+12+12 + 4×1 s backoff = 44 s.
                const CONNECT_TIMEOUTS: [Duration; 5] = [
                    Duration::from_secs(3),
                    Duration::from_secs(5),
                    Duration::from_secs(8),
                    Duration::from_secs(12),
                    Duration::from_secs(12),
                ];
                let stream = {
                    let mut attempt = 1usize;
                    loop {
                        let res = tokio::time::timeout(
                            CONNECT_TIMEOUTS[attempt - 1],
                            self.endpoint.connect(&remote_peer_addr, protocol),
                        )
                        .await;
                        // Flatten timeout(Ok/Err) and the inner connect Result.
                        //
                        // The dialed peer chooses part of that error: a QUIC
                        // close reason it picks is stringified into
                        // `P2pError::Connect("open_bi: …")`. It reaches the
                        // operator's terminal up to five times (once per retry
                        // below, then as the returned error `main` prints), and
                        // this is the terminal on which the operator compares
                        // the peer fingerprint for an unpinned peer. Gate it
                        // once, here, where the peer's bytes enter our string —
                        // so the retry log, the returned error and anything
                        // else that renders it are all covered. Bounded like
                        // every sibling peer-string sink: our own `connect
                        // attempt n/m failed (` scaffolding is outside the
                        // bound, so only attacker-chosen tail can be cut.
                        let outcome = match res {
                            Ok(Ok(s)) => Ok(s),
                            Ok(Err(e)) => Err(crate::utils::sanitize_for_terminal_bounded(
                                &e.to_string(),
                                256,
                            )),
                            Err(_) => Err("attempt timed out".to_string()),
                        };
                        match outcome {
                            Ok(s) => break s,
                            Err(e) if attempt < CONNECT_TIMEOUTS.len() => {
                                eprintln!(
                                    "[nkct] connect attempt {attempt}/{} failed \
                                     ({e}); retrying…",
                                    CONNECT_TIMEOUTS.len()
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
                    if has_signing_identity(&config) { client_flags |= hs_flags::INITIATOR_SELF_AUTH; }
                    if expects_responder_auth { client_flags |= hs_flags::EXPECTS_RESPONDER_AUTH; }
                    let client_auth_flag = [client_flags];
                    writer.write_all(&client_auth_flag).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
                    tb.append_raw(&client_auth_flag); // #5 initiator flags

                    // #6 initiator ML-DSA pub (if self-auth). Load the signing key but
                    // defer signing until after #7 is appended so sig_I covers #1–#7.
                    let mut sign_priv: Option<Zeroizing<Vec<u8>>> = None;
                    if client_auth_flag[0] & hs_flags::INITIATOR_SELF_AUTH != 0 {
                        let raw_priv = {
                            let privkey_bytes = signing_pem_bytes(&config)?
                                .expect("INITIATOR_SELF_AUTH set ⇒ signing identity present");
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
                        
                        if let Some(ref source) = self.cached_allowlist {
                            // Client side: we are pinning which SERVER we will talk
                            // to, so membership (any grant) is what matters — grants
                            // gate a server authorizing a client, not the reverse.
                            let allowlist = source.current().await?;
                            let hash: [u8; 32] = Sha3_256::digest(&server_dsa_pub).into();
                            if !allowlist.contains_key(&hash) {
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
                        crate::scp::ScpOp::Get { remote: remote.clone(), local: local.clone(), recursive: config.scp_recursive, resume: config.scp_resume }
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
                } else if config.copy_bundle {
                    // Pairing client: send our pre-built KeyBundle + the one-time token.
                    let token = config.pairing_token.as_deref().ok_or_else(|| {
                        CryptoError::Parameter("copy-bundle requires --token".to_string())
                    })?;
                    let bytes = config.pairing_bundle_bytes.clone().ok_or_else(|| {
                        CryptoError::Parameter("copy-bundle: no KeyBundle was built".to_string())
                    })?;
                    let msg = crate::pairing::run_pairing_client(
                        reader,
                        writer,
                        &config.aead_algo,
                        &s2c_key,
                        &c2s_key,
                        token,
                        bytes,
                    )
                    .await?;
                    println!("{msg}");
                    Ok(())
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

    // Tuning overrides: a bad value must fall back to the shipped default rather
    // than disable admission control, and the floors must hold.

    #[test]
    fn limit_override_parsing_falls_back_on_junk() {
        assert_eq!(parse_limit("V", None, 32), 32, "unset → default");
        assert_eq!(parse_limit("V", Some("64"), 32), 64);
        assert_eq!(parse_limit("V", Some("  64  "), 32), 64, "whitespace tolerated");
        assert_eq!(parse_limit("V", Some("0"), 32), 0, "zero parses; floors applied later");
        // Junk must not silently become 0 (which the floor would then turn into
        // 1) or panic — it falls back to the shipped default.
        for junk in ["", "abc", "-1", "3.5", "64k", "99999999999999999999999"] {
            assert_eq!(parse_limit("V", Some(junk), 32), 32, "junk {junk:?} → default");
        }
    }

    #[test]
    fn resolved_limits_floor_the_pools_but_not_the_grace() {
        let l = AdmissionLimits::resolve(0, 0, 0);
        assert_eq!(l.unauthenticated, 1, "a zero pool would accept nothing");
        assert_eq!(l.sessions, 1);
        assert_eq!(l.grace, Duration::ZERO, "zero grace is a valid 'never wait'");

        // An inverted split is honoured (it only warns) — pinning that the guard
        // is advisory, so an explicit operator setting is never silently altered.
        let l = AdmissionLimits::resolve(2, 50, 7);
        assert_eq!((l.unauthenticated, l.sessions), (2, 50));
        assert_eq!(l.grace, Duration::from_secs(7));

        let l = AdmissionLimits::resolve(
            DEFAULT_MAX_UNAUTHENTICATED,
            DEFAULT_MAX_SESSIONS,
            DEFAULT_SESSION_ADMISSION_GRACE_SECS as usize,
        );
        assert_eq!(l.unauthenticated, DEFAULT_MAX_UNAUTHENTICATED);
        assert_eq!(l.sessions, DEFAULT_MAX_SESSIONS);
    }

    /// The shipped grace, used directly rather than via `AdmissionLimits::get()`
    /// so these tests pin the *design* and stay deterministic regardless of what
    /// `NKCT_*` happens to be set to in the environment running them.
    fn test_grace() -> Duration {
        Duration::from_secs(DEFAULT_SESSION_ADMISSION_GRACE_SECS)
    }

    // Admission control: the pre-auth and session budgets must stay independent.
    // A single shared pool was exhaustible from either side — unauthenticated
    // peers that connect and stall could consume every slot (holding each for up
    // to P2P_SETUP_TIMEOUT + handshake_timeout, and evading the NodeId-keyed
    // throttle by rotating identities), and conversely a full set of long-lived
    // sessions blocked all new handshakes. These two tests pin each direction.

    /// Session side: the handover must give the pre-auth slot back. If it ever
    /// regresses to holding both, saturating the session pool would again starve
    /// new handshakes.
    #[tokio::test]
    async fn full_session_pool_leaves_every_preauth_slot_free() {
        let preauth = Arc::new(Semaphore::new(DEFAULT_MAX_UNAUTHENTICATED));
        let sessions = Arc::new(Semaphore::new(DEFAULT_MAX_SESSIONS));

        let mut established = Vec::new();
        for _ in 0..DEFAULT_MAX_SESSIONS {
            // The handover `handle_server_connection` performs once the handshake
            // authenticates the peer: take the session permit, THEN release the
            // pre-auth one, so the connection is never in neither pool.
            let admission = Admission {
                preauth: preauth.clone().acquire_owned().await.unwrap(),
                sessions: sessions.clone(),
                grace: test_grace(),
                session_cap: DEFAULT_MAX_SESSIONS,
            };
            established.push(admission.into_session_permit().await.unwrap());
        }

        assert_eq!(sessions.available_permits(), 0, "session pool should be full");
        assert_eq!(
            preauth.available_permits(),
            DEFAULT_MAX_UNAUTHENTICATED,
            "a saturated session pool must leave the pre-auth pool untouched, \
             otherwise long-lived shells/transfers starve new handshakes"
        );
    }

    /// Pre-auth side: a peer that connects and stalls never reaches the handover,
    /// so it can only ever spend the pre-auth budget — never a session slot.
    #[tokio::test]
    async fn unauthenticated_flood_cannot_reach_the_session_pool() {
        let preauth = Arc::new(Semaphore::new(DEFAULT_MAX_UNAUTHENTICATED));
        let sessions = Arc::new(Semaphore::new(DEFAULT_MAX_SESSIONS));

        let mut stalled = Vec::new();
        for _ in 0..DEFAULT_MAX_UNAUTHENTICATED {
            stalled.push(Admission {
                preauth: preauth.clone().acquire_owned().await.unwrap(),
                sessions: sessions.clone(),
                grace: test_grace(),
                session_cap: DEFAULT_MAX_SESSIONS,
            });
        }

        assert_eq!(preauth.available_permits(), 0, "pre-auth pool should be full");
        assert_eq!(
            sessions.available_permits(),
            DEFAULT_MAX_SESSIONS,
            "unauthenticated peers must not be able to consume session slots"
        );
        // Timing out / erroring drops the Admission, which frees the slot.
        stalled.pop();
        assert_eq!(preauth.available_permits(), 1);
    }

    /// Contended handover: with the session pool full, waiting for a slot must be
    /// bounded AND must give the pre-auth slot back.
    ///
    /// This is the case the two tests above do not reach — they only ever hand
    /// over while a session permit is free. An unbounded wait here is worse than
    /// the single-pool design this replaced: `DEFAULT_MAX_UNAUTHENTICATED` connections
    /// that finished their handshake would pin every pre-auth slot for as long as
    /// the session pool stayed full, halting the accept loop with no timeout to
    /// break it.
    #[tokio::test]
    async fn full_session_pool_refuses_instead_of_pinning_a_preauth_slot() {
        tokio::time::pause(); // auto-advances over the grace

        let preauth = Arc::new(Semaphore::new(DEFAULT_MAX_UNAUTHENTICATED));
        let sessions = Arc::new(Semaphore::new(DEFAULT_MAX_SESSIONS));

        // Saturate the session pool and keep it that way.
        let _held: Vec<_> = (0..DEFAULT_MAX_SESSIONS)
            .map(|_| sessions.clone().try_acquire_owned().unwrap())
            .collect();
        assert_eq!(sessions.available_permits(), 0);

        let admission = Admission {
            preauth: preauth.clone().acquire_owned().await.unwrap(),
            sessions: sessions.clone(),
            grace: test_grace(),
            session_cap: DEFAULT_MAX_SESSIONS,
        };
        assert_eq!(preauth.available_permits(), DEFAULT_MAX_UNAUTHENTICATED - 1);

        // The outer bound is far longer than the inner one, so on a paused clock
        // the inner timer always fires first. It exists only so that *removing*
        // the inner bound fails this test with a diagnostic instead of hanging.
        let err = tokio::time::timeout(Duration::from_secs(600), admission.into_session_permit())
            .await
            .expect("the handover must be bounded — it waited on a full session pool")
            .expect_err("a full session pool must refuse, not wait forever");
        assert!(
            err.to_string().contains("session capacity"),
            "expected an at-capacity refusal, got: {err}"
        );
        assert_eq!(
            preauth.available_permits(),
            DEFAULT_MAX_UNAUTHENTICATED,
            "a refused connection must release its pre-auth slot"
        );
    }

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

    /// The fixed expected-responder-fingerprint used for the #7 pre-commit in the
    /// KAT (raw32; a recognizable pattern distinct from CID/SID).
    const KAT_EXP_FP: [u8; 32] = [0x33; 32];

    /// Build the canonical transcript for fixed inputs via `TranscriptBuilder`.
    /// `full=false` stops after the initiator-auth block (#1–#7) — the slice the
    /// client signs (returned as the builder's prefix snapshot). `#5` is the
    /// initiator flags byte: bit0 (`client_auth`) gates #6, bit1
    /// (`expects_responder_auth`) gates the #7 expected-responder-fingerprint.
    fn kat_builder(
        client_auth: bool,
        expects_responder_auth: bool,
        server_auth: bool,
        full: bool,
    ) -> TranscriptBuilder {
        const CID: [u8; 32] = [0x11; 32];
        const SID: [u8; 32] = [0x22; 32];
        let mut tb = TranscriptBuilder::new();
        tb.append_raw(&CID); // #1 raw  server:369 / client:723
        tb.append_raw(&SID); // #2 raw  server:370 / client:724
        tb.append_lp(b"CECC"); // #3 lp server:375/client:741
        tb.append_lp(b"CKEM"); // #4 lp server:376/client:742
        // #5 initiator flags: bit0 = INITIATOR_SELF_AUTH (→#6), bit1 =
        // EXPECTS_RESPONDER_AUTH (→#7). Mirrors hs_flags on server:380 / client:746.
        let flags = (client_auth as u8) * hs_flags::INITIATOR_SELF_AUTH
            + (expects_responder_auth as u8) * hs_flags::EXPECTS_RESPONDER_AUTH;
        tb.append_raw(&[flags]);
        if client_auth {
            tb.append_lp(b"CDSA"); // #6 lp server:384/client:759
        }
        if expects_responder_auth {
            tb.append_raw(&KAT_EXP_FP); // #7 raw32 server:507 / client:1009
        }
        if !full {
            return tb; // client-signature view ends at #7
        }
        tb.append_lp(b"SECC"); // #8 lp server / client
        tb.append_lp(b"KEMCT"); // #9 lp server / client
        tb.append_raw(&[server_auth as u8]); // #10 raw server / client
        if server_auth {
            tb.append_lp(b"SDSA"); // #11 lp server / client
            tb.append_lp(b"SKEM"); // #12 lp server / client
        }
        tb
    }

    fn kat_transcript(
        client_auth: bool,
        expects_responder_auth: bool,
        server_auth: bool,
        full: bool,
    ) -> Vec<u8> {
        kat_builder(client_auth, expects_responder_auth, server_auth, full)
            .snapshot()
            .to_vec()
    }

    // Golden bytes of the canonical v3 transcript for the fixed KAT inputs above.
    // Mutual-auth layout (client_auth + expects_responder_auth + server_auth):
    // client_id(32 raw) ‖ server_id(32 raw) ‖ u32LE(4)"CECC" ‖ u32LE(4)"CKEM" ‖
    // 03 (#5 flags: bit0|bit1) ‖ u32LE(4)"CDSA" (#6) ‖ 33*32 (#7 expected
    // responder fingerprint, raw32) ‖ u32LE(4)"SECC" (#8) ‖ u32LE(5)"KEMCT" (#9) ‖
    // 01 (#10) ‖ u32LE(4)"SDSA" (#11) ‖ u32LE(4)"SKEM" (#12). The length prefix is
    // u32 little-endian (the v3 wire format); changing it would break compat.
    const KAT_FULL_AUTH: &str = "11111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222040000004345434304000000434b454d03040000004344534133333333333333333333333333333333333333333333333333333333333333330400000053454343050000004b454d435401040000005344534104000000534b454d";
    const KAT_PARTIAL_AUTH: &str = "11111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222040000004345434304000000434b454d0304000000434453413333333333333333333333333333333333333333333333333333333333333333";
    const KAT_FULL_NOAUTH: &str = "11111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222040000004345434304000000434b454d000400000053454343050000004b454d435400";
    const KAT_SALT_AUTH: &str =
        "8d2e9988414f470b465700d3cb09ffa17ce571122dc482cb24071a11d17d9634";

    #[test]
    fn handshake_transcript_kat() {
        // Mutual-auth full transcript bound into the salt — #1..#12 incl. the #7
        // expected-responder-fingerprint pre-commit.
        assert_eq!(hex(&kat_transcript(true, true, true, true)), KAT_FULL_AUTH);
        // Partial transcript the initiator signs — #1..#7 (incl. #6 and #7).
        assert_eq!(hex(&kat_transcript(true, true, true, false)), KAT_PARTIAL_AUTH);
        // Unauthenticated mode: no #6, no #7; still binds the KEM ciphertext (#9).
        assert_eq!(hex(&kat_transcript(false, false, false, true)), KAT_FULL_NOAUTH);
        // Salt = SHA3-256(full transcript), via the builder's finalize_salt().
        assert_eq!(
            hex(&kat_builder(true, true, true, true).finalize_salt()),
            KAT_SALT_AUTH
        );
        // The KEM ciphertext ("KEMCT") and both ephemeral pubkeys MUST appear in
        // the salt's preimage — the property the hybrid combiner relies on.
        assert!(KAT_FULL_AUTH.contains(&hex(b"KEMCT")));
        assert!(KAT_FULL_AUTH.contains(&hex(b"CECC")) && KAT_FULL_AUTH.contains(&hex(b"SECC")));
        // The #7 expected-responder-fingerprint (raw32) MUST be bound into the
        // signed transcript — this is the pre-commit that the responder cross-checks
        // (A-resp) and that gets covered by sig_I. Its omission was the stale-KAT bug.
        assert!(KAT_FULL_AUTH.contains(&hex(&KAT_EXP_FP)));
        assert!(KAT_PARTIAL_AUTH.contains(&hex(&KAT_EXP_FP)));
        // The unauth transcript must NOT carry a #7 (no pre-commit without bit1).
        assert!(!KAT_FULL_NOAUTH.contains(&hex(&KAT_EXP_FP)));
        // The initiator-signature view MUST be a strict prefix of the full
        // transcript (same buffer up to #7). Pins that `snapshot()` returns a
        // genuine prefix, not a separately built / trailing-padded value.
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
        // The test drives the handshake over ALPN_FILE, which is gated on this
        // like shell/scp/forward are on theirs — declare the role being tested.
        server_config.serve_chat = true;
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
            server_proc.run_listen_once_with_progress(|_| {}, |_| {}, None).await
        });

        let client_res = client_proc.run_connect().await;

        assert!(client_res.is_ok(), "Client connection failed: {:?}", client_res.err());
        assert!(server_task.await.unwrap().is_ok(), "Server listening failed");
    }

    /// The ALPN dispatch is duplicated between `run_listen_loop` and the
    /// single-shot `run_listen_once`, so the chat/file gate has to be tested on
    /// both. The single-shot path is what `--serve-pairing` and the GUI use: a
    /// node serving pairing must not additionally hand out a chat session
    /// against its own stdin to a peer that simply dials `nkct/chat/2`.
    #[tokio::test]
    async fn single_shot_listener_refuses_chat_file_without_serve_chat() {
        let net = MockNetwork::new();
        let server_id = P2pPeerId::new([3; 32]);
        let client_id = P2pPeerId::new([4; 32]);

        let proto_chat = P2pProtocol(ALPN_CHAT);
        let proto_file = P2pProtocol(ALPN_FILE);
        let server_ep = Arc::new(net.register(server_id, vec![proto_chat, proto_file]));
        let client_ep = Arc::new(net.register(client_id, vec![proto_chat, proto_file]));

        let mut server_config = CryptoConfig::default();
        server_config.chat_mode = false;
        server_config.allow_unauth = true;
        server_config.handshake_timeout = 2;
        // Deliberately NOT a chat/file server.
        assert!(!server_config.serve_chat);

        let mut client_config = CryptoConfig::default();
        client_config.chat_mode = false;
        client_config.allow_unauth = true;
        client_config.handshake_timeout = 2;

        let server_addr = server_ep.local_addr().await.unwrap();
        client_config.connect_addr = Some(Ticket::new(server_addr, None, None).to_string());

        let server_proc = NetworkProcessor::new(server_config, server_ep, Arc::new(TestIOProvider));
        let client_proc = NetworkProcessor::new(client_config, client_ep, Arc::new(TestIOProvider));

        let server_task = tokio::spawn(async move {
            server_proc.run_listen_once_with_progress(|_| {}, |_| {}, None).await
        });
        let client_res = client_proc.run_connect().await;

        let server_res = server_task.await.unwrap();
        assert!(
            server_res.is_err(),
            "the single-shot listener served a chat/file ALPN it never enabled"
        );
        assert!(
            format!("{:?}", server_res.unwrap_err()).contains("not enabled on this node"),
            "the refusal must name the missing role"
        );
        assert!(
            client_res.is_err(),
            "the client must not complete a session the server refused"
        );
    }

    // ------------------------------------------------------------------
    // §8 / §10(B): responder-side parser robustness (raw-byte injection).
    //
    // A pseudo-client writes attacker-controlled bytes straight to the server's
    // handshake reader; the server MUST return a clean Err — never panic, hang,
    // or over-allocate. One harness serves both the targeted malformed-frame
    // negatives (reserved flag / missing pre-commit) and a deterministic fuzz
    // sweep. Field-length gates (`ensure_field_len`) fire before any crypto, so a
    // valid-length garbage prefix is enough to reach the flag/#7 logic.
    // ------------------------------------------------------------------

    /// LP-frame `b` (u32-LE length ‖ bytes) exactly as the wire encodes a field.
    fn kx6_lp(b: &[u8]) -> Vec<u8> {
        let mut v = (b.len() as u32).to_le_bytes().to_vec();
        v.extend_from_slice(b);
        v
    }

    /// #3 (P-256 SPKI, 91B) ‖ #4 (ML-KEM ek, 1184B) with garbage contents: the
    /// exact lengths pass `ensure_field_len`, letting the parser reach the #5
    /// flags byte (the flag checks fire before the garbage is used as a key).
    fn kx6_valid_len_prefix() -> Vec<u8> {
        let mut v = kx6_lp(&vec![0u8; backend::P256_SPKI_DER_LEN]);
        v.extend_from_slice(&kx6_lp(&vec![
            0u8;
            backend::mlkem_ek_len("ML-KEM-768").unwrap()
        ]));
        v
    }

    /// Feed `client_bytes` verbatim to one server handshake and return the
    /// server's result. The stream is shut down after the write so the server's
    /// reads hit EOF (a clean Err) instead of blocking. A timeout turns any hang
    /// into a test failure, and the join turns any panic into one.
    async fn kx6_drive_raw_to_server(client_bytes: Vec<u8>) -> Result<()> {
        // Unique peer ids per call: the server's auth-failure throttle is keyed by
        // the remote NodeId and is a process-global — reusing one id across the
        // fuzz sweep (or colliding with another test's ids) would throttle later
        // handshakes and cause spurious failures. A per-call counter in a distinct
        // high byte-range keeps every peer a first-time (un-throttled) failure and
        // never collides with the fixed ids other tests use.
        use std::sync::atomic::{AtomicU64, Ordering};
        static KX6_COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = KX6_COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut sid = [0xE5u8; 32];
        let mut cid = [0xC1u8; 32];
        sid[24..32].copy_from_slice(&n.to_le_bytes());
        cid[24..32].copy_from_slice(&n.to_le_bytes());
        let net = crate::p2p::backend::mock::MockNetwork::new();
        let server_id = P2pPeerId::new(sid);
        let client_id = P2pPeerId::new(cid);
        let proto = P2pProtocol(ALPN_CHAT);
        let server_ep = Arc::new(net.register(server_id, vec![proto]));
        let client_ep = Arc::new(net.register(client_id, vec![proto]));
        let server_addr = server_ep.local_addr().await.unwrap();

        let mut server_config = CryptoConfig::default();
        server_config.chat_mode = false;
        server_config.allow_unauth = true;
        server_config.handshake_timeout = 3;

        let server_proc =
            NetworkProcessor::new(server_config, server_ep, Arc::new(TestIOProvider));
        let server_task = tokio::spawn(async move {
            server_proc
                .run_listen_once_with_progress(|_| {}, |_| {}, None)
                .await
        });

        let mut stream = client_ep.connect(&server_addr, proto).await.unwrap();
        let _ = stream.write_all(&client_bytes).await;
        let _ = stream.shutdown().await;

        tokio::time::timeout(Duration::from_secs(8), server_task)
            .await
            .expect("server handshake hung on malformed input")
            .expect("server handshake task panicked on malformed input")
    }

    // §8 item 10a: a reserved bit in the #5 initiator-flags byte → reject.
    #[tokio::test]
    async fn handshake_reserved_initiator_flag_bit_rejected() {
        let mut msg = kx6_valid_len_prefix();
        msg.push(0x04); // not in INITIATOR_ALLOWED (0x03) → reserved
        assert!(
            kx6_drive_raw_to_server(msg).await.is_err(),
            "a reserved bit in #5 must be rejected"
        );
    }

    // §8 item 10b: #5.bit1 (EXPECTS_RESPONDER_AUTH) set but the #7 pre-commit
    // (raw32) missing (truncated) → reject, not panic.
    #[tokio::test]
    async fn handshake_expects_responder_but_precommit_missing_rejected() {
        let mut msg = kx6_valid_len_prefix();
        msg.push(hs_flags::EXPECTS_RESPONDER_AUTH); // 0x02: #7 now required
        // ...and send no #7 at all (the stream ends here).
        assert!(
            kx6_drive_raw_to_server(msg).await.is_err(),
            "#5.bit1 set with a missing #7 pre-commit must be rejected"
        );
    }

    // §8 / §10(B): fuzz the responder handshake parser with deterministic
    // (fixed-seed) malformed inputs — every one must be a clean Err, never a
    // panic / hang / over-allocation. Catches remote-triggerable DoS in the LP /
    // length parsing (this project has a peer-id-extraction panic in its history).
    #[tokio::test]
    async fn handshake_parser_fuzz_no_panic() {
        // SplitMix64-style PRNG, fixed seed → CI-reproducible.
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        };
        for i in 0..200u32 {
            // Mix in some structurally-valid prefixes so the fuzzer reaches deeper
            // parser states, not just the first length check.
            let mut bytes = if i % 3 == 0 { kx6_valid_len_prefix() } else { Vec::new() };
            let n = (next() % 2048) as usize;
            bytes.extend((0..n).map(|_| (next() >> 33) as u8));
            // The only assertion is implicit: kx6_drive_raw_to_server must return
            // (Ok/Err) without panicking or hanging. A valid handshake is
            // impossible from these bytes (no valid signatures), so it always Errs.
            let _ = kx6_drive_raw_to_server(bytes).await;
        }
    }

    // §8 item 11: the #12 responder static ML-KEM ek is OPTIONAL — the length
    // check is three-way: empty → skipped (caller's `!is_empty()` guard),
    // fixed-len → passes, intermediate (non-empty wrong) → Err. Pins the branch
    // that keeps a stripped/short #12 from being length-confused.
    #[test]
    fn optional_static_kem_length_three_way() {
        let ek = backend::mlkem_ek_len("ML-KEM-768");
        // fixed length → Ok.
        assert!(ensure_field_len("#12", ek.unwrap(), ek).is_ok());
        // intermediate (non-empty, wrong length) → Err (never panic).
        assert!(ensure_field_len("#12", ek.unwrap() - 1, ek).is_err());
        assert!(ensure_field_len("#12", 1, ek).is_err());
        // empty is handled by the caller's `!is_empty()` guard before this check
        // runs — the length gate is only applied to a non-empty #12 (processor.rs
        // ~1047). enc-pin closes the empty case separately (SHA3(empty) ≠ fp).
    }

    // §8 item 9 / §10(D): ephemeral freshness. The handshake generates a fresh
    // P-256 (and ML-KEM) ephemeral each run — there is no cache/persist field —
    // so two handshakes derive different transcripts and keys (replay/KCI
    // resistance). Pin the underlying property: back-to-back ephemeral keygens
    // never repeat.
    #[test]
    fn ephemeral_keys_are_fresh_each_time() {
        let (_, p1) = backend::generate_ecc_key_pair("prime256v1").unwrap();
        let (_, p2) = backend::generate_ecc_key_pair("prime256v1").unwrap();
        assert_ne!(p1, p2, "ephemeral P-256 pubkeys must be fresh (no cache/persist)");
    }

    // §7(A) flag-day, ctx side. The handshake signs/verifies under a NON-EMPTY
    // native ctx (this value); the empty-ctx (`ctx=""`) handshake path of the
    // pre-flag-day wire was removed in increment 3. This pins the ctx label —
    // paired with the ALPN version guard in `network::mod` (both move together on
    // any future handshake-wire change).
    #[test]
    fn handshake_ctx_is_the_flag_day_label() {
        assert_eq!(HANDSHAKE_CTX_IROH, b"nkct-handshake-iroh-v1");
        assert!(!HANDSHAKE_CTX_IROH.is_empty(), "handshake ctx must never be empty again");
    }

    // §7(A) flag-day, security essence: a signature an OLD (pre-flag-day) peer
    // produced over the handshake transcript with `ctx=""` MUST NOT verify under
    // the post-flag-day verifier (native ctx). This is what makes the ALPN bump a
    // true cutover rather than cosmetic — even if an old signature reached a new
    // verifier, the ctx domain separation rejects it. Faithful (real ML-DSA
    // sign/verify), no ALPN-negotiation mock needed.
    #[test]
    fn pre_flag_day_empty_ctx_handshake_sig_is_rejected() {
        let algo = "ML-DSA-65";
        let (sk, pk, _) = backend::pqc_keygen_dsa(algo).unwrap();
        let transcript = b"a canonical handshake transcript snapshot";
        // Old peer: signs the transcript with the pre-flag-day empty ctx.
        let old_sig = backend::pqc_sign(algo, &sk, transcript, b"").unwrap();
        // New verifier: checks under the native handshake ctx → must reject.
        assert!(
            !backend::pqc_verify(algo, &pk, transcript, &old_sig, HANDSHAKE_CTX_IROH).unwrap(),
            "a ctx=\"\" (old wire) handshake signature must not verify post-flag-day",
        );
        // Sanity: it does verify under the empty ctx it was made with (proving the
        // rejection above is the ctx domain, not a broken signature).
        assert!(backend::pqc_verify(algo, &pk, transcript, &old_sig, b"").unwrap());
    }
}
