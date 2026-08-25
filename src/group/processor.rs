//! MLS group chat processor.
//!
//! P1 introduced the `GroupChatProcessor` shell on the hybrid passthrough
//! provider; P1.5.a/b made the cipher suite real PQC (hybrid signature +
//! hybrid KEM); P2 added sqlite persistence; P3 (this revision) wires up
//! the public KeyPackage / add_member / join surface that the higher-
//! level CLI and GUI will eventually call.
//!
//! The processor owns:
//! - an mls-rs `Client` configured with our [`HybridCryptoProvider`] and
//!   the sqlite-backed group / key-package / PSK storage triple,
//! - the [`GroupStorage`] handle itself (kept alive so we can run our
//!   own `list_group_ids` queries against the same database), and
//! - a `P2pEndpoint` reserved for P4 transport routing.
//!
//! `create_group` persists the freshly created group via `write_to_storage`.
//! `list_groups` / `load_group_summary` provide the read path.
//! P3 adds three byte-oriented helpers that bridge mls-rs's `MlsMessage`
//! to flat byte buffers suitable for transport (P4) or sneakernet:
//!
//! - [`export_key_package`] — produce a publishable `KeyPackage` blob.
//! - [`add_member`] — admit a peer whose `KeyPackage` blob you have.
//! - [`join_group_from_welcome`] — accept an inbound `Welcome` blob.
//!
//! Wire framing (which is what P4 sits on top of) is **not** in this
//! module — the byte slices returned/accepted here are raw MLS
//! TLS-presentation messages. P4's `transport.rs` adds the u32-length-
//! prefix framing for `nkct/mls/1`.
//!
//! [`export_key_package`]: GroupChatProcessor::export_key_package
//! [`add_member`]: GroupChatProcessor::add_member
//! [`join_group_from_welcome`]: GroupChatProcessor::join_group_from_welcome

use std::sync::Arc;

use mls_rs::client_builder::{
    BaseConfig, PaddingMode, WithCryptoProvider, WithGroupStateStorage, WithIdentityProvider,
    WithKeyPackageRepo, WithMlsRules, WithPskStore,
};
use mls_rs::identity::SigningIdentity;
use mls_rs::identity::basic::BasicCredential;
use mls_rs::mls_rules::{DefaultMlsRules, EncryptionOptions};
use mls_rs::{Client, ExtensionList, MlsMessage, WireFormat};
use mls_rs_core::crypto::{CipherSuiteProvider, CryptoProvider};
use zeroize::Zeroizing;

use crate::group::crypto_adapter::{hybrid_cipher_suite, HybridCryptoProvider};
use crate::group::redb_storage::{
    RedbGroupStateStorage, RedbKeyPackageStorage, RedbPreSharedKeyStorage,
};
use crate::group::storage::GroupStorage;
use crate::group::types::{
    AddMemberOutput, GroupError, GroupId, GroupSummary, IncomingGroupEvent, MemberInfo,
};
use crate::p2p::{P2pEndpoint, PeerAddr, PeerId};

/// MLS-RS `Config` shape after stacking our storage providers and
/// crypto/identity providers on top of the base config.
///
/// Order matches the call chain in [`GroupChatProcessor::new`]:
/// `.group_state_storage(..).key_package_repo(..).psk_store(..).crypto_provider(..).identity_provider(..).mls_rules(..)`,
/// which composes outermost-first as `WithMlsRules<.., WithIdentityProvider<.., WithCryptoProvider<.., WithPskStore<.., WithKeyPackageRepo<.., WithGroupStateStorage<.., BaseConfig>>>>>>`.
type MlsConfig = WithMlsRules<
    DefaultMlsRules,
    WithIdentityProvider<
        GroupIdentityProvider,
        WithCryptoProvider<
            HybridCryptoProvider,
            WithPskStore<
                RedbPreSharedKeyStorage,
                WithKeyPackageRepo<
                    RedbKeyPackageStorage,
                    WithGroupStateStorage<RedbGroupStateStorage, BaseConfig>,
                >,
            >,
        >,
    >,
>;

/// MlsRules installed on every `Client` this module builds.
///
/// The only deviation from `DefaultMlsRules::new()` is
/// `encrypt_control_messages = true`, which makes a member-sent Commit or
/// standalone Proposal a `WireFormat::PrivateMessage` (AEAD-sealed under the
/// epoch key schedule) instead of the signed-but-readable
/// `WireFormat::PublicMessage` mls-rs emits by default. That matters because
/// those frames are deposited at the store-and-forward relay whenever a direct
/// send fails (`send_one_with_inbox`), and an Add's inline KeyPackage carries
/// the joiner's NKCB credential — iroh NodeId, ML-DSA-65 transport public key,
/// display name — which is what `projected_member_fingerprints` turns into
/// shell and port-forward policy.
///
/// The scope is exactly `Sender::Member`: `control_wire_format` returns
/// `PrivateMessage` for `Sender::Member(_)` and `PublicMessage` for every
/// other sender, so this covers a Commit or Proposal built by a member of the
/// group. That is all this module ever builds — every commit path here goes
/// through `Group::commit_builder()` on a loaded group, and there is no
/// external-commit or `ExternalClient` path in this crate. A future one would
/// not be covered by this setting.
///
/// Everything else is left at its default on purpose:
/// - `commit_options` is `CommitOptions::default()`, byte-for-byte what
///   `ClientBuilder::new()` already installs, so commit construction is
///   unchanged (notably `path_required = false`).
/// - `PaddingMode::StepFunction` is `PaddingMode`'s own `#[default]`, so it is
///   the mode already in force for every application message this project
///   sends. It is spelled out here only because of how the struct is built:
///   `EncryptionOptions` is `#[non_exhaustive]`, which bars a struct literal
///   (and `..Default::default()`) from outside mls-rs, so setting the flag in
///   one expression goes through `new(encrypt_control_messages, padding_mode)`
///   — which takes the mode positionally. `Default::default()` is public too,
///   but what it yields is the flag `false`, which is the thing being changed.
///   Naming the mode already in force keeps this a single-variable change.
///
/// This is **not** a flag day. `EncryptionOptions` is read from three
/// send-side call sites in mls-rs 0.55.2 and from nothing on the receive path
/// — `message_processor.rs` contains no `WireFormat` comparison at all — so a
/// peer built before this change still applies our Commits, and we still apply
/// theirs. See [`GroupChatProcessor::broadcast_commit`].
fn mls_rules() -> DefaultMlsRules {
    DefaultMlsRules::new().with_encryption_options(EncryptionOptions::new(
        true,
        PaddingMode::StepFunction,
    ))
}

#[derive(Clone, Debug)]
pub struct GroupIdentityProvider {
    crypto: HybridCryptoProvider,
}

#[derive(Debug, thiserror::Error)]
pub enum GroupIdentityProviderError {
    #[error("unsupported credential type: {0:?}")]
    UnsupportedCredential(mls_rs::identity::CredentialType),
    #[error("invalid MLS-transport binding: {0}")]
    InvalidBinding(String),
}

impl mls_rs::error::IntoAnyError for GroupIdentityProviderError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(self.into())
    }
}

/// Parse the `NKCB` binding embedded in a BasicCredential identifier:
/// `b"NKCB" ‖ peer_id(32) ‖ lp32(transport_pub) ‖ lp32(mls_sig) ‖ lp32(transport_sig) ‖ display_name`
/// where `lp32(x) = (len(x) as u32 BE) ‖ x`. Returns `None` for a non-NKCB or
/// malformed identifier. Bounds are checked via slice splitting (never
/// `offset + len`), so a huge length field cannot overflow `usize` on 32-bit
/// targets (an earlier in-place parser could panic there).
fn parse_nkcb_binding(
    id: &[u8],
) -> Option<([u8; 32], Vec<u8>, crate::group::binding::MemberBinding)> {
    let rest = id.strip_prefix(b"NKCB".as_slice())?;
    if rest.len() < 32 {
        return None;
    }
    let mut peer_id = [0u8; 32];
    peer_id.copy_from_slice(&rest[..32]);
    let mut cur = &rest[32..];

    // Read one u32-length-prefixed field; advance the cursor. Overflow-safe:
    // the length is only ever *compared* against the remaining slice length.
    fn take_lp<'a>(cur: &mut &'a [u8]) -> Option<&'a [u8]> {
        let len = u32::from_be_bytes(cur.get(..4)?.try_into().unwrap()) as usize;
        let body = &cur[4..];
        if body.len() < len {
            return None;
        }
        let (field, after) = body.split_at(len);
        *cur = after;
        Some(field)
    }

    let transport_pub = take_lp(&mut cur)?.to_vec();
    let mls_sig = take_lp(&mut cur)?.to_vec();
    let transport_sig = take_lp(&mut cur)?.to_vec();
    Some((
        peer_id,
        transport_pub,
        crate::group::binding::MemberBinding {
            mls_sig,
            transport_sig,
        },
    ))
}

impl GroupIdentityProvider {
    fn verify_credential_binding(
        &self,
        signing_identity: &SigningIdentity,
    ) -> Result<(), GroupIdentityProviderError> {
        let basic = signing_identity
            .credential
            .as_basic()
            .ok_or_else(|| GroupIdentityProviderError::UnsupportedCredential(signing_identity.credential.credential_type()))?;

        // Every MLS member MUST carry a valid NKCB transport binding. Reject a
        // missing/malformed binding at join so no member exists without an
        // authenticated transport identity (closes the non-NKCB bypass that
        // would otherwise let an attacker join with a self-asserted PeerId).
        let (peer_id_bytes, transport_dsa_pub, binding) = parse_nkcb_binding(&basic.identifier)
            .ok_or_else(|| {
                GroupIdentityProviderError::InvalidBinding(
                    "missing or malformed NKCB transport binding".to_string(),
                )
            })?;

        let provider = self
            .crypto
            .cipher_suite_provider(hybrid_cipher_suite())
            .ok_or_else(|| {
                GroupIdentityProviderError::InvalidBinding("unsupported cipher suite".to_string())
            })?;

        if !crate::group::binding::verify_binding(
            &provider,
            &signing_identity.signature_key,
            "ML-DSA-65",
            &transport_dsa_pub,
            0, // identity-level binding
            &peer_id_bytes,
            &binding,
        ) {
            return Err(GroupIdentityProviderError::InvalidBinding(
                "cryptographic verification failed".to_string(),
            ));
        }
        Ok(())
    }
}

impl mls_rs_core::identity::IdentityProvider for GroupIdentityProvider {
    type Error = GroupIdentityProviderError;

    fn validate_member(
        &self,
        signing_identity: &SigningIdentity,
        _timestamp: Option<mls_rs::time::MlsTime>,
        _context: mls_rs_core::identity::MemberValidationContext<'_>,
    ) -> Result<(), Self::Error> {
        self.verify_credential_binding(signing_identity)
    }

    fn validate_external_sender(
        &self,
        signing_identity: &SigningIdentity,
        _timestamp: Option<mls_rs::time::MlsTime>,
        _extensions: Option<&ExtensionList>,
    ) -> Result<(), Self::Error> {
        self.verify_credential_binding(signing_identity)
    }

    fn identity(
        &self,
        signing_identity: &SigningIdentity,
        _extensions: &ExtensionList,
    ) -> Result<Vec<u8>, Self::Error> {
        let basic = signing_identity
            .credential
            .as_basic()
            .ok_or_else(|| GroupIdentityProviderError::UnsupportedCredential(signing_identity.credential.credential_type()))?;
        Ok(basic.identifier.to_vec())
    }

    fn valid_successor(
        &self,
        predecessor: &SigningIdentity,
        successor: &SigningIdentity,
        _extensions: &ExtensionList,
    ) -> Result<bool, Self::Error> {
        let p = predecessor.credential.as_basic().ok_or_else(|| GroupIdentityProviderError::UnsupportedCredential(predecessor.credential.credential_type()))?;
        let s = successor.credential.as_basic().ok_or_else(|| GroupIdentityProviderError::UnsupportedCredential(successor.credential.credential_type()))?;
        Ok(p == s)
    }

    fn supported_types(&self) -> Vec<mls_rs::identity::CredentialType> {
        vec![mls_rs::identity::CredentialType::BASIC]
    }
}

type MlsClient = Client<MlsConfig>;

/// Transport-agnostic MLS group chat orchestrator.
///
/// Holds an mls-rs `Client` (which in turn holds the signing identity,
/// crypto provider, identity provider, and storage providers) plus the
/// `P2pEndpoint` used to deliver Welcome / Commit / Application messages
/// (wired in P3+).
pub struct GroupChatProcessor {
    pub(crate) client: MlsClient,
    storage: GroupStorage,
    /// Transport used to send Welcomes (and, in P5+, Commits and
    /// Application messages). Wrapped in `Arc<dyn>` so the processor
    /// owns it but the same endpoint can be shared with other
    /// subsystems (e.g. the 1:1 chat) if a single iroh endpoint serves
    /// multiple ALPNs.
    endpoint: Arc<dyn P2pEndpoint>,
    /// Optional `nkct/inbox/1` store-and-forward server. When set,
    /// every outbound send_one tries the direct path first and falls
    /// back to depositing into the inbox if direct fails (peer offline
    /// / unreachable). When `None`, behaviour matches the original
    /// direct-only path.
    inbox: Option<PeerAddr>,
    /// Per-group serialization of the `load → mutate → write` cycle.
    ///
    /// `listen`/`chat-group` share one `Arc<GroupChatProcessor>` across an
    /// inbound `accept_next` task, an optional inbox-poll task and the stdin
    /// REPL, all on the multi-threaded runtime. Each of those reloads the group
    /// from storage, mutates it and writes it back; interleave two and the
    /// later writer persists a snapshot built from a state it read *before* the
    /// earlier one landed, silently discarding it. When the discarded change is
    /// a Commit that removed a member, the member is back on the roster and the
    /// old epoch secrets stay live.
    ///
    /// Keyed by group id so unrelated groups still proceed in parallel. The map
    /// holds `Weak` references, so an entry costs nothing once no task holds
    /// that group's lock and is reclaimed on the next acquisition — the table
    /// cannot grow without bound across a long-running session.
    group_locks: std::sync::Mutex<
        std::collections::HashMap<Vec<u8>, std::sync::Weak<tokio::sync::Mutex<()>>>,
    >,
}

/// What one SYNC exchange did to **our own** state
/// ([`GroupChatProcessor::request_resync`]).
///
/// Both fields record what *this* node did — they are set only after mls-rs
/// verified a Commit against our own group state and `write_to_storage`
/// persisted it. Nothing in the SYNC exchange authenticates the responder, so
/// these are the only two things a caller may build a statement out of; what the
/// peer said about itself is not among them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResyncOutcome {
    /// At least one Commit from this peer's stream was verified and written.
    ///
    /// **Not the same as "our epoch moved."** A Commit that removes *us* is
    /// verified and persisted like any other, but mls-rs does not advance the
    /// locally persisted epoch for it, so this can be `true` while
    /// [`load_group_summary`](GroupChatProcessor::load_group_summary) reports
    /// the epoch unchanged. A caller that wants to say the sweep made progress
    /// has to read its own epoch rather than trust this flag.
    pub applied: bool,
    /// One of those Commits was a Remove of **us**, verified against our own
    /// state.
    ///
    /// **This is a fact about the responder, not about our membership**, and a
    /// caller must render it as one. mls-rs verifying the Commit establishes
    /// that its signer held this group's state at the epoch we are at — and a
    /// member the group evicted at some *later* epoch, one we have not applied,
    /// still holds exactly that, so it can sign a Remove of us that verifies
    /// here while every honest member's roster still lists us. It establishes
    /// less than on any other Commit, at that: mls-rs 0.55.2 gates
    /// `update_key_schedule` on `!is_self_removed` and recomputes the
    /// confirmation tag only inside it, so on this one the tag must be present
    /// but is never checked against the transcript.
    ///
    /// Applying **this Commit** changes nothing here: mls-rs skips
    /// `update_key_schedule` for a self-removal and drops the provisional state,
    /// so it leaves our epoch, tree and roster as it found them and a later
    /// honest delta applies normally. That says nothing about the rest of the
    /// stream — every Commit ahead of this one was applied and persisted before
    /// the loop broke — so a caller reporting what a peer did to us must read
    /// its own epoch rather than infer "nothing happened" from this flag.
    ///
    /// What it *is* good for is weighing the peer that sent it. A responder
    /// streams history only to a caller its **current** roster lists (see the
    /// membership check in `accept_next`, which answers `ERR\x01` otherwise), so
    /// a node whose roster reflected this Commit — i.e. no longer lists us —
    /// would have refused instead of streaming. That is not the same as "it
    /// never applied this Commit": a responder that removed us and re-admitted
    /// us later lists us again, and one that does not clamp what it serves to
    /// our own admission — a peer on a build older than `sync_history_floor`,
    /// where an unrecorded join epoch served history unclamped — hands us the
    /// old Remove out of its retained history while behaving honestly.
    pub removed_us: bool,
}

/// The **exclusive** lower bound of the commit span a SYNC responder may stream
/// to a requester: everything above it is the requester's to have, everything at
/// or below it is not.
///
/// Three inputs, only one of which the requester supplies:
/// - `claimed_epoch` — 8 bytes the requester chose. It can only ever raise the
///   floor ("I already have up to here"), never lower it.
/// - `requester_join_epoch` — the epoch at which *we* witnessed its Add, if we
///   did. This is the authorization: history from before a member's own
///   admission is not history it is entitled to, however low it claims.
/// - `group_history_floor` — the exclusive bound of the span in which our join
///   records are complete (see [`GroupStorage::history_floor`]).
///
/// The `None` cases are where this earns its keep. An unrecorded requester is
/// not an entitled one: it may be a member that predates the record, a member
/// already on the roster when we joined, or a member whose record we failed to
/// write, and the answer cannot depend on telling those apart. Above the group
/// floor our records are complete, so an unrecorded member demonstrably did not
/// join there and that span is safe to serve; with no floor at all we can
/// demonstrate nothing and return `local_epoch`, which yields an empty delta.
///
/// Every path is monotone in the direction of disclosing less, and nothing the
/// requester sends can lower the result below what we recorded ourselves.
fn sync_history_floor(
    claimed_epoch: u64,
    local_epoch: u64,
    requester_join_epoch: Option<u64>,
    group_history_floor: Option<u64>,
) -> u64 {
    match (requester_join_epoch, group_history_floor) {
        // We watched them join: their own admission is the floor.
        (Some(joined), _) => claimed_epoch.max(joined),
        // We did not, but we can vouch for the span above the floor.
        (None, Some(floor)) => claimed_epoch.max(floor),
        // We can vouch for nothing. Serve nothing.
        (None, None) => local_epoch,
    }
}

impl GroupChatProcessor {
    /// Acquire the per-group lock, creating it if this is the first waiter.
    ///
    /// The returned guard must be held across the whole `load → mutate →
    /// write` sequence — releasing it after the load defeats the point.
    async fn lock_group(&self, group_id: &[u8]) -> tokio::sync::OwnedMutexGuard<()> {
        // The strong reference is kept alive across the await below; the table
        // holds only a `Weak`, so dropping it here would let a second caller
        // mint a *different* mutex for the same group and defeat the exclusion.
        let lock = self.group_lock_arc(group_id);
        lock.lock_owned().await
    }

    /// The `Arc<Mutex>` for `group_id`, creating it on first use.
    ///
    /// Split out from [`lock_group`](Self::lock_group) so the table's own
    /// (synchronous) lock is released before anyone awaits the group lock —
    /// awaiting while holding it would serialize every group behind one.
    fn group_lock_arc(&self, group_id: &[u8]) -> Arc<tokio::sync::Mutex<()>> {
        let mut map = self
            .group_locks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Reclaim entries whose lock nobody holds any more. Done here rather
        // than on release so it costs one pass per acquisition and needs no
        // drop guard.
        map.retain(|_, weak| weak.strong_count() > 0);
        match map.get(group_id).and_then(|w| w.upgrade()) {
            Some(existing) => existing,
            None => {
                let fresh = Arc::new(tokio::sync::Mutex::new(()));
                map.insert(group_id.to_vec(), Arc::downgrade(&fresh));
                fresh
            }
        }
    }

    /// Build a processor backed by `storage`. The signing identity is
    /// **loaded from the sqlite db** when present, otherwise generated
    /// fresh and stored — so multiple invocations against the same db
    /// (e.g. an `export-key-package` one-shot followed by a `listen`
    /// long-running process) share the same MLS identity.
    ///
    /// `display_name` is stored in the MLS `BasicCredential` for UX
    /// only — it is not a security boundary; recipients verify by
    /// fingerprint of the hybrid public key.
    ///
    /// `endpoint` is the transport the processor will use for Welcome
    /// and message delivery.
    ///
    /// `storage` owns the sqlite file. Multiple processors must not
    /// write to the same db concurrently from multiple machines; on a
    /// single machine, sqlite WAL + `busy_timeout = 5 s` absorbs the
    /// short contention windows that arise from a sibling one-shot
    /// process opening the db while a `listen` holds it.
    ///
    /// ## Signing-key persistence
    ///
    /// Keys are stored in `mls-rs-provider-sqlite`'s application_data
    /// kvs table under `mls:identity:sk` (private) and
    /// `mls:identity:pk` (public). The whole sqlite file is
    /// SQLCipher 4 encrypted (AES-256-CBC + HMAC-SHA512, PBKDF2-HMAC-
    /// SHA512 256 000 iters) using the passphrase supplied to
    /// [`GroupStorage::open_at`]. File mode `0o600` is retained as
    /// defence in depth. See `SECURITY_PROFILE.md` §7.3.
    pub fn new(
        display_name: &str,
        endpoint: Arc<dyn P2pEndpoint>,
        storage: GroupStorage,
        transport_dsa_priv: Option<zeroize::Zeroizing<Vec<u8>>>,
    ) -> Result<Self, GroupError> {
        let crypto = HybridCryptoProvider::new();
        let suite_id = hybrid_cipher_suite();
        let suite = crypto.cipher_suite_provider(suite_id).ok_or_else(|| {
            GroupError::Backend(
                "hybrid cipher suite (0xF101) construction failed; \
                 is OpenSSL configured with X25519 + SHA-256 + AES-128-GCM?"
                    .to_string(),
            )
        })?;

        // Load existing identity from the application_data table, or
        // generate + store one on first use.
        const IDENTITY_SK_KEY: &str = "mls:identity:sk";
        const IDENTITY_PK_KEY: &str = "mls:identity:pk";
        let app = storage.application_data_storage()?;
        let (signing_key, signing_pub) = match (
            app.get(IDENTITY_SK_KEY)
                .map_err(|e| GroupError::Storage(format!("read identity sk: {e}")))?,
            app.get(IDENTITY_PK_KEY)
                .map_err(|e| GroupError::Storage(format!("read identity pk: {e}")))?,
        ) {
            (Some(sk), Some(pk)) => {
                use mls_rs_core::crypto::{SignaturePublicKey, SignatureSecretKey};
                // `sk`/`pk` come back as `Zeroizing<Vec<u8>>` (audit L3). The
                // `sk.to_vec()` copy is moved straight into `SignatureSecretKey`,
                // which derives `ZeroizeOnDrop` (mls-rs-core), so the secret ends
                // up in a self-zeroizing container — there is no lingering
                // un-zeroized copy — and the transient `Zeroizing` `sk` wipes on
                // drop. (`pk` is public; zeroizing it is harmless.)
                (
                    SignatureSecretKey::new(sk.to_vec()),
                    SignaturePublicKey::new(pk.to_vec()),
                )
            }
            _ => {
                let (sk, pk) = suite
                    .signature_key_generate()
                    .map_err(|e| GroupError::Backend(format!("sig keygen: {e}")))?;
                app.insert(IDENTITY_SK_KEY, sk.as_bytes())
                    .map_err(|e| GroupError::Storage(format!("write identity sk: {e}")))?;
                app.insert(IDENTITY_PK_KEY, pk.as_bytes())
                    .map_err(|e| GroupError::Storage(format!("write identity pk: {e}")))?;
                (sk, pk)
            }
        };

        // Load or generate transport ML-DSA-65 private key for the binding.
        // Keep it in Zeroizing so the raw secret is wiped on drop (a plain Vec
        // would linger in freed heap memory).
        let transport_priv_key: zeroize::Zeroizing<Vec<u8>> = match transport_dsa_priv {
            Some(priv_key) => priv_key,
            None => {
                // `priv_key` is already `Zeroizing<Vec<u8>>`; move it (no
                // `.to_vec()` copy that would leave an un-wiped plain Vec).
                let (priv_key, _, _) = crate::backend::pqc_keygen_dsa("ML-DSA-65")
                    .map_err(|e| GroupError::Backend(format!("generate ephemeral transport key: {e}")))?;
                priv_key
            }
        };
        let transport_pub_key = crate::backend::pqc_pub_from_priv_dsa("ML-DSA-65", &transport_priv_key)
            .map_err(|e| GroupError::Backend(format!("unwrap pqc public key: {e}")))?;

        // Create the MemberBinding
        let b = crate::group::binding::create_binding(
            &suite,
            &signing_key,
            &signing_pub,
            "ML-DSA-65",
            &transport_priv_key,
            &transport_pub_key,
            0, // identity-level binding (epoch = 0)
            endpoint.local_id().as_bytes(),
        ).map_err(|e| GroupError::Backend(format!("create binding: {e:?}")))?;

        // Serialize it in credential_bytes:
        // MAGIC (4 bytes) || PeerId (32 bytes) || pub_key_len (u32) || pub_key || mls_sig_len (u32) || mls_sig || transport_sig_len (u32) || transport_sig || display_name
        let mut credential_bytes = Vec::new();
        credential_bytes.extend_from_slice(b"NKCB");
        credential_bytes.extend_from_slice(endpoint.local_id().as_bytes());
        credential_bytes.extend_from_slice(&(transport_pub_key.len() as u32).to_be_bytes());
        credential_bytes.extend_from_slice(&transport_pub_key);
        credential_bytes.extend_from_slice(&(b.mls_sig.len() as u32).to_be_bytes());
        credential_bytes.extend_from_slice(&b.mls_sig);
        credential_bytes.extend_from_slice(&(b.transport_sig.len() as u32).to_be_bytes());
        credential_bytes.extend_from_slice(&b.transport_sig);
        credential_bytes.extend_from_slice(display_name.as_bytes());

        let credential = BasicCredential::new(credential_bytes);
        let identity = SigningIdentity::new(credential.into_credential(), signing_pub);

        // The three storage components are fetched once each — each
        // call opens an independent connection backed by the same
        // file, so concurrent reads/writes are coordinated by sqlite's
        // own busy_timeout (configured in TunedFileStrategy).
        let group_state_storage = storage.group_state_storage()?;
        let key_package_storage = storage.key_package_storage()?;
        let psk_storage = storage.pre_shared_key_storage()?;

        let client = Client::builder()
            .group_state_storage(group_state_storage)
            .key_package_repo(key_package_storage)
            .psk_store(psk_storage)
            .crypto_provider(crypto.clone())
            .identity_provider(GroupIdentityProvider { crypto })
            .mls_rules(mls_rules())
            .signing_identity(identity, signing_key, suite_id)
            .build();

        Ok(Self {
            client,
            storage,
            endpoint,
            inbox: None,
            group_locks: std::sync::Mutex::new(std::collections::HashMap::new()),
        })
    }

    /// Configure (or remove) the inbox store-and-forward server. When
    /// set, an outbound send falls back to `inbox::deposit` if the
    /// direct connect fails — providing offline-capable delivery via an
    /// untrusted relay.
    ///
    /// "Untrusted" is a statement about what the relay is *given*, not a
    /// promise about its behaviour: the operator holds the bytes and can
    /// read whatever is not encrypted. Application messages
    /// (`PrivateMessage`) and a `Welcome`'s GroupSecrets are encrypted,
    /// so it learns only their size and timing. Commits and Proposals that
    /// *we* emit are encrypted too — [`mls_rules`] sets
    /// `encrypt_control_messages`, so they are `PrivateMessage` under the
    /// epoch key schedule, which no relay holds. What the operator still
    /// sees for every frame is the recipient's node id, the size and the
    /// timing, which is enough to chart who talks to whom and when a group
    /// is busy.
    ///
    /// One caveat that deployment cannot remove: the wire format is chosen
    /// by whoever *builds* the Commit, and this setting is only ours. Every
    /// frame deposited from here is one this node built itself
    /// (`send_welcome_to`, `broadcast_commit`, `send_application_message`);
    /// nothing here forwards a frame received from a peer, and the inbox
    /// server stores rather than relays. What we cannot reach is the other
    /// direction: a peer still running a build without
    /// `encrypt_control_messages` deposits its own Commits in the clear, at
    /// whatever inbox *it* was pointed at, so a group's control traffic is
    /// only as private as its least-upgraded committer. See
    /// `KNOWN_ISSUES.md` "Security Audit Residuals" item 11 — including why
    /// refusing to deposit a control frame is *not* the answer.
    ///
    /// [`mls_rules`]: fn@mls_rules
    pub fn set_inbox(&mut self, inbox: Option<PeerAddr>) {
        self.inbox = inbox;
    }

    /// Currently configured inbox server address, if any.
    pub fn inbox(&self) -> Option<&PeerAddr> {
        self.inbox.as_ref()
    }

    /// Borrow the underlying P2P endpoint. Used by background tasks
    /// (e.g. the listen-loop's inbox poller) that need to call
    /// transport-level helpers directly.
    pub fn endpoint_ref(&self) -> &dyn P2pEndpoint {
        self.endpoint.as_ref()
    }

    /// Create a fresh single-member group and persist it.
    ///
    /// Returns the freshly generated `GroupId`. After this call, the
    /// group is durably stored — a subsequent process restart (with a
    /// new processor against the same `GroupStorage` path) will see
    /// the group via [`list_groups`](Self::list_groups) and be able to
    /// reload its state via [`load_group_summary`](Self::load_group_summary).
    ///
    /// Method is `async` so future revisions can add transport calls
    /// (Welcome dispatch via `self.endpoint.connect`) without churning
    /// call sites.
    pub async fn create_group(&self) -> Result<GroupId, GroupError> {
        let mut group = self
            .client
            .create_group(ExtensionList::default(), Default::default(), None)
            .map_err(|e| GroupError::Backend(format!("create_group: {e}")))?;

        // Persist before extracting the id — if write fails, the
        // caller doesn't get back a `GroupId` for a group that
        // wasn't actually saved.
        group
            .write_to_storage()
            .map_err(|e| GroupError::Storage(format!("write_to_storage: {e}")))?;

        let id_bytes = group.group_id().to_vec();
        // MLS group_id is variable-length per RFC 9420; mls-rs defaults
        // to 32 bytes for newly created groups. We assert that to keep
        // the public `GroupId` shape stable for callers.
        if id_bytes.len() != 32 {
            return Err(GroupError::Backend(format!(
                "unexpected group_id length: {} (expected 32)",
                id_bytes.len()
            )));
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&id_bytes);

        // Drop the in-memory Group; its keys are zeroized via mls-rs's
        // ZeroizeOnDrop. The state lives on in sqlite for later reload.
        drop(group);

        // Anchor for grep'ability: persistence-related secret material
        // is auto-zeroed both in mls-rs (ZeroizeOnDrop) and in our own
        // `Zeroizing` wrappers around HPKE / KDF outputs.
        let _intent_anchor: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());

        Ok(GroupId::new(id))
    }

    /// Return the IDs of all groups stored in the underlying database.
    ///
    /// Cheap — a single sqlite `SELECT` against the `mls_group` table.
    /// Synchronous; mls-rs's `Client::load_group` is the async path
    /// (it uses the same storage but goes through MLS state decoding).
    pub fn list_groups(&self) -> Result<Vec<GroupId>, GroupError> {
        self.storage.list_group_ids()
    }

    /// Generate a fresh `KeyPackage` and return its wire-format bytes.
    ///
    /// A `KeyPackage` is a self-contained advertisement of "here is an
    /// MLS identity you can add to a group". Each call generates a
    /// **fresh init key** and stores the private half in the local key-
    /// package storage (via `SqLiteKeyPackageStorage`); the returned
    /// bytes are safe to publish, hand-carry, or embed in a ticket.
    ///
    /// Per RFC 9420 §10.1, each KeyPackage MUST be used at most once
    /// (otherwise forward-secrecy of the join is broken). mls-rs deletes
    /// the corresponding private key from storage when the KeyPackage
    /// is consumed by `join_group`, so a second join attempt on the
    /// same bytes will fail — by design.
    ///
    /// The returned bytes are wrapped in `Zeroizing` even though they
    /// are public. The private key half lives in the SQLCipher-encrypted
    /// sqlite file (with `0o600` as defence in depth); the returned blob
    /// is harmless to leak.
    /// The wrapper is for caller convenience — e.g. when piping into
    /// a file, the bytes get cleared from a transient buffer before
    /// the next allocation reuses the pages.
    pub async fn export_key_package(
        &self,
    ) -> Result<Zeroizing<Vec<u8>>, GroupError> {
        let msg = self
            .client
            .generate_key_package_message(
                ExtensionList::default(),
                ExtensionList::default(),
                None,
            )
            .map_err(|e| GroupError::Backend(format!("generate_key_package: {e}")))?;
        let bytes = msg
            .to_bytes()
            .map_err(|e| GroupError::Backend(format!("KeyPackage encode: {e}")))?;
        Ok(Zeroizing::new(bytes))
    }

    /// Add a member to an existing group and return both the `Welcome`
    /// (for the new joiner) and the `Commit` (for existing members).
    ///
    /// `gid` identifies a group this processor already owns (per
    /// [`list_groups`](Self::list_groups)). `key_package_bytes` is a
    /// peer's `KeyPackage` blob (typically produced by their
    /// [`export_key_package`]).
    ///
    /// On success, the group state on this side has advanced by one
    /// epoch (the Add commit is applied and persisted). The returned
    /// [`AddMemberOutput`] carries:
    ///
    /// - `welcome` — pass to the new joiner via
    ///   [`send_welcome_to`](Self::send_welcome_to). They then call
    ///   [`join_group_from_welcome`] (or react to a
    ///   [`IncomingGroupEvent::NewGroup`](crate::group::IncomingGroupEvent)
    ///   from [`accept_next`](Self::accept_next)).
    /// - `commit` — broadcast to every *existing* member except the
    ///   new joiner via [`broadcast_commit`](Self::broadcast_commit).
    ///   For the 2-member-after case (group of 1 → 2) there are no
    ///   existing members and the commit is effectively a no-op, but
    ///   it is still produced so the field is meaningful for callers.
    ///
    /// Failure modes:
    /// - `GroupError::NotFound` — `gid` is not present in storage.
    /// - `GroupError::InvalidWelcome` — `key_package_bytes` is malformed
    ///   or not a `KeyPackage` (the variant is named for the join-side
    ///   counterpart but covers any "bad MLS blob" from the caller).
    /// - `GroupError::Backend(_)` — mls-rs rejected the proposal or
    ///   commit, e.g. because the KeyPackage uses a different cipher
    ///   suite or has expired.
    ///
    /// [`export_key_package`]: Self::export_key_package
    /// [`join_group_from_welcome`]: Self::join_group_from_welcome
    pub async fn add_member(
        &self,
        gid: &GroupId,
        key_package_bytes: &[u8],
    ) -> Result<AddMemberOutput, GroupError> {
        // Parse the caller's bytes back into a typed MlsMessage and
        // confirm it's actually a KeyPackage (otherwise mls-rs's
        // commit_builder gives a confusing error).
        let key_package = MlsMessage::from_bytes(key_package_bytes).map_err(|e| {
            GroupError::InvalidWelcome(format!("KeyPackage decode: {e}"))
        })?;
        if key_package.wire_format() != WireFormat::KeyPackage {
            return Err(GroupError::InvalidWelcome(format!(
                "expected WireFormat::KeyPackage, got {:?}",
                key_package.wire_format()
            )));
        }

        // Held across load → commit → write, like every other mutation path.
        let _guard = self.lock_group(gid.as_bytes()).await;
        let mut group = self.client.load_group(gid.as_bytes()).map_err(|e| {
            let msg = format!("{e}");
            if msg.contains("GroupNotFound") || msg.contains("group not found") {
                GroupError::NotFound
            } else {
                GroupError::Backend(format!("load_group for add_member: {e}"))
            }
        })?;

        // Roster before the Add, so the member(s) this commit introduces can be
        // identified below and their join epoch recorded.
        let roster_before = Self::roster_peer_ids(&group);

        let commit_output = group
            .commit_builder()
            .add_member(key_package)
            .map_err(|e| GroupError::Backend(format!("add_member proposal: {e}")))?
            .build()
            .map_err(|e| GroupError::Backend(format!("commit build: {e}")))?;
        if commit_output.welcome_messages.len() != 1 {
            return Err(GroupError::Backend(format!(
                "Add expected exactly one Welcome, got {}",
                commit_output.welcome_messages.len()
            )));
        }
        // Advance Alice's own state and persist before handing the
        // Welcome to the caller. If write_to_storage fails after the
        // commit was applied in memory we'd be inconsistent — sqlite
        // WAL + busy_timeout makes this rare but the order matters:
        // apply_pending_commit advances the *in-memory* group, then
        // write_to_storage flushes it.
        group
            .apply_pending_commit()
            .map_err(|e| GroupError::Backend(format!("apply_pending_commit: {e}")))?;
        group
            .write_to_storage()
            .map_err(|e| GroupError::Storage(format!("write_to_storage after Add: {e}")))?;

        let welcome_bytes = commit_output.welcome_messages[0]
            .to_bytes()
            .map_err(|e| GroupError::Backend(format!("Welcome encode: {e}")))?;
        let commit_bytes = commit_output
            .commit_message
            .to_bytes()
            .map_err(|e| GroupError::Backend(format!("Commit encode: {e}")))?;

        if let Err(e) =
            self.storage
                .store_commit(group.group_id(), group.current_epoch(), &commit_bytes)
        {
            // The MLS state is already persisted (write_to_storage); only the
            // resync commit-history failed, so this epoch may need a full
            // Welcome instead of a delta. Never silent.
            eprintln!("[mls] failed to persist commit history (epoch advanced): {e}");
        }
        self.record_witnessed_joins(
            group.group_id(),
            group.current_epoch(),
            &roster_before,
            &Self::roster_peer_ids(&group),
        );

        Ok(AddMemberOutput {
            welcome: Zeroizing::new(welcome_bytes),
            commit: Zeroizing::new(commit_bytes),
        })
    }

    /// Accept a `Welcome` blob and join the group it admits us to.
    ///
    /// Returns the `GroupId` of the group we just joined. The group
    /// state is durably persisted before this call returns — a
    /// subsequent `list_groups()` will include the new id and a
    /// subsequent `load_group_summary(id)` will reproduce it.
    ///
    /// Failure modes:
    /// - `GroupError::InvalidWelcome` — `welcome_bytes` is not a
    ///   `Welcome` (wrong wire format, malformed encoding, or for a
    ///   group whose cipher suite we don't support — our provider
    ///   advertises only `0xF101`, so a classical-suite Welcome
    ///   surfaces here).
    /// - `GroupError::Backend(_)` — mls-rs rejected the Welcome for a
    ///   reason that doesn't fit the categories above (e.g. the
    ///   `KeyPackage` we previously generated was already consumed).
    pub async fn join_group_from_welcome(
        &self,
        welcome_bytes: &[u8],
    ) -> Result<GroupId, GroupError> {
        let welcome = MlsMessage::from_bytes(welcome_bytes).map_err(|e| {
            GroupError::InvalidWelcome(format!("Welcome decode: {e}"))
        })?;
        if welcome.wire_format() != WireFormat::Welcome {
            return Err(GroupError::InvalidWelcome(format!(
                "expected WireFormat::Welcome, got {:?}",
                welcome.wire_format()
            )));
        }

        let (mut group, _info) = self
            .client
            .join_group(None, &welcome, None)
            .map_err(|e| {
                // mls-rs's MlsError doesn't expose a clean discriminator
                // for "this Welcome wasn't meant for me" vs general
                // backend failure; the safest categorisation is to keep
                // join failures under Backend and let the caller see
                // the detail string.
                GroupError::Backend(format!("join_group: {e}"))
            })?;

        // Everything below runs BEFORE `write_to_storage`. The group id is
        // chosen by whoever authored the Welcome — reachable unauthenticated
        // over `nkct/mls/1` — and mls-rs puts no constraint on it, so it must
        // be checked while rejecting still costs nothing. Persisting first and
        // validating afterwards left the bad row committed with no way to
        // remove it.
        let id_bytes = group.group_id().to_vec();
        if id_bytes.len() != 32 {
            return Err(GroupError::Backend(format!(
                "joined group has non-32 id length {}",
                id_bytes.len()
            )));
        }

        // A Welcome must not silently take over a group we are already in.
        // The id travels in cleartext in every PrivateMessage header, so any
        // past or present member of a group knows it; without this check one
        // accepted Welcome replaces that group's stored MLS state, after which
        // inbound messages no longer decrypt and outbound ones are encrypted
        // under the attacker's key schedule. Mirrors the clobber protection
        // already applied to commits and to keyring handles.
        let existing = self.storage.list_group_ids_raw()?;
        if existing.iter().any(|k| k.as_slice() == id_bytes.as_slice()) {
            return Err(GroupError::InvalidWelcome(
                "Welcome is for a group id that already exists locally; refusing to overwrite \
                 its state (leave the existing group first if this is intentional)"
                    .to_string(),
            ));
        }

        group
            .write_to_storage()
            .map_err(|e| GroupError::Storage(format!("write_to_storage after join: {e}")))?;

        let mut id = [0u8; 32];
        id.copy_from_slice(&id_bytes);
        // Drop `group` to zeroize its in-memory keys via ZeroizeOnDrop;
        // the state lives on in storage.
        drop(group);

        Ok(GroupId::new(id))
    }

    /// Send a previously-generated `Welcome` blob over the
    /// `nkct/mls/1` ALPN to a peer's reachable address (P4).
    ///
    /// `welcome_bytes` is the buffer returned by
    /// [`add_member`](Self::add_member). `recipient` is the new
    /// member's `PeerAddr` (acquired out-of-band — for now, via a
    /// ticket, in the future via discovery).
    ///
    /// Errors:
    /// - `GroupError::InvalidWelcome` — `welcome_bytes` does not parse
    ///   as a `WireFormat::Welcome`.
    /// - `GroupError::Transport(_)` — the connect / write failed
    ///   (peer unreachable, protocol not registered on remote, idle
    ///   timeout, etc.).
    pub async fn send_welcome_to(
        &self,
        recipient: &crate::p2p::PeerAddr,
        welcome_bytes: &[u8],
    ) -> Result<(), GroupError> {
        let msg = MlsMessage::from_bytes(welcome_bytes).map_err(|e| {
            GroupError::InvalidWelcome(format!("Welcome decode in send: {e}"))
        })?;
        if msg.wire_format() != WireFormat::Welcome {
            return Err(GroupError::InvalidWelcome(format!(
                "send_welcome_to: expected WireFormat::Welcome, got {:?}",
                msg.wire_format()
            )));
        }
        crate::group::transport::send_one_with_inbox(
            self.endpoint.as_ref(),
            recipient,
            &msg,
            self.inbox.as_ref(),
        )
        .await
        .map_err(|e| match e {
            crate::group::transport::FramingError::Transport(p) => GroupError::Transport(p),
            other => GroupError::Backend(format!("send_welcome_to framing: {other}")),
        })
    }

    /// Accept the next inbound MLS stream and process the single frame
    /// it carries (P4).
    ///
    /// For P4's acceptance criterion we only need to handle the
    /// `Welcome` case end-to-end; other wire formats are surfaced as
    /// errors so the caller can decide what to do (P5 will broaden the
    /// dispatch to `Commit` / `Application` / `Proposal`).
    ///
    /// Returns the `GroupId` of the group we just joined. The group
    /// state is durably persisted before this call returns.
    ///
    /// Errors:
    /// - `GroupError::Transport(_)` — the endpoint was closed or the
    ///   peer used the wrong ALPN.
    /// - `GroupError::InvalidWelcome` — the stream carried an MLS
    ///   message that is not a `Welcome`, or the bytes failed to
    ///   decode at all.
    /// - `GroupError::Backend(_)` — mls-rs rejected the Welcome
    ///   (e.g. the KeyPackage we previously published was already
    ///   consumed elsewhere).
    pub async fn accept_welcome(&self) -> Result<GroupId, GroupError> {
        let pending = self
            .endpoint
            .accept()
            .await
            .map_err(GroupError::Transport)?;
        // Run per-connection setup off the (now cheap) accept, bounded so a peer
        // that stalls the handshake cannot hang this call forever.
        let inc = pending
            .establish(crate::p2p::P2P_SETUP_TIMEOUT)
            .await
            // `establish` reports the peer's identity alongside the error when
            // setup got far enough to prove one; this path has no throttle to
            // feed it to, so keep the transport error and drop the attribution.
            .map_err(|e| GroupError::Transport(e.into()))?;
        if inc.protocol != crate::group::transport::ALPN_MLS_PROTOCOL {
            return Err(GroupError::Transport(crate::p2p::P2pError::Accept(format!(
                "accept_welcome: unexpected ALPN {:?}",
                inc.protocol
            ))));
        }
        // Use the typed message *and* the raw bytes — the typed value
        // lets us dispatch by wire_format, the bytes are what
        // `join_group_from_welcome` re-decodes (keeping a single
        // canonical entry point for join logic).
        let (msg, raw) = crate::group::transport::recv_mls_message(inc.stream)
            .await
            .map_err(|e| match e {
                crate::group::transport::FramingError::Transport(p) => {
                    GroupError::Transport(p)
                }
                other => {
                    GroupError::InvalidWelcome(format!("recv_mls_message: {other}"))
                }
            })?;
        if msg.wire_format() != WireFormat::Welcome {
            return Err(GroupError::InvalidWelcome(format!(
                "accept_welcome: expected Welcome, got {:?}",
                msg.wire_format()
            )));
        }
        self.join_group_from_welcome(&raw).await
    }

    /// Encrypt an application message and broadcast it to a list of
    /// recipients over `nkct/mls/1` (P5).
    ///
    /// `body` is the plaintext payload (raw bytes — the UI layer is
    /// responsible for character-set decisions). `recipients` is the
    /// **N − 1** peer addresses that should receive the message — the
    /// caller maintains the `MemberId → PeerAddr` mapping outside this
    /// module (mls-rs only knows the SigningIdentity, not the network
    /// address).
    ///
    /// MLS Private messages are *not* self-decryptable by design
    /// (RFC 9420 §15.1 — only counterparties can derive the per-sender
    /// secret needed to open the AEAD). The caller is therefore
    /// expected to echo `body` to its own UI separately; this method
    /// also returns the encrypted bytes so callers wanting an exact
    /// record-of-send can persist the wire form.
    ///
    /// The group state advances by one ratchet generation per
    /// `encrypt_application_message`. The state is flushed to sqlite
    /// before the broadcast starts so a crash mid-send doesn't leave
    /// our key schedule out of sync with what peers will see.
    pub async fn send_application_message(
        &self,
        gid: &GroupId,
        body: &[u8],
        recipients: &[crate::p2p::PeerAddr],
    ) -> Result<Zeroizing<Vec<u8>>, GroupError> {
        // The group guard covers load → encrypt → persist → encode and
        // NOTHING beyond it. It is a state-consistency lock, not a delivery
        // lock: `fanout_send` below awaits QUIC connects, writes and a
        // per-recipient linger against peer-controlled endpoints, and holding
        // a group's mutation lock across that lets any one recipient freeze
        // every other task that needs this group — including the inbound
        // `process_mls_bytes` that would apply the Commit evicting it. Keep
        // the fan-out outside this block.
        //
        // The key schedule is persisted inside the block, before any bytes
        // leave the host: if a recipient receives the encrypted message but
        // our state was never written, a subsequent re-encrypt could reuse a
        // nonce. That ordering also fixes the failure semantics — once we are
        // past this block the epoch has advanced durably, so a fan-out error
        // is a *delivery* failure and must never roll the MLS state back.
        let (msg, wire_bytes) = {
            let _guard = self.lock_group(gid.as_bytes()).await;
            let mut group = self.client.load_group(gid.as_bytes()).map_err(|e| {
                let msg = format!("{e}");
                if msg.contains("GroupNotFound") || msg.contains("group not found") {
                    GroupError::NotFound
                } else {
                    GroupError::Backend(format!("load_group for send: {e}"))
                }
            })?;

            let msg = group
                .encrypt_application_message(body, Vec::new())
                .map_err(|e| GroupError::Backend(format!("encrypt_application_message: {e}")))?;
            group
                .write_to_storage()
                .map_err(|e| GroupError::Storage(format!("write_to_storage after encrypt: {e}")))?;

            let wire_bytes = msg
                .to_bytes()
                .map_err(|e| GroupError::Backend(format!("PrivateMessage encode: {e}")))?;
            (msg, wire_bytes)
        };

        // Fan-out in parallel, with the group guard released. One QUIC
        // stream per recipient (1 frame = 1 MlsMessage per the §5.4
        // contract). We wait for all sends to
        // settle and surface the first error encountered — that way a
        // mid-list failure doesn't abandon downstream recipients (the
        // earlier sequential `?` would skip recipients after the first
        // error, leaving them silently unfed). Recipients that did
        // succeed have actually received the message.
        fanout_send(
            &self.endpoint,
            recipients,
            msg,
            self.inbox.as_ref(),
            "send_application_message",
        )
        .await?;

        Ok(Zeroizing::new(wire_bytes))
    }

    /// Broadcast a previously-built Commit message to a list of
    /// existing-member recipients (P5).
    ///
    /// `commit_bytes` is the [`AddMemberOutput::commit`] returned by
    /// [`add_member`]. Recipients receive it via `accept_next` and
    /// surface it as
    /// [`IncomingGroupEvent::EpochAdvanced`](crate::group::IncomingGroupEvent::EpochAdvanced).
    ///
    /// For a 1 → 2 group transition there are no existing-member
    /// recipients; the caller should pass an empty slice. The function
    /// does not touch the local group state — that was already
    /// advanced by `add_member` before the bytes were handed back.
    ///
    /// [`add_member`]: Self::add_member
    pub async fn broadcast_commit(
        &self,
        commit_bytes: &[u8],
        recipients: &[crate::p2p::PeerAddr],
    ) -> Result<(), GroupError> {
        if recipients.is_empty() {
            // Nothing to do; avoid decoding the commit unnecessarily.
            return Ok(());
        }
        let msg = MlsMessage::from_bytes(commit_bytes).map_err(|e| {
            GroupError::InvalidWelcome(format!("Commit decode for broadcast: {e}"))
        })?;
        // We accept either PublicMessage or PrivateMessage Commits and do not
        // restrict here — recipients revalidate. That is not cosmetic: a peer
        // on a build without `encrypt_control_messages` sends PublicMessage
        // Commits, and refusing them here would break the group rather than
        // protect it. Keep this accepting.
        //
        // Which one we *emit* is a choice, and `mls_rules()` makes it:
        // `encrypt_control_messages = true`, so mls-rs's `control_wire_format`
        // returns `PrivateMessage` for a member-sent Commit (mls-rs 0.55.2,
        // `group/mls_rules.rs`). Both callers outside tests hand us bytes this
        // node just built (`add_member`, `remove_member` via `cli::add_member`
        // and `cli::remove_member`), so every Commit this function broadcasts
        // is AEAD-sealed under the epoch key schedule: the committer's
        // leaf index and the membership change itself — an Add carries the
        // joining member's whole KeyPackage — are readable only by a member
        // holding that epoch's secrets. The group id and epoch stay in the
        // PrivateMessage header in the clear, by RFC 9420's framing, and so do
        // the frame's size and timing.
        //
        // That is what makes the store-and-forward fallback safe. A recipient
        // we cannot reach inside the direct window gets the frame via
        // `send_one_with_inbox`, and the relay operator is not a member: it now
        // holds a ciphertext plus that header, instead of the roster change in
        // full. There is no flag day here — the wire format is read on the send
        // path only, so an un-upgraded peer applies these Commits normally (and
        // we apply its PublicMessage ones). What does *not* follow is that the
        // group's control traffic is confidential: that holds only once every
        // peer that commits in it has upgraded, since each sender frames its
        // own Commits. See `KNOWN_ISSUES.md` "Security Audit Residuals" item 11.
        //
        // Parallel fan-out: a Welcome+Commit for member N reaches N-1
        // existing members. Sequential `connect()`s dominated setup
        // time in N-member group builds (Σ handshakes grows quadratically
        // with N); parallel cuts the wall-clock cost to ~one handshake's
        // RTT regardless of recipient count.
        fanout_send(
            &self.endpoint,
            recipients,
            msg,
            self.inbox.as_ref(),
            "broadcast_commit",
        )
        .await
    }

    /// Accept the next inbound MLS stream and dispatch by wire format
    /// (P5; the general-purpose successor to P4's [`accept_welcome`]).
    ///
    /// Returns one [`IncomingGroupEvent`] per accepted stream:
    /// - [`NewGroup`](IncomingGroupEvent::NewGroup) — a `Welcome` was
    ///   processed and the group state persisted.
    /// - [`Message`](IncomingGroupEvent::Message) — a `PrivateMessage`
    ///   (or `PublicMessage`) carrying application data was decrypted.
    ///   The body is returned verbatim; UTF-8 decisions are deferred
    ///   to the UI.
    /// - [`EpochAdvanced`](IncomingGroupEvent::EpochAdvanced) — a
    ///   Commit was processed; the group is now at a new epoch and
    ///   the state has been persisted.
    ///
    /// Frames whose `wire_format` doesn't fit any of these (KeyPackage,
    /// GroupInfo) are rejected as `InvalidWelcome` for now — there is
    /// no use case in the current processor for receiving them over
    /// `nkct/mls/1`. P3 sneakernet flows hand KeyPackages around
    /// out-of-band.
    ///
    /// [`accept_welcome`]: Self::accept_welcome
    pub async fn accept_next(&self) -> Result<IncomingGroupEvent, GroupError> {
        let pending = self
            .endpoint
            .accept()
            .await
            .map_err(GroupError::Transport)?;
        // Run per-connection setup off the (now cheap) accept, bounded so a peer
        // that stalls the handshake cannot hang this call forever.
        let mut inc = pending
            .establish(crate::p2p::P2P_SETUP_TIMEOUT)
            .await
            // `establish` reports the peer's identity alongside the error when
            // setup got far enough to prove one; this path has no throttle to
            // feed it to, so keep the transport error and drop the attribution.
            .map_err(|e| GroupError::Transport(e.into()))?;
        if inc.protocol != crate::group::transport::ALPN_MLS_PROTOCOL {
            return Err(GroupError::Transport(crate::p2p::P2pError::Accept(format!(
                "accept_next: unexpected ALPN {:?}",
                inc.protocol
            ))));
        }

        // Read first 4 bytes to distinguish standard message vs SYNC request
        let mut header = [0u8; 4];
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // Short handshake timeout (not the 5-minute bulk IDLE_TIMEOUT): a peer
        // that connects then stalls before sending its small fixed header must
        // be dropped quickly, because `accept_next` is consumed in a serialized
        // loop and a long block here is a head-of-line DoS that stalls all MLS
        // message processing (Welcome/Commit/Application) for every peer.
        tokio::time::timeout(crate::network::HANDSHAKE_TIMEOUT, inc.stream.read_exact(&mut header))
            .await
            .map_err(|_| {
                GroupError::Transport(crate::p2p::P2pError::Accept(
                    "read header: handshake timeout".into(),
                ))
            })?
            .map_err(|e| {
                GroupError::Transport(crate::p2p::P2pError::Accept(format!("read header: {e}")))
            })?;

        if &header == b"SYNC" {
            // Read group_id (32 bytes) and claimed_epoch (8 bytes)
            let mut req = [0u8; 40];
            tokio::time::timeout(crate::network::HANDSHAKE_TIMEOUT, inc.stream.read_exact(&mut req))
                .await
                .map_err(|_| {
                    GroupError::Transport(crate::p2p::P2pError::Accept(
                        "read sync request: handshake timeout".into(),
                    ))
                })?
                .map_err(|e| {
                    GroupError::Transport(crate::p2p::P2pError::Accept(format!(
                        "read sync request: {e}"
                    )))
                })?;
            let mut gid_bytes = [0u8; 32];
            gid_bytes.copy_from_slice(&req[0..32]);
            let claimed_epoch = u64::from_le_bytes(req[32..40].try_into().unwrap());

            // 1. Mutual Authentication Prove Node Identity
            let peer_id = inc.peer_id;

            // Load the group. This precedes the roster membership check because
            // membership can only be decided *from* the roster (which loading
            // produces). The resulting DoS surface is bounded and modest:
            //   - an unknown/random group_id is a single redb key miss → cheap
            //     `ERR` (no amplification);
            //   - a real group_id costs one redb read (page-cached when hot);
            //   - each request needs a full QUIC handshake + bi-stream and
            //     `accept_next` is serialized, so connection setup is the
            //     natural rate limiter, and idle timeouts (above) cap stalls;
            //   - the delta below is bounded by `DEFAULT_COMMIT_RETENTION` and
            //     the `oldest_epoch` floor.
            // Per-peer SYNC rate-limiting remains a possible future hardening
            // (see MLS_P2P_SYNC_DESIGN.md §3.3).
            let group_opt = self.client.load_group(&gid_bytes).ok();
            if group_opt.is_none() {
                let _ = inc.stream.write_all(b"ERR\x01").await;
                return Err(GroupError::NotFound);
            }
            let group = group_opt.unwrap();

            // Verify the requester is a current member (Case A check). Match the
            // connecting transport PeerId against a roster member, AND require
            // that member's bidirectional NKCB binding to verify cryptographically
            // — not just a PeerId-from-credential string match. Join-time
            // (`verify_credential_binding`) already rejects members without a
            // valid binding, so the roster should never hold one; this is
            // defense-in-depth so the commit history (control-plane data) is
            // never disclosed to a SYNC requester whose claimed identity is not
            // cryptographically bound to its transport key.
            let mut is_member = false;
            for m in group.roster().members_iter() {
                if let Some(pid) = Self::peer_id_from_credential(&m.signing_identity.credential) {
                    if pid == peer_id && self.verify_member_binding(&m.signing_identity) {
                        is_member = true;
                        break;
                    }
                }
            }

            if !is_member {
                let _ = inc.stream.write_all(b"ERR\x01").await;
                return Err(GroupError::Backend("Sync rejected: peer not in roster".to_string()));
            }

            let local_epoch = group.current_epoch();
            let oldest_epoch = self.storage.oldest_retained_epoch(&gid_bytes)?
                .unwrap_or(0);

            if claimed_epoch < oldest_epoch {
                let _ = inc.stream.write_all(b"ERR\x02").await;
                return Err(GroupError::Backend(format!(
                    "Sync rejected: epoch {} is pruned (oldest retained is {})",
                    claimed_epoch, oldest_epoch
                )));
            }

            // Current-roster membership is not by itself authorization for the
            // *whole* retained history: `claimed_epoch` is 8 bytes the requester
            // chose, and a member admitted at epoch N that claims the oldest
            // retained epoch would be streamed up to DEFAULT_COMMIT_RETENTION
            // epochs of Commits predating its own admission, learning the
            // identities and transport fingerprints of members evicted before
            // it arrived — exactly the membership history MLS's joiner model
            // withholds. Clamp the floor to the requester's own admission where
            // we witnessed it.
            //
            // Encrypting control frames (`mls_rules`) does not replace this
            // clamp. This is an authorization decision, and two things keep it
            // biting. Retained history is not uniform: `store_commit` keeps the
            // frame as it arrived, so a group older than that change holds
            // `PublicMessage` Commits, as does any epoch committed by a peer
            // still on a build without `encrypt_control_messages` — those are
            // readable by whoever we hand them to. And a member removed and
            // later re-admitted is recorded at its *latest* admission while
            // still holding the epoch secrets from its first stay, so for the
            // span in between the key schedule is no barrier at all. Refusing
            // to serve a frame is a property of this responder; failing to open
            // one is a property of the requester's key material, and only the
            // first is ours to decide.
            //
            // `None` (unknown) is not an entitlement, and must not be read as
            // one. It means this node never applied the Add commit for that
            // member, which covers three different situations: a database
            // written before this record existed, a member that was already on
            // the roster when *we* joined, and a record we failed to write. Only
            // the middle one is harmless — our own history starts at our own
            // join, which is at or after theirs — and nothing in a `None` says
            // which of the three we are looking at.
            //
            // So the group-wide history floor answers instead. It is the
            // exclusive bound of the epoch span in which our join records are
            // complete, which is exactly what makes a missing record mean
            // something: above the floor, "no record" really does say "this
            // member did not join here", so that history is theirs to have. A
            // database that can vouch for no span at all reads `None` there too,
            // and then we serve nothing rather than everything.
            let requester_join_epoch = match self
                .storage
                .member_join_epoch(&gid_bytes, peer_id.as_bytes())
            {
                Ok(v) => v,
                Err(e) => {
                    // A lookup failure is not a `None`. `None` is an answer;
                    // this is the absence of one, and treating the two alike
                    // would make "break this read" a way to ask for unclamped
                    // history. Refuse with the same `ERR\x02` the pruning floor
                    // uses — "no delta for you, take a Welcome".
                    let _ = inc.stream.write_all(b"ERR\x02").await;
                    return Err(GroupError::Storage(format!(
                        "Sync refused: join-epoch lookup failed: {e}"
                    )));
                }
            };
            let group_history_floor = match self.storage.history_floor(&gid_bytes) {
                Ok(v) => v,
                Err(e) => {
                    let _ = inc.stream.write_all(b"ERR\x02").await;
                    return Err(GroupError::Storage(format!(
                        "Sync refused: history-floor lookup failed: {e}"
                    )));
                }
            };
            let effective_floor = sync_history_floor(
                claimed_epoch,
                local_epoch,
                requester_join_epoch,
                group_history_floor,
            );

            // Case B: Delta resync. Bound the *entire* response (the OK marker
            // plus every commit frame) by a single HANDSHAKE_TIMEOUT deadline.
            // A per-write timeout alone does not bound the loop's total time — a
            // slow-reading peer could keep each individual write just under the
            // limit across up to DEFAULT_COMMIT_RETENTION frames and still occupy
            // the serialized accept loop for N x timeout (head-of-line DoS). The
            // disk read (load_commits) happens before the deadline; only the
            // network send is timed.
            // `load_commits` treats its lower bound as *exclusive*, so passing
            // the join epoch serves the commits after the Add that admitted the
            // requester — never the Add itself, which it received as a Welcome.
            // The `oldest_retained_epoch` floor above still applies and is not
            // replaced by this one: it answers "your epoch is unrecoverable,
            // take a Welcome", which is about pruning, not about entitlement.
            let commits = if effective_floor < local_epoch {
                self.storage.load_commits(&gid_bytes, effective_floor, local_epoch)?
            } else {
                Vec::new()
            };
            let send_resp = async {
                inc.stream.write_all(b"OK\x00\x00").await.map_err(|e| {
                    GroupError::Transport(crate::p2p::P2pError::Accept(format!("write OK: {e}")))
                })?;
                for (_epoch, commit_bytes) in &commits {
                    let len = (commit_bytes.len() as u32).to_le_bytes();
                    inc.stream.write_all(&len).await.map_err(|e| {
                        GroupError::Transport(crate::p2p::P2pError::Accept(format!("write commit length: {e}")))
                    })?;
                    inc.stream.write_all(commit_bytes).await.map_err(|e| {
                        GroupError::Transport(crate::p2p::P2pError::Accept(format!("write commit bytes: {e}")))
                    })?;
                }
                Ok::<(), GroupError>(())
            };
            tokio::time::timeout(crate::network::HANDSHAKE_TIMEOUT, send_resp)
                .await
                .map_err(|_| {
                    GroupError::Transport(crate::p2p::P2pError::Accept(
                        "write sync response: handshake timeout".into(),
                    ))
                })??;

            let _ = inc.stream.shutdown().await;

            return Ok(IncomingGroupEvent::EpochAdvanced {
                group_id: GroupId::new(gid_bytes),
                new_epoch: local_epoch,
            });
        }

        // Standard MLS message processing:
        let len = u32::from_le_bytes(header) as usize;
        if len == 0 {
            return Err(GroupError::InvalidWelcome("Empty MLS frame length".to_string()));
        }
        if len > crate::group::transport::MAX_MLS_FRAME_BYTES {
            return Err(GroupError::InvalidWelcome(format!(
                "MLS frame length {len} exceeds limit"
            )));
        }

        let mut raw = vec![0u8; len];
        // HANDSHAKE_TIMEOUT (not the 5-minute bulk IDLE_TIMEOUT): ALPN_MLS is the
        // *control plane* (Welcome/Commit/Proposal/small app frames); bulk data
        // rides the data plane (ALPN_CHAT/ALPN_FILE). A peer that sends a header
        // then stalls the body must not occupy the serialized accept loop for
        // minutes (head-of-line DoS). MAX_MLS_FRAME_BYTES caps the body size.
        tokio::time::timeout(crate::network::HANDSHAKE_TIMEOUT, inc.stream.read_exact(&mut raw))
            .await
            .map_err(|_| {
                GroupError::Transport(crate::p2p::P2pError::Accept(
                    "read MLS frame body: handshake timeout".into(),
                ))
            })?
            .map_err(|e| {
                GroupError::Transport(crate::p2p::P2pError::Accept(format!("read MLS frame body: {e}")))
            })?;

        let msg = MlsMessage::from_bytes(&raw).map_err(|e| {
            GroupError::InvalidWelcome(format!("MLS message decode: {e}"))
        })?;

        let res = self.process_mls_bytes(msg, raw).await;
        let _ = inc.stream.write_all(&[1u8]).await;
        let _ = inc.stream.shutdown().await;
        res
    }

    pub async fn request_resync(&self, gid: &GroupId, peer_addr: &PeerAddr) -> Result<ResyncOutcome, GroupError> {
        let group = self.client.load_group(gid.as_bytes()).map_err(|e| {
            let m = format!("{e}");
            if m.contains("GroupNotFound") || m.contains("group not found") {
                GroupError::NotFound
            } else {
                GroupError::Backend(format!("load_group for resync: {e}"))
            }
        })?;

        let claimed_epoch = group.current_epoch();

        let mut stream = self.endpoint.connect(peer_addr, crate::group::transport::ALPN_MLS_PROTOCOL)
            .await
            .map_err(GroupError::Transport)?;

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        stream.write_all(b"SYNC").await.map_err(|e| {
            GroupError::Transport(crate::p2p::P2pError::Connect(format!("write SYNC header: {e}")))
        })?;

        let mut req = [0u8; 40];
        req[0..32].copy_from_slice(gid.as_bytes());
        req[32..40].copy_from_slice(&claimed_epoch.to_le_bytes());
        stream.write_all(&req).await.map_err(|e| {
            GroupError::Transport(crate::p2p::P2pError::Connect(format!("write SYNC request: {e}")))
        })?;

        let mut resp = [0u8; 4];
        // HANDSHAKE_TIMEOUT, not the 5-minute bulk IDLE_TIMEOUT — the mirror
        // image of the deadline the responder puts on *its* small fixed reads
        // (see `accept_next` above, which calls that pattern a head-of-line
        // DoS). A responder that connects and then says nothing would otherwise
        // hold this call for 300 s, and the caller sweeps peers one at a time
        // from a REPL, so n silent peers cost n x 300 s of an operator's
        // session. IDLE_TIMEOUT itself is shared with the bulk transfer paths
        // in `network` and `group::transport` and is deliberately not changed.
        tokio::time::timeout(crate::network::HANDSHAKE_TIMEOUT, stream.read_exact(&mut resp))
            .await
            .map_err(|_| {
                GroupError::Transport(crate::p2p::P2pError::Connect(
                    "read SYNC response: handshake timeout".into(),
                ))
            })?
            .map_err(|e| {
                GroupError::Transport(crate::p2p::P2pError::Connect(format!("read SYNC response: {e}")))
            })?;

        // Typed, not stringly. These two are the responder's own rejection
        // codes, and a caller that wants to tell them apart must not do it by
        // matching substrings of the rendered error: a QUIC close reason the
        // peer chose arrives inside `Transport(Connect(..))` and would match,
        // so text matching let *any* peer produce the rejection of its choice.
        //
        // What the variant establishes is exactly this and no more: the
        // responder sent that code. It does **not** establish that the claim is
        // true. Nothing here authenticates the responder — not its membership,
        // not its view of the roster, not that it runs this software — so a
        // caller rendering these must attribute the claim to the peer rather
        // than assert it (see `cli::describe_resync_failure`).
        if &resp == b"ERR\x01" {
            return Err(GroupError::SyncRejectedByRoster);
        }
        if &resp == b"ERR\x02" {
            return Err(GroupError::SyncEpochPruned);
        }
        if &resp != b"OK\x00\x00" {
            return Err(GroupError::Backend(format!("Sync rejected: unexpected response {:?}", resp)));
        }

        let mut outcome = ResyncOutcome::default();
        let mut loop_count = 0;
        loop {
            loop_count += 1;
            if loop_count > 1000 {
                return Err(GroupError::Backend("Sync rejected: too many commits streamed (possible infinite loop or DoS)".to_string()));
            }

            let mut len_bytes = [0u8; 4];
            // Same deadline as the response read above, for the same reason: a
            // peer that stops mid-stream must not pin the caller for 300 s.
            let read_res =
                match tokio::time::timeout(crate::network::HANDSHAKE_TIMEOUT, stream.read_exact(&mut len_bytes))
                    .await
                {
                    Ok(r) => r,
                    Err(_) => {
                        return Err(GroupError::Transport(crate::p2p::P2pError::Connect(
                            "read commit length: handshake timeout".into(),
                        )))
                    }
                };
            if let Err(e) = read_res {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    break;
                }
                return Err(GroupError::Transport(crate::p2p::P2pError::Connect(format!("read commit length: {e}"))));
            }
            let len = u32::from_le_bytes(len_bytes) as usize;
            if len == 0 {
                return Err(GroupError::InvalidWelcome("Empty SYNC frame length".to_string()));
            }
            if len > crate::group::transport::MAX_MLS_FRAME_BYTES {
                return Err(GroupError::InvalidWelcome(format!(
                    "SYNC frame length {len} exceeds limit"
                )));
            }
            let mut commit_bytes = vec![0u8; len];
            // The body too, mirroring the responder's own MLS-frame body read
            // (`accept_next`, which bounds the same MAX_MLS_FRAME_BYTES-capped
            // body by HANDSHAKE_TIMEOUT). A peer that sends a length prefix and
            // then trickles is otherwise a second 300 s stall per frame.
            tokio::time::timeout(crate::network::HANDSHAKE_TIMEOUT, stream.read_exact(&mut commit_bytes))
                .await
                .map_err(|_| {
                    GroupError::Transport(crate::p2p::P2pError::Connect(
                        "read commit bytes: handshake timeout".into(),
                    ))
                })?
                .map_err(|e| {
                    GroupError::Transport(crate::p2p::P2pError::Connect(format!(
                        "read commit bytes: {e}"
                    )))
                })?;

            let msg = MlsMessage::from_bytes(&commit_bytes).map_err(|e| {
                GroupError::InvalidWelcome(format!("SYNC commit decode: {e}"))
            })?;

            // Locked per applied commit rather than for the whole resync: each
            // load → process → write must be atomic, but a resync streams over
            // the network and holding the group for its full duration would
            // stall the REPL and the inbound task for as long as the peer takes.
            let _guard = self.lock_group(gid.as_bytes()).await;
            let mut group = self.client.load_group(gid.as_bytes()).map_err(|e| {
                GroupError::Backend(format!("load_group during SYNC: {e}"))
            })?;

            // Same roster diff as the direct-receive path: commits replayed
            // during a catch-up are just as much a witnessed Add, and skipping
            // them here would leave us holding history from before a member
            // joined with no record of when that was.
            let roster_before = Self::roster_peer_ids(&group);

            let received = group.process_incoming_message(msg).map_err(|e| {
                GroupError::Backend(format!("SYNC process commit: {e}"))
            })?;

            // A resync stream must carry only Commits. A malicious responder
            // could otherwise return a valid non-Commit (e.g. an Application
            // message); persisting it into the commit-history DB as if it were a
            // Commit would corrupt future delta resyncs. Reject before any write
            // (the non-Commit mutation stays in-memory only and is dropped).
            //
            // Bound rather than matched so the commit's *effect* can be read
            // after the write below. Same reject, same place, same bytes.
            let commit = match received {
                mls_rs::group::ReceivedMessage::Commit(desc) => desc,
                _ => {
                    return Err(GroupError::Backend(
                        "SYNC stream carried a non-Commit MLS message; aborting resync".into(),
                    ))
                }
            };

            group.write_to_storage().map_err(|e| {
                GroupError::Storage(format!("SYNC write_to_storage: {e}"))
            })?;

            if let Err(e) =
            self.storage
                .store_commit(group.group_id(), group.current_epoch(), &commit_bytes)
        {
            // The MLS state is already persisted (write_to_storage); only the
            // resync commit-history failed, so this epoch may need a full
            // Welcome instead of a delta. Never silent.
            eprintln!("[mls] failed to persist commit history (epoch advanced): {e}");
        }
            self.record_witnessed_joins(
                group.group_id(),
                group.current_epoch(),
                &roster_before,
                &Self::roster_peer_ids(&group),
            );
            outcome.applied = true;

            // Read the same way the direct-receive path reads it (see
            // `accept_next`'s `CommitEffect::Removed` arm). What it is worth is
            // spelled out on `ResyncOutcome::removed_us`, and it is less than it
            // looks: verification says the signer held this group's state at our
            // epoch, which an evicted member also does, so this is evidence
            // about the responder rather than about our membership.
            //
            // Note it does *not* advance our persisted epoch — mls-rs discards
            // the provisional state for a self-removal — so a caller measuring
            // progress by epoch alone would report "nothing happened" for the
            // one message a lagging member most needs to see.
            //
            // Stop reading here. Nothing later in the stream can apply to a
            // group we are no longer in, so continuing would only feed more
            // peer-chosen bytes to mls-rs and turn this into a `Backend` error
            // that loses the fact above. The frames not read are dropped with
            // the stream.
            if matches!(commit.effect, mls_rs::group::CommitEffect::Removed { .. }) {
                outcome.removed_us = true;
                break;
            }
        }

        Ok(outcome)
    }

    /// Process a single MLS payload that arrived through some channel
    /// other than the direct `ALPN_MLS` stream (e.g. drained from an
    /// inbox poll). The wire dispatch is identical to `accept_next`
    /// post-framing; factoring it out lets us share one body between
    /// the direct-receive and store-and-forward paths.
    ///
    /// The caller is responsible for length-prefix framing — pass the
    /// raw bytes that would have been on the wire after the u32 length
    /// prefix is stripped. (Inbox envelopes store exactly that.)
    pub async fn process_inbox_envelope(
        &self,
        envelope: &[u8],
    ) -> Result<IncomingGroupEvent, GroupError> {
        let msg = MlsMessage::from_bytes(envelope).map_err(|e| {
            GroupError::InvalidWelcome(format!("decode inbox envelope: {e}"))
        })?;
        self.process_mls_bytes(msg, envelope.to_vec()).await
    }

    async fn process_mls_bytes(
        &self,
        msg: MlsMessage,
        raw: Vec<u8>,
    ) -> Result<IncomingGroupEvent, GroupError> {
        match msg.wire_format() {
            WireFormat::Welcome => {
                let gid = self.join_group_from_welcome(&raw).await?;
                Ok(IncomingGroupEvent::NewGroup { id: gid })
            }
            WireFormat::PrivateMessage | WireFormat::PublicMessage => {
                // PrivateMessage/PublicMessage carry the group_id in
                // their header (peekable without decryption); we use
                // it to route the message to the right local group.
                let gid_bytes = msg.group_id().ok_or_else(|| {
                    GroupError::InvalidWelcome(format!(
                        "accept_next: {:?} carries no group_id",
                        msg.wire_format()
                    ))
                })?;
                if gid_bytes.len() != 32 {
                    return Err(GroupError::Backend(format!(
                        "accept_next: incoming group_id has length {} (expected 32)",
                        gid_bytes.len()
                    )));
                }
                let mut gid_arr = [0u8; 32];
                gid_arr.copy_from_slice(gid_bytes);
                let group_id = GroupId::new(gid_arr);

                // Held across load → process → write. This is the side that
                // carries Commits, including the Remove that a concurrent
                // REPL/inbox write would otherwise roll back.
                let _guard = self.lock_group(gid_bytes).await;
                let mut group = self.client.load_group(gid_bytes).map_err(|e| {
                    let m = format!("{e}");
                    if m.contains("GroupNotFound") || m.contains("group not found") {
                        GroupError::NotFound
                    } else {
                        GroupError::Backend(format!("load_group for incoming: {e}"))
                    }
                })?;

                // Roster before processing: if this turns out to be a Commit
                // that adds members, the difference names them and the epoch it
                // produces is their join epoch. Taken unconditionally because
                // the message type is only known after processing; a roster
                // walk is cheap next to the MLS decrypt that follows.
                let roster_before = Self::roster_peer_ids(&group);

                let received = group
                    .process_incoming_message(msg)
                    .map_err(|e| GroupError::Backend(format!("process_incoming_message: {e}")))?;

                // Always persist after processing — Application
                // messages advance the per-sender ratchet, Commits
                // advance the epoch, both must survive a restart.
                group.write_to_storage().map_err(|e| {
                    GroupError::Storage(format!("write_to_storage after process: {e}"))
                })?;

                use mls_rs::group::{CommitEffect, ReceivedMessage};
                match received {
                    ReceivedMessage::ApplicationMessage(desc) => {
                        Ok(IncomingGroupEvent::Message {
                            group_id,
                            sender_index: desc.sender_index,
                            body: desc.data().to_vec(),
                        })
                    }
                    ReceivedMessage::Commit(desc) => {
                        if let Err(e) = self.storage.store_commit(
                            group.group_id(),
                            group.current_epoch(),
                            &raw,
                        ) {
                            eprintln!(
                                "[mls] failed to persist commit history (epoch advanced): {e}"
                            );
                        }
                        self.record_witnessed_joins(
                            group.group_id(),
                            group.current_epoch(),
                            &roster_before,
                            &Self::roster_peer_ids(&group),
                        );

                        match desc.effect {
                            CommitEffect::Removed { remover, .. } => {
                                let remover_index = match remover {
                                    mls_rs::group::Sender::Member(i) => i,
                                    // External-sender Removes are
                                    // possible per RFC 9420 §12.1.7
                                    // but not used by this project;
                                    // report the wrapper variant's
                                    // raw discriminator as 0 so the
                                    // event still has *some* value
                                    // for the caller.
                                    _ => 0,
                                };
                                Ok(IncomingGroupEvent::RemovedFromGroup {
                                    group_id,
                                    remover_index,
                                })
                            }
                            _ => Ok(IncomingGroupEvent::EpochAdvanced {
                                group_id,
                                new_epoch: group.current_epoch(),
                            }),
                        }
                    }
                    other => Err(GroupError::Backend(format!(
                        "unexpected ReceivedMessage variant after PrivateMessage decode: {other:?}"
                    ))),
                }
            }
            other => Err(GroupError::InvalidWelcome(format!(
                "accept_next: unsupported WireFormat {other:?}"
            ))),
        }
    }

    fn peer_id_from_credential(cred: &mls_rs::identity::Credential) -> Option<PeerId> {
        if let mls_rs::identity::Credential::Basic(basic) = cred {
            let id = &basic.identifier;
            if id.starts_with(b"NKCB") {
                if id.len() >= 36 {
                    let mut bytes = [0u8; 32];
                    bytes.copy_from_slice(&id[4..36]);
                    return Some(PeerId::new(bytes));
                }
            } else if id.len() >= 32 {
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&id[0..32]);
                return Some(PeerId::new(bytes));
            }
        }
        None
    }

    fn verify_member_binding(&self, signing_identity: &SigningIdentity) -> bool {
        let crypto = HybridCryptoProvider::new();
        let provider = match crypto.cipher_suite_provider(hybrid_cipher_suite()) {
            Some(p) => p,
            None => return false,
        };
        let basic = match signing_identity.credential.as_basic() {
            Some(b) => b,
            None => return false,
        };
        // Only a member with a valid bidirectional NKCB binding is projected
        // onto the transport allowlist. Non-NKCB / malformed credentials are
        // NOT projected (a self-asserted PeerId must never enter the allowlist
        // — that is the poisoning hole). Backward-compat for non-MLS / 1:1 use
        // is handled by the "empty allowlist = allow all" gate, not here.
        match parse_nkcb_binding(&basic.identifier) {
            Some((peer_id, transport_pub, binding)) => crate::group::binding::verify_binding(
                &provider,
                &signing_identity.signature_key,
                "ML-DSA-65",
                &transport_pub,
                0, // identity-level binding
                &peer_id,
                &binding,
            ),
            None => false,
        }
    }

    /// The transport peer ids currently on `group`'s roster, as far as their
    /// credentials identify one. Used to diff the roster across a commit we
    /// apply, which is how a member's join epoch is witnessed.
    fn roster_peer_ids(group: &mls_rs::Group<MlsConfig>) -> std::collections::HashSet<PeerId> {
        group
            .roster()
            .members_iter()
            .filter_map(|m| Self::peer_id_from_credential(&m.signing_identity.credential))
            .collect()
    }

    /// Persist `epoch` as the join epoch of every peer that is on the roster in
    /// `after` but was not in `before` — i.e. every member this commit added —
    /// and move the group's history floor to match.
    ///
    /// Call it immediately after a commit has been applied *and* persisted, with
    /// `epoch = group.current_epoch()`, on **every** commit we apply and not
    /// only the ones that add someone. That is the epoch whose Add commit the
    /// new member never receives (it gets a Welcome instead), so it is exactly
    /// the exclusive floor the SYNC responder may serve that member from — and
    /// a commit that adds nobody still carries the fact the floor is made of:
    /// that we now know who joined at this epoch, namely no one.
    ///
    /// The floor is the group-wide half of the same statement, and it is what
    /// makes a *missing* join record mean something. It is pinned at
    /// `epoch - 1` the first time we get here (`load_commits` reads its lower
    /// bound exclusively, so `E - 1` serves epoch `E` onwards), and left where
    /// it is by every later commit whose records we wrote — the invariant it
    /// stands for is "for every epoch above the floor, every Add we applied
    /// there was recorded", which the first successful call establishes and each
    /// later one merely extends.
    ///
    /// Best-effort on the individual record, like the commit-history write next
    /// to it: it must not fail a group operation that has already advanced the
    /// epoch on disk. But a record we failed to write breaks that invariant at
    /// this epoch, so instead of pinning we *raise* the floor above it — the
    /// span we can vouch for shrinks rather than silently going stale. Never
    /// silent either way.
    fn record_witnessed_joins(
        &self,
        group_id: &[u8],
        epoch: u64,
        before: &std::collections::HashSet<PeerId>,
        after: &std::collections::HashSet<PeerId>,
    ) {
        let mut all_recorded = true;
        for pid in after.difference(before) {
            if let Err(e) = self
                .storage
                .put_member_join_epoch(group_id, pid.as_bytes(), epoch)
            {
                all_recorded = false;
                eprintln!(
                    "[mls] failed to record a member's join epoch (sync history for that \
                     member will not be clamped to its own admission): {e}"
                );
            }
        }
        let floor = if all_recorded {
            self.storage
                .pin_history_floor_if_absent(group_id, epoch.saturating_sub(1))
        } else {
            self.storage.raise_history_floor(group_id, epoch)
        };
        if let Err(e) = floor {
            eprintln!(
                "[mls] failed to update the group's sync history floor (delta resync may \
                 serve less history to members whose join epoch we never recorded): {e}"
            );
        }
    }

    /// Return this processor's own reachable address — typically what
    /// a peer would need to call [`send_welcome_to`] back to us.
    ///
    /// Equivalent to `self.endpoint.local_addr()`; exposed at the
    /// processor level so callers don't have to reach into the raw
    /// transport.
    pub async fn local_addr(&self) -> Result<crate::p2p::PeerAddr, GroupError> {
        self.endpoint
            .local_addr()
            .await
            .map_err(GroupError::Transport)
    }

    /// Remember member delivery hints for a group: store each ticket string
    /// keyed by its transport node id, so a later `send`/`chat-group` can target
    /// these peers without the user re-supplying `--mls-recipient-ticket`.
    ///
    /// Only tickets whose node id matches an **actual current group member** are
    /// stored. This stops a wrong or malicious ticket — supplied once by mistake
    /// — from poisoning the address book and making every later auto-resolved
    /// send connect to / leak ciphertext metadata at a non-member. Best-effort:
    /// errors are logged, never fatal.
    pub fn remember_member_tickets(&self, gid: &GroupId, tickets: &[crate::ticket::Ticket]) {
        if tickets.is_empty() {
            return;
        }
        let members = match self.current_member_node_ids(gid) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("[mls] cannot validate member tickets (group load failed): {e}");
                return;
            }
        };
        for t in tickets {
            let node_id = *t.peer_addr().peer_id.as_bytes();
            if !members.contains(&node_id) {
                eprintln!(
                    "[mls] refusing to remember a ticket for a node that is not a current group member"
                );
                continue;
            }
            if let Err(e) = self.storage.put_member_addr(gid.as_bytes(), &node_id, &t.to_string()) {
                eprintln!("[mls] failed to remember member address (non-fatal): {e}");
            }
        }
    }

    /// The transport node ids of a group's **current** members — the exact set
    /// [`remember_member_tickets`](Self::remember_member_tickets) validates
    /// against and [`known_member_addrs`](Self::known_member_addrs) filters by,
    /// so both sides key on one notion of identity (the PeerId carried in the
    /// member's own credential, via `peer_id_from_credential`).
    ///
    /// Crate-visible because a long-running chat/listen session cannot use
    /// `known_member_addrs`: it resolves its recipients once and then holds
    /// that `Vec`, so it needs the roster itself to tell which of the peers it
    /// already holds have since left (see `cli::prune_departed_recipients`).
    ///
    /// **Not an authenticated identity.** These ids are *self-asserted*: the
    /// credential is written by the member it describes, and a verified NKCB
    /// binding proves only possession of the two keys it names — nothing ties
    /// `peer_id` to the node key it claims, so any member can seat a leaf
    /// bearing any node id. Callers may use this to decide *delivery hints*
    /// (which address to stop dialling), never to authorize a peer: the
    /// authenticated member identity is the transport fingerprint
    /// [`projected_member_fingerprints`](Self::projected_member_fingerprints)
    /// derives from a verified binding.
    pub(crate) fn current_member_node_ids(
        &self,
        gid: &GroupId,
    ) -> Result<std::collections::HashSet<[u8; 32]>, GroupError> {
        let group = self
            .client
            .load_group(gid.as_bytes())
            .map_err(|e| GroupError::Backend(format!("load_group for member roster: {e}")))?;
        Ok(group
            .roster()
            .members_iter()
            .filter_map(|m| Self::peer_id_from_credential(&m.signing_identity.credential))
            .map(|pid| *pid.as_bytes())
            .collect())
    }

    /// Return the remembered recipient addresses for a group (delivery hints).
    /// A stored ticket that no longer parses is skipped rather than failing the
    /// whole lookup.
    ///
    /// The stored book is **advisory**: a row can go stale behind our back, so
    /// every hint is re-checked against the group's **live roster** here, on
    /// every read. The write-time check in
    /// [`remember_member_tickets`](Self::remember_member_tickets) is not enough
    /// on its own — a member evicted by *another* member's Commit leaves the
    /// roster without this node ever touching the address book, and its row
    /// simply stays there. Filtering on read is what guarantees such a stale row
    /// can never produce a non-member recipient: we must not keep dialling an
    /// evicted peer and leaking ciphertext / timing metadata at it.
    ///
    /// This fails **closed**: a hint whose node id is not on the live roster is
    /// dropped, and a group whose MLS state cannot be loaded yields an error
    /// rather than the unchecked book. An explicit `--mls-recipient-ticket`
    /// bypasses the book entirely, so the operator keeps a way to reach a peer
    /// this filter cannot vouch for.
    pub fn known_member_addrs(&self, gid: &GroupId) -> Result<Vec<PeerAddr>, GroupError> {
        let members = self.current_member_node_ids(gid)?;
        let mut out = Vec::new();
        for (_node_id, ticket_str) in self.storage.list_member_addrs(gid.as_bytes())? {
            match ticket_str.parse::<crate::ticket::Ticket>() {
                Ok(t) => {
                    let addr = t.peer_addr();
                    if !members.contains(addr.peer_id.as_bytes()) {
                        // Static literal: never echo the stored ticket or node
                        // id, both of which are peer-influenced.
                        eprintln!(
                            "[mls] dropping a remembered address whose node is not a current group member"
                        );
                        continue;
                    }
                    out.push(addr);
                }
                Err(e) => eprintln!("[mls] skipping unparseable stored ticket: {e}"),
            }
        }
        Ok(out)
    }

    /// List the current members of a group (P6).
    ///
    /// Returns one [`MemberInfo`] per live leaf in the group's TreeKEM,
    /// in ascending leaf-index order. The leaf index is the only
    /// identity surfaced for now — sufficient for the `remove_member`
    /// caller to address a removal target; richer identity (display
    /// name from the BasicCredential, signing-key fingerprint) is
    /// deferred to the UI layer (P7+).
    ///
    /// Errors:
    /// - `GroupError::NotFound` — `gid` is not present in storage.
    /// - `GroupError::Backend(_)` — mls-rs rejected the load.
    pub async fn list_members(
        &self,
        gid: &GroupId,
    ) -> Result<Vec<MemberInfo>, GroupError> {
        let group = self.client.load_group(gid.as_bytes()).map_err(|e| {
            let m = format!("{e}");
            if m.contains("GroupNotFound") || m.contains("group not found") {
                GroupError::NotFound
            } else {
                GroupError::Backend(format!("load_group for list_members: {e}"))
            }
        })?;
        let mut out: Vec<MemberInfo> = group
            .roster()
            .members_iter()
            .map(|m| MemberInfo { index: m.index })
            .collect();
        // mls-rs already yields leaves in ascending index order, but
        // sort defensively in case the iterator's guarantee changes.
        out.sort_by_key(|m| m.index);
        Ok(out)
    }

    /// Return the transport ML-DSA fingerprints (`SHA3-256(transport pubkey)`) of
    /// the group's current members whose NKCB binding verifies.
    ///
    /// These are exactly the 32-byte fingerprints the shell / port-forward
    /// authorization layer compares a connecting peer against
    /// (`PeerId::Pubkey(SHA3-256(signing pubkey))`), because a member's NKCB
    /// binding ties its MLS identity to the *same* ML-DSA transport key it
    /// authenticates the transport handshake with. So this list can be **projected**
    /// into a `--shell-policy` / `--forward-policy` file: group membership becomes
    /// the team's allow-list, managed by MLS add/remove rather than by hand-editing
    /// every server's policy. Authorization stays on the ML-DSA fingerprint (the
    /// real transport identity) — the group only *derives* the member set; we never
    /// gate on the iroh node id.
    ///
    /// A member without a valid bidirectional binding is skipped (never projected),
    /// so a self-asserted identity can never enter a policy.
    pub async fn projected_member_fingerprints(
        &self,
        gid: &GroupId,
    ) -> Result<Vec<[u8; 32]>, GroupError> {
        let group = self.client.load_group(gid.as_bytes()).map_err(|e| {
            let m = format!("{e}");
            if m.contains("GroupNotFound") || m.contains("group not found") {
                GroupError::NotFound
            } else {
                GroupError::Backend(format!("load_group for projection: {e}"))
            }
        })?;
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for m in group.roster().members_iter() {
            if !self.verify_member_binding(&m.signing_identity) {
                continue;
            }
            let Some(basic) = m.signing_identity.credential.as_basic() else { continue };
            let Some((_peer_id, transport_pub, _b)) = parse_nkcb_binding(&basic.identifier) else {
                continue;
            };
            let fp = crate::group::binding::transport_fingerprint(&transport_pub);
            if seen.insert(fp) {
                out.push(fp);
            }
        }
        Ok(out)
    }

    /// Remove a member from a group and return the Commit bytes to
    /// broadcast (P6).
    ///
    /// `index` is the leaf index of the member to remove — as listed
    /// by [`list_members`](Self::list_members) or carried in an
    /// [`IncomingGroupEvent::Message::sender_index`].
    ///
    /// Unlike [`add_member`](Self::add_member), removal produces no
    /// Welcome — there is no new member to admit. The returned Commit
    /// must be broadcast to **all remaining members** (which includes
    /// the removed member if you want them to learn they've been
    /// kicked; otherwise omit them and they will simply observe their
    /// next inbound message fail to decrypt). Per the plan §7.4 the
    /// project broadcasts to the removed member too so they get a
    /// clean
    /// [`IncomingGroupEvent::RemovedFromGroup`](crate::group::IncomingGroupEvent::RemovedFromGroup)
    /// event.
    ///
    /// Forward / post-compromise security: after this Commit is
    /// applied, the group transitions to a new epoch with a fresh key
    /// schedule. The removed member's previous keys decrypt nothing
    /// at the new epoch — RFC 9420 §16. The PCS test
    /// `remove_member_blocks_new_epoch_decrypt` pins this property.
    ///
    /// Errors:
    /// - `GroupError::NotFound` — `gid` is not present in storage.
    /// - `GroupError::Backend(_)` — mls-rs rejected the removal (e.g.
    ///   index out of range, or trying to remove ourselves — mls-rs
    ///   surfaces both as `MlsError` variants).
    pub async fn remove_member(
        &self,
        gid: &GroupId,
        index: u32,
    ) -> Result<Zeroizing<Vec<u8>>, GroupError> {
        // Held across load → commit → write. This is the path whose loss the
        // whole finding is about: a discarded Remove leaves the evicted member
        // on the roster with the old epoch secrets still live.
        let _guard = self.lock_group(gid.as_bytes()).await;
        let mut group = self.client.load_group(gid.as_bytes()).map_err(|e| {
            let m = format!("{e}");
            if m.contains("GroupNotFound") || m.contains("group not found") {
                GroupError::NotFound
            } else {
                GroupError::Backend(format!("load_group for remove_member: {e}"))
            }
        })?;

        // Resolve the removed member's transport node id from the roster while it
        // is still present, but do NOT forget its address hint yet — only after
        // the removal is durably applied below, so a mid-way failure can't drop a
        // still-current member's hint (availability).
        let removed_node_id = group
            .roster()
            .members_iter()
            .find(|m| m.index == index)
            .and_then(|m| Self::peer_id_from_credential(&m.signing_identity.credential))
            .map(|pid| *pid.as_bytes());

        // Same roster diff as the Add path. A Remove adds nobody, so this
        // records no join epoch — but it is still a commit we applied, and
        // saying so is what pins the group's history floor (see
        // `record_witnessed_joins`). Skipping it here would leave a node whose
        // only group operations are removals retaining history it can vouch for
        // and refusing to serve it.
        let roster_before = Self::roster_peer_ids(&group);

        let commit_output = group
            .commit_builder()
            .remove_member(index)
            .map_err(|e| GroupError::Backend(format!("remove_member proposal: {e}")))?
            .build()
            .map_err(|e| GroupError::Backend(format!("remove commit build: {e}")))?;
        // Remove must not produce a Welcome (no one is being added).
        if !commit_output.welcome_messages.is_empty() {
            return Err(GroupError::Backend(format!(
                "remove_member yielded {} Welcomes (expected 0)",
                commit_output.welcome_messages.len()
            )));
        }

        group
            .apply_pending_commit()
            .map_err(|e| GroupError::Backend(format!("apply_pending_commit after remove: {e}")))?;
        group
            .write_to_storage()
            .map_err(|e| GroupError::Storage(format!("write_to_storage after remove: {e}")))?;

        // The removal is now durably applied — forget the evicted member's
        // delivery hint so a later auto-resolved send no longer targets it (the
        // evicted peer can't decrypt the new epoch anyway, but we must not keep
        // connecting to / leaking ciphertext metadata at it). Best-effort.
        if let Some(node_id) = removed_node_id {
            if let Err(e) = self.storage.forget_member_addr(gid.as_bytes(), &node_id) {
                eprintln!("[mls] failed to forget removed member's address (non-fatal): {e}");
            }
        }

        let commit_bytes = commit_output
            .commit_message
            .to_bytes()
            .map_err(|e| GroupError::Backend(format!("Commit encode after remove: {e}")))?;

        if let Err(e) =
            self.storage
                .store_commit(group.group_id(), group.current_epoch(), &commit_bytes)
        {
            // The MLS state is already persisted (write_to_storage); only the
            // resync commit-history failed, so this epoch may need a full
            // Welcome instead of a delta. Never silent.
            eprintln!("[mls] failed to persist commit history (epoch advanced): {e}");
        }
        self.record_witnessed_joins(
            group.group_id(),
            group.current_epoch(),
            &roster_before,
            &Self::roster_peer_ids(&group),
        );

        Ok(Zeroizing::new(commit_bytes))
    }

    /// Load a group from storage and return a read-only summary of its
    /// current state.
    ///
    /// This is the canonical *read-only* round-trip used to verify
    /// persistence: the group state is fully reconstructed from sqlite
    /// (including TreeKEM, key schedule, application secret), summarised,
    /// and dropped. The intermediate `mls_rs::Group` is zeroized via
    /// mls-rs's own ZeroizeOnDrop when it goes out of scope at the end
    /// of this method.
    ///
    /// Returns `GroupError::NotFound` if no group with that ID exists.
    pub async fn load_group_summary(
        &self,
        gid: &GroupId,
    ) -> Result<GroupSummary, GroupError> {
        let group = self
            .client
            .load_group(gid.as_bytes())
            .map_err(|e| {
                // mls-rs returns `GroupNotFound` for missing rows; map
                // it to our domain `NotFound` so callers don't depend
                // on the upstream error enum.
                let msg = format!("{e}");
                if msg.contains("GroupNotFound") || msg.contains("group not found") {
                    GroupError::NotFound
                } else {
                    GroupError::Backend(format!("load_group: {e}"))
                }
            })?;
        let epoch = group.current_epoch();
        let member_count = group.roster().members_iter().count();
        Ok(GroupSummary {
            id: *gid,
            epoch,
            member_count,
        })
    }
}

/// Send one `MlsMessage` to many recipients concurrently via the shared
/// endpoint. Waits for every send to settle before returning, then
/// surfaces the first error if any. `label` is used in error context.
///
/// Each send opens its own QUIC stream — the iroh endpoint multiplexes
/// connections by NodeId, so concurrent `connect()`s to distinct peers
/// run truly in parallel rather than serialising on a single mutex.
async fn fanout_send(
    endpoint: &Arc<dyn P2pEndpoint>,
    recipients: &[crate::p2p::PeerAddr],
    msg: MlsMessage,
    inbox: Option<&PeerAddr>,
    label: &'static str,
) -> Result<(), GroupError> {
    if recipients.is_empty() {
        return Ok(());
    }
    // Single recipient: avoid the JoinSet machinery — common case for
    // 1→2 group transitions and direct sends.
    if recipients.len() == 1 {
        return crate::group::transport::send_one_with_inbox(
            endpoint.as_ref(),
            &recipients[0],
            &msg,
            inbox,
        )
        .await
        .map_err(|e| match e {
            crate::group::transport::FramingError::Transport(p) => GroupError::Transport(p),
            other => GroupError::Backend(format!("{label}: {other}")),
        });
    }
    let msg = Arc::new(msg);
    let inbox_owned: Option<PeerAddr> = inbox.cloned();
    let mut set = tokio::task::JoinSet::new();
    for addr in recipients {
        let ep = Arc::clone(endpoint);
        let msg = Arc::clone(&msg);
        let addr = addr.clone();
        let inbox = inbox_owned.clone();
        set.spawn(async move {
            crate::group::transport::send_one_with_inbox(
                ep.as_ref(),
                &addr,
                &msg,
                inbox.as_ref(),
            )
            .await
        });
    }
    let mut first_err: Option<GroupError> = None;
    while let Some(join_res) = set.join_next().await {
        match join_res {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                let ge = match e {
                    crate::group::transport::FramingError::Transport(p) => {
                        GroupError::Transport(p)
                    }
                    other => GroupError::Backend(format!("{label}: {other}")),
                };
                if first_err.is_none() {
                    first_err = Some(ge);
                }
            }
            Err(je) => {
                if first_err.is_none() {
                    first_err = Some(GroupError::Backend(format!("{label} join: {je}")));
                }
            }
        }
    }
    match first_err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p::backend::mock::MockNetwork;
    use crate::p2p::{P2pProtocol, PeerId};
    use mls_rs::ExtensionList;
    use std::time::Duration;
    use tempfile::tempdir;

    const PROTO_MLS: P2pProtocol = P2pProtocol(b"nkct/mls/1");

    // ---- F8: per-group serialization of load → mutate → persist ----------

    /// A second waiter on the SAME group cannot enter the critical section
    /// while the first holds it, and enters as soon as it is released.
    /// Ordering is fixed with a `Notify`, not with sleeps.
    #[tokio::test]
    async fn same_group_waiters_are_serialized() {
        let (proc, _dir) = build_proc("alice", 1);
        let proc = Arc::new(proc);
        let gid = [1u8; 32];

        let held = proc.lock_group(&gid).await;

        let entered = Arc::new(tokio::sync::Notify::new());
        let waiter = {
            let (p, entered) = (proc.clone(), entered.clone());
            tokio::spawn(async move {
                let _g = p.lock_group(&gid).await;
                entered.notify_one();
            })
        };

        // With the lock held, the waiter must not get in. `notified()` is
        // polled once; a ready notification here would mean it did.
        tokio::task::yield_now().await;
        assert!(
            tokio::time::timeout(Duration::from_millis(200), entered.notified())
                .await
                .is_err(),
            "a second task entered the critical section while the group was locked"
        );

        drop(held);
        tokio::time::timeout(Duration::from_secs(5), entered.notified())
            .await
            .expect("waiter never acquired the lock after it was released");
        waiter.await.unwrap();
    }

    /// Holding one group's lock must not stall an unrelated group.
    #[tokio::test]
    async fn different_groups_stay_parallel() {
        let (proc, _dir) = build_proc("alice", 1);
        let held = proc.lock_group(&[1u8; 32]).await;
        let other = tokio::time::timeout(Duration::from_secs(5), proc.lock_group(&[2u8; 32])).await;
        assert!(
            other.is_ok(),
            "an unrelated group blocked on another group's lock"
        );
        drop(other);
        drop(held);
    }

    // ---- F4: the group lock must NOT span the fan-out --------------------

    /// `send_application_message` must release the group guard before it
    /// starts talking to recipients. Otherwise one silent member holds the
    /// group's mutation lock for the whole linger window, and every other
    /// task that needs the group — including the inbound path that would
    /// apply the Commit evicting that very member — is stuck behind it.
    ///
    /// The synchronisation here is an ordering, not a sleep: Bob's `accept()`
    /// resolves only once Alice has dialled him, which happens *after* the
    /// load → encrypt → persist section. So when it returns we know Alice is
    /// inside the fan-out, and the lock must be free at that instant. Bob
    /// then never reads the frame and never ACKs, which is exactly the
    /// hostile behaviour the finding describes.
    #[tokio::test]
    async fn send_releases_group_lock_before_fanout() {
        let net = MockNetwork::new();
        let (alice, _da) = build_proc_on_net(&net, "alice", 1);
        let bob_id = PeerId::new([2u8; 32]);
        // Registered so the dial succeeds — but we never service his inbox.
        let bob_ep = net.register(bob_id, vec![PROTO_MLS]);

        let alice = Arc::new(alice);
        let gid = alice.create_group().await.expect("create_group");

        let sender = {
            let (a, gid) = (alice.clone(), gid.clone());
            tokio::spawn(async move {
                a.send_application_message(&gid, b"hello", &[PeerAddr::new(bob_id)])
                    .await
            })
        };

        // Proof that Alice is past the critical section and inside the fan-out.
        let _pending = tokio::time::timeout(Duration::from_secs(10), bob_ep.accept())
            .await
            .expect("Alice never dialled the recipient")
            .expect("accept failed");

        // The whole point: with Bob stalled, this must not wait on him.
        let guard = tokio::time::timeout(
            Duration::from_secs(2),
            alice.lock_group(gid.as_bytes()),
        )
        .await
        .expect("send_application_message held the group lock across the fan-out");
        drop(guard);

        // And the send itself still finishes once the linger expires.
        let _ = tokio::time::timeout(Duration::from_secs(60), sender)
            .await
            .expect("send never completed");
    }

    /// The narrowed scope must not lose F8: the critical section itself is
    /// still serialized, so a send cannot interleave with another task's
    /// load → mutate → persist cycle for the same group.
    #[tokio::test]
    async fn send_still_waits_for_the_group_lock() {
        let net = MockNetwork::new();
        let (alice, _da) = build_proc_on_net(&net, "alice", 1);
        let bob_id = PeerId::new([2u8; 32]);
        let _bob_ep = net.register(bob_id, vec![PROTO_MLS]);

        let alice = Arc::new(alice);
        let gid = alice.create_group().await.expect("create_group");

        let held = alice.lock_group(gid.as_bytes()).await;

        let sender = {
            let (a, gid) = (alice.clone(), gid.clone());
            tokio::spawn(async move {
                a.send_application_message(&gid, b"hello", &[PeerAddr::new(bob_id)])
                    .await
            })
        };

        tokio::task::yield_now().await;
        assert!(
            !sender.is_finished(),
            "a send entered the critical section while the group was locked"
        );

        drop(held);
        let _ = tokio::time::timeout(Duration::from_secs(60), sender)
            .await
            .expect("send never completed after the lock was released");
    }

    /// Concurrent first-acquisition must converge on ONE mutex per group —
    /// otherwise each caller would lock a private mutex and exclude nothing.
    #[tokio::test]
    async fn concurrent_first_acquisition_shares_one_mutex() {
        let (proc, _dir) = build_proc("alice", 1);
        let proc = Arc::new(proc);
        let gid = [7u8; 32];

        let barrier = Arc::new(tokio::sync::Barrier::new(16));
        let mut handles = Vec::new();
        for _ in 0..16 {
            let (p, barrier) = (proc.clone(), barrier.clone());
            handles.push(tokio::spawn(async move {
                barrier.wait().await; // fix the race point
                p.group_lock_arc(&gid)
            }));
        }
        let mut arcs = Vec::new();
        for h in handles {
            arcs.push(h.await.unwrap());
        }
        for a in &arcs[1..] {
            assert!(
                Arc::ptr_eq(&arcs[0], a),
                "the table handed out more than one mutex for the same group"
            );
        }
        assert_eq!(proc.group_locks.lock().unwrap().len(), 1);
    }

    /// The table holds only `Weak`s, so a released lock becomes unupgradable
    /// and its entry is swept — it cannot grow without bound over a session.
    #[tokio::test]
    async fn released_locks_are_reclaimed() {
        let (proc, _dir) = build_proc("alice", 1);
        let gid = [9u8; 32];

        // (1) While a strong reference lives, the same group yields the same Arc.
        let a = proc.group_lock_arc(&gid);
        let b = proc.group_lock_arc(&gid);
        assert!(Arc::ptr_eq(&a, &b));

        // (2) Once every strong reference is dropped, the table's Weak expires.
        let weak = Arc::downgrade(&a);
        drop(a);
        drop(b);
        assert!(
            weak.upgrade().is_none(),
            "the table kept a strong reference to a released lock"
        );

        // (3) A later acquisition mints a fresh Arc — and concurrent callers at
        //     that point again converge on it.
        let c = proc.group_lock_arc(&gid);
        assert!(
            weak.upgrade().is_none(),
            "the expired lock must not come back"
        );
        let d = proc.group_lock_arc(&gid);
        assert!(Arc::ptr_eq(&c, &d));
        drop(c);
        drop(d);

        for i in 0..200u8 {
            let _g = proc.lock_group(&[i; 32]).await;
        }
        // The next acquisition's retain() sweeps every dangling Weak.
        let _g = proc.lock_group(&[255u8; 32]).await;
        let live = proc.group_locks.lock().unwrap().len();
        assert!(
            live <= 2,
            "lock table retained {live} entries for released locks"
        );
    }

    /// Test helper: build a `GroupChatProcessor` with a freshly
    /// registered mock endpoint and a sqlite database backed by a
    /// tempdir. The endpoint is not exercised by most tests (its only
    /// purpose is to satisfy the `new` signature) — the `peer_byte`
    /// parameter just lets the caller distinguish PeerIds.
    ///
    /// Returns the processor *and* the tempdir guard. Drop the guard
    /// only after dropping the processor, since the sqlite file lives
    /// inside it.
    fn build_proc(
        display_name: &str,
        peer_byte: u8,
    ) -> (GroupChatProcessor, tempfile::TempDir) {
        let dir = tempdir().expect("tempdir");
        let storage = GroupStorage::open_at(
            dir.path().join("groups.db"),
            crate::group::storage::test_passphrase(),
        )
        .expect("storage");
        let net = MockNetwork::new();
        let ep = net.register(PeerId::new([peer_byte; 32]), vec![PROTO_MLS]);
        let proc =
            GroupChatProcessor::new(display_name, Arc::new(ep), storage, None).expect("builder");
        (proc, dir)
    }

    /// Test helper: build a `GroupChatProcessor` against a *shared*
    /// `MockNetwork` so two processors can reach each other via
    /// `endpoint.connect` / `endpoint.accept`. Used by P4 integration
    /// tests that need actual transport routing.
    fn build_proc_on_net(
        net: &Arc<MockNetwork>,
        display_name: &str,
        peer_byte: u8,
    ) -> (GroupChatProcessor, tempfile::TempDir) {
        let dir = tempdir().expect("tempdir");
        let storage = GroupStorage::open_at(
            dir.path().join("groups.db"),
            crate::group::storage::test_passphrase(),
        )
        .expect("storage");
        let ep = net.register(PeerId::new([peer_byte; 32]), vec![PROTO_MLS]);
        let proc =
            GroupChatProcessor::new(display_name, Arc::new(ep), storage, None).expect("builder");
        (proc, dir)
    }

    /// Smoke test inherited from P1: build a processor, create a group,
    /// confirm the GroupId is non-zero.
    #[tokio::test]
    async fn create_group_smoke() {
        let (proc, _dir) = build_proc("alice", 1);
        let gid = proc.create_group().await.expect("create_group");
        assert_ne!(gid.as_bytes(), &[0u8; 32]);
    }

    /// P2 acceptance: create a group, drop the processor, open a new
    /// processor against the *same* sqlite file, and confirm the group
    /// is still there with the same state.
    ///
    /// This exercises the full persistence path: `write_to_storage`,
    /// `list_group_ids` against the `mls_group` table, and `load_group`
    /// re-decoding the snapshot. If any of those is misconfigured —
    /// schema not created, journal mode rejecting the file, snapshot
    /// codec mismatch — this fails.
    #[tokio::test]
    async fn create_drop_reload_persists_group() {
        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("groups.db");

        // ---- session 1: create + persist ---------------------------
        let gid_before;
        {
            let storage = GroupStorage::open_at(
                &db_path,
                crate::group::storage::test_passphrase(),
            )
            .expect("storage 1");
            let net = MockNetwork::new();
            let ep = net.register(PeerId::new([1; 32]), vec![PROTO_MLS]);
            let proc = GroupChatProcessor::new("alice", Arc::new(ep), storage, None)
                .expect("builder 1");
            gid_before = proc.create_group().await.expect("create_group");
            // Drop the whole processor — including its Client, signing
            // key (zeroized by mls-rs), and storage handle. The sqlite
            // file remains.
        }

        // ---- session 2: reload at the same path --------------------
        let storage = GroupStorage::open_at(
            &db_path,
            crate::group::storage::test_passphrase(),
        )
        .expect("storage 2");
        let net = MockNetwork::new();
        let ep = net.register(PeerId::new([2; 32]), vec![PROTO_MLS]);
        // New signing identity (the original one is gone). That is OK
        // for read-only inspection; sending into the group from this
        // processor would fail authentication, but the round-trip we
        // care about is state reconstruction.
        let proc = GroupChatProcessor::new("alice-reloaded", Arc::new(ep), storage, None)
            .expect("builder 2");

        let listed = proc.list_groups().expect("list_groups");
        assert_eq!(
            listed,
            vec![gid_before],
            "exactly one persisted group should be visible after reload"
        );

        let summary = proc
            .load_group_summary(&gid_before)
            .await
            .expect("load_group_summary");
        assert_eq!(summary.id, gid_before);
        assert_eq!(summary.epoch, 0, "fresh group is at epoch 0");
        assert_eq!(
            summary.member_count, 1,
            "fresh group has exactly one member (the creator)"
        );
    }

    /// Loading a non-existent group_id must return `NotFound`, not a
    /// generic Backend error — callers want to distinguish missing
    /// from corrupt.
    #[tokio::test]
    async fn load_unknown_group_returns_not_found() {
        let (proc, _dir) = build_proc("alice", 1);
        let bogus = GroupId::new([0xFF; 32]);
        let err = proc.load_group_summary(&bogus).await.unwrap_err();
        assert!(
            matches!(err, GroupError::NotFound),
            "expected NotFound, got: {err:?}"
        );
    }

    /// P3 acceptance: the byte-oriented public surface
    /// (`export_key_package` → `add_member` → `join_group_from_welcome`)
    /// round-trips a 2-member group via flat byte buffers — the same
    /// shape P4 will move over the `nkct/mls/1` ALPN.
    ///
    /// Verifies durability at every step: Alice's add_member persists
    /// the post-commit state, Bob's join_group_from_welcome persists
    /// the just-joined state. After both peers' processors are dropped
    /// and reloaded against the same sqlite files, the group is still
    /// visible on both sides.
    #[tokio::test]
    async fn export_keypackage_add_member_join_roundtrip() {
        let dir_a = tempdir().expect("tempdir alice");
        let dir_b = tempdir().expect("tempdir bob");
        let path_a = dir_a.path().join("alice.db");
        let path_b = dir_b.path().join("bob.db");

        let net = MockNetwork::new();
        let alice_ep = net.register(PeerId::new([1; 32]), vec![PROTO_MLS]);
        let bob_ep = net.register(PeerId::new([2; 32]), vec![PROTO_MLS]);

        let alice = GroupChatProcessor::new(
            "alice",
            Arc::new(alice_ep),
            GroupStorage::open_at(&path_a, crate::group::storage::test_passphrase())
                .expect("alice storage"),
            None,
        )
        .expect("alice processor");
        let bob = GroupChatProcessor::new(
            "bob",
            Arc::new(bob_ep),
            GroupStorage::open_at(&path_b, crate::group::storage::test_passphrase())
                .expect("bob storage"),
            None,
        )
        .expect("bob processor");

        // Bob publishes a KeyPackage as a flat byte blob.
        let bob_kp = bob.export_key_package().await.expect("bob export");
        // KeyPackages are non-trivial in size — sanity check that we
        // got something on the same order as the hybrid sizes
        // (X25519+ML-KEM-768 ≈ 1.2 KiB just for init_key) without
        // pinning an exact number (mls-rs may evolve the encoding).
        assert!(
            bob_kp.len() > 1_000,
            "hybrid KeyPackage should be at least ~1 KiB, got {}",
            bob_kp.len()
        );

        // Alice creates a group and admits Bob.
        let gid = alice.create_group().await.expect("alice create_group");
        let added = alice
            .add_member(&gid, &bob_kp)
            .await
            .expect("alice add_member");

        // Alice's state advanced to epoch 1 with 2 members; this is
        // persisted by add_member's write_to_storage.
        let alice_summary = alice
            .load_group_summary(&gid)
            .await
            .expect("alice load_group_summary");
        assert_eq!(alice_summary.epoch, 1);
        assert_eq!(alice_summary.member_count, 2);

        // Bob joins via the Welcome blob. Commit is not delivered here
        // because there are no pre-existing members to inform (this is
        // a group of 1 → 2).
        let bob_gid = bob
            .join_group_from_welcome(&added.welcome)
            .await
            .expect("bob join_group_from_welcome");
        assert_eq!(bob_gid, gid, "both peers must agree on GroupId");

        let bob_summary = bob
            .load_group_summary(&bob_gid)
            .await
            .expect("bob load_group_summary");
        assert_eq!(bob_summary.epoch, 1);
        assert_eq!(bob_summary.member_count, 2);

        // Drop both processors, then reopen against the same sqlite
        // files. Both must still see the group.
        drop(alice);
        drop(bob);

        let alice2 = GroupChatProcessor::new(
            "alice",
            Arc::new(net.register(PeerId::new([3; 32]), vec![PROTO_MLS])),
            GroupStorage::open_at(&path_a, crate::group::storage::test_passphrase())
                .expect("alice storage 2"),
            None,
        )
        .expect("alice processor 2");
        let bob2 = GroupChatProcessor::new(
            "bob",
            Arc::new(net.register(PeerId::new([4; 32]), vec![PROTO_MLS])),
            GroupStorage::open_at(&path_b, crate::group::storage::test_passphrase())
                .expect("bob storage 2"),
            None,
        )
        .expect("bob processor 2");

        assert_eq!(alice2.list_groups().expect("alice2 list"), vec![gid]);
        assert_eq!(bob2.list_groups().expect("bob2 list"), vec![gid]);
    }

    /// `add_member` against a GroupId not in storage must surface
    /// `NotFound`, not a generic Backend error.
    #[tokio::test]
    async fn add_member_on_unknown_group_is_not_found() {
        let (alice, _dir_a) = build_proc("alice", 1);
        let (bob, _dir_b) = build_proc("bob", 2);
        let bob_kp = bob.export_key_package().await.expect("bob export");
        let bogus_gid = GroupId::new([0xAB; 32]);
        let err = alice.add_member(&bogus_gid, &bob_kp).await.unwrap_err();
        assert!(matches!(err, GroupError::NotFound), "got: {err:?}");
    }

    /// `join_group_from_welcome` on something that is *not* a Welcome
    /// (e.g. another KeyPackage) must surface `InvalidWelcome`, not
    /// a Backend error. This is what would happen if a peer sends the
    /// wrong message type over `nkct/mls/1`.
    #[tokio::test]
    async fn join_group_with_keypackage_bytes_is_invalid_welcome() {
        let (bob, _dir) = build_proc("bob", 2);
        let bob_kp = bob.export_key_package().await.expect("bob export");
        // Feed Bob his own KeyPackage as if it were a Welcome — same
        // wire encoding namespace, different WireFormat tag inside.
        let err = bob
            .join_group_from_welcome(&bob_kp)
            .await
            .unwrap_err();
        match err {
            GroupError::InvalidWelcome(msg) => {
                assert!(
                    msg.contains("WireFormat") || msg.contains("Welcome"),
                    "expected wire-format mismatch detail, got: {msg}"
                );
            }
            other => panic!("expected InvalidWelcome, got: {other:?}"),
        }
    }

    /// `join_group_from_welcome` on a totally bogus byte sequence must
    /// also surface `InvalidWelcome`, not panic and not produce a
    /// generic Backend error.
    #[tokio::test]
    async fn join_group_with_garbage_bytes_is_invalid_welcome() {
        let (bob, _dir) = build_proc("bob", 2);
        let garbage = b"this is not even an MLS message";
        let err = bob.join_group_from_welcome(garbage).await.unwrap_err();
        assert!(
            matches!(err, GroupError::InvalidWelcome(_)),
            "got: {err:?}"
        );
    }

    /// P4 acceptance: 2-node Welcome delivery over `nkct/mls/1`.
    ///
    /// End-to-end shape: Bob publishes a KeyPackage, Alice creates a
    /// group + adds Bob (producing a Welcome blob), Alice opens a
    /// `nkct/mls/1` stream to Bob and sends the Welcome, Bob's
    /// `accept_welcome` reads the frame and joins.
    ///
    /// This is the integration test the plan §P4 calls out: "2 ノード間
    /// で実際に Welcome 配信成功". The `MockEndpoint` substitutes for
    /// iroh, but the framing and dispatch code paths exercised here
    /// are exactly the ones that run against iroh in production.
    #[tokio::test]
    async fn welcome_delivery_over_alpn_mls_2_node() {
        let net = MockNetwork::new();
        let (alice, _dir_a) = build_proc_on_net(&net, "alice", 1);
        let (bob, _dir_b) = build_proc_on_net(&net, "bob", 2);
        let bob_addr = bob.local_addr().await.expect("bob addr");

        // Bob exports a KeyPackage (out-of-band — for this test, we
        // just hand the bytes to Alice in-process).
        let bob_kp = bob.export_key_package().await.expect("bob export");

        // Alice creates a group and admits Bob, then sends the Welcome
        // over the `nkct/mls/1` ALPN.
        let gid = alice.create_group().await.expect("create_group");
        let added = alice
            .add_member(&gid, &bob_kp)
            .await
            .expect("add_member");

        // Bob's accept task — spawned *before* Alice sends so the
        // `accept().await` is already pending when the stream arrives.
        let bob_task = tokio::spawn(async move {
            let joined_gid = bob.accept_welcome().await.expect("accept_welcome");
            let summary = bob
                .load_group_summary(&joined_gid)
                .await
                .expect("bob summary");
            (joined_gid, summary, bob)
        });

        // Give Bob a moment to park in accept() — not strictly required
        // (MockNetwork queues the connection), but makes the intent
        // obvious and matches the production code path's ordering.
        tokio::task::yield_now().await;

        alice
            .send_welcome_to(&bob_addr, &added.welcome)
            .await
            .expect("send_welcome_to");

        let (bob_gid, bob_summary, _bob_kept_alive) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            bob_task,
        )
        .await
        .expect("bob join timed out")
        .expect("bob task joined");

        assert_eq!(bob_gid, gid, "both peers must agree on GroupId");
        assert_eq!(bob_summary.epoch, 1);
        assert_eq!(bob_summary.member_count, 2);

        let alice_summary = alice
            .load_group_summary(&gid)
            .await
            .expect("alice summary");
        assert_eq!(alice_summary.epoch, 1);
        assert_eq!(alice_summary.member_count, 2);
    }

    /// P5 acceptance: 3-member application message round-trip.
    ///
    /// Builds a 3-member group (Alice creates, adds Bob, then Carol —
    /// with the second add's Commit broadcast to Bob so all peers reach
    /// epoch 2). Then Alice broadcasts an application message and both
    /// recipients decrypt it; finally Bob sends one in the other
    /// direction and Alice + Carol both decrypt that too.
    ///
    /// This exercises the whole P5 surface end-to-end:
    /// - `add_member` returning both Welcome and Commit
    /// - `broadcast_commit` advancing existing members
    /// - `accept_next` dispatching `NewGroup` / `EpochAdvanced` /
    ///   `Message` events
    /// - `send_application_message` fanning out N-1 unicast streams
    ///
    /// Each peer's accept calls run on a spawned task that returns
    /// the peer's processor back; tests serialize the dispatch by
    /// joining-then-respawning rather than running multiple accepts
    /// in parallel (MockEndpoint's inbox is a single-consumer mpsc).
    #[tokio::test]
    async fn three_member_message_roundtrip() {
        let net = MockNetwork::new();
        let (alice, _dir_a) = build_proc_on_net(&net, "alice", 1);
        let (bob, _dir_b) = build_proc_on_net(&net, "bob", 2);
        let (carol, _dir_c) = build_proc_on_net(&net, "carol", 3);
        let alice_addr = alice.local_addr().await.expect("alice addr");
        let bob_addr = bob.local_addr().await.expect("bob addr");
        let carol_addr = carol.local_addr().await.expect("carol addr");

        let bob_kp = bob.export_key_package().await.expect("bob export");
        let carol_kp = carol.export_key_package().await.expect("carol export");

        // ---- 1) Alice creates and admits Bob (1 → 2) -------------------
        let gid = alice.create_group().await.expect("create_group");
        let add_bob = alice
            .add_member(&gid, &bob_kp)
            .await
            .expect("alice add bob");

        // Bob accepts the Welcome.
        let bob = {
            let bob_task = tokio::spawn(async move {
                let evt = bob.accept_next().await.expect("bob accept welcome");
                (evt, bob)
            });
            tokio::task::yield_now().await;
            alice
                .send_welcome_to(&bob_addr, &add_bob.welcome)
                .await
                .expect("send welcome to bob");
            let (evt, bob) = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                bob_task,
            )
            .await
            .expect("bob welcome timed out")
            .expect("bob task joined");
            match evt {
                IncomingGroupEvent::NewGroup { id } => assert_eq!(id, gid),
                other => panic!("bob expected NewGroup, got {other:?}"),
            }
            bob
        };
        // 1 → 2 transition: no existing members to inform; commit
        // broadcast is a no-op. Verify the API tolerates an empty
        // recipient slice.
        alice
            .broadcast_commit(&add_bob.commit, &[])
            .await
            .expect("empty broadcast");

        // ---- 2) Alice admits Carol (2 → 3) -----------------------------
        let add_carol = alice
            .add_member(&gid, &carol_kp)
            .await
            .expect("alice add carol");

        // Bob processes the Commit (so he advances to epoch 2) while
        // Carol processes the Welcome (so she joins at epoch 2).
        let bob_task = tokio::spawn(async move {
            let evt = bob.accept_next().await.expect("bob accept commit");
            (evt, bob)
        });
        let carol_task = tokio::spawn(async move {
            let evt = carol.accept_next().await.expect("carol accept welcome");
            (evt, carol)
        });
        tokio::task::yield_now().await;

        // Fire both Welcome (to Carol) and Commit (to Bob) — order
        // doesn't matter for these two recipients, but we send the
        // Welcome first to match the plan §7.5 sequence diagram.
        alice
            .send_welcome_to(&carol_addr, &add_carol.welcome)
            .await
            .expect("send welcome to carol");
        alice
            .broadcast_commit(&add_carol.commit, &[bob_addr.clone()])
            .await
            .expect("broadcast commit to bob");

        let (bob_evt, bob) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            bob_task,
        )
        .await
        .expect("bob commit timed out")
        .expect("bob task joined");
        let (carol_evt, carol) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            carol_task,
        )
        .await
        .expect("carol welcome timed out")
        .expect("carol task joined");

        match bob_evt {
            IncomingGroupEvent::EpochAdvanced { group_id, new_epoch } => {
                assert_eq!(group_id, gid);
                assert_eq!(new_epoch, 2);
            }
            other => panic!("bob expected EpochAdvanced(2), got {other:?}"),
        }
        match carol_evt {
            IncomingGroupEvent::NewGroup { id } => assert_eq!(id, gid),
            other => panic!("carol expected NewGroup, got {other:?}"),
        }

        // All three peers should agree on epoch 2 / 3 members.
        for (name, proc) in [("alice", &alice), ("bob", &bob), ("carol", &carol)] {
            let s = proc.load_group_summary(&gid).await.expect("summary");
            assert_eq!(s.epoch, 2, "{name} epoch mismatch");
            assert_eq!(s.member_count, 3, "{name} member_count mismatch");
        }

        // ---- 3) Alice sends an application message -----------------
        let bob_task = tokio::spawn(async move {
            let evt = bob.accept_next().await.expect("bob accept alice's msg");
            (evt, bob)
        });
        let carol_task = tokio::spawn(async move {
            let evt = carol.accept_next().await.expect("carol accept alice's msg");
            (evt, carol)
        });
        tokio::task::yield_now().await;

        let body_from_alice = b"hello from alice".to_vec();
        let _wire = alice
            .send_application_message(
                &gid,
                &body_from_alice,
                &[bob_addr.clone(), carol_addr.clone()],
            )
            .await
            .expect("alice send app msg");

        let (bob_evt, bob) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            bob_task,
        )
        .await
        .expect("bob app msg timed out")
        .expect("bob task joined");
        let (carol_evt, carol) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            carol_task,
        )
        .await
        .expect("carol app msg timed out")
        .expect("carol task joined");

        for (name, evt) in [("bob", bob_evt), ("carol", carol_evt)] {
            match evt {
                IncomingGroupEvent::Message {
                    group_id,
                    body,
                    sender_index: _,
                } => {
                    assert_eq!(group_id, gid, "{name} group_id mismatch");
                    assert_eq!(body, body_from_alice, "{name} body mismatch");
                }
                other => panic!("{name} expected Message, got {other:?}"),
            }
        }

        // ---- 4) Bob sends in reverse direction ---------------------
        let alice_task = tokio::spawn(async move {
            let evt = alice.accept_next().await.expect("alice accept bob's msg");
            (evt, alice)
        });
        let carol_task = tokio::spawn(async move {
            let evt = carol.accept_next().await.expect("carol accept bob's msg");
            (evt, carol)
        });
        tokio::task::yield_now().await;

        let body_from_bob = b"reply from bob".to_vec();
        let _wire = bob
            .send_application_message(
                &gid,
                &body_from_bob,
                &[alice_addr.clone(), carol_addr.clone()],
            )
            .await
            .expect("bob send app msg");

        let (alice_evt, _alice) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            alice_task,
        )
        .await
        .expect("alice app msg timed out")
        .expect("alice task joined");
        let (carol_evt, _carol) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            carol_task,
        )
        .await
        .expect("carol app msg timed out")
        .expect("carol task joined");

        for (name, evt) in [("alice", alice_evt), ("carol", carol_evt)] {
            match evt {
                IncomingGroupEvent::Message { body, .. } => {
                    assert_eq!(body, body_from_bob, "{name} body mismatch");
                }
                other => panic!("{name} expected Message, got {other:?}"),
            }
        }
    }

    /// MLS PrivateMessages are NOT self-decryptable. Sending an
    /// application message from Alice to herself (via her own loopback
    /// PeerAddr) must surface as a Backend error from
    /// `process_incoming_message` — RFC 9420 §15.1. The point of this
    /// test is to pin that property so the caller knows it must echo
    /// to its own UI separately, not via the MLS pipeline.
    #[tokio::test]
    async fn self_send_does_not_self_decrypt() {
        // 2-member group: Alice + Bob. Alice tries to receive what she
        // just encrypted by feeding her own address into the recipient
        // list. mls-rs raises a decrypt error.
        let net = MockNetwork::new();
        let (alice, _dir_a) = build_proc_on_net(&net, "alice", 1);
        let (bob, _dir_b) = build_proc_on_net(&net, "bob", 2);
        let alice_addr = alice.local_addr().await.expect("alice addr");
        let bob_addr = bob.local_addr().await.expect("bob addr");

        let bob_kp = bob.export_key_package().await.expect("bob export");
        let gid = alice.create_group().await.expect("create_group");
        let added = alice.add_member(&gid, &bob_kp).await.expect("add bob");

        // Drive Bob's join through the wire.
        let bob_task = tokio::spawn(async move {
            let evt = bob.accept_next().await.expect("bob accept welcome");
            (evt, bob)
        });
        tokio::task::yield_now().await;
        alice
            .send_welcome_to(&bob_addr, &added.welcome)
            .await
            .expect("welcome send");
        let (_bob_evt, bob) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            bob_task,
        )
        .await
        .expect("bob welcome timed out")
        .expect("bob task joined");

        // P9 framing change: send_application_message now waits for
        // the receiver's ACK byte before returning (so the sender's
        // iroh endpoint doesn't drop while the receiver is still
        // reading). For this test to make progress, Bob must be in
        // an accept loop when Alice sends — spawn one.
        let bob_recv_task = tokio::spawn(async move {
            let _ = bob.accept_next().await;
        });
        tokio::task::yield_now().await;

        // Alice sends an application message to Bob. The interesting
        // assertion isn't the delivery to Bob (we know that works
        // from `three_member_message_roundtrip`); it's that the
        // SAME wire bytes, fed back into Alice's own MLS state, fail
        // to decrypt — the RFC 9420 §15.1 self-decrypt prohibition.
        let wire = alice
            .send_application_message(&gid, b"echo to me", &[bob_addr.clone()])
            .await
            .expect("alice send");
        // Bob's task is no longer needed; abort so it doesn't keep
        // the runtime alive past test completion.
        bob_recv_task.abort();

        // Now try to feed `wire` back into alice via mls-rs directly.
        // We reach into the internal client; this is a test-only check.
        let msg = MlsMessage::from_bytes(&wire).expect("decode self msg");
        let mut alice_group = alice
            .client
            .load_group(gid.as_bytes())
            .expect("alice load group");
        // mls-rs raises `CantProcessMessageFromSelf` (or equivalent).
        let res = alice_group.process_incoming_message(msg);
        assert!(
            res.is_err(),
            "self-decrypt MUST fail, got Ok({:?})",
            res.unwrap()
        );
        // Silence unused.
        let _ = alice_addr;
    }

    /// P6 acceptance: remove a member and verify
    /// post-compromise-security holds — the removed member cannot
    /// decrypt application messages at the new epoch.
    ///
    /// Sequence:
    /// 1. 3-member group (Alice creates, adds Bob, adds Carol → epoch 2)
    /// 2. Alice removes Bob — Commit broadcast to BOTH Bob (so he
    ///    learns he's been kicked) and Carol (so she advances epoch)
    /// 3. Bob's `accept_next` returns
    ///    [`IncomingGroupEvent::RemovedFromGroup`]; Carol's returns
    ///    [`IncomingGroupEvent::EpochAdvanced`]
    /// 4. Alice sends an application message addressed to Carol only
    /// 5. Carol decrypts successfully (epoch 3)
    /// 6. Feed the *same wire bytes* into Bob's group state — must
    ///    fail. This is the PCS property: Bob, who held the epoch-2
    ///    key schedule and was admitted to the post-removal
    ///    membership-change commit, gets no useful key material for
    ///    epoch 3.
    #[tokio::test]
    async fn remove_member_blocks_new_epoch_decrypt() {
        let net = MockNetwork::new();
        let (alice, _dir_a) = build_proc_on_net(&net, "alice", 1);
        let (bob, _dir_b) = build_proc_on_net(&net, "bob", 2);
        let (carol, _dir_c) = build_proc_on_net(&net, "carol", 3);
        let bob_addr = bob.local_addr().await.expect("bob addr");
        let carol_addr = carol.local_addr().await.expect("carol addr");

        let bob_kp = bob.export_key_package().await.expect("bob kp");
        let carol_kp = carol.export_key_package().await.expect("carol kp");

        // ---- build 3-member group --------------------------------------
        let gid = alice.create_group().await.expect("create_group");

        // Add Bob (1 → 2).
        let add_bob = alice.add_member(&gid, &bob_kp).await.expect("add bob");
        let bob = {
            let task = tokio::spawn(async move {
                bob.accept_next().await.expect("bob accepts welcome");
                bob
            });
            tokio::task::yield_now().await;
            alice
                .send_welcome_to(&bob_addr, &add_bob.welcome)
                .await
                .expect("welcome→bob");
            tokio::time::timeout(std::time::Duration::from_secs(5), task)
                .await
                .expect("bob welcome timeout")
                .expect("bob task")
        };

        // Add Carol (2 → 3). Commit goes to Bob, Welcome to Carol.
        let add_carol = alice
            .add_member(&gid, &carol_kp)
            .await
            .expect("add carol");
        let bob_task = tokio::spawn(async move {
            bob.accept_next().await.expect("bob accepts commit");
            bob
        });
        let carol_task = tokio::spawn(async move {
            carol.accept_next().await.expect("carol accepts welcome");
            carol
        });
        tokio::task::yield_now().await;
        alice
            .send_welcome_to(&carol_addr, &add_carol.welcome)
            .await
            .expect("welcome→carol");
        alice
            .broadcast_commit(&add_carol.commit, &[bob_addr.clone()])
            .await
            .expect("commit→bob");
        let bob = tokio::time::timeout(std::time::Duration::from_secs(5), bob_task)
            .await
            .expect("bob commit timeout")
            .expect("bob task");
        let carol = tokio::time::timeout(std::time::Duration::from_secs(5), carol_task)
            .await
            .expect("carol welcome timeout")
            .expect("carol task");

        // ---- identify Bob's leaf index from Alice's roster -------------
        let alice_members = alice.list_members(&gid).await.expect("alice roster");
        assert_eq!(
            alice_members.len(),
            3,
            "Alice's roster should be 3 members"
        );
        // Alice is leaf 0 (she created the group). Bob is leaf 1
        // (added first). Carol is leaf 2 (added second). Pin those
        // expectations so a mls-rs leaf-allocation change shows up
        // here clearly.
        assert_eq!(
            alice_members.iter().map(|m| m.index).collect::<Vec<_>>(),
            vec![0, 1, 2],
        );
        let bob_leaf = 1u32;

        // ---- remove Bob (epoch 2 → 3) ----------------------------------
        let remove_commit = alice
            .remove_member(&gid, bob_leaf)
            .await
            .expect("alice remove bob");

        // Broadcast the Remove commit to BOTH the removed member (Bob,
        // so he learns) and the surviving members (Carol, so she
        // advances). Plan §7.4 calls out this delivery shape.
        let bob_task = tokio::spawn(async move {
            let evt = bob.accept_next().await.expect("bob accepts remove");
            (evt, bob)
        });
        let carol_task = tokio::spawn(async move {
            let evt = carol.accept_next().await.expect("carol accepts remove commit");
            (evt, carol)
        });
        tokio::task::yield_now().await;
        alice
            .broadcast_commit(&remove_commit, &[bob_addr.clone(), carol_addr.clone()])
            .await
            .expect("remove commit broadcast");

        let (bob_evt, bob) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            bob_task,
        )
        .await
        .expect("bob remove timeout")
        .expect("bob task");
        let (carol_evt, carol) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            carol_task,
        )
        .await
        .expect("carol remove-commit timeout")
        .expect("carol task");

        // Bob sees RemovedFromGroup; Carol sees EpochAdvanced.
        match bob_evt {
            IncomingGroupEvent::RemovedFromGroup {
                group_id,
                remover_index,
            } => {
                assert_eq!(group_id, gid);
                assert_eq!(remover_index, 0, "Alice is leaf 0");
            }
            other => panic!("bob expected RemovedFromGroup, got {other:?}"),
        }
        match carol_evt {
            IncomingGroupEvent::EpochAdvanced {
                group_id,
                new_epoch,
            } => {
                assert_eq!(group_id, gid);
                assert_eq!(new_epoch, 3, "epoch advances to 3 on remove");
            }
            other => panic!("carol expected EpochAdvanced(3), got {other:?}"),
        }
        // Alice is also at epoch 3 (her own remove_member advanced
        // her state).
        let alice_summary = alice
            .load_group_summary(&gid)
            .await
            .expect("alice summary");
        assert_eq!(alice_summary.epoch, 3);
        assert_eq!(alice_summary.member_count, 2);

        // ---- Alice sends an application message to Carol ----------------
        let carol_task = tokio::spawn(async move {
            let evt = carol
                .accept_next()
                .await
                .expect("carol accepts alice app msg");
            (evt, carol)
        });
        tokio::task::yield_now().await;

        let body = b"post-remove message".to_vec();
        let wire = alice
            .send_application_message(&gid, &body, &[carol_addr.clone()])
            .await
            .expect("alice send post-remove");

        // Carol decrypts cleanly.
        let (carol_evt, _carol) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            carol_task,
        )
        .await
        .expect("carol app msg timeout")
        .expect("carol task");
        match carol_evt {
            IncomingGroupEvent::Message {
                body: got_body, ..
            } => {
                assert_eq!(got_body, body, "carol should decrypt cleanly");
            }
            other => panic!("carol expected Message, got {other:?}"),
        }

        // ---- PCS: Bob fed the same bytes must NOT decrypt ----------------
        // We can't go through Bob's `accept_next` here because the
        // group state is in a removed-from state — `accept_next`
        // expects the group to still be live for Application messages.
        // Test the property directly: feed the bytes into Bob's
        // loaded group's process_incoming_message and confirm it
        // errors out.
        let msg = MlsMessage::from_bytes(&wire).expect("decode wire");
        // Bob may or may not be able to even load the group anymore
        // (mls-rs's behavior post-removal varies). Both outcomes are
        // acceptable PCS demonstrations — what we MUST NOT see is a
        // successful ApplicationMessage decrypt.
        match bob.client.load_group(gid.as_bytes()) {
            Ok(mut bob_group) => {
                let res = bob_group.process_incoming_message(msg);
                assert!(
                    res.is_err(),
                    "PCS violated: Bob decrypted a post-removal message"
                );
            }
            Err(_) => {
                // mls-rs marked the group unrecoverable on Bob's side;
                // this is the strongest PCS signal — there's no path
                // to even attempt decryption.
            }
        }
    }

    /// A remembered delivery hint is only handed out while its node is still on
    /// the group's roster.
    ///
    /// `known_member_addrs` re-checks every stored row against the current
    /// members, so a row that went stale behind our back — written by an older
    /// revision, or left behind by a removal this node never authored — can
    /// never become an auto-resolved recipient. Both directions are asserted:
    /// the stranger's hint is dropped **and** the current member's hint is still
    /// returned (an over-firing filter would silently stop delivering to
    /// legitimate members).
    #[tokio::test]
    async fn known_member_addrs_drops_hints_for_non_members() {
        let (alice, _dir) = build_proc("alice", 1);
        let gid = alice.create_group().await.expect("create_group");

        // Alice is the group's only member, and her credential carries her mock
        // endpoint's PeerId — the node id the address book is keyed by.
        let alice_node = *alice.endpoint.local_id().as_bytes();
        assert_eq!(alice_node, [1u8; 32], "build_proc peer_byte 1");
        let stranger_node = [9u8; 32];

        // Write both hints straight to storage, bypassing the write-time check
        // in `remember_member_tickets` — that is exactly the shape a row left
        // stale by a remote removal has.
        for node in [alice_node, stranger_node] {
            let ticket = crate::ticket::Ticket::new(PeerAddr::new(PeerId::new(node)), None, None);
            alice
                .storage
                .put_member_addr(gid.as_bytes(), &node, &ticket.to_string())
                .expect("put_member_addr");
        }
        assert_eq!(
            alice
                .storage
                .list_member_addrs(gid.as_bytes())
                .expect("list_member_addrs")
                .len(),
            2,
            "both hints must be in the book before the read filter runs"
        );

        let resolved: Vec<[u8; 32]> = alice
            .known_member_addrs(&gid)
            .expect("known_member_addrs")
            .iter()
            .map(|a| *a.peer_id.as_bytes())
            .collect();
        assert!(
            resolved.contains(&alice_node),
            "a current member's hint must still resolve (filter over-fired): {resolved:?}"
        );
        assert!(
            !resolved.contains(&stranger_node),
            "a hint for a node that is not a current member must not resolve"
        );
        assert_eq!(resolved.len(), 1, "exactly one member is in this group");
    }

    /// A member evicted by *another* member's Commit stops being an
    /// auto-resolved recipient on this node too.
    ///
    /// Alice removes Bob and Carol learns of it only by processing Alice's
    /// Commit (`accept_next` → `EpochAdvanced`) — the path that never touches
    /// Carol's address book, so Bob's row is still sitting there afterwards.
    /// Carol remembered both hints while Bob was still a member, so both resolve
    /// before the Commit; afterwards `known_member_addrs` filters Bob's stale row
    /// against the new roster and yields Alice only — Alice still resolving, so
    /// surviving members keep being delivered to.
    #[tokio::test]
    async fn remote_remove_commit_stops_addressing_evicted_member() {
        let net = MockNetwork::new();
        let (alice, _dir_a) = build_proc_on_net(&net, "alice", 1);
        let (bob, _dir_b) = build_proc_on_net(&net, "bob", 2);
        let (carol, _dir_c) = build_proc_on_net(&net, "carol", 3);
        let alice_addr = alice.local_addr().await.expect("alice addr");
        let bob_addr = bob.local_addr().await.expect("bob addr");
        let carol_addr = carol.local_addr().await.expect("carol addr");

        let bob_kp = bob.export_key_package().await.expect("bob kp");
        let carol_kp = carol.export_key_package().await.expect("carol kp");

        // ---- build the 3-member group (Alice, Bob, Carol) --------------
        let gid = alice.create_group().await.expect("create_group");
        let add_bob = alice.add_member(&gid, &bob_kp).await.expect("add bob");
        let bob = {
            let task = tokio::spawn(async move {
                bob.accept_next().await.expect("bob accepts welcome");
                bob
            });
            tokio::task::yield_now().await;
            alice
                .send_welcome_to(&bob_addr, &add_bob.welcome)
                .await
                .expect("welcome→bob");
            tokio::time::timeout(std::time::Duration::from_secs(5), task)
                .await
                .expect("bob welcome timeout")
                .expect("bob task")
        };
        let add_carol = alice.add_member(&gid, &carol_kp).await.expect("add carol");
        let bob_task = tokio::spawn(async move {
            bob.accept_next().await.expect("bob accepts commit");
            bob
        });
        let carol_task = tokio::spawn(async move {
            carol.accept_next().await.expect("carol accepts welcome");
            carol
        });
        tokio::task::yield_now().await;
        alice
            .send_welcome_to(&carol_addr, &add_carol.welcome)
            .await
            .expect("welcome→carol");
        alice
            .broadcast_commit(&add_carol.commit, &[bob_addr.clone()])
            .await
            .expect("commit→bob");
        let _bob = tokio::time::timeout(std::time::Duration::from_secs(5), bob_task)
            .await
            .expect("bob commit timeout")
            .expect("bob task");
        let carol = tokio::time::timeout(std::time::Duration::from_secs(5), carol_task)
            .await
            .expect("carol welcome timeout")
            .expect("carol task");

        // ---- Carol remembers both peers while both are members ---------
        let alice_node = *alice_addr.peer_id.as_bytes();
        let bob_node = *bob_addr.peer_id.as_bytes();
        carol.remember_member_tickets(
            &gid,
            &[
                crate::ticket::Ticket::new(alice_addr.clone(), None, None),
                crate::ticket::Ticket::new(bob_addr.clone(), None, None),
            ],
        );
        let mut before: Vec<[u8; 32]> = carol
            .known_member_addrs(&gid)
            .expect("carol hints before")
            .iter()
            .map(|a| *a.peer_id.as_bytes())
            .collect();
        before.sort();
        let mut both = vec![alice_node, bob_node];
        both.sort();
        assert_eq!(
            before, both,
            "both hints must resolve while both peers are members"
        );

        // ---- Alice removes Bob; only Carol processes the Commit ---------
        // Bob is leaf 1 (added first); pinned by the sibling P6 test.
        let remove_commit = alice.remove_member(&gid, 1).await.expect("remove bob");
        let carol_task = tokio::spawn(async move {
            let evt = carol.accept_next().await.expect("carol accepts remove commit");
            (evt, carol)
        });
        tokio::task::yield_now().await;
        alice
            .broadcast_commit(&remove_commit, &[carol_addr.clone()])
            .await
            .expect("remove commit→carol");
        let (carol_evt, carol) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            carol_task,
        )
        .await
        .expect("carol remove-commit timeout")
        .expect("carol task");
        match carol_evt {
            IncomingGroupEvent::EpochAdvanced { group_id, new_epoch } => {
                assert_eq!(group_id, gid);
                assert_eq!(new_epoch, 3, "epoch advances to 3 on remove");
            }
            other => panic!("carol expected EpochAdvanced(3), got {other:?}"),
        }

        // ---- the evicted member is no longer an auto-resolved recipient --
        // Only the resolved set is asserted on. Whether Bob's *row* survives in
        // `mls_member_addr` is an implementation detail: the read filter makes
        // such a row inert either way, so pinning it would over-specify.
        let resolved: Vec<[u8; 32]> = carol
            .known_member_addrs(&gid)
            .expect("carol hints after")
            .iter()
            .map(|a| *a.peer_id.as_bytes())
            .collect();
        assert!(
            !resolved.contains(&bob_node),
            "an auto-resolved send must not target the evicted member"
        );
        assert_eq!(
            resolved,
            vec![alice_node],
            "the surviving member must still be resolved"
        );
    }

    /// `remove_member` rejects an invalid leaf index. The exact error
    /// shape from mls-rs varies (out-of-range, removing self), so we
    /// only assert that it surfaces as a non-NotFound error — i.e.,
    /// it's not silently a no-op.
    #[tokio::test]
    async fn remove_member_rejects_out_of_range_index() {
        let (alice, _dir) = build_proc("alice", 1);
        let gid = alice.create_group().await.expect("create_group");
        // Group has one member (Alice at leaf 0); leaf 99 is unused.
        let err = alice.remove_member(&gid, 99).await.unwrap_err();
        assert!(
            !matches!(err, GroupError::NotFound),
            "out-of-range remove must error (got NotFound for unknown reason): {err:?}"
        );
    }

    /// `list_members` on a 1-member group returns just the creator
    /// (Alice at index 0). Pin the leaf-index allocation order so a
    /// future mls-rs change doesn't silently shift our removal API
    /// semantics.
    #[tokio::test]
    async fn list_members_yields_creator_at_index_zero() {
        let (alice, _dir) = build_proc("alice", 1);
        let gid = alice.create_group().await.expect("create_group");
        let members = alice.list_members(&gid).await.expect("list");
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].index, 0);
    }

    /// Projecting a fresh 1-member group yields exactly one 32-byte transport
    /// fingerprint (the creator, whose NKCB binding verifies). This is the value
    /// the shell/forward policy layer keys on, so the projection is a valid
    /// membership-derived allow-list.
    #[tokio::test]
    async fn projection_yields_creator_transport_fingerprint() {
        let (alice, _dir) = build_proc("alice", 1);
        let gid = alice.create_group().await.expect("create_group");
        let fps = alice
            .projected_member_fingerprints(&gid)
            .await
            .expect("project");
        assert_eq!(fps.len(), 1, "exactly the creator is projected");
        // A real fingerprint, not all-zero.
        assert_ne!(fps[0], [0u8; 32]);
    }

    /// P1.5.b round-trip: exercise the full MLS Add flow with the
    /// hybrid cipher suite. Alice creates a group, Bob produces a
    /// KeyPackage, Alice commits the Add and emits a Welcome, Bob
    /// joins via that Welcome. Both must end up on the same epoch
    /// with two members.
    ///
    /// This is the load-bearing integration test for P1.5.b: it
    /// runs the *real* mls-rs group machinery (commit construction,
    /// Welcome encryption with hybrid HPKE, key-schedule advancement)
    /// against our hybrid suite. P2 only changes the storage backing;
    /// the test continues to assert the same cryptographic round-trip.
    #[tokio::test]
    async fn add_member_roundtrip_with_hybrid_suite() {
        let (alice, _dir_a) = build_proc("alice", 1);
        let (bob, _dir_b) = build_proc("bob", 2);

        // Alice creates a fresh group; she is the only member at epoch 0.
        let mut alice_group = alice
            .client
            .create_group(ExtensionList::default(), Default::default(), None)
            .expect("alice create_group");
        assert_eq!(alice_group.current_epoch(), 0);
        assert_eq!(alice_group.roster().members_iter().count(), 1);

        // Bob generates a KeyPackage that Alice can use to add him.
        let bob_key_package = bob
            .client
            .generate_key_package_message(
                ExtensionList::default(),
                ExtensionList::default(),
                None,
            )
            .expect("bob generate_key_package");

        // Alice builds a commit containing an Add proposal for Bob's
        // KeyPackage. `build()` returns the commit + a Welcome message
        // for Bob. The commit is now *pending* on Alice's side; she
        // must apply it to advance her own state.
        let commit_output = alice_group
            .commit_builder()
            .add_member(bob_key_package)
            .expect("add_member proposal")
            .build()
            .expect("commit build");
        assert_eq!(
            commit_output.welcome_messages.len(),
            1,
            "Add produces exactly one Welcome"
        );

        // Alice apply_pending_commit() advances her own epoch.
        alice_group
            .apply_pending_commit()
            .expect("alice apply_pending_commit");
        assert_eq!(alice_group.current_epoch(), 1);
        assert_eq!(alice_group.roster().members_iter().count(), 2);

        // Bob joins via the Welcome — this is the path that exercises
        // hybrid HPKE end-to-end (Welcome's GroupSecrets are HPKE-
        // encrypted to Bob's KeyPackage init_key, which under the
        // hybrid suite is an X25519+ML-KEM-768 composite).
        let (bob_group, _info) = bob
            .client
            .join_group(None, &commit_output.welcome_messages[0], None)
            .expect("bob join_group");

        // Final invariant: both peers on epoch 1 with the same
        // group_id and the same 2-member roster.
        assert_eq!(bob_group.current_epoch(), 1);
        assert_eq!(bob_group.roster().members_iter().count(), 2);
        assert_eq!(bob_group.group_id(), alice_group.group_id());
    }

    /// Every Commit this processor emits is a `WireFormat::PrivateMessage`.
    ///
    /// This is the assertion the `mls_rules()` builder call exists to make
    /// true, and it is the one that must not silently regress: mls-rs's
    /// `EncryptionOptions::default()` has `encrypt_control_messages = false`,
    /// so dropping `.mls_rules(mls_rules())` from `GroupChatProcessor::new`
    /// puts every frame below back to `PublicMessage` — signed but readable —
    /// and this test fails on the first `assert_eq!`. Nothing else in the
    /// suite catches that, because a `PublicMessage` Commit is processed
    /// perfectly well by every receiver here; the leak is to whoever *holds*
    /// the frame, which for the inbox-fallback path is the relay operator.
    ///
    /// The Add case is the one that matters most: an Add carries the joiner's
    /// whole KeyPackage inline, so its plaintext is the NKCB credential — iroh
    /// NodeId, ML-DSA-65 transport public key, display name.
    ///
    /// The test also pins the two frames this change must **not** touch: a
    /// Welcome stays a `WireFormat::Welcome` (its GroupSecrets were already
    /// HPKE-sealed to the joiner and `control_wire_format` never applied to
    /// it), and an application message stays a `PrivateMessage` (it always
    /// was one — `check_metadata` rejects a cleartext Application outright).
    #[tokio::test]
    async fn commits_are_emitted_as_private_message() {
        let net = MockNetwork::new();
        let (alice, _da) = build_proc_on_net(&net, "alice", 1);
        let (bob, _db) = build_proc_on_net(&net, "bob", 2);
        let (carol, _dc) = build_proc_on_net(&net, "carol", 3);

        let gid = alice.create_group().await.expect("create_group");

        // 1 -> 2: the Add whose plaintext would be Bob's KeyPackage.
        let bob_kp = bob.export_key_package().await.expect("bob kp");
        let add_bob = alice.add_member(&gid, &bob_kp).await.expect("add bob");
        let add_bob_msg = MlsMessage::from_bytes(&add_bob.commit).expect("decode Add(bob)");
        assert_eq!(
            add_bob_msg.wire_format(),
            WireFormat::PrivateMessage,
            "an Add Commit must be encrypted; PublicMessage here means \
             `.mls_rules(mls_rules())` was lost from `GroupChatProcessor::new` \
             and the joiner's KeyPackage is readable by anyone holding the frame"
        );

        // The Welcome is a different envelope and is deliberately unchanged.
        let welcome_msg = MlsMessage::from_bytes(&add_bob.welcome).expect("decode Welcome");
        assert_eq!(
            welcome_msg.wire_format(),
            WireFormat::Welcome,
            "the Welcome envelope must not change"
        );
        bob.join_group_from_welcome(&add_bob.welcome)
            .await
            .expect("bob joins");

        // 2 -> 3: a second Add, so the assertion is not an artifact of the
        // 1 -> 2 transition (which has no existing-member recipients).
        let carol_kp = carol.export_key_package().await.expect("carol kp");
        let add_carol = alice.add_member(&gid, &carol_kp).await.expect("add carol");
        let add_carol_msg = MlsMessage::from_bytes(&add_carol.commit).expect("decode Add(carol)");
        assert_eq!(
            add_carol_msg.wire_format(),
            WireFormat::PrivateMessage,
            "an Add Commit into a populated group must be encrypted"
        );
        carol
            .join_group_from_welcome(&add_carol.welcome)
            .await
            .expect("carol joins");

        // A Remove: its plaintext is the evicted leaf index, and it is the
        // frame most likely to reach the relay (the peer being told about an
        // eviction is exactly the peer that may be offline).
        let remove = alice.remove_member(&gid, 1).await.expect("remove bob");
        let remove_msg = MlsMessage::from_bytes(&remove).expect("decode Remove");
        assert_eq!(
            remove_msg.wire_format(),
            WireFormat::PrivateMessage,
            "a Remove Commit must be encrypted"
        );

        // Application messages were already PrivateMessage and stay so.
        let app = alice
            .send_application_message(&gid, b"hello", &[])
            .await
            .expect("send application message");
        assert_eq!(
            MlsMessage::from_bytes(&app)
                .expect("decode application message")
                .wire_format(),
            WireFormat::PrivateMessage,
            "application messages were already encrypted and must stay so"
        );

        // Encryption grows a Commit, and the growth must stay far inside the
        // transport frame cap — a Commit that no longer fits would be an
        // availability regression, not a confidentiality win. Printed so the
        // margin is a measured number in the log rather than a claim.
        let cap = crate::group::transport::MAX_MLS_FRAME_BYTES;
        for (what, len) in [
            ("Add(bob)", add_bob.commit.len()),
            ("Add(carol)", add_carol.commit.len()),
            ("Remove(leaf 1)", remove.len()),
        ] {
            println!(
                "encrypted Commit {what}: {len} bytes = {:.3}% of MAX_MLS_FRAME_BYTES ({cap})",
                100.0 * len as f64 / cap as f64
            );
            assert!(
                len < cap / 16,
                "{what} is {len} bytes, within 16x of the {cap}-byte frame cap"
            );
        }
    }

    /// The SYNC responder clamps `claimed_epoch` to the requester's own
    /// admission, and to nothing more than that.
    ///
    /// `claimed_epoch` is 8 bytes the requester chooses, and the only floor it
    /// had was the oldest *retained* epoch. Carol is admitted at epoch 3, so
    /// the epoch-2 Commit — the Add that carries Erin's KeyPackage, i.e. her
    /// NKCB credential, iroh NodeId and ML-DSA-65 transport key — is history
    /// from before Carol was in the group and must not be served however low
    /// she claims. That the responder now *frames* its own Commits as
    /// `PrivateMessage` does not decide this: retained history also holds
    /// frames committed before that change or by a peer without it, and the
    /// clamp is a decision about what to send rather than about what the
    /// requester can open. The epoch-4 delta she genuinely missed must
    /// still be, and Bob (admitted at epoch 1) must still get every commit
    /// after his own: a clamp that starves legitimate resync would be a worse
    /// bug than the leak.
    #[tokio::test]
    async fn sync_does_not_serve_history_from_before_the_requester_joined() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        /// Split a SYNC response body (after the 4-byte marker) into its
        /// length-prefixed commit frames.
        fn frames_of(rest: &[u8]) -> Vec<Vec<u8>> {
            let mut out = Vec::new();
            let mut off = 0usize;
            while off + 4 <= rest.len() {
                let len = u32::from_le_bytes(rest[off..off + 4].try_into().unwrap()) as usize;
                off += 4;
                assert!(off + len <= rest.len(), "truncated commit frame");
                out.push(rest[off..off + len].to_vec());
                off += len;
            }
            assert_eq!(off, rest.len(), "trailing bytes after the last commit frame");
            out
        }

        /// Issue a raw SYNC request as `requester` and return the commit frames
        /// the responder streamed back.
        async fn sync_as(
            requester: &GroupChatProcessor,
            responder_addr: &PeerAddr,
            gid: &GroupId,
            claimed_epoch: u64,
        ) -> Vec<Vec<u8>> {
            let mut stream = requester
                .endpoint_ref()
                .connect(responder_addr, crate::group::transport::ALPN_MLS_PROTOCOL)
                .await
                .expect("connect for SYNC");
            stream.write_all(b"SYNC").await.expect("write SYNC header");
            let mut req = [0u8; 40];
            req[0..32].copy_from_slice(gid.as_bytes());
            req[32..40].copy_from_slice(&claimed_epoch.to_le_bytes());
            stream.write_all(&req).await.expect("write SYNC request");

            let mut marker = [0u8; 4];
            stream.read_exact(&mut marker).await.expect("read marker");
            assert_eq!(&marker, b"OK\x00\x00", "responder refused the request");
            let mut rest = Vec::new();
            stream.read_to_end(&mut rest).await.expect("read response");
            frames_of(&rest)
        }

        let net = MockNetwork::new();
        let (alice, _da) = build_proc_on_net(&net, "alice", 1);
        let (bob, _db) = build_proc_on_net(&net, "bob", 2);
        let (carol, _dc) = build_proc_on_net(&net, "carol", 3);
        let (dave, _dd) = build_proc_on_net(&net, "dave", 4);
        let (erin, _de) = build_proc_on_net(&net, "erin", 5);

        let alice_addr = alice.local_addr().await.unwrap();

        let bob_kp = bob.export_key_package().await.unwrap();
        let carol_kp = carol.export_key_package().await.unwrap();
        let dave_kp = dave.export_key_package().await.unwrap();
        let erin_kp = erin.export_key_package().await.unwrap();

        // Alice builds the group. Welcomes are not delivered — this test is
        // about what the *responder* will serve, and the requesters' identities
        // are on her roster either way.
        let gid = alice.create_group().await.unwrap();
        let add_bob = alice.add_member(&gid, &bob_kp).await.unwrap(); // epoch 1
        let add_erin = alice.add_member(&gid, &erin_kp).await.unwrap(); // epoch 2
        let add_carol = alice.add_member(&gid, &carol_kp).await.unwrap(); // epoch 3
        let add_dave = alice.add_member(&gid, &dave_kp).await.unwrap(); // epoch 4
        assert_eq!(alice.load_group_summary(&gid).await.unwrap().epoch, 4);

        // Carol claims epoch 1 — above the oldest retained epoch, so the
        // pruning floor lets it through, but below her own admission.
        let alice = {
            let task = tokio::spawn(async move {
                alice.accept_next().await.expect("alice serves carol's SYNC");
                alice
            });
            let frames = sync_as(&carol, &alice_addr, &gid, 1).await;
            let alice = task.await.unwrap();

            assert_eq!(
                frames.len(),
                1,
                "Carol joined at epoch 3: she may be served the epoch-4 delta and \
                 nothing older, whatever she claims"
            );
            assert_eq!(frames[0], *add_dave.commit);
            assert!(
                !frames
                    .iter()
                    .any(|f| f == &*add_erin.commit || f == &*add_carol.commit),
                "commits from before Carol's admission were disclosed"
            );
            alice
        };

        // Bob, admitted at epoch 1, is not starved: he still gets every commit
        // that followed his admission.
        let _alice = {
            let task = tokio::spawn(async move {
                alice.accept_next().await.expect("alice serves bob's SYNC");
                alice
            });
            let frames = sync_as(&bob, &alice_addr, &gid, 1).await;
            let alice = task.await.unwrap();

            assert_eq!(frames.len(), 3, "Bob's legitimate delta must still be served");
            assert_eq!(frames[0], *add_erin.commit);
            assert_eq!(frames[1], *add_carol.commit);
            assert_eq!(frames[2], *add_dave.commit);
            assert!(
                !frames.iter().any(|f| f == &*add_bob.commit),
                "the floor stays exclusive: Bob's own Add is not replayed to him"
            );
            alice
        };
    }

    /// The decision itself, on all four shapes of what we know about a
    /// requester.
    ///
    /// The two `None` rows are the ones the responder used to get wrong: an
    /// unrecorded requester was served from its own `claimed_epoch`, i.e. from
    /// no floor at all. What replaces that is not "refuse everyone" — with a
    /// history floor we can still say which span is safely theirs — but the
    /// no-floor row does refuse, because a database that can vouch for no span
    /// has nothing to offer but a guess.
    #[test]
    fn sync_history_floor_never_takes_the_requester_at_its_word() {
        // Recorded: the requester's own admission is the floor, and claiming
        // lower does not move it.
        assert_eq!(sync_history_floor(1, 90, Some(42), None), 42);
        assert_eq!(sync_history_floor(1, 90, Some(42), Some(7)), 42);
        // ...but a requester that is already ahead of its admission keeps its
        // own (higher) floor: we never re-serve what it has.
        assert_eq!(sync_history_floor(80, 90, Some(42), Some(7)), 80);

        // Unrecorded, with a floor: the span above the floor is where our
        // records are complete, so it is demonstrably not this member's
        // pre-admission history.
        assert_eq!(sync_history_floor(1, 90, None, Some(60)), 60);
        assert_eq!(sync_history_floor(70, 90, None, Some(60)), 70);

        // Unrecorded, no floor: we can demonstrate nothing. `local_epoch` makes
        // the delta empty rather than serving the requester's own guess.
        assert_eq!(sync_history_floor(1, 90, None, None), 90);
        assert_eq!(sync_history_floor(0, 0, None, None), 0);

        // The requester's 8 bytes can only ever raise the floor.
        for claimed in [0u64, 1, 41, 42, 43, u64::MAX] {
            for join in [None, Some(42u64)] {
                for floor in [None, Some(60u64)] {
                    let got = sync_history_floor(claimed, 90, join, floor);
                    let at_word = sync_history_floor(0, 90, join, floor);
                    assert!(
                        got >= at_word,
                        "claimed_epoch {claimed} lowered the floor ({got} < {at_word}) \
                         for join={join:?} floor={floor:?}"
                    );
                }
            }
        }
    }

    /// A responder that joined by Welcome and whose own group operations are
    /// **removals only** must still serve the delta a legitimate member is
    /// entitled to.
    ///
    /// This is the shape a one-shot CLI produces — join, evict, exit, never
    /// process an inbound Commit — and it is the shape in which a history floor
    /// is easiest to get wrong. Bob retains commits, none of which predate
    /// Carol's admission (she was in the group before he was), so there is no
    /// pre-admission history to withhold here and an empty delta would be a
    /// pure availability regression: exactly the "clamp that starves legitimate
    /// resync" the sibling test above warns about.
    ///
    /// It also drives the responder's *unrecorded* branch end to end, which no
    /// other test does: every requester in the sibling test is recorded on the
    /// responder, so only the recorded path is exercised there. Bob applied no
    /// member's Add, so `member_join_epoch` is `None` for every requester he can
    /// possibly answer.
    #[tokio::test]
    async fn sync_serves_a_removals_only_responder_delta_to_an_unrecorded_member() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        /// Issue a raw SYNC request and return the commit frames streamed back.
        async fn sync_as(
            requester: &GroupChatProcessor,
            responder_addr: &PeerAddr,
            gid: &GroupId,
            claimed_epoch: u64,
        ) -> Vec<Vec<u8>> {
            let mut stream = requester
                .endpoint_ref()
                .connect(responder_addr, crate::group::transport::ALPN_MLS_PROTOCOL)
                .await
                .expect("connect for SYNC");
            stream.write_all(b"SYNC").await.expect("write SYNC header");
            let mut req = [0u8; 40];
            req[0..32].copy_from_slice(gid.as_bytes());
            req[32..40].copy_from_slice(&claimed_epoch.to_le_bytes());
            stream.write_all(&req).await.expect("write SYNC request");

            let mut marker = [0u8; 4];
            stream.read_exact(&mut marker).await.expect("read marker");
            assert_eq!(&marker, b"OK\x00\x00", "responder refused the request");
            let mut rest = Vec::new();
            stream.read_to_end(&mut rest).await.expect("read response");

            let mut out = Vec::new();
            let mut off = 0usize;
            while off + 4 <= rest.len() {
                let len = u32::from_le_bytes(rest[off..off + 4].try_into().unwrap()) as usize;
                off += 4;
                assert!(off + len <= rest.len(), "truncated commit frame");
                out.push(rest[off..off + len].to_vec());
                off += len;
            }
            assert_eq!(off, rest.len(), "trailing bytes after the last commit frame");
            out
        }

        let net = MockNetwork::new();
        let (alice, _da) = build_proc_on_net(&net, "alice", 1);
        let (bob, _db) = build_proc_on_net(&net, "bob", 2);
        let (carol, _dc) = build_proc_on_net(&net, "carol", 3);
        let (dave, _dd) = build_proc_on_net(&net, "dave", 4);
        let (erin, _de) = build_proc_on_net(&net, "erin", 5);

        let bob_addr = bob.local_addr().await.unwrap();

        let carol_kp = carol.export_key_package().await.unwrap();
        let dave_kp = dave.export_key_package().await.unwrap();
        let erin_kp = erin.export_key_package().await.unwrap();
        let bob_kp = bob.export_key_package().await.unwrap();

        // Alice builds the group and admits Bob last (leaves: alice 0, carol 1,
        // dave 2, erin 3, bob 4). On Bob's database every other member predates
        // him and he applied none of their Adds.
        let gid = alice.create_group().await.unwrap();
        alice.add_member(&gid, &carol_kp).await.unwrap(); // epoch 1
        alice.add_member(&gid, &dave_kp).await.unwrap(); // epoch 2
        alice.add_member(&gid, &erin_kp).await.unwrap(); // epoch 3
        let add_bob = alice.add_member(&gid, &bob_kp).await.unwrap(); // epoch 4
        let bob_gid = bob.join_group_from_welcome(&add_bob.welcome).await.unwrap();
        assert_eq!(bob_gid, gid);
        assert_eq!(bob.load_group_summary(&gid).await.unwrap().epoch, 4);

        // Bob's own operations: removals, which store commit history and add
        // nobody.
        let _remove_dave = bob.remove_member(&gid, 2).await.unwrap(); // epoch 5
        let remove_erin = bob.remove_member(&gid, 3).await.unwrap(); // epoch 6
        assert_eq!(bob.load_group_summary(&gid).await.unwrap().epoch, 6);

        // Carol asks Bob for the delta after epoch 5. Bob never witnessed her
        // Add, so this is the unrecorded path; his retained history starts after
        // his own admission, which is long after hers.
        let task = tokio::spawn(async move {
            bob.accept_next().await.expect("bob serves carol's SYNC");
            bob
        });
        let frames = sync_as(&carol, &bob_addr, &gid, 5).await;
        let bob = task.await.unwrap();

        assert_eq!(
            frames.len(),
            1,
            "Carol predates every commit Bob retains: her delta must be served, \
             not swallowed because Bob never witnessed her Add"
        );
        assert_eq!(frames[0], *remove_erin);

        // And the floor Bob pinned is the one his own admission implies — pinned
        // by a Remove, since that is the only kind of commit he ever applied.
        assert_eq!(
            bob.storage.history_floor(gid.as_bytes()).expect("floor"),
            Some(4),
            "a removals-only node must still pin a floor, or it can vouch for \
             nothing and serves nobody"
        );
    }

    #[tokio::test]
    async fn test_resync_and_eviction_flow() {
        let net = MockNetwork::new();
        let (alice, _dir_a) = build_proc_on_net(&net, "alice", 1);
        let (bob, _dir_b) = build_proc_on_net(&net, "bob", 2);
        let (carol, _dir_c) = build_proc_on_net(&net, "carol", 3);

        let alice_addr = alice.local_addr().await.unwrap();
        let bob_addr = bob.local_addr().await.unwrap();
        let carol_addr = carol.local_addr().await.unwrap();

        let bob_kp = bob.export_key_package().await.unwrap();
        let carol_kp = carol.export_key_package().await.unwrap();

        // Alice creates a group (epoch 1)
        let gid = alice.create_group().await.unwrap();

        // Alice adds Bob (epoch 1 -> 2)
        let add_bob = alice.add_member(&gid, &bob_kp).await.unwrap();
        let bob = {
            let task = tokio::spawn(async move {
                bob.accept_next().await.unwrap();
                bob
            });
            alice.send_welcome_to(&bob_addr, &add_bob.welcome).await.unwrap();
            task.await.unwrap()
        };

        // Bob goes offline now (we don't broadcast epoch 3 commits to Bob)
        // Alice adds Carol (epoch 2 -> 3)
        let add_carol = alice.add_member(&gid, &carol_kp).await.unwrap();
        let carol = {
            let task = tokio::spawn(async move {
                carol.accept_next().await.unwrap();
                carol
            });
            alice.send_welcome_to(&carol_addr, &add_carol.welcome).await.unwrap();
            task.await.unwrap()
        };

        // Bob is at epoch 1, Alice/Carol are at epoch 2.
        let alice_summary = alice.load_group_summary(&gid).await.unwrap();
        assert_eq!(alice_summary.epoch, 2);
        let bob_summary = bob.load_group_summary(&gid).await.unwrap();
        assert_eq!(bob_summary.epoch, 1);

        // Bob requests resync from Alice (Client connects to Alice)
        let alice_task = tokio::spawn(async move {
            alice.accept_next().await.unwrap(); // handles resync request
            alice
        });

        let resync_res = bob.request_resync(&gid, &alice_addr).await.unwrap();
        assert!(resync_res.applied, "Bob should have applied missing commits");
        assert!(!resync_res.removed_us, "this catch-up did not remove Bob");

        let alice = alice_task.await.unwrap();

        let bob_summary_after = bob.load_group_summary(&gid).await.unwrap();
        assert_eq!(bob_summary_after.epoch, 2);

        // Test Case A: Evict Carol (epoch 2 -> 3)
        let alice_members = alice.list_members(&gid).await.unwrap();
        let carol_leaf = alice_members.iter().find(|m| m.index == 2).unwrap().index;
        let _remove_carol_commit = alice.remove_member(&gid, carol_leaf).await.unwrap();

        // Carol tries to sync but she is evicted (Case A check)
        let alice_task_2 = tokio::spawn(async move {
            let err = alice.accept_next().await.unwrap_err();
            assert!(err.to_string().contains("Sync rejected") || err.to_string().contains("not in roster"));
            alice
        });

        let resync_err = carol.request_resync(&gid, &alice_addr).await.unwrap_err();
        assert!(resync_err.to_string().contains("peer rejected roster") || resync_err.to_string().contains("not in roster"));
        let alice = alice_task_2.await.unwrap();

        // Test Case C: welcome fallback (compaction pruning)
        // Prune commits older than 1 on Alice's side (keep only current commit)
        alice.storage.prune_commits(gid.as_bytes(), 0).unwrap();

        // Bob is offline, Alice advances group to epoch 4
        let _add_carol_again = alice.add_member(&gid, &carol_kp).await.unwrap();
        let alice_task_3 = tokio::spawn(async move {
            let err = alice.accept_next().await.unwrap_err();
            assert!(err.to_string().contains("pruned") || err.to_string().contains("Welcome fallback"));
            alice
        });

        let resync_err_c = bob.request_resync(&gid, &alice_addr).await.unwrap_err();
        assert!(resync_err_c.to_string().contains("Welcome fallback") || resync_err_c.to_string().contains("pruned"));
        let _ = alice_task_3.await.unwrap();
    }

    /// A responder that connects and then says nothing is dropped on the
    /// **handshake** deadline, not the five-minute bulk one.
    ///
    /// `request_resync` is the mirror image of the responder loop, whose own
    /// comment calls a long block on a small fixed read a head-of-line DoS: the
    /// caller sweeps peers one at a time, from an interactive REPL, so every
    /// silent peer used to cost 300 s of an operator's session on a four-byte
    /// read (and again on each frame length and body). `IDLE_TIMEOUT` itself is
    /// shared with the bulk transfer paths and is deliberately unchanged, so
    /// this pins which of the two deadlines this read uses.
    ///
    /// Time is paused, so the wait is virtual and the test is instant; the
    /// silent peer holds the stream open on a far-future sleep so the runtime's
    /// next timer is the deadline under test.
    #[tokio::test(start_paused = true)]
    async fn request_resync_bounds_a_silent_responder_by_the_handshake_deadline() {
        use tokio::io::AsyncReadExt;

        let net = MockNetwork::new();
        let (alice, _dir_a) = build_proc_on_net(&net, "alice", 1);
        let (bob, _dir_b) = build_proc_on_net(&net, "bob", 2);
        let bob_addr = bob.local_addr().await.unwrap();
        let bob_kp = bob.export_key_package().await.unwrap();

        let gid = alice.create_group().await.unwrap();
        let add_bob = alice.add_member(&gid, &bob_kp).await.unwrap();
        let bob = {
            let task = tokio::spawn(async move {
                bob.accept_next().await.unwrap();
                bob
            });
            alice.send_welcome_to(&bob_addr, &add_bob.welcome).await.unwrap();
            task.await.unwrap()
        };

        // A peer that accepts the connection, reads the request, and then never
        // answers — holding the stream open so this is a stall, not an EOF.
        let mute_id = PeerId::new([9; 32]);
        let mute_ep = net.register(mute_id, vec![PROTO_MLS]);
        let mute = tokio::spawn(async move {
            let inc = mute_ep
                .accept()
                .await
                .unwrap()
                .establish(std::time::Duration::from_secs(5))
                .await
                .unwrap();
            let mut s = inc.stream;
            let mut req = [0u8; 44];
            let _ = s.read_exact(&mut req).await;
            tokio::time::sleep(std::time::Duration::from_secs(86_400)).await;
        });

        let started = tokio::time::Instant::now();
        let err = bob
            .request_resync(&gid, &PeerAddr::new(mute_id))
            .await
            .expect_err("a responder that says nothing must not be waited on forever");
        let waited = started.elapsed();
        mute.abort();

        assert!(
            waited >= crate::network::HANDSHAKE_TIMEOUT,
            "it must actually wait the handshake deadline, waited {waited:?}"
        );
        assert!(
            waited < crate::network::IDLE_TIMEOUT,
            "a small fixed read must not be bounded by the 5-minute bulk deadline, \
             waited {waited:?}"
        );
        assert!(
            err.to_string().contains("handshake timeout"),
            "got: {err}"
        );
    }
}
