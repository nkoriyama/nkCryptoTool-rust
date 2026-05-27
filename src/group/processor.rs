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
    BaseConfig, WithCryptoProvider, WithGroupStateStorage, WithIdentityProvider,
    WithKeyPackageRepo, WithPskStore,
};
use mls_rs::identity::SigningIdentity;
use mls_rs::identity::basic::{BasicCredential, BasicIdentityProvider};
use mls_rs::{Client, ExtensionList, MlsMessage, WireFormat};
use mls_rs_core::crypto::{CipherSuiteProvider, CryptoProvider};
use mls_rs_provider_sqlite::storage::{
    SqLiteGroupStateStorage, SqLiteKeyPackageStorage, SqLitePreSharedKeyStorage,
};
use zeroize::Zeroizing;

use crate::group::crypto_adapter::{hybrid_cipher_suite, HybridCryptoProvider};
use crate::group::storage::GroupStorage;
use crate::group::types::{
    AddMemberOutput, GroupError, GroupId, GroupSummary, IncomingGroupEvent, MemberInfo,
};
use crate::p2p::P2pEndpoint;

/// MLS-RS `Config` shape after stacking our storage providers and
/// crypto/identity providers on top of the base config.
///
/// Order matches the call chain in [`GroupChatProcessor::new`]:
/// `.group_state_storage(..).key_package_repo(..).psk_store(..).crypto_provider(..).identity_provider(..)`,
/// which composes outermost-first as `WithIdentityProvider<.., WithCryptoProvider<.., WithPskStore<.., WithKeyPackageRepo<.., WithGroupStateStorage<.., BaseConfig>>>>>`.
type MlsConfig = WithIdentityProvider<
    BasicIdentityProvider,
    WithCryptoProvider<
        HybridCryptoProvider,
        WithPskStore<
            SqLitePreSharedKeyStorage,
            WithKeyPackageRepo<
                SqLiteKeyPackageStorage,
                WithGroupStateStorage<SqLiteGroupStateStorage, BaseConfig>,
            >,
        >,
    >,
>;

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
}

impl GroupChatProcessor {
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
    /// `mls:identity:pk` (public). The bytes are **plaintext** in the
    /// sqlite file; the file's `0o600` permission is the at-rest
    /// boundary. SQLCipher (the `sqlcipher-bundled` feature of
    /// `mls-rs-provider-sqlite`) is a one-feature swap away — see
    /// `SECURITY_PROFILE.md` §7.3.
    pub fn new(
        display_name: &str,
        endpoint: Arc<dyn P2pEndpoint>,
        storage: GroupStorage,
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
                (SignatureSecretKey::new(sk), SignaturePublicKey::new(pk))
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

        let credential = BasicCredential::new(display_name.as_bytes().to_vec());
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
            .crypto_provider(crypto)
            .identity_provider(BasicIdentityProvider)
            .signing_identity(identity, signing_key, suite_id)
            .build();

        Ok(Self {
            client,
            storage,
            endpoint,
        })
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
    /// are public. The private key half lives in sqlite (where 0o600
    /// permissions protect it); the returned blob is harmless to leak.
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

        let mut group = self.client.load_group(gid.as_bytes()).map_err(|e| {
            let msg = format!("{e}");
            if msg.contains("GroupNotFound") || msg.contains("group not found") {
                GroupError::NotFound
            } else {
                GroupError::Backend(format!("load_group for add_member: {e}"))
            }
        })?;

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

        group
            .write_to_storage()
            .map_err(|e| GroupError::Storage(format!("write_to_storage after join: {e}")))?;

        let id_bytes = group.group_id().to_vec();
        if id_bytes.len() != 32 {
            return Err(GroupError::Backend(format!(
                "joined group has non-32 id length {}",
                id_bytes.len()
            )));
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&id_bytes);
        // Drop `group` to zeroize its in-memory keys via ZeroizeOnDrop;
        // the state lives on in sqlite.
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
        crate::group::transport::send_one(self.endpoint.as_ref(), recipient, &msg)
            .await
            .map_err(|e| match e {
                crate::group::transport::FramingError::Transport(p) => {
                    GroupError::Transport(p)
                }
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
        let inc = self
            .endpoint
            .accept()
            .await
            .map_err(GroupError::Transport)?;
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
        // Persist the advanced key schedule before fanning out — if a
        // recipient receives the encrypted message but our state was
        // never written, a subsequent re-encrypt could reuse a nonce.
        // sqlite WAL + busy_timeout makes this a single quick write.
        group
            .write_to_storage()
            .map_err(|e| GroupError::Storage(format!("write_to_storage after encrypt: {e}")))?;

        let wire_bytes = msg
            .to_bytes()
            .map_err(|e| GroupError::Backend(format!("PrivateMessage encode: {e}")))?;

        // Fan-out. We send one stream per recipient (1 frame = 1
        // MlsMessage per the §5.4 contract). Any failure surfaces;
        // partial fan-out is reported as the first error so the caller
        // can choose to retry or compensate. We continue past a single
        // failure on best-effort transports, but here we stop early —
        // peer dropouts are visible in `endpoint.connect` errors.
        for addr in recipients {
            crate::group::transport::send_one(self.endpoint.as_ref(), addr, &msg)
                .await
                .map_err(|e| match e {
                    crate::group::transport::FramingError::Transport(p) => {
                        GroupError::Transport(p)
                    }
                    other => {
                        GroupError::Backend(format!("send_application_message: {other}"))
                    }
                })?;
        }

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
        // We accept either PublicMessage or PrivateMessage Commits.
        // mls-rs defaults to PrivateMessage; PublicMessage is opt-in.
        // We don't restrict here — recipients will revalidate.
        for addr in recipients {
            crate::group::transport::send_one(self.endpoint.as_ref(), addr, &msg)
                .await
                .map_err(|e| match e {
                    crate::group::transport::FramingError::Transport(p) => {
                        GroupError::Transport(p)
                    }
                    other => {
                        GroupError::Backend(format!("broadcast_commit: {other}"))
                    }
                })?;
        }
        Ok(())
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
        let inc = self
            .endpoint
            .accept()
            .await
            .map_err(GroupError::Transport)?;
        if inc.protocol != crate::group::transport::ALPN_MLS_PROTOCOL {
            return Err(GroupError::Transport(crate::p2p::P2pError::Accept(format!(
                "accept_next: unexpected ALPN {:?}",
                inc.protocol
            ))));
        }
        let (msg, raw) = crate::group::transport::recv_mls_message(inc.stream)
            .await
            .map_err(|e| match e {
                crate::group::transport::FramingError::Transport(p) => {
                    GroupError::Transport(p)
                }
                other => GroupError::InvalidWelcome(format!("recv_mls_message: {other}")),
            })?;

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

                let mut group = self.client.load_group(gid_bytes).map_err(|e| {
                    let m = format!("{e}");
                    if m.contains("GroupNotFound") || m.contains("group not found") {
                        GroupError::NotFound
                    } else {
                        GroupError::Backend(format!("load_group for incoming: {e}"))
                    }
                })?;

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
                        // CommitEffect::Removed is the load-bearing
                        // PCS signal: this commit's effect on the
                        // local member was "you are no longer in
                        // the group". Surface it as a dedicated
                        // event so the caller can stop polling this
                        // group's stream.
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
        let mut group = self.client.load_group(gid.as_bytes()).map_err(|e| {
            let m = format!("{e}");
            if m.contains("GroupNotFound") || m.contains("group not found") {
                GroupError::NotFound
            } else {
                GroupError::Backend(format!("load_group for remove_member: {e}"))
            }
        })?;

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

        let commit_bytes = commit_output
            .commit_message
            .to_bytes()
            .map_err(|e| GroupError::Backend(format!("Commit encode after remove: {e}")))?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p::backend::mock::MockNetwork;
    use crate::p2p::{P2pProtocol, PeerId};
    use mls_rs::ExtensionList;
    use tempfile::tempdir;

    const PROTO_MLS: P2pProtocol = P2pProtocol(b"nkct/mls/1");

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
        let storage = GroupStorage::open_at(dir.path().join("groups.db")).expect("storage");
        let net = MockNetwork::new();
        let ep = net.register(PeerId::new([peer_byte; 32]), vec![PROTO_MLS]);
        let proc =
            GroupChatProcessor::new(display_name, Arc::new(ep), storage).expect("builder");
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
        let storage = GroupStorage::open_at(dir.path().join("groups.db")).expect("storage");
        let ep = net.register(PeerId::new([peer_byte; 32]), vec![PROTO_MLS]);
        let proc =
            GroupChatProcessor::new(display_name, Arc::new(ep), storage).expect("builder");
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
            let storage = GroupStorage::open_at(&db_path).expect("storage 1");
            let net = MockNetwork::new();
            let ep = net.register(PeerId::new([1; 32]), vec![PROTO_MLS]);
            let proc = GroupChatProcessor::new("alice", Arc::new(ep), storage)
                .expect("builder 1");
            gid_before = proc.create_group().await.expect("create_group");
            // Drop the whole processor — including its Client, signing
            // key (zeroized by mls-rs), and storage handle. The sqlite
            // file remains.
        }

        // ---- session 2: reload at the same path --------------------
        let storage = GroupStorage::open_at(&db_path).expect("storage 2");
        let net = MockNetwork::new();
        let ep = net.register(PeerId::new([2; 32]), vec![PROTO_MLS]);
        // New signing identity (the original one is gone). That is OK
        // for read-only inspection; sending into the group from this
        // processor would fail authentication, but the round-trip we
        // care about is state reconstruction.
        let proc = GroupChatProcessor::new("alice-reloaded", Arc::new(ep), storage)
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
            GroupStorage::open_at(&path_a).expect("alice storage"),
        )
        .expect("alice processor");
        let bob = GroupChatProcessor::new(
            "bob",
            Arc::new(bob_ep),
            GroupStorage::open_at(&path_b).expect("bob storage"),
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
            GroupStorage::open_at(&path_a).expect("alice storage 2"),
        )
        .expect("alice processor 2");
        let bob2 = GroupChatProcessor::new(
            "bob",
            Arc::new(net.register(PeerId::new([4; 32]), vec![PROTO_MLS])),
            GroupStorage::open_at(&path_b).expect("bob storage 2"),
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
}
