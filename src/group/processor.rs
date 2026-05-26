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
use crate::group::types::{GroupError, GroupId, GroupSummary};
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
    /// Build a processor with a freshly generated signing identity and
    /// sqlite-backed storage.
    ///
    /// `display_name` is stored in the MLS `BasicCredential` for UX
    /// only — it is not a security boundary; recipients verify by
    /// fingerprint of the hybrid public key.
    ///
    /// `endpoint` is the transport the processor will use for Welcome
    /// and message delivery once those code paths land (P3+).
    ///
    /// `storage` owns the sqlite file. Multiple processors must not
    /// share a `GroupStorage` for the same file concurrently; sqlite
    /// busy_timeout (5 s) absorbs short contention but the design here
    /// assumes one writer per database. Reopen between sessions.
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

        let (signing_key, signing_pub) = suite
            .signature_key_generate()
            .map_err(|e| GroupError::Backend(format!("sig keygen: {e}")))?;

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

    /// Add a member to an existing group and return the `Welcome` blob
    /// to hand to that new member.
    ///
    /// `gid` identifies a group this processor already owns (per
    /// [`list_groups`](Self::list_groups)). `key_package_bytes` is a
    /// peer's `KeyPackage` blob (typically produced by their
    /// [`export_key_package`]).
    ///
    /// On success, the group state on this side has advanced by one
    /// epoch (the Add commit is applied and persisted) and the returned
    /// bytes are the `Welcome` MLS message that the new member needs
    /// to call [`join_group_from_welcome`].
    ///
    /// A `Commit` message bound for *existing* members is NOT returned
    /// here — for the 2-member case there are no existing-member
    /// recipients, and for ≥ 3 it's the caller's job to broadcast the
    /// commit (P5 work). The plan §7.2 covers this split.
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
    ) -> Result<Zeroizing<Vec<u8>>, GroupError> {
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
        Ok(Zeroizing::new(welcome_bytes))
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
        let welcome = alice
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

        // Bob joins via the Welcome blob.
        let bob_gid = bob
            .join_group_from_welcome(&welcome)
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
        let welcome_bytes = alice
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
            .send_welcome_to(&bob_addr, &welcome_bytes)
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
