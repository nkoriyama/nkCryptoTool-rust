//! MLS group chat processor.
//!
//! P1 introduced the `GroupChatProcessor` shell on the hybrid passthrough
//! provider; P1.5.a/b made the cipher suite real PQC (hybrid signature +
//! hybrid KEM); P2 (this revision) adds sqlite persistence so groups
//! survive a process restart.
//!
//! The processor owns:
//! - an mls-rs `Client` configured with our [`HybridCryptoProvider`] and
//!   the sqlite-backed group / key-package / PSK storage triple,
//! - the [`GroupStorage`] handle itself (kept alive so we can run our
//!   own `list_group_ids` queries against the same database), and
//! - a `P2pEndpoint` reserved for P3+ transport routing.
//!
//! `create_group` now actually persists the freshly created group to
//! sqlite via `mls-rs`'s `write_to_storage`. `list_groups` and
//! `load_group_summary` provide the round-trip read path.
//!
//! Per-group send / receive / add_member orchestration (versus the raw
//! mls-rs Client surface used by the existing tests) is still P3+.

use std::sync::Arc;

use mls_rs::client_builder::{
    BaseConfig, WithCryptoProvider, WithGroupStateStorage, WithIdentityProvider,
    WithKeyPackageRepo, WithPskStore,
};
use mls_rs::identity::SigningIdentity;
use mls_rs::identity::basic::{BasicCredential, BasicIdentityProvider};
use mls_rs::{Client, ExtensionList};
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
    #[allow(dead_code)] // wired in P4 (ALPN routing).
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
