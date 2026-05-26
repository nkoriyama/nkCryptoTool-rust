//! MLS group chat processor.
//!
//! P1 scope: construct an `mls-rs` Client via the (passthrough)
//! `HybridCryptoProvider`, expose `create_group` as the first concrete
//! operation, and define the surface for later phases. Send / receive /
//! add_member / remove_member arrive in P3+ per `MLS_GROUP_CHAT_PLAN.md`
//! §14.

use std::sync::Arc;

use mls_rs::client_builder::{BaseConfig, WithCryptoProvider, WithIdentityProvider};
use mls_rs::identity::SigningIdentity;
use mls_rs::identity::basic::{BasicCredential, BasicIdentityProvider};
use mls_rs::{Client, ExtensionList};
use mls_rs_core::crypto::{CipherSuiteProvider, CryptoProvider};
use zeroize::Zeroizing;

use crate::group::crypto_adapter::{hybrid_cipher_suite, HybridCryptoProvider};
use crate::group::types::{GroupError, GroupId};
use crate::p2p::P2pEndpoint;

/// MLS-RS `Client` built with our `HybridCryptoProvider`.
///
/// `HybridCryptoProvider` is the only `CryptoProvider` we expose; it
/// exposes a single cipher suite (the hybrid `0xF101`) and internally
/// builds the X25519 + ML-KEM-768 / SHA-256 / AES-128-GCM primitives.
///
/// Type alias shape follows the mls-rs 0.55 docs example: the builder
/// stacks `WithIdentityProvider<.., WithCryptoProvider<.., BaseConfig>>`
/// outermost-first to match the call chain
/// `.crypto_provider(..).identity_provider(..)`.
type MlsClient = Client<
    WithIdentityProvider<
        BasicIdentityProvider,
        WithCryptoProvider<HybridCryptoProvider, BaseConfig>,
    >,
>;

// P1.5.b: the cipher suite used here is the full hybrid suite — both
// signatures (Ed25519 + ML-DSA-65) and KEM (X25519 + ML-KEM-768) are
// hybrid. AEAD remains AES-128-GCM and KDF/Hash remain SHA-256; those
// classical primitives are considered acceptable post-quantum for the
// purposes of MLS because key material is protected by the PQ KEM.

/// Transport-agnostic MLS group chat orchestrator.
///
/// Holds an mls-rs `Client` (which in turn holds the signing identity,
/// crypto provider, and identity provider) plus the `P2pEndpoint` used
/// to deliver Welcome / Commit / Application messages.
pub struct GroupChatProcessor {
    client: MlsClient,
    #[allow(dead_code)] // wired in P4 (ALPN routing).
    endpoint: Arc<dyn P2pEndpoint>,
}

impl GroupChatProcessor {
    /// Build a processor with a freshly generated signing identity.
    ///
    /// `display_name` is stored only in the MLS `BasicCredential`
    /// (not a security boundary; recipients verify by fingerprint).
    /// `endpoint` is the transport the processor will use for Welcome
    /// and message delivery once those code paths land.
    pub fn new(
        display_name: &str,
        endpoint: Arc<dyn P2pEndpoint>,
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

        let client = Client::builder()
            .identity_provider(BasicIdentityProvider)
            .crypto_provider(crypto)
            .signing_identity(identity, signing_key, suite_id)
            .build();

        Ok(Self { client, endpoint })
    }

    /// Create a fresh single-member group. Returns the freshly
    /// generated `GroupId`.
    ///
    /// P1 limitation: the group state is held in-memory only. Persistence
    /// to sqlite arrives in P2. mls-rs's `create_group` is synchronous
    /// in its default (non-`mls_build_async`) build, but we keep this
    /// method `async` so subsequent phases can add transport calls
    /// (Welcome dispatch via `self.endpoint.connect`) without churning
    /// the call sites again.
    pub async fn create_group(&self) -> Result<GroupId, GroupError> {
        let group = self
            .client
            .create_group(ExtensionList::default(), Default::default(), None)
            .map_err(|e| GroupError::Backend(format!("create_group: {e}")))?;

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

        // P1: hold the freshly created group only for the lifetime of
        // this call. The processor itself remains stateless; P2 wires
        // in sqlite-backed persistence and a `groups: HashMap` field.
        // `_group` is intentionally dropped here so its in-memory keys
        // are zeroized via mls-rs' own ZeroizeOnDrop.
        drop(group);

        // Silence: `signing_key` and intermediate `Zeroizing` buffers
        // are auto-zeroed via their wrappers; explicit anchor so this
        // file's intent is grep-able.
        let _intent_anchor: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());

        Ok(GroupId::new(id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p::backend::mock::MockNetwork;
    use crate::p2p::{P2pProtocol, PeerId};
    use mls_rs::ExtensionList;

    const PROTO_MLS: P2pProtocol = P2pProtocol(b"nkct/mls/1");

    /// Test helper: build a `GroupChatProcessor` with a freshly
    /// registered mock endpoint. The endpoint is not exercised by
    /// the test (its only purpose is to satisfy the `new` signature)
    /// — the `peer_byte` parameter just lets the caller distinguish
    /// PeerIds.
    fn build_proc(display_name: &str, peer_byte: u8) -> GroupChatProcessor {
        let net = MockNetwork::new();
        let ep = net.register(PeerId::new([peer_byte; 32]), vec![PROTO_MLS]);
        GroupChatProcessor::new(display_name, Arc::new(ep)).expect("builder")
    }

    /// P1 smoke test: build a `GroupChatProcessor` with a mock
    /// endpoint and round-trip a `create_group` call.
    #[tokio::test]
    async fn create_group_smoke() {
        let proc = build_proc("alice", 1);
        let gid = proc.create_group().await.expect("create_group");
        // GroupId は 32B 乱数。零値は事故時のみで実運用ではあり得ない。
        assert_ne!(gid.as_bytes(), &[0u8; 32]);
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
    /// against our hybrid suite. If any part of the hybrid plumbing
    /// is misconfigured — wrong KEM byte layout, sig key length,
    /// SHAKE adapter wiring, etc. — this test fails.
    #[tokio::test]
    async fn add_member_roundtrip_with_hybrid_suite() {
        // mls-rs's group machinery takes `&self` on the Client, so we
        // can drive both Alice and Bob without consuming the procs.
        let alice = build_proc("alice", 1);
        let bob = build_proc("bob", 2);

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
