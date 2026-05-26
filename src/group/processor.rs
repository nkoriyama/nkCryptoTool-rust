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
use mls_rs::{CipherSuite, Client, ExtensionList};
use mls_rs_core::crypto::{CipherSuiteProvider, CryptoProvider};
use mls_rs_crypto_openssl::OpensslCryptoProvider;
use zeroize::Zeroizing;

use crate::group::crypto_adapter::HybridCryptoProvider;
use crate::group::types::{GroupError, GroupId};
use crate::p2p::P2pEndpoint;

/// MLS-RS `Client` built with our `HybridCryptoProvider` on top of an
/// OpenSSL base.
///
/// Type alias shape follows the mls-rs 0.55 docs example: the builder
/// stacks `WithIdentityProvider<.., WithCryptoProvider<.., BaseConfig>>`
/// outermost-first to match the call chain
/// `.crypto_provider(..).identity_provider(..)`.
type MlsClient = Client<
    WithIdentityProvider<
        BasicIdentityProvider,
        WithCryptoProvider<HybridCryptoProvider<OpensslCryptoProvider>, BaseConfig>,
    >,
>;

/// P1 ciphersuite: non-PQC, default-shipped by the OpenSSL crypto
/// provider. The full hybrid PQC suite lands in P1.5.
pub const CIPHER_SUITE_P1: CipherSuite = CipherSuite::CURVE25519_AES128;

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
        let crypto = HybridCryptoProvider::new(OpensslCryptoProvider::new());
        let suite = crypto
            .cipher_suite_provider(CIPHER_SUITE_P1)
            .ok_or_else(|| {
                GroupError::Backend("CURVE25519_AES128 not supported by base provider".to_string())
            })?;

        let (signing_key, signing_pub) = suite
            .signature_key_generate()
            .map_err(|e| GroupError::Backend(format!("sig keygen: {e}")))?;

        let credential = BasicCredential::new(display_name.as_bytes().to_vec());
        let identity = SigningIdentity::new(credential.into_credential(), signing_pub);

        let client = Client::builder()
            .identity_provider(BasicIdentityProvider)
            .crypto_provider(crypto)
            .signing_identity(identity, signing_key, CIPHER_SUITE_P1)
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

    const PROTO_MLS: P2pProtocol = P2pProtocol(b"nkct/mls/1");

    /// P1 smoke test: build a `GroupChatProcessor` with a mock
    /// endpoint and round-trip a `create_group` call.
    #[tokio::test]
    async fn create_group_smoke() {
        let net = MockNetwork::new();
        let ep = net.register(PeerId::new([1; 32]), vec![PROTO_MLS]);
        let proc = GroupChatProcessor::new("alice", Arc::new(ep)).expect("builder");

        let gid = proc.create_group().await.expect("create_group");
        // GroupId は 32B 乱数。零値は事故時のみで実運用ではあり得ない。
        assert_ne!(gid.as_bytes(), &[0u8; 32]);
    }
}
