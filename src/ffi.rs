//! UniFFI bridge (P-mobile, scaffolding) — exposes a C-ABI / Kotlin / Swift
//! surface over the MLS chat & crypto core so a mobile app can drive it.
//!
//! Compiled only with the `mobile-ffi` feature, into the `cdylib`
//! (`libnk_crypto_tool.so`). Kotlin bindings are generated with the bundled
//! `uniffi-bindgen` bin — see `BUILD_ANDROID.md`.
//!
//! This is the *scaffolding* increment: a small, real surface that proves the
//! bridge compiles, links the MLS core, and marshals data across the FFI. The
//! stateful chat API (`GroupChatProcessor`, async send/receive over iroh) is
//! layered on top of this in later increments as UniFFI objects.

use sha3::{Digest, Sha3_256};

// NOTE: `uniffi::setup_scaffolding!()` is invoked at the crate root (lib.rs) so
// the generated `UniFfiTag` lives where `#[uniffi::export]` expects it.

/// Errors surfaced across the FFI boundary.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiError {
    #[error("invalid input: {reason}")]
    InvalidInput { reason: String },
    #[error("chat error: {reason}")]
    Chat { reason: String },
}

impl FfiError {
    fn chat(e: impl std::fmt::Display) -> Self {
        FfiError::Chat { reason: e.to_string() }
    }
}

/// Crate version (`CARGO_PKG_VERSION`). A trivial round-trip that confirms the
/// generated bindings load the library and marshal a `String` back.
#[uniffi::export]
pub fn library_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// The hybrid PQC MLS cipher-suite id (Ed25519‖ML-DSA-65 + X-Wing), `0xF101`.
/// Proves the FFI links against the actual `mls` core, not just a stub.
#[uniffi::export]
pub fn hybrid_suite_id() -> u16 {
    crate::group::HYBRID_SUITE_ID
}

/// SHA3-256 fingerprint of `data` as lowercase hex — the same digest the CLI's
/// `--fingerprint` uses for public keys. Exercises `bytes -> string`
/// marshalling end-to-end.
#[uniffi::export]
pub fn sha3_256_fingerprint(data: Vec<u8>) -> Result<String, FfiError> {
    if data.is_empty() {
        return Err(FfiError::InvalidInput {
            reason: "empty input".to_string(),
        });
    }
    let digest = Sha3_256::digest(&data);
    Ok(hex::encode(digest))
}

// ===================== Stateful chat client =========================

use std::sync::Arc;

/// A mobile-facing handle to the MLS group-chat engine: opens (or creates) the
/// encrypted redb storage + at-rest keys under `storage_dir`, binds an iroh
/// endpoint, and drives [`GroupChatProcessor`].
///
/// Held behind a `tokio::Mutex` so the (`&self`, async) methods can be called
/// from any foreign thread. This increment exposes the local operations
/// (create / list groups); peer-to-peer send & receive over iroh — which need
/// two live nodes — are layered on next.
#[derive(uniffi::Object)]
pub struct MobileChatClient {
    inner: tokio::sync::Mutex<crate::group::GroupChatProcessor>,
}

#[uniffi::export(async_runtime = "tokio")]
impl MobileChatClient {
    /// Open the chat engine. `storage_dir` holds `groups.db` (+ at-rest key
    /// files) and the persistent iroh `node.key`. `passphrase` unlocks the
    /// at-rest key hierarchy. `disable_relay` binds the iroh endpoint without
    /// the public relays (useful offline / on a LAN / in tests).
    #[uniffi::constructor]
    pub async fn open(
        storage_dir: String,
        passphrase: String,
        display_name: String,
        disable_relay: bool,
    ) -> Result<Arc<Self>, FfiError> {
        use crate::group::{open_at_rest_storage, AtRestPaths, GroupChatProcessor};
        use crate::p2p::P2pEndpoint;

        if passphrase.is_empty() {
            return Err(FfiError::InvalidInput { reason: "empty passphrase".into() });
        }
        let dir = std::path::PathBuf::from(&storage_dir);
        std::fs::create_dir_all(&dir).map_err(FfiError::chat)?;

        let mut cfg = crate::config::CryptoConfig::default();
        cfg.node_key_path = Some(dir.join("node.key"));
        cfg.no_relay = disable_relay;

        let endpoint = crate::p2p::backend::iroh::IrohEndpoint::new(&cfg, false)
            .await
            .map_err(FfiError::chat)?;
        let endpoint: Arc<dyn P2pEndpoint> = Arc::new(endpoint);

        let paths = AtRestPaths::from_db_path(dir.join("groups.db"));
        let storage = open_at_rest_storage(&paths, &zeroize::Zeroizing::new(passphrase))
            .map_err(FfiError::chat)?;

        let proc = GroupChatProcessor::new(&display_name, endpoint, storage)
            .map_err(FfiError::chat)?;
        Ok(Arc::new(Self { inner: tokio::sync::Mutex::new(proc) }))
    }

    /// Create a new MLS group; returns its 32-byte id as lowercase hex.
    pub async fn create_group(&self) -> Result<String, FfiError> {
        let proc = self.inner.lock().await;
        let gid = proc.create_group().await.map_err(FfiError::chat)?;
        Ok(hex::encode(gid.as_bytes()))
    }

    /// List the ids (lowercase hex) of all groups in local storage.
    pub async fn list_groups(&self) -> Result<Vec<String>, FfiError> {
        let proc = self.inner.lock().await;
        let ids = proc.list_groups().map_err(FfiError::chat)?;
        Ok(ids.iter().map(|g| hex::encode(g.as_bytes())).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_and_suite_id() {
        assert_eq!(library_version(), env!("CARGO_PKG_VERSION"));
        assert_eq!(hybrid_suite_id(), 0xF101);
    }

    #[tokio::test]
    async fn chat_client_create_and_list_groups() {
        // Headless: relay disabled so the iroh endpoint binds offline. Group
        // creation is a local MLS op (no peer needed).
        let dir = tempfile::tempdir().expect("tempdir");
        let client = MobileChatClient::open(
            dir.path().to_string_lossy().into_owned(),
            "ffi-test-pass".to_string(),
            "alice".to_string(),
            true, // disable_relay
        )
        .await
        .expect("open client");

        assert!(client.list_groups().await.expect("list").is_empty());
        let gid = client.create_group().await.expect("create group");
        assert_eq!(gid.len(), 64, "group id is 32 bytes as hex");
        let groups = client.list_groups().await.expect("list");
        assert_eq!(groups, vec![gid]);
    }

    #[test]
    fn fingerprint_roundtrips() {
        // SHA3-256("") would be rejected; a non-empty input yields 64 hex chars.
        let fp = sha3_256_fingerprint(vec![1, 2, 3]).expect("fp");
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(matches!(
            sha3_256_fingerprint(vec![]),
            Err(FfiError::InvalidInput { .. })
        ));
    }
}
