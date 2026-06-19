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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_and_suite_id() {
        assert_eq!(library_version(), env!("CARGO_PKG_VERSION"));
        assert_eq!(hybrid_suite_id(), 0xF101);
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
