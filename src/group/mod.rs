//! MLS-based group chat (RFC 9420).
//!
//! This module exposes a transport-agnostic group chat layer built on
//! top of the [`mls-rs`](https://docs.rs/mls-rs) library. It sits on
//! the same P2P abstraction as the 1:1 chat (see `src/p2p/`) but uses
//! a dedicated ALPN (`nkct/mls/1`).
//!
//! The phased plan lives at [`MLS_GROUP_CHAT_PLAN.md`](../../MLS_GROUP_CHAT_PLAN.md);
//! this submodule corresponds to **Phase 1** of that plan:
//!
//! - Cargo `mls` feature flag and `mls-rs` dependency set
//! - `src/group/` skeleton (this module)
//! - `crypto_adapter::HybridCryptoProvider<B>` *passthrough* shell
//!   (P1.5 wraps it into a real hybrid PQC ciphersuite)
//! - `GroupChatProcessor::create_group` working with the **non-PQC**
//!   default ciphersuite (`CURVE25519_AES128`) as a smoke test
//!
//! Everything is gated behind `#[cfg(feature = "mls")]` so the default
//! crate build (and all 1:1 chat / file transfer paths) are unaffected.

// `mls` is now backed by the pure-Rust redb storage (`redb_storage`); the
// SQLCipher reader lives only under `legacy-sqlcipher-migration` for the P3
// migration tool.
pub mod at_rest;
pub mod binding;
pub mod cli;
pub mod rollback;
pub mod crypto_adapter;
pub mod file_xfer;
#[cfg(feature = "legacy-sqlcipher-migration")]
pub mod migrate;
pub mod processor;
pub mod redb_storage;
pub mod storage;
pub mod transport;
pub mod types;

pub use at_rest::{
    current_rollback_epoch, open_at_rest_storage, resolve_dek, rotate_dek, AtRestKey, AtRestPaths,
};
pub use crypto_adapter::{hybrid_cipher_suite, HYBRID_SUITE_ID};
pub use processor::GroupChatProcessor;
pub use storage::GroupStorage;
pub use types::{
    AddMemberOutput, GroupError, GroupId, GroupMessage, GroupSummary, IncomingGroupEvent,
    MemberId, MemberInfo, Welcome,
};
