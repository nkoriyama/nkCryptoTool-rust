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

// The sqlite-backed group stack. `mls-redb` (pure-Rust storage) compiles only
// `redb_storage` from this module — the rest still assumes the sqlite provider
// and is gated to `mls` until the P4 cutover rewires them onto redb.
#[cfg(feature = "mls")]
pub mod at_rest;
#[cfg(feature = "mls")]
pub mod cli;
#[cfg(feature = "mls")]
pub mod rollback;
#[cfg(feature = "mls")]
pub mod crypto_adapter;
#[cfg(feature = "mls")]
pub mod processor;
#[cfg(feature = "mls-redb")]
pub mod redb_storage;
#[cfg(feature = "mls")]
pub mod storage;
#[cfg(feature = "mls")]
pub mod transport;
#[cfg(feature = "mls")]
pub mod types;

#[cfg(feature = "mls")]
pub use at_rest::{
    current_rollback_epoch, open_at_rest_storage, resolve_dek, rotate_dek, AtRestKey, AtRestPaths,
};
#[cfg(feature = "mls")]
pub use crypto_adapter::{hybrid_cipher_suite, HYBRID_SUITE_ID};
#[cfg(feature = "mls")]
pub use processor::GroupChatProcessor;
#[cfg(feature = "mls")]
pub use storage::{GroupStorage, TunedFileStrategy};
#[cfg(feature = "mls")]
pub use types::{
    AddMemberOutput, GroupError, GroupId, GroupMessage, GroupSummary, IncomingGroupEvent,
    MemberId, MemberInfo, Welcome,
};
