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

pub mod crypto_adapter;
pub mod processor;
pub mod storage;
pub mod types;

pub use crypto_adapter::{hybrid_cipher_suite, HYBRID_SUITE_ID};
pub use processor::GroupChatProcessor;
pub use storage::{GroupStorage, TunedFileStrategy};
pub use types::{GroupError, GroupId, GroupMessage, GroupSummary, MemberId, Welcome};
