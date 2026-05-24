//! Concrete backend implementations of the P2P traits.
//!
//! Each backend lives in its own submodule. The invariant enforced by
//! CI (`! grep -rn 'iroh::' src/ ...`) is that iroh-specific types
//! appear only under `backend/iroh.rs` and nowhere else in the crate.
//!
//! Submodules will be populated in subsequent steps:
//! - `iroh`: moved from `crate::network::iroh`, wraps `iroh::Endpoint`.
//! - `mock`: in-memory `tokio::io::duplex` backend for deterministic
//!   unit tests of application protocols (chat, file transfer).
