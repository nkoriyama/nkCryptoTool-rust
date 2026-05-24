//! Concrete backend implementations of the P2P traits.
//!
//! Each backend lives in its own submodule. The invariant enforced by
//! CI (`! grep -rn 'iroh::' src/ ...`) is that iroh-specific types
//! appear only under `backend/iroh.rs` and nowhere else in the crate.
//!
//! - `iroh`: wraps `iroh::Endpoint`. The `IrohEndpoint` skeleton
//!   implements the `P2pEndpoint` trait; the legacy `NetworkProcessor`
//!   still lives here pending its own transport-level refactor.
//! - `mock`: (planned) in-memory `tokio::io::duplex` backend for
//!   deterministic unit tests of application protocols.

pub mod iroh;
