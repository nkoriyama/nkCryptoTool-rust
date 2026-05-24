//! P2P transport abstraction.
//!
//! Application code talks to peers through the [`P2pEndpoint`] and
//! [`P2pStream`] traits and never touches a concrete backend type.
//! Concrete implementations live under `crate::p2p::backend`; an iroh
//! backend will be moved in here from `crate::network::iroh`, and an
//! in-memory `mock` backend is provided for deterministic tests.
//!
//! Design principles:
//!
//! - The trait is shaped by what *this* application needs, not by what
//!   any specific library offers. Adding capabilities is a feature
//!   request, not a default.
//! - No backend-specific type appears in the public surface — concrete
//!   conversions happen inside the backend module and nowhere else.
//! - Errors are normalised to [`P2pError`]; raw backend errors are
//!   never propagated to callers.

pub mod backend;
mod traits;
mod types;

pub use traits::{P2pEndpoint, P2pIncoming, P2pStream};
pub use types::{P2pError, P2pProtocol, PeerAddr, PeerId};
