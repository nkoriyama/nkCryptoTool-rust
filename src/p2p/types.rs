//! Application-native types for the P2P abstraction.
//!
//! These types are intentionally backend-independent. Concrete
//! conversions (e.g. `iroh::NodeId` ↔ [`PeerId`]) live inside
//! `crate::p2p::backend::iroh` and nowhere else.

use std::net::SocketAddr;

/// Peer identifier — a 32-byte public-key-based identity. Maps to
/// `iroh::NodeId` (ed25519 pubkey) or libp2p's `PeerId` in concrete
/// backends, but the trait-facing type stays library-independent.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerId([u8; 32]);

impl PeerId {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, P2pError> {
        if bytes.len() != 32 {
            return Err(P2pError::InvalidPeerId);
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(bytes);
        Ok(Self(id))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl std::fmt::Debug for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PeerId({})", hex::encode(self.0))
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl std::str::FromStr for PeerId {
    type Err = P2pError;
    fn from_str(s: &str) -> Result<Self, P2pError> {
        let bytes = hex::decode(s).map_err(|_| P2pError::InvalidPeerId)?;
        Self::from_bytes(&bytes)
    }
}

/// A reachable address for a peer, agnostic of the underlying transport.
/// Mirrors the shape of iroh's `NodeAddr` (relay URL + direct addresses)
/// but is expressible by any reasonable P2P transport.
#[derive(Clone, Debug)]
pub struct PeerAddr {
    pub peer_id: PeerId,
    /// Optional relay URL the peer can be reached through.
    pub relay_url: Option<String>,
    /// Known direct socket addresses (NAT'd or routable).
    pub direct_addrs: Vec<SocketAddr>,
}

impl PeerAddr {
    pub fn new(peer_id: PeerId) -> Self {
        Self {
            peer_id,
            relay_url: None,
            direct_addrs: Vec::new(),
        }
    }
}

/// ALPN-style protocol identifier used for multiplexing distinct
/// application protocols over a single endpoint (e.g. `nkct/chat/1`,
/// `nkct/file/1`). Wraps a byte slice so callers can use stable byte
/// constants without allocation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct P2pProtocol(pub &'static [u8]);

/// Errors surfaced by the P2P abstraction. Backend-specific errors are
/// caught at the backend boundary and wrapped in `Backend(String)` so
/// callers never depend on a concrete library's error type.
#[derive(thiserror::Error, Debug)]
pub enum P2pError {
    #[error("connection failed: {0}")]
    Connect(String),
    #[error("accept failed: {0}")]
    Accept(String),
    #[error("send failed: {0}")]
    Send(String),
    #[error("receive failed: {0}")]
    Recv(String),
    #[error("peer not found / unreachable")]
    Unreachable,
    #[error("connection closed")]
    Closed,
    #[error("invalid peer id")]
    InvalidPeerId,
    #[error("backend error: {0}")]
    Backend(String),
}

/// A point-in-time view of the live connection's selected path: whether it is
/// relayed and its round-trip estimate. Backend-neutral so the UI layer (the
/// shell status bar) does not depend on iroh types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnSnapshot {
    /// The selected path is carried over a relay (vs a direct hole-punched path).
    pub relay: bool,
    /// Round-trip time of the selected path, milliseconds.
    pub rtt_ms: Option<u32>,
}

/// Pollable source of [`ConnSnapshot`]s for an established connection. A backend
/// that can report live path metrics (iroh) provides one; others return `None`.
pub trait ConnMetrics: Send + Sync {
    /// Current selected-path snapshot, or `None` if no path is selected yet.
    fn snapshot(&self) -> Option<ConnSnapshot>;
}
