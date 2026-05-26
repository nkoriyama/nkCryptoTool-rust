//! Public types for the MLS group chat API.
//!
//! These types are intentionally library-independent: callers should
//! never see `mls_rs::*` types. Conversions to/from `mls-rs` types live
//! inside `crate::group::processor` and `crate::group::crypto_adapter`.

use std::fmt;
use zeroize::Zeroizing;

use crate::p2p::PeerAddr;

/// 32-byte MLS group identifier.
///
/// Generated as a cryptographic random value when the group is created;
/// stable for the lifetime of the group.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct GroupId(pub [u8; 32]);

impl GroupId {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for GroupId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GroupId({})", hex::encode(self.0))
    }
}

impl fmt::Display for GroupId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// Identifier for an MLS group member.
///
/// Distinct from `crate::p2p::PeerId`: a single user may run several
/// nkCryptoTool devices, each appearing as its own MLS member. The
/// transport-layer `PeerId` identifies devices on the network; this
/// `MemberId` identifies an MLS LeafNode credential.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MemberId(pub [u8; 32]);

impl MemberId {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for MemberId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MemberId({})", hex::encode(self.0))
    }
}

impl fmt::Display for MemberId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// One application-level message in a group.
///
/// `body` is UTF-8; non-UTF-8 incoming bytes are lossy-decoded into
/// U+FFFD (`String::from_utf8_lossy`) so partial-but-readable messages
/// always reach the recipient.
#[derive(Clone, Debug)]
pub struct GroupMessage {
    pub sender: MemberId,
    /// MLS epoch the message was sent in. Useful for ordering within
    /// the group and detecting late deliveries.
    pub epoch: u64,
    /// Unix milliseconds at the sender's clock.
    pub timestamp_ms: u64,
    pub body: String,
}

/// An MLS Welcome message bound for a specific recipient.
///
/// The byte buffer is wrapped in `Zeroizing` because Welcome carries
/// the new member's HPKE-encrypted view into the group key tree;
/// defense-in-depth wipes it from process memory on drop.
pub struct Welcome {
    pub recipient: PeerAddr,
    pub bytes: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for Welcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Welcome")
            .field("recipient", &self.recipient)
            .field("bytes_len", &self.bytes.len())
            .finish()
    }
}

/// Errors surfaced by the group chat API. Library-specific errors are
/// caught at the boundary and wrapped in `Backend(String)` so callers
/// never depend on a concrete `mls-rs` error type.
#[derive(thiserror::Error, Debug)]
pub enum GroupError {
    #[error("group not found")]
    NotFound,
    #[error("not a member of this group")]
    NotMember,
    #[error("invalid welcome / key package")]
    InvalidWelcome,
    #[error("transport: {0}")]
    Transport(#[from] crate::p2p::P2pError),
    #[error("storage: {0}")]
    Storage(String),
    #[error("backend: {0}")]
    Backend(String),
}
