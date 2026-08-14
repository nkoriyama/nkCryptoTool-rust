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

/// Both sides of an `add_member` operation.
///
/// `welcome` is the per-new-member MLS Welcome to be delivered to the
/// admitted peer (see [`crate::group::GroupChatProcessor::send_welcome_to`]).
/// `commit` is the MLS Commit message that *existing* members of the
/// group need to process so they advance to the new epoch — broadcast
/// to every current member except the new joiner via
/// [`crate::group::GroupChatProcessor::broadcast_commit`].
///
/// For a 2-member-after case (group of 1 → 2) the commit has nothing
/// to do downstream because there are no pre-existing members besides
/// the committer; the field is still populated for shape uniformity.
///
/// Both fields are `Zeroizing` because their contents include
/// HPKE-protected secrets bound to the new epoch's key schedule —
/// defense-in-depth wipes them from process memory when callers drop
/// the struct.
pub struct AddMemberOutput {
    pub welcome: Zeroizing<Vec<u8>>,
    pub commit: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for AddMemberOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Don't print the bytes — they include encrypted key material.
        f.debug_struct("AddMemberOutput")
            .field("welcome_len", &self.welcome.len())
            .field("commit_len", &self.commit.len())
            .finish()
    }
}

/// Lightweight description of one group member as returned by
/// [`crate::group::GroupChatProcessor::list_members`].
///
/// Carries only the leaf index for now — the index is the value
/// `commit_builder().remove_member` and
/// `IncomingGroupEvent::Message::sender_index` use to identify
/// members. Display-side identity (name, fingerprint of the
/// SigningIdentity) is intentionally left for P7 (CLI polish) when
/// the UI layer wires up roster rendering.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MemberInfo {
    /// Leaf index in the group's TreeKEM. Stable for the lifetime of
    /// the member; matches the value embedded in incoming MLS messages
    /// and accepted by `remove_member`.
    pub index: u32,
}

/// One event surfaced by
/// [`crate::group::GroupChatProcessor::accept_next`].
///
/// Variants correspond to the MLS message types the application has to
/// react to. P3+P4 added the [`NewGroup`](Self::NewGroup) and basic
/// per-frame ingest; P5 (this revision) extends the dispatcher with
/// [`Message`](Self::Message) (decrypted application body) and
/// [`EpochAdvanced`](Self::EpochAdvanced) (an existing group moved to
/// a new epoch because someone else committed an Add or Remove).
#[derive(Clone, Debug)]
pub enum IncomingGroupEvent {
    /// A `Welcome` was received and processed; we are now a member of
    /// a new group.
    NewGroup {
        id: GroupId,
    },
    /// An application message was received and decrypted.
    Message {
        group_id: GroupId,
        /// Sender's leaf index in the group's TreeKEM. Stable across
        /// the lifetime of a member; combined with the roster (looked
        /// up separately) it identifies who sent the message.
        sender_index: u32,
        /// Decoded body. UTF-8 lossy decoding is the responsibility of
        /// the *display* layer, not this layer — the raw bytes are
        /// returned verbatim so non-text payloads (file metadata,
        /// future binary extensions) remain usable.
        body: Vec<u8>,
    },
    /// An existing group advanced by one epoch because a Commit was
    /// processed. The group state has already been persisted by the
    /// time this event surfaces.
    EpochAdvanced {
        group_id: GroupId,
        new_epoch: u64,
    },
    /// A Commit was processed and its effect was that *we* were
    /// removed from the group (P6). The group state on this side
    /// transitions to a frozen, post-removal state — further
    /// `accept_next` calls for messages in this group will fail,
    /// which is the load-bearing post-compromise-security guarantee:
    /// from this epoch onward we hold no keys that decrypt new traffic.
    RemovedFromGroup {
        group_id: GroupId,
        /// Leaf index of the member who issued the removing commit.
        remover_index: u32,
    },
}

/// Snapshot of a group's state suitable for read-only display.
///
/// Returned by [`crate::group::GroupChatProcessor::load_group_summary`]
/// after reconstructing a group from persistent storage. Carries
/// enough to drive a UI listing (`epoch`, `member_count`) without
/// exposing the underlying `mls_rs::Group` — which is dropped (and
/// its key material zeroized) at the end of the load.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupSummary {
    pub id: GroupId,
    /// Current MLS epoch. Increments by 1 on each Commit.
    pub epoch: u64,
    /// Number of members currently in the group (live LeafNode count).
    pub member_count: usize,
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
    /// The caller-provided byte buffer was not the expected MLS
    /// message type (Welcome / KeyPackage) or failed wire decode.
    /// String carries the underlying detail for logging — callers
    /// match on the variant, not the string content.
    #[error("invalid welcome / key package: {0}")]
    InvalidWelcome(String),
    #[error("transport: {0}")]
    Transport(#[from] crate::p2p::P2pError),
    /// The SYNC responder answered `ERR\x01`, i.e. it **claims** it does not
    /// have us on the roster of the group we asked about.
    ///
    /// Distinct from [`NotMember`](Self::NotMember), which is *our* view of our
    /// own membership, decided from state we hold. This is one peer's assertion
    /// about it, and **nothing authenticates it**: the SYNC exchange proves
    /// nothing about the responder's membership, its view of the roster, or even
    /// that it runs this software. Any node the caller dials can send these four
    /// bytes. A caller that renders this must attribute the claim to that peer,
    /// never restate it as fact and never turn it into a recommendation to
    /// accept a Welcome — `accept_next` authorizes no sender, so acting on one
    /// unauthenticated peer's word is the mistake this wording has to avoid.
    ///
    /// This variant and [`SyncEpochPruned`](Self::SyncEpochPruned) exist so
    /// callers can classify a rejection **on the variant**. The two are told
    /// apart on the wire, and that distinction must be carried out as a type:
    /// classifying by substring on the rendered error was strictly worse, because
    /// a QUIC close reason the peer chose arrives inside `Transport(Connect(..))`
    /// and would match, so *any* failure could be dressed as either rejection.
    /// A transport-level failure must stay a transport-level failure. What the
    /// variant buys is provenance of the four bytes, not their truth.
    #[error("Sync rejected: peer rejected roster or group")]
    SyncRejectedByRoster,
    /// The SYNC responder answered `ERR\x02`, i.e. it **claims** the epoch we
    /// asked from is older than its oldest retained commit, so it cannot bridge
    /// the gap with a delta. See [`SyncRejectedByRoster`](Self::SyncRejectedByRoster)
    /// on why this is a variant rather than a message — and on why it is one
    /// unauthenticated peer's claim rather than a fact about the group.
    #[error("Sync rejected: epoch too old, Welcome fallback needed")]
    SyncEpochPruned,
    #[error("storage: {0}")]
    Storage(String),
    #[error("backend: {0}")]
    Backend(String),
}

impl From<crate::group::redb_storage::RedbStorageError> for GroupError {
    fn from(e: crate::group::redb_storage::RedbStorageError) -> Self {
        GroupError::Storage(e.to_string())
    }
}
