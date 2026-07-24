//! Application-defined P2P transport traits.
//!
//! Two layers: an [`P2pEndpoint`] (a local node) hands out
//! [`P2pStream`]s (bidirectional byte streams) keyed by a
//! [`P2pProtocol`]. The current application uses one stream per
//! connection per protocol, so an explicit connection layer is not
//! exposed; backends may keep one internally.

use crate::p2p::types::{P2pError, P2pProtocol, PeerAddr, PeerId};
use tokio::io::{AsyncRead, AsyncWrite};

/// A bidirectional byte stream. Concrete backings include an iroh QUIC
/// bi-stream pair joined into one type, a libp2p substream, or an
/// in-memory `tokio::io::duplex` half in tests.
pub trait P2pStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: ?Sized + AsyncRead + AsyncWrite + Send + Unpin> P2pStream for T {}

/// An incoming connection: which peer, which negotiated protocol, and
/// the established bidirectional stream ready for application use.
pub struct P2pIncoming {
    pub peer_id: PeerId,
    pub protocol: P2pProtocol,
    pub stream: Box<dyn P2pStream>,
}

/// Bound on the per-connection setup that [`P2pPending::establish`] runs
/// (protocol negotiation + stream open). Generous enough for a real cross-NAT /
/// relay handshake, short enough to cut a peer that completes the QUIC handshake
/// then never opens a stream (a Slowloris-style accept-loop stall).
pub const P2P_SETUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Why [`P2pPending::establish`] failed, plus the remote's identity when setup
/// got far enough to have one.
///
/// The split exists so the listener can throttle a peer that stalls connection
/// setup. Setup has two phases with different attribution:
///
/// * **Before** the transport handshake completes there is no *authenticated*
///   identity — only a claimed one. Attributing a failure to it would let any
///   peer get a third party throttled, so `peer_id` is `None` and the failure
///   goes unrecorded.
/// * **After** it completes, the identity is proven. A peer that finishes the
///   handshake and then never opens a stream — the Slowloris shape, which holds
///   an accept slot for the whole `timeout` — is attributable, and the caller
///   records it so a repeat offender is refused at the next accept.
#[derive(Debug)]
pub struct EstablishError {
    /// The remote's proven transport identity, or `None` when the failure
    /// predates authentication (see the type docs).
    pub peer_id: Option<PeerId>,
    pub error: P2pError,
}

impl EstablishError {
    /// A failure with no authenticated peer to attribute it to.
    pub fn anonymous(error: P2pError) -> Self {
        Self { peer_id: None, error }
    }

    /// A failure attributable to an already-authenticated peer.
    pub fn attributed(peer_id: PeerId, error: P2pError) -> Self {
        Self { peer_id: Some(peer_id), error }
    }
}

impl std::fmt::Display for EstablishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}

impl std::error::Error for EstablishError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

impl From<EstablishError> for P2pError {
    fn from(e: EstablishError) -> Self {
        e.error
    }
}

/// A half-open incoming connection whose per-peer setup — protocol negotiation
/// and opening the bidirectional stream — has **not** run yet. Accepting one is
/// cheap and cannot be stalled by the peer, so the listener can accept the next
/// connection immediately and run [`establish`](Self::establish) off the accept
/// loop (bounded by a concurrency permit + `timeout`), removing the head-of-line
/// stall where one slow/malicious peer blocks all new connections.
#[async_trait::async_trait]
pub trait P2pPending: Send {
    /// Negotiate the protocol and open the bidirectional stream, bounded by
    /// `timeout`. A peer that stalls this (e.g. never opens the stream) yields a
    /// timeout error rather than blocking forever. On failure the error carries
    /// the peer's identity when setup got far enough to prove one, so the caller
    /// can throttle a peer that repeatedly stalls — see [`EstablishError`].
    async fn establish(
        self: Box<Self>,
        timeout: std::time::Duration,
    ) -> Result<P2pIncoming, EstablishError>;
}

/// A local P2P node — the origin of outgoing connections and the
/// recipient of incoming ones.
///
/// Supported application protocols (ALPN-style) are declared at
/// endpoint construction time (e.g. via a backend builder), not on each
/// `accept` call. The trait stays narrow on purpose: only operations
/// the application actually needs are exposed here.
#[async_trait::async_trait]
pub trait P2pEndpoint: Send + Sync {
    /// This node's stable identifier.
    fn local_id(&self) -> PeerId;

    /// This node's reachable address (PeerId + optional relay URL +
    /// known direct socket addresses). Used by listener-side code to
    /// build connection tickets without exposing a backend type. May
    /// involve awaiting backend reachability initialisation.
    async fn local_addr(&self) -> Result<PeerAddr, P2pError>;

    /// Open a new bidirectional stream to `addr` under `protocol`.
    /// Backends are responsible for NAT traversal, discovery, and relay
    /// fallback as configured at construction time.
    async fn connect(
        &self,
        addr: &PeerAddr,
        protocol: P2pProtocol,
    ) -> Result<Box<dyn P2pStream>, P2pError>;

    /// Wait for the next incoming connection. Returns a [`P2pPending`] whose
    /// per-peer setup has not run yet, so this call cannot be stalled by the
    /// peer; the caller runs [`P2pPending::establish`] off the accept loop to
    /// learn the negotiated protocol and obtain the stream.
    async fn accept(&self) -> Result<Box<dyn P2pPending>, P2pError>;

    /// Shut the endpoint down. Subsequent `connect` / `accept` calls
    /// return [`P2pError::Closed`].
    async fn close(&self) -> Result<(), P2pError>;

    /// Pollable live metrics for the most recent outgoing [`connect`](Self::connect),
    /// if the backend can report them (iroh reports relay/direct + RTT; others
    /// return `None`). Queried right after a successful connect by the status bar.
    fn last_connect_metrics(&self) -> Option<std::sync::Arc<dyn crate::p2p::ConnMetrics>> {
        None
    }
}
