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

    /// Open a new bidirectional stream to `addr` under `protocol`.
    /// Backends are responsible for NAT traversal, discovery, and relay
    /// fallback as configured at construction time.
    async fn connect(
        &self,
        addr: &PeerAddr,
        protocol: P2pProtocol,
    ) -> Result<Box<dyn P2pStream>, P2pError>;

    /// Wait for the next incoming connection on any registered
    /// protocol. The returned [`P2pIncoming`] reports which protocol
    /// was negotiated so the caller can dispatch accordingly.
    async fn accept(&self) -> Result<P2pIncoming, P2pError>;

    /// Shut the endpoint down. Subsequent `connect` / `accept` calls
    /// return [`P2pError::Closed`].
    async fn close(&self) -> Result<(), P2pError>;
}
