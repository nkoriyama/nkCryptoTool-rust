//! In-process `P2pEndpoint` for deterministic tests.
//!
//! Two `MockEndpoint`s registered against the same [`MockNetwork`] can
//! `connect` and `accept` each other; the resulting [`P2pStream`]s are
//! the two halves of a `tokio::io::duplex` pair, giving a perfectly
//! reliable in-memory pipe.
//!
//! Intent: let protocol-level tests (handshake framing, chat message
//! framing, file-transfer chunking) run without binding sockets, without
//! NAT traversal, and with no scheduler nondeterminism beyond what
//! tokio's runtime guarantees. NAT / relay / discovery testing
//! deliberately stays the iroh backend's responsibility.
//!
//! This intentionally does NOT model packet loss, reordering, or
//! adversarial peers. Tests that need those should construct their own
//! adversarial stream types.
//!
//! # Example
//! ```ignore
//! use crate::p2p::{P2pEndpoint, P2pProtocol, PeerAddr, PeerId};
//! use crate::p2p::backend::mock::MockNetwork;
//! const PROTO: P2pProtocol = P2pProtocol(b"test/1");
//! let net = MockNetwork::new();
//! let alice = net.register(PeerId::new([1; 32]), vec![PROTO]);
//! let bob   = net.register(PeerId::new([2; 32]), vec![PROTO]);
//! // alice.connect(bob's addr, PROTO) <─pipe─> bob.accept()
//! ```

use crate::p2p::{P2pEndpoint, P2pError, P2pIncoming, P2pProtocol, P2pStream, PeerAddr, PeerId};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};
use tokio::sync::{mpsc, Mutex};

/// Buffer size of each direction of the in-memory duplex. Generous so
/// chat-sized messages never need backpressure mid-test.
const DUPLEX_BUF: usize = 64 * 1024;

/// Shared registry mapping `PeerId` → incoming-connection channel.
/// Created once per test, shared by every `MockEndpoint` in it.
///
/// Uses `std::sync::Mutex` (not `tokio::sync::Mutex`) because every
/// operation holds the lock only for a single sync `HashMap` access —
/// the lock is never held across an `.await`, so we get callable-from-
/// anywhere `register()` without runtime panics.
#[derive(Default)]
pub struct MockNetwork {
    inboxes: StdMutex<HashMap<PeerId, mpsc::UnboundedSender<P2pIncoming>>>,
}

impl MockNetwork {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Register an endpoint for `peer_id` accepting the given
    /// `protocols`. Returns the new endpoint; dropping it (or calling
    /// `close`) removes the inbox so further `connect`s to this peer
    /// fail with `P2pError::Unreachable`.
    pub fn register(
        self: &Arc<Self>,
        peer_id: PeerId,
        protocols: Vec<P2pProtocol>,
    ) -> MockEndpoint {
        let (tx, rx) = mpsc::unbounded_channel();
        self.inboxes
            .lock()
            .expect("MockNetwork inboxes mutex poisoned")
            .insert(peer_id, tx);
        MockEndpoint {
            network: Arc::clone(self),
            peer_id,
            protocols,
            inbox: Mutex::new(rx),
        }
    }
}

/// Per-node `P2pEndpoint` view of a `MockNetwork`.
pub struct MockEndpoint {
    network: Arc<MockNetwork>,
    peer_id: PeerId,
    protocols: Vec<P2pProtocol>,
    inbox: Mutex<mpsc::UnboundedReceiver<P2pIncoming>>,
}

#[async_trait]
impl P2pEndpoint for MockEndpoint {
    fn local_id(&self) -> PeerId {
        self.peer_id
    }

    async fn connect(
        &self,
        addr: &PeerAddr,
        protocol: P2pProtocol,
    ) -> Result<Box<dyn P2pStream>, P2pError> {
        // Reject ALPNs we did not register locally — symmetry with iroh,
        // where the client's ALPN must be in the endpoint's set too.
        if !self.protocols.contains(&protocol) {
            return Err(P2pError::Connect(format!(
                "protocol {:?} not registered on local endpoint",
                protocol
            )));
        }

        let tx = self
            .network
            .inboxes
            .lock()
            .expect("MockNetwork inboxes mutex poisoned")
            .get(&addr.peer_id)
            .cloned()
            .ok_or(P2pError::Unreachable)?;

        let (client_side, server_side) = tokio::io::duplex(DUPLEX_BUF);
        tx.send(P2pIncoming {
            peer_id: self.peer_id,
            protocol,
            stream: Box::new(server_side),
        })
        .map_err(|_| P2pError::Unreachable)?;
        Ok(Box::new(client_side))
    }

    async fn accept(&self) -> Result<P2pIncoming, P2pError> {
        self.inbox
            .lock()
            .await
            .recv()
            .await
            .ok_or(P2pError::Closed)
    }

    async fn close(&self) -> Result<(), P2pError> {
        self.network
            .inboxes
            .lock()
            .expect("MockNetwork inboxes mutex poisoned")
            .remove(&self.peer_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const PROTO_CHAT: P2pProtocol = P2pProtocol(b"test/chat/1");
    const PROTO_FILE: P2pProtocol = P2pProtocol(b"test/file/1");

    fn pid(b: u8) -> PeerAddr {
        PeerAddr::new(PeerId::new([b; 32]))
    }

    /// Two endpoints exchange a byte sequence both ways over the trait;
    /// proves the contract is wireable without any real networking.
    #[tokio::test]
    async fn roundtrip_message_via_trait() {
        let net = MockNetwork::new();
        let alice = net.register(PeerId::new([1; 32]), vec![PROTO_CHAT]);
        let bob = net.register(PeerId::new([2; 32]), vec![PROTO_CHAT]);

        let server = tokio::spawn(async move {
            let inc = bob.accept().await.unwrap();
            assert_eq!(inc.peer_id, PeerId::new([1; 32]));
            assert_eq!(inc.protocol, PROTO_CHAT);
            let mut s = inc.stream;
            let mut buf = [0u8; 5];
            s.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hello");
            s.write_all(b"world").await.unwrap();
            s.shutdown().await.unwrap();
        });

        let mut s = alice.connect(&pid(2), PROTO_CHAT).await.unwrap();
        s.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"world");
        server.await.unwrap();
    }

    /// `connect` to an unregistered peer surfaces `Unreachable`, not a
    /// hang and not a backend-shaped error string.
    #[tokio::test]
    async fn connect_to_unregistered_peer_is_unreachable() {
        let net = MockNetwork::new();
        let alice = net.register(PeerId::new([1; 32]), vec![PROTO_CHAT]);
        let err = match alice.connect(&pid(99), PROTO_CHAT).await {
            Ok(_) => panic!("connect to unregistered peer must fail"),
            Err(e) => e,
        };
        assert!(matches!(err, P2pError::Unreachable), "got {:?}", err);
    }

    /// A client whose ALPN is unknown locally is rejected up front (no
    /// half-open connection delivered to the peer's inbox).
    #[tokio::test]
    async fn connect_with_unregistered_protocol_fails_locally() {
        let net = MockNetwork::new();
        let alice = net.register(PeerId::new([1; 32]), vec![PROTO_CHAT]);
        let _bob = net.register(PeerId::new([2; 32]), vec![PROTO_FILE]);
        let err = match alice.connect(&pid(2), PROTO_FILE).await {
            Ok(_) => panic!("client must reject unknown ALPN before send"),
            Err(e) => e,
        };
        assert!(matches!(err, P2pError::Connect(_)), "got {:?}", err);
    }

    /// `accept` distinguishes which protocol was negotiated so the
    /// caller can dispatch (mirrors iroh's ALPN-multiplexed accept).
    #[tokio::test]
    async fn accept_reports_negotiated_protocol() {
        let net = MockNetwork::new();
        let alice = net.register(PeerId::new([1; 32]), vec![PROTO_CHAT, PROTO_FILE]);
        let bob = net.register(PeerId::new([2; 32]), vec![PROTO_CHAT, PROTO_FILE]);

        let _s1 = alice.connect(&pid(2), PROTO_CHAT).await.unwrap();
        let _s2 = alice.connect(&pid(2), PROTO_FILE).await.unwrap();

        let inc1 = bob.accept().await.unwrap();
        let inc2 = bob.accept().await.unwrap();
        let mut seen = vec![inc1.protocol, inc2.protocol];
        seen.sort_by_key(|p| p.0);
        assert_eq!(seen, vec![PROTO_CHAT, PROTO_FILE]);
    }
}
