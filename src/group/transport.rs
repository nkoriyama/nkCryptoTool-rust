//! MLS message framing over the `nkct/mls/1` ALPN (P4).
//!
//! Per `MLS_GROUP_CHAT_PLAN.md` §5.4, each accepted stream carries
//! **exactly one** `mls_rs::MlsMessage` — Welcome, Commit, Application,
//! Proposal, or KeyPackage. The framing is intentionally minimal:
//!
//! ```text
//! ┌────────────────────────┬────────────────────────────────────────┐
//! │ u32 little-endian len  │ MlsMessage TLS-presentation bytes      │
//! └────────────────────────┴────────────────────────────────────────┘
//! ```
//!
//! `len` is sized to fit any practical hybrid-suite message (a Welcome
//! for a single new member is on the order of a few KiB; an
//! Application message is bounded by the message body size). We cap
//! it at [`MAX_MLS_FRAME_BYTES`] to refuse obviously hostile inputs.
//!
//! After successfully decoding the body, the receiver writes a single
//! ACK byte back on the same bi-stream. The sender's `send_mls_message`
//! reads this byte before returning — that ensures the sender does not
//! drop its iroh endpoint (and the underlying QUIC connection) while
//! the receiver is still mid-read. Without the ACK, a sender that
//! exits immediately after `shutdown()` returns can race the
//! receiver's `read_exact` for the body and surface a spurious
//! "connection lost" on the receive side. The ACK byte's value is
//! arbitrary (`0x01`); only its presence matters.
//!
//! This module is *transport-only* — it does not interpret the
//! `MlsMessage`. Dispatch by `wire_format()` happens in
//! [`crate::group::processor::GroupChatProcessor`].
//!
//! ## Timeouts
//!
//! Read/write operations are wrapped in
//! [`crate::network::IDLE_TIMEOUT`] (5 minutes), matching the 1:1 chat
//! conventions. A stalled peer therefore fails fast rather than
//! blocking the processor indefinitely.

use mls_rs::MlsMessage;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::network::IDLE_TIMEOUT;
use crate::p2p::{P2pEndpoint, P2pError, P2pProtocol, P2pStream, PeerAddr};

/// Maximum acceptable encoded MLS frame size (16 MiB).
///
/// MLS Welcomes and Commits in this codebase are at most low MiB
/// (hybrid suite gives ~2-3 KiB Welcomes; application messages are
/// bounded by application body size). 16 MiB is a generous over-
/// estimate that still refuses an obviously hostile peer trying to
/// allocate gigabytes via a crafted length prefix.
pub const MAX_MLS_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// `P2pProtocol` constant for the MLS ALPN. Re-exposed here so callers
/// don't need to remember the raw bytes (`crate::network::ALPN_MLS`).
pub const ALPN_MLS_PROTOCOL: P2pProtocol = P2pProtocol(crate::network::ALPN_MLS);

/// Errors raised by the MLS framing layer. These map at the call site
/// into [`crate::group::GroupError`] — most often `Transport` (which
/// already accepts `P2pError` via `From`).
#[derive(thiserror::Error, Debug)]
pub enum FramingError {
    #[error("transport: {0}")]
    Transport(#[from] P2pError),
    #[error("declared frame length {0} exceeds maximum {MAX_MLS_FRAME_BYTES}")]
    FrameTooLarge(usize),
    #[error("declared frame length is zero")]
    EmptyFrame,
    #[error("idle timeout while {0}")]
    Idle(&'static str),
    #[error("I/O error while {what}: {err}")]
    Io {
        what: &'static str,
        err: std::io::Error,
    },
}

/// Write one length-prefixed `MlsMessage` to a stream.
///
/// Encodes the message into its wire bytes, prepends a u32 little-
/// endian length, and writes the whole thing. `stream` is flushed +
/// `shutdown`ed on success so the reader sees an FIN immediately and
/// can release the underlying QUIC stream without waiting for a
/// keepalive.
///
/// This function takes the stream by value because the 1-message-per-
/// stream contract makes any reuse a bug.
pub async fn send_mls_message<S: P2pStream>(
    mut stream: S,
    msg: &MlsMessage,
) -> Result<(), FramingError> {
    let body = msg.to_bytes().map_err(|e| FramingError::Io {
        what: "MLS encode",
        err: std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{e}")),
    })?;
    if body.is_empty() {
        return Err(FramingError::EmptyFrame);
    }
    if body.len() > MAX_MLS_FRAME_BYTES {
        return Err(FramingError::FrameTooLarge(body.len()));
    }

    let len = (body.len() as u32).to_le_bytes();
    tokio::time::timeout(IDLE_TIMEOUT, stream.write_all(&len))
        .await
        .map_err(|_| FramingError::Idle("writing MLS frame length"))?
        .map_err(|e| FramingError::Io {
            what: "writing MLS frame length",
            err: e,
        })?;
    tokio::time::timeout(IDLE_TIMEOUT, stream.write_all(&body))
        .await
        .map_err(|_| FramingError::Idle("writing MLS frame body"))?
        .map_err(|e| FramingError::Io {
            what: "writing MLS frame body",
            err: e,
        })?;
    tokio::time::timeout(IDLE_TIMEOUT, stream.flush())
        .await
        .map_err(|_| FramingError::Idle("flushing MLS frame"))?
        .map_err(|e| FramingError::Io {
            what: "flushing MLS frame",
            err: e,
        })?;
    // Wait for the receiver's ACK byte before returning. Without this,
    // a caller that exits immediately after `send_mls_message`
    // returns can have its iroh endpoint dropped while the receiver
    // is still mid-body — QUIC tears down the connection and the
    // receiver sees a "connection lost" error mid-read. Reading one
    // ACK byte synchronises the close.
    let mut ack = [0u8; 1];
    tokio::time::timeout(IDLE_TIMEOUT, stream.read_exact(&mut ack))
        .await
        .map_err(|_| FramingError::Idle("waiting for receiver ACK"))?
        .map_err(|e| FramingError::Io {
            what: "reading receiver ACK",
            err: e,
        })?;
    if ack[0] != 0x01 {
        return Err(FramingError::Io {
            what: "receiver ACK",
            err: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("expected ACK byte 0x01, got 0x{:02x}", ack[0]),
            ),
        });
    }
    // Only now is it safe to drop our SendStream — shutdown ensures
    // FIN reaches the peer cleanly after the ACK round-trip.
    tokio::time::timeout(IDLE_TIMEOUT, stream.shutdown())
        .await
        .map_err(|_| FramingError::Idle("shutting down MLS stream"))?
        .map_err(|e| FramingError::Io {
            what: "shutting down MLS stream",
            err: e,
        })?;
    Ok(())
}

/// Read one length-prefixed `MlsMessage` from a stream.
///
/// Reads the u32 length prefix, allocates a buffer of exactly that
/// size, reads the body, and decodes. Length prefixes outside
/// `(0, MAX_MLS_FRAME_BYTES]` are rejected before allocation, so a
/// hostile peer cannot make us OOM via a crafted prefix.
///
/// On success, returns the raw bytes too (not just the typed
/// `MlsMessage`) so the caller can persist or forward the frame
/// verbatim without re-encoding it.
pub async fn recv_mls_message<S: P2pStream>(
    mut stream: S,
) -> Result<(MlsMessage, Vec<u8>), FramingError> {
    let mut len_bytes = [0u8; 4];
    tokio::time::timeout(IDLE_TIMEOUT, stream.read_exact(&mut len_bytes))
        .await
        .map_err(|_| FramingError::Idle("reading MLS frame length"))?
        .map_err(|e| FramingError::Io {
            what: "reading MLS frame length",
            err: e,
        })?;
    let len = u32::from_le_bytes(len_bytes) as usize;
    if len == 0 {
        return Err(FramingError::EmptyFrame);
    }
    if len > MAX_MLS_FRAME_BYTES {
        return Err(FramingError::FrameTooLarge(len));
    }

    let mut body = vec![0u8; len];
    tokio::time::timeout(IDLE_TIMEOUT, stream.read_exact(&mut body))
        .await
        .map_err(|_| FramingError::Idle("reading MLS frame body"))?
        .map_err(|e| FramingError::Io {
            what: "reading MLS frame body",
            err: e,
        })?;

    let msg = MlsMessage::from_bytes(&body).map_err(|e| FramingError::Io {
        what: "MLS decode",
        err: std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{e}")),
    })?;
    // Send the ACK byte back so the sender knows we got the whole
    // body. Without this round-trip the sender could exit before the
    // ACK timeout we both depend on for graceful close.
    tokio::time::timeout(IDLE_TIMEOUT, stream.write_all(&[0x01u8]))
        .await
        .map_err(|_| FramingError::Idle("writing receiver ACK"))?
        .map_err(|e| FramingError::Io {
            what: "writing receiver ACK",
            err: e,
        })?;
    tokio::time::timeout(IDLE_TIMEOUT, stream.flush())
        .await
        .map_err(|_| FramingError::Idle("flushing receiver ACK"))?
        .map_err(|e| FramingError::Io {
            what: "flushing receiver ACK",
            err: e,
        })?;
    // Explicitly shutdown the SendStream half. Without this, dropping
    // the stream relies on iroh's lazy close which may not push the
    // ACK byte onto the UDP wire before the receiver process exits.
    // Shutdown's FIN bundles in the pending data and forces it out.
    tokio::time::timeout(IDLE_TIMEOUT, stream.shutdown())
        .await
        .map_err(|_| FramingError::Idle("shutting down ACK stream"))?
        .map_err(|e| FramingError::Io {
            what: "shutting down ACK stream",
            err: e,
        })?;
    Ok((msg, body))
}

/// Convenience: open a fresh `ALPN_MLS` stream to `addr` and send one
/// `MlsMessage`. The stream is implicitly dropped (FIN sent by
/// `send_mls_message`'s shutdown) once the message is written.
pub async fn send_one(
    endpoint: &dyn P2pEndpoint,
    addr: &PeerAddr,
    msg: &MlsMessage,
) -> Result<(), FramingError> {
    let stream = endpoint
        .connect(addr, ALPN_MLS_PROTOCOL)
        .await
        .map_err(FramingError::Transport)?;
    send_mls_message(stream, msg).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p::backend::mock::MockNetwork;
    use crate::p2p::PeerId;

    /// Round-trip a single `KeyPackage` MlsMessage between two
    /// MockEndpoints over a fresh `ALPN_MLS` stream. The framing
    /// layer is what's under test here — the message contents come
    /// from the same `GroupChatProcessor::export_key_package` path
    /// that the higher-level integration test uses.
    #[tokio::test]
    async fn frame_roundtrip_via_mock_network() {
        let net = MockNetwork::new();
        let alice = net.register(PeerId::new([1; 32]), vec![ALPN_MLS_PROTOCOL]);
        let bob = net.register(PeerId::new([2; 32]), vec![ALPN_MLS_PROTOCOL]);

        // Concoct a representative MlsMessage by going through the
        // public processor path. Cheaper / more honest than synthesising
        // one by hand and forces this test to exercise the same encode
        // path the production code uses.
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = crate::group::storage::GroupStorage::open_at(
            dir.path().join("p4_frame_test.db"),
        )
        .expect("storage");
        // Endpoint for the GroupChatProcessor doesn't get used in this
        // test — we only need it to satisfy the constructor.
        let helper_ep = net.register(PeerId::new([9; 32]), vec![ALPN_MLS_PROTOCOL]);
        let helper = crate::group::GroupChatProcessor::new(
            "helper",
            std::sync::Arc::new(helper_ep),
            storage,
        )
        .expect("processor");
        let kp_bytes = helper.export_key_package().await.expect("export kp");

        let bob_addr = bob.local_addr().await.expect("bob addr");

        let server = tokio::spawn(async move {
            let inc = bob.accept().await.expect("bob accept");
            assert_eq!(inc.protocol, ALPN_MLS_PROTOCOL);
            let (msg, raw) = recv_mls_message(inc.stream).await.expect("recv");
            assert_eq!(msg.wire_format(), mls_rs::WireFormat::KeyPackage);
            raw
        });

        // Alice sends the KeyPackage bytes she got from `helper` as if
        // it were her own to publish.
        let msg = mls_rs::MlsMessage::from_bytes(&kp_bytes).expect("decode kp");
        send_one(&alice, &bob_addr, &msg).await.expect("send");
        let echoed = server.await.expect("server task");
        assert_eq!(
            echoed, *kp_bytes,
            "received bytes must match what was sent"
        );
    }

    /// A frame whose length prefix exceeds `MAX_MLS_FRAME_BYTES` is
    /// rejected *before* allocating the body buffer. We test this by
    /// crafting a raw u32 prefix on a duplex pair without going through
    /// `send_mls_message`.
    #[tokio::test]
    async fn frame_too_large_is_rejected_pre_allocation() {
        let (mut tx, rx) = tokio::io::duplex(64);
        let too_big = (MAX_MLS_FRAME_BYTES as u32 + 1).to_le_bytes();
        tx.write_all(&too_big).await.expect("write prefix");
        drop(tx); // signal EOF so reader doesn't wait for the body
        let err = recv_mls_message(rx).await.unwrap_err();
        assert!(
            matches!(err, FramingError::FrameTooLarge(_)),
            "got: {err:?}"
        );
    }

    /// A zero-length frame is rejected with `EmptyFrame`. (mls-rs's
    /// own decoder would reject an empty payload too, but checking
    /// before reading the body lets us fail fast and gives the caller
    /// a clearer error variant.)
    #[tokio::test]
    async fn empty_frame_is_rejected() {
        let (mut tx, rx) = tokio::io::duplex(64);
        tx.write_all(&0u32.to_le_bytes()).await.expect("write zero");
        drop(tx);
        let err = recv_mls_message(rx).await.unwrap_err();
        assert!(matches!(err, FramingError::EmptyFrame), "got: {err:?}");
    }
}
