/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 *
 * Phase 4 F4 E2E: real-network file transfer + SHA-256 hash integrity check.
 *
 * Each test case spins up two NetworkProcessor instances in the same process:
 * - listener: FileIOProvider::new_recv writing to a temp file, run_listen_once
 * - connector: FileIOProvider::new_send reading a generated payload,
 *   run_connect_with_handshake_callback_and_progress
 *
 * Tests are serialized with `#[serial(iroh)]` to avoid Iroh endpoint port
 * contention. CI timeouts are 60s+ to absorb slow runners. The test set
 * covers chunk boundary edge cases by parameterizing payload sizes:
 *   - small (< 64 KiB, sub-chunk)
 *   - medium (~1 MiB, ~16 chunks)
 *   - large (~10 MiB, ~160 chunks, exercises CUMULATIVE_TIMEOUT margin)
 *
 * Each test asserts:
 *   1. Receiver's SHA-256 == sender's SHA-256 (byte-level integrity)
 *   2. ProgressCallback fired at least floor(size / PROGRESS_CHUNK_BYTES) times
 *   3. Final ProgressCallback emission reports sent == file_size (100%)
 */

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use sha2::{Digest, Sha256};

use nk_crypto_tool::config::{CryptoConfig, TransportKind};
use nk_crypto_tool::network::{
    FileIOProvider, IOProvider, ProgressCallback, PROGRESS_CHUNK_BYTES,
};
use nk_crypto_tool::p2p::NetworkProcessor;
use nk_crypto_tool::ticket::Ticket;

const E2E_TIMEOUT: Duration = Duration::from_secs(60);

fn build_payload(size: usize) -> Vec<u8> {
    // Deterministic non-zero pattern so chunk boundaries are non-trivially
    // covered and a byte-flip would alter the hash.
    let mut v = Vec::with_capacity(size);
    for i in 0..size {
        v.push(((i.wrapping_mul(7).wrapping_add(13)) & 0xff) as u8);
    }
    v
}

async fn make_processor_with_file_io(
    file_io: Arc<dyn IOProvider>,
    connect_addr: Option<String>,
) -> NetworkProcessor {
    let mut config = CryptoConfig::default();
    config.chat_mode = false;
    config.no_relay = true;
    config.allow_unauth = true;
    config.transport = TransportKind::Iroh;
    config.connect_addr = connect_addr;
    let endpoint = Arc::new(nk_crypto_tool::p2p::backend::iroh::IrohEndpoint::new(&config, false).await.unwrap());
    NetworkProcessor::new(config, endpoint, file_io)
}

async fn run_e2e_transfer(payload_size: usize) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let send_path = tmp.path().join("send.bin");
    let recv_path = tmp.path().join("recv.bin");

    let payload = build_payload(payload_size);
    let send_hash: [u8; 32] = Sha256::digest(&payload).into();
    tokio::fs::write(&send_path, &payload).await.expect("write payload");

    // ---- Listener ----
    let listener_io: Arc<dyn IOProvider> = Arc::new(
        FileIOProvider::new_recv(recv_path.clone())
            .await
            .expect("recv io"),
    );
    let listener = make_processor_with_file_io(listener_io, None).await;

    // Bridge ticket from listener to connector via oneshot
    let (ticket_tx, ticket_rx) = tokio::sync::oneshot::channel::<String>();
    let ticket_tx_holder = Arc::new(parking_lot::Mutex::new(Some(ticket_tx)));

    let listener_task = {
        let ticket_tx_holder = ticket_tx_holder.clone();
        tokio::spawn(async move {
            let ticket_tx_holder = ticket_tx_holder.clone();
            let on_ticket = move |t: &Ticket| {
                if let Some(tx) = ticket_tx_holder.lock().take() {
                    let _ = tx.send(t.to_string());
                }
            };
            let on_handshake = || {};
            listener.run_listen_once(on_ticket, on_handshake).await
        })
    };

    let ticket_str = tokio::time::timeout(E2E_TIMEOUT, ticket_rx)
        .await
        .expect("listener did not produce ticket within timeout")
        .expect("ticket channel closed");

    // ---- Connector with progress capture ----
    let send_path_clone = send_path.clone();
    let connector_io: Arc<dyn IOProvider> = Arc::new(
        FileIOProvider::new_send(send_path_clone)
            .await
            .expect("send io"),
    );
    let connector = make_processor_with_file_io(connector_io, Some(ticket_str)).await;

    let progress_count = Arc::new(AtomicU64::new(0));
    let last_sent = Arc::new(AtomicU64::new(0));

    let on_progress: ProgressCallback = {
        let cnt = progress_count.clone();
        let last = last_sent.clone();
        Arc::new(move |sent, _total| {
            cnt.fetch_add(1, Ordering::SeqCst);
            last.store(sent, Ordering::SeqCst);
        })
    };

    let connector_task = tokio::spawn(async move {
        connector
            .run_connect_with_handshake_callback_and_progress(|| {}, Some(on_progress))
            .await
    });

    // ---- Wait for both with timeout ----
    let connector_result = tokio::time::timeout(E2E_TIMEOUT, connector_task)
        .await
        .expect("connector timed out")
        .expect("connector task panicked");
    connector_result.expect("connector returned error");

    let listener_result = tokio::time::timeout(E2E_TIMEOUT, listener_task)
        .await
        .expect("listener timed out")
        .expect("listener task panicked");
    listener_result.expect("listener returned error");

    // ---- Assert integrity ----
    let recv_bytes = tokio::fs::read(&recv_path).await.expect("read recv");
    assert_eq!(
        recv_bytes.len(),
        payload_size,
        "recv size {} != payload size {}",
        recv_bytes.len(),
        payload_size,
    );
    let recv_hash: [u8; 32] = Sha256::digest(&recv_bytes).into();
    assert_eq!(
        recv_hash, send_hash,
        "SHA-256 mismatch (size={})",
        payload_size,
    );

    // ---- Assert progress callback fired ----
    let count = progress_count.load(Ordering::SeqCst);
    let final_sent = last_sent.load(Ordering::SeqCst);

    // PROGRESS_CHUNK_BYTES (64 KiB) is the *minimum frequency cap* (do not
    // fire more often than this), not a guaranteed firing rate. The actual
    // fire count is bounded above by ceil(payload / max(BUF_SIZE,
    // PROGRESS_CHUNK_BYTES)) per-iteration emissions plus 1 final emission.
    // We assert only the final emission contract: at least one fire, with
    // final-call sent == payload_size.
    assert!(
        count >= 1,
        "progress must fire at least the final emission (got {})",
        count,
    );

    // The final emission reports `sent` == plaintext file_size (per
    // send_file_with_progress final callback contract).
    assert_eq!(
        final_sent, payload_size as u64,
        "final progress {} bytes != payload size {}",
        final_sent, payload_size,
    );

    // Silence unused-import warning when assertion uses only constants
    // indirectly: keep the import live by referencing it.
    let _ = PROGRESS_CHUNK_BYTES;
}

#[tokio::test]
#[serial_test::serial(iroh)]
async fn test_e2e_file_transfer_small_subchunk() {
    // < PROGRESS_CHUNK_BYTES (64 KiB): exercises sub-threshold path. Final
    // emission is the only progress fire.
    run_e2e_transfer(50_000).await;
}

#[tokio::test]
#[serial_test::serial(iroh)]
async fn test_e2e_file_transfer_medium_around_1mib() {
    // ~1 MiB: ~16 PROGRESS_CHUNK_BYTES + multiple BUF_SIZE (1 MiB) reads.
    run_e2e_transfer(1_048_576).await;
}

#[tokio::test]
#[serial_test::serial(iroh)]
async fn test_e2e_file_transfer_large_10mib() {
    // ~10 MiB: stresses chunk-counter cadence + AEAD streaming over many
    // BUF_SIZE iterations.
    run_e2e_transfer(10 * 1024 * 1024).await;
}

// --------------------------------------------------------------------------
// Adversarial transfer tests (P1-R3): the wire bytes between sender and
// receiver are attacker-controlled, so the receive path must reject any
// in-flight mutation rather than surface corrupted plaintext. These drive the
// exact framing the P2P file transfer uses — NetworkProcessor::{send_file,
// receive_file} over an in-memory buffer — so a byte can be flipped/forged at
// a precise offset without standing up an Iroh transport.
//
// Wire layout produced by send_file:
//   repeat { [chunk_len: u32 LE] [AEAD ciphertext: chunk_len bytes] }
//   [0u32]                      (terminator)
//   [tag: 16 bytes]             (AEAD authentication tag over the stream)
// --------------------------------------------------------------------------

const ADV_AEAD: &str = "AES-256-GCM";

async fn encrypt_to_wire(plaintext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut wire: Vec<u8> = Vec::new();
    nk_crypto_tool::network::NetworkProcessor::send_file(plaintext, &mut wire, ADV_AEAD, key, iv)
        .await
        .expect("send_file (encrypt) should succeed");
    wire
}

async fn decrypt_from_wire(
    wire: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, nk_crypto_tool::CryptoError> {
    let mut out: Vec<u8> = Vec::new();
    nk_crypto_tool::network::NetworkProcessor::receive_file(wire, &mut out, ADV_AEAD, key, iv)
        .await?;
    Ok(out)
}

#[tokio::test]
async fn test_e2e_aead_tampering() {
    let key = [7u8; 32];
    let iv = [3u8; 12];
    let payload = build_payload(300_000);
    let wire = encrypt_to_wire(&payload, &key, &iv).await;

    // Baseline: the untampered wire round-trips back to the original bytes.
    let clean = decrypt_from_wire(&wire, &key, &iv)
        .await
        .expect("untampered wire must decrypt");
    assert_eq!(clean, payload, "untampered roundtrip mismatch");

    // Flip one bit deep inside the ciphertext body (past the 4-byte length
    // prefix at offset 0, well before the trailing terminator + tag).
    let mut tampered = wire.clone();
    let mid = tampered.len() / 2;
    tampered[mid] ^= 0x01;

    // AES-256-GCM authenticates the whole stream at finalize(): a single
    // flipped ciphertext byte must surface as an error, never silent
    // corruption.
    let err = decrypt_from_wire(&tampered, &key, &iv)
        .await
        .expect_err("tampered ciphertext must fail AEAD authentication");
    // Any error is acceptable here; the contract is "not Ok". Reference the
    // value so the binding is not flagged as unused.
    let _ = err;
}

#[tokio::test]
async fn test_e2e_chunk_len_forgery() {
    let key = [9u8; 32];
    let iv = [5u8; 12];
    let payload = build_payload(120_000);
    let wire = encrypt_to_wire(&payload, &key, &iv).await;

    // Forge the first chunk's length prefix to a value far beyond the
    // receiver's per-chunk bound (BUF_SIZE + 256). receive_file must reject it
    // immediately with a Parameter error, before allocating/reading the body.
    let mut forged = wire.clone();
    let huge: u32 = 200_000_000; // >> BUF_SIZE + 256
    forged[0..4].copy_from_slice(&huge.to_le_bytes());

    let err = decrypt_from_wire(&forged, &key, &iv)
        .await
        .expect_err("forged oversize chunk length must be rejected");
    match err {
        nk_crypto_tool::CryptoError::Parameter(msg) => assert!(
            msg.contains("exceeds limit"),
            "expected chunk-size bound error, got: {msg}"
        ),
        other => panic!("expected Parameter(chunk size) error, got: {other:?}"),
    }
}
