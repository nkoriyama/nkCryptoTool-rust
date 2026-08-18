/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 *
 * Adversarial handshake tests (P1-R3, Gemini §3.2#4): handshake signature
 * tampering is a distinct threat model from in-flight file-transfer
 * corruption, so it lives in its own file.
 *
 * The responder has two independent gates on the initiator's identity, and
 * they fail in a fixed order. One test per gate, because a test that stops at
 * the first gate says nothing about the second:
 *
 * 1. `test_handshake_signature_tampering` — a real client whose key is NOT the
 *    one the server pinned with `--signing-pubkey`. The responder compares the
 *    wire `#6` against the pinned key BEFORE reading sig_I, so this is
 *    rejected at the pin ("Client public key mismatch with pinned key") and
 *    never reaches the signature check.
 *
 * 2. `test_handshake_forged_transcript_signature` — the only input that
 *    reaches the signature check: `#6` IS the pinned key (so gate 1 passes)
 *    but sig_I over the transcript was made by a different key. No stock
 *    client can produce that frame (it derives `#6` from the key it signs
 *    with), so the initiator half is hand-rolled over the in-process mock
 *    transport, and a positive control signs the same frame with the pinned
 *    key to prove the hand-rolled transcript is the one the responder builds.
 *
 * Both assert on the specific rejection, not merely on `is_err()`: a listener
 * that refuses the service outright (e.g. at the ALPN gate) errors too, and
 * would otherwise satisfy the assertion just as well as a rejected forgery.
 */

use std::fs;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;

use nk_crypto_tool::backend;
use nk_crypto_tool::config::{CryptoConfig, TransportKind};
use nk_crypto_tool::error::CryptoError;
// The unit struct that owns the handshake's wire codec (length-prefixed fields
// and the transcript encoding). Using the production helpers rather than a
// re-implementation keeps the hand-rolled initiator below byte-identical to the
// real one.
use nk_crypto_tool::network::NetworkProcessor as WireCodec;
use nk_crypto_tool::network::{FileIOProvider, IOProvider, ALPN_FILE};
use nk_crypto_tool::p2p::backend::mock::MockNetwork;
use nk_crypto_tool::p2p::NetworkProcessor;
use nk_crypto_tool::p2p::{P2pEndpoint, P2pProtocol, PeerAddr, PeerId};
use nk_crypto_tool::ticket::Ticket;
use nk_crypto_tool::utils;

const E2E_TIMEOUT: Duration = Duration::from_secs(60);
const DSA: &str = "ML-DSA-65";
/// Must match `CryptoConfig::default().pqc_kem_algo`: the responder length-checks
/// `#4` against its own configured KEM algorithm.
const KEM: &str = "ML-KEM-768";

/// FIPS 204 context string the handshake signs under (`HANDSHAKE_CTX_IROH` in
/// `src/p2p/processor.rs`, which is private). The positive control in
/// `test_handshake_forged_transcript_signature` is what catches drift here: if
/// this constant went stale, the control's *valid* signature would stop
/// verifying and that test would fail rather than pass vacuously.
const HANDSHAKE_CTX_IROH: &[u8] = b"nkct-handshake-iroh-v1";
/// `#5` bit0 (`hs_flags::INITIATOR_SELF_AUTH`, also private): the initiator
/// authenticates itself, which gates `#6` + sig_I — the fields under test.
const INITIATOR_SELF_AUTH: u8 = 0x01;

fn write_priv(path: &std::path::Path, raw: &[u8]) {
    let pkcs8 = utils::wrap_pqc_priv_to_pkcs8(raw, DSA).expect("wrap priv");
    fs::write(path, utils::wrap_to_pem(&pkcs8, "PRIVATE KEY")).expect("write priv pem");
}

fn write_pub(path: &std::path::Path, raw: &[u8]) {
    let spki = utils::wrap_pqc_pub_to_spki(raw, DSA).expect("wrap pub");
    fs::write(path, utils::wrap_to_pem(&spki, "PUBLIC KEY")).expect("write pub pem");
}

async fn make_processor(config: CryptoConfig, io: Arc<dyn IOProvider>) -> NetworkProcessor {
    let endpoint = Arc::new(
        nk_crypto_tool::p2p::backend::iroh::IrohEndpoint::new(&config, false)
            .await
            .expect("iroh endpoint"),
    );
    NetworkProcessor::new(config, endpoint, io)
}

#[tokio::test]
#[serial_test::serial(iroh)]
async fn test_handshake_signature_tampering() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let s_key = tmp.path().join("server.priv.pem");
    let s_pub = tmp.path().join("server.pub.pem");
    let cb_pub = tmp.path().join("client_trusted.pub.pem");
    let ca_key = tmp.path().join("client_attacker.priv.pem");

    // Server identity, the trusted client identity (B), and the attacker
    // identity (A) the client will actually sign with.
    let (s_priv_raw, s_pub_raw, _) = backend::pqc_keygen_dsa(DSA).expect("server keygen");
    let (_cb_priv_raw, cb_pub_raw, _) = backend::pqc_keygen_dsa(DSA).expect("trusted client keygen");
    let (ca_priv_raw, _ca_pub_raw, _) = backend::pqc_keygen_dsa(DSA).expect("attacker client keygen");

    write_priv(&s_key, &s_priv_raw);
    write_pub(&s_pub, &s_pub_raw);
    write_pub(&cb_pub, &cb_pub_raw); // server trusts B's public key
    write_priv(&ca_key, &ca_priv_raw); // client signs with A's private key

    // ---- Server: auth required, trusts only client B ----
    let mut server_config = CryptoConfig::default();
    server_config.transport = TransportKind::Iroh;
    server_config.no_relay = true;
    server_config.chat_mode = false;
    // The connector below dials ALPN_FILE, which is gated on `serve_chat` the
    // way shell/scp/forward are gated on their own flags (same idiom as
    // tests/e2e_file_transfer.rs). Without it the listener refuses at the ALPN
    // gate before a single handshake byte is read, and this test would assert
    // nothing about the handshake.
    server_config.serve_chat = true;
    server_config.allow_unauth = false;
    server_config.signing_privkey = Some(s_key.to_str().unwrap().to_string());
    server_config.signing_pubkey = Some(cb_pub.to_str().unwrap().to_string());

    let (ticket_tx, ticket_rx) = tokio::sync::oneshot::channel::<String>();
    let ticket_tx_holder = Arc::new(parking_lot::Mutex::new(Some(ticket_tx)));

    let recv_path = tmp.path().join("recv.bin");
    let server_io: Arc<dyn IOProvider> = Arc::new(
        FileIOProvider::new_recv(recv_path)
            .await
            .expect("recv io"),
    );
    let server = make_processor(server_config, server_io).await;
    let server_task = {
        let ticket_tx_holder = ticket_tx_holder.clone();
        tokio::spawn(async move {
            let on_ticket = move |t: &Ticket| {
                if let Some(tx) = ticket_tx_holder.lock().take() {
                    let _ = tx.send(t.to_string());
                }
            };
            server.run_listen_once(on_ticket, || {}).await
        })
    };

    let ticket_str = tokio::time::timeout(E2E_TIMEOUT, ticket_rx)
        .await
        .expect("server did not produce ticket within timeout")
        .expect("ticket channel closed");

    // ---- Client: auth required, signs the transcript with attacker key A ----
    let mut client_config = CryptoConfig::default();
    client_config.transport = TransportKind::Iroh;
    client_config.no_relay = true;
    client_config.chat_mode = false;
    client_config.allow_unauth = false;
    client_config.signing_privkey = Some(ca_key.to_str().unwrap().to_string());
    client_config.signing_pubkey = Some(s_pub.to_str().unwrap().to_string());
    client_config.connect_addr = Some(ticket_str);

    let send_path = tmp.path().join("send.bin");
    fs::write(&send_path, b"adversarial-handshake-payload").expect("write send file");
    let client_io: Arc<dyn IOProvider> = Arc::new(
        FileIOProvider::new_send(send_path)
            .await
            .expect("send io"),
    );
    let client = make_processor(client_config, client_io).await;
    let client_task = tokio::spawn(async move {
        client
            .run_connect_with_handshake_callback_and_progress(|| {}, None)
            .await
    });

    let client_res = tokio::time::timeout(E2E_TIMEOUT, client_task)
        .await
        .expect("client connect timed out")
        .expect("client task panicked");

    let server_res = tokio::time::timeout(E2E_TIMEOUT, server_task)
        .await
        .expect("server did not finish the rejected handshake within timeout")
        .expect("server task panicked");

    // The client offered A's public key as #6 while the server pinned B, so the
    // responder rejects at the pinned-key comparison — before sig_I is even
    // read. Bind that specific rejection: the listener must have reached the
    // handshake and refused the identity, not refused the service.
    match server_res {
        Err(CryptoError::Parameter(ref msg))
            if msg.contains("Client public key mismatch with pinned key") => {}
        other => panic!(
            "responder must reject the untrusted client key at the pin, got {other:?}"
        ),
    }
    // ...and no session is established on the client side either.
    assert!(
        client_res.is_err(),
        "handshake with a signature from an untrusted key must be rejected, got Ok"
    );
}

/// Outcome of one hand-rolled initiator handshake against a single-shot listener.
struct HandshakeProbe {
    /// What the listener's `run_listen_once` returned.
    listener: Result<(), CryptoError>,
    /// Whether the responder answered with `#8` (its P-256 public key) — the
    /// first byte it writes, and only after sig_I has verified. `false` means
    /// the handshake was rejected before that point.
    responder_replied: bool,
}

/// Drive one initiator handshake by hand over the in-process mock transport,
/// against a listener that pins `#6` to `pinned_pub_pem`.
///
/// `presented_pub` is what the initiator claims as `#6`; `signing_priv_raw` is
/// what it signs the transcript with. Passing the pinned key for both is the
/// honest case; passing the pinned key with a *different* signing key is the
/// forgery — the only input that reaches the responder's `pqc_verify` of sig_I,
/// since the pinned-key comparison rejects everything else first.
async fn probe_initiator_signature(
    tmp: &std::path::Path,
    tag: &str,
    server_priv_pem: &std::path::Path,
    pinned_pub_pem: &std::path::Path,
    presented_pub: &[u8],
    signing_priv_raw: &[u8],
    client_peer_byte: u8,
) -> HandshakeProbe {
    let file_proto = P2pProtocol(ALPN_FILE);
    let net = MockNetwork::new();
    let server_id = PeerId::new([0xaa; 32]);
    // Distinct per probe: the responder throttles repeated auth failures per
    // transport NodeId, and that state is process-global.
    let client_id = PeerId::new([client_peer_byte; 32]);
    let server_ep = net.register(server_id, vec![file_proto]);
    let client_ep = net.register(client_id, vec![file_proto]);

    // Same posture as the iroh test above: auth required, exactly one pinned
    // client identity, file-receive service enabled.
    let mut server_config = CryptoConfig::default();
    server_config.no_relay = true;
    server_config.chat_mode = false;
    server_config.serve_chat = true;
    server_config.allow_unauth = false;
    server_config.signing_privkey = Some(server_priv_pem.to_str().unwrap().to_string());
    server_config.signing_pubkey = Some(pinned_pub_pem.to_str().unwrap().to_string());

    let recv_path = tmp.join(format!("recv-{tag}.bin"));
    let server_io: Arc<dyn IOProvider> = Arc::new(
        FileIOProvider::new_recv(recv_path)
            .await
            .expect("recv io"),
    );
    let server = NetworkProcessor::new(server_config, Arc::new(server_ep), server_io);
    let server_task = tokio::spawn(async move { server.run_listen_once(|_: &Ticket| {}, || {}).await });

    let mut stream = client_ep
        .connect(&PeerAddr::new(server_id), file_proto)
        .await
        .expect("mock connect");

    // Initiator fields #3..#6 + sig_I, in the responder's exact order, with the
    // transcript accumulated the same way it accumulates it.
    let (_ecc_priv, ecc_pub) = backend::generate_ecc_key_pair("prime256v1").expect("p256 keygen");
    let (_kem_priv, kem_pub, _) = backend::pqc_keygen_kem(KEM).expect("ml-kem keygen");

    let mut transcript = Vec::new();
    transcript.extend_from_slice(client_id.as_bytes()); // #1 initiator id
    transcript.extend_from_slice(server_id.as_bytes()); // #2 responder id

    WireCodec::write_vec(&mut stream, &ecc_pub).await.expect("write #3");
    WireCodec::update_transcript(&mut transcript, &ecc_pub); // #3
    WireCodec::write_vec(&mut stream, &kem_pub).await.expect("write #4");
    WireCodec::update_transcript(&mut transcript, &kem_pub); // #4

    // bit0 only: self-authenticating initiator that does not require responder
    // auth, so there is no #7 pre-commit between #6 and sig_I.
    let flags = [INITIATOR_SELF_AUTH];
    stream.write_all(&flags).await.expect("write #5");
    transcript.extend_from_slice(&flags); // #5

    WireCodec::write_vec(&mut stream, presented_pub).await.expect("write #6");
    WireCodec::update_transcript(&mut transcript, presented_pub); // #6

    let sig = backend::pqc_sign(DSA, signing_priv_raw, &transcript, HANDSHAKE_CTX_IROH)
        .expect("sign transcript");
    WireCodec::write_vec(&mut stream, &sig).await.expect("write sig_I");

    // The responder writes nothing until the whole initiator half has been
    // accepted, so receiving #8 is exactly "sig_I verified".
    let responder_replied = WireCodec::read_vec(&mut stream).await.is_ok();
    drop(stream);

    let listener = tokio::time::timeout(E2E_TIMEOUT, server_task)
        .await
        .expect("listener did not finish within timeout")
        .expect("listener task panicked");

    HandshakeProbe { listener, responder_replied }
}

/// The responder must verify sig_I against the key in `#6` and reject a
/// signature made by any other key. This is the regression guard for that
/// verification: deleting it from `handle_server_connection` makes the forged
/// probe below reach `#8`, which fails both assertions.
#[tokio::test]
async fn test_handshake_forged_transcript_signature() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let s_key = tmp.path().join("server.priv.pem");
    let cb_pub = tmp.path().join("client_trusted.pub.pem");

    let (s_priv_raw, _s_pub_raw, _) = backend::pqc_keygen_dsa(DSA).expect("server keygen");
    let (cb_priv_raw, cb_pub_raw, _) = backend::pqc_keygen_dsa(DSA).expect("trusted client keygen");
    let (ca_priv_raw, _ca_pub_raw, _) = backend::pqc_keygen_dsa(DSA).expect("attacker client keygen");

    write_priv(&s_key, &s_priv_raw);
    write_pub(&cb_pub, &cb_pub_raw); // server pins B's public key

    // Positive control: B's key in #6, signed by B. Proves the hand-rolled
    // frames and transcript are the ones the responder expects — without it a
    // malformed probe would be rejected for the wrong reason and the forgery
    // case below would pass vacuously.
    let control = probe_initiator_signature(
        tmp.path(),
        "control",
        &s_key,
        &cb_pub,
        &cb_pub_raw,
        &cb_priv_raw,
        0x01,
    )
    .await;
    assert!(
        control.responder_replied,
        "control: a correctly signed transcript from the pinned key must pass sig_I \
         verification and get the responder's #8; listener returned {:?}",
        control.listener
    );

    // Forgery: B's key in #6 (so the pinned-key comparison passes) with sig_I
    // made by attacker key A.
    let forged = probe_initiator_signature(
        tmp.path(),
        "forged",
        &s_key,
        &cb_pub,
        &cb_pub_raw,
        &ca_priv_raw,
        0x02,
    )
    .await;
    assert!(
        !forged.responder_replied,
        "responder answered a transcript signature made by a key other than #6"
    );
    match forged.listener {
        Err(CryptoError::SignatureVerification) => {}
        other => panic!(
            "forged sig_I must be rejected by the responder's signature verification, \
             got {other:?}"
        ),
    }
}
