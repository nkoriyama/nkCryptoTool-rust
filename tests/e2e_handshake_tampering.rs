/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 *
 * Adversarial handshake test (P1-R3, Gemini §3.2#4): handshake signature
 * tampering is a distinct threat model from in-flight file-transfer
 * corruption, so it lives in its own file.
 *
 * Scenario: the server requires authentication and trusts exactly one client
 * identity (key B). A connecting client signs the handshake transcript with a
 * *different* key (attacker key A). The server's signature verification over
 * the transcript must reject the mismatched signature and abort the handshake,
 * so the client's connect returns an error instead of establishing a session.
 */

use std::fs;
use std::sync::Arc;
use std::time::Duration;

use nk_crypto_tool::backend;
use nk_crypto_tool::config::{CryptoConfig, TransportKind};
use nk_crypto_tool::network::{FileIOProvider, IOProvider};
use nk_crypto_tool::p2p::NetworkProcessor;
use nk_crypto_tool::ticket::Ticket;
use nk_crypto_tool::utils;

const E2E_TIMEOUT: Duration = Duration::from_secs(60);
const DSA: &str = "ML-DSA-65";

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

    server_task.abort();

    // The server verifies the client's transcript signature against B's public
    // key; the client signed with A, so verification fails and the handshake
    // must be rejected (no session established).
    assert!(
        client_res.is_err(),
        "handshake with a signature from an untrusted key must be rejected, got Ok"
    );
}
