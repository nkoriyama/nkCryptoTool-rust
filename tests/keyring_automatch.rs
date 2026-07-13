/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

//! End-to-end coverage of the keyring my-identities auto-match plumbing:
//! encrypt to an in-memory recipient key, then decrypt with the private key
//! injected as its keyring form (passphrase-encrypted PKCS#8 PEM) — the exact
//! path `--decrypt` takes when the key comes out of `keyring.db` instead of a
//! file. No private-key file exists at any point.

use nk_crypto_tool::config::{CryptoConfig, CryptoMode, Operation};
use nk_crypto_tool::keyring;
use nk_crypto_tool::processor::CryptoProcessor;
use zeroize::Zeroizing;

fn tmp_dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("nkct-automatch-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[tokio::test]
async fn pqc_decrypt_via_keyring_injected_pem() {
    const PASS: &str = "keyring-test-pass";
    let dir = tmp_dir("pqc");
    let plain_path = dir.join("plain.txt");
    let ct_path = dir.join("ct.bin");
    let out_path = dir.join("out.txt");
    std::fs::write(&plain_path, b"keyring auto-match round-trip").unwrap();

    // A key pair whose private half exists ONLY in keyring form.
    let (raw_priv, raw_pub, _) = nk_crypto_tool::backend::pqc_keygen_kem("ML-KEM-768").unwrap();
    let enc_der =
        nk_crypto_tool::utils::wrap_pqc_priv_to_pkcs8_encrypted(&raw_priv, "ML-KEM-768", PASS)
            .unwrap();
    let pem = nk_crypto_tool::utils::wrap_to_pem(&enc_der, "ENCRYPTED PRIVATE KEY");

    // Import validation builds the record (binding check + KEM self-test)...
    let (algo, role, rec) =
        keyring::build_my_identity_record(pem.as_bytes(), PASS, None, 1).unwrap();
    assert_eq!((algo.as_str(), role), ("ML-KEM-768", Some("enc")));
    // ...and store/fetch round-trips through an actual keyring.db.
    let store = keyring::KeyringStore::open(&dir.join("keyring.db")).unwrap();
    store.put_my_identity("me", "enc", &algo, &rec).unwrap();
    let rec = store.get_my_identity("me", "enc", &algo).unwrap().unwrap();

    // Encrypt (recipient key injected in memory, as a KeyBundle would).
    let mut enc_cfg = CryptoConfig::default();
    enc_cfg.mode = CryptoMode::PQC;
    enc_cfg.operation = Operation::Encrypt;
    enc_cfg.input_files = vec![plain_path.to_string_lossy().into_owned()];
    enc_cfg.output_file = Some(ct_path.to_string_lossy().into_owned());
    enc_cfg.recipient_enc_key_bytes = Some(raw_pub.clone());
    CryptoProcessor::new(CryptoMode::PQC)
        .process(&enc_cfg, None)
        .await
        .unwrap();

    // The header peek that drives auto-match resolves the right slot.
    let head = std::fs::read(&ct_path).unwrap();
    let peek = keyring::peek_v3_header(&head).unwrap();
    assert_eq!(peek.strategy, 2);
    assert_eq!(peek.kem_algo.as_deref(), Some("ML-KEM-768"));

    // Unlock enforces the pub↔priv binding, then the strategy decrypts from
    // the injected PEM — no key file anywhere.
    let unlocked = keyring::unlock_and_verify_identity(&rec, &algo, PASS).unwrap();
    let mut dec_cfg = CryptoConfig::default();
    dec_cfg.mode = CryptoMode::PQC;
    dec_cfg.operation = Operation::Decrypt;
    dec_cfg.input_files = vec![ct_path.to_string_lossy().into_owned()];
    dec_cfg.output_file = Some(out_path.to_string_lossy().into_owned());
    dec_cfg.user_enc_privkey_pem = Some(unlocked);
    dec_cfg.passphrase = Some(Zeroizing::new(PASS.to_string()));
    CryptoProcessor::new(CryptoMode::PQC)
        .process(&dec_cfg, None)
        .await
        .unwrap();

    assert_eq!(
        std::fs::read(&out_path).unwrap(),
        b"keyring auto-match round-trip"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn hybrid_decrypt_via_keyring_injected_pems() {
    const PASS: &str = "keyring-hybrid-pass";
    let dir = tmp_dir("hybrid");
    let plain_path = dir.join("plain.txt");
    let ct_path = dir.join("ct.bin");
    let out_path = dir.join("out.txt");
    std::fs::write(&plain_path, b"hybrid needs both halves").unwrap();

    // ML-KEM half.
    let (kem_priv, kem_pub, _) = nk_crypto_tool::backend::pqc_keygen_kem("ML-KEM-768").unwrap();
    let kem_pem = nk_crypto_tool::utils::wrap_to_pem(
        &nk_crypto_tool::utils::wrap_pqc_priv_to_pkcs8_encrypted(&kem_priv, "ML-KEM-768", PASS)
            .unwrap(),
        "ENCRYPTED PRIVATE KEY",
    );
    // P-256 half (plain PKCS#8 DER from keygen → encrypted PKCS#8 PEM).
    let (ecc_priv_der, ecc_pub_spki) =
        nk_crypto_tool::backend::generate_ecc_key_pair("prime256v1").unwrap();
    let ecc_pem = nk_crypto_tool::utils::wrap_to_pem(
        &nk_crypto_tool::utils::encrypt_pkcs8_der(&ecc_priv_der, PASS).unwrap(),
        "ENCRYPTED PRIVATE KEY",
    );

    // Both halves import as expected (P-256 needs the role told).
    let (kalgo, krole, krec) =
        keyring::build_my_identity_record(kem_pem.as_bytes(), PASS, None, 1).unwrap();
    assert_eq!((kalgo.as_str(), krole), ("ML-KEM-768", Some("enc")));
    let (ealgo, erole, erec) =
        keyring::build_my_identity_record(ecc_pem.as_bytes(), PASS, None, 1).unwrap();
    assert_eq!((ealgo.as_str(), erole), ("P-256", None));

    // Encrypt with both recipient halves injected.
    let mut enc_cfg = CryptoConfig::default();
    enc_cfg.mode = CryptoMode::Hybrid;
    enc_cfg.operation = Operation::Encrypt;
    enc_cfg.input_files = vec![plain_path.to_string_lossy().into_owned()];
    enc_cfg.output_file = Some(ct_path.to_string_lossy().into_owned());
    enc_cfg.recipient_enc_key_bytes = Some(kem_pub.clone());
    enc_cfg.recipient_hybrid_key_bytes = Some(ecc_pub_spki.clone());
    CryptoProcessor::new(CryptoMode::Hybrid)
        .process(&enc_cfg, None)
        .await
        .unwrap();

    // The peek names BOTH slots hybrid needs.
    let head = std::fs::read(&ct_path).unwrap();
    let peek = keyring::peek_v3_header(&head).unwrap();
    assert_eq!(peek.strategy, 3);
    assert_eq!(peek.kem_algo.as_deref(), Some("ML-KEM-768"));
    assert_eq!(peek.ecc_algo.as_deref(), Some("P-256"));

    // Decrypt with both keyring PEMs injected.
    let mut dec_cfg = CryptoConfig::default();
    dec_cfg.mode = CryptoMode::Hybrid;
    dec_cfg.operation = Operation::Decrypt;
    dec_cfg.input_files = vec![ct_path.to_string_lossy().into_owned()];
    dec_cfg.output_file = Some(out_path.to_string_lossy().into_owned());
    dec_cfg.user_enc_privkey_pem =
        Some(keyring::unlock_and_verify_identity(&krec, &kalgo, PASS).unwrap());
    dec_cfg.user_hybrid_privkey_pem =
        Some(keyring::unlock_and_verify_identity(&erec, &ealgo, PASS).unwrap());
    dec_cfg.passphrase = Some(Zeroizing::new(PASS.to_string()));
    CryptoProcessor::new(CryptoMode::Hybrid)
        .process(&dec_cfg, None)
        .await
        .unwrap();

    assert_eq!(std::fs::read(&out_path).unwrap(), b"hybrid needs both halves");
    let _ = std::fs::remove_dir_all(&dir);
}
