/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

use std::fs;
use std::path::Path;
use std::process::Command;

fn get_bin() -> String {
    let bin = "./target/debug/nkct";
    if !Path::new(bin).exists() {
        // Try running cargo build if not exists
        Command::new("cargo").arg("build").status().unwrap();
    }
    bin.to_string()
}

const TEST_PASSPHRASE: &str = "test-passphrase-123";

/// Generate an ML-DSA-65 identity (`sign_mode` = pqc or hybrid) and a signed
/// NKKB KeyBundle binding the `enc_mode` encryption public key(s) under it.
/// Returns the owner fingerprint a sender pins with `--recipient-fingerprint`.
/// Encryption is now bundle-only (raw recipient-pubkey flags are abolished).
fn make_recipient_keybundle(
    bin: &str,
    key_dir: &str,
    enc_mode: &str,
    sign_mode: &str,
    bundle_path: &str,
) -> String {
    // The KeyBundle identity is the ML-DSA-65 single anchor, independent of the
    // encryption mode; ecc encryption therefore anchors on a pqc-mode identity.
    let status = Command::new(bin)
        .env("NK_PASSPHRASE", TEST_PASSPHRASE)
        .args(["--mode", sign_mode, "--gen-sign-key", "--key-dir", key_dir])
        .status()
        .expect("Failed to execute gen-sign-key");
    assert!(status.success());
    let out = Command::new(bin)
        .env("NK_PASSPHRASE", TEST_PASSPHRASE)
        .args([
            "--mode",
            enc_mode,
            "--gen-keybundle",
            "--key-dir",
            key_dir,
            "--signing-privkey",
            &format!("{key_dir}/private_sign_{sign_mode}.key"),
            "--keybundle-handle",
            "e2e",
            "--keybundle-output",
            bundle_path,
        ])
        .output()
        .expect("Failed to execute gen-keybundle");
    assert!(
        out.status.success(),
        "gen-keybundle failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout
        .split_whitespace()
        .find(|w| w.len() == 64 && w.chars().all(|c| c.is_ascii_hexdigit()))
        .expect("fingerprint in gen-keybundle output")
        .to_string()
}

#[test]
fn test_ecc_e2e_cycle() {
    let bin = get_bin();
    let key_dir = "tests/temp_ecc_keys";
    let input_file = "tests/input_ecc.txt";
    let encrypted_file = "tests/output_ecc.enc";
    let decrypted_file = "tests/output_ecc.dec";

    let _ = fs::remove_dir_all(key_dir);
    let _ = fs::remove_file(input_file);
    let _ = fs::remove_file(encrypted_file);
    let _ = fs::remove_file(decrypted_file);

    // 1. Key Generation
    let status = Command::new(&bin)
        .env("NK_PASSPHRASE", TEST_PASSPHRASE)
        .args(["--mode", "ecc", "--gen-enc-key", "--key-dir", key_dir])
        .status()
        .expect("Failed to execute gen-enc-key");
    assert!(status.success());

    // 2. Encryption
    let input_file = "tests/input_ecc.txt";
    let encrypted_file = "tests/output_ecc.enc";
    let decrypted_file = "tests/output_ecc.dec";
    let content = "Secret message for ECC E2E test";
    fs::write(input_file, content).unwrap();

    let bundle = format!("{}/recipient.nkkb", key_dir);
    let fp = make_recipient_keybundle(&bin, key_dir, "ecc", "pqc", &bundle);
    let status = Command::new(&bin)
        .args([
            "--mode",
            "ecc",
            "--encrypt",
            "--recipient-keybundle",
            &bundle,
            "--recipient-fingerprint",
            &fp,
            "--key-dir",
            key_dir,
            "--output-file",
            encrypted_file,
            input_file,
        ])
        .status()
        .expect("Failed to execute encrypt");
    assert!(status.success());

    // 3. Decryption
    let status = Command::new(&bin)
        .env("NK_PASSPHRASE", TEST_PASSPHRASE)
        .args([
            "--mode",
            "ecc",
            "--decrypt",
            "--user-privkey",
            &format!("{}/private_enc_ecc.key", key_dir),
            "--output-file",
            decrypted_file,
            encrypted_file,
        ])
        .status()
        .expect("Failed to execute decrypt");
    assert!(status.success());

    // 4. Verification
    let result = fs::read_to_string(decrypted_file).unwrap();
    assert_eq!(result, content);

    // Cleanup
    let _ = fs::remove_dir_all(key_dir);
    let _ = fs::remove_file(input_file);
    let _ = fs::remove_file(encrypted_file);
    let _ = fs::remove_file(decrypted_file);
}

#[test]
fn test_ecc_signing_e2e() {
    let bin = get_bin();
    let key_dir = "tests/temp_ecc_sig_keys";
    let _ = fs::remove_dir_all(key_dir);

    // 1. Key Generation
    let status = Command::new(&bin)
        .env("NK_PASSPHRASE", TEST_PASSPHRASE)
        .args(["--mode", "ecc", "--gen-sign-key", "--key-dir", key_dir])
        .status()
        .expect("Failed to execute gen-sign-key");
    assert!(status.success());

    // 2. Signing
    let input_file = "tests/input_sig.txt";
    let sig_file = "tests/input_sig.sig";
    fs::write(input_file, "Message to sign").unwrap();

    let status = Command::new(&bin)
        .env("NK_PASSPHRASE", TEST_PASSPHRASE)
        .args([
            "--mode",
            "ecc",
            "--sign",
            "--signing-privkey",
            &format!("{}/private_sign_ecc.key", key_dir),
            "--signature",
            sig_file,
            input_file,
        ])
        .status()
        .expect("Failed to execute sign");
    assert!(status.success());

    // 3. Verification
    let status = Command::new(&bin)
        .args([
            "--mode",
            "ecc",
            "--verify",
            "--signing-pubkey",
            &format!("{}/public_sign_ecc.key", key_dir),
            "--signature",
            sig_file,
            input_file,
        ])
        .status()
        .expect("Failed to execute verify");
    assert!(status.success());

    // Cleanup
    let _ = fs::remove_dir_all(key_dir);
    let _ = fs::remove_file(input_file);
    let _ = fs::remove_file(sig_file);
}

#[test]
fn test_pqc_e2e_cycle() {
    let bin = get_bin();
    let key_dir = "tests/temp_pqc_keys";
    let input_file = "tests/input_pqc.txt";
    let encrypted_file = "tests/output_pqc.enc";
    let decrypted_file = "tests/output_pqc.dec";

    let _ = fs::remove_dir_all(key_dir);
    let _ = fs::remove_file(input_file);
    let _ = fs::remove_file(encrypted_file);
    let _ = fs::remove_file(decrypted_file);

    // 1. Key Generation
    let status = Command::new(&bin)
        .env("NK_PASSPHRASE", TEST_PASSPHRASE)
        .args(["--mode", "pqc", "--gen-enc-key", "--key-dir", key_dir])
        .status()
        .expect("Failed to execute gen-enc-key");
    assert!(status.success());

    // 2. Encryption
    let content = "Quantum resistant secret message";
    fs::write(input_file, content).unwrap();

    let bundle = format!("{}/recipient.nkkb", key_dir);
    let fp = make_recipient_keybundle(&bin, key_dir, "pqc", "pqc", &bundle);
    let status = Command::new(&bin)
        .args([
            "--mode",
            "pqc",
            "--encrypt",
            "--recipient-keybundle",
            &bundle,
            "--recipient-fingerprint",
            &fp,
            "--key-dir",
            key_dir,
            "--output-file",
            encrypted_file,
            input_file,
        ])
        .status()
        .expect("Failed to execute encrypt");
    assert!(status.success());

    // 3. Decryption
    let status = Command::new(&bin)
        .env("NK_PASSPHRASE", TEST_PASSPHRASE)
        .args([
            "--mode",
            "pqc",
            "--decrypt",
            "--user-privkey",
            &format!("{}/private_enc_pqc.key", key_dir),
            "--output-file",
            decrypted_file,
            encrypted_file,
        ])
        .status()
        .expect("Failed to execute decrypt");
    assert!(status.success());

    // 4. Verification
    let result = fs::read_to_string(decrypted_file).unwrap();
    assert_eq!(result, content);

    // Cleanup
    let _ = fs::remove_dir_all(key_dir);
    let _ = fs::remove_file(input_file);
    let _ = fs::remove_file(encrypted_file);
    let _ = fs::remove_file(decrypted_file);
}

#[test]
fn test_hybrid_e2e_cycle() {
    let bin = get_bin();
    let key_dir = "tests/temp_hybrid_keys";
    let input_file = "tests/input_hybrid.txt";
    let encrypted_file = "tests/output_hybrid.enc";
    let decrypted_file = "tests/output_hybrid.dec";

    let _ = fs::remove_dir_all(key_dir);
    let _ = fs::remove_file(input_file);
    let _ = fs::remove_file(encrypted_file);
    let _ = fs::remove_file(decrypted_file);

    // 1. Key Generation
    let status = Command::new(&bin)
        .env("NK_PASSPHRASE", TEST_PASSPHRASE)
        .args(["--mode", "hybrid", "--gen-enc-key", "--key-dir", key_dir])
        .status()
        .expect("Failed to execute gen-enc-key");
    assert!(status.success());

    // 2. Encryption
    let input_file = "tests/input_hybrid.txt";
    let encrypted_file = "tests/output_hybrid.enc";
    let decrypted_file = "tests/output_hybrid.dec";
    let content = "Hybrid encryption test message";
    fs::write(input_file, content).unwrap();

    let bundle = format!("{}/recipient.nkkb", key_dir);
    let fp = make_recipient_keybundle(&bin, key_dir, "hybrid", "hybrid", &bundle);
    let status = Command::new(&bin)
        .args([
            "--mode",
            "hybrid",
            "--encrypt",
            "--recipient-keybundle",
            &bundle,
            "--recipient-fingerprint",
            &fp,
            "--key-dir",
            key_dir,
            "--output-file",
            encrypted_file,
            input_file,
        ])
        .status()
        .expect("Failed to execute encrypt");
    assert!(status.success());

    // 3. Decryption
    let status = Command::new(&bin)
        .env("NK_PASSPHRASE", TEST_PASSPHRASE)
        .args([
            "--mode",
            "hybrid",
            "--decrypt",
            "--user-mlkem-privkey",
            &format!("{}/private_enc_hybrid_mlkem.key", key_dir),
            "--user-ecdh-privkey",
            &format!("{}/private_enc_hybrid_ecdh.key", key_dir),
            "--output-file",
            decrypted_file,
            encrypted_file,
        ])
        .status()
        .expect("Failed to execute decrypt");
    assert!(status.success());

    // 4. Verification
    let result = fs::read_to_string(decrypted_file).unwrap();
    assert_eq!(result, content);

    // Cleanup
    let _ = fs::remove_dir_all(key_dir);
    let _ = fs::remove_file(input_file);
    let _ = fs::remove_file(encrypted_file);
    let _ = fs::remove_file(decrypted_file);
}
