/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

use std::process::Command;
use std::fs;
use std::path::Path;

fn get_bin() -> String {
    let bin = "./target/debug/nk-crypto-tool";
    if !Path::new(bin).exists() {
        // Try running cargo build if not exists
        Command::new("cargo").arg("build").status().unwrap();
    }
    bin.to_string()
}

#[test]
fn test_ecc_e2e_cycle() {
    let bin = get_bin();
    let key_dir = "tests/temp_ecc_keys";
    let _ = fs::remove_dir_all(key_dir);

    // 1. Key Generation
    let status = Command::new(&bin)
        .args(["--mode", "ecc", "--gen-enc-key", "--key-dir", key_dir])
        .status().expect("Failed to execute gen-enc-key");
    assert!(status.success());

    // 2. Encryption
    let input_file = "tests/input_ecc.txt";
    let encrypted_file = "tests/output_ecc.enc";
    let decrypted_file = "tests/output_ecc.dec";
    let content = "Secret message for ECC E2E test";
    fs::write(input_file, content).unwrap();

    let status = Command::new(&bin)
        .args([
            "--mode", "ecc", "--encrypt",
            "--recipient-pubkey", &format!("{}/public_enc_ecc.key", key_dir),
            "--output-file", encrypted_file,
            input_file
        ])
        .status().expect("Failed to execute encrypt");
    assert!(status.success());

    // 3. Decryption
    let status = Command::new(&bin)
        .args([
            "--mode", "ecc", "--decrypt",
            "--user-privkey", &format!("{}/private_enc_ecc.key", key_dir),
            "--output-file", decrypted_file,
            encrypted_file
        ])
        .status().expect("Failed to execute decrypt");
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
        .args(["--mode", "ecc", "--gen-sign-key", "--key-dir", key_dir])
        .status().expect("Failed to execute gen-sign-key");
    assert!(status.success());

    // 2. Signing
    let input_file = "tests/input_sig.txt";
    let sig_file = "tests/input_sig.sig";
    fs::write(input_file, "Message to sign").unwrap();

    let status = Command::new(&bin)
        .args([
            "--mode", "ecc", "--sign",
            "--signing-privkey", &format!("{}/private_sign_ecc.key", key_dir),
            "--signature", sig_file,
            input_file
        ])
        .status().expect("Failed to execute sign");
    assert!(status.success());

    // 3. Verification
    let status = Command::new(&bin)
        .args([
            "--mode", "ecc", "--verify",
            "--signing-pubkey", &format!("{}/public_sign_ecc.key", key_dir),
            "--signature", sig_file,
            input_file
        ])
        .status().expect("Failed to execute verify");
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
    let _ = fs::remove_dir_all(key_dir);

    // 1. Key Generation
    let status = Command::new(&bin)
        .args(["--mode", "pqc", "--gen-enc-key", "--key-dir", key_dir])
        .status().expect("Failed to execute gen-enc-key");
    assert!(status.success());

    // 2. Encryption
    let input_file = "tests/input_pqc.txt";
    let encrypted_file = "tests/output_pqc.enc";
    let decrypted_file = "tests/output_pqc.dec";
    let content = "Quantum resistant secret message";
    fs::write(input_file, content).unwrap();

    let status = Command::new(&bin)
        .args([
            "--mode", "pqc", "--encrypt",
            "--recipient-pubkey", &format!("{}/public_enc_pqc.key", key_dir),
            "--output-file", encrypted_file,
            input_file
        ])
        .status().expect("Failed to execute encrypt");
    assert!(status.success());

    // 3. Decryption
    let status = Command::new(&bin)
        .args([
            "--mode", "pqc", "--decrypt",
            "--user-privkey", &format!("{}/private_enc_pqc.key", key_dir),
            "--output-file", decrypted_file,
            encrypted_file
        ])
        .status().expect("Failed to execute decrypt");
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
    let _ = fs::remove_dir_all(key_dir);

    // 1. Key Generation
    let status = Command::new(&bin)
        .args(["--mode", "hybrid", "--gen-enc-key", "--key-dir", key_dir])
        .status().expect("Failed to execute gen-enc-key");
    assert!(status.success());

    // 2. Encryption
    let input_file = "tests/input_hybrid.txt";
    let encrypted_file = "tests/output_hybrid.enc";
    let decrypted_file = "tests/output_hybrid.dec";
    let content = "Hybrid encryption test message";
    fs::write(input_file, content).unwrap();

    let status = Command::new(&bin)
        .args([
            "--mode", "hybrid", "--encrypt",
            "--recipient-mlkem-pubkey", &format!("{}/public_enc_hybrid_mlkem.key", key_dir),
            "--recipient-ecdh-pubkey", &format!("{}/public_enc_hybrid_ecdh.key", key_dir),
            "--output-file", encrypted_file,
            input_file
        ])
        .status().expect("Failed to execute encrypt");
    assert!(status.success());

    // 3. Decryption
    let status = Command::new(&bin)
        .args([
            "--mode", "hybrid", "--decrypt",
            "--user-mlkem-privkey", &format!("{}/private_enc_hybrid_mlkem.key", key_dir),
            "--user-ecdh-privkey", &format!("{}/private_enc_hybrid_ecdh.key", key_dir),
            "--output-file", decrypted_file,
            encrypted_file
        ])
        .status().expect("Failed to execute decrypt");
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
