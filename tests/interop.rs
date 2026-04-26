/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

use std::process::Command;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Once;

static INIT: Once = Once::new();

/// Builds the binary with specific features and returns the path.
/// We use a separate target directory to avoid locks during 'cargo test'.
fn get_bin(backend: &str) -> PathBuf {
    let target_dir = format!("target/interop-{}", backend);
    let bin_name = if cfg!(windows) { "nk-crypto-tool.exe" } else { "nk-crypto-tool" };
    let bin_path = PathBuf::from(&target_dir).join("release").join(bin_name);

    INIT.call_once(|| {
        let _ = fs::create_dir_all("tests/interop_data");
    });

    // Build if not exists or always for fresh test? 
    // For performance in tests, we check if it exists.
    if !bin_path.exists() {
        println!("Building backend: {}...", backend);
        let mut cmd = Command::new("cargo");
        cmd.arg("build").arg("--release").arg("--bin").arg("nk-crypto-tool");
        cmd.env("CARGO_TARGET_DIR", &target_dir);

        if backend == "rustcrypto" {
            cmd.arg("--no-default-features").arg("--features").arg("backend-rustcrypto");
        } else {
            cmd.arg("--features").arg("backend-openssl");
        }

        let status = cmd.status().expect("Failed to run cargo build");
        assert!(status.success(), "Failed to build {} backend", backend);
    }

    bin_path
}

fn cleanup(path: &str) {
    let _ = fs::remove_dir_all(path);
}

#[test]
fn test_ecc_interop_encryption_bidirectional() {
    let openssl_bin = get_bin("openssl");
    let rustcrypto_bin = get_bin("rustcrypto");
    let data_dir = "tests/interop_data/ecc_enc";
    let _ = fs::remove_dir_all(data_dir);
    fs::create_dir_all(data_dir).unwrap();

    let input_file = Path::new(data_dir).join("input.txt");
    let content = "Interoperability test for ECC encryption";
    fs::write(&input_file, content).unwrap();

    // Case 1: OpenSSL Encrypt -> RustCrypto Decrypt
    let key_dir_1 = Path::new(data_dir).join("keys_1");
    let enc_file_1 = Path::new(data_dir).join("output_1.enc");
    let dec_file_1 = Path::new(data_dir).join("output_1.dec");

    // Gen key with OpenSSL
    assert!(Command::new(&openssl_bin).args(["--mode", "ecc", "--gen-enc-key", "--key-dir", key_dir_1.to_str().unwrap()]).status().unwrap().success());
    // Encrypt with OpenSSL
    assert!(Command::new(&openssl_bin).args([
        "--mode", "ecc", "--encrypt", 
        "--recipient-pubkey", key_dir_1.join("public_enc_ecc.key").to_str().unwrap(),
        "--output-file", enc_file_1.to_str().unwrap(),
        input_file.to_str().unwrap()
    ]).status().unwrap().success());
    // Decrypt with RustCrypto
    assert!(Command::new(&rustcrypto_bin).args([
        "--mode", "ecc", "--decrypt", 
        "--user-privkey", key_dir_1.join("private_enc_ecc.key").to_str().unwrap(),
        "--output-file", dec_file_1.to_str().unwrap(),
        enc_file_1.to_str().unwrap()
    ]).status().unwrap().success());
    assert_eq!(fs::read_to_string(dec_file_1).unwrap(), content);

    // Case 2: RustCrypto Encrypt -> OpenSSL Decrypt
    let key_dir_2 = Path::new(data_dir).join("keys_2");
    let enc_file_2 = Path::new(data_dir).join("output_2.enc");
    let dec_file_2 = Path::new(data_dir).join("output_2.dec");

    // Gen key with RustCrypto
    assert!(Command::new(&rustcrypto_bin).args(["--mode", "ecc", "--gen-enc-key", "--key-dir", key_dir_2.to_str().unwrap()]).status().unwrap().success());
    // Encrypt with RustCrypto
    assert!(Command::new(&rustcrypto_bin).args([
        "--mode", "ecc", "--encrypt", 
        "--recipient-pubkey", key_dir_2.join("public_enc_ecc.key").to_str().unwrap(),
        "--output-file", enc_file_2.to_str().unwrap(),
        input_file.to_str().unwrap()
    ]).status().unwrap().success());
    // Decrypt with OpenSSL
    assert!(Command::new(&openssl_bin).args([
        "--mode", "ecc", "--decrypt", 
        "--user-privkey", key_dir_2.join("private_enc_ecc.key").to_str().unwrap(),
        "--output-file", dec_file_2.to_str().unwrap(),
        enc_file_2.to_str().unwrap()
    ]).status().unwrap().success());
    assert_eq!(fs::read_to_string(dec_file_2).unwrap(), content);

    cleanup(data_dir);
}

#[test]
fn test_ecc_interop_signature_bidirectional() {
    let openssl_bin = get_bin("openssl");
    let rustcrypto_bin = get_bin("rustcrypto");
    let data_dir = "tests/interop_data/ecc_sig";
    let _ = fs::remove_dir_all(data_dir);
    fs::create_dir_all(data_dir).unwrap();

    let input_file = Path::new(data_dir).join("input.txt");
    let content = "Interoperability test for ECC signature";
    fs::write(&input_file, content).unwrap();

    // Case 1: OpenSSL Sign -> RustCrypto Verify
    let key_dir_1 = Path::new(data_dir).join("keys_1");
    let sig_file_1 = Path::new(data_dir).join("output_1.sig");

    assert!(Command::new(&openssl_bin).args(["--mode", "ecc", "--gen-sign-key", "--key-dir", key_dir_1.to_str().unwrap()]).status().unwrap().success());
    assert!(Command::new(&openssl_bin).args([
        "--mode", "ecc", "--sign", 
        "--signing-privkey", key_dir_1.join("private_sign_ecc.key").to_str().unwrap(),
        "--signature", sig_file_1.to_str().unwrap(),
        input_file.to_str().unwrap()
    ]).status().unwrap().success());
    assert!(Command::new(&rustcrypto_bin).args([
        "--mode", "ecc", "--verify", 
        "--signing-pubkey", key_dir_1.join("public_sign_ecc.key").to_str().unwrap(),
        "--signature", sig_file_1.to_str().unwrap(),
        input_file.to_str().unwrap()
    ]).status().unwrap().success());

    // Case 2: RustCrypto Sign -> OpenSSL Verify
    let key_dir_2 = Path::new(data_dir).join("keys_2");
    let sig_file_2 = Path::new(data_dir).join("output_2.sig");

    assert!(Command::new(&rustcrypto_bin).args(["--mode", "ecc", "--gen-sign-key", "--key-dir", key_dir_2.to_str().unwrap()]).status().unwrap().success());
    assert!(Command::new(&rustcrypto_bin).args([
        "--mode", "ecc", "--sign", 
        "--signing-privkey", key_dir_2.join("private_sign_ecc.key").to_str().unwrap(),
        "--signature", sig_file_2.to_str().unwrap(),
        input_file.to_str().unwrap()
    ]).status().unwrap().success());
    assert!(Command::new(&openssl_bin).args([
        "--mode", "ecc", "--verify", 
        "--signing-pubkey", key_dir_2.join("public_sign_ecc.key").to_str().unwrap(),
        "--signature", sig_file_2.to_str().unwrap(),
        input_file.to_str().unwrap()
    ]).status().unwrap().success());

    cleanup(data_dir);
}

#[test]
fn test_pqc_interop_encryption_bidirectional() {
    let openssl_bin = get_bin("openssl");
    let rustcrypto_bin = get_bin("rustcrypto");
    let data_dir = "tests/interop_data/pqc_enc";
    let _ = fs::remove_dir_all(data_dir);
    fs::create_dir_all(data_dir).unwrap();

    let input_file = Path::new(data_dir).join("input.txt");
    let content = "Interoperability test for PQC encryption";
    fs::write(&input_file, content).unwrap();

    // Gen key with RustCrypto (guaranteed to work)
    let key_dir = Path::new(data_dir).join("keys");
    assert!(Command::new(&rustcrypto_bin).args(["--mode", "pqc", "--gen-enc-key", "--key-dir", key_dir.to_str().unwrap()]).status().unwrap().success());

    // RustCrypto Encrypt -> OpenSSL Decrypt
    let enc_file = Path::new(data_dir).join("output.enc");
    let dec_file = Path::new(data_dir).join("output.dec");

    assert!(Command::new(&rustcrypto_bin).args([
        "--mode", "pqc", "--encrypt", 
        "--recipient-pubkey", key_dir.join("public_enc_pqc.key").to_str().unwrap(),
        "--output-file", enc_file.to_str().unwrap(),
        input_file.to_str().unwrap()
    ]).status().unwrap().success());

    assert!(Command::new(&openssl_bin).args([
        "--mode", "pqc", "--decrypt", 
        "--user-privkey", key_dir.join("private_enc_pqc.key").to_str().unwrap(),
        "--output-file", dec_file.to_str().unwrap(),
        enc_file.to_str().unwrap()
    ]).status().unwrap().success());

    assert_eq!(fs::read_to_string(dec_file).unwrap(), content);

    cleanup(data_dir);
}
