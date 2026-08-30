/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Once;

static INIT: Once = Once::new();

/// Builds the binary with specific features and returns the path.
/// We use a separate target directory to avoid locks during 'cargo test'.
fn get_bin(backend: &str) -> PathBuf {
    let target_dir = format!("target/interop-{}", backend);
    let bin_name = if cfg!(windows) {
        "nkct.exe"
    } else {
        "nkct"
    };
    let bin_path = PathBuf::from(&target_dir).join("release").join(bin_name);

    INIT.call_once(|| {
        let _ = fs::create_dir_all("tests/interop_data");
    });

    // Build if not exists or always for fresh test?
    // For performance in tests, we check if it exists.
    if !bin_path.exists() {
        println!("Building backend: {}...", backend);
        let mut cmd = Command::new("cargo");
        cmd.arg("build")
            .arg("--release")
            .arg("--bin")
            .arg("nkct");
        cmd.env("CARGO_TARGET_DIR", &target_dir);

        if backend == "rustcrypto" {
            cmd.arg("--no-default-features")
                .arg("--features")
                .arg("backend-rustcrypto");
        } else {
            // Force an OpenSSL-only build. The default feature is
            // backend-rustcrypto, which otherwise wins the `crypto_impl` alias
            // (see backend/mod.rs) and would make this "openssl" bin actually
            // run rustcrypto — defeating the interop test. Use the *vendored*
            // OpenSSL 3.6.x so ML-KEM is available regardless of the host/CI
            // system libssl version (ubuntu runners pin a pre-3.5 libssl
            // without ML-KEM), keeping this test host-independent.
            cmd.arg("--no-default-features")
                .arg("--features")
                .arg("backend-openssl-vendored");
        }

        let status = cmd.status().expect("Failed to run cargo build");
        assert!(status.success(), "Failed to build {} backend", backend);
    }

    bin_path
}

fn cleanup(path: &str) {
    let _ = fs::remove_dir_all(path);
}

const TEST_PASSPHRASE: &str = "interop-test-pass";

/// Generate an ML-DSA-65 identity (`sign_mode` = pqc) and a signed NKKB
/// KeyBundle binding the `enc_mode` encryption public key(s) already in
/// `key_dir`, using `bin`. Returns the owner fingerprint the sender pins.
/// Encryption is bundle-only now (raw recipient-pubkey flags are abolished);
/// keeping bundle-gen and encrypt on the same backend keeps this test about
/// file-format interop, not KeyBundle cross-verification.
fn gen_bundle(bin: &Path, key_dir: &str, enc_mode: &str, sign_mode: &str, bundle_path: &str) -> String {
    assert!(Command::new(bin)
        .env("NK_PASSPHRASE", TEST_PASSPHRASE)
        .args(["--mode", sign_mode, "--gen-sign-key", "--key-dir", key_dir])
        .status()
        .unwrap()
        .success());
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
            "interop",
            "--keybundle-output",
            bundle_path,
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "gen-keybundle failed: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .find(|w| w.len() == 64 && w.chars().all(|c| c.is_ascii_hexdigit()))
        .expect("fingerprint in gen-keybundle output")
        .to_string()
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
    assert!(Command::new(&openssl_bin)
        .env("NK_PASSPHRASE", TEST_PASSPHRASE)
        .args([
            "--mode",
            "ecc",
            "--gen-enc-key",
            "--key-dir",
            key_dir_1.to_str().unwrap()
        ])
        .status()
        .unwrap()
        .success());
    // Encrypt with OpenSSL (to the recipient's signed KeyBundle)
    let bundle_1 = key_dir_1.join("recipient.nkkb");
    let fp_1 = gen_bundle(&openssl_bin, key_dir_1.to_str().unwrap(), "ecc", "pqc", bundle_1.to_str().unwrap());
    assert!(Command::new(&openssl_bin)
        .args([
            "--mode",
            "ecc",
            "--encrypt",
            "--recipient-keybundle",
            bundle_1.to_str().unwrap(),
            "--recipient-fingerprint",
            &fp_1,
            "--output-file",
            enc_file_1.to_str().unwrap(),
            input_file.to_str().unwrap()
        ])
        .status()
        .unwrap()
        .success());
    // Decrypt with RustCrypto
    assert!(Command::new(&rustcrypto_bin)
        .env("NK_PASSPHRASE", TEST_PASSPHRASE)
        .args([
            "--mode",
            "ecc",
            "--decrypt",
            "--user-privkey",
            key_dir_1.join("private_enc_ecc.key").to_str().unwrap(),
            "--output-file",
            dec_file_1.to_str().unwrap(),
            enc_file_1.to_str().unwrap()
        ])
        .status()
        .unwrap()
        .success());
    assert_eq!(fs::read_to_string(dec_file_1).unwrap(), content);

    // Case 2: RustCrypto Encrypt -> OpenSSL Decrypt
    let key_dir_2 = Path::new(data_dir).join("keys_2");
    let enc_file_2 = Path::new(data_dir).join("output_2.enc");
    let dec_file_2 = Path::new(data_dir).join("output_2.dec");

    // Gen key with RustCrypto
    assert!(Command::new(&rustcrypto_bin)
        .env("NK_PASSPHRASE", TEST_PASSPHRASE)
        .args([
            "--mode",
            "ecc",
            "--gen-enc-key",
            "--key-dir",
            key_dir_2.to_str().unwrap()
        ])
        .status()
        .unwrap()
        .success());
    // Encrypt with RustCrypto (to the recipient's signed KeyBundle)
    let bundle_2 = key_dir_2.join("recipient.nkkb");
    let fp_2 = gen_bundle(&rustcrypto_bin, key_dir_2.to_str().unwrap(), "ecc", "pqc", bundle_2.to_str().unwrap());
    assert!(Command::new(&rustcrypto_bin)
        .args([
            "--mode",
            "ecc",
            "--encrypt",
            "--recipient-keybundle",
            bundle_2.to_str().unwrap(),
            "--recipient-fingerprint",
            &fp_2,
            "--output-file",
            enc_file_2.to_str().unwrap(),
            input_file.to_str().unwrap()
        ])
        .status()
        .unwrap()
        .success());
    // Decrypt with OpenSSL
    assert!(Command::new(&openssl_bin)
        .env("NK_PASSPHRASE", TEST_PASSPHRASE)
        .args([
            "--mode",
            "ecc",
            "--decrypt",
            "--user-privkey",
            key_dir_2.join("private_enc_ecc.key").to_str().unwrap(),
            "--output-file",
            dec_file_2.to_str().unwrap(),
            enc_file_2.to_str().unwrap()
        ])
        .status()
        .unwrap()
        .success());
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

    assert!(Command::new(&openssl_bin)
        .env("NK_PASSPHRASE", TEST_PASSPHRASE)
        .args([
            "--mode",
            "ecc",
            "--gen-sign-key",
            "--key-dir",
            key_dir_1.to_str().unwrap()
        ])
        .status()
        .unwrap()
        .success());
    assert!(Command::new(&openssl_bin)
        .env("NK_PASSPHRASE", TEST_PASSPHRASE)
        .args([
            "--mode",
            "ecc",
            "--sign",
            "--signing-privkey",
            key_dir_1.join("private_sign_ecc.key").to_str().unwrap(),
            "--signature",
            sig_file_1.to_str().unwrap(),
            input_file.to_str().unwrap()
        ])
        .status()
        .unwrap()
        .success());
    assert!(Command::new(&rustcrypto_bin)
        .args([
            "--mode",
            "ecc",
            "--verify",
            "--signing-pubkey",
            key_dir_1.join("public_sign_ecc.key").to_str().unwrap(),
            "--signature",
            sig_file_1.to_str().unwrap(),
            input_file.to_str().unwrap()
        ])
        .status()
        .unwrap()
        .success());

    // Case 2: RustCrypto Sign -> OpenSSL Verify
    let key_dir_2 = Path::new(data_dir).join("keys_2");
    let sig_file_2 = Path::new(data_dir).join("output_2.sig");

    assert!(Command::new(&rustcrypto_bin)
        .env("NK_PASSPHRASE", TEST_PASSPHRASE)
        .args([
            "--mode",
            "ecc",
            "--gen-sign-key",
            "--key-dir",
            key_dir_2.to_str().unwrap()
        ])
        .status()
        .unwrap()
        .success());
    assert!(Command::new(&rustcrypto_bin)
        .env("NK_PASSPHRASE", TEST_PASSPHRASE)
        .args([
            "--mode",
            "ecc",
            "--sign",
            "--signing-privkey",
            key_dir_2.join("private_sign_ecc.key").to_str().unwrap(),
            "--signature",
            sig_file_2.to_str().unwrap(),
            input_file.to_str().unwrap()
        ])
        .status()
        .unwrap()
        .success());
    assert!(Command::new(&openssl_bin)
        .args([
            "--mode",
            "ecc",
            "--verify",
            "--signing-pubkey",
            key_dir_2.join("public_sign_ecc.key").to_str().unwrap(),
            "--signature",
            sig_file_2.to_str().unwrap(),
            input_file.to_str().unwrap()
        ])
        .status()
        .unwrap()
        .success());

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
    assert!(Command::new(&rustcrypto_bin)
        .env("NK_PASSPHRASE", TEST_PASSPHRASE)
        .args([
            "--mode",
            "pqc",
            "--gen-enc-key",
            "--key-dir",
            key_dir.to_str().unwrap()
        ])
        .status()
        .unwrap()
        .success());

    // RustCrypto Encrypt -> OpenSSL Decrypt
    let enc_file = Path::new(data_dir).join("output.enc");
    let dec_file = Path::new(data_dir).join("output.dec");

    let bundle = key_dir.join("recipient.nkkb");
    let fp = gen_bundle(&rustcrypto_bin, key_dir.to_str().unwrap(), "pqc", "pqc", bundle.to_str().unwrap());
    assert!(Command::new(&rustcrypto_bin)
        .args([
            "--mode",
            "pqc",
            "--encrypt",
            "--recipient-keybundle",
            bundle.to_str().unwrap(),
            "--recipient-fingerprint",
            &fp,
            "--output-file",
            enc_file.to_str().unwrap(),
            input_file.to_str().unwrap()
        ])
        .status()
        .unwrap()
        .success());

    assert!(Command::new(&openssl_bin)
        .env("NK_PASSPHRASE", TEST_PASSPHRASE)
        .args([
            "--mode",
            "pqc",
            "--decrypt",
            "--user-privkey",
            key_dir.join("private_enc_pqc.key").to_str().unwrap(),
            "--output-file",
            dec_file.to_str().unwrap(),
            enc_file.to_str().unwrap()
        ])
        .status()
        .unwrap()
        .success());

    assert_eq!(fs::read_to_string(dec_file).unwrap(), content);

    cleanup(data_dir);
}
