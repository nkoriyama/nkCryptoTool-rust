/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

use std::fs;
use std::path::Path;
use std::process::Command;

fn get_bin() -> String {
    let bin = "./target/debug/nk-crypto-tool";
    if !Path::new(bin).exists() {
        Command::new("cargo").arg("build").status().unwrap();
    }
    bin.to_string()
}

const TEST_PASSPHRASE: &str = "test-passphrase-123";

#[test]
fn test_threat_37_1_tampered_ciphertext_leaves_no_temp_file() {
    let bin = get_bin();
    let key_dir = "tests/temp_37_1_keys";
    let input_file = "tests/input_37_1.txt";
    let encrypted_file = "tests/output_37_1.enc";
    let decrypted_file = "tests/output_37_1.dec";

    let _ = fs::remove_dir_all(key_dir);
    let _ = fs::remove_file(input_file);
    let _ = fs::remove_file(encrypted_file);
    let _ = fs::remove_file(decrypted_file);
    
    // 1. Setup
    fs::create_dir_all(key_dir).unwrap();
    Command::new(&bin)
        .env("NK_PASSPHRASE", TEST_PASSPHRASE)
        .args(["--mode", "ecc", "--gen-enc-key", "--key-dir", key_dir, "--force"])
        .status().unwrap();

    let content = "Sensitive data that should not leak to disk before verification";
    fs::write(input_file, content).unwrap();

    Command::new(&bin)
        .args([
            "--mode", "ecc", "--encrypt",
            "--recipient-pubkey", &format!("{}/public_enc_ecc.key", key_dir),
            "--output-file", encrypted_file,
            input_file,
        ])
        .status().unwrap();

    // 2. Tamper the ciphertext
    let mut enc_data = fs::read(encrypted_file).unwrap();
    // Flip a bit in the ciphertext area (header is usually small, so end of file is safe)
    let len = enc_data.len();
    if len > 32 {
        enc_data[len - 20] ^= 0xFF; 
    }
    fs::write(encrypted_file, &enc_data).unwrap();

    // 3. Attempt Decryption (Expected to fail)
    let output = Command::new(&bin)
        .env("NK_PASSPHRASE", TEST_PASSPHRASE)
        .args([
            "--mode", "ecc", "--decrypt",
            "--user-privkey", &format!("{}/private_enc_ecc.key", key_dir),
            "--output-file", decrypted_file,
            encrypted_file,
        ])
        .output()
        .expect("Failed to execute decrypt");
    
    assert!(!output.status.success(), "Decryption should fail for tampered ciphertext");

    // 4. CHECK FOR TEMP FILES
    let parent_dir = Path::new(decrypted_file).parent().unwrap();
    let mut temp_files = Vec::new();
    for entry in fs::read_dir(parent_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        let name = path.file_name().unwrap().to_string_lossy();
        if name.starts_with("output_37_1.dec.tmp.") {
            temp_files.push(path);
        }
    }

    assert!(temp_files.is_empty(), "Temporary files found after failed decryption: {:?}", temp_files);
    assert!(!Path::new(decrypted_file).exists(), "Decrypted file exists despite failure");

    // Cleanup
    let _ = fs::remove_dir_all(key_dir);
    let _ = fs::remove_file(input_file);
    let _ = fs::remove_file(encrypted_file);
}

#[test]
fn test_threat_37_1_normal_decryption_regression() {
    let bin = get_bin();
    let key_dir = "tests/temp_37_1_reg_keys";
    let input_file = "tests/input_37_1_reg.txt";
    let encrypted_file = "tests/output_37_1_reg.enc";
    let decrypted_file = "tests/output_37_1_reg.dec";

    let _ = fs::remove_dir_all(key_dir);
    let _ = fs::remove_file(input_file);
    let _ = fs::remove_file(encrypted_file);
    let _ = fs::remove_file(decrypted_file);
    
    // Setup
    fs::create_dir_all(key_dir).unwrap();
    Command::new(&bin)
        .env("NK_PASSPHRASE", TEST_PASSPHRASE)
        .args(["--mode", "ecc", "--gen-enc-key", "--key-dir", key_dir, "--force"])
        .status().unwrap();

    let content = "Regression test for two-pass decryption";
    fs::write(input_file, content).unwrap();

    Command::new(&bin)
        .args([
            "--mode", "ecc", "--encrypt",
            "--recipient-pubkey", &format!("{}/public_enc_ecc.key", key_dir),
            "--output-file", encrypted_file,
            input_file,
        ])
        .status().unwrap();

    // Decrypt
    let status = Command::new(&bin)
        .env("NK_PASSPHRASE", TEST_PASSPHRASE)
        .args([
            "--mode", "ecc", "--decrypt",
            "--user-privkey", &format!("{}/private_enc_ecc.key", key_dir),
            "--output-file", decrypted_file,
            encrypted_file,
        ])
        .status().unwrap();
    
    assert!(status.success());
    assert_eq!(fs::read_to_string(decrypted_file).unwrap(), content);

    // Cleanup
    let _ = fs::remove_dir_all(key_dir);
    let _ = fs::remove_file(input_file);
    let _ = fs::remove_file(encrypted_file);
    let _ = fs::remove_file(decrypted_file);
}
