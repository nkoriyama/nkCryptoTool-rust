/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

//! CLI increment: `--recipient-keybundle` wiring, raw-pubkey abolition, and
//! expiry entry-point enforcement. The happy round-trip (encrypt-via-bundle →
//! decrypt) for pqc/ecc/hybrid lives in `e2e.rs`; this file covers the negative
//! and edge paths.

use std::fs;
use std::path::Path;
use std::process::Command;

fn bin() -> String {
    let b = "./target/debug/nk-crypto-tool";
    if !Path::new(b).exists() {
        Command::new("cargo").arg("build").status().unwrap();
    }
    b.to_string()
}

const PASS: &str = "kb-cli-test-pass";

/// Gen an ML-DSA-65 identity + pqc enc keys under `dir`, then a signed bundle.
/// Returns (bundle_path, owner_fingerprint). `expiry_secs` is optional.
fn setup(dir: &str, expiry_secs: Option<u64>) -> (String, String) {
    let b = bin();
    let _ = fs::remove_dir_all(dir);
    for kind in ["--gen-sign-key", "--gen-enc-key"] {
        assert!(Command::new(&b)
            .env("NK_PASSPHRASE", PASS)
            .args(["--mode", "pqc", kind, "--key-dir", dir])
            .status()
            .unwrap()
            .success());
    }
    let bundle = format!("{dir}/r.nkkb");
    let mut args = vec![
        "--mode".into(), "pqc".into(), "--gen-keybundle".into(),
        "--key-dir".into(), dir.into(),
        "--signing-privkey".into(), format!("{dir}/private_sign_pqc.key"),
        "--keybundle-handle".into(), "h".into(),
        "--keybundle-output".into(), bundle.clone(),
    ];
    if let Some(s) = expiry_secs {
        args.push("--keybundle-expiry-secs".into());
        args.push(s.to_string());
    }
    let out = Command::new(&b)
        .env("NK_PASSPHRASE", PASS)
        .args(&args)
        .output()
        .unwrap();
    assert!(out.status.success(), "gen-keybundle: {}", String::from_utf8_lossy(&out.stderr));
    let fp = String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .find(|w| w.len() == 64 && w.chars().all(|c| c.is_ascii_hexdigit()))
        .expect("fingerprint")
        .to_string();
    (bundle, fp)
}

fn encrypt(dir: &str, bundle: &str, fp: &str, input: &str, output: &str) -> std::process::Output {
    Command::new(bin())
        .args([
            "--mode", "pqc", "--encrypt",
            "--recipient-keybundle", bundle,
            "--recipient-fingerprint", fp,
            "--key-dir", dir,
            "--output-file", output,
            input,
        ])
        .output()
        .unwrap()
}

#[test]
fn expired_keybundle_rejected() {
    let dir = "tests/tmp_kb_expired";
    let (bundle, fp) = setup(dir, Some(0)); // expires_at == created_at → already expired
    let input = format!("{dir}/in.txt");
    fs::write(&input, "x").unwrap();
    let out = encrypt(dir, &bundle, &fp, &input, &format!("{dir}/out.enc"));
    assert!(!out.status.success(), "expired bundle must be rejected");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("expired"), "expected expiry message, got: {err}");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn wrong_pin_rejected() {
    let dir = "tests/tmp_kb_wrongpin";
    let (bundle, _fp) = setup(dir, None);
    let input = format!("{dir}/in.txt");
    fs::write(&input, "x").unwrap();
    let wrong = "0".repeat(64);
    let out = encrypt(dir, &bundle, &wrong, &input, &format!("{dir}/out.enc"));
    assert!(!out.status.success(), "pin mismatch must be rejected");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("rejected") || err.contains("pinned"), "got: {err}");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn raw_flag_rejected_for_encrypt_but_fingerprint_still_works() {
    let dir = "tests/tmp_kb_rawgate";
    let (_bundle, _fp) = setup(dir, None);
    let input = format!("{dir}/in.txt");
    fs::write(&input, "x").unwrap();

    // Encrypt with a raw recipient pubkey is abolished (guidance error).
    let out = Command::new(bin())
        .args([
            "--mode", "pqc", "--encrypt",
            "--recipient-pubkey", &format!("{dir}/public_enc_pqc.key"),
            "--key-dir", dir,
            "--output-file", &format!("{dir}/out.enc"),
            &input,
        ])
        .output()
        .unwrap();
    assert!(!out.status.success(), "raw --recipient-pubkey must be rejected for --encrypt");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("no longer accepted") && err.contains("--recipient-keybundle"),
        "expected guidance, got: {err}");

    // The gate is Encrypt-scoped: --fingerprint still reads --recipient-pubkey.
    let out = Command::new(bin())
        .args([
            "--mode", "pqc", "--fingerprint",
            "--recipient-pubkey", &format!("{dir}/public_sign_pqc.key"),
            "--key-dir", dir,
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "fingerprint must still accept --recipient-pubkey");
    assert!(String::from_utf8_lossy(&out.stdout).contains("Fingerprint:"));
    let _ = fs::remove_dir_all(dir);
}
