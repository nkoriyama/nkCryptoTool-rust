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

/// Keyring direct-read: `--gen-keybundle` with NO `--signing-privkey` resolves
/// the ML-DSA identity and the enc key from the my-identities table, and the
/// resulting bundle round-trips (encrypt to it → keyring auto-match decrypt).
/// After import, no explicit key path appears anywhere in the circle.
#[test]
fn keyring_gen_keybundle_full_circle() {
    let dir = "tests/tmp_kb_keyring";
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

    // Empty keyring: the keyring path must fail with the import hint, not
    // silently fall back to key files.
    let out = Command::new(&b)
        .env("NK_PASSPHRASE", PASS)
        .args([
            "--mode", "pqc", "--gen-keybundle",
            "--key-dir", dir,
            "--keybundle-handle", "me",
            "--keybundle-output", &format!("{dir}/r.nkkb"),
        ])
        .output()
        .unwrap();
    assert!(!out.status.success(), "empty keyring must not produce a bundle");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("import-my-key"), "expected import hint, got: {err}");

    // Import both halves of the identity into the keyring.
    for key in ["private_sign_pqc.key", "private_enc_pqc.key"] {
        let out = Command::new(&b)
            .env("NK_PASSPHRASE", PASS)
            .args([
                "--keyring-cmd", "import-my-key",
                "--user-privkey", &format!("{dir}/{key}"),
                "--key-dir", dir,
            ])
            .output()
            .unwrap();
        assert!(out.status.success(), "import {key}: {}", String::from_utf8_lossy(&out.stderr));
    }

    // Bundle from the keyring alone (no --signing-privkey).
    let bundle = format!("{dir}/r.nkkb");
    let out = Command::new(&b)
        .env("NK_PASSPHRASE", PASS)
        .args([
            "--mode", "pqc", "--gen-keybundle",
            "--key-dir", dir,
            "--keybundle-handle", "me",
            "--keybundle-output", &bundle,
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "gen-keybundle: {}", String::from_utf8_lossy(&out.stderr));
    let fp = String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .find(|w| w.len() == 64 && w.chars().all(|c| c.is_ascii_hexdigit()))
        .expect("fingerprint")
        .to_string();

    // Encrypt to the keyring-built bundle, then decrypt with keyring
    // auto-match — no private-key path on either side.
    let input = format!("{dir}/in.txt");
    fs::write(&input, "keyfile-less full circle").unwrap();
    let enc = format!("{dir}/out.enc");
    let out = encrypt(dir, &bundle, &fp, &input, &enc);
    assert!(out.status.success(), "encrypt: {}", String::from_utf8_lossy(&out.stderr));

    let plain = format!("{dir}/out.txt");
    let out = Command::new(&b)
        .env("NK_PASSPHRASE", PASS)
        .args([
            "--mode", "pqc", "--decrypt",
            "--key-dir", dir,
            "--output-file", &plain,
            &enc,
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "decrypt: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(fs::read(&plain).unwrap(), b"keyfile-less full circle");
    let _ = fs::remove_dir_all(dir);
}

/// `gen-my-key`: keys are born inside the keyring — no key file ever exists.
/// Generate the identity + enc key directly into keyring.db, bundle, encrypt
/// to it, auto-match decrypt. Also: P-256 must be told its role, and a held
/// slot refuses silent regeneration (clobber guard).
#[test]
fn keyring_gen_my_key_never_touches_disk() {
    let dir = "tests/tmp_kb_genmykey";
    let b = bin();
    let _ = fs::remove_dir_all(dir);

    for algo in ["ML-DSA-65", "ML-KEM-768"] {
        let out = Command::new(&b)
            .env("NK_PASSPHRASE", PASS)
            .args(["--keyring-cmd", "gen-my-key", "--key-algo", algo, "--key-dir", dir])
            .output()
            .unwrap();
        assert!(out.status.success(), "gen-my-key {algo}: {}", String::from_utf8_lossy(&out.stderr));
        assert!(String::from_utf8_lossy(&out.stdout).contains("no key file written"));
    }
    // The key dir holds ONLY the keyring — no private/public key files.
    let names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, vec!["keyring.db"], "unexpected files: {names:?}");

    // P-256 serves both roles: without --key-role it must refuse.
    let out = Command::new(&b)
        .env("NK_PASSPHRASE", PASS)
        .args(["--keyring-cmd", "gen-my-key", "--key-algo", "P-256", "--key-dir", dir])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--key-role"));

    // A held slot refuses silent regeneration.
    let out = Command::new(&b)
        .env("NK_PASSPHRASE", PASS)
        .args(["--keyring-cmd", "gen-my-key", "--key-algo", "ML-DSA-65", "--key-dir", dir])
        .output()
        .unwrap();
    assert!(!out.status.success(), "regeneration into a held slot must be refused");
    assert!(String::from_utf8_lossy(&out.stderr).contains("remove-my-key"));

    // The generated-in-DB keys drive the whole circle: bundle → encrypt → decrypt.
    let bundle = format!("{dir}/r.nkkb");
    let out = Command::new(&b)
        .env("NK_PASSPHRASE", PASS)
        .args([
            "--mode", "pqc", "--gen-keybundle",
            "--key-dir", dir,
            "--keybundle-handle", "me",
            "--keybundle-output", &bundle,
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "gen-keybundle: {}", String::from_utf8_lossy(&out.stderr));
    let fp = String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .find(|w| w.len() == 64 && w.chars().all(|c| c.is_ascii_hexdigit()))
        .expect("fingerprint")
        .to_string();

    let input = format!("{dir}/in.txt");
    fs::write(&input, "born in the keyring").unwrap();
    let enc = format!("{dir}/out.enc");
    let out = encrypt(dir, &bundle, &fp, &input, &enc);
    assert!(out.status.success(), "encrypt: {}", String::from_utf8_lossy(&out.stderr));

    let plain = format!("{dir}/out.txt");
    let out = Command::new(&b)
        .env("NK_PASSPHRASE", PASS)
        .args(["--mode", "pqc", "--decrypt", "--key-dir", dir, "--output-file", &plain, &enc])
        .output()
        .unwrap();
    assert!(out.status.success(), "decrypt: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(fs::read(&plain).unwrap(), b"born in the keyring");
    let _ = fs::remove_dir_all(dir);
}
