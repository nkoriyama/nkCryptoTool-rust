/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

//! The pairing OTP must never be accepted on the command line.
//!
//! On Linux argv is world-readable via `/proc/<pid>/cmdline` for the whole
//! process lifetime, and the OTP is the sole authorization secret for
//! `--copy-bundle`: a local user who reads it can enrol their own identity into
//! the server's keyring with the operator's configured grants. A warning was
//! not enough — the documented workflow still put it on the command line — so
//! the literal form is rejected outright and only `--token -` remains.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

fn bin() -> String {
    let b = "./target/debug/nkct";
    if !Path::new(b).exists() {
        Command::new("cargo").arg("build").status().unwrap();
    }
    b.to_string()
}

#[test]
fn token_on_the_command_line_is_rejected() {
    let out = Command::new(bin())
        .args([
            "--copy-bundle",
            "--mode",
            "pqc",
            "--connect",
            "nkct1example",
            "--token",
            "ABCD2345",
        ])
        .output()
        .unwrap();

    assert!(
        !out.status.success(),
        "a literal --token was accepted; the OTP would be readable from /proc"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--token no longer accepts the OTP on the command line"),
        "expected the argv rejection, got: {stderr}"
    );
}

/// The gate is specific to the literal form: `--token -` still gets past the
/// token stage. (It fails later, on the unreachable ticket — what matters here
/// is that it is not the argv rejection.)
#[test]
fn token_dash_is_still_accepted() {
    let mut child = Command::new(bin())
        .args([
            "--copy-bundle",
            "--mode",
            "pqc",
            "--connect",
            "nkct1example",
            "--token",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"ABCD2345\n")
        .unwrap();
    let out = child.wait_with_output().unwrap();

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("--token no longer accepts the OTP on the command line"),
        "`--token -` was caught by the argv gate: {stderr}"
    );
}
