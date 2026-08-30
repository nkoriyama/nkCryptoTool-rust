/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * Integration tests for the v3 ChunkedAead format:
 *   - chunk boundary roundtrips (empty / 1B / chunk_size / non-multiple / multi)
 *   - truncation, reordering, mix-and-match attacks
 *   - chunk size tamper via SHA-256 File Session ID
 *   - ML-KEM-768 PQC and Hybrid roundtrip
 *
 * Tests use a small chunk size via the NKCT_V3_CHUNK_SIZE env var so the
 * boundary cases stay cheap. Env-var sensitive tests are serialized.
 */

use nkct::config::{CryptoConfig, CryptoMode, Operation};
use nkct::strategy::ecc::EccStrategy;
use nkct::strategy::hybrid::HybridStrategy;
use nkct::strategy::pqc::PqcStrategy;
use nkct::strategy::CryptoStrategy;
use nkct::CryptoProcessor;
use serial_test::serial;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;
use zeroize::Zeroizing;

const V3_CHUNK_SIZE: u32 = 64;
const V3_TAG_LEN: usize = 16;

struct EccKeys {
    pub_key: PathBuf,
    priv_key: PathBuf,
}

fn make_ecc_keys(dir: &TempDir) -> EccKeys {
    let key_dir = dir.path().join("keys");
    fs::create_dir_all(&key_dir).unwrap();
    let pub_key = key_dir.join("public_enc_ecc.key");
    let priv_key = key_dir.join("private_enc_ecc.key");
    let mut paths = HashMap::new();
    paths.insert(
        "public-key".to_string(),
        pub_key.to_str().unwrap().to_string(),
    );
    paths.insert(
        "private-key".to_string(),
        priv_key.to_str().unwrap().to_string(),
    );
    let strat = EccStrategy::new();
    strat
        .generate_encryption_key_pair(&paths, Some("test"), true)
        .expect("ecc keygen");
    EccKeys { pub_key, priv_key }
}

fn ecc_config(
    op: Operation,
    input: &std::path::Path,
    output: &std::path::Path,
    keys: &EccKeys,
) -> CryptoConfig {
    CryptoConfig {
        operation: op,
        input_files: vec![input.to_str().unwrap().to_string()],
        output_file: Some(output.to_str().unwrap().to_string()),
        recipient_pubkey: Some(keys.pub_key.to_str().unwrap().to_string()),
        user_privkey: Some(keys.priv_key.to_str().unwrap().to_string()),
        passphrase: Some(Zeroizing::new("test".to_string())),
        key_dir: keys
            .pub_key
            .parent()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string(),
        force: true,
        mode: CryptoMode::ECC,
        ..CryptoConfig::default()
    }
}

async fn ecc_encrypt(input: &std::path::Path, output: &std::path::Path, keys: &EccKeys) {
    let mut p = CryptoProcessor::new(CryptoMode::ECC);
    let cfg = ecc_config(Operation::Encrypt, input, output, keys);
    p.process(&cfg, None).await.expect("encrypt");
}

async fn ecc_decrypt(input: &std::path::Path, output: &std::path::Path, keys: &EccKeys) {
    let mut p = CryptoProcessor::new(CryptoMode::ECC);
    let cfg = ecc_config(Operation::Decrypt, input, output, keys);
    p.process(&cfg, None).await.expect("decrypt");
}

async fn ecc_decrypt_expect_err(
    input: &std::path::Path,
    output: &std::path::Path,
    keys: &EccKeys,
) -> nkct::CryptoError {
    let mut p = CryptoProcessor::new(CryptoMode::ECC);
    let cfg = ecc_config(Operation::Decrypt, input, output, keys);
    p.process(&cfg, None).await.expect_err("decrypt should fail")
}

fn read_header_size_v3(file: &std::path::Path) -> usize {
    // ECC v3 header layout, computed by replaying the deserializer.
    let mut s = EccStrategy::new();
    let buf = fs::read(file).expect("read enc");
    s.deserialize_header(&buf).expect("hdr ok")
}

fn parse_v3_chunks(file: &std::path::Path, chunk_size: u32) -> (Vec<u8>, Vec<Vec<u8>>) {
    let buf = fs::read(file).expect("read enc");
    let hdr_size = read_header_size_v3(file);
    let header = buf[..hdr_size].to_vec();
    let body = &buf[hdr_size..];
    let mut chunks = Vec::new();
    let mut off = 0usize;
    let max_chunk_wire = chunk_size as usize + V3_TAG_LEN;
    while off < body.len() {
        let remaining = body.len() - off;
        let take = std::cmp::min(remaining, max_chunk_wire);
        chunks.push(body[off..off + take].to_vec());
        off += take;
    }
    (header, chunks)
}

fn write_v3_file(path: &std::path::Path, header: &[u8], chunks: &[Vec<u8>]) {
    let mut buf = Vec::new();
    buf.extend_from_slice(header);
    for c in chunks {
        buf.extend_from_slice(c);
    }
    fs::write(path, &buf).expect("write tampered");
}

// ------------- Roundtrip: chunk boundaries ----------------------

#[tokio::test]
#[serial]
async fn v3_roundtrip_empty_file() {
    std::env::set_var("NKCT_V3_CHUNK_SIZE", V3_CHUNK_SIZE.to_string());
    let dir = TempDir::new().unwrap();
    let keys = make_ecc_keys(&dir);
    let pt_path = dir.path().join("in.bin");
    let ct_path = dir.path().join("out.enc");
    let dec_path = dir.path().join("out.dec");
    fs::write(&pt_path, b"").unwrap();

    ecc_encrypt(&pt_path, &ct_path, &keys).await;
    ecc_decrypt(&ct_path, &dec_path, &keys).await;
    assert_eq!(fs::read(&dec_path).unwrap(), b"");
}

#[tokio::test]
#[serial]
async fn v3_roundtrip_one_byte() {
    std::env::set_var("NKCT_V3_CHUNK_SIZE", V3_CHUNK_SIZE.to_string());
    let dir = TempDir::new().unwrap();
    let keys = make_ecc_keys(&dir);
    let pt_path = dir.path().join("in.bin");
    let ct_path = dir.path().join("out.enc");
    let dec_path = dir.path().join("out.dec");
    fs::write(&pt_path, b"X").unwrap();
    ecc_encrypt(&pt_path, &ct_path, &keys).await;
    ecc_decrypt(&ct_path, &dec_path, &keys).await;
    assert_eq!(fs::read(&dec_path).unwrap(), b"X");
}

#[tokio::test]
#[serial]
async fn v3_roundtrip_exact_chunk_size() {
    std::env::set_var("NKCT_V3_CHUNK_SIZE", V3_CHUNK_SIZE.to_string());
    let dir = TempDir::new().unwrap();
    let keys = make_ecc_keys(&dir);
    let pt_path = dir.path().join("in.bin");
    let ct_path = dir.path().join("out.enc");
    let dec_path = dir.path().join("out.dec");
    let content: Vec<u8> = (0..V3_CHUNK_SIZE as u8).collect();
    fs::write(&pt_path, &content).unwrap();
    ecc_encrypt(&pt_path, &ct_path, &keys).await;
    ecc_decrypt(&ct_path, &dec_path, &keys).await;
    assert_eq!(fs::read(&dec_path).unwrap(), content);
}

#[tokio::test]
#[serial]
async fn v3_roundtrip_multiple_chunks_aligned() {
    std::env::set_var("NKCT_V3_CHUNK_SIZE", V3_CHUNK_SIZE.to_string());
    let dir = TempDir::new().unwrap();
    let keys = make_ecc_keys(&dir);
    let pt_path = dir.path().join("in.bin");
    let ct_path = dir.path().join("out.enc");
    let dec_path = dir.path().join("out.dec");
    let content: Vec<u8> = (0..(V3_CHUNK_SIZE as usize * 3)).map(|i| i as u8).collect();
    fs::write(&pt_path, &content).unwrap();
    ecc_encrypt(&pt_path, &ct_path, &keys).await;
    ecc_decrypt(&ct_path, &dec_path, &keys).await;
    assert_eq!(fs::read(&dec_path).unwrap(), content);
}

#[tokio::test]
#[serial]
async fn v3_roundtrip_non_aligned_partial_final() {
    std::env::set_var("NKCT_V3_CHUNK_SIZE", V3_CHUNK_SIZE.to_string());
    let dir = TempDir::new().unwrap();
    let keys = make_ecc_keys(&dir);
    let pt_path = dir.path().join("in.bin");
    let ct_path = dir.path().join("out.enc");
    let dec_path = dir.path().join("out.dec");
    let content: Vec<u8> = (0..(V3_CHUNK_SIZE as usize * 2 + 13))
        .map(|i| (i ^ 0xA5) as u8)
        .collect();
    fs::write(&pt_path, &content).unwrap();
    ecc_encrypt(&pt_path, &ct_path, &keys).await;
    ecc_decrypt(&ct_path, &dec_path, &keys).await;
    assert_eq!(fs::read(&dec_path).unwrap(), content);
}

// ------------- Attack: truncation ------------------------------

#[tokio::test]
#[serial]
async fn v3_truncation_attack_detected() {
    std::env::set_var("NKCT_V3_CHUNK_SIZE", V3_CHUNK_SIZE.to_string());
    let dir = TempDir::new().unwrap();
    let keys = make_ecc_keys(&dir);
    let pt_path = dir.path().join("in.bin");
    let ct_path = dir.path().join("out.enc");
    let tamper_path = dir.path().join("tampered.enc");
    let dec_path = dir.path().join("out.dec");
    // 3 chunks total: two full + one final partial.
    let content: Vec<u8> = (0..(V3_CHUNK_SIZE as usize * 2 + 10)).map(|i| i as u8).collect();
    fs::write(&pt_path, &content).unwrap();
    ecc_encrypt(&pt_path, &ct_path, &keys).await;

    let (header, chunks) = parse_v3_chunks(&ct_path, V3_CHUNK_SIZE);
    assert!(chunks.len() >= 2, "need at least 2 chunks for truncation test");
    // Drop the last (final) chunk. The new last chunk is intermediate
    // (Flags=0x00), but decryption thinks it is final — AEAD verify fails
    // with mismatched AAD, surfacing as a generic auth failure. Even if
    // it didn't, the EOF would trigger TruncationDetected.
    let truncated = chunks[..chunks.len() - 1].to_vec();
    write_v3_file(&tamper_path, &header, &truncated);

    let err = ecc_decrypt_expect_err(&tamper_path, &dec_path, &keys).await;
    let msg = format!("{}", err);
    assert!(
        matches!(err, nkct::CryptoError::TruncationDetected)
            || matches!(err, nkct::CryptoError::SignatureVerification),
        "expected truncation or auth failure, got: {}",
        msg
    );
    assert!(
        !dec_path.exists(),
        "no plaintext file should be created on auth failure"
    );
}

// ------------- Attack: reordering ------------------------------

#[tokio::test]
#[serial]
async fn v3_reorder_attack_detected() {
    std::env::set_var("NKCT_V3_CHUNK_SIZE", V3_CHUNK_SIZE.to_string());
    let dir = TempDir::new().unwrap();
    let keys = make_ecc_keys(&dir);
    let pt_path = dir.path().join("in.bin");
    let ct_path = dir.path().join("out.enc");
    let tamper_path = dir.path().join("tampered.enc");
    let dec_path = dir.path().join("out.dec");
    let content: Vec<u8> = (0..(V3_CHUNK_SIZE as usize * 3)).map(|i| i as u8).collect();
    fs::write(&pt_path, &content).unwrap();
    ecc_encrypt(&pt_path, &ct_path, &keys).await;

    let (header, mut chunks) = parse_v3_chunks(&ct_path, V3_CHUNK_SIZE);
    assert!(chunks.len() >= 3);
    chunks.swap(0, 1);
    write_v3_file(&tamper_path, &header, &chunks);

    let err = ecc_decrypt_expect_err(&tamper_path, &dec_path, &keys).await;
    assert!(matches!(
        err,
        nkct::CryptoError::SignatureVerification
    ));
    assert!(!dec_path.exists());
}

// ------------- Attack: mix-and-match across files ---------------

#[tokio::test]
#[serial]
async fn v3_mix_and_match_attack_detected() {
    std::env::set_var("NKCT_V3_CHUNK_SIZE", V3_CHUNK_SIZE.to_string());
    let dir = TempDir::new().unwrap();
    let keys = make_ecc_keys(&dir);
    let pt_a = dir.path().join("a.bin");
    let pt_b = dir.path().join("b.bin");
    let ct_a = dir.path().join("a.enc");
    let ct_b = dir.path().join("b.enc");
    let tamper = dir.path().join("tampered.enc");
    let dec_path = dir.path().join("out.dec");

    let content_a: Vec<u8> = (0..(V3_CHUNK_SIZE as usize * 3)).map(|i| i as u8).collect();
    let content_b: Vec<u8> = (0..(V3_CHUNK_SIZE as usize * 3))
        .map(|i| (i ^ 0xFF) as u8)
        .collect();
    fs::write(&pt_a, &content_a).unwrap();
    fs::write(&pt_b, &content_b).unwrap();
    ecc_encrypt(&pt_a, &ct_a, &keys).await;
    ecc_encrypt(&pt_b, &ct_b, &keys).await;

    let (header_a, mut chunks_a) = parse_v3_chunks(&ct_a, V3_CHUNK_SIZE);
    let (_header_b, chunks_b) = parse_v3_chunks(&ct_b, V3_CHUNK_SIZE);
    // Splice file B's first chunk into file A at position 1.
    chunks_a[1] = chunks_b[1].clone();
    write_v3_file(&tamper, &header_a, &chunks_a);

    let err = ecc_decrypt_expect_err(&tamper, &dec_path, &keys).await;
    assert!(matches!(
        err,
        nkct::CryptoError::SignatureVerification
    ));
    assert!(!dec_path.exists());
}

// ------------- Attack: chunk_size tamper via session id ---------

#[tokio::test]
#[serial]
async fn v3_chunk_size_tamper_detected_via_session_id() {
    std::env::set_var("NKCT_V3_CHUNK_SIZE", V3_CHUNK_SIZE.to_string());
    let dir = TempDir::new().unwrap();
    let keys = make_ecc_keys(&dir);
    let pt_path = dir.path().join("in.bin");
    let ct_path = dir.path().join("out.enc");
    let tamper_path = dir.path().join("tampered.enc");
    let dec_path = dir.path().join("out.dec");
    let content: Vec<u8> = (0..(V3_CHUNK_SIZE as usize * 4)).map(|i| i as u8).collect();
    fs::write(&pt_path, &content).unwrap();
    ecc_encrypt(&pt_path, &ct_path, &keys).await;

    // The chunk_size lives in the last 4 bytes of the v3 ECC header. Flip
    // one bit there and rewrite. The header SHA-256 (= File Session ID)
    // will differ from what the encryptor used, so every chunk's AAD
    // mismatches and the very first decrypt_chunk_v3 must fail.
    let buf = fs::read(&ct_path).unwrap();
    let hdr_size = read_header_size_v3(&ct_path);
    let mut tampered = buf.clone();
    tampered[hdr_size - 4] ^= 0x01;
    fs::write(&tamper_path, &tampered).unwrap();

    let err = ecc_decrypt_expect_err(&tamper_path, &dec_path, &keys).await;
    assert!(matches!(
        err,
        nkct::CryptoError::SignatureVerification
    ));
    assert!(!dec_path.exists());
}

// ------------- PQC roundtrip ----------------------------------

fn make_pqc_keys(dir: &TempDir) -> (PathBuf, PathBuf) {
    let key_dir = dir.path().join("keys");
    fs::create_dir_all(&key_dir).unwrap();
    let pub_key = key_dir.join("public_enc_pqc.key");
    let priv_key = key_dir.join("private_enc_pqc.key");
    let mut paths = HashMap::new();
    paths.insert(
        "public-key".to_string(),
        pub_key.to_str().unwrap().to_string(),
    );
    paths.insert(
        "private-key".to_string(),
        priv_key.to_str().unwrap().to_string(),
    );
    paths.insert("kem-algo".to_string(), "ML-KEM-768".to_string());
    let strat = PqcStrategy::new();
    strat
        .generate_encryption_key_pair(&paths, None, true)
        .expect("pqc keygen");
    (pub_key, priv_key)
}

#[tokio::test]
#[serial]
async fn v3_roundtrip_pqc_mlkem768() {
    std::env::set_var("NKCT_V3_CHUNK_SIZE", V3_CHUNK_SIZE.to_string());
    let dir = TempDir::new().unwrap();
    let (pub_key, priv_key) = make_pqc_keys(&dir);
    let pt_path = dir.path().join("in.bin");
    let ct_path = dir.path().join("out.enc");
    let dec_path = dir.path().join("out.dec");
    let content: Vec<u8> = (0..(V3_CHUNK_SIZE as usize * 2 + 7))
        .map(|i| (i ^ 0x33) as u8)
        .collect();
    fs::write(&pt_path, &content).unwrap();

    let mut p = CryptoProcessor::new(CryptoMode::PQC);
    let cfg = CryptoConfig {
        operation: Operation::Encrypt,
        input_files: vec![pt_path.to_str().unwrap().to_string()],
        output_file: Some(ct_path.to_str().unwrap().to_string()),
        recipient_pubkey: Some(pub_key.to_str().unwrap().to_string()),
        force: true,
        mode: CryptoMode::PQC,
        pqc_kem_algo: "ML-KEM-768".to_string(),
        ..CryptoConfig::default()
    };
    p.process(&cfg, None).await.expect("encrypt pqc");

    let mut p2 = CryptoProcessor::new(CryptoMode::PQC);
    let cfg = CryptoConfig {
        operation: Operation::Decrypt,
        input_files: vec![ct_path.to_str().unwrap().to_string()],
        output_file: Some(dec_path.to_str().unwrap().to_string()),
        user_privkey: Some(priv_key.to_str().unwrap().to_string()),
        force: true,
        mode: CryptoMode::PQC,
        pqc_kem_algo: "ML-KEM-768".to_string(),
        ..CryptoConfig::default()
    };
    p2.process(&cfg, None).await.expect("decrypt pqc");
    assert_eq!(fs::read(&dec_path).unwrap(), content);
}

// ------------- Hybrid roundtrip ------------------------------

#[tokio::test]
#[serial]
async fn v3_roundtrip_hybrid_ecdh_mlkem() {
    std::env::set_var("NKCT_V3_CHUNK_SIZE", V3_CHUNK_SIZE.to_string());
    let dir = TempDir::new().unwrap();
    let key_dir = dir.path().join("keys");
    fs::create_dir_all(&key_dir).unwrap();

    let mut paths = HashMap::new();
    paths.insert(
        "public-ecdh-key".to_string(),
        key_dir.join("pub_ecdh.key").to_str().unwrap().to_string(),
    );
    paths.insert(
        "private-ecdh-key".to_string(),
        key_dir.join("priv_ecdh.key").to_str().unwrap().to_string(),
    );
    paths.insert(
        "public-mlkem-key".to_string(),
        key_dir.join("pub_mlkem.key").to_str().unwrap().to_string(),
    );
    paths.insert(
        "private-mlkem-key".to_string(),
        key_dir
            .join("priv_mlkem.key")
            .to_str()
            .unwrap()
            .to_string(),
    );
    paths.insert("kem-algo".to_string(), "ML-KEM-768".to_string());
    let strat = HybridStrategy::new();
    strat
        .generate_encryption_key_pair(&paths, None, true)
        .expect("hybrid keygen");

    let pt_path = dir.path().join("in.bin");
    let ct_path = dir.path().join("out.enc");
    let dec_path = dir.path().join("out.dec");
    let content: Vec<u8> = (0..(V3_CHUNK_SIZE as usize * 3 + 5))
        .map(|i| (i ^ 0x77) as u8)
        .collect();
    fs::write(&pt_path, &content).unwrap();

    let mut p = CryptoProcessor::new(CryptoMode::Hybrid);
    let cfg = CryptoConfig {
        operation: Operation::Encrypt,
        input_files: vec![pt_path.to_str().unwrap().to_string()],
        output_file: Some(ct_path.to_str().unwrap().to_string()),
        recipient_ecdh_pubkey: Some(key_dir.join("pub_ecdh.key").to_str().unwrap().to_string()),
        recipient_mlkem_pubkey: Some(
            key_dir.join("pub_mlkem.key").to_str().unwrap().to_string(),
        ),
        force: true,
        mode: CryptoMode::Hybrid,
        pqc_kem_algo: "ML-KEM-768".to_string(),
        ..CryptoConfig::default()
    };
    p.process(&cfg, None).await.expect("encrypt hybrid");

    let mut p2 = CryptoProcessor::new(CryptoMode::Hybrid);
    let cfg = CryptoConfig {
        operation: Operation::Decrypt,
        input_files: vec![ct_path.to_str().unwrap().to_string()],
        output_file: Some(dec_path.to_str().unwrap().to_string()),
        user_ecdh_privkey: Some(key_dir.join("priv_ecdh.key").to_str().unwrap().to_string()),
        user_mlkem_privkey: Some(
            key_dir.join("priv_mlkem.key").to_str().unwrap().to_string(),
        ),
        force: true,
        mode: CryptoMode::Hybrid,
        pqc_kem_algo: "ML-KEM-768".to_string(),
        ..CryptoConfig::default()
    };
    p2.process(&cfg, None).await.expect("decrypt hybrid");
    assert_eq!(fs::read(&dec_path).unwrap(), content);
}
