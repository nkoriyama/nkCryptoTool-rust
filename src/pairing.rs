/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

//! P2P KeyBundle auto-registration (pairing, ALPN `nkct/pairing/1`) — the
//! `ssh-copy-id` equivalent. A not-yet-registered client self-authenticates in
//! the iroh handshake, proves it holds a one-time token, and sends its signed
//! KeyBundle; the server verifies it and registers the client (fingerprint →
//! `--peer-allowlist`, bundle → `<key-dir>/received/<handle>.nkkb`).
//!
//! **Trust model**: the OTP authorizes the enrollment; the client's handshake
//! self-signature proves it owns the identity it is registering. The two are
//! tied together because `parse_and_verify` is pinned to the **handshake-verified
//! client fingerprint** — so the bundle MUST be self-signed by the connecting
//! identity (refinement 1). Registration adds only the allowlist entry, never a
//! shell/scp policy, so a freshly-paired client can connect but do nothing until
//! an admin writes an explicit policy (default-deny preserved).

use crate::config::CryptoConfig;
use crate::error::CryptoError;
use crate::shell::{recv_packet, role_keys, send_packet};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type Result<T> = std::result::Result<T, CryptoError>;

/// The identity signing algorithm for a KeyBundle owner (single anchor).
const PAIRING_IDENTITY_DSA: &str = "ML-DSA-65";
/// Upper bound on a received KeyBundle so a malformed length never over-allocates.
const MAX_BUNDLE_LEN: usize = 256 * 1024;
/// Upper bound on the token field (tokens are short; this rejects abuse).
const MAX_TOKEN_LEN: usize = 256;

// -- wire messages (one AEAD packet each, over the encrypted session) ----------
// Framing within the packet: u32-LE length ‖ bytes, bounds-checked, never panics.

fn put_lp(buf: &mut Vec<u8>, b: &[u8]) {
    buf.extend_from_slice(&(b.len() as u32).to_le_bytes());
    buf.extend_from_slice(b);
}

fn read_lp(buf: &[u8], off: &mut usize, cap: usize) -> Result<Vec<u8>> {
    if buf.len() < *off + 4 {
        return Err(CryptoError::Parameter("pairing: truncated length prefix".into()));
    }
    let len = u32::from_le_bytes(buf[*off..*off + 4].try_into().unwrap()) as usize;
    *off += 4;
    if len > cap {
        return Err(CryptoError::Parameter(format!("pairing: field of {len} bytes exceeds cap {cap}")));
    }
    if buf.len() < *off + len {
        return Err(CryptoError::Parameter("pairing: length exceeds remaining bytes".into()));
    }
    let v = buf[*off..*off + len].to_vec();
    *off += len;
    Ok(v)
}

/// Client → server: the one-time token and the client's signed KeyBundle bytes.
pub struct PairingRequest {
    pub token: String,
    pub keybundle_bytes: Vec<u8>,
}

impl PairingRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        put_lp(&mut b, self.token.as_bytes());
        put_lp(&mut b, &self.keybundle_bytes);
        b
    }
    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut off = 0;
        let token_bytes = read_lp(buf, &mut off, MAX_TOKEN_LEN)?;
        let keybundle_bytes = read_lp(buf, &mut off, MAX_BUNDLE_LEN)?;
        if off != buf.len() {
            return Err(CryptoError::Parameter("pairing: trailing bytes in request".into()));
        }
        let token = String::from_utf8(token_bytes)
            .map_err(|_| CryptoError::Parameter("pairing: token is not valid UTF-8".into()))?;
        Ok(Self { token, keybundle_bytes })
    }
}

/// Server → client: outcome of the pairing.
pub struct PairingResponse {
    pub ok: bool,
    pub msg: String,
}

impl PairingResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = vec![self.ok as u8];
        put_lp(&mut b, self.msg.as_bytes());
        b
    }
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.is_empty() {
            return Err(CryptoError::Parameter("pairing: empty response".into()));
        }
        let ok = buf[0] != 0;
        let mut off = 1;
        let msg_bytes = read_lp(buf, &mut off, 4096)?;
        if off != buf.len() {
            return Err(CryptoError::Parameter("pairing: trailing bytes in response".into()));
        }
        let msg = String::from_utf8_lossy(&msg_bytes).into_owned();
        Ok(Self { ok, msg })
    }
}

// -- helpers -------------------------------------------------------------------

/// Constant-time byte-slice equality (`subtle` was dropped in the M5 audit, so
/// this is a local implementation). Length is not secret here.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    // Length is not secret (the token length is fixed/public), so an early return
    // on mismatched length leaks nothing. `black_box` keeps the accumulate loop
    // from being optimized into a short-circuit.
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    std::hint::black_box(diff) == 0
}

/// Generate a random pairing token: 40 bits from the OS CSPRNG, base32 (8 chars,
/// no `0/1/8/9` ambiguity via RFC-4648 base32). Copy-pasteable and infeasible to
/// brute-force within the deadline.
pub fn generate_token() -> String {
    use rand_core::{OsRng, RngCore};
    let mut raw = [0u8; 5];
    OsRng.fill_bytes(&mut raw);
    data_encoding::BASE32_NOPAD.encode(&raw)
}

/// Validate a bundle `handle` used as a filename component: reject anything that
/// could escape the received-bundles directory. Only `[A-Za-z0-9._-]`, non-empty,
/// not `.`/`..`, no leading dot.
fn validate_handle(handle: &str) -> Result<()> {
    if handle.is_empty() || handle.len() > 128 {
        return Err(CryptoError::Parameter("pairing: handle empty or too long".into()));
    }
    if handle == "." || handle == ".." || handle.starts_with('.') {
        return Err(CryptoError::Parameter("pairing: handle must not start with a dot".into()));
    }
    if !handle
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return Err(CryptoError::Parameter(
            "pairing: handle may only contain [A-Za-z0-9._-]".into(),
        ));
    }
    Ok(())
}

/// Append `fp` (as 64-hex) to the allowlist file if absent, atomically. Parses
/// the existing hex-per-line format (mirrors `preload_allowlist`), dedups via a
/// set, and rewrites via `secure_write` (temp + rename, 0600).
fn append_allowlist(path: &str, fp: &[u8; 32]) -> Result<bool> {
    let mut set = std::collections::HashSet::new();
    if let Ok(content) = std::fs::read_to_string(path) {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Ok(bytes) = hex::decode(line) {
                if bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    set.insert(arr);
                }
            }
        }
    }
    let already = !set.insert(*fp);
    if already {
        return Ok(false);
    }
    let mut lines: Vec<String> = set.iter().map(hex::encode).collect();
    lines.sort();
    let body = lines.join("\n") + "\n";
    crate::utils::secure_write(path, body.as_bytes(), true)
        .map_err(|e| CryptoError::FileWrite(format!("pairing: write allowlist {path}: {e}")))?;
    Ok(true)
}

/// The core registration decision, returning a user-facing success message or an
/// error string (sent back to the client). Verifies the token (constant-time +
/// deadline), verifies the KeyBundle **pinned to the handshake-verified client
/// fingerprint** (refinement 1: the bundle must be self-signed by the connecting
/// identity), validates the handle, appends the allowlist, and saves the bundle.
fn register(req: &PairingRequest, client_fp: [u8; 32], config: &CryptoConfig) -> std::result::Result<String, String> {
    // 1. Token: constant-time compare + deadline.
    let expected = config
        .pairing_otp
        .as_deref()
        .ok_or_else(|| "server has no pairing token configured".to_string())?;
    if !ct_eq(req.token.as_bytes(), expected.as_bytes()) {
        return Err("invalid pairing token".into());
    }
    if let Some(deadline) = config.pairing_deadline_secs {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(u64::MAX);
        if now >= deadline {
            return Err("pairing token expired".into());
        }
    }

    // 2. KeyBundle: pin to the handshake-verified client fingerprint. If the
    //    bundle owner is not the connecting identity, parse_and_verify rejects it
    //    at step 1 (owner fingerprint != pin) — this IS refinement 1.
    let vb = crate::keybundle::parse_and_verify(&req.keybundle_bytes, PAIRING_IDENTITY_DSA, &client_fp)
        .map_err(|e| format!("KeyBundle rejected (must be self-signed by the connecting identity): {e}"))?;

    // 3. Handle → filename safety.
    validate_handle(&vb.handle).map_err(|e| e.to_string())?;

    // 4. Register the fingerprint into the allowlist (dedup, atomic).
    let allowlist = config
        .peer_allowlist
        .as_deref()
        .ok_or_else(|| "server has no --peer-allowlist configured".to_string())?;
    let added = append_allowlist(allowlist, &client_fp).map_err(|e| e.to_string())?;

    // 5. Save the bundle under <key-dir>/received/<handle>.nkkb (atomic, 0600).
    let dir = std::path::Path::new(&config.key_dir).join("received");
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {dir:?}: {e}"))?;
    let out = dir.join(format!("{}.nkkb", vb.handle));
    // Never let a client overwrite a bundle registered to a DIFFERENT identity by
    // claiming the same handle (that would redirect the server's mail to the
    // attacker). Overwrite is allowed ONLY when the existing bundle verifies under
    // the SAME owner (idempotent re-pairing) — reusing the refinement-1 pin check.
    if let Ok(existing) = std::fs::read(&out) {
        if crate::keybundle::parse_and_verify(&existing, PAIRING_IDENTITY_DSA, &client_fp).is_err() {
            return Err(format!(
                "handle {:?} is already registered to a different identity — pick another handle",
                vb.handle
            ));
        }
    }
    crate::utils::secure_write(&out, &req.keybundle_bytes, true)
        .map_err(|e| format!("save bundle {out:?}: {e}"))?;

    let fp_hex = hex::encode(client_fp);
    Ok(format!(
        "registered {} (fingerprint {}{}); saved bundle to {}",
        vb.handle,
        &fp_hex[..16],
        if added { "" } else { ", already in allowlist" },
        out.display()
    ))
}

/// Server handler for one pairing connection. `client_fp` is the
/// handshake-verified fingerprint (`SHA3-256(client ML-DSA pub)`).
pub async fn run_pairing_server<R, W>(
    mut reader: R,
    mut writer: W,
    aead_name: &str,
    s2c_key: &[u8],
    c2s_key: &[u8],
    client_fp: [u8; 32],
    config: &CryptoConfig,
) -> Result<()>
where
    R: AsyncReadExt + Unpin + Send,
    W: AsyncWriteExt + Unpin + Send,
{
    let (rx_key, tx_key) = role_keys(s2c_key, c2s_key, true);
    let (mut rx, mut tx) = (0u64, 0u64);

    let pt = recv_packet(&mut reader, aead_name, rx_key, &mut rx)
        .await?
        .ok_or_else(|| CryptoError::Parameter("pairing: client closed before request".into()))?;
    let req = PairingRequest::decode(&pt)?;

    let outcome = register(&req, client_fp, config);
    let resp = match &outcome {
        Ok(msg) => {
            eprintln!("[pairing] {msg}");
            PairingResponse { ok: true, msg: msg.clone() }
        }
        Err(msg) => {
            eprintln!("[pairing] rejected: {msg}");
            PairingResponse { ok: false, msg: msg.clone() }
        }
    };
    send_packet(&mut writer, aead_name, tx_key, &mut tx, &resp.encode()).await?;
    // Finish our send stream and wait for the client to drain the response and
    // close its side, so the connection isn't torn down with the response still
    // in flight (mirrors scp's terminal-frame teardown). Returning immediately
    // resets the stream and the client sees "server closed before responding"
    // even though the registration already committed.
    let _ = writer.shutdown().await;
    crate::scp::drain_until_close(&mut reader).await;

    outcome
        .map(|_| ())
        .map_err(|e| CryptoError::Parameter(format!("pairing rejected: {e}")))
}

/// Client side: send our KeyBundle and read the response. Returns the server's
/// message on success.
pub async fn run_pairing_client<R, W>(
    mut reader: R,
    mut writer: W,
    aead_name: &str,
    s2c_key: &[u8],
    c2s_key: &[u8],
    token: &str,
    keybundle_bytes: Vec<u8>,
) -> Result<String>
where
    R: AsyncReadExt + Unpin + Send,
    W: AsyncWriteExt + Unpin + Send,
{
    let (rx_key, tx_key) = role_keys(s2c_key, c2s_key, false);
    let (mut rx, mut tx) = (0u64, 0u64);

    let req = PairingRequest { token: token.to_string(), keybundle_bytes };
    send_packet(&mut writer, aead_name, tx_key, &mut tx, &req.encode()).await?;
    let _ = writer.flush().await;

    // Read the response *before* closing our send side. The server drains our
    // send stream until EOF and only then tears down the connection, so closing
    // early would release that drain and let the server close before the
    // response reached us (a race lost over a real network, hidden on loopback).
    let pt = recv_packet(&mut reader, aead_name, rx_key, &mut rx)
        .await?
        .ok_or_else(|| CryptoError::Parameter("pairing: server closed before responding".into()))?;
    // Now that we have the response, close our send side to signal the server's
    // drain that we are done, letting it tear down cleanly.
    let _ = writer.shutdown().await;
    let resp = PairingResponse::decode(&pt)?;
    if resp.ok {
        Ok(resp.msg)
    } else {
        Err(CryptoError::Parameter(format!("pairing rejected by server: {}", resp.msg)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_roundtrips_and_rejects_malformed() {
        let r = PairingRequest { token: "ABCD2345".into(), keybundle_bytes: vec![1, 2, 3, 4] };
        let enc = r.encode();
        let d = PairingRequest::decode(&enc).unwrap();
        assert_eq!(d.token, "ABCD2345");
        assert_eq!(d.keybundle_bytes, vec![1, 2, 3, 4]);
        // trailing byte / truncation → Err, never panic.
        let mut trailing = enc.clone();
        trailing.push(0);
        assert!(PairingRequest::decode(&trailing).is_err());
        assert!(PairingRequest::decode(&enc[..enc.len() / 2]).is_err());
        assert!(PairingRequest::decode(&[]).is_err());
    }

    #[test]
    fn response_roundtrips() {
        let r = PairingResponse { ok: true, msg: "ok".into() };
        let d = PairingResponse::decode(&r.encode()).unwrap();
        assert!(d.ok && d.msg == "ok");
    }

    #[test]
    fn ct_eq_matches_semantics() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }

    #[test]
    fn handle_validation_blocks_traversal() {
        assert!(validate_handle("alice").is_ok());
        assert!(validate_handle("alice_work-2").is_ok());
        for bad in ["", ".", "..", "../x", "a/b", ".hidden", "a\0b"] {
            assert!(validate_handle(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn generate_token_is_base32_and_stable_length() {
        let t = generate_token();
        assert_eq!(t.len(), 8);
        assert!(t.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()));
    }

    // Deterministic coverage of the security-critical registration decision
    // (refinement 1 / token / expiry / handle) without any networking.
    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        // Unique-per-owner-key temp dir (no Math.random needed): the caller seeds
        // it with a distinctive byte from the fresh keypair.
        let d = std::env::temp_dir().join(format!("nkct-pairing-test-{tag}"));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Build a real KeyBundle signed by a fresh ML-DSA-65 key; return
    /// `(bundle_bytes, owner_fp)`.
    fn sample_bundle(handle: &str) -> (Vec<u8>, [u8; 32]) {
        use sha3::{Digest, Sha3_256};
        let (sk, pk, _) = crate::backend::pqc_keygen_dsa("ML-DSA-65").unwrap();
        let target = vec![7u8; 1184]; // dummy ML-KEM-sized enc key
        let keys = vec![(crate::keybundle::KEY_USAGE_ENC, target, 1000u64, None)];
        let bytes = crate::keybundle::build_signed("ML-DSA-65", &sk, &pk, handle, 1000, &keys).unwrap();
        let fp: [u8; 32] = Sha3_256::digest(&pk).into();
        (bytes, fp)
    }

    fn base_config(dir: &std::path::Path, allowlist: &std::path::Path, token: &str, deadline: u64) -> CryptoConfig {
        let mut c = CryptoConfig::default();
        c.key_dir = dir.to_str().unwrap().to_string();
        c.peer_allowlist = Some(allowlist.to_str().unwrap().to_string());
        c.pairing_otp = Some(token.to_string());
        c.pairing_deadline_secs = Some(deadline);
        c
    }

    fn future() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 300
    }

    #[test]
    fn register_happy_path_writes_allowlist_and_bundle() {
        let (bytes, fp) = sample_bundle("alice");
        let dir = tmp_dir(&format!("ok-{:02x}", fp[0]));
        let allow = dir.join("allowlist");
        let config = base_config(&dir, &allow, "TOKEN123", future());
        let req = PairingRequest { token: "TOKEN123".into(), keybundle_bytes: bytes };
        let msg = register(&req, fp, &config).expect("should register");
        assert!(msg.contains("registered alice"));
        let al = std::fs::read_to_string(&allow).unwrap();
        assert!(al.contains(&hex::encode(fp)), "allowlist must contain the fingerprint");
        assert!(dir.join("received/alice.nkkb").exists(), "bundle must be saved");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn register_rejects_bundle_from_a_different_identity_refinement_1() {
        // The bundle is self-signed by identity A (fp), but the connecting client
        // authenticated as a DIFFERENT identity (wrong_fp). parse_and_verify is
        // pinned to the handshake fp, so it rejects — this IS refinement 1.
        let (bytes, _fp_a) = sample_bundle("alice");
        let (_b, fp_b) = sample_bundle("bob"); // a different identity's fingerprint
        let dir = tmp_dir(&format!("r1-{:02x}", fp_b[0]));
        let allow = dir.join("allowlist");
        let config = base_config(&dir, &allow, "T", future());
        let req = PairingRequest { token: "T".into(), keybundle_bytes: bytes };
        let r = register(&req, fp_b, &config); // pin = wrong identity
        assert!(r.is_err(), "a bundle not signed by the connecting identity must be rejected");
        assert!(!allow.exists() || std::fs::read_to_string(&allow).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn register_rejects_wrong_and_expired_token() {
        let (bytes, fp) = sample_bundle("alice");
        let dir = tmp_dir(&format!("tok-{:02x}", fp[0]));
        let allow = dir.join("allowlist");
        // wrong token
        let c1 = base_config(&dir, &allow, "RIGHT", future());
        let req = PairingRequest { token: "WRONG".into(), keybundle_bytes: bytes.clone() };
        assert!(register(&req, fp, &c1).is_err(), "wrong token must be rejected");
        // expired (deadline in the past)
        let c2 = base_config(&dir, &allow, "RIGHT", 1);
        let req2 = PairingRequest { token: "RIGHT".into(), keybundle_bytes: bytes };
        assert!(register(&req2, fp, &c2).is_err(), "expired token must be rejected");
        assert!(!allow.exists() || std::fs::read_to_string(&allow).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn register_refuses_handle_collision_from_a_different_identity() {
        let (bytes_a, fp_a) = sample_bundle("alice");
        let (bytes_b, fp_b) = sample_bundle("alice"); // different identity, SAME handle
        let dir = tmp_dir(&format!("coll-{:02x}{:02x}", fp_a[0], fp_b[0]));
        let allow = dir.join("allowlist");
        let ca = base_config(&dir, &allow, "T", future());
        register(&PairingRequest { token: "T".into(), keybundle_bytes: bytes_a.clone() }, fp_a, &ca)
            .expect("A registers alice");
        // B claims the same handle with a different identity → refused.
        let cb = base_config(&dir, &allow, "T", future());
        assert!(
            register(&PairingRequest { token: "T".into(), keybundle_bytes: bytes_b }, fp_b, &cb).is_err(),
            "a different identity must not overwrite an existing handle"
        );
        // A's bundle is intact (still owned by A).
        let saved = std::fs::read(dir.join("received/alice.nkkb")).unwrap();
        assert!(crate::keybundle::parse_and_verify(&saved, "ML-DSA-65", &fp_a).is_ok());
        // The SAME identity may re-register (idempotent).
        register(&PairingRequest { token: "T".into(), keybundle_bytes: bytes_a }, fp_a, &ca)
            .expect("A re-registers (idempotent)");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parser_fuzz_no_panic() {
        let mut state: u64 = 0xA5A5_1234_DEAD_BEEF;
        let mut next = || {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        };
        for _ in 0..2000u32 {
            let n = (next() % 1024) as usize;
            let bytes: Vec<u8> = (0..n).map(|_| (next() >> 33) as u8).collect();
            let _ = PairingRequest::decode(&bytes);
            let _ = PairingResponse::decode(&bytes);
        }
    }
}
