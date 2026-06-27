/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

//! P2P shell (bastion-less PQC SSH) — see `P2P_SHELL_DESIGN.md`.
//!
//! **Phase 0** of that plan: the `ALPN_SHELL` wire framing plus an **echo**
//! server/client, with no PTY yet. It validates that the typed control frames
//! survive a round trip over the existing PQC-authenticated, AEAD-secured
//! stream. Authorization is still only the transport `allowlist` (the handshake
//! already rejects unknown peers); per-user / PTY / privilege-drop come in later
//! phases.
//!
//! Each frame is carried as one AEAD packet: `len(u32 LE) ‖ ciphertext ‖
//! tag(16)`, sealed under the per-direction session key. The 96-bit nonce is a
//! **monotonic per-direction counter** (not transmitted; each side derives it
//! from its own counter), so a nonce is never reused under a session key, and a
//! replayed / reordered / tampered packet decrypts under the wrong counter and
//! fails AEAD authentication — no separate replay window needed. Session keys
//! are ephemeral (per connection, from the PQC handshake), so counters reset
//! safely each connection. The plaintext inside one packet is a single
//! [`Frame`].

use crate::backend;
use crate::backend::AeadBackend;
use crate::error::{CryptoError, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

/// Largest AEAD packet we will read (ciphertext + tag). Sized for a terminal
/// write burst, bounded so a peer cannot force a large allocation per packet.
const MAX_PACKET: usize = 128 * 1024;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const MIN_PACKET: usize = TAG_LEN + 1; // tag + at least the 1-byte frame type

/// Derive the 96-bit AEAD nonce for a direction's message counter: 4 zero bytes
/// followed by the big-endian counter. Monotonic and never reused under a given
/// session key.
fn nonce_from_ctr(ctr: u64) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[4..].copy_from_slice(&ctr.to_be_bytes());
    n
}

const T_OPEN: u8 = 0x01;
const T_DATA: u8 = 0x02;
const T_WINSZ: u8 = 0x03;
const T_EXIT: u8 = 0x04;
const T_ERROR: u8 = 0x05;

/// One control/data frame exchanged over `ALPN_SHELL`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// Client → server, once: request a session. `cmd` empty = login shell.
    Open { cols: u16, rows: u16, term: String, cmd: String },
    /// Terminal bytes (client→server = stdin, server→client = stdout/err).
    Data(Vec<u8>),
    /// Client → server: the controlling terminal resized.
    Winsz { cols: u16, rows: u16 },
    /// Server → client: the remote program exited with this status.
    Exit(i32),
    /// Either direction: a textual error (authz denied, spawn failed, …).
    Error(String),
}

impl Frame {
    /// Serialize to the plaintext that goes inside one AEAD packet.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::new();
        match self {
            Frame::Open { cols, rows, term, cmd } => {
                v.push(T_OPEN);
                v.extend_from_slice(&cols.to_be_bytes());
                v.extend_from_slice(&rows.to_be_bytes());
                v.extend_from_slice(&(term.len() as u16).to_be_bytes());
                v.extend_from_slice(term.as_bytes());
                v.extend_from_slice(&(cmd.len() as u16).to_be_bytes());
                v.extend_from_slice(cmd.as_bytes());
            }
            Frame::Data(d) => {
                v.push(T_DATA);
                v.extend_from_slice(d);
            }
            Frame::Winsz { cols, rows } => {
                v.push(T_WINSZ);
                v.extend_from_slice(&cols.to_be_bytes());
                v.extend_from_slice(&rows.to_be_bytes());
            }
            Frame::Exit(code) => {
                v.push(T_EXIT);
                v.extend_from_slice(&code.to_be_bytes());
            }
            Frame::Error(m) => {
                v.push(T_ERROR);
                v.extend_from_slice(m.as_bytes());
            }
        }
        v
    }

    /// Parse a frame from one packet's plaintext. Every length is bounds-checked
    /// against the buffer so a malformed frame is a clean error, never a panic.
    pub fn decode(buf: &[u8]) -> Result<Frame> {
        let bad = || CryptoError::Parameter("malformed shell frame".to_string());
        let (&ty, rest) = buf.split_first().ok_or_else(bad)?;
        match ty {
            T_OPEN => {
                if rest.len() < 6 {
                    return Err(bad());
                }
                let cols = u16::from_be_bytes([rest[0], rest[1]]);
                let rows = u16::from_be_bytes([rest[2], rest[3]]);
                let tlen = u16::from_be_bytes([rest[4], rest[5]]) as usize;
                let rest = &rest[6..];
                if rest.len() < tlen + 2 {
                    return Err(bad());
                }
                let term = std::str::from_utf8(&rest[..tlen]).map_err(|_| bad())?.to_string();
                let rest = &rest[tlen..];
                let clen = u16::from_be_bytes([rest[0], rest[1]]) as usize;
                let rest = &rest[2..];
                if rest.len() < clen {
                    return Err(bad());
                }
                let cmd = std::str::from_utf8(&rest[..clen]).map_err(|_| bad())?.to_string();
                Ok(Frame::Open { cols, rows, term, cmd })
            }
            T_DATA => Ok(Frame::Data(rest.to_vec())),
            T_WINSZ => {
                if rest.len() < 4 {
                    return Err(bad());
                }
                Ok(Frame::Winsz {
                    cols: u16::from_be_bytes([rest[0], rest[1]]),
                    rows: u16::from_be_bytes([rest[2], rest[3]]),
                })
            }
            T_EXIT => {
                if rest.len() < 4 {
                    return Err(bad());
                }
                Ok(Frame::Exit(i32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]])))
            }
            T_ERROR => Ok(Frame::Error(String::from_utf8_lossy(rest).into_owned())),
            _ => Err(CryptoError::Parameter(format!("unknown shell frame type {ty}"))),
        }
    }
}

/// Seal `frame` under `key` with the nonce derived from `ctr` (incremented on
/// success) and write it as one length-prefixed AEAD packet (`ct ‖ tag`).
pub async fn send_frame<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    aead_name: &str,
    key: &[u8],
    ctr: &mut u64,
    frame: &Frame,
) -> Result<()> {
    let nonce = nonce_from_ctr(*ctr);
    let pt = Zeroizing::new(frame.encode());
    let mut aead = backend::new_encrypt(aead_name, key, &nonce)?;
    let mut ct = Zeroizing::new(vec![0u8; pt.len() + 32]);
    let n = aead.update(&pt, &mut ct)?;
    let fin = aead.finalize(&mut ct[n..])?;
    let mut tag = [0u8; TAG_LEN];
    aead.get_tag(&mut tag)?;

    let mut packet = Vec::with_capacity(n + fin + TAG_LEN);
    packet.extend_from_slice(&ct[..n + fin]);
    packet.extend_from_slice(&tag);

    w.write_all(&(packet.len() as u32).to_le_bytes()).await.map_err(io_err)?;
    w.write_all(&packet).await.map_err(io_err)?;
    w.flush().await.map_err(io_err)?;
    *ctr = ctr.checked_add(1).ok_or_else(|| {
        CryptoError::Parameter("shell send counter overflow".to_string())
    })?;
    Ok(())
}

/// Read one length-prefixed AEAD packet, decrypt under `key` with the nonce
/// derived from `ctr` (incremented on success), and decode the [`Frame`].
/// Returns `Ok(None)` on a clean stream close (zero-length frame or EOF). A
/// replayed/reordered/tampered packet decrypts under the wrong counter-nonce and
/// surfaces as an authentication error.
pub async fn recv_frame<R: AsyncReadExt + Unpin>(
    r: &mut R,
    aead_name: &str,
    key: &[u8],
    ctr: &mut u64,
) -> Result<Option<Frame>> {
    let mut len_bytes = [0u8; 4];
    match r.read_exact(&mut len_bytes).await {
        Ok(_) => {}
        Err(_) => return Ok(None), // EOF / peer closed
    }
    let len = u32::from_le_bytes(len_bytes) as usize;
    if len == 0 {
        return Ok(None);
    }
    if !(MIN_PACKET..=MAX_PACKET).contains(&len) {
        return Err(CryptoError::Parameter(format!("shell packet size {len} out of range")));
    }
    let mut packet = Zeroizing::new(vec![0u8; len]);
    r.read_exact(&mut packet).await.map_err(io_err)?;

    let (ciphertext, tag) = packet.split_at(packet.len() - TAG_LEN);
    let nonce = nonce_from_ctr(*ctr);
    let mut aead = backend::new_decrypt(aead_name, key, &nonce)?;
    aead.set_tag(tag)?;
    let mut out = Zeroizing::new(vec![0u8; ciphertext.len() + 32]);
    let n = aead.update(ciphertext, &mut out)?;
    let fin = aead.finalize(&mut out[n..])?;
    *ctr = ctr.checked_add(1).ok_or_else(|| {
        CryptoError::Parameter("shell recv counter overflow".to_string())
    })?;
    Frame::decode(&out[..n + fin]).map(Some)
}

fn io_err(e: std::io::Error) -> CryptoError {
    CryptoError::FileRead(e.to_string())
}

/// Pick `(rx_key, tx_key)` from the session keys for our role, matching
/// `chat_loop`: the server receives on c2s and sends on s2c.
fn role_keys<'a>(s2c: &'a [u8], c2s: &'a [u8], is_server: bool) -> (&'a [u8], &'a [u8]) {
    if is_server {
        (c2s, s2c)
    } else {
        (s2c, c2s)
    }
}

/// **Phase 0 echo server.** Accepts the `Open`, then echoes every `Data` frame
/// straight back, until the client sends `Exit` or the stream closes. No PTY yet
/// — this exercises the framing and the secured transport end to end.
pub async fn run_echo_server<R, W>(
    mut reader: R,
    mut writer: W,
    aead_name: &str,
    s2c_key: &[u8],
    c2s_key: &[u8],
) -> Result<()>
where
    R: AsyncReadExt + Unpin + Send,
    W: AsyncWriteExt + Unpin + Send,
{
    let (rx_key, tx_key) = role_keys(s2c_key, c2s_key, true);
    let (mut rx_ctr, mut tx_ctr) = (0u64, 0u64);
    let mut opened = false;
    loop {
        let frame = match recv_frame(&mut reader, aead_name, rx_key, &mut rx_ctr).await? {
            Some(f) => f,
            None => break,
        };
        match frame {
            Frame::Open { term, cmd, .. } => {
                opened = true;
                eprintln!(
                    "[shell] echo session opened (TERM={term:?}, cmd={})",
                    if cmd.is_empty() { "<login>" } else { cmd.as_str() }
                );
            }
            Frame::Data(d) if opened => {
                send_frame(&mut writer, aead_name, tx_key, &mut tx_ctr, &Frame::Data(d)).await?;
            }
            Frame::Data(_) => {
                send_frame(
                    &mut writer,
                    aead_name,
                    tx_key,
                    &mut tx_ctr,
                    &Frame::Error("DATA before OPEN".to_string()),
                )
                .await?;
                break;
            }
            Frame::Exit(_) => break,
            Frame::Winsz { .. } => {} // ignored by the echo server
            Frame::Error(_) => break,
        }
    }
    let _ = send_frame(&mut writer, aead_name, tx_key, &mut tx_ctr, &Frame::Exit(0)).await;
    Ok(())
}

/// **Phase 0 echo client.** Sends `Open`, then for each line on `input` sends a
/// `Data` frame and prints the echoed reply to `out`, until `input` ends; then
/// sends `Exit`. Mirrors how the real client will pump a PTY in later phases.
pub async fn run_echo_client<R, W, IN, OUT>(
    mut reader: R,
    mut writer: W,
    aead_name: &str,
    s2c_key: &[u8],
    c2s_key: &[u8],
    mut input: IN,
    out: &mut OUT,
) -> Result<()>
where
    R: AsyncReadExt + Unpin + Send,
    W: AsyncWriteExt + Unpin + Send,
    IN: AsyncReadExt + Unpin + Send,
    OUT: AsyncWriteExt + Unpin + Send,
{
    let (rx_key, tx_key) = role_keys(s2c_key, c2s_key, false);
    let (mut rx_ctr, mut tx_ctr) = (0u64, 0u64);
    send_frame(
        &mut writer,
        aead_name,
        tx_key,
        &mut tx_ctr,
        &Frame::Open { cols: 80, rows: 24, term: "xterm-256color".to_string(), cmd: String::new() },
    )
    .await?;

    let mut buf = vec![0u8; 4096];
    loop {
        let n = input.read(&mut buf).await.map_err(io_err)?;
        if n == 0 {
            break;
        }
        send_frame(&mut writer, aead_name, tx_key, &mut tx_ctr, &Frame::Data(buf[..n].to_vec()))
            .await?;
        // Read the echoed reply for this burst (Phase 0 is lockstep; the real
        // PTY client in Phase 1 pumps both directions concurrently).
        match recv_frame(&mut reader, aead_name, rx_key, &mut rx_ctr).await? {
            Some(Frame::Data(d)) => {
                out.write_all(&d).await.map_err(io_err)?;
                out.flush().await.map_err(io_err)?;
            }
            Some(Frame::Error(m)) => {
                return Err(CryptoError::Parameter(format!("shell server error: {m}")));
            }
            Some(Frame::Exit(_)) | None => break,
            Some(_) => {}
        }
    }
    send_frame(&mut writer, aead_name, tx_key, &mut tx_ctr, &Frame::Exit(0)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_encode_decode_roundtrip() {
        let frames = vec![
            Frame::Open { cols: 120, rows: 40, term: "xterm".into(), cmd: "ls -la".into() },
            Frame::Open { cols: 80, rows: 24, term: String::new(), cmd: String::new() },
            Frame::Data(vec![0, 1, 2, 255, 254]),
            Frame::Winsz { cols: 200, rows: 50 },
            Frame::Exit(-7),
            Frame::Error("denied".into()),
        ];
        for f in frames {
            let enc = f.encode();
            assert_eq!(Frame::decode(&enc).unwrap(), f);
        }
    }

    #[test]
    fn decode_rejects_truncated_open() {
        assert!(Frame::decode(&[T_OPEN, 0, 80]).is_err());
        assert!(Frame::decode(&[]).is_err());
        assert!(Frame::decode(&[0x99]).is_err());
    }

    #[tokio::test]
    async fn secure_frame_roundtrip_over_duplex() {
        let aead = "AES-256-GCM";
        let s2c = vec![7u8; 32];
        let c2s = vec![9u8; 32];
        let (mut a, mut b) = tokio::io::duplex(65536);

        // Client (sender) seals under c2s; server (receiver) opens with c2s.
        // Two frames to confirm the counter advances in lockstep.
        let (mut tx, mut rx) = (0u64, 0u64);
        let f1 = Frame::Data(b"secure hello".to_vec());
        let f2 = Frame::Winsz { cols: 100, rows: 30 };
        send_frame(&mut a, aead, &c2s, &mut tx, &f1).await.unwrap();
        send_frame(&mut a, aead, &c2s, &mut tx, &f2).await.unwrap();
        assert_eq!(recv_frame(&mut b, aead, &c2s, &mut rx).await.unwrap(), Some(f1));
        assert_eq!(recv_frame(&mut b, aead, &c2s, &mut rx).await.unwrap(), Some(f2));
        assert_eq!((tx, rx), (2, 2));
        let _ = &s2c;
    }

    #[tokio::test]
    async fn replayed_or_reordered_packet_fails_auth() {
        let aead = "AES-256-GCM";
        let key = vec![5u8; 32];
        let (mut a, mut b) = tokio::io::duplex(65536);
        let mut tx = 0u64;
        send_frame(&mut a, aead, &key, &mut tx, &Frame::Data(b"x".to_vec())).await.unwrap();
        // Receiver expects counter 1 (e.g. this packet is a replay of an earlier
        // one, or arrived out of order): the derived nonce differs → AEAD fails.
        let mut rx = 1u64;
        assert!(recv_frame(&mut b, aead, &key, &mut rx).await.is_err());
    }

    #[tokio::test]
    async fn echo_server_and_client_roundtrip() {
        let aead = "AES-256-GCM";
        let s2c = vec![1u8; 32];
        let c2s = vec![2u8; 32];
        // Two duplex pipes: client→server and server→client.
        let (c_tx, s_rx) = tokio::io::duplex(65536); // client writes, server reads
        let (s_tx, c_rx) = tokio::io::duplex(65536); // server writes, client reads

        let (s2c_s, c2s_s) = (s2c.clone(), c2s.clone());
        let server = tokio::spawn(async move {
            run_echo_server(s_rx, s_tx, aead, &s2c_s, &c2s_s).await
        });

        let input = std::io::Cursor::new(b"line-one\nline-two\n".to_vec());
        let mut out: Vec<u8> = Vec::new();
        run_echo_client(c_rx, c_tx, aead, &s2c, &c2s, input, &mut out)
            .await
            .unwrap();
        assert_eq!(out, b"line-one\nline-two\n");
        server.await.unwrap().unwrap();
    }
}
