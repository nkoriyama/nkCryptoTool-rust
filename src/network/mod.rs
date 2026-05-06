pub mod iroh;
pub mod tcp;

use crate::backend;
use crate::backend::{Aead, AeadBackend};
use crate::config::{CryptoConfig, TransportKind};
use crate::error::{CryptoError, Result};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::{Zeroize, Zeroizing};

pub const BUF_SIZE: usize = 1024 * 1024;
pub const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024 * 1024; // 10GB
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
pub const CUMULATIVE_TIMEOUT: Duration = Duration::from_secs(7200);
pub const CHAT_SESSION_TIMEOUT: Duration = Duration::from_secs(7200); // 2 hours

pub const ALPN_CHAT: &[u8] = b"nkct/chat/1";
pub const ALPN_FILE: &[u8] = b"nkct/file/1";

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PeerId {
    Ip(std::net::IpAddr),
    Node([u8; 32]), // Iroh NodeId
    Pubkey([u8; 32]),
}

#[derive(Debug, PartialEq, Eq)]
pub enum LineRead {
    Line,       // Got a full line ending with \n (or \r\n)
    PartialEof, // Got EOF but with some data before it
    Eof,        // Got EOF with 0 bytes
}

pub static CHAT_ACTIVE: Lazy<std::sync::atomic::AtomicBool> =
    Lazy::new(|| std::sync::atomic::AtomicBool::new(false));

pub static PEER_COOLDOWNS: Lazy<Mutex<std::collections::HashMap<PeerId, std::time::Instant>>> =
    Lazy::new(|| Mutex::new(std::collections::HashMap::new()));

pub struct ChatActiveGuard {
    pub peer_id: PeerId,
    pub _start_time: std::time::Instant,
}

impl Drop for ChatActiveGuard {
    fn drop(&mut self) {
        let mut cooldowns = PEER_COOLDOWNS.lock();
        cooldowns.insert(self.peer_id.clone(), std::time::Instant::now());
        CHAT_ACTIVE.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

pub struct AbortGuard(pub tokio::task::AbortHandle);
impl Drop for AbortGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub struct NetworkProcessor;

impl NetworkProcessor {
    pub async fn listen(config: &CryptoConfig) -> Result<()> {
        match config.transport {
            TransportKind::Tcp => tcp::NetworkProcessor::listen(config).await,
            TransportKind::Iroh => iroh::NetworkProcessor::listen(config).await,
        }
    }

    pub async fn connect(config: &CryptoConfig) -> Result<()> {
        match config.transport {
            TransportKind::Tcp => tcp::NetworkProcessor::connect(config).await,
            TransportKind::Iroh => iroh::NetworkProcessor::connect(config).await,
        }
    }

    pub async fn read_line_secure<R: AsyncReadExt + Unpin>(
        reader: &mut R,
        buf: &mut Vec<u8>,
    ) -> Result<LineRead> {
        let mut b = [0u8; 1];
        let mut total = 0;
        const MAX_LINE_LEN: usize = 65536;
        loop {
            match reader.read(&mut b).await {
                Ok(0) => {
                    if total > 0 {
                        return Ok(LineRead::PartialEof);
                    } else {
                        return Ok(LineRead::Eof);
                    }
                }
                Ok(1) => {
                    if b[0] == b'\n' {
                        return Ok(LineRead::Line);
                    }
                    if b[0] != b'\r' {
                        if total >= MAX_LINE_LEN {
                            return Err(CryptoError::Parameter("Line too long".to_string()));
                        }
                        buf.push(b[0]);
                        total += 1;
                    }
                }
                _ => return Err(CryptoError::FileRead("Unexpected read result".to_string())),
            }
        }
    }

    pub fn update_transcript(transcript: &mut Vec<u8>, data: &[u8]) {
        transcript.extend_from_slice(&(data.len() as u32).to_le_bytes());
        transcript.extend_from_slice(data);
    }

    pub async fn read_vec<R: AsyncReadExt + Unpin>(stream: &mut R) -> Result<Vec<u8>> {
        let mut len_bytes = [0u8; 4];
        stream
            .read_exact(&mut len_bytes)
            .await
            .map_err(|e| CryptoError::FileRead(e.to_string()))?;
        let len = u32::from_le_bytes(len_bytes) as usize;
        if len > 8192 {
            return Err(CryptoError::Parameter("Vector too large".to_string()));
        }
        let mut v = vec![0u8; len];
        stream
            .read_exact(&mut v)
            .await
            .map_err(|e| CryptoError::FileRead(e.to_string()))?;
        Ok(v)
    }

    pub async fn write_vec<W: AsyncWriteExt + Unpin>(stream: &mut W, v: &[u8]) -> Result<()> {
        stream
            .write_all(&(v.len() as u32).to_le_bytes())
            .await
            .map_err(|e| CryptoError::FileRead(e.to_string()))?;
        stream
            .write_all(v)
            .await
            .map_err(|e| CryptoError::FileRead(e.to_string()))?;
        Ok(())
    }

    pub async fn receive_file<R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
        mut reader: R,
        mut writer: W,
        aead_algo: &str,
        key: &[u8],
        iv: &[u8],
    ) -> Result<()> {
        let mut aead = backend::new_decrypt(aead_algo, key, iv)?;
        let mut out_buffer = Zeroizing::new(vec![0u8; BUF_SIZE + 32]);
        let mut total_received = 0u64;
        loop {
            let mut len_bytes = [0u8; 4];
            let read_res =
                tokio::time::timeout(IDLE_TIMEOUT, reader.read_exact(&mut len_bytes)).await;
            match read_res {
                Ok(Ok(_)) => {}
                Ok(Err(_)) | Err(_) => break,
            }

            let chunk_len = u32::from_le_bytes(len_bytes) as usize;
            if chunk_len == 0 {
                break;
            }
            if chunk_len > BUF_SIZE + 256 {
                return Err(CryptoError::Parameter(format!(
                    "Chunk size {} exceeds limit",
                    chunk_len
                )));
            }
            total_received += chunk_len as u64;
            if total_received > MAX_FILE_SIZE {
                return Err(CryptoError::Parameter(
                    "File size limit exceeded".to_string(),
                ));
            }

            let mut encrypted_chunk = Zeroizing::new(vec![0u8; chunk_len]);
            tokio::time::timeout(IDLE_TIMEOUT, reader.read_exact(&mut encrypted_chunk))
                .await
                .map_err(|_| {
                    CryptoError::Parameter("Idle timeout while reading chunk".to_string())
                })?
                .map_err(|e| CryptoError::FileRead(e.to_string()))?;

            let n = aead.update(&encrypted_chunk, &mut out_buffer)?;
            writer
                .write_all(&out_buffer[..n])
                .await
                .map_err(|e| CryptoError::FileRead(e.to_string()))?;
        }

        let mut tag = [0u8; 16];
        tokio::time::timeout(IDLE_TIMEOUT, reader.read_exact(&mut tag))
            .await
            .map_err(|_| CryptoError::Parameter("Idle timeout while reading tag".to_string()))?
            .map_err(|e| CryptoError::FileRead(format!("Failed to read GCM tag: {}", e)))?;

        aead.set_tag(&tag)?;
        let final_n = aead.finalize(&mut out_buffer)?;
        writer
            .write_all(&out_buffer[..final_n])
            .await
            .map_err(|e| CryptoError::FileRead(e.to_string()))?;
        writer
            .flush()
            .await
            .map_err(|e| CryptoError::FileRead(e.to_string()))?;

        eprintln!("File received and decrypted successfully.");
        Ok(())
    }

    pub async fn send_file<R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
        mut reader: R,
        mut writer: W,
        aead_algo: &str,
        key: &[u8],
        iv: &[u8],
    ) -> Result<()> {
        let mut aead = backend::new_encrypt(aead_algo, key, iv)?;
        let mut buffer = Zeroizing::new(vec![0u8; BUF_SIZE]);
        let mut out_buffer = Zeroizing::new(vec![0u8; BUF_SIZE + 32]);

        loop {
            let n = reader
                .read(&mut buffer)
                .await
                .map_err(|e| CryptoError::FileRead(e.to_string()))?;
            if n == 0 {
                break;
            }
            let enc_n = aead.update(&buffer[..n], &mut out_buffer)?;

            tokio::time::timeout(IDLE_TIMEOUT, writer.write_all(&(enc_n as u32).to_le_bytes()))
                .await
                .map_err(|_| {
                    CryptoError::Parameter("Idle timeout while sending chunk header".to_string())
                })?
                .map_err(|e| CryptoError::FileRead(e.to_string()))?;
            tokio::time::timeout(IDLE_TIMEOUT, writer.write_all(&out_buffer[..enc_n]))
                .await
                .map_err(|_| {
                    CryptoError::Parameter("Idle timeout while sending chunk".to_string())
                })?
                .map_err(|e| CryptoError::FileRead(e.to_string()))?;
        }

        let final_n = aead.finalize(&mut out_buffer)?;
        let mut tag = vec![0u8; 16];
        aead.get_tag(&mut tag)?;

        tokio::time::timeout(IDLE_TIMEOUT, writer.write_all(&(final_n as u32).to_le_bytes()))
            .await
            .map_err(|_| {
                CryptoError::Parameter(
                    "Idle timeout while sending final chunk header".to_string(),
                )
            })?
            .map_err(|e| CryptoError::FileRead(e.to_string()))?;
        tokio::time::timeout(IDLE_TIMEOUT, writer.write_all(&out_buffer[..final_n]))
            .await
            .map_err(|_| {
                CryptoError::Parameter("Idle timeout while sending final chunk".to_string())
            })?
            .map_err(|e| CryptoError::FileRead(e.to_string()))?;
        tokio::time::timeout(IDLE_TIMEOUT, writer.write_all(&tag))
            .await
            .map_err(|_| CryptoError::Parameter("Idle timeout while sending tag".to_string()))?
            .map_err(|e| CryptoError::FileRead(e.to_string()))?;

        writer
            .flush()
            .await
            .map_err(|e| CryptoError::FileRead(e.to_string()))?;
        eprintln!("File sent successfully.");
        Ok(())
    }

    pub async fn chat_loop<R, W, SI>(
        mut stream_rx: R,
        mut stream_tx: W,
        mut stdin: SI,
        aead_name: &str,
        s2c_key: &[u8],
        c2s_key: &[u8],
        is_server: bool,
    ) -> Result<()>
    where
        R: AsyncReadExt + Unpin + Send + 'static,
        W: AsyncWriteExt + Unpin + Send + 'static,
        SI: AsyncReadExt + Unpin + Send,
    {
        let (rx_key, tx_key) = if is_server {
            (
                Zeroizing::new(c2s_key.to_vec()),
                Zeroizing::new(s2c_key.to_vec()),
            )
        } else {
            (
                Zeroizing::new(s2c_key.to_vec()),
                Zeroizing::new(c2s_key.to_vec()),
            )
        };

        let aead_name_str = aead_name.to_string();
        let (rx_done_tx, mut rx_done_rx) = tokio::sync::mpsc::channel(1);

        let rx_task = tokio::spawn(async move {
            let mut out_buf = Zeroizing::new(vec![0u8; 70000]);
            let mut seen_nonces: std::collections::HashSet<Vec<u8>> =
                std::collections::HashSet::new();
            let mut nonce_history = std::collections::VecDeque::new();
            let mut rx_aead_opt: Option<Aead> = None;
            let result = async {
                loop {
                    let mut len_bytes = [0u8; 4];
                    let read_res =
                        tokio::time::timeout(IDLE_TIMEOUT, stream_rx.read_exact(&mut len_bytes))
                            .await;
                    match read_res {
                        Ok(Ok(_)) => {}
                        Ok(Err(_)) | Err(_) => break,
                    }

                    let chunk_len = u32::from_le_bytes(len_bytes) as usize;
                    if chunk_len == 0 {
                        break;
                    }
                    if chunk_len < 29 || chunk_len > 70000 {
                        return Err(CryptoError::Parameter("Invalid packet size".to_string()));
                    }

                    let mut packet = Zeroizing::new(vec![0u8; chunk_len]);
                    tokio::time::timeout(IDLE_TIMEOUT, stream_rx.read_exact(&mut packet))
                        .await
                        .map_err(|_| {
                            CryptoError::Parameter(
                                "Idle timeout while reading chat packet".to_string(),
                            )
                        })?
                        .map_err(|e| CryptoError::FileRead(e.to_string()))?;

                    let (nonce, rest) = packet.split_at(12);
                    let (ciphertext, tag) = rest.split_at(rest.len() - 16);

                    if seen_nonces.contains(nonce) {
                        return Err(CryptoError::Parameter(
                            "Replayed nonce detected".to_string(),
                        ));
                    }
                    let nonce_vec = nonce.to_vec();
                    seen_nonces.insert(nonce_vec.clone());
                    nonce_history.push_back(nonce_vec);
                    if nonce_history.len() > 100000 {
                        if let Some(oldest) = nonce_history.pop_front() {
                            seen_nonces.remove(&oldest);
                        }
                    }

                    if rx_aead_opt.is_none() {
                        rx_aead_opt = Some(backend::new_decrypt(&aead_name_str, &rx_key, nonce)?);
                    } else {
                        rx_aead_opt.as_mut().unwrap().re_init(&rx_key, nonce)?;
                    }
                    let rx_aead = rx_aead_opt.as_mut().unwrap();
                    rx_aead.set_tag(tag)?;

                    let n = rx_aead.update(ciphertext, &mut out_buf)?;
                    let final_n = rx_aead.finalize(&mut out_buf[n..])?;
                    let used = n + final_n;

                    let msg_content =
                        std::str::from_utf8(&out_buf[..used]).unwrap_or("[Invalid UTF-8 Message]");
                    let msg = Zeroizing::new(
                        msg_content
                            .chars()
                            .filter(|c| {
                                let is_dangerous = match *c {
                                    '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' => true,
                                    '\u{200B}'..='\u{200D}' | '\u{FEFF}' => true,
                                    '\u{061C}' => true,
                                    '\u{180E}' => true,
                                    '\u{E0000}'..='\u{E007F}' => true,
                                    '\u{115F}' | '\u{1160}' | '\u{3164}' | '\u{FFA0}' => true,
                                    _ => false,
                                };
                                (!c.is_control() || *c == '\n' || *c == '\t') && !is_dangerous
                            })
                            .collect::<String>(),
                    );
                    let mut stdout = tokio::io::stdout();
                    let _ = stdout.write_all(b"\r[Peer]: ").await;
                    let _ = stdout.write_all(msg.as_bytes()).await;
                    let _ = stdout.write_all(b"\n> ").await;
                    let _ = stdout.flush().await;

                    out_buf.fill(0);
                }
                Ok::<(), CryptoError>(())
            }
            .await;
            let _ = rx_done_tx.send(result).await;
        });

        let _rx_guard = AbortGuard(rx_task.abort_handle());

        let mut line_buf = Zeroizing::new(Vec::new());

        eprintln!("--- Chat mode started ---");
        {
            let mut stdout = tokio::io::stdout();
            let _ = stdout.write_all(b"> ").await;
            let _ = stdout.flush().await;
        }

        let mut tx_aead_opt: Option<Aead> = None;
        loop {
            tokio::select! {
                rx_result = rx_done_rx.recv() => {
                    if let Some(Err(e)) = rx_result {
                        eprintln!("\r\n[System]: Connection closed due to error: {}", e);
                        return Err(e);
                    }
                    eprintln!("\r\n[System]: Connection closed by peer.");
                    break Ok(());
                }
                res = Self::read_line_secure(&mut stdin, &mut line_buf) => {
                    let lr = res?;
                    if lr == LineRead::Eof {
                        eprintln!("\r\n[System]: stdin closed.");
                        break Ok(());
                    }
                    if lr == LineRead::Line && line_buf.is_empty() {
                        let mut stdout = tokio::io::stdout();
                        let _ = stdout.write_all(b"> ").await;
                        let _ = stdout.flush().await;
                        continue;
                    }
                    let line = Zeroizing::new(
                        std::str::from_utf8(&line_buf)
                            .unwrap_or("[Invalid UTF-8]")
                            .to_string()
                    );
                    line_buf.zeroize();
                    line_buf.clear();

                    let mut data = line.as_bytes();
                    if data.len() > 65000 {
                        data = &data[..65000];
                        eprintln!("Warning: Message truncated to 65000 bytes.");
                    }

                    let mut nonce = Zeroizing::new(vec![0u8; 12]);
                    #[cfg(feature = "backend-openssl")]
                    openssl::rand::rand_bytes(&mut nonce).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
                    #[cfg(feature = "backend-rustcrypto")]
                    {
                        use rand_core::{RngCore, OsRng};
                        OsRng.fill_bytes(&mut *nonce);
                    }

                    if tx_aead_opt.is_none() {
                        tx_aead_opt = Some(backend::new_encrypt(aead_name, &tx_key, &nonce)?);
                    } else {
                        tx_aead_opt.as_mut().unwrap().re_init(&tx_key, &nonce)?;
                    }
                    let tx_aead = tx_aead_opt.as_mut().unwrap();
                    let mut encrypted = Zeroizing::new(vec![0u8; data.len() + 32]);
                    let n = tx_aead.update(data, &mut encrypted)?;
                    let final_n = tx_aead.finalize(&mut encrypted[n..])?;

                    let mut tag = Zeroizing::new(vec![0u8; 16]);
                    tx_aead.get_tag(&mut tag)?;

                    let mut packet = Zeroizing::new(Vec::with_capacity(12 + n + final_n + 16));
                    packet.extend_from_slice(&nonce);
                    packet.extend_from_slice(&encrypted[..n + final_n]);
                    packet.extend_from_slice(&tag);

                    tokio::time::timeout(IDLE_TIMEOUT, stream_tx.write_all(&(packet.len() as u32).to_le_bytes())).await
                        .map_err(|_| CryptoError::Parameter("Idle timeout while sending chat header".to_string()))?
                        .map_err(|e| CryptoError::FileRead(e.to_string()))?;
                    tokio::time::timeout(IDLE_TIMEOUT, stream_tx.write_all(&packet)).await
                        .map_err(|_| CryptoError::Parameter("Idle timeout while sending chat packet".to_string()))?
                        .map_err(|e| CryptoError::FileRead(e.to_string()))?;

                    let mut stdout = tokio::io::stdout();
                    let _ = stdout.write_all(b"> ").await;
                    let _ = stdout.flush().await;

                    if lr == LineRead::PartialEof {
                        eprintln!("\r\n[System]: stdin closed.");
                        break Ok(());
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_read_line_secure_eof() {
        let mut input = tokio::io::empty();
        let mut buf = Vec::new();
        let res = NetworkProcessor::read_line_secure(&mut input, &mut buf).await.unwrap();
        assert_eq!(res, LineRead::Eof);
        assert!(buf.is_empty());
    }

    #[tokio::test]
    async fn test_read_line_secure_line() {
        let mut input = std::io::Cursor::new(b"hello\n");
        let mut buf = Vec::new();
        let res = NetworkProcessor::read_line_secure(&mut input, &mut buf).await.unwrap();
        assert_eq!(res, LineRead::Line);
        assert_eq!(buf, b"hello");
    }

    #[tokio::test]
    async fn test_read_line_secure_partial_eof() {
        let mut input = std::io::Cursor::new(b"partial");
        let mut buf = Vec::new();
        let res = NetworkProcessor::read_line_secure(&mut input, &mut buf).await.unwrap();
        assert_eq!(res, LineRead::PartialEof);
        assert_eq!(buf, b"partial");
    }

    #[tokio::test]
    async fn test_read_line_secure_empty_line() {
        let mut input = std::io::Cursor::new(b"\n");
        let mut buf = Vec::new();
        let res = NetworkProcessor::read_line_secure(&mut input, &mut buf).await.unwrap();
        assert_eq!(res, LineRead::Line);
        assert!(buf.is_empty());
    }
}
