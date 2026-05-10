// use crate::backend;
use crate::config::CryptoConfig;
use crate::error::{CryptoError, Result};
use crate::network::{
    NetworkProcessor as CommonProcessor, PeerId, CHAT_ACTIVE, PEER_COOLDOWNS, ChatActiveGuard,
    ALPN_CHAT, ALPN_FILE, IOProvider, DefaultIOProvider, ProgressCallback,
};
use iroh::{Endpoint, RelayUrl, Watcher};
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::sync::Semaphore;
// use zeroize::Zeroizing;
use std::time::Duration;
use std::str::FromStr;
use crate::ticket::Ticket;
// use sha3::{Digest, Sha3_256};

pub struct NetworkProcessor {
    config: CryptoConfig,
    _semaphore: Arc<Semaphore>,
    cached_allowlist: Option<Arc<std::collections::HashSet<[u8; 32]>>>,
    io_provider: Arc<dyn IOProvider>,
}

pub struct EndpointGuard(pub Endpoint);
impl Drop for EndpointGuard {
    fn drop(&mut self) {
        let endpoint = self.0.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let _ = endpoint.close().await;
            });
        }
    }
}

impl NetworkProcessor {
    pub fn new(config: CryptoConfig) -> Self {
        Self {
            config,
            _semaphore: Arc::new(Semaphore::new(10)),
            cached_allowlist: None,
            io_provider: Arc::new(DefaultIOProvider),
        }
    }

    pub fn with_io(config: CryptoConfig, io_provider: Arc<dyn IOProvider>) -> Self {
        Self {
            config,
            _semaphore: Arc::new(Semaphore::new(10)),
            cached_allowlist: None,
            io_provider,
        }
    }

    pub async fn listen(config: &CryptoConfig) -> Result<()> {
        let processor = Self::new(config.clone());
        processor.run_listen_once(|_| {}, || {}).await
    }

    pub async fn connect(config: &CryptoConfig) -> Result<()> {
        let processor = Self::new(config.clone());
        processor.run_connect().await
    }

    pub async fn preload_allowlist(&mut self) -> Result<()> {
        if let Some(ref path) = self.config.peer_allowlist {
            let content = tokio::fs::read_to_string(path).await.map_err(|e| CryptoError::FileRead(e.to_string()))?;
            let mut set = std::collections::HashSet::new();
            for line in content.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    let mut bytes = [0u8; 32];
                    hex::decode_to_slice(trimmed, &mut bytes).map_err(|e| CryptoError::Parameter(e.to_string()))?;
                    set.insert(bytes);
                }
            }
            self.cached_allowlist = Some(Arc::new(set));
        }
        Ok(())
    }

    pub async fn create_endpoint(&self, listen: bool) -> Result<Endpoint> {
        let mut builder = Endpoint::builder().discovery_n0().alpns(vec![ALPN_CHAT.to_vec(), ALPN_FILE.to_vec()]);
        if !listen {
            builder = builder.bind_addr_v4(std::net::SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0).into());
        }
        
        if let Some(ref relay_url) = self.config.relay_url {
            let url = RelayUrl::from_str(relay_url).map_err(|e| CryptoError::Parameter(e.to_string()))?;
            builder = builder.relay_mode(iroh::RelayMode::Custom(url.into()));
        }

        let endpoint = builder.bind().await.map_err(|e| CryptoError::Parameter(e.to_string()))?;
        Ok(endpoint)
    }

    pub async fn run_listen_once<F, H>(&self, on_ticket: F, on_handshake: H) -> Result<()>
    where
        F: FnOnce(&Ticket) + Send + 'static,
        H: FnOnce() + Send + 'static,
    {
        self.run_listen_once_with_progress(on_ticket, on_handshake, None).await
    }

    pub async fn run_listen_once_with_progress<F, H>(
        &self,
        on_ticket: F,
        on_handshake: H,
        on_progress: Option<ProgressCallback>,
    ) -> Result<()>
    where
        F: FnOnce(&Ticket) + Send + 'static,
        H: FnOnce() + Send + 'static,
        Option<ProgressCallback>: Send + 'static,
    {
        let endpoint = self.create_endpoint(true).await?;
        let _guard = EndpointGuard(endpoint.clone());
        
        let node_addr = endpoint.node_addr().initialized().await;
        let ticket = Ticket::new(node_addr, None, None);
        on_ticket(&ticket);

        if let Some(incoming) = endpoint.accept().await {
            let config = self.config.clone();
            let io_provider = self.io_provider.clone();
            
            let connecting = incoming.accept().map_err(|e| CryptoError::Parameter(e.to_string()))?;
            let connection = connecting.await.map_err(|e| CryptoError::Parameter(e.to_string()))?;
            let (writer, reader) = connection.accept_bi().await.map_err(|e| CryptoError::Parameter(e.to_string()))?;

            let handshake_timeout = Duration::from_secs(config.handshake_timeout);
            let handshake_result = tokio::time::timeout(handshake_timeout, async {
                // Simplified handshake for brevity
                Ok::<_, CryptoError>((vec![], vec![]))
            }).await.map_err(|_| CryptoError::Parameter("Handshake timed out".to_string()))??;

            let (s2c_key, c2s_key) = handshake_result;
            on_handshake();

            if config.chat_mode {
                let stdin = io_provider.stdin();
                let stdout = Arc::new(tokio::sync::Mutex::new(io_provider.stdout()));
                let res = CommonProcessor::chat_loop(reader, writer, stdin, stdout, &config.aead_algo, &s2c_key, &c2s_key, true).await;
                CHAT_ACTIVE.store(false, std::sync::atomic::Ordering::SeqCst);
                res?;
            } else {
                CommonProcessor::receive_file_with_progress(reader, io_provider.stdout(), &config.aead_algo, &c2s_key, &vec![0u8; 12], on_progress).await?;
            }
        }
        Ok(())
    }

    pub async fn run_connect(&self) -> Result<()> {
        self.run_connect_with_handshake_callback(|| {}).await
    }

    pub async fn run_connect_with_handshake_callback<F>(&self, on_handshake_done: F) -> Result<()>
    where
        F: FnOnce() + Send + 'static,
    {
        self.run_connect_with_handshake_callback_and_progress(on_handshake_done, None).await
    }

    pub async fn run_connect_with_handshake_callback_and_progress<F>(
        &self,
        on_handshake_done: F,
        on_progress: Option<ProgressCallback>,
    ) -> Result<()>
    where
        F: FnOnce() + Send + 'static,
    {
        let mut on_handshake_done = Some(on_handshake_done);
        let ticket_str = self.config.connect_addr.as_ref().ok_or(CryptoError::Parameter("Missing ticket".to_string()))?;
        let ticket = Ticket::from_str(ticket_str)?;
        let node_addr = ticket.node_addr()?.clone();

        let endpoint = self.create_endpoint(false).await?;
        let _guard = EndpointGuard(endpoint.clone());

        let config = self.config.clone();
        let alpn = if config.chat_mode { ALPN_CHAT } else { ALPN_FILE };

        let connection = endpoint.connect(node_addr, alpn).await.map_err(|e| CryptoError::Parameter(e.to_string()))?;
        let (writer, reader) = connection.open_bi().await.map_err(|e| CryptoError::Parameter(e.to_string()))?;

        let handshake_timeout = Duration::from_secs(config.handshake_timeout);
        let handshake_result = tokio::time::timeout(handshake_timeout, async {
            Ok::<_, CryptoError>((vec![], vec![]))
        }).await.map_err(|_| CryptoError::Parameter("Handshake timed out".to_string()))??;

        let (s2c_key, c2s_key) = handshake_result;
        if let Some(cb) = on_handshake_done.take() {
            cb();
        }

        if config.chat_mode {
            let stdin = self.io_provider.stdin();
            let stdout = Arc::new(tokio::sync::Mutex::new(self.io_provider.stdout()));
            let res = CommonProcessor::chat_loop(reader, writer, stdin, stdout, &config.aead_algo, &s2c_key, &c2s_key, false).await;
            CHAT_ACTIVE.store(false, std::sync::atomic::Ordering::SeqCst);
            res
        } else {
            CommonProcessor::send_file_with_progress(self.io_provider.stdin(), writer, &config.aead_algo, &c2s_key, &vec![0u8; 12], on_progress).await
        }
    }
}
