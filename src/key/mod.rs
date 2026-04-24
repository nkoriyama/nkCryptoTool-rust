use crate::error::Result;
use openssl::pkey::{PKey, Private};
use std::sync::Arc;

pub trait KeyProvider: Send + Sync {
    fn wrap_key(&self, _pkey: &PKey<Private>, _passphrase: Option<&str>) -> Result<String> {
        Err(crate::error::CryptoError::ProviderNotAvailable)
    }
    fn unwrap_key(&self, _wrapped_pem: &str, _passphrase: Option<&str>) -> Result<PKey<Private>> {
        Err(crate::error::CryptoError::ProviderNotAvailable)
    }
    fn is_available(&self) -> bool { false }
}

pub type SharedKeyProvider = Arc<dyn KeyProvider>;

pub struct DefaultKeyProvider;

impl DefaultKeyProvider {
    pub fn new() -> Self {
        Self
    }
}

impl KeyProvider for DefaultKeyProvider {}
