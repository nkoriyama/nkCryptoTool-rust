pub mod tpm;

use crate::error::Result;
use openssl::pkey::{PKey, Private};
use std::sync::Arc;
use self::tpm::TpmKeyProvider;

pub trait KeyProvider: Send + Sync {
    fn wrap_key(&self, pkey: &PKey<Private>, passphrase: Option<&str>) -> Result<String> {
        let der = pkey.private_key_to_der().map_err(|e| crate::error::CryptoError::OpenSSL(e.to_string()))?;
        self.wrap_raw(&der, passphrase)
    }

    fn unwrap_key(&self, wrapped_pem: &str, passphrase: Option<&str>) -> Result<PKey<Private>> {
        let der = self.unwrap_raw(wrapped_pem, passphrase)?;
        PKey::private_key_from_der(&der).map_err(|e| crate::error::CryptoError::OpenSSL(e.to_string()))
    }

    fn wrap_raw(&self, _data: &[u8], _passphrase: Option<&str>) -> Result<String> {
        Err(crate::error::CryptoError::ProviderNotAvailable)
    }

    fn unwrap_raw(&self, _wrapped_pem: &str, _passphrase: Option<&str>) -> Result<Vec<u8>> {
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

pub fn create_best_provider() -> SharedKeyProvider {
    let tpm = TpmKeyProvider::new();
    if tpm.is_available() {
        Arc::new(tpm)
    } else {
        Arc::new(DefaultKeyProvider::new())
    }
}
