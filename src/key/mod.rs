/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

pub mod tpm;

use crate::error::Result;
use std::sync::Arc;

pub trait KeyProvider: Send + Sync {
    /// Wrap raw key bytes using the provider's hardware protection (e.g. TPM).
    fn wrap_raw(&self, _data: &[u8], _passphrase: Option<&str>) -> Result<String> {
        Err(crate::error::CryptoError::ProviderNotAvailable)
    }

    /// Unwrap a provider-specific blob into raw key bytes.
    fn unwrap_raw(&self, _wrapped_pem: &str, _passphrase: Option<&str>) -> Result<Vec<u8>> {
        Err(crate::error::CryptoError::ProviderNotAvailable)
    }

    /// Check if the hardware provider is available in the current environment.
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
    let tpm = self::tpm::TpmKeyProvider::new();
    if tpm.is_available() {
        Arc::new(tpm)
    } else {
        Arc::new(DefaultKeyProvider::new())
    }
}
