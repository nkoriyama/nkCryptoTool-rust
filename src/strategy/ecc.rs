/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

use crate::backend::{self, HashBackend};
use crate::error::{CryptoError, Result};
use crate::key::SharedKeyProvider;
use crate::strategy::streaming_aead::{
    self as v3, V3_DEFAULT_CHUNK_SIZE, V3_NONCE_PREFIX_LEN, V3_SESSION_ID_LEN,
};
use crate::strategy::{CryptoStrategy, StrategyType};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EccStrategy {
    #[zeroize(skip)]
    key_provider: Option<SharedKeyProvider>,
    #[zeroize(skip)]
    curve_name: String,
    #[zeroize(skip)]
    digest_algo: String,
    #[zeroize(skip)]
    aead_algo: String,

    #[zeroize(skip)]
    hash_ctx: Option<backend::Hash>,

    // Key states
    encryption_key: Zeroizing<Vec<u8>>,
    iv: Vec<u8>,
    salt: Vec<u8>,
    shared_secret: Zeroizing<Vec<u8>>,
    ephemeral_pubkey: Vec<u8>,

    // Recipient P-256 public key as SubjectPublicKeyInfo DER, injected in memory
    // from a verified NKKB KeyBundle. When `Some`, encryption uses it directly
    // and skips reading a recipient pubkey file. A public key is not secret, so
    // it is exempt from zeroization.
    #[zeroize(skip)]
    recipient_pub_der: Option<Vec<u8>>,

    // The user's own P-256 private key as passphrase-encrypted PKCS#8 PEM
    // text, injected in memory from the keyring my-identities table
    // (auto-match). When `Some`, decryption uses it and never reads a
    // user-privkey file.
    user_privkey_pem: Option<Zeroizing<String>>,

    // Signing keys (stored as DER to be backend-agnostic)
    sign_key_der: Option<Zeroizing<Vec<u8>>>,
    verify_key_der: Option<Zeroizing<Vec<u8>>>,

    // ---- v3 chunked-AEAD state ----
    #[zeroize(skip)]
    chunk_size: u32,
    nonce_prefix: Zeroizing<Vec<u8>>,
    #[zeroize(skip)]
    file_session_id: Option<[u8; V3_SESSION_ID_LEN]>,
    #[zeroize(skip)]
    chunk_counter: u32,
}

impl EccStrategy {
    pub fn new() -> Self {
        Self {
            key_provider: None,
            curve_name: "prime256v1".to_string(),
            digest_algo: "SHA3-512".to_string(),
            aead_algo: "AES-256-GCM".to_string(),
            hash_ctx: None,
            encryption_key: Zeroizing::new(Vec::new()),
            iv: Vec::new(),
            salt: Vec::new(),
            shared_secret: Zeroizing::new(Vec::new()),
            ephemeral_pubkey: Vec::new(),
            recipient_pub_der: None,
            user_privkey_pem: None,
            sign_key_der: None,
            verify_key_der: None,
            chunk_size: V3_DEFAULT_CHUNK_SIZE,
            nonce_prefix: Zeroizing::new(Vec::new()),
            file_session_id: None,
            chunk_counter: 0,
        }
    }

    pub fn take_shared_secret(&mut self) -> Zeroizing<Vec<u8>> {
        std::mem::take(&mut self.shared_secret)
    }

    pub fn prepare_shared_secret_encryption(
        &mut self,
        key_paths: &HashMap<String, String>,
    ) -> Result<()> {
        if let Some(algo) = key_paths.get("digest-algo") {
            self.digest_algo = algo.clone();
        }
        if let Some(algo) = key_paths.get("aead-algo") {
            self.aead_algo = algo.clone();
        }

        // Prefer a KeyBundle-injected P-256 SPKI DER (already authenticated in
        // memory): ECDH directly, no file read. Fall back to the recipient
        // pubkey file only when no bundle key was injected.
        // clone() (not take()): keep the injected key so the strategy stays
        // reusable, matching the idempotent file-path branch.
        let recipient_pub_der: Vec<u8> = match self.recipient_pub_der.clone() {
            Some(der) => der,
            None => {
                let pubkey_path = key_paths
                    .get("recipient-pubkey")
                    .or_else(|| key_paths.get("recipient-ecdh-pubkey"))
                    .ok_or(CryptoError::PublicKeyLoad(
                        "Missing recipient public key".to_string(),
                    ))?;
                let pubkey_pem = fs::read_to_string(pubkey_path)?;
                crate::utils::unwrap_from_pem(&pubkey_pem, "PUBLIC KEY")?.to_vec()
            }
        };

        let (ephem_priv, ephem_pub) = backend::generate_ecc_key_pair(&self.curve_name)?;
        self.shared_secret = backend::ecc_dh(&ephem_priv, &recipient_pub_der, None)?;
        self.ephemeral_pubkey = ephem_pub;

        self.salt = vec![0u8; 16];
        self.iv = vec![0u8; 12];

        #[cfg(feature = "backend-openssl")]
        openssl::rand::rand_bytes(&mut self.salt)
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        #[cfg(feature = "backend-openssl")]
        openssl::rand::rand_bytes(&mut self.iv).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;

        #[cfg(feature = "backend-rustcrypto")]
        {
            use rand_core::{OsRng, RngCore};
            OsRng.fill_bytes(&mut self.salt);
            OsRng.fill_bytes(&mut self.iv);
        }
        Ok(())
    }

    pub fn prepare_shared_secret_decryption(
        &mut self,
        key_paths: &HashMap<String, String>,
        passphrase: &mut Option<Zeroizing<String>>,
    ) -> Result<()> {
        // Prefer a keyring-injected encrypted-PKCS#8 PEM (auto-match): no file
        // read. clone() (not take()) keeps the strategy reusable, matching the
        // recipient_pub_der convention.
        let pem_str: Zeroizing<String> = match self.user_privkey_pem.clone() {
            Some(pem) => pem,
            None => {
                let privkey_path = key_paths
                    .get("user-privkey")
                    .or_else(|| key_paths.get("recipient-ecdh-privkey"))
                    .ok_or(CryptoError::PrivateKeyLoad(
                        "Missing private key path".to_string(),
                    ))?;
                let priv_bytes = Zeroizing::new(fs::read(privkey_path)?);
                Zeroizing::new(
                    std::str::from_utf8(&priv_bytes)
                        .map_err(|_| CryptoError::Parameter("Invalid UTF-8 in key".to_string()))?
                        .to_string(),
                )
            }
        };

        let priv_key_der = if pem_str.contains("-----BEGIN TPM WRAPPED BLOB-----") {
            let provider = self
                .key_provider
                .as_ref()
                .ok_or(CryptoError::ProviderNotAvailable)?;
            provider.unwrap_raw(&pem_str, passphrase.as_deref().map(|x| x.as_str()))?
        } else {
            let pass = crate::utils::get_passphrase_if_needed(
                &pem_str,
                passphrase.as_deref().map(|x| x.as_str()),
            )?;
            if let Some(p) = pass {
                *passphrase = Some(p);
            }
            crate::utils::unwrap_from_pem(&pem_str, "PRIVATE KEY")?
        };

        // Decrypt if the key is a passphrase-encrypted PKCS#8 (no-op for a
        // plaintext key), so the backend always receives raw PKCS#8.
        let priv_key_der = crate::utils::extract_raw_private_key(
            &priv_key_der,
            passphrase.as_deref().map(|x| x.as_str()),
        )?;

        // priv_key_der is already decrypted above, so no passphrase is needed.
        self.shared_secret = backend::ecc_dh(&priv_key_der, &self.ephemeral_pubkey, None)?;
        Ok(())
    }
}

impl CryptoStrategy for EccStrategy {
    fn get_strategy_type(&self) -> StrategyType {
        StrategyType::ECC
    }

    fn set_key_provider(&mut self, provider: SharedKeyProvider) {
        self.key_provider = Some(provider);
    }

    fn generate_encryption_key_pair(
        &self,
        key_paths: &HashMap<String, String>,
        passphrase: Option<&str>,
        force: bool,
    ) -> Result<()> {
        let pub_path = key_paths
            .get("public-key")
            .or_else(|| key_paths.get("signing-public-key"))
            .ok_or(CryptoError::Parameter(
                "Missing public key path".to_string(),
            ))?;
        let priv_path = key_paths
            .get("private-key")
            .or_else(|| key_paths.get("signing-private-key"))
            .ok_or(CryptoError::Parameter(
                "Missing private key path".to_string(),
            ))?;

        let use_tpm = key_paths
            .get("use-tpm")
            .map(|s| s == "true")
            .unwrap_or(false);

        let (priv_der, pub_der) = backend::generate_ecc_key_pair(&self.curve_name)?;

        if use_tpm {
            let provider = self
                .key_provider
                .as_ref()
                .ok_or(CryptoError::ProviderNotAvailable)?;
            let wrapped = provider.wrap_raw(&priv_der, passphrase)?;
            crate::utils::secure_write(priv_path, wrapped, force)?;
        } else {
            // When a passphrase is supplied, encrypt the PKCS#8 key (PBES2)
            // instead of writing it in the clear. `priv_der` is already PKCS#8.
            // Previously the passphrase was silently ignored and the ECC private
            // key was stored unencrypted — a false sense of protection.
            let priv_pem = match passphrase.filter(|p| !p.is_empty()) {
                Some(pass) => {
                    let enc = Zeroizing::new(crate::utils::encrypt_pkcs8_der(&priv_der, pass)?);
                    crate::utils::wrap_to_pem_zeroizing(&enc, "PRIVATE KEY")
                }
                // No extra plaintext copy: wrap the already-`Zeroizing` der.
                None => crate::utils::wrap_to_pem_zeroizing(&priv_der, "PRIVATE KEY"),
            };
            crate::utils::secure_write(priv_path, priv_pem.as_bytes(), force)?;
        }

        let pub_pem = crate::utils::wrap_to_pem_zeroizing(&pub_der, "PUBLIC KEY");
        crate::utils::secure_write(pub_path, pub_pem.as_bytes(), force)?;
        Ok(())
    }

    fn generate_signing_key_pair(
        &self,
        key_paths: &HashMap<String, String>,
        passphrase: Option<&str>,
        force: bool,
    ) -> Result<()> {
        self.generate_encryption_key_pair(key_paths, passphrase, force)
    }

    fn regenerate_public_key(
        &self,
        priv_path: &Path,
        pub_path: &Path,
        passphrase: &mut Option<Zeroizing<String>>,
        force: bool,
    ) -> Result<()> {
        let priv_bytes = Zeroizing::new(fs::read(priv_path)?);
        let pem_str = Zeroizing::new(
            std::str::from_utf8(&priv_bytes)
                .map_err(|_| CryptoError::Parameter("Invalid UTF-8 in key".to_string()))?
                .to_string(),
        );

        let priv_key_der = if pem_str.contains("-----BEGIN TPM WRAPPED BLOB-----") {
            let provider = self
                .key_provider
                .as_ref()
                .ok_or(CryptoError::ProviderNotAvailable)?;
            provider.unwrap_raw(&pem_str, passphrase.as_deref().map(|x| x.as_str()))?
        } else {
            let pass = crate::utils::get_passphrase_if_needed(
                &pem_str,
                passphrase.as_deref().map(|x| x.as_str()),
            )?;
            if let Some(p) = pass {
                *passphrase = Some(p);
            }
            crate::utils::unwrap_from_pem(&pem_str, "PRIVATE KEY")?
        };

        // Decrypt if the key is a passphrase-encrypted PKCS#8 (no-op for a
        // plaintext key), so the backend always receives raw PKCS#8.
        let priv_key_der = crate::utils::extract_raw_private_key(
            &priv_key_der,
            passphrase.as_deref().map(|x| x.as_str()),
        )?;

        // priv_key_der is already decrypted above, so no passphrase is needed.
        let pub_der = backend::extract_public_key(&priv_key_der, None)?;
        crate::utils::secure_write(pub_path, crate::utils::wrap_to_pem(&pub_der, "PUBLIC KEY"), force)?;
        Ok(())
    }

    fn prepare_encryption(&mut self, key_paths: &HashMap<String, String>) -> Result<()> {
        self.prepare_shared_secret_encryption(key_paths)?;
        self.encryption_key =
            v3::hkdf_expand(&self.shared_secret, &self.salt, v3::V3_INFO_ENC_KEY, 32)?;
        self.nonce_prefix = v3::hkdf_expand(
            &self.shared_secret,
            &self.salt,
            v3::V3_INFO_NONCE_PREFIX,
            V3_NONCE_PREFIX_LEN,
        )?;
        self.chunk_counter = 0;
        Ok(())
    }

    fn prepare_decryption(
        &mut self,
        key_paths: &HashMap<String, String>,
        passphrase: &mut Option<Zeroizing<String>>,
    ) -> Result<()> {
        self.prepare_shared_secret_decryption(key_paths, passphrase)?;
        self.encryption_key =
            v3::hkdf_expand(&self.shared_secret, &self.salt, v3::V3_INFO_ENC_KEY, 32)?;
        self.nonce_prefix = v3::hkdf_expand(
            &self.shared_secret,
            &self.salt,
            v3::V3_INFO_NONCE_PREFIX,
            V3_NONCE_PREFIX_LEN,
        )?;
        self.chunk_counter = 0;
        Ok(())
    }

    fn prepare_signing(
        &mut self,
        priv_key_path: &Path,
        passphrase: &mut Option<Zeroizing<String>>,
        digest_algo: &str,
    ) -> Result<()> {
        let priv_bytes = Zeroizing::new(fs::read(priv_key_path)?);
        let pem_str = Zeroizing::new(
            std::str::from_utf8(&priv_bytes)
                .map_err(|_| CryptoError::Parameter("Invalid UTF-8 in key".to_string()))?
                .to_string(),
        );

        let priv_key_der = if pem_str.contains("-----BEGIN TPM WRAPPED BLOB-----") {
            let provider = self
                .key_provider
                .as_ref()
                .ok_or(CryptoError::ProviderNotAvailable)?;
            provider.unwrap_raw(&pem_str, passphrase.as_deref().map(|x| x.as_str()))?
        } else {
            let pass = crate::utils::get_passphrase_if_needed(
                &pem_str,
                passphrase.as_deref().map(|x| x.as_str()),
            )?;
            if let Some(p) = pass {
                *passphrase = Some(p);
            }
            crate::utils::unwrap_from_pem(&pem_str, "PRIVATE KEY")?
        };

        // Decrypt if the key is a passphrase-encrypted PKCS#8 (no-op for a
        // plaintext key), so the signer always receives raw PKCS#8.
        let priv_key_der = crate::utils::extract_raw_private_key(
            &priv_key_der,
            passphrase.as_deref().map(|x| x.as_str()),
        )?;

        // priv_key_der is already decrypted above, so no passphrase is needed.
        let mut ctx = backend::new_hash(digest_algo)?;
        ctx.init_sign(&priv_key_der, None)?;

        self.sign_key_der = Some(priv_key_der);
        self.hash_ctx = Some(ctx);
        self.digest_algo = digest_algo.to_string();
        Ok(())
    }

    fn prepare_verification(&mut self, pub_key_path: &Path, digest_algo: &str) -> Result<()> {
        let pub_bytes = fs::read(pub_key_path)?;
        let pub_der =
            crate::utils::unwrap_from_pem(&String::from_utf8_lossy(&pub_bytes), "PUBLIC KEY")?;

        let mut ctx = backend::new_hash(digest_algo)?;
        ctx.init_verify(&pub_der)?;

        self.verify_key_der = Some(pub_der);
        self.hash_ctx = Some(ctx);
        self.digest_algo = digest_algo.to_string();
        Ok(())
    }

    fn update_hash(&mut self, data: &[u8]) -> Result<()> {
        let ctx = self.hash_ctx.as_mut().ok_or(CryptoError::Parameter(
            "Hash context not initialized".to_string(),
        ))?;
        ctx.update(data)
    }

    fn sign_hash(&mut self) -> Result<Vec<u8>> {
        let ctx = self.hash_ctx.as_mut().ok_or(CryptoError::Parameter(
            "Hash context not initialized".to_string(),
        ))?;
        let key_der = self
            .sign_key_der
            .as_ref()
            .ok_or(CryptoError::Parameter("Sign key missing".to_string()))?;
        ctx.finalize_sign(key_der)
    }

    fn verify_hash(&mut self, signature: &[u8]) -> Result<bool> {
        let ctx = self.hash_ctx.as_mut().ok_or(CryptoError::Parameter(
            "Hash context not initialized".to_string(),
        ))?;
        let key_der = self
            .verify_key_der
            .as_ref()
            .ok_or(CryptoError::Parameter("Verify key missing".to_string()))?;
        ctx.finalize_verify(key_der, signature)
    }

    fn serialize_signature_header(&self) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(b"NKCS");
        header.extend_from_slice(&1u16.to_le_bytes());
        header.push(self.get_strategy_type() as u8);

        header.extend_from_slice(&(self.curve_name.len() as u32).to_le_bytes());
        header.extend_from_slice(self.curve_name.as_bytes());

        header.extend_from_slice(&(self.digest_algo.len() as u32).to_le_bytes());
        header.extend_from_slice(self.digest_algo.as_bytes());

        header
    }

    fn deserialize_signature_header(&mut self, data: &[u8]) -> Result<usize> {
        if data.len() < 7 {
            return Err(CryptoError::FileRead(
                "Signature header too short".to_string(),
            ));
        }
        if &data[0..4] != b"NKCS" {
            return Err(CryptoError::FileRead("Invalid signature magic".to_string()));
        }

        let mut pos = 4;
        let version = u16::from_le_bytes(
            data[pos..pos + 2]
                .try_into()
                .map_err(|_| CryptoError::FileRead("Invalid version".to_string()))?,
        );
        pos += 2;
        if version != 1 {
            return Err(CryptoError::FileRead(
                "Unsupported signature version".to_string(),
            ));
        }

        let strategy_type = data[pos];
        pos += 1;
        if strategy_type != self.get_strategy_type() as u8 {
            return Err(CryptoError::FileRead(
                "Signature strategy mismatch".to_string(),
            ));
        }

        let read_string = |p: &mut usize| -> Result<String> {
            if data.len() < *p + 4 {
                return Err(CryptoError::FileRead(
                    "Incomplete string header".to_string(),
                ));
            }
            let len = u32::from_le_bytes(
                data[*p..*p + 4]
                    .try_into()
                    .map_err(|_| CryptoError::FileRead("Invalid length".to_string()))?,
            ) as usize;
            *p += 4;
            if data.len() < *p + len {
                return Err(CryptoError::FileRead("Incomplete string data".to_string()));
            }
            let s = String::from_utf8_lossy(&data[*p..*p + len]).to_string();
            *p += len;
            Ok(s)
        };

        self.curve_name = read_string(&mut pos)?;
        self.digest_algo = read_string(&mut pos)?;
        Ok(pos)
    }

    fn get_metadata(&self, _magic: &str) -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("Strategy".to_string(), "ECC".to_string());
        m.insert("Curve-Name".to_string(), self.curve_name.clone());
        m.insert("Digest-Algorithm".to_string(), self.digest_algo.clone());
        m
    }

    fn get_header_size(&self) -> usize {
        let size = 4 + 2
            + 1
            + 4
            + self.curve_name.len()
            + 4
            + self.digest_algo.len()
            + 4
            + self.ephemeral_pubkey.len()
            + 4
            + self.salt.len()
            + 4
            + self.iv.len()
            + 4
            + self.aead_algo.len()
            + 4; // chunk_size u32
        size
    }

    fn serialize_header(&self) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(b"NKCT");
        let version: u16 = 3;
        header.extend_from_slice(&version.to_le_bytes());
        header.push(self.get_strategy_type() as u8);

        header.extend_from_slice(&(self.curve_name.len() as u32).to_le_bytes());
        header.extend_from_slice(self.curve_name.as_bytes());

        header.extend_from_slice(&(self.digest_algo.len() as u32).to_le_bytes());
        header.extend_from_slice(self.digest_algo.as_bytes());

        header.extend_from_slice(&(self.ephemeral_pubkey.len() as u32).to_le_bytes());
        header.extend_from_slice(&self.ephemeral_pubkey);

        header.extend_from_slice(&(self.salt.len() as u32).to_le_bytes());
        header.extend_from_slice(&self.salt);

        header.extend_from_slice(&(self.iv.len() as u32).to_le_bytes());
        header.extend_from_slice(&self.iv);

        header.extend_from_slice(&(self.aead_algo.len() as u32).to_le_bytes());
        header.extend_from_slice(self.aead_algo.as_bytes());

        header.extend_from_slice(&self.chunk_size.to_le_bytes());

        header
    }

    fn deserialize_header(&mut self, data: &[u8]) -> Result<usize> {
        if data.len() < 7 {
            return Err(CryptoError::FileRead("Header too short".to_string()));
        }
        if &data[0..4] != b"NKCT" {
            return Err(CryptoError::FileRead("Invalid magic".to_string()));
        }

        let mut pos = 4;
        let version = u16::from_le_bytes(
            data[pos..pos + 2]
                .try_into()
                .map_err(|_| CryptoError::FileRead("Invalid version".to_string()))?,
        );
        pos += 2;
        if version != 3 {
            return Err(CryptoError::FileRead(
                "legacy v1/v2 file format is no longer supported; decrypt it with an older nkCryptoTool release and re-encrypt".into(),
            ));
        }

        let strategy_type = data[pos];
        pos += 1;
        if strategy_type != self.get_strategy_type() as u8 {
            return Err(CryptoError::FileRead("Strategy mismatch".to_string()));
        }

        let read_string = |p: &mut usize| -> Result<String> {
            if data.len() < *p + 4 {
                return Err(CryptoError::FileRead(
                    "Incomplete string header".to_string(),
                ));
            }
            let len = u32::from_le_bytes(
                data[*p..*p + 4]
                    .try_into()
                    .map_err(|_| CryptoError::FileRead("Invalid length".to_string()))?,
            ) as usize;
            *p += 4;
            if data.len() < *p + len {
                return Err(CryptoError::FileRead("Incomplete string data".to_string()));
            }
            let s = String::from_utf8_lossy(&data[*p..*p + len]).to_string();
            *p += len;
            Ok(s)
        };

        let read_vec = |p: &mut usize| -> Result<Vec<u8>> {
            if data.len() < *p + 4 {
                return Err(CryptoError::FileRead("Incomplete vec header".to_string()));
            }
            let len = u32::from_le_bytes(
                data[*p..*p + 4]
                    .try_into()
                    .map_err(|_| CryptoError::FileRead("Invalid length".to_string()))?,
            ) as usize;
            *p += 4;
            if data.len() < *p + len {
                return Err(CryptoError::FileRead("Incomplete string data".to_string()));
            }
            let v = data[*p..*p + len].to_vec();
            *p += len;
            Ok(v)
        };

        self.curve_name = read_string(&mut pos)?;
        self.digest_algo = read_string(&mut pos)?;
        self.ephemeral_pubkey = read_vec(&mut pos)?;
        self.salt = read_vec(&mut pos)?;
        self.iv = read_vec(&mut pos)?;

        // v3 always carries the AEAD algorithm string.
        self.aead_algo = read_string(&mut pos)?;

        // v3 trailer: chunk_size (u32).
        if data.len() < pos + 4 {
            return Err(CryptoError::FileRead(
                "v3 header missing chunk_size".to_string(),
            ));
        }
        self.chunk_size = u32::from_le_bytes(
            data[pos..pos + 4]
                .try_into()
                .map_err(|_| CryptoError::FileRead("Invalid chunk_size".to_string()))?,
        );
        pos += 4;
        if self.chunk_size == 0 {
            return Err(CryptoError::FileRead(
                "v3 chunk_size must be > 0".to_string(),
            ));
        }

        Ok(pos)
    }

    fn get_tag_size(&self) -> usize {
        16
    }

    fn get_shared_secret(&self) -> Zeroizing<Vec<u8>> {
        self.shared_secret.clone()
    }

    fn set_recipient_hybrid_key(&mut self, p256_spki_der: Vec<u8>) {
        self.recipient_pub_der = Some(p256_spki_der);
    }

    fn set_user_enc_privkey_pem(&mut self, pem: Zeroizing<String>) {
        self.user_privkey_pem = Some(pem);
    }

    fn get_salt(&self) -> Vec<u8> {
        self.salt.clone()
    }

    fn get_iv(&self) -> Vec<u8> {
        self.iv.clone()
    }

    fn chunk_size(&self) -> u32 {
        self.chunk_size
    }

    fn set_chunk_size(&mut self, size: u32) {
        if size > 0 {
            self.chunk_size = size;
        }
    }

    fn file_session_id(&self) -> Option<[u8; V3_SESSION_ID_LEN]> {
        self.file_session_id
    }

    fn set_file_session_id(&mut self, sid: [u8; V3_SESSION_ID_LEN]) {
        self.file_session_id = Some(sid);
    }

    fn nonce_prefix(&self) -> Option<[u8; V3_NONCE_PREFIX_LEN]> {
        if self.nonce_prefix.len() == V3_NONCE_PREFIX_LEN {
            let mut out = [0u8; V3_NONCE_PREFIX_LEN];
            out.copy_from_slice(&self.nonce_prefix);
            Some(out)
        } else {
            None
        }
    }

    fn encrypt_chunk_v3(&mut self, plaintext: &[u8], is_final: bool) -> Result<Vec<u8>> {
        encrypt_chunk_inner(
            &self.aead_algo,
            &self.encryption_key,
            &self.nonce_prefix,
            self.file_session_id.as_ref(),
            &mut self.chunk_counter,
            plaintext,
            is_final,
        )
    }

    fn decrypt_chunk_v3(
        &mut self,
        ciphertext_and_tag: &[u8],
        is_final: bool,
    ) -> Result<Zeroizing<Vec<u8>>> {
        decrypt_chunk_inner(
            &self.aead_algo,
            &self.encryption_key,
            &self.nonce_prefix,
            self.file_session_id.as_ref(),
            &mut self.chunk_counter,
            ciphertext_and_tag,
            is_final,
        )
    }

    fn decrypt_chunk_v3_into(
        &mut self,
        ciphertext_and_tag: &[u8],
        is_final: bool,
        out: &mut Vec<u8>,
    ) -> Result<()> {
        v3::decrypt_chunk_v3_into(
            &self.aead_algo,
            &self.encryption_key,
            &self.nonce_prefix,
            self.file_session_id.as_ref(),
            &mut self.chunk_counter,
            ciphertext_and_tag,
            is_final,
            out,
        )
    }

    fn reset_chunk_counter(&mut self) {
        self.chunk_counter = 0;
    }
}

fn encrypt_chunk_inner(
    aead_algo: &str,
    key: &[u8],
    nonce_prefix: &[u8],
    sid: Option<&[u8; V3_SESSION_ID_LEN]>,
    counter: &mut u32,
    plaintext: &[u8],
    is_final: bool,
) -> Result<Vec<u8>> {
    if nonce_prefix.len() != V3_NONCE_PREFIX_LEN {
        return Err(CryptoError::Parameter(
            "v3 nonce prefix not initialized".to_string(),
        ));
    }
    let sid = sid.ok_or(CryptoError::Parameter(
        "v3 file session id not set".to_string(),
    ))?;
    let nonce = v3::build_nonce(nonce_prefix, *counter);
    let flags = if is_final {
        v3::V3_FLAG_FINAL
    } else {
        v3::V3_FLAG_INTERMEDIATE
    };
    let aad = v3::build_aad(sid, *counter, flags);
    let out = v3::aead_encrypt_chunk(aead_algo, key, &nonce, &aad, plaintext)?;
    *counter = counter.checked_add(1).ok_or(CryptoError::CounterOverflow)?;
    Ok(out)
}

fn decrypt_chunk_inner(
    aead_algo: &str,
    key: &[u8],
    nonce_prefix: &[u8],
    sid: Option<&[u8; V3_SESSION_ID_LEN]>,
    counter: &mut u32,
    ciphertext_and_tag: &[u8],
    is_final: bool,
) -> Result<Zeroizing<Vec<u8>>> {
    if nonce_prefix.len() != V3_NONCE_PREFIX_LEN {
        return Err(CryptoError::Parameter(
            "v3 nonce prefix not initialized".to_string(),
        ));
    }
    let sid = sid.ok_or(CryptoError::Parameter(
        "v3 file session id not set".to_string(),
    ))?;
    let nonce = v3::build_nonce(nonce_prefix, *counter);
    let flags = if is_final {
        v3::V3_FLAG_FINAL
    } else {
        v3::V3_FLAG_INTERMEDIATE
    };
    let aad = v3::build_aad(sid, *counter, flags);
    let pt = v3::aead_decrypt_chunk(aead_algo, key, &nonce, &aad, ciphertext_and_tag)?;
    *counter = counter.checked_add(1).ok_or(CryptoError::CounterOverflow)?;
    Ok(pt)
}
