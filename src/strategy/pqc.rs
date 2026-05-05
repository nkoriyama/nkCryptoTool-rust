/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

use crate::backend::{self, Aead, AeadBackend};
use crate::error::{CryptoError, Result};
use crate::key::SharedKeyProvider;
use crate::strategy::{CryptoStrategy, StrategyType};
use rand_core::{OsRng, RngCore};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PqcStrategy {
    #[zeroize(skip)]
    key_provider: Option<SharedKeyProvider>,
    passphrase: Option<Zeroizing<String>>,
    encryption_key: Zeroizing<Vec<u8>>,
    kem_shared_secret: Zeroizing<Vec<u8>>,
    salt: Vec<u8>,
    iv: Vec<u8>,
    kem_algo: String,
    dsa_algo: String,
    digest_algo: String,
    aead_algo: String,
    kem_ciphertext: Zeroizing<Vec<u8>>,
    #[zeroize(skip)]
    aead_ctx: Option<Aead>,
    peer_public_key: Option<Zeroizing<Vec<u8>>>,

    // DSA specific
    dsa_privkey: Zeroizing<Vec<u8>>,
    sign_buffer: Zeroizing<Vec<u8>>,
    signature: Vec<u8>,
}

impl PqcStrategy {
    pub fn new() -> Self {
        Self {
            key_provider: None,
            passphrase: None,
            encryption_key: Zeroizing::new(Vec::new()),
            kem_shared_secret: Zeroizing::new(Vec::new()),
            salt: Vec::new(),
            iv: Vec::new(),
            kem_algo: "ML-KEM-768".to_string(),
            dsa_algo: "ML-DSA-65".to_string(),
            digest_algo: "SHA3-512".to_string(),
            aead_algo: "AES-256-GCM".to_string(),
            kem_ciphertext: Zeroizing::new(Vec::new()),
            aead_ctx: None,
            peer_public_key: None,
            dsa_privkey: Zeroizing::new(Vec::new()),
            sign_buffer: Zeroizing::new(Vec::new()),
            signature: Vec::new(),
        }
    }

    fn hkdf_derive(
        &self,
        secret: &[u8],
        out_len: usize,
        salt: &[u8],
        info: &str,
    ) -> Result<Zeroizing<Vec<u8>>> {
        backend::hkdf(secret, out_len, salt, info, "SHA3-256")
    }
    pub fn take_shared_secret(&mut self) -> Zeroizing<Vec<u8>> {
        std::mem::take(&mut self.kem_shared_secret)
    }

    pub fn prepare_shared_secret_encryption(
        &mut self,
        key_paths: &HashMap<String, String>,
    ) -> Result<()> {
        if let Some(algo) = key_paths.get("kem-algo") {
            self.kem_algo = algo.clone();
        }
        let pubkey_path = key_paths
            .get("recipient-pubkey")
            .or_else(|| key_paths.get("recipient-mlkem-pubkey"))
            .ok_or(CryptoError::PublicKeyLoad(
                "Missing recipient public key".to_string(),
            ))?;

        let pem = Zeroizing::new(fs::read_to_string(pubkey_path)?);
        let der = crate::utils::unwrap_from_pem(&pem, "PUBLIC KEY")?;
        let raw_pub = crate::utils::unwrap_pqc_pub_from_spki(&der, &self.kem_algo)?;

        let (ss_bytes, ct_bytes) = backend::pqc_encap(&self.kem_algo, &raw_pub)?;
        self.kem_shared_secret = ss_bytes;
        self.kem_ciphertext = Zeroizing::new(ct_bytes);

        self.salt = vec![0u8; 16];
        self.iv = vec![0u8; 12];
        OsRng.fill_bytes(&mut self.salt);
        OsRng.fill_bytes(&mut self.iv);
        Ok(())
    }

    pub fn prepare_shared_secret_decryption(
        &mut self,
        key_paths: &HashMap<String, String>,
        passphrase: &mut Option<Zeroizing<String>>,
    ) -> Result<()> {
        if let Some(algo) = key_paths.get("kem-algo") {
            self.kem_algo = algo.clone();
        }
        let privkey_path = key_paths
            .get("user-privkey")
            .or_else(|| key_paths.get("recipient-mlkem-privkey"))
            .ok_or(CryptoError::PrivateKeyLoad(
                "Missing private key path".to_string(),
            ))?;

        let priv_bytes = Zeroizing::new(fs::read(privkey_path)?);
        let pem_str = Zeroizing::new(
            std::str::from_utf8(&*priv_bytes)
                .map_err(|_| CryptoError::Parameter("Invalid UTF-8 in key".to_string()))?
                .to_string(),
        );

        let decrypted_der = if pem_str.contains("-----BEGIN TPM WRAPPED BLOB-----") {
            return Err(CryptoError::Parameter(
                "TPM not supported for PQC yet".to_string(),
            ));
        } else {
            let pass = crate::utils::get_passphrase_if_needed(
                &pem_str,
                passphrase.as_deref().map(|x| x.as_str()),
            )?;
            if let Some(p) = pass {
                *passphrase = Some(p);
            }
            let der = crate::utils::unwrap_from_pem(&pem_str, "PRIVATE KEY")?;
            crate::utils::extract_raw_private_key(&der, passphrase.as_deref().map(|x| x.as_str()))?
        };

        let raw_priv = crate::utils::unwrap_pqc_priv_from_pkcs8(&decrypted_der, &self.kem_algo)?;
        self.kem_shared_secret = backend::pqc_decap(
            &self.kem_algo,
            &raw_priv,
            &self.kem_ciphertext,
            passphrase.as_deref().map(|x| x.as_str()),
        )?;
        Ok(())
    }
}

impl CryptoStrategy for PqcStrategy {
    fn get_strategy_type(&self) -> StrategyType {
        StrategyType::PQC
    }

    fn set_key_provider(&mut self, provider: SharedKeyProvider) {
        self.key_provider = Some(provider);
    }

    fn generate_encryption_key_pair(
        &self,
        key_paths: &HashMap<String, String>,
        _passphrase: Option<&str>,
        force: bool,
    ) -> Result<()> {
        let kem_algo = key_paths
            .get("kem-algo")
            .map(|s| s.as_str())
            .unwrap_or("ML-KEM-768");
        let pub_path = key_paths.get("public-key").ok_or(CryptoError::Parameter(
            "Missing public key path".to_string(),
        ))?;
        let priv_path = key_paths.get("private-key").ok_or(CryptoError::Parameter(
            "Missing private key path".to_string(),
        ))?;

        let (sk_bytes, pk_bytes, _seed) = backend::pqc_keygen_kem(kem_algo)?;

        let spki = crate::utils::wrap_pqc_pub_to_spki(&pk_bytes, kem_algo)?;
        crate::utils::secure_write(
            pub_path,
            &*crate::utils::wrap_to_pem_zeroizing(&spki, "PUBLIC KEY"),
            force,
        )?;

        let pkcs8 = if let Some(pass) = _passphrase {
            crate::utils::wrap_pqc_priv_to_pkcs8_encrypted(&sk_bytes, kem_algo, pass)?
        } else {
            crate::utils::wrap_pqc_priv_to_pkcs8(&sk_bytes, kem_algo)?.to_vec()
        };
        crate::utils::secure_write(
            priv_path,
            &*crate::utils::wrap_to_pem_zeroizing(&pkcs8, "PRIVATE KEY"),
            force,
        )?;

        Ok(())
    }

    fn generate_signing_key_pair(
        &self,
        key_paths: &HashMap<String, String>,
        passphrase: Option<&str>,
        force: bool,
    ) -> Result<()> {
        let dsa_algo = key_paths
            .get("dsa-algo")
            .map(|s| s.as_str())
            .unwrap_or("ML-DSA-65");
        let pub_path = key_paths.get("public-key").ok_or(CryptoError::Parameter(
            "Missing public key path".to_string(),
        ))?;
        let priv_path = key_paths.get("private-key").ok_or(CryptoError::Parameter(
            "Missing private key path".to_string(),
        ))?;

        let (sk_bytes, pk_bytes, _seed) = backend::pqc_keygen_dsa(dsa_algo)?;

        let spki = crate::utils::wrap_pqc_pub_to_spki(&pk_bytes, dsa_algo)?;
        crate::utils::secure_write(
            pub_path,
            &*crate::utils::wrap_to_pem_zeroizing(&spki, "PUBLIC KEY"),
            force,
        )?;

        let pkcs8 = if let Some(pass) = passphrase {
            crate::utils::wrap_pqc_priv_to_pkcs8_encrypted(&sk_bytes, dsa_algo, pass)?
        } else {
            crate::utils::wrap_pqc_priv_to_pkcs8(&sk_bytes, dsa_algo)?.to_vec()
        };
        crate::utils::secure_write(
            priv_path,
            &*crate::utils::wrap_to_pem_zeroizing(&pkcs8, "PRIVATE KEY"),
            force,
        )?;

        Ok(())
    }

    fn prepare_encryption(&mut self, key_paths: &HashMap<String, String>) -> Result<()> {
        self.prepare_shared_secret_encryption(key_paths)?;
        self.encryption_key =
            self.hkdf_derive(&self.kem_shared_secret, 32, &self.salt, "pqc-encryption")?;
        let ctx = backend::new_encrypt("AES-256-GCM", &self.encryption_key, &self.iv)?;
        self.aead_ctx = Some(ctx);
        Ok(())
    }

    fn prepare_decryption(
        &mut self,
        key_paths: &HashMap<String, String>,
        passphrase: &mut Option<Zeroizing<String>>,
    ) -> Result<()> {
        self.prepare_shared_secret_decryption(key_paths, passphrase)?;
        self.encryption_key =
            self.hkdf_derive(&self.kem_shared_secret, 32, &self.salt, "pqc-encryption")?;
        let ctx = backend::new_decrypt("AES-256-GCM", &self.encryption_key, &self.iv)?;
        self.aead_ctx = Some(ctx);
        Ok(())
    }

    fn encrypt_transform(&mut self, data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let ctx = self
            .aead_ctx
            .as_mut()
            .ok_or(CryptoError::Parameter("AEAD not init".to_string()))?;
        let mut out = Zeroizing::new(vec![0u8; data.len()]);
        let n = ctx.update(data, &mut out)?;
        out.truncate(n);
        Ok(out)
    }

    fn decrypt_transform(&mut self, data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let ctx = self
            .aead_ctx
            .as_mut()
            .ok_or(CryptoError::Parameter("AEAD not init".to_string()))?;
        let mut out = Zeroizing::new(vec![0u8; data.len()]);
        let n = ctx.update(data, &mut out)?;
        out.truncate(n);
        Ok(out)
    }

    fn encrypt_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize> {
        let ctx = self
            .aead_ctx
            .as_mut()
            .ok_or(CryptoError::Parameter("AEAD not init".to_string()))?;
        ctx.update(input, output)
    }

    fn decrypt_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize> {
        let ctx = self
            .aead_ctx
            .as_mut()
            .ok_or(CryptoError::Parameter("AEAD not init".to_string()))?;
        ctx.update(input, output)
    }

    fn finalize_encryption(&mut self) -> Result<Vec<u8>> {
        let ctx = self
            .aead_ctx
            .as_mut()
            .ok_or(CryptoError::Parameter("AEAD not init".to_string()))?;
        let mut tag = vec![0u8; 16];
        ctx.finalize(&mut [])?;
        ctx.get_tag(&mut tag)?;
        Ok(tag)
    }

    fn finalize_decryption(&mut self, tag: &[u8]) -> Result<()> {
        let ctx = self
            .aead_ctx
            .as_mut()
            .ok_or(CryptoError::Parameter("AEAD not init".to_string()))?;
        ctx.set_tag(tag)?;
        ctx.finalize(&mut [])?;
        Ok(())
    }

    fn prepare_signing(
        &mut self,
        priv_key_path: &Path,
        passphrase_opt: &mut Option<Zeroizing<String>>,
        _digest_algo: &str,
    ) -> Result<()> {
        let priv_bytes = Zeroizing::new(fs::read(priv_key_path)?);
        let pem_str = Zeroizing::new(
            std::str::from_utf8(&*priv_bytes)
                .map_err(|_| CryptoError::Parameter("Invalid UTF-8 in key".to_string()))?
                .to_string(),
        );

        let pass = crate::utils::get_passphrase_if_needed(
            &pem_str,
            passphrase_opt.as_deref().map(|x| x.as_str()),
        )?;
        if let Some(p) = pass {
            *passphrase_opt = Some(p);
        }

        let der = crate::utils::unwrap_from_pem(&pem_str, "PRIVATE KEY")?;
        let decrypted_der =
            crate::utils::extract_raw_private_key(&der, passphrase_opt.as_deref().map(|x| x.as_str()))?;
        let raw_priv = crate::utils::unwrap_pqc_priv_from_pkcs8(&decrypted_der, &self.dsa_algo)?;
        self.dsa_privkey = raw_priv;
        self.sign_buffer = Zeroizing::new(Vec::new());
        Ok(())
    }

    fn prepare_verification(&mut self, pub_key_path: &Path, _digest_algo: &str) -> Result<()> {
        let pub_bytes = Zeroizing::new(fs::read(pub_key_path)?);
        let pem_str = Zeroizing::new(
            std::str::from_utf8(&*pub_bytes)
                .map_err(|_| CryptoError::Parameter("Invalid UTF-8 in key".to_string()))?
                .to_string(),
        );
        let der = crate::utils::unwrap_from_pem(&pem_str, "PUBLIC KEY")?;
        let raw_pub = crate::utils::unwrap_pqc_pub_from_spki(&der, &self.dsa_algo)?;
        self.peer_public_key = Some(Zeroizing::new(raw_pub));
        self.sign_buffer = Zeroizing::new(Vec::new());
        Ok(())
    }

    fn update_hash(&mut self, data: &[u8]) -> Result<()> {
        self.sign_buffer.extend_from_slice(data);
        Ok(())
    }

    fn sign_hash(&mut self) -> Result<Vec<u8>> {
        backend::pqc_sign(&self.dsa_algo, &self.dsa_privkey, &self.sign_buffer, None)
    }

    fn verify_hash(&mut self, signature: &[u8]) -> Result<bool> {
        let raw_pub = self
            .peer_public_key
            .as_ref()
            .ok_or(CryptoError::Parameter("No pubkey".to_string()))?;
        backend::pqc_verify(&self.dsa_algo, raw_pub, &self.sign_buffer, signature)
    }

    fn serialize_signature_header(&self) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(b"NKCS");
        header.extend_from_slice(&1u16.to_le_bytes());
        header.push(self.get_strategy_type() as u8);

        let add_string = |h: &mut Vec<u8>, s: &str| {
            h.extend_from_slice(&(s.len() as u32).to_le_bytes());
            h.extend_from_slice(s.as_bytes());
        };

        add_string(&mut header, &self.kem_algo);
        add_string(&mut header, &self.dsa_algo);
        add_string(&mut header, &self.digest_algo);
        header
    }

    fn deserialize_signature_header(&mut self, data: &[u8]) -> Result<usize> {
        if data.len() < 7 || &data[0..4] != b"NKCS" {
            return Err(CryptoError::FileRead("Invalid signature magic".to_string()));
        }
        let mut pos = 7;

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

        self.kem_algo = read_string(&mut pos)?;
        self.dsa_algo = read_string(&mut pos)?;
        self.digest_algo = read_string(&mut pos)?;
        Ok(pos)
    }

    fn get_metadata(&self, _magic: &str) -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("Strategy".to_string(), "PQC".to_string());
        m.insert("kem-algo".to_string(), self.kem_algo.clone());
        m.insert("dsa-algo".to_string(), self.dsa_algo.clone());
        m
    }

    fn get_header_size(&self) -> usize {
        4 + 2
            + 1
            + 4
            + self.kem_algo.len()
            + 4
            + self.dsa_algo.len()
            + 4
            + self.kem_ciphertext.len()
            + 4
            + self.salt.len()
            + 4
            + self.iv.len()
            + 4
            + self.aead_algo.len()
    }

    fn serialize_header(&self) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(b"NKCT");
        header.extend_from_slice(&2u16.to_le_bytes());
        header.push(self.get_strategy_type() as u8);

        let add_string = |h: &mut Vec<u8>, s: &str| {
            h.extend_from_slice(&(s.len() as u32).to_le_bytes());
            h.extend_from_slice(s.as_bytes());
        };
        let add_vec = |h: &mut Vec<u8>, v: &[u8]| {
            h.extend_from_slice(&(v.len() as u32).to_le_bytes());
            h.extend_from_slice(v);
        };

        add_string(&mut header, &self.kem_algo);
        add_string(&mut header, &self.dsa_algo);
        add_vec(&mut header, &self.kem_ciphertext);
        add_vec(&mut header, &self.salt);
        add_vec(&mut header, &self.iv);
        add_string(&mut header, &self.aead_algo);
        header
    }

    fn deserialize_header(&mut self, data: &[u8]) -> Result<usize> {
        if data.len() < 7 || &data[0..4] != b"NKCT" {
            return Err(CryptoError::FileRead("Invalid magic".to_string()));
        }

        let mut pos = 4;
        let version = u16::from_le_bytes(
            data[pos..pos + 2]
                .try_into()
                .map_err(|_| CryptoError::FileRead("Invalid version".to_string()))?,
        );
        pos = 7;

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
                return Err(CryptoError::FileRead("Incomplete vec data".to_string()));
            }
            let v = data[*p..*p + len].to_vec();
            *p += len;
            Ok(v)
        };

        self.kem_algo = read_string(&mut pos)?;
        self.dsa_algo = read_string(&mut pos)?;
        self.kem_ciphertext = Zeroizing::new(read_vec(&mut pos)?);
        self.salt = read_vec(&mut pos)?;
        self.iv = read_vec(&mut pos)?;

        if version >= 2 {
            self.aead_algo = read_string(&mut pos)?;
        } else {
            self.aead_algo = "AES-256-GCM".to_string();
        }

        Ok(pos)
    }
    fn get_tag_size(&self) -> usize {
        16
    }

    fn get_shared_secret(&self) -> Zeroizing<Vec<u8>> {
        self.kem_shared_secret.clone()
    }
    fn get_salt(&self) -> Vec<u8> {
        self.salt.clone()
    }
    fn get_iv(&self) -> Vec<u8> {
        self.iv.clone()
    }
}
