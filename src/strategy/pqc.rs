/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

use crate::backend;
use crate::error::{CryptoError, Result};
use crate::key::SharedKeyProvider;
use crate::strategy::streaming_aead::{
    self as v3, V3_DEFAULT_CHUNK_SIZE, V3_NONCE_PREFIX_LEN, V3_SESSION_ID_LEN,
};
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
    peer_public_key: Option<Zeroizing<Vec<u8>>>,

    // Raw ML-KEM ek injected in memory from a verified NKKB KeyBundle. When
    // `Some`, `prepare_shared_secret_encryption` encaps against it directly and
    // never reads a recipient pubkey file. (A public key is not secret, but
    // Zeroizing keeps the field type-uniform and costs nothing here.)
    recipient_enc_key: Option<Zeroizing<Vec<u8>>>,

    // The user's own ML-KEM private key as passphrase-encrypted PKCS#8 PEM
    // text, injected in memory from the keyring my-identities table
    // (auto-match). When `Some`, `prepare_shared_secret_decryption` uses it
    // and never reads a user-privkey file.
    user_privkey_pem: Option<Zeroizing<String>>,

    // DSA specific
    dsa_privkey: Zeroizing<Vec<u8>>,
    sign_buffer: Zeroizing<Vec<u8>>,
    signature: Vec<u8>,

    // ---- v3 chunked-AEAD state ----
    #[zeroize(skip)]
    chunk_size: u32,
    nonce_prefix: Zeroizing<Vec<u8>>,
    #[zeroize(skip)]
    file_session_id: Option<[u8; V3_SESSION_ID_LEN]>,
    #[zeroize(skip)]
    chunk_counter: u32,
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
            peer_public_key: None,
            recipient_enc_key: None,
            user_privkey_pem: None,
            dsa_privkey: Zeroizing::new(Vec::new()),
            sign_buffer: Zeroizing::new(Vec::new()),
            signature: Vec::new(),
            chunk_size: V3_DEFAULT_CHUNK_SIZE,
            nonce_prefix: Zeroizing::new(Vec::new()),
            file_session_id: None,
            chunk_counter: 0,
        }
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
        // Prefer a KeyBundle-injected raw ek (already authenticated in memory):
        // encaps directly, no file read, no PEM/SPKI unwrap. Fall back to the
        // recipient pubkey file only when no bundle key was injected.
        // clone() (not take()): keep the injected key so the strategy stays
        // reusable, matching the idempotent file-path branch.
        let raw_pub: Zeroizing<Vec<u8>> = match self.recipient_enc_key.clone() {
            Some(ek) => ek,
            None => {
                let pubkey_path = key_paths
                    .get("recipient-pubkey")
                    .or_else(|| key_paths.get("recipient-mlkem-pubkey"))
                    .ok_or(CryptoError::PublicKeyLoad(
                        "Missing recipient public key".to_string(),
                    ))?;
                let pem = Zeroizing::new(fs::read_to_string(pubkey_path)?);
                let der = crate::utils::unwrap_from_pem(&pem, "PUBLIC KEY")?;
                Zeroizing::new(crate::utils::unwrap_pqc_pub_from_spki(&der, &self.kem_algo)?)
            }
        };

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
        // Prefer a keyring-injected encrypted-PKCS#8 PEM (auto-match): no file
        // read. clone() (not take()) keeps the strategy reusable, matching the
        // recipient_enc_key convention above.
        let pem_str: Zeroizing<String> = match self.user_privkey_pem.clone() {
            Some(pem) => pem,
            None => {
                let privkey_path = key_paths
                    .get("user-privkey")
                    .or_else(|| key_paths.get("recipient-mlkem-privkey"))
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
            v3::hkdf_expand(&self.kem_shared_secret, &self.salt, v3::V3_INFO_ENC_KEY, 32)?;
        self.nonce_prefix = v3::hkdf_expand(
            &self.kem_shared_secret,
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
            v3::hkdf_expand(&self.kem_shared_secret, &self.salt, v3::V3_INFO_ENC_KEY, 32)?;
        self.nonce_prefix = v3::hkdf_expand(
            &self.kem_shared_secret,
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
        passphrase_opt: &mut Option<Zeroizing<String>>,
        _digest_algo: &str,
    ) -> Result<()> {
        let priv_bytes = Zeroizing::new(fs::read(priv_key_path)?);
        let pem_str = Zeroizing::new(
            std::str::from_utf8(&priv_bytes)
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
            std::str::from_utf8(&pub_bytes)
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
        backend::pqc_sign(&self.dsa_algo, &self.dsa_privkey, &self.sign_buffer, &[])
    }

    fn verify_hash(&mut self, signature: &[u8]) -> Result<bool> {
        let raw_pub = self
            .peer_public_key
            .as_ref()
            .ok_or(CryptoError::Parameter("No pubkey".to_string()))?;
        backend::pqc_verify(&self.dsa_algo, raw_pub, &self.sign_buffer, signature, &[])
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
        let size = 4 + 2
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
            + 4; // chunk_size u32
        size
    }

    fn serialize_header(&self) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(b"NKCT");
        let version: u16 = 3;
        header.extend_from_slice(&version.to_le_bytes());
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
        header.extend_from_slice(&self.chunk_size.to_le_bytes());
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
        if version != 3 {
            return Err(CryptoError::FileRead(
                "legacy v1/v2 file format is no longer supported; decrypt it with an older nkCryptoTool release and re-encrypt".into(),
            ));
        }
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
        self.kem_shared_secret.clone()
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

    fn set_recipient_enc_key(&mut self, raw_mlkem_ek: Vec<u8>) {
        self.recipient_enc_key = Some(Zeroizing::new(raw_mlkem_ek));
    }

    fn set_user_enc_privkey_pem(&mut self, pem: Zeroizing<String>) {
        self.user_privkey_pem = Some(pem);
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
        v3_encrypt_chunk(
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
        v3_decrypt_chunk(
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

fn v3_encrypt_chunk(
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

fn v3_decrypt_chunk(
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
