/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

use crate::error::{CryptoError, Result};
use crate::key::SharedKeyProvider;
use crate::strategy::{CryptoStrategy, StrategyType};
use crate::backend::{self, AeadBackend};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use hkdf::Hkdf;
use sha3::Sha3_256;
use fips203::traits::{KeyGen as _, SerDes as _, Encaps as _, Decaps as _};
use fips204::traits::{KeyGen as _, SerDes as _, Signer as _, Verifier as _};
use rand_core::{RngCore, OsRng};

pub struct PqcStrategy {
    key_provider: Option<SharedKeyProvider>,
    kem_algo: String,
    dsa_algo: String,
    digest_algo: String,
    
    // Abstract contexts
    aead_ctx: Option<backend::Aead>,
    
    // Message buffer for ML-DSA (no pre-hash in Pure-mode)
    message_buffer: Vec<u8>,
    
    // Key states
    encryption_key: Vec<u8>,
    iv: Vec<u8>,
    salt: Vec<u8>,
    kem_ct: Vec<u8>,
    shared_secret: Vec<u8>,

    // Signing keys (stored as DER to be backend-agnostic)
    sign_key_der: Option<Vec<u8>>,
    verify_key_der: Option<Vec<u8>>,
}

impl PqcStrategy {
    pub fn new() -> Self {
        Self {
            key_provider: None,
            kem_algo: "ML-KEM-768".to_string(),
            dsa_algo: "ML-DSA-65".to_string(),
            digest_algo: "SHA3-512".to_string(),
            aead_ctx: None,
            message_buffer: Vec::new(),
            encryption_key: Vec::new(),
            iv: Vec::new(),
            salt: Vec::new(),
            kem_ct: Vec::new(),
            shared_secret: Vec::new(),
            sign_key_der: None,
            verify_key_der: None,
        }
    }

    fn hkdf_derive(&self, secret: &[u8], out_len: usize, salt: &[u8], info: &str) -> Result<Vec<u8>> {
        let mut okm = vec![0u8; out_len];
        let hk = Hkdf::<Sha3_256>::new(Some(salt), secret);
        hk.expand(info.as_bytes(), &mut okm).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        Ok(okm)
    }

    // ASN.1 Helpers
    fn read_asn1_len(&self, der: &[u8], pos: &mut usize) -> usize {
        if *pos >= der.len() { return 0; }
        let b = der[*pos];
        *pos += 1;
        if b < 128 { return b as usize; }
        let n = (b & 0x7F) as usize;
        if *pos + n > der.len() || n > 4 { return 0; }
        let mut res = 0usize;
        for _ in 0..n {
            res = (res << 8) | (der[*pos] as usize);
            *pos += 1;
        }
        res
    }

    fn unwrap_pqc_der(&self, der: &[u8], is_public: bool) -> Vec<u8> {
        if der.is_empty() || der[0] != 0x30 { return der.to_vec(); }
        
        let mut best = Vec::new();
        for i in 0..der.len().saturating_sub(4) {
            let tag = der[i];
            if tag == 0x04 || (is_public && tag == 0x03) {
                let mut pos = i + 1;
                let o_len = self.read_asn1_len(der, &mut pos);
                if o_len > 0 && pos + o_len <= der.len() {
                    let mut actual_len = o_len;
                    let mut data_start = pos;
                    if tag == 0x03 {
                        if actual_len > 1 && der[data_start] == 0x00 {
                            data_start += 1;
                            actual_len -= 1;
                        } else { continue; }
                    }
                    
                    if [1632, 2400, 3168, 2560, 4032, 4896, 800, 1184, 1568, 1312, 1952, 2592]
                        .contains(&actual_len) {
                        return der[data_start..data_start + actual_len].to_vec();
                    }
                    if actual_len > best.len() {
                        best = der[data_start..data_start + actual_len].to_vec();
                    }
                }
            }
        }
        if best.is_empty() { der.to_vec() } else { best }
    }

    fn asn1_append_len(&self, buf: &mut Vec<u8>, len: usize) {
        if len < 128 {
            buf.push(len as u8);
        } else if len < 256 {
            buf.push(0x81);
            buf.push(len as u8);
        } else {
            buf.push(0x82);
            buf.push((len >> 8) as u8);
            buf.push((len & 0xff) as u8);
        }
    }

    fn asn1_append_seq(&self, buf: &mut Vec<u8>, content: &[u8]) {
        buf.push(0x30);
        self.asn1_append_len(buf, content.len());
        buf.extend_from_slice(content);
    }

    fn wrap_pqc_der(&self, raw: &[u8], algo_name: &str, is_public: bool, seed: Option<&[u8]>) -> Vec<u8> {
        let (oid, default_seed_len) = match algo_name {
            "ML-KEM-512" => (vec![0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x01], 64),
            "ML-KEM-768" => (vec![0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02], 64),
            "ML-KEM-1024" => (vec![0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x03], 64),
            "ML-DSA-44" => (vec![0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11], 32),
            "ML-DSA-65" => (vec![0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12], 32),
            "ML-DSA-87" => (vec![0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13], 32),
            _ => return raw.to_vec(),
        };

        let mut algo_id = Vec::new();
        self.asn1_append_seq(&mut algo_id, &oid);

        if is_public {
            let mut bit_str = vec![0x03];
            self.asn1_append_len(&mut bit_str, raw.len() + 1);
            bit_str.push(0x00);
            bit_str.extend_from_slice(raw);

            let mut spki_content = Vec::new();
            spki_content.extend_from_slice(&algo_id);
            spki_content.extend_from_slice(&bit_str);

            let mut res = Vec::new();
            self.asn1_append_seq(&mut res, &spki_content);
            res
        } else {
            let seed_v = if let Some(s) = seed {
                s.to_vec()
            } else {
                vec![0u8; default_seed_len]
            };

            let mut seed_oct = vec![0x04];
            self.asn1_append_len(&mut seed_oct, seed_v.len());
            seed_oct.extend_from_slice(&seed_v);

            let mut key_oct = vec![0x04];
            self.asn1_append_len(&mut key_oct, raw.len());
            key_oct.extend_from_slice(raw);

            let mut nested_seq_content = Vec::new();
            nested_seq_content.extend_from_slice(&seed_oct);
            nested_seq_content.extend_from_slice(&key_oct);
            let mut nested_seq = Vec::new();
            self.asn1_append_seq(&mut nested_seq, &nested_seq_content);

            let mut p8_content = vec![0x02, 0x01, 0x00];
            p8_content.extend_from_slice(&algo_id);
            
            let mut final_key_oct = vec![0x04];
            self.asn1_append_len(&mut final_key_oct, nested_seq.len());
            final_key_oct.extend_from_slice(&nested_seq);
            p8_content.extend_from_slice(&final_key_oct);

            let mut res = Vec::new();
            self.asn1_append_seq(&mut res, &p8_content);
            res
        }
    }
}

impl CryptoStrategy for PqcStrategy {
    fn get_strategy_type(&self) -> StrategyType {
        StrategyType::PQC
    }

    fn set_key_provider(&mut self, provider: SharedKeyProvider) {
        self.key_provider = Some(provider);
    }

    fn generate_encryption_key_pair(&self, key_paths: &HashMap<String, String>, passphrase: Option<&str>) -> Result<()> {
        let kem_algo = key_paths.get("kem-algo").cloned().unwrap_or_else(|| self.kem_algo.clone());
        let pub_path = key_paths.get("public-key")
            .ok_or(CryptoError::Parameter("Missing public key path".to_string()))?;
        let priv_path = key_paths.get("private-key")
            .ok_or(CryptoError::Parameter("Missing private key path".to_string()))?;

        let use_tpm = key_paths.get("use-tpm").map(|s| s == "true").unwrap_or(false);
        
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];
        OsRng.fill_bytes(&mut d);
        OsRng.fill_bytes(&mut z);
        let mut seed = [0u8; 64];
        seed[0..32].copy_from_slice(&d);
        seed[32..64].copy_from_slice(&z);

        let (pk_bytes, sk_bytes) = match kem_algo.as_str() {
            "ML-KEM-512" => {
                let (pk, sk) = fips203::ml_kem_512::KG::keygen_from_seed(d, z);
                (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
            },
            "ML-KEM-768" => {
                let (pk, sk) = fips203::ml_kem_768::KG::keygen_from_seed(d, z);
                (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
            },
            "ML-KEM-1024" => {
                let (pk, sk) = fips203::ml_kem_1024::KG::keygen_from_seed(d, z);
                (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
            },
            _ => return Err(CryptoError::Parameter(format!("Unsupported KEM: {}", kem_algo))),
        };

        let wrapped_pub = self.wrap_pqc_der(&pk_bytes, &kem_algo, true, None);
        let pub_pem = crate::utils::wrap_to_pem(&wrapped_pub, "PUBLIC KEY");
        fs::write(pub_path, pub_pem)?;

        let wrapped_priv = self.wrap_pqc_der(&sk_bytes, &kem_algo, false, Some(&seed));
        if use_tpm {
            let provider = self.key_provider.as_ref().ok_or(CryptoError::ProviderNotAvailable)?;
            let wrapped = provider.wrap_raw(&wrapped_priv, passphrase)?;
            fs::write(priv_path, wrapped)?;
        } else {
            let priv_pem = crate::utils::wrap_to_pem(&wrapped_priv, "PRIVATE KEY");
            fs::write(priv_path, priv_pem)?;
        }

        Ok(())
    }

    fn generate_signing_key_pair(&self, key_paths: &HashMap<String, String>, passphrase: Option<&str>) -> Result<()> {
        let dsa_algo = key_paths.get("dsa-algo").cloned().unwrap_or_else(|| self.dsa_algo.clone());
        let pub_path = key_paths.get("signing-public-key")
            .ok_or(CryptoError::Parameter("Missing public key path".to_string()))?;
        let priv_path = key_paths.get("signing-private-key")
            .ok_or(CryptoError::Parameter("Missing private key path".to_string()))?;

        let use_tpm = key_paths.get("use-tpm").map(|s| s == "true").unwrap_or(false);

        let mut xi = [0u8; 32];
        OsRng.fill_bytes(&mut xi);

        let (pk_bytes, sk_bytes) = match dsa_algo.as_str() {
            "ML-DSA-44" => {
                let (pk, sk) = fips204::ml_dsa_44::KG::keygen_from_seed(&xi);
                (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
            },
            "ML-DSA-65" => {
                let (pk, sk) = fips204::ml_dsa_65::KG::keygen_from_seed(&xi);
                (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
            },
            "ML-DSA-87" => {
                let (pk, sk) = fips204::ml_dsa_87::KG::keygen_from_seed(&xi);
                (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
            },
            _ => return Err(CryptoError::Parameter(format!("Unsupported DSA: {}", dsa_algo))),
        };

        let wrapped_pub = self.wrap_pqc_der(&pk_bytes, &dsa_algo, true, None);
        let pub_pem = crate::utils::wrap_to_pem(&wrapped_pub, "PUBLIC KEY");
        fs::write(pub_path, pub_pem)?;

        let wrapped_priv = self.wrap_pqc_der(&sk_bytes, &dsa_algo, false, Some(&xi));
        if use_tpm {
            let provider = self.key_provider.as_ref().ok_or(CryptoError::ProviderNotAvailable)?;
            let wrapped = provider.wrap_raw(&wrapped_priv, passphrase)?;
            fs::write(priv_path, wrapped)?;
        } else {
            let priv_pem = crate::utils::wrap_to_pem(&wrapped_priv, "PRIVATE KEY");
            fs::write(priv_path, priv_pem)?;
        }

        Ok(())
    }

    fn regenerate_public_key(&self, priv_path: &Path, pub_path: &Path, passphrase: &mut Option<String>) -> Result<()> {
        let priv_bytes = fs::read(priv_path)?;
        let pem_str = String::from_utf8_lossy(&priv_bytes);
        
        let priv_key_der = if pem_str.contains("-----BEGIN TPM WRAPPED BLOB-----") {
            let provider = self.key_provider.as_ref().ok_or(CryptoError::ProviderNotAvailable)?;
            provider.unwrap_raw(&pem_str, passphrase.as_deref())?
        } else {
            *passphrase = crate::utils::get_passphrase_if_needed(&pem_str, passphrase.as_deref())?;
            crate::utils::unwrap_from_pem(&pem_str, "PRIVATE KEY")?
        };

        let pub_der = backend::extract_public_key(&priv_key_der, passphrase.as_deref())?;
        fs::write(pub_path, crate::utils::wrap_to_pem(&pub_der, "PUBLIC KEY"))?;
        Ok(())
    }

    fn prepare_encryption(&mut self, key_paths: &HashMap<String, String>) -> Result<()> {
        if let Some(algo) = key_paths.get("kem-algo") { self.kem_algo = algo.clone(); }
        if let Some(algo) = key_paths.get("digest-algo") { self.digest_algo = algo.clone(); }

        let pubkey_path = key_paths.get("recipient-pubkey")
            .or_else(|| key_paths.get("recipient-mlkem-pubkey"))
            .ok_or(CryptoError::PublicKeyLoad("Missing recipient public key".to_string()))?;

        let pem = fs::read_to_string(pubkey_path)?;
        let der = crate::utils::unwrap_from_pem(&pem, "PUBLIC KEY")?;
        let raw_pub = self.unwrap_pqc_der(&der, true);
        
        let (ss_bytes, ct_bytes) = match self.kem_algo.as_str() {
            "ML-KEM-512" => {
                use fips203::ml_kem_512::*;
                let pk = EncapsKey::try_from_bytes(raw_pub.try_into().map_err(|_| CryptoError::Parameter("Invalid key size".to_string()))?)
                    .map_err(|_| CryptoError::PublicKeyLoad("Invalid key".to_string()))?;
                let (ss, ct) = pk.try_encaps().map_err(|_| CryptoError::OpenSSL("Encap failed".to_string()))?;
                (ss.into_bytes().to_vec(), ct.into_bytes().to_vec())
            },
            "ML-KEM-768" => {
                use fips203::ml_kem_768::*;
                let pk = EncapsKey::try_from_bytes(raw_pub.try_into().map_err(|_| CryptoError::Parameter("Invalid key size".to_string()))?)
                    .map_err(|_| CryptoError::PublicKeyLoad("Invalid key".to_string()))?;
                let (ss, ct) = pk.try_encaps().map_err(|_| CryptoError::OpenSSL("Encap failed".to_string()))?;
                (ss.into_bytes().to_vec(), ct.into_bytes().to_vec())
            },
            "ML-KEM-1024" => {
                use fips203::ml_kem_1024::*;
                let pk = EncapsKey::try_from_bytes(raw_pub.try_into().map_err(|_| CryptoError::Parameter("Invalid key size".to_string()))?)
                    .map_err(|_| CryptoError::PublicKeyLoad("Invalid key".to_string()))?;
                let (ss, ct) = pk.try_encaps().map_err(|_| CryptoError::OpenSSL("Encap failed".to_string()))?;
                (ss.into_bytes().to_vec(), ct.into_bytes().to_vec())
            },
            _ => return Err(CryptoError::Parameter(format!("Unsupported KEM: {}", self.kem_algo))),
        };
        
        self.shared_secret = ss_bytes;
        self.kem_ct = ct_bytes;
        self.salt = vec![0u8; 16];
        self.iv = vec![0u8; 12];
        OsRng.fill_bytes(&mut self.salt);
        OsRng.fill_bytes(&mut self.iv);

        self.encryption_key = self.hkdf_derive(&self.shared_secret, 32, &self.salt, "pqc-encryption")?;
        let ctx = backend::new_encrypt("AES-256-GCM", &self.encryption_key, &self.iv)?;
        self.aead_ctx = Some(ctx);
        Ok(())
    }

    fn prepare_decryption(&mut self, key_paths: &HashMap<String, String>, passphrase: &mut Option<String>) -> Result<()> {
        if let Some(algo) = key_paths.get("kem-algo") { self.kem_algo = algo.clone(); }
        if let Some(algo) = key_paths.get("dsa-algo") { self.dsa_algo = algo.clone(); }

        let privkey_path = key_paths.get("user-privkey")
            .or_else(|| key_paths.get("recipient-mlkem-privkey"))
            .ok_or(CryptoError::PrivateKeyLoad("Missing private key path".to_string()))?;

        let priv_bytes = fs::read(privkey_path)?;
        let pem_str = String::from_utf8_lossy(&priv_bytes);
        
        let wrapped_priv = if pem_str.contains("-----BEGIN TPM WRAPPED BLOB-----") {
            let provider = self.key_provider.as_ref().ok_or(CryptoError::ProviderNotAvailable)?;
            provider.unwrap_raw(&pem_str, passphrase.as_deref())?
        } else {
            *passphrase = crate::utils::get_passphrase_if_needed(&pem_str, passphrase.as_deref())?;
            crate::utils::unwrap_from_pem(&pem_str, "PRIVATE KEY")?
        };

        // If backend is OpenSSL 3.5, we could use backend::pqc_decap with passphrase.
        // For pure-Rust with fips203, we must manually decrypt with OpenSSL if needed.
        // Here we try to use backend::pqc_decap if available to support encrypted keys.
        let ss_bytes = if cfg!(feature = "backend-openssl") {
            backend::pqc_decap(&wrapped_priv, &self.kem_ct, passphrase.as_deref())?
        } else {
            // Pure Rust or WolfSSL without robust PQC decap:
            // For now, assume it's already decrypted if unwrap_from_pem succeeded.
            let raw_priv = self.unwrap_pqc_der(&wrapped_priv, false);
            match self.kem_algo.as_str() {
                "ML-KEM-512" => {
                    use fips203::ml_kem_512::*;
                    let sk = DecapsKey::try_from_bytes(raw_priv.try_into().map_err(|_| CryptoError::Parameter("Invalid key size".to_string()))?)
                        .map_err(|_| CryptoError::PrivateKeyLoad("Invalid key".to_string()))?;
                    let ct = CipherText::try_from_bytes(self.kem_ct.clone().try_into().map_err(|_| CryptoError::Parameter("Invalid CT size".to_string()))?)
                        .map_err(|_| CryptoError::FileRead("Invalid CT".to_string()))?;
                    sk.try_decaps(&ct).map_err(|_| CryptoError::OpenSSL("Decaps failed".to_string()))?.into_bytes().to_vec()
                },
                "ML-KEM-768" => {
                    use fips203::ml_kem_768::*;
                    let sk = DecapsKey::try_from_bytes(raw_priv.try_into().map_err(|_| CryptoError::Parameter("Invalid key size".to_string()))?)
                        .map_err(|_| CryptoError::PrivateKeyLoad("Invalid key".to_string()))?;
                    let ct = CipherText::try_from_bytes(self.kem_ct.clone().try_into().map_err(|_| CryptoError::Parameter("Invalid CT size".to_string()))?)
                        .map_err(|_| CryptoError::FileRead("Invalid CT".to_string()))?;
                    sk.try_decaps(&ct).map_err(|_| CryptoError::OpenSSL("Decaps failed".to_string()))?.into_bytes().to_vec()
                },
                "ML-KEM-1024" => {
                    use fips203::ml_kem_1024::*;
                    let sk = DecapsKey::try_from_bytes(raw_priv.try_into().map_err(|_| CryptoError::Parameter("Invalid key size".to_string()))?)
                        .map_err(|_| CryptoError::PrivateKeyLoad("Invalid key".to_string()))?;
                    let ct = CipherText::try_from_bytes(self.kem_ct.clone().try_into().map_err(|_| CryptoError::Parameter("Invalid CT size".to_string()))?)
                        .map_err(|_| CryptoError::FileRead("Invalid CT".to_string()))?;
                    sk.try_decaps(&ct).map_err(|_| CryptoError::OpenSSL("Decaps failed".to_string()))?.into_bytes().to_vec()
                },
                _ => return Err(CryptoError::Parameter(format!("Unsupported KEM: {}", self.kem_algo))),
            }
        };
        
        self.shared_secret = ss_bytes;
        self.encryption_key = self.hkdf_derive(&self.shared_secret, 32, &self.salt, "pqc-encryption")?;
        let ctx = backend::new_decrypt("AES-256-GCM", &self.encryption_key, &self.iv)?;
        self.aead_ctx = Some(ctx);
        Ok(())
    }

    fn encrypt_transform(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let ctx = self.aead_ctx.as_mut().ok_or(CryptoError::Parameter("AEAD context not initialized".to_string()))?;
        let mut out = vec![0u8; data.len() + 16];
        let n = ctx.update(data, &mut out)?;
        out.truncate(n);
        Ok(out)
    }

    fn decrypt_transform(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let ctx = self.aead_ctx.as_mut().ok_or(CryptoError::Parameter("AEAD context not initialized".to_string()))?;
        let mut out = vec![0u8; data.len() + 16];
        let n = ctx.update(data, &mut out)?;
        out.truncate(n);
        Ok(out)
    }

    fn finalize_encryption(&mut self) -> Result<Vec<u8>> {
        let ctx = self.aead_ctx.as_mut().ok_or(CryptoError::Parameter("AEAD context not initialized".to_string()))?;
        let mut out = vec![0u8; 16];
        let n = ctx.finalize(&mut out)?;
        out.truncate(n);
        
        let mut tag = vec![0u8; 16];
        ctx.get_tag(&mut tag)?;
        out.extend_from_slice(&tag);
        
        Ok(out)
    }

    fn finalize_decryption(&mut self, tag: &[u8]) -> Result<()> {
        let ctx = self.aead_ctx.as_mut().ok_or(CryptoError::Parameter("AEAD context not initialized".to_string()))?;
        ctx.set_tag(tag)?;
        let mut out = vec![0u8; 16];
        ctx.finalize(&mut out).map_err(|_| CryptoError::SignatureVerification)?;
        Ok(())
    }

    fn prepare_signing(&mut self, priv_key_path: &Path, passphrase: &mut Option<String>, digest_algo: &str) -> Result<()> {
        let priv_bytes = fs::read(priv_key_path)?;
        let pem_str = String::from_utf8_lossy(&priv_bytes);

        let wrapped_priv = if pem_str.contains("-----BEGIN TPM WRAPPED BLOB-----") {
            let provider = self.key_provider.as_ref().ok_or(CryptoError::ProviderNotAvailable)?;
            provider.unwrap_raw(&pem_str, passphrase.as_deref())?
        } else {
            *passphrase = crate::utils::get_passphrase_if_needed(&pem_str, passphrase.as_deref())?;
            crate::utils::unwrap_from_pem(&pem_str, "PRIVATE KEY")?
        };
        
        // Similarly for signing, if it was encrypted we need to decrypt it before unwrap_pqc_der
        // or let backend handle it.
        let raw_priv = if cfg!(feature = "backend-openssl") {
             // For now, in Rust PQC we use fips crates which need raw bytes.
             // We can use a temporary EVP_PKEY to export raw bytes if encrypted.
             let exported = backend::extract_raw_private_key(&wrapped_priv, passphrase.as_deref())?;
             self.unwrap_pqc_der(&exported, false)
        } else {
             self.unwrap_pqc_der(&wrapped_priv, false)
        };
        
        self.sign_key_der = Some(raw_priv);
        self.digest_algo = digest_algo.to_string();
        self.message_buffer.clear();
        Ok(())
    }

    fn prepare_verification(&mut self, pub_key_path: &Path, digest_algo: &str) -> Result<()> {
        let pub_bytes = fs::read(pub_key_path)?;
        let der = crate::utils::unwrap_from_pem(&String::from_utf8_lossy(&pub_bytes), "PUBLIC KEY")?;
        let raw_pub = self.unwrap_pqc_der(&der, true);

        self.verify_key_der = Some(raw_pub);
        self.digest_algo = digest_algo.to_string();
        self.message_buffer.clear();
        Ok(())
    }

    fn update_hash(&mut self, data: &[u8]) -> Result<()> {
        self.message_buffer.extend_from_slice(data);
        Ok(())
    }

    fn sign_hash(&mut self) -> Result<Vec<u8>> {
        let raw_priv = self.sign_key_der.as_ref().ok_or(CryptoError::Parameter("Sign key missing".to_string()))?;
        match self.dsa_algo.as_str() {
            "ML-DSA-44" => {
                let sk = fips204::ml_dsa_44::PrivateKey::try_from_bytes(raw_priv.clone().try_into().map_err(|_| CryptoError::Parameter("Invalid key size".to_string()))?)
                    .map_err(|_| CryptoError::PrivateKeyLoad("Invalid key".to_string()))?;
                Ok(sk.try_sign(&self.message_buffer, &[]).map_err(|_| CryptoError::OpenSSL("Sign failed".to_string()))?.to_vec())
            },
            "ML-DSA-65" => {
                let sk = fips204::ml_dsa_65::PrivateKey::try_from_bytes(raw_priv.clone().try_into().map_err(|_| CryptoError::Parameter("Invalid key size".to_string()))?)
                    .map_err(|_| CryptoError::PrivateKeyLoad("Invalid key".to_string()))?;
                Ok(sk.try_sign(&self.message_buffer, &[]).map_err(|_| CryptoError::OpenSSL("Sign failed".to_string()))?.to_vec())
            },
            "ML-DSA-87" => {
                let sk = fips204::ml_dsa_87::PrivateKey::try_from_bytes(raw_priv.clone().try_into().map_err(|_| CryptoError::Parameter("Invalid key size".to_string()))?)
                    .map_err(|_| CryptoError::PrivateKeyLoad("Invalid key".to_string()))?;
                Ok(sk.try_sign(&self.message_buffer, &[]).map_err(|_| CryptoError::OpenSSL("Sign failed".to_string()))?.to_vec())
            },
            _ => Err(CryptoError::Parameter(format!("Unsupported DSA: {}", self.dsa_algo))),
        }
    }

    fn verify_hash(&mut self, signature: &[u8]) -> Result<bool> {
        let raw_pub = self.verify_key_der.as_ref().ok_or(CryptoError::Parameter("Verify key missing".to_string()))?;
        match self.dsa_algo.as_str() {
            "ML-DSA-44" => {
                let pk = fips204::ml_dsa_44::PublicKey::try_from_bytes(raw_pub.clone().try_into().map_err(|_| CryptoError::Parameter("Invalid key size".to_string()))?)
                    .map_err(|_| CryptoError::PublicKeyLoad("Invalid key".to_string()))?;
                let sig_arr: [u8; 2420] = signature.try_into().map_err(|_| CryptoError::Parameter("Invalid sig size".to_string()))?;
                Ok(pk.verify(&self.message_buffer, &sig_arr, &[]))
            },
            "ML-DSA-65" => {
                let pk = fips204::ml_dsa_65::PublicKey::try_from_bytes(raw_pub.clone().try_into().map_err(|_| CryptoError::Parameter("Invalid key size".to_string()))?)
                    .map_err(|_| CryptoError::PublicKeyLoad("Invalid key".to_string()))?;
                let sig_arr: [u8; 3309] = signature.try_into().map_err(|_| CryptoError::Parameter("Invalid sig size".to_string()))?;
                Ok(pk.verify(&self.message_buffer, &sig_arr, &[]))
            },
            "ML-DSA-87" => {
                let pk = fips204::ml_dsa_87::PublicKey::try_from_bytes(raw_pub.clone().try_into().map_err(|_| CryptoError::Parameter("Invalid key size".to_string()))?)
                    .map_err(|_| CryptoError::PublicKeyLoad("Invalid key".to_string()))?;
                let sig_arr: [u8; 4627] = signature.try_into().map_err(|_| CryptoError::Parameter("Invalid sig size".to_string()))?;
                Ok(pk.verify(&self.message_buffer, &sig_arr, &[]))
            },
            _ => Err(CryptoError::Parameter(format!("Unsupported DSA: {}", self.dsa_algo))),
        }
    }

    fn serialize_signature_header(&self) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(b"NKCS");
        header.extend_from_slice(&1u16.to_le_bytes());
        header.push(self.get_strategy_type() as u8);

        header.extend_from_slice(&(self.kem_algo.len() as u32).to_le_bytes());
        header.extend_from_slice(self.kem_algo.as_bytes());

        header.extend_from_slice(&(self.dsa_algo.len() as u32).to_le_bytes());
        header.extend_from_slice(self.dsa_algo.as_bytes());
        
        header.extend_from_slice(&(self.digest_algo.len() as u32).to_le_bytes());
        header.extend_from_slice(self.digest_algo.as_bytes());
        
        header
    }

    fn deserialize_signature_header(&mut self, data: &[u8]) -> Result<usize> {
        if data.len() < 7 { return Err(CryptoError::FileRead("Signature header too short".to_string())); }
        if &data[0..4] != b"NKCS" { return Err(CryptoError::FileRead("Invalid signature magic".to_string())); }
        
        let mut pos = 4;
        let version = u16::from_le_bytes(data[pos..pos+2].try_into().unwrap());
        pos += 2;
        if version != 1 { return Err(CryptoError::FileRead("Unsupported signature version".to_string())); }
        
        let strategy_type = data[pos];
        pos += 1;
        if strategy_type != self.get_strategy_type() as u8 {
            return Err(CryptoError::FileRead("Signature strategy mismatch".to_string()));
        }

        let read_string = |p: &mut usize| -> Result<String> {
            if data.len() < *p + 4 { return Err(CryptoError::FileRead("Incomplete string header".to_string())); }
            let len = u32::from_le_bytes(data[*p..*p+4].try_into().unwrap()) as usize;
            *p += 4;
            if data.len() < *p + len { return Err(CryptoError::FileRead("Incomplete string data".to_string())); }
            let s = String::from_utf8_lossy(&data[*p..*p+len]).to_string();
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
        m.insert("KEM-Algorithm".to_string(), self.kem_algo.clone());
        m.insert("DSA-Algorithm".to_string(), self.dsa_algo.clone());
        m
    }

    fn get_header_size(&self) -> usize {
        4 + 2 + 1 + 
        4 + self.kem_algo.len() + 
        4 + self.dsa_algo.len() + 
        4 + self.kem_ct.len() + 4 + self.salt.len() + 4 + self.iv.len()
    }

    fn serialize_header(&self) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(b"NKCT");
        header.extend_from_slice(&1u16.to_le_bytes());
        header.push(self.get_strategy_type() as u8);

        header.extend_from_slice(&(self.kem_algo.len() as u32).to_le_bytes());
        header.extend_from_slice(self.kem_algo.as_bytes());
        
        header.extend_from_slice(&(self.dsa_algo.len() as u32).to_le_bytes());
        header.extend_from_slice(self.dsa_algo.as_bytes());
        
        header.extend_from_slice(&(self.kem_ct.len() as u32).to_le_bytes());
        header.extend_from_slice(&self.kem_ct);
        
        header.extend_from_slice(&(self.salt.len() as u32).to_le_bytes());
        header.extend_from_slice(&self.salt);
        
        header.extend_from_slice(&(self.iv.len() as u32).to_le_bytes());
        header.extend_from_slice(&self.iv);
        
        header
    }

    fn deserialize_header(&mut self, data: &[u8]) -> Result<usize> {
        if data.len() < 7 { return Err(CryptoError::FileRead("Header too short".to_string())); }
        if &data[0..4] != b"NKCT" { return Err(CryptoError::FileRead("Invalid magic".to_string())); }
        
        let mut pos = 4;
        let version = u16::from_le_bytes(data[pos..pos+2].try_into().unwrap());
        pos += 2;
        if version != 1 { return Err(CryptoError::FileRead("Unsupported version".to_string())); }
        
        let strategy_type = data[pos];
        pos += 1;
        if strategy_type != self.get_strategy_type() as u8 {
            return Err(CryptoError::FileRead("Strategy mismatch".to_string()));
        }

        let read_string = |p: &mut usize| -> Result<String> {
            if data.len() < *p + 4 { return Err(CryptoError::FileRead("Incomplete string header".to_string())); }
            let len = u32::from_le_bytes(data[*p..*p+4].try_into().unwrap()) as usize;
            *p += 4;
            if data.len() < *p + len { return Err(CryptoError::FileRead("Incomplete string data".to_string())); }
            let s = String::from_utf8_lossy(&data[*p..*p+len]).to_string();
            *p += len;
            Ok(s)
        };

        let read_vec = |p: &mut usize| -> Result<Vec<u8>> {
            if data.len() < *p + 4 { return Err(CryptoError::FileRead("Incomplete vec header".to_string())); }
            let len = u32::from_le_bytes(data[*p..*p+4].try_into().unwrap()) as usize;
            *p += 4;
            if data.len() < *p + len { return Err(CryptoError::FileRead("Incomplete string data".to_string())); }
            let v = data[*p..*p+len].to_vec();
            *p += len;
            Ok(v)
        };

        self.kem_algo = read_string(&mut pos)?;
        self.dsa_algo = read_string(&mut pos)?;
        self.kem_ct = read_vec(&mut pos)?;
        self.salt = read_vec(&mut pos)?;
        self.iv = read_vec(&mut pos)?;

        Ok(pos)
    }

    fn get_tag_size(&self) -> usize {
        16
    }

    fn get_shared_secret(&self) -> Vec<u8> {
        self.shared_secret.clone()
    }

    fn get_salt(&self) -> Vec<u8> {
        self.salt.clone()
    }

    fn get_iv(&self) -> Vec<u8> {
        self.iv.clone()
    }
}
