/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

use crate::error::{CryptoError, Result};
use crate::key::SharedKeyProvider;
use crate::strategy::streaming_aead::{
    self as v3, V3_DEFAULT_CHUNK_SIZE, V3_NONCE_PREFIX_LEN, V3_SESSION_ID_LEN,
};
use crate::strategy::{ecc::EccStrategy, pqc::PqcStrategy, CryptoStrategy, StrategyType};
use std::collections::HashMap;
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HybridStrategy {
    ecc: EccStrategy,
    pqc: PqcStrategy,
    encryption_key: Zeroizing<Vec<u8>>,
    iv: Vec<u8>,
    salt: Vec<u8>,

    // ---- v3 chunked-AEAD state ----
    #[zeroize(skip)]
    chunk_size: u32,
    nonce_prefix: Zeroizing<Vec<u8>>,
    #[zeroize(skip)]
    file_session_id: Option<[u8; V3_SESSION_ID_LEN]>,
    #[zeroize(skip)]
    chunk_counter: u32,
    #[zeroize(skip)]
    aead_algo_v3: String,
}

impl HybridStrategy {
    pub fn new() -> Self {
        Self {
            ecc: EccStrategy::new(),
            pqc: PqcStrategy::new(),
            encryption_key: Zeroizing::new(Vec::new()),
            iv: Vec::new(),
            salt: Vec::new(),
            chunk_size: V3_DEFAULT_CHUNK_SIZE,
            nonce_prefix: Zeroizing::new(Vec::new()),
            file_session_id: None,
            chunk_counter: 0,
            aead_algo_v3: "AES-256-GCM".to_string(),
        }
    }
}

impl CryptoStrategy for HybridStrategy {
    fn get_strategy_type(&self) -> StrategyType {
        StrategyType::Hybrid
    }

    fn set_key_provider(&mut self, provider: SharedKeyProvider) {
        self.ecc.set_key_provider(provider.clone());
        self.pqc.set_key_provider(provider);
    }

    // Route KeyBundle-injected recipient keys to the sub-strategies: the ML-KEM
    // ek to the PQC half, the P-256 SPKI DER to the ECC half. Hybrid encryption
    // then needs neither `recipient-mlkem-pubkey` nor `recipient-ecdh-pubkey`
    // path entries.
    fn set_recipient_enc_key(&mut self, raw_mlkem_ek: Vec<u8>) {
        self.pqc.set_recipient_enc_key(raw_mlkem_ek);
    }

    fn set_recipient_hybrid_key(&mut self, p256_spki_der: Vec<u8>) {
        self.ecc.set_recipient_hybrid_key(p256_spki_der);
    }

    fn generate_encryption_key_pair(
        &self,
        key_paths: &HashMap<String, String>,
        passphrase: Option<&str>,
        force: bool,
    ) -> Result<()> {
        let mut ecc_paths = key_paths.clone();
        let mut pqc_paths = key_paths.clone();

        let ecc_pub = key_paths
            .get("public-ecdh-key")
            .cloned()
            .unwrap_or_else(|| {
                key_paths
                    .get("public-key")
                    .cloned()
                    .unwrap_or_default()
                    .replace(".key", "_ecdh.key")
            });
        let ecc_priv = key_paths
            .get("private-ecdh-key")
            .cloned()
            .unwrap_or_else(|| {
                key_paths
                    .get("private-key")
                    .cloned()
                    .unwrap_or_default()
                    .replace(".key", "_ecdh.key")
            });
        ecc_paths.insert("public-key".to_string(), ecc_pub);
        ecc_paths.insert("private-key".to_string(), ecc_priv);

        let pqc_pub = key_paths
            .get("public-mlkem-key")
            .cloned()
            .unwrap_or_else(|| {
                key_paths
                    .get("public-key")
                    .cloned()
                    .unwrap_or_default()
                    .replace(".key", "_mlkem.key")
            });
        let pqc_priv = key_paths
            .get("private-mlkem-key")
            .cloned()
            .unwrap_or_else(|| {
                key_paths
                    .get("private-key")
                    .cloned()
                    .unwrap_or_default()
                    .replace(".key", "_mlkem.key")
            });
        pqc_paths.insert("public-key".to_string(), pqc_pub);
        pqc_paths.insert("private-key".to_string(), pqc_priv);

        self.ecc.generate_encryption_key_pair(&ecc_paths, passphrase, force)?;
        self.pqc.generate_encryption_key_pair(&pqc_paths, passphrase, force)
    }

    fn generate_signing_key_pair(
        &self,
        key_paths: &HashMap<String, String>,
        passphrase: Option<&str>,
        force: bool,
    ) -> Result<()> {
        self.pqc.generate_signing_key_pair(key_paths, passphrase, force)
    }

    fn regenerate_public_key(
        &self,
        priv_path: &Path,
        pub_path: &Path,
        passphrase: &mut Option<Zeroizing<String>>,
        force: bool,
    ) -> Result<()> {
        // For hybrid, we typically only regenerate the PQC part for signing,
        // or we don't have a clear single path.
        // Here we delegate to PQC strategy as a default.
        self.pqc
            .regenerate_public_key(priv_path, pub_path, passphrase, force)
    }

    fn prepare_encryption(&mut self, key_paths: &HashMap<String, String>) -> Result<()> {
        let mut ecc_paths = key_paths.clone();
        let mut pqc_paths = key_paths.clone();
        if let Some(p) = key_paths.get("recipient-ecdh-pubkey") {
            ecc_paths.insert("recipient-pubkey".to_string(), p.clone());
        }
        if let Some(p) = key_paths.get("recipient-mlkem-pubkey") {
            pqc_paths.insert("recipient-pubkey".to_string(), p.clone());
        }

        self.ecc.prepare_shared_secret_encryption(&ecc_paths)?;
        self.pqc.prepare_shared_secret_encryption(&pqc_paths)?;

        let ss_ecc = self.ecc.take_shared_secret();
        let ss_pqc = self.pqc.take_shared_secret();
        let mut combined_ss = crate::utils::SecureBuffer::new(ss_ecc.len() + ss_pqc.len())?;
        combined_ss[..ss_ecc.len()].copy_from_slice(&ss_ecc);
        combined_ss[ss_ecc.len()..].copy_from_slice(&ss_pqc);

        self.salt = self.ecc.get_salt();
        self.iv = self.ecc.get_iv();

        self.encryption_key = v3::hkdf_expand(&combined_ss, &self.salt, v3::V3_INFO_ENC_KEY, 32)?;
        self.nonce_prefix = v3::hkdf_expand(
            &combined_ss,
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
        let mut ecc_paths = key_paths.clone();
        let mut pqc_paths = key_paths.clone();
        if let Some(p) = key_paths.get("user-ecdh-privkey") {
            ecc_paths.insert("user-privkey".to_string(), p.clone());
        }
        if let Some(p) = key_paths.get("user-mlkem-privkey") {
            pqc_paths.insert("user-privkey".to_string(), p.clone());
        }

        self.ecc
            .prepare_shared_secret_decryption(&ecc_paths, passphrase)?;
        self.pqc
            .prepare_shared_secret_decryption(&pqc_paths, passphrase)?;

        let ss_ecc = self.ecc.take_shared_secret();
        let ss_pqc = self.pqc.take_shared_secret();
        let mut combined_ss = crate::utils::SecureBuffer::new(ss_ecc.len() + ss_pqc.len())?;
        combined_ss[..ss_ecc.len()].copy_from_slice(&ss_ecc);
        combined_ss[ss_ecc.len()..].copy_from_slice(&ss_pqc);

        self.encryption_key = v3::hkdf_expand(&combined_ss, &self.salt, v3::V3_INFO_ENC_KEY, 32)?;
        self.nonce_prefix = v3::hkdf_expand(
            &combined_ss,
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
        self.pqc
            .prepare_signing(priv_key_path, passphrase, digest_algo)
    }

    fn prepare_verification(&mut self, pub_key_path: &Path, digest_algo: &str) -> Result<()> {
        self.pqc.prepare_verification(pub_key_path, digest_algo)
    }

    fn update_hash(&mut self, data: &[u8]) -> Result<()> {
        self.pqc.update_hash(data)
    }
    fn sign_hash(&mut self) -> Result<Vec<u8>> {
        self.pqc.sign_hash()
    }
    fn verify_hash(&mut self, signature: &[u8]) -> Result<bool> {
        self.pqc.verify_hash(signature)
    }

    fn sign_full(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        self.pqc.sign_full(message)
    }
    fn verify_full(&mut self, message: &[u8], signature: &[u8]) -> Result<bool> {
        self.pqc.verify_full(message, signature)
    }

    fn serialize_signature_header(&self) -> Vec<u8> {
        self.pqc.serialize_signature_header()
    }
    fn deserialize_signature_header(&mut self, data: &[u8]) -> Result<usize> {
        self.pqc.deserialize_signature_header(data)
    }

    fn get_metadata(&self, _magic: &str) -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("Strategy".to_string(), "Hybrid".to_string());
        m.extend(self.ecc.get_metadata("NKCT"));
        m.extend(self.pqc.get_metadata("NKCT"));
        m
    }

    fn get_header_size(&self) -> usize {
        let size = 4
            + 2
            + 1
            + 4
            + self.ecc.get_header_size()
            + 4
            + self.pqc.get_header_size()
            + 4; // chunk_size u32
        size
    }

    fn serialize_header(&self) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(b"NKCT");
        let outer_version: u16 = 3;
        header.extend_from_slice(&outer_version.to_le_bytes());
        header.push(self.get_strategy_type() as u8);

        let ecc_h = self.ecc.serialize_header();
        header.extend_from_slice(&(ecc_h.len() as u32).to_le_bytes());
        header.extend_from_slice(&ecc_h);

        let pqc_h = self.pqc.serialize_header();
        header.extend_from_slice(&(pqc_h.len() as u32).to_le_bytes());
        header.extend_from_slice(&pqc_h);

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

        let outer_version = u16::from_le_bytes(
            data[4..6]
                .try_into()
                .map_err(|_| CryptoError::FileRead("Invalid version".to_string()))?,
        );
        if outer_version != 3 {
            return Err(CryptoError::FileRead(
                "legacy v1/v2 file format is no longer supported; decrypt it with an older nkCryptoTool release and re-encrypt".into(),
            ));
        }

        let mut pos = 7;
        if data.len() < pos + 4 {
            return Err(CryptoError::FileRead(
                "Header too short for ECC length".to_string(),
            ));
        }
        let ecc_len = u32::from_le_bytes(
            data[pos..pos + 4]
                .try_into()
                .map_err(|_| CryptoError::FileRead("Invalid length".to_string()))?,
        ) as usize;
        pos += 4;

        if data.len() < pos + ecc_len {
            return Err(CryptoError::FileRead(
                "Header too short for ECC data".to_string(),
            ));
        }
        self.ecc.deserialize_header(&data[pos..pos + ecc_len])?;
        pos += ecc_len;

        if data.len() < pos + 4 {
            return Err(CryptoError::FileRead(
                "Header too short for PQC length".to_string(),
            ));
        }
        let pqc_len = u32::from_le_bytes(
            data[pos..pos + 4]
                .try_into()
                .map_err(|_| CryptoError::FileRead("Invalid length".to_string()))?,
        ) as usize;
        pos += 4;

        if data.len() < pos + pqc_len {
            return Err(CryptoError::FileRead(
                "Header too short for PQC data".to_string(),
            ));
        }
        self.pqc.deserialize_header(&data[pos..pos + pqc_len])?;
        pos += pqc_len;

        // v3 trailer: chunk_size (u32).
        if data.len() < pos + 4 {
            return Err(CryptoError::FileRead(
                "v3 hybrid header missing chunk_size".to_string(),
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

        self.salt = self.ecc.get_salt();
        self.iv = self.ecc.get_iv();
        Ok(pos)
    }

    fn get_tag_size(&self) -> usize {
        16
    }
    fn get_shared_secret(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(Vec::new())
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
        hybrid_v3_encrypt_chunk(
            &self.aead_algo_v3,
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
        hybrid_v3_decrypt_chunk(
            &self.aead_algo_v3,
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
            &self.aead_algo_v3,
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

fn hybrid_v3_encrypt_chunk(
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

fn hybrid_v3_decrypt_chunk(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::strategy::CryptoStrategy;

    #[test]
    fn test_hybrid_deserialize_header_short() {
        let mut strategy = HybridStrategy::new();
        // 7 bytes v3 header (magic + version 3 + strategy): too short for the
        // ECC length field that follows.
        let data = b"NKCT\x03\x00\x02";
        let res = strategy.deserialize_header(data);
        assert!(res.is_err());
        if let Err(e) = res {
            assert!(e.to_string().contains("Header too short"));
        }

        // 11 bytes v3 header (enough for magic/version, but not enough for
        // the ECC/PQC bodies the lengths point at).
        let data = b"NKCT\x03\x00\x02\x00\x00\x00\x00";
        let res = strategy.deserialize_header(data);
        assert!(res.is_err());
    }

    #[test]
    fn test_hybrid_deserialize_header_rejects_legacy_version() {
        let mut strategy = HybridStrategy::new();
        // Legacy outer version 1 is no longer accepted.
        let data = b"NKCT\x01\x00\x03\x00\x00\x00\x00";
        let res = strategy.deserialize_header(data);
        assert!(res.is_err());
        if let Err(e) = res {
            assert!(e.to_string().contains("no longer supported"));
        }
    }
}
