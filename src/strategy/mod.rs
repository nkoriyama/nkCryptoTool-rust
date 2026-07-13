/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

use crate::error::Result;
use crate::key::SharedKeyProvider;
use std::collections::HashMap;
use std::path::Path;
use zeroize::Zeroizing;

pub mod ecc;
pub mod hybrid;
pub mod pqc;
pub mod streaming_aead;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrategyType {
    ECC = 1,
    PQC = 2,
    Hybrid = 3,
}

pub trait CryptoStrategy: Send + Sync {
    fn get_strategy_type(&self) -> StrategyType;

    fn set_key_provider(&mut self, provider: SharedKeyProvider);

    // Key Generation
    fn generate_encryption_key_pair(
        &self,
        key_paths: &HashMap<String, String>,
        passphrase: Option<&str>,
        force: bool,
    ) -> Result<()>;
    fn generate_signing_key_pair(
        &self,
        key_paths: &HashMap<String, String>,
        passphrase: Option<&str>,
        force: bool,
    ) -> Result<()>;
    fn regenerate_public_key(
        &self,
        priv_path: &Path,
        pub_path: &Path,
        passphrase: &mut Option<Zeroizing<String>>,
        force: bool,
    ) -> Result<()> {
        let _ = (priv_path, pub_path, passphrase, force);
        Err(crate::error::CryptoError::Parameter(
            "Not implemented".to_string(),
        ))
    }

    // Encryption / Decryption Pipeline
    fn prepare_encryption(&mut self, key_paths: &HashMap<String, String>) -> Result<()>;
    fn prepare_decryption(
        &mut self,
        key_paths: &HashMap<String, String>,
        passphrase: &mut Option<Zeroizing<String>>,
    ) -> Result<()>;

    // Signing / Verification
    fn prepare_signing(
        &mut self,
        priv_key_path: &Path,
        passphrase: &mut Option<Zeroizing<String>>,
        digest_algo: &str,
    ) -> Result<()>;
    fn prepare_verification(&mut self, pub_key_path: &Path, digest_algo: &str) -> Result<()>;

    fn update_hash(&mut self, data: &[u8]) -> Result<()>;
    fn sign_hash(&mut self) -> Result<Vec<u8>>;
    fn verify_hash(&mut self, signature: &[u8]) -> Result<bool>;

    fn sign_full(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        self.update_hash(message)?;
        self.sign_hash()
    }
    fn verify_full(&mut self, message: &[u8], signature: &[u8]) -> Result<bool> {
        self.update_hash(message)?;
        self.verify_hash(signature)
    }

    // Header Serialization
    fn serialize_signature_header(&self) -> Vec<u8>;
    fn deserialize_signature_header(&mut self, data: &[u8]) -> Result<usize>;

    fn get_metadata(&self, magic: &str) -> HashMap<String, String>;
    fn get_header_size(&self) -> usize;
    fn serialize_header(&self) -> Vec<u8>;
    fn deserialize_header(&mut self, data: &[u8]) -> Result<usize>;
    fn get_tag_size(&self) -> usize;

    // Internal state access for hybrid
    fn get_shared_secret(&self) -> Zeroizing<Vec<u8>>;
    fn get_salt(&self) -> Vec<u8>;
    fn get_iv(&self) -> Vec<u8>;

    // ---- v3 chunked-AEAD hooks ----

    /// Chunk size that this strategy will use for v3 encrypt or has decoded
    /// from a v3 header. Returns `streaming_aead::V3_DEFAULT_CHUNK_SIZE` by
    /// default.
    fn chunk_size(&self) -> u32 {
        streaming_aead::V3_DEFAULT_CHUNK_SIZE
    }

    /// Sets the chunk size to use for v3 encrypt operations.
    fn set_chunk_size(&mut self, _size: u32) {}

    /// Inject the recipient's raw ML-KEM encapsulation key, already
    /// authenticated in memory from a verified NKKB KeyBundle. When set,
    /// `prepare_encryption` uses these bytes directly and skips reading a
    /// `recipient-*-pubkey` PEM file — no recipient pubkey touches disk.
    /// Default no-op: strategies that do not perform ML-KEM ignore it.
    fn set_recipient_enc_key(&mut self, _raw_mlkem_ek: Vec<u8>) {}

    /// Inject the recipient's P-256 public key as SubjectPublicKeyInfo DER,
    /// already authenticated in memory from a verified NKKB KeyBundle. Default
    /// no-op: strategies that do not perform P-256 ECDH ignore it.
    fn set_recipient_hybrid_key(&mut self, _p256_spki_der: Vec<u8>) {}

    /// Inject the user's own private key as its passphrase-encrypted PKCS#8
    /// **PEM text** (keyring my-identities auto-match). When set,
    /// `prepare_decryption` uses it directly and skips reading the
    /// `user-privkey` file. For PQC this is the ML-KEM key, for pure ECC the
    /// P-256 key, for Hybrid the ML-KEM half. Default no-op.
    fn set_user_enc_privkey_pem(&mut self, _pem: Zeroizing<String>) {}

    /// Hybrid only: inject the P-256 ECDH half of the user's key pair, same
    /// form as [`CryptoStrategy::set_user_enc_privkey_pem`]. Default no-op.
    fn set_user_hybrid_privkey_pem(&mut self, _pem: Zeroizing<String>) {}

    /// Returns the SHA-256(header_bytes)[..16] file session ID. Available
    /// only after `prepare_encryption` or after `deserialize_header` has
    /// consumed a v3 header.
    fn file_session_id(&self) -> Option<[u8; streaming_aead::V3_SESSION_ID_LEN]> {
        None
    }

    /// Stores the SHA-256-derived file session ID. Processor calls this
    /// after serialize_header (encrypt path) or deserialize_header (decrypt
    /// path) with the SHA-256 of the exact header bytes.
    fn set_file_session_id(&mut self, _sid: [u8; streaming_aead::V3_SESSION_ID_LEN]) {}

    /// Returns the 8-byte HKDF-derived nonce prefix for v3.
    fn nonce_prefix(&self) -> Option<[u8; streaming_aead::V3_NONCE_PREFIX_LEN]> {
        None
    }

    /// Encrypts one v3 chunk. Returns ciphertext || tag.
    /// `is_final` controls the AAD Flags byte.
    fn encrypt_chunk_v3(&mut self, _plaintext: &[u8], _is_final: bool) -> Result<Vec<u8>> {
        Err(crate::error::CryptoError::Parameter(
            "v3 chunked encrypt not supported by this strategy".to_string(),
        ))
    }

    /// Decrypts one v3 chunk. `ciphertext_and_tag` is the on-wire payload
    /// for the chunk (ciphertext bytes followed by the 16-byte tag).
    fn decrypt_chunk_v3(
        &mut self,
        _ciphertext_and_tag: &[u8],
        _is_final: bool,
    ) -> Result<Zeroizing<Vec<u8>>> {
        Err(crate::error::CryptoError::Parameter(
            "v3 chunked decrypt not supported by this strategy".to_string(),
        ))
    }

    /// Decrypts one v3 chunk into the caller-provided `out` buffer (reusing
    /// its allocation across chunks) instead of returning a fresh buffer.
    /// The default falls back to the allocating `decrypt_chunk_v3`; strategies
    /// that support v3 override this to avoid the per-chunk allocation and the
    /// per-chunk drop-time zeroize that dominate decrypt on large files.
    fn decrypt_chunk_v3_into(
        &mut self,
        ciphertext_and_tag: &[u8],
        is_final: bool,
        out: &mut Vec<u8>,
    ) -> Result<()> {
        let pt = self.decrypt_chunk_v3(ciphertext_and_tag, is_final)?;
        out.clear();
        out.extend_from_slice(&pt);
        Ok(())
    }

    /// Resets the v3 chunk counter to zero. Used between the two-pass
    /// decrypt passes so that the second pass replays the same chunk
    /// counter sequence as the first pass.
    fn reset_chunk_counter(&mut self) {}
}
