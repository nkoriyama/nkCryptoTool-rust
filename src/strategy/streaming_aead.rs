/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 *
 * Common streaming AEAD processor shared by ECC / PQC / Hybrid strategies.
 *
 * Two modes are supported:
 *   - LegacySingleMessage (v2): one AES-GCM context spanning the whole file,
 *     single trailing tag. Wire-format identical to nkCryptoTool v2.
 *   - ChunkedAead (v3): independent AEAD invocation per chunk with
 *     prefix+counter nonce and AAD = session_id || counter || flags.
 */

use crate::backend::{self, Aead, AeadBackend};
use crate::error::{CryptoError, Result};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[cfg(feature = "backend-rustcrypto")]
use aes_gcm::{
    aead::{Aead as AesAead, KeyInit as AesKeyInit, Payload as AesPayload},
    Aes256Gcm,
};
// On backend-rustcrypto the Aead/KeyInit traits are already in scope via
// the aes-gcm re-exports above (they all come from the same upstream
// `aead` crate). Re-importing the same traits under a ChaCha-prefixed
// alias just triggers an unused-import warning, so the trait imports are
// gated to non-rustcrypto builds where aes-gcm is absent. Payload and
// ChaCha20Poly1305 are distinct types and stay unconditional.
#[cfg(not(feature = "backend-rustcrypto"))]
use chacha20poly1305::aead::{Aead as ChaChaAead, KeyInit as ChaChaKeyInit};
use chacha20poly1305::{aead::Payload as ChaChaPayload, ChaCha20Poly1305};

#[cfg(feature = "backend-rustcrypto")]
use aes_gcm::aead::generic_array::GenericArray as AesGenericArray;
use chacha20poly1305::aead::generic_array::GenericArray as ChaChaGenericArray;

pub const V3_NONCE_PREFIX_LEN: usize = 8;
pub const V3_COUNTER_LEN: usize = 4;
pub const V3_NONCE_LEN: usize = V3_NONCE_PREFIX_LEN + V3_COUNTER_LEN; // 12 bytes
pub const V3_TAG_LEN: usize = 16;
pub const V3_SESSION_ID_LEN: usize = 16;
pub const V3_FLAG_INTERMEDIATE: u8 = 0x00;
pub const V3_FLAG_FINAL: u8 = 0x01;
pub const V3_DEFAULT_CHUNK_SIZE: u32 = 1024 * 1024;

/// HKDF info labels for v3 derivation.
pub const V3_INFO_ENC_KEY: &[u8] = b"nkct-v3-enc-key";
pub const V3_INFO_NONCE_PREFIX: &[u8] = b"nkct-v3-nonce-prefix";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamingMode {
    LegacySingleMessage,
    ChunkedAead,
}

impl Default for StreamingMode {
    fn default() -> Self {
        StreamingMode::LegacySingleMessage
    }
}

/// Wraps the legacy single-message AEAD context used by v2.
pub struct StreamingAeadProcessor {
    aead_algo: String,
    encryption_key: Zeroizing<Vec<u8>>,
    iv: Vec<u8>,
    aead_ctx: Option<Aead>,
}

impl Zeroize for StreamingAeadProcessor {
    fn zeroize(&mut self) {
        self.encryption_key.zeroize();
        self.iv.zeroize();
        // aead_ctx is zeroized via its own Drop.
    }
}

impl ZeroizeOnDrop for StreamingAeadProcessor {}

impl Drop for StreamingAeadProcessor {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl StreamingAeadProcessor {
    pub fn new_encrypt(aead_algo: &str, key: &[u8], iv: &[u8]) -> Result<Self> {
        let ctx = backend::new_encrypt(aead_algo, key, iv)?;
        Ok(Self {
            aead_algo: aead_algo.to_string(),
            encryption_key: Zeroizing::new(key.to_vec()),
            iv: iv.to_vec(),
            aead_ctx: Some(ctx),
        })
    }

    pub fn new_decrypt(aead_algo: &str, key: &[u8], iv: &[u8]) -> Result<Self> {
        let ctx = backend::new_decrypt(aead_algo, key, iv)?;
        Ok(Self {
            aead_algo: aead_algo.to_string(),
            encryption_key: Zeroizing::new(key.to_vec()),
            iv: iv.to_vec(),
            aead_ctx: Some(ctx),
        })
    }

    pub fn aead_algo(&self) -> &str {
        &self.aead_algo
    }

    pub fn encryption_key(&self) -> &[u8] {
        &self.encryption_key
    }

    pub fn encrypt_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize> {
        let ctx = self
            .aead_ctx
            .as_mut()
            .ok_or(CryptoError::Parameter("AEAD context not initialized".to_string()))?;
        ctx.update(input, output)
    }

    pub fn decrypt_into(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize> {
        let ctx = self
            .aead_ctx
            .as_mut()
            .ok_or(CryptoError::Parameter("AEAD context not initialized".to_string()))?;
        ctx.update(input, output)
    }

    pub fn finalize_encryption(&mut self) -> Result<Vec<u8>> {
        let ctx = self
            .aead_ctx
            .as_mut()
            .ok_or(CryptoError::Parameter("AEAD context not initialized".to_string()))?;
        let mut out = vec![0u8; 16];
        let n = ctx.finalize(&mut out)?;
        out.truncate(n);
        let mut tag = vec![0u8; 16];
        ctx.get_tag(&mut tag)?;
        out.extend_from_slice(&tag);
        Ok(out)
    }

    pub fn finalize_decryption(&mut self, tag: &[u8]) -> Result<()> {
        let ctx = self
            .aead_ctx
            .as_mut()
            .ok_or(CryptoError::Parameter("AEAD context not initialized".to_string()))?;
        ctx.set_tag(tag)?;
        let mut out = vec![0u8; 16];
        ctx.finalize(&mut out)
            .map_err(|_| CryptoError::SignatureVerification)?;
        Ok(())
    }

    pub fn restart_decryption(&mut self) -> Result<()> {
        if self.encryption_key.is_empty() {
            return Err(CryptoError::Parameter("Key not set".to_string()));
        }
        let ctx = backend::new_decrypt(&self.aead_algo, &self.encryption_key, &self.iv)?;
        self.aead_ctx = Some(ctx);
        Ok(())
    }
}

/// One-shot AEAD encryption with AAD for v3 chunks. Returns ciphertext || tag.
pub fn aead_encrypt_chunk(
    aead_algo: &str,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    if nonce.len() != V3_NONCE_LEN {
        return Err(CryptoError::Parameter(format!(
            "v3 nonce must be {} bytes",
            V3_NONCE_LEN
        )));
    }
    match aead_algo.to_lowercase().as_str() {
        "aes-256-gcm" => aes_gcm_encrypt(key, nonce, aad, plaintext),
        "chacha20-poly1305" => {
            let cipher = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|e| CryptoError::OpenSSL(format!("ChaCha20-Poly1305 key: {}", e)))?;
            let nonce_arr = ChaChaGenericArray::from_slice(nonce);
            cipher
                .encrypt(nonce_arr, ChaChaPayload { msg: plaintext, aad })
                .map_err(|_| CryptoError::OpenSSL("ChaCha20-Poly1305 encrypt failed".to_string()))
        }
        other => Err(CryptoError::Parameter(format!(
            "Unsupported v3 cipher: {}",
            other
        ))),
    }
}

/// One-shot AEAD decryption with AAD for v3 chunks. Input is ciphertext || tag.
pub fn aead_decrypt_chunk(
    aead_algo: &str,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if nonce.len() != V3_NONCE_LEN {
        return Err(CryptoError::Parameter(format!(
            "v3 nonce must be {} bytes",
            V3_NONCE_LEN
        )));
    }
    if ciphertext_and_tag.len() < V3_TAG_LEN {
        return Err(CryptoError::FileRead(
            "v3 chunk shorter than tag length".to_string(),
        ));
    }
    let pt = match aead_algo.to_lowercase().as_str() {
        "aes-256-gcm" => aes_gcm_decrypt(key, nonce, aad, ciphertext_and_tag)?,
        "chacha20-poly1305" => {
            let cipher = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|e| CryptoError::OpenSSL(format!("ChaCha20-Poly1305 key: {}", e)))?;
            let nonce_arr = ChaChaGenericArray::from_slice(nonce);
            cipher
                .decrypt(
                    nonce_arr,
                    ChaChaPayload {
                        msg: ciphertext_and_tag,
                        aad,
                    },
                )
                .map_err(|_| CryptoError::SignatureVerification)?
        }
        other => {
            return Err(CryptoError::Parameter(format!(
                "Unsupported v3 cipher: {}",
                other
            )))
        }
    };
    Ok(Zeroizing::new(pt))
}

/// Like `aead_decrypt_chunk` but writes the plaintext into `out` (reusing its
/// allocation) instead of returning a fresh buffer. The default AES-256-GCM
/// (OpenSSL) path decrypts straight into `out` with no per-chunk allocation;
/// other ciphers fall back to the allocating path plus a copy. `out` must be
/// owned by a `Zeroizing` buffer at the call site so its capacity is wiped on
/// drop — this function does not zeroize it.
pub fn aead_decrypt_chunk_into(
    aead_algo: &str,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
    out: &mut Vec<u8>,
) -> Result<()> {
    if nonce.len() != V3_NONCE_LEN {
        return Err(CryptoError::Parameter(format!(
            "v3 nonce must be {} bytes",
            V3_NONCE_LEN
        )));
    }
    if ciphertext_and_tag.len() < V3_TAG_LEN {
        return Err(CryptoError::FileRead(
            "v3 chunk shorter than tag length".to_string(),
        ));
    }
    #[cfg(all(not(feature = "backend-rustcrypto"), feature = "backend-openssl"))]
    {
        if aead_algo.eq_ignore_ascii_case("aes-256-gcm") {
            return aes_gcm_decrypt_into(key, nonce, aad, ciphertext_and_tag, out);
        }
    }
    // Fallback (ChaCha20-Poly1305, RustCrypto backend, etc.): use the
    // allocating primitive then move the bytes into `out`.
    let pt = aead_decrypt_chunk(aead_algo, key, nonce, aad, ciphertext_and_tag)?;
    out.clear();
    out.extend_from_slice(&pt);
    Ok(())
}

/// Builds the nonce/AAD for chunk `*counter`, decrypts into `out`, then bumps
/// the counter. Buffer-reusing counterpart of the per-strategy
/// `*_decrypt_chunk` helpers; shared by ECC / PQC / Hybrid.
#[allow(clippy::too_many_arguments)]
pub fn decrypt_chunk_v3_into(
    aead_algo: &str,
    key: &[u8],
    nonce_prefix: &[u8],
    sid: Option<&[u8; V3_SESSION_ID_LEN]>,
    counter: &mut u32,
    ciphertext_and_tag: &[u8],
    is_final: bool,
    out: &mut Vec<u8>,
) -> Result<()> {
    if nonce_prefix.len() != V3_NONCE_PREFIX_LEN {
        return Err(CryptoError::Parameter(
            "v3 nonce prefix not initialized".to_string(),
        ));
    }
    let sid = sid.ok_or(CryptoError::Parameter(
        "v3 file session id not set".to_string(),
    ))?;
    let nonce = build_nonce(nonce_prefix, *counter);
    let flags = if is_final {
        V3_FLAG_FINAL
    } else {
        V3_FLAG_INTERMEDIATE
    };
    let aad = build_aad(sid, *counter, flags);
    aead_decrypt_chunk_into(aead_algo, key, &nonce, &aad, ciphertext_and_tag, out)?;
    *counter = counter.checked_add(1).ok_or(CryptoError::CounterOverflow)?;
    Ok(())
}

#[cfg(feature = "backend-rustcrypto")]
fn aes_gcm_encrypt(key: &[u8], nonce: &[u8], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| CryptoError::OpenSSL(format!("AES-256-GCM key: {}", e)))?;
    let nonce_arr = AesGenericArray::from_slice(nonce);
    cipher
        .encrypt(nonce_arr, AesPayload { msg: pt, aad })
        .map_err(|_| CryptoError::OpenSSL("AES-256-GCM encrypt failed".to_string()))
}

#[cfg(feature = "backend-rustcrypto")]
fn aes_gcm_decrypt(key: &[u8], nonce: &[u8], aad: &[u8], ct_tag: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| CryptoError::OpenSSL(format!("AES-256-GCM key: {}", e)))?;
    let nonce_arr = AesGenericArray::from_slice(nonce);
    cipher
        .decrypt(nonce_arr, AesPayload { msg: ct_tag, aad })
        .map_err(|_| CryptoError::SignatureVerification)
}

#[cfg(all(not(feature = "backend-rustcrypto"), feature = "backend-openssl"))]
fn aes_gcm_encrypt(key: &[u8], nonce: &[u8], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
    use openssl::cipher::Cipher;
    use openssl::cipher_ctx::CipherCtx;
    let mut ctx = CipherCtx::new().map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
    ctx.encrypt_init(Some(Cipher::aes_256_gcm()), None, None)
        .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
    ctx.set_iv_length(nonce.len())
        .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
    ctx.encrypt_init(None, Some(key), Some(nonce))
        .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
    if !aad.is_empty() {
        ctx.cipher_update(aad, None)
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
    }
    let mut out = vec![0u8; pt.len() + 16];
    let n = ctx
        .cipher_update(pt, Some(&mut out))
        .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
    let m = ctx
        .cipher_final(&mut out[n..])
        .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
    out.truncate(n + m);
    let mut tag = [0u8; V3_TAG_LEN];
    ctx.tag(&mut tag)
        .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
    out.extend_from_slice(&tag);
    Ok(out)
}

#[cfg(all(not(feature = "backend-rustcrypto"), feature = "backend-openssl"))]
fn aes_gcm_decrypt(key: &[u8], nonce: &[u8], aad: &[u8], ct_tag: &[u8]) -> Result<Vec<u8>> {
    use openssl::cipher::Cipher;
    use openssl::cipher_ctx::CipherCtx;
    let split = ct_tag.len() - V3_TAG_LEN;
    let ct = &ct_tag[..split];
    let tag = &ct_tag[split..];
    let mut ctx = CipherCtx::new().map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
    ctx.decrypt_init(Some(Cipher::aes_256_gcm()), None, None)
        .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
    ctx.set_iv_length(nonce.len())
        .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
    ctx.decrypt_init(None, Some(key), Some(nonce))
        .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
    if !aad.is_empty() {
        ctx.cipher_update(aad, None)
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
    }
    ctx.set_tag(tag)
        .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
    let mut out = vec![0u8; ct.len() + 16];
    let n = ctx
        .cipher_update(ct, Some(&mut out))
        .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
    let m = ctx
        .cipher_final(&mut out[n..])
        .map_err(|_| CryptoError::SignatureVerification)?;
    out.truncate(n + m);
    Ok(out)
}

#[cfg(all(not(feature = "backend-rustcrypto"), feature = "backend-openssl"))]
fn aes_gcm_decrypt_into(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ct_tag: &[u8],
    out: &mut Vec<u8>,
) -> Result<()> {
    use openssl::cipher::Cipher;
    use openssl::cipher_ctx::CipherCtx;
    let split = ct_tag.len() - V3_TAG_LEN;
    let ct = &ct_tag[..split];
    let tag = &ct_tag[split..];
    let mut ctx = CipherCtx::new().map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
    ctx.decrypt_init(Some(Cipher::aes_256_gcm()), None, None)
        .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
    ctx.set_iv_length(nonce.len())
        .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
    ctx.decrypt_init(None, Some(key), Some(nonce))
        .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
    if !aad.is_empty() {
        ctx.cipher_update(aad, None)
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
    }
    ctx.set_tag(tag)
        .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
    // GCM output length equals the ciphertext length; grow `out` only when a
    // chunk is larger than any seen so far (the newly grown tail is the only
    // region zero-filled, the rest is overwritten by cipher_update below).
    let needed = ct.len() + V3_TAG_LEN;
    if out.len() < needed {
        out.resize(needed, 0);
    }
    let n = ctx
        .cipher_update(ct, Some(&mut out[..]))
        .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
    let m = ctx
        .cipher_final(&mut out[n..])
        .map_err(|_| CryptoError::SignatureVerification)?;
    out.truncate(n + m);
    Ok(())
}

#[cfg(not(any(feature = "backend-rustcrypto", feature = "backend-openssl")))]
fn aes_gcm_encrypt(_key: &[u8], _nonce: &[u8], _aad: &[u8], _pt: &[u8]) -> Result<Vec<u8>> {
    Err(CryptoError::Parameter(
        "No AEAD backend enabled for v3 chunks".to_string(),
    ))
}

#[cfg(not(any(feature = "backend-rustcrypto", feature = "backend-openssl")))]
fn aes_gcm_decrypt(_key: &[u8], _nonce: &[u8], _aad: &[u8], _ct_tag: &[u8]) -> Result<Vec<u8>> {
    Err(CryptoError::Parameter(
        "No AEAD backend enabled for v3 chunks".to_string(),
    ))
}

/// Computes the File Session ID = SHA-256(header_bytes)[..16].
pub fn compute_session_id(header_bytes: &[u8]) -> [u8; V3_SESSION_ID_LEN] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(header_bytes);
    let digest = hasher.finalize();
    let mut id = [0u8; V3_SESSION_ID_LEN];
    id.copy_from_slice(&digest[..V3_SESSION_ID_LEN]);
    id
}

/// Builds the 12-byte v3 nonce from 8-byte prefix + 4-byte big-endian counter.
pub fn build_nonce(prefix: &[u8], counter: u32) -> [u8; V3_NONCE_LEN] {
    assert_eq!(prefix.len(), V3_NONCE_PREFIX_LEN);
    let mut nonce = [0u8; V3_NONCE_LEN];
    nonce[..V3_NONCE_PREFIX_LEN].copy_from_slice(prefix);
    nonce[V3_NONCE_PREFIX_LEN..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

/// Builds the v3 AAD = session_id (16) || counter (4 BE) || flags (1).
pub fn build_aad(session_id: &[u8], counter: u32, flags: u8) -> Vec<u8> {
    assert_eq!(session_id.len(), V3_SESSION_ID_LEN);
    let mut aad = Vec::with_capacity(V3_SESSION_ID_LEN + V3_COUNTER_LEN + 1);
    aad.extend_from_slice(session_id);
    aad.extend_from_slice(&counter.to_be_bytes());
    aad.push(flags);
    aad
}

/// HKDF-Expand a single PRK into a key with the given info label.
/// Uses SHA3-256 to match the rest of the project's HKDF use.
pub fn hkdf_expand(prk_secret: &[u8], salt: &[u8], info: &[u8], out_len: usize) -> Result<Zeroizing<Vec<u8>>> {
    use hkdf::Hkdf;
    use sha3::Sha3_256;
    let mut okm = Zeroizing::new(vec![0u8; out_len]);
    let hk = Hkdf::<Sha3_256>::new(Some(salt), prk_secret);
    hk.expand(info, &mut *okm)
        .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
    drop(hk);
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_id_is_first_16_bytes_of_sha256() {
        let id = compute_session_id(b"hello");
        // Known: SHA-256("hello") starts with 2cf24dba5fb0a30e26e83b2ac5b9e29e
        let expected = hex::decode("2cf24dba5fb0a30e26e83b2ac5b9e29e").unwrap();
        assert_eq!(&id[..], &expected[..]);
    }

    #[test]
    fn nonce_layout_is_prefix_plus_be_counter() {
        let prefix = [0xAA; V3_NONCE_PREFIX_LEN];
        let nonce = build_nonce(&prefix, 0x01020304);
        assert_eq!(&nonce[..V3_NONCE_PREFIX_LEN], &prefix);
        assert_eq!(&nonce[V3_NONCE_PREFIX_LEN..], &[0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn aad_layout_is_session_id_counter_flags() {
        let sid = [0x55u8; V3_SESSION_ID_LEN];
        let aad = build_aad(&sid, 0x10203040, V3_FLAG_FINAL);
        assert_eq!(aad.len(), V3_SESSION_ID_LEN + V3_COUNTER_LEN + 1);
        assert_eq!(&aad[..V3_SESSION_ID_LEN], &sid);
        assert_eq!(
            &aad[V3_SESSION_ID_LEN..V3_SESSION_ID_LEN + V3_COUNTER_LEN],
            &[0x10, 0x20, 0x30, 0x40]
        );
        assert_eq!(aad[V3_SESSION_ID_LEN + V3_COUNTER_LEN], V3_FLAG_FINAL);
    }

    #[test]
    fn aes_gcm_chunk_roundtrip_with_aad() {
        let key = [7u8; 32];
        let nonce = build_nonce(&[3u8; 8], 42);
        let aad = b"some-aad-bytes";
        let pt = b"the quick brown fox jumps over the lazy dog";
        let ct = aead_encrypt_chunk("AES-256-GCM", &key, &nonce, aad, pt).unwrap();
        // ct = ciphertext || 16B tag, so it must be pt.len() + 16
        assert_eq!(ct.len(), pt.len() + V3_TAG_LEN);
        let pt2 = aead_decrypt_chunk("AES-256-GCM", &key, &nonce, aad, &ct).unwrap();
        assert_eq!(&pt2[..], pt);
    }

    #[test]
    fn aes_gcm_chunk_aad_tamper_fails() {
        let key = [9u8; 32];
        let nonce = build_nonce(&[1u8; 8], 0);
        let ct =
            aead_encrypt_chunk("AES-256-GCM", &key, &nonce, b"aadA", b"payload").unwrap();
        assert!(aead_decrypt_chunk("AES-256-GCM", &key, &nonce, b"aadB", &ct).is_err());
    }

    #[test]
    fn chacha_chunk_roundtrip_with_aad() {
        let key = [1u8; 32];
        let nonce = build_nonce(&[2u8; 8], 7);
        let aad = b"chacha-aad";
        let pt = b"streaming-aead chacha test";
        let ct = aead_encrypt_chunk("ChaCha20-Poly1305", &key, &nonce, aad, pt).unwrap();
        let pt2 = aead_decrypt_chunk("ChaCha20-Poly1305", &key, &nonce, aad, &ct).unwrap();
        assert_eq!(&pt2[..], pt);
    }
}
