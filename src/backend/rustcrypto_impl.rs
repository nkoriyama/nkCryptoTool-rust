/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

use crate::backend::{AeadBackend, HashBackend};
use crate::error::{CryptoError, Result};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[cfg(feature = "backend-rustcrypto")]
use fips203::traits::{Decaps as _, Encaps as _, KeyGen as _, SerDes as _};
#[cfg(feature = "backend-rustcrypto")]
use fips204::traits::{KeyGen as _, SerDes as _, Signer as _, Verifier as _};

#[cfg(feature = "backend-rustcrypto")]
mod rc_internal {
    pub use p256::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
    pub use pkcs8::der::Decode;
    pub use p256::{PublicKey, SecretKey};
    pub use rand_core::OsRng;
    pub use sha3::{Digest, Sha3_256, Sha3_512};

    pub use aes::{
        cipher::{BlockEncrypt, KeyInit as _, KeyIvInit, StreamCipher},
        Aes256,
    };
    pub use aes_gcm::aead::consts;
    pub use ctr::Ctr64BE;
    pub use generic_array::GenericArray;
    pub use ghash::{
        universal_hash::{KeyInit as _, UniversalHash},
        GHash,
    };
    pub use subtle::ConstantTimeEq;

    pub use chacha20::ChaCha20;
    pub use poly1305::Poly1305;

    pub use p256::ecdsa::{
        signature::hazmat::{PrehashSigner, PrehashVerifier},
        Signature, SigningKey, VerifyingKey,
    };
}

pub type Aead = RustCryptoAead;
pub type Hash = RustCryptoHash;

#[cfg(feature = "backend-rustcrypto")]
fn zeroize_bytes<T>(val: &mut T) {
    let len = std::mem::size_of::<T>();
    if len > 0 {
        // Use the zeroize crate's implementation on a raw byte slice
        // to ensure it's not optimized away.
        let slice = unsafe { std::slice::from_raw_parts_mut(val as *mut T as *mut u8, len) };
        slice.zeroize();
    }
}

#[cfg(feature = "backend-rustcrypto")]
enum AeadMode {
    #[allow(dead_code)]
    Empty,
    AesGcm {
        ctr: rc_internal::Ctr64BE<rc_internal::Aes256>,
        ghash: rc_internal::GHash,
        tag_mask: [u8; 16],
        _cipher_name: String, // Store to support re_init
    },
    ChaChaPoly {
        cipher: rc_internal::ChaCha20,
        poly: rc_internal::Poly1305,
        _cipher_name: String, // Store to support re_init
    },
}

#[cfg(feature = "backend-rustcrypto")]
impl Zeroize for AeadMode {
    fn zeroize(&mut self) {
        match self {
            AeadMode::AesGcm {
                ctr,
                ghash,
                tag_mask,
                ..
            } => {
                zeroize_bytes(ctr);
                zeroize_bytes(ghash);
                tag_mask.zeroize();
            }
            AeadMode::ChaChaPoly { cipher, poly, .. } => {
                zeroize_bytes(cipher);
                zeroize_bytes(poly);
            }
            AeadMode::Empty => {}
        }
    }
}

pub struct RustCryptoAead {
    #[cfg(feature = "backend-rustcrypto")]
    mode: Option<AeadMode>,
    _cipher_name: String, // #27 Fix: Store cipher name to support re_init after finalize
    _iv: Vec<u8>,
    _tag: Vec<u8>,
    _is_encrypt: bool,
    _data_len: u64,
}

impl Zeroize for RustCryptoAead {
    fn zeroize(&mut self) {
        #[cfg(feature = "backend-rustcrypto")]
        if let Some(mut m) = self.mode.take() {
            m.zeroize();
        }
        self._iv.zeroize();
        self._tag.zeroize();
        // _cipher_name is not zeroized as it is not sensitive
    }
}

impl Drop for RustCryptoAead {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for RustCryptoAead {}

impl AeadBackend for RustCryptoAead {
    fn new_encrypt(cipher_name: &str, key: &[u8], iv: &[u8]) -> Result<Self> {
        #[cfg(feature = "backend-rustcrypto")]
        {
            use rc_internal::*;
            let normalized = cipher_name.to_lowercase();
            let mode = if normalized == "aes-256-gcm" {
                let aes =
                    Aes256::new_from_slice(key).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
                let mut h = Zeroizing::new([0u8; 16]); // #26 Fix: Wrap in Zeroizing
                aes.encrypt_block(GenericArray::from_mut_slice(&mut *h));
                let ghash = GHash::new(GenericArray::from_slice(&*h));
                let mut j0 = [0u8; 16];
                j0[..12].copy_from_slice(iv);
                j0[15] = 1;
                let mut tag_mask = j0;
                aes.encrypt_block(GenericArray::from_mut_slice(&mut tag_mask));
                let mut ctr_iv = j0;
                ctr_iv[15] = 2;
                let ctr = Ctr64BE::<Aes256>::new(
                    GenericArray::from_slice(key),
                    GenericArray::from_slice(&ctr_iv),
                );
                AeadMode::AesGcm {
                    ctr,
                    ghash,
                    tag_mask,
                    _cipher_name: normalized.clone(),
                }
            } else if normalized == "chacha20-poly1305" {
                let mut cipher =
                    ChaCha20::new(GenericArray::from_slice(key), GenericArray::from_slice(iv));
                let mut poly_key = Zeroizing::new([0u8; 32]); // #25 Fix: Wrap in Zeroizing
                cipher.apply_keystream(&mut *poly_key);
                let poly = Poly1305::new(GenericArray::from_slice(&*poly_key));
                AeadMode::ChaChaPoly {
                    cipher,
                    poly,
                    _cipher_name: normalized.clone(),
                }
            } else {
                return Err(CryptoError::Parameter(format!(
                    "Unsupported: {}",
                    cipher_name
                )));
            };

            Ok(Self {
                mode: Some(mode),
                _cipher_name: normalized,
                _iv: iv.to_vec(),
                _tag: vec![0u8; 16],
                _is_encrypt: true,
                _data_len: 0,
            })
        }
        #[cfg(not(feature = "backend-rustcrypto"))]
        {
            let _ = (cipher_name, key, iv);
            Err(CryptoError::Parameter(
                "RustCrypto backend not enabled".to_string(),
            ))
        }
    }

    fn new_decrypt(cipher_name: &str, key: &[u8], iv: &[u8]) -> Result<Self> {
        let mut me = Self::new_encrypt(cipher_name, key, iv)?;
        me._is_encrypt = false;
        Ok(me)
    }

    fn re_init(&mut self, key: &[u8], iv: &[u8]) -> Result<()> {
        #[cfg(feature = "backend-rustcrypto")]
        {
            use rc_internal::*;
            if let Some(mut old_mode) = self.mode.take() {
                old_mode.zeroize(); // #25 Fix: Explicitly zeroize old mode before drop
            }
            let cipher_name = self._cipher_name.clone();

            let new_mode = if cipher_name == "aes-256-gcm" {
                let aes =
                    Aes256::new_from_slice(key).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
                let mut h = Zeroizing::new([0u8; 16]); // #26 Fix: Wrap in Zeroizing
                aes.encrypt_block(GenericArray::from_mut_slice(&mut *h));
                let ghash = GHash::new(GenericArray::from_slice(&*h));
                let mut j0 = [0u8; 16];
                j0[..12].copy_from_slice(iv);
                j0[15] = 1;
                let mut tag_mask = j0;
                aes.encrypt_block(GenericArray::from_mut_slice(&mut tag_mask));
                let mut ctr_iv = j0;
                ctr_iv[15] = 2;
                let ctr = Ctr64BE::<Aes256>::new(
                    GenericArray::from_slice(key),
                    GenericArray::from_slice(&ctr_iv),
                );
                AeadMode::AesGcm {
                    ctr,
                    ghash,
                    tag_mask,
                    _cipher_name: cipher_name,
                }
            } else {
                let mut cipher =
                    ChaCha20::new(GenericArray::from_slice(key), GenericArray::from_slice(iv));
                let mut poly_key = Zeroizing::new([0u8; 32]); // #25 Fix: Wrap in Zeroizing
                cipher.apply_keystream(&mut *poly_key);
                let poly = Poly1305::new(GenericArray::from_slice(&*poly_key));
                AeadMode::ChaChaPoly {
                    cipher,
                    poly,
                    _cipher_name: cipher_name,
                }
            };

            self.mode = Some(new_mode);
            self._iv = iv.to_vec();
            self._tag = vec![0u8; 16];
            self._data_len = 0;
            Ok(())
        }
        #[cfg(not(feature = "backend-rustcrypto"))]
        {
            let _ = (key, iv);
            Err(CryptoError::Parameter(
                "RustCrypto backend not enabled".to_string(),
            ))
        }
    }

    fn update(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize> {
        #[cfg(feature = "backend-rustcrypto")]
        {
            use rc_internal::*;
            let mode = self
                .mode
                .as_mut()
                .ok_or(CryptoError::Parameter("AEAD not init".to_string()))?;
            match mode {
                AeadMode::AesGcm { ctr, ghash, .. } => {
                    let mut pos = 0;
                    const CHUNK_SIZE: usize = 128;
                    while pos + CHUNK_SIZE <= input.len() {
                        let in_chunk = &input[pos..pos + CHUNK_SIZE];
                        let out_chunk = &mut output[pos..pos + CHUNK_SIZE];
                        out_chunk.copy_from_slice(in_chunk);
                        ctr.apply_keystream(out_chunk);
                        let aad_or_cipher = if self._is_encrypt {
                            out_chunk
                        } else {
                            in_chunk
                        };
                        ghash.update_padded(aad_or_cipher);
                        pos += CHUNK_SIZE;
                    }
                    if pos < input.len() {
                        let in_rem = &input[pos..];
                        let out_rem = &mut output[pos..pos + in_rem.len()];
                        out_rem.copy_from_slice(in_rem);
                        ctr.apply_keystream(out_rem);
                        let aad_or_cipher = if self._is_encrypt { out_rem } else { in_rem };
                        ghash.update_padded(aad_or_cipher);
                    }
                }
                AeadMode::ChaChaPoly { cipher, poly, .. } => {
                    let out_slice = &mut output[..input.len()];
                    out_slice.copy_from_slice(input);
                    cipher.apply_keystream(out_slice);
                    let aad_or_cipher = if self._is_encrypt { out_slice } else { input };
                    poly.update_padded(aad_or_cipher);
                }
                AeadMode::Empty => {
                    return Err(CryptoError::Parameter("AEAD mode is empty".to_string()))
                }
            }
            self._data_len += input.len() as u64;
            Ok(input.len())
        }
        #[cfg(not(feature = "backend-rustcrypto"))]
        {
            let _ = (input, output);
            Err(CryptoError::Parameter(
                "RustCrypto backend not enabled".to_string(),
            ))
        }
    }

    fn finalize(&mut self, _output: &mut [u8]) -> Result<usize> {
        #[cfg(feature = "backend-rustcrypto")]
        {
            use rc_internal::*;
            let mode = self
                .mode
                .take()
                .ok_or(CryptoError::Parameter("AEAD not init".to_string()))?;
            let res = match mode {
                AeadMode::AesGcm {
                    mut ghash,
                    mut tag_mask,
                    ..
                } => {
                    let mut len_block = [0u8; 16];
                    len_block[8..16].copy_from_slice(&(self._data_len * 8).to_be_bytes());
                    ghash.update(&[*GenericArray::from_slice(&len_block)]);
                    let mut tag = ghash.finalize();
                    for i in 0..16 {
                        tag[i] ^= tag_mask[i];
                    }
                    tag_mask.zeroize();
                    if self._is_encrypt {
                        self._tag = tag.to_vec();
                        Ok(0)
                    } else {
                        let expected_tag = GenericArray::<u8, consts::U16>::from_slice(&self._tag);
                        if tag.ct_eq(expected_tag).unwrap_u8() == 1 {
                            Ok(0)
                        } else {
                            Err(CryptoError::SignatureVerification)
                        }
                    }
                }
                AeadMode::ChaChaPoly { mut poly, .. } => {
                    let mut len_block = [0u8; 16];
                    len_block[8..16].copy_from_slice(&self._data_len.to_le_bytes());
                    poly.update_padded(&len_block);
                    let tag = poly.finalize();
                    if self._is_encrypt {
                        self._tag = tag.to_vec();
                        Ok(0)
                    } else {
                        let expected_tag = GenericArray::<u8, consts::U16>::from_slice(&self._tag);
                        if tag.ct_eq(expected_tag).unwrap_u8() == 1 {
                            Ok(0)
                        } else {
                            Err(CryptoError::SignatureVerification)
                        }
                    }
                }
                AeadMode::Empty => Err(CryptoError::Parameter("AEAD mode is empty".to_string())),
            };
            res
        }
        #[cfg(not(feature = "backend-rustcrypto"))]
        {
            let _ = _output;
            Err(CryptoError::Parameter(
                "RustCrypto backend not enabled".to_string(),
            ))
        }
    }

    fn get_tag(&self, tag: &mut [u8]) -> Result<()> {
        tag.copy_from_slice(&self._tag);
        Ok(())
    }

    fn set_tag(&mut self, tag: &[u8]) -> Result<()> {
        self._tag = tag.to_vec();
        Ok(())
    }
}

pub struct RustCryptoHash {
    #[cfg(feature = "backend-rustcrypto")]
    digest_256: Option<rc_internal::Sha3_256>,
    #[cfg(feature = "backend-rustcrypto")]
    digest_512: Option<rc_internal::Sha3_512>,
}

impl HashBackend for RustCryptoHash {
    fn new(algo: &str) -> Result<Self> {
        #[cfg(feature = "backend-rustcrypto")]
        {
            use rc_internal::*;
            match algo {
                "SHA3-256" => Ok(Self {
                    digest_256: Some(Sha3_256::new()),
                    digest_512: None,
                }),
                "SHA3-512" => Ok(Self {
                    digest_256: None,
                    digest_512: Some(Sha3_512::new()),
                }),
                _ => Err(CryptoError::Parameter(format!(
                    "Unsupported digest: {}",
                    algo
                ))),
            }
        }
        #[cfg(not(feature = "backend-rustcrypto"))]
        {
            let _ = algo;
            Err(CryptoError::Parameter(
                "RustCrypto backend not enabled".to_string(),
            ))
        }
    }

    fn update(&mut self, data: &[u8]) -> Result<()> {
        #[cfg(feature = "backend-rustcrypto")]
        {
            if let Some(d) = &mut self.digest_256 {
                rc_internal::Digest::update(d, data);
            }
            if let Some(d) = &mut self.digest_512 {
                rc_internal::Digest::update(d, data);
            }
            Ok(())
        }
        #[cfg(not(feature = "backend-rustcrypto"))]
        {
            let _ = data;
            Err(CryptoError::Parameter(
                "RustCrypto backend not enabled".to_string(),
            ))
        }
    }

    fn finalize_sign(&mut self, key_der: &[u8]) -> Result<Vec<u8>> {
        #[cfg(feature = "backend-rustcrypto")]
        {
            use rc_internal::*;
            let hash_bytes = if let Some(d) = self.digest_256.take() {
                Zeroizing::new(d.finalize().to_vec())
            } else if let Some(d) = self.digest_512.take() {
                Zeroizing::new(d.finalize().to_vec())
            } else {
                return Err(CryptoError::Parameter("Digest not init".to_string()));
            };

            let sk_raw = SecretKey::from_pkcs8_der(key_der)
                .or_else(|_| SecretKey::from_sec1_der(key_der))
                .map_err(|e| CryptoError::PrivateKeyLoad(e.to_string()))?;
            let sig_key = SigningKey::from(&sk_raw);
            let signature: Signature = sig_key
                .sign_prehash(&hash_bytes)
                .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
            Ok(signature.to_der().to_bytes().to_vec())
        }
        #[cfg(not(feature = "backend-rustcrypto"))]
        {
            let _ = key_der;
            Err(CryptoError::Parameter(
                "RustCrypto backend not enabled".to_string(),
            ))
        }
    }

    fn finalize_verify(&mut self, key_der: &[u8], signature: &[u8]) -> Result<bool> {
        #[cfg(feature = "backend-rustcrypto")]
        {
            use rc_internal::*;
            let hash_bytes = if let Some(d) = self.digest_256.take() {
                Zeroizing::new(d.finalize().to_vec())
            } else if let Some(d) = self.digest_512.take() {
                Zeroizing::new(d.finalize().to_vec())
            } else {
                return Err(CryptoError::Parameter("Digest not init".to_string()));
            };

            let vk = VerifyingKey::from_public_key_der(key_der)
                .map_err(|e| CryptoError::PublicKeyLoad(e.to_string()))?;
            let sig = Signature::from_der(signature)
                .map_err(|e| CryptoError::Parameter(e.to_string()))?;
            Ok(vk.verify_prehash(&hash_bytes, &sig).is_ok())
        }
        #[cfg(not(feature = "backend-rustcrypto"))]
        {
            let _ = (key_der, signature);
            Err(CryptoError::Parameter(
                "RustCrypto backend not enabled".to_string(),
            ))
        }
    }

    fn init_sign(&mut self, _key_der: &[u8], _passphrase: Option<&str>) -> Result<()> {
        Ok(())
    }

    fn init_verify(&mut self, _key_der: &[u8]) -> Result<()> {
        Ok(())
    }
}

pub fn generate_ecc_key_pair(curve_name: &str) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
    #[cfg(feature = "backend-rustcrypto")]
    {
        use rc_internal::*;
        if curve_name != "prime256v1" {
            return Err(CryptoError::Parameter(format!(
                "Unsupported curve: {}",
                curve_name
            )));
        }
        let secret_key = SecretKey::random(&mut OsRng);
        let public_key = secret_key.public_key();

        let priv_der = secret_key
            .to_pkcs8_der()
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        let pub_der = public_key
            .to_public_key_der()
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;

        Ok((
            Zeroizing::new(priv_der.to_bytes().to_vec()),
            pub_der.as_bytes().to_vec(),
        ))
    }
    #[cfg(not(feature = "backend-rustcrypto"))]
    {
        let _ = curve_name;
        Err(CryptoError::Parameter(
            "RustCrypto backend not enabled".to_string(),
        ))
    }
}

pub fn ecc_dh(
    my_priv_der: &[u8],
    peer_pub_der: &[u8],
    _passphrase: Option<&str>,
) -> Result<Zeroizing<Vec<u8>>> {
    #[cfg(feature = "backend-rustcrypto")]
    {
        use rc_internal::*;
        let sk = SecretKey::from_pkcs8_der(my_priv_der)
            .or_else(|_| SecretKey::from_sec1_der(my_priv_der))
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        let pk = PublicKey::from_public_key_der(peer_pub_der)
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        let shared_secret = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
        Ok(Zeroizing::new(shared_secret.raw_secret_bytes().to_vec()))
    }
    #[cfg(not(feature = "backend-rustcrypto"))]
    {
        let _ = (my_priv_der, peer_pub_der, _passphrase);
        Err(CryptoError::Parameter(
            "RustCrypto backend not enabled".to_string(),
        ))
    }
}

pub fn extract_public_key(priv_der: &[u8], _passphrase: Option<&str>) -> Result<Vec<u8>> {
    #[cfg(feature = "backend-rustcrypto")]
    {
        use rc_internal::*;
        let sk = SecretKey::from_pkcs8_der(priv_der)
            .or_else(|_| SecretKey::from_sec1_der(priv_der))
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        let pk = sk.public_key();
        pk.to_public_key_der()
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))
            .map(|d| d.as_bytes().to_vec())
    }
    #[cfg(not(feature = "backend-rustcrypto"))]
    {
        let _ = (priv_der, _passphrase);
        Err(CryptoError::Parameter(
            "RustCrypto backend not enabled".to_string(),
        ))
    }
}

#[cfg(feature = "backend-rustcrypto")]

pub fn pqc_keygen_kem(
    algo: &str,
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>, Option<Zeroizing<Vec<u8>>>)> {
    #[cfg(feature = "backend-rustcrypto")]
    {
        use rand_core::RngCore;
        use rc_internal::OsRng;
        let mut d = Zeroizing::new([0u8; 32]);
        let mut z = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *d);
        OsRng.fill_bytes(&mut *z);
        let mut seeds = Zeroizing::new(Vec::with_capacity(64));
        seeds.extend_from_slice(&*d);
        seeds.extend_from_slice(&*z);
        match algo {
            "ML-KEM-512" => {
                use fips203::ml_kem_512::KG;
                let mut d_tmp = *d;
                let mut z_tmp = *z;
                let (pk, sk) = KG::keygen_from_seed(d_tmp, z_tmp);
                d_tmp.zeroize();
                z_tmp.zeroize();
                Ok((
                    Zeroizing::new(sk.into_bytes().to_vec()),
                    pk.into_bytes().to_vec(),
                    Some(seeds),
                ))
            }
            "ML-KEM-768" => {
                use fips203::ml_kem_768::KG;
                let mut d_tmp = *d;
                let mut z_tmp = *z;
                let (pk, sk) = KG::keygen_from_seed(d_tmp, z_tmp);
                d_tmp.zeroize();
                z_tmp.zeroize();
                Ok((
                    Zeroizing::new(sk.into_bytes().to_vec()),
                    pk.into_bytes().to_vec(),
                    Some(seeds),
                ))
            }
            "ML-KEM-1024" => {
                use fips203::ml_kem_1024::KG;
                let mut d_tmp = *d;
                let mut z_tmp = *z;
                let (pk, sk) = KG::keygen_from_seed(d_tmp, z_tmp);
                d_tmp.zeroize();
                z_tmp.zeroize();
                Ok((
                    Zeroizing::new(sk.into_bytes().to_vec()),
                    pk.into_bytes().to_vec(),
                    Some(seeds),
                ))
            }
            _ => Err(CryptoError::Parameter(format!("Unsupported KEM: {}", algo))),
        }
    }
    #[cfg(not(feature = "backend-rustcrypto"))]
    {
        let _ = algo;
        Err(CryptoError::Parameter(
            "RustCrypto backend not enabled".to_string(),
        ))
    }
}

pub fn pqc_keygen_dsa(
    algo: &str,
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>, Option<Zeroizing<Vec<u8>>>)> {
    #[cfg(feature = "backend-rustcrypto")]
    {
        use rand_core::RngCore;
        use rc_internal::OsRng;
        let mut xi = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *xi);
        let seed = Zeroizing::new(xi.to_vec());
        match algo {
            "ML-DSA-44" => {
                let (pk, sk) = fips204::ml_dsa_44::KG::keygen_from_seed(&*xi);
                Ok((
                    Zeroizing::new(sk.into_bytes().to_vec()),
                    pk.into_bytes().to_vec(),
                    Some(seed),
                ))
            }
            "ML-DSA-65" => {
                let (pk, sk) = fips204::ml_dsa_65::KG::keygen_from_seed(&*xi);
                Ok((
                    Zeroizing::new(sk.into_bytes().to_vec()),
                    pk.into_bytes().to_vec(),
                    Some(seed),
                ))
            }
            "ML-DSA-87" => {
                let (pk, sk) = fips204::ml_dsa_87::KG::keygen_from_seed(&*xi);
                Ok((
                    Zeroizing::new(sk.into_bytes().to_vec()),
                    pk.into_bytes().to_vec(),
                    Some(seed),
                ))
            }
            _ => Err(CryptoError::Parameter(format!("Unsupported DSA: {}", algo))),
        }
    }
    #[cfg(not(feature = "backend-rustcrypto"))]
    {
        let _ = algo;
        Err(CryptoError::Parameter(
            "RustCrypto backend not enabled".to_string(),
        ))
    }
}

pub fn pqc_sign(
    algo: &str,
    raw_priv: &[u8],
    message: &[u8],
    _passphrase: Option<&str>,
) -> Result<Vec<u8>> {
    #[cfg(feature = "backend-rustcrypto")]
    {
        match algo {
            "ML-DSA-44" => {
                let sk_bytes: [u8; 2560] = (raw_priv)
                    .try_into()
                    .map_err(|_| CryptoError::Parameter("Invalid key size".to_string()))?;
                let mut sk = fips204::ml_dsa_44::PrivateKey::try_from_bytes(sk_bytes)
                    .map_err(|_| CryptoError::PrivateKeyLoad("Invalid key".to_string()))?;
                let res = sk
                    .try_sign(message, &[])
                    .map_err(|_| CryptoError::OpenSSL("Sign failed".to_string()))?
                    .to_vec();
                zeroize_bytes(&mut sk);
                Ok(res)
            }
            "ML-DSA-65" => {
                let sk_bytes: [u8; 4032] = (raw_priv)
                    .try_into()
                    .map_err(|_| CryptoError::Parameter("Invalid key size".to_string()))?;
                let mut sk = fips204::ml_dsa_65::PrivateKey::try_from_bytes(sk_bytes)
                    .map_err(|_| CryptoError::PrivateKeyLoad("Invalid key".to_string()))?;
                let res = sk
                    .try_sign(message, &[])
                    .map_err(|_| CryptoError::OpenSSL("Sign failed".to_string()))?
                    .to_vec();
                zeroize_bytes(&mut sk);
                Ok(res)
            }
            "ML-DSA-87" => {
                let sk_bytes: [u8; 4896] = (raw_priv)
                    .try_into()
                    .map_err(|_| CryptoError::Parameter("Invalid key size".to_string()))?;
                let mut sk = fips204::ml_dsa_87::PrivateKey::try_from_bytes(sk_bytes)
                    .map_err(|_| CryptoError::PrivateKeyLoad("Invalid key".to_string()))?;
                let res = sk
                    .try_sign(message, &[])
                    .map_err(|_| CryptoError::OpenSSL("Sign failed".to_string()))?
                    .to_vec();
                zeroize_bytes(&mut sk);
                Ok(res)
            }
            _ => Err(CryptoError::Parameter(format!("Unsupported DSA: {}", algo))),
        }
    }
    #[cfg(not(feature = "backend-rustcrypto"))]
    {
        let _ = (algo, raw_priv, message, _passphrase);
        Err(CryptoError::Parameter(
            "RustCrypto backend not enabled".to_string(),
        ))
    }
}

pub fn pqc_verify(algo: &str, raw_pub: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
    #[cfg(feature = "backend-rustcrypto")]
    {
        match algo {
            "ML-DSA-44" => {
                let pk_bytes: [u8; 1312] = (raw_pub)
                    .try_into()
                    .map_err(|_| CryptoError::Parameter("Invalid key size".to_string()))?;
                let pk = fips204::ml_dsa_44::PublicKey::try_from_bytes(pk_bytes)
                    .map_err(|_| CryptoError::PublicKeyLoad("Invalid key".to_string()))?;
                let sig_arr: [u8; 2420] = signature
                    .try_into()
                    .map_err(|_| CryptoError::Parameter("Invalid sig size".to_string()))?;
                Ok(pk.verify(message, &sig_arr, &[]))
            }
            "ML-DSA-65" => {
                let pk_bytes: [u8; 1952] = (raw_pub)
                    .try_into()
                    .map_err(|_| CryptoError::Parameter("Invalid key size".to_string()))?;
                let pk = fips204::ml_dsa_65::PublicKey::try_from_bytes(pk_bytes)
                    .map_err(|_| CryptoError::PublicKeyLoad("Invalid key".to_string()))?;
                let sig_arr: [u8; 3309] = signature
                    .try_into()
                    .map_err(|_| CryptoError::Parameter("Invalid sig size".to_string()))?;
                Ok(pk.verify(message, &sig_arr, &[]))
            }
            "ML-DSA-87" => {
                let pk_bytes: [u8; 2592] = (raw_pub)
                    .try_into()
                    .map_err(|_| CryptoError::Parameter("Invalid key size".to_string()))?;
                let pk = fips204::ml_dsa_87::PublicKey::try_from_bytes(pk_bytes)
                    .map_err(|_| CryptoError::PublicKeyLoad("Invalid key".to_string()))?;
                let sig_arr: [u8; 4627] = signature
                    .try_into()
                    .map_err(|_| CryptoError::Parameter("Invalid sig size".to_string()))?;
                Ok(pk.verify(message, &sig_arr, &[]))
            }
            _ => Err(CryptoError::Parameter(format!("Unsupported DSA: {}", algo))),
        }
    }
    #[cfg(not(feature = "backend-rustcrypto"))]
    {
        let _ = (algo, raw_pub, message, signature);
        Err(CryptoError::Parameter(
            "RustCrypto backend not enabled".to_string(),
        ))
    }
}

pub fn pqc_encap(_algo: &str, raw_pub: &[u8]) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
    #[cfg(feature = "backend-rustcrypto")]
    {
        let actual_len = raw_pub.len();
        if actual_len == 800 {
            use fips203::ml_kem_512::EncapsKey;
            let pk_bytes: [u8; 800] = (raw_pub)
                .try_into()
                .map_err(|_| CryptoError::PublicKeyLoad("Invalid key size".to_string()))?;
            let pk = EncapsKey::try_from_bytes(pk_bytes)
                .map_err(|_| CryptoError::PublicKeyLoad("Invalid key".to_string()))?;
            let (ss, ct) = pk
                .try_encaps()
                .map_err(|_| CryptoError::OpenSSL("Encap failed".to_string()))?;
            Ok((
                Zeroizing::new(ss.into_bytes().to_vec()),
                ct.into_bytes().to_vec(),
            ))
        } else if actual_len == 1184 {
            use fips203::ml_kem_768::EncapsKey;
            let pk_bytes: [u8; 1184] = (raw_pub)
                .try_into()
                .map_err(|_| CryptoError::PublicKeyLoad("Invalid key size".to_string()))?;
            let pk = EncapsKey::try_from_bytes(pk_bytes)
                .map_err(|_| CryptoError::PublicKeyLoad("Invalid key".to_string()))?;
            let (ss, ct) = pk
                .try_encaps()
                .map_err(|_| CryptoError::OpenSSL("Encap failed".to_string()))?;
            Ok((
                Zeroizing::new(ss.into_bytes().to_vec()),
                ct.into_bytes().to_vec(),
            ))
        } else if actual_len == 1568 {
            use fips203::ml_kem_1024::EncapsKey;
            let pk_bytes: [u8; 1568] = (raw_pub)
                .try_into()
                .map_err(|_| CryptoError::PublicKeyLoad("Invalid key size".to_string()))?;
            let pk = EncapsKey::try_from_bytes(pk_bytes)
                .map_err(|_| CryptoError::PublicKeyLoad("Invalid key".to_string()))?;
            let (ss, ct) = pk
                .try_encaps()
                .map_err(|_| CryptoError::OpenSSL("Encap failed".to_string()))?;
            Ok((
                Zeroizing::new(ss.into_bytes().to_vec()),
                ct.into_bytes().to_vec(),
            ))
        } else {
            Err(CryptoError::Parameter(format!(
                "Unsupported or mismatched KEM key size: {}",
                actual_len
            )))
        }
    }
    #[cfg(not(feature = "backend-rustcrypto"))]
    {
        let _ = (_algo, raw_pub);
        Err(CryptoError::Parameter(
            "RustCrypto backend not enabled".to_string(),
        ))
    }
}

pub fn pqc_decap(
    _algo: &str,
    raw_priv: &[u8],
    kem_ct: &[u8],
    _passphrase: Option<&str>,
) -> Result<Zeroizing<Vec<u8>>> {
    #[cfg(feature = "backend-rustcrypto")]
    {
        let actual_len = raw_priv.len();
        if actual_len == 1632 {
            use fips203::ml_kem_512::{CipherText, DecapsKey};
            let sk_bytes: [u8; 1632] = (raw_priv)
                .try_into()
                .map_err(|_| CryptoError::PrivateKeyLoad("Invalid key size".to_string()))?;
            let mut sk = DecapsKey::try_from_bytes(sk_bytes)
                .map_err(|_| CryptoError::PrivateKeyLoad("Invalid key".to_string()))?;
            let ct = CipherText::try_from_bytes(
                kem_ct
                    .try_into()
                    .map_err(|_| CryptoError::Parameter("Invalid CT size".to_string()))?,
            )
            .map_err(|_| CryptoError::Parameter("Invalid CT".to_string()))?;
            let ss = sk
                .try_decaps(&ct)
                .map_err(|_| CryptoError::OpenSSL("Decap failed".to_string()))?;
            zeroize_bytes(&mut sk);
            Ok(Zeroizing::new(ss.into_bytes().to_vec()))
        } else if actual_len == 2400 {
            use fips203::ml_kem_768::{CipherText, DecapsKey};
            let sk_bytes: [u8; 2400] = (raw_priv)
                .try_into()
                .map_err(|_| CryptoError::PrivateKeyLoad("Invalid key size".to_string()))?;
            let mut sk = DecapsKey::try_from_bytes(sk_bytes)
                .map_err(|_| CryptoError::PrivateKeyLoad("Invalid key".to_string()))?;
            let ct = CipherText::try_from_bytes(
                kem_ct
                    .try_into()
                    .map_err(|_| CryptoError::Parameter("Invalid CT size".to_string()))?,
            )
            .map_err(|_| CryptoError::Parameter("Invalid CT".to_string()))?;
            let ss = sk
                .try_decaps(&ct)
                .map_err(|_| CryptoError::OpenSSL("Decap failed".to_string()))?;
            zeroize_bytes(&mut sk);
            Ok(Zeroizing::new(ss.into_bytes().to_vec()))
        } else if actual_len == 3168 {
            use fips203::ml_kem_1024::{CipherText, DecapsKey};
            let sk_bytes: [u8; 3168] = (raw_priv)
                .try_into()
                .map_err(|_| CryptoError::PrivateKeyLoad("Invalid key size".to_string()))?;
            let mut sk = DecapsKey::try_from_bytes(sk_bytes)
                .map_err(|_| CryptoError::PrivateKeyLoad("Invalid key".to_string()))?;
            let ct = CipherText::try_from_bytes(
                kem_ct
                    .try_into()
                    .map_err(|_| CryptoError::Parameter("Invalid CT size".to_string()))?,
            )
            .map_err(|_| CryptoError::Parameter("Invalid CT".to_string()))?;
            let ss = sk
                .try_decaps(&ct)
                .map_err(|_| CryptoError::OpenSSL("Decap failed".to_string()))?;
            zeroize_bytes(&mut sk);
            Ok(Zeroizing::new(ss.into_bytes().to_vec()))
        } else {
            Err(CryptoError::Parameter(format!(
                "Unsupported or mismatched KEM key size: {}",
                actual_len
            )))
        }
    }
    #[cfg(not(feature = "backend-rustcrypto"))]
    {
        let _ = (_algo, raw_priv, kem_ct, _passphrase);
        Err(CryptoError::Parameter(
            "RustCrypto backend not enabled".to_string(),
        ))
    }
}

pub fn hkdf(
    ikm: &[u8],
    length: usize,
    salt: &[u8],
    info: &str,
    md_name: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    #[cfg(feature = "backend-rustcrypto")]
    {
        use hkdf::Hkdf;
        use rc_internal::*;
        let mut okm = Zeroizing::new(vec![0u8; length]);
        if md_name.contains("256") {
            let h = Hkdf::<Sha3_256>::new(Some(salt), ikm);
            h.expand(info.as_bytes(), &mut *okm)
                .map_err(|_| CryptoError::Parameter("HKDF expand failed".to_string()))?;
            drop(h); // #15 Fix: Explicitly drop Hkdf object to minimize PRK lifetime
        } else {
            let h = Hkdf::<Sha3_512>::new(Some(salt), ikm);
            h.expand(info.as_bytes(), &mut *okm)
                .map_err(|_| CryptoError::Parameter("HKDF expand failed".to_string()))?;
            drop(h); // #15 Fix: Explicitly drop Hkdf object to minimize PRK lifetime
        }
        Ok(okm)
    }
    #[cfg(not(feature = "backend-rustcrypto"))]
    {
        let _ = (ikm, length, salt, info, md_name);
        Err(CryptoError::Parameter(
            "RustCrypto backend not enabled".to_string(),
        ))
    }
}

pub fn new_encrypt(cipher: &str, key: &[u8], iv: &[u8]) -> Result<Aead> {
    AeadBackend::new_encrypt(cipher, key, iv)
}

pub fn new_decrypt(cipher: &str, key: &[u8], iv: &[u8]) -> Result<Aead> {
    AeadBackend::new_decrypt(cipher, key, iv)
}

pub fn new_hash(algo: &str) -> Result<Hash> {
    HashBackend::new(algo)
}
