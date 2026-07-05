/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

use crate::backend::HashBackend;
use crate::error::{CryptoError, Result};
#[cfg(feature = "backend-rustcrypto")]
use zeroize::Zeroize;
use zeroize::Zeroizing;

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

    pub use p256::ecdsa::{
        signature::hazmat::{PrehashSigner, PrehashVerifier},
        Signature, SigningKey, VerifyingKey,
    };
}

pub type Hash = RustCryptoHash;

/// Overwrite the in-place bytes of `val` with zeros (not optimizable away).
///
/// # Safety invariant (audit L6)
///
/// This reinterprets `val` as `size_of::<T>()` raw bytes and wipes them, so it
/// is only sound for types that are plain-old-data — a fixed-size byte array or
/// a struct of such — where an all-zero bit pattern is a valid inhabitant. It
/// MUST NOT be used on:
///   - a type that owns heap-allocated or otherwise indirected secrets (`Box`,
///     `Vec`, `String`, or anything holding a pointer): zeroing would (a) wipe
///     the pointer/length while leaving the real secret on the heap, and (b)
///     corrupt the pointer so the following drop double-frees or frees a bogus
///     address; or
///   - a type for which all-zero is an *invalid* bit pattern (`&T`, `NonNull`,
///     `NonZero*`, a niche-optimized enum): writing zero there is instant
///     undefined behaviour.
/// Every current caller passes a fixed-size POD stack value (the fips203/204
/// key structs), so the invariant holds; keep it that way. For a heap-owning
/// secret, wrap it in `Zeroizing` / derive `ZeroizeOnDrop` instead.
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

pub fn pqc_pub_from_priv_dsa(algo: &str, raw_priv: &[u8]) -> Result<Vec<u8>> {
    #[cfg(feature = "backend-rustcrypto")]
    {
        match algo {
            "ML-DSA-44" => {
                let sk_bytes: [u8; 2560] = raw_priv.try_into().map_err(|_| CryptoError::Parameter("Invalid key size".to_string()))?;
                let sk = fips204::ml_dsa_44::PrivateKey::try_from_bytes(sk_bytes).map_err(|_| CryptoError::PrivateKeyLoad("Invalid key".to_string()))?;
                Ok(sk.get_public_key().into_bytes().to_vec())
            }
            "ML-DSA-65" => {
                let sk_bytes: [u8; 4032] = raw_priv.try_into().map_err(|_| CryptoError::Parameter("Invalid key size".to_string()))?;
                let sk = fips204::ml_dsa_65::PrivateKey::try_from_bytes(sk_bytes).map_err(|_| CryptoError::PrivateKeyLoad("Invalid key".to_string()))?;
                Ok(sk.get_public_key().into_bytes().to_vec())
            }
            "ML-DSA-87" => {
                let sk_bytes: [u8; 4896] = raw_priv.try_into().map_err(|_| CryptoError::Parameter("Invalid key size".to_string()))?;
                let sk = fips204::ml_dsa_87::PrivateKey::try_from_bytes(sk_bytes).map_err(|_| CryptoError::PrivateKeyLoad("Invalid key".to_string()))?;
                Ok(sk.get_public_key().into_bytes().to_vec())
            }
            _ => Err(CryptoError::Parameter(format!("Unsupported DSA: {}", algo))),
        }
    }
    #[cfg(not(feature = "backend-rustcrypto"))]
    {
        let _ = (algo, raw_priv);
        Err(CryptoError::Parameter("RustCrypto backend not enabled".to_string()))
    }
}

pub fn pqc_pub_from_priv_kem(algo: &str, raw_priv: &[u8]) -> Result<Vec<u8>> {
    #[cfg(feature = "backend-rustcrypto")]
    {
        match algo {
            "ML-KEM-512" => {
                if raw_priv.len() != 1632 {
                    return Err(CryptoError::Parameter("Invalid key size".to_string()));
                }
                // FIPS 203 §7.2: dk = dk_pke || ek || H(ek) || z
                // ML-KEM-512: dk_pke = 768, ek = 800
                Ok(raw_priv[768..768 + 800].to_vec())
            }
            "ML-KEM-768" => {
                if raw_priv.len() != 2400 {
                    return Err(CryptoError::Parameter("Invalid key size".to_string()));
                }
                // ML-KEM-768: dk_pke = 1152, ek = 1184
                Ok(raw_priv[1152..1152 + 1184].to_vec())
            }
            "ML-KEM-1024" => {
                if raw_priv.len() != 3168 {
                    return Err(CryptoError::Parameter("Invalid key size".to_string()));
                }
                // ML-KEM-1024: dk_pke = 1536, ek = 1568
                Ok(raw_priv[1536..1536 + 1568].to_vec())
            }
            _ => Err(CryptoError::Parameter(format!("Unsupported KEM: {}", algo))),
        }
    }
    #[cfg(not(feature = "backend-rustcrypto"))]
    {
        let _ = (algo, raw_priv);
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
                let (pk, sk) = fips204::ml_dsa_44::KG::keygen_from_seed(&xi);
                Ok((
                    Zeroizing::new(sk.into_bytes().to_vec()),
                    pk.into_bytes().to_vec(),
                    Some(seed),
                ))
            }
            "ML-DSA-65" => {
                let (pk, sk) = fips204::ml_dsa_65::KG::keygen_from_seed(&xi);
                Ok((
                    Zeroizing::new(sk.into_bytes().to_vec()),
                    pk.into_bytes().to_vec(),
                    Some(seed),
                ))
            }
            "ML-DSA-87" => {
                let (pk, sk) = fips204::ml_dsa_87::KG::keygen_from_seed(&xi);
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
            h.expand(info.as_bytes(), &mut okm)
                .map_err(|_| CryptoError::Parameter("HKDF expand failed".to_string()))?;
            drop(h); // #15 Fix: Explicitly drop Hkdf object to minimize PRK lifetime
        } else {
            let h = Hkdf::<Sha3_512>::new(Some(salt), ikm);
            h.expand(info.as_bytes(), &mut okm)
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

pub fn new_hash(algo: &str) -> Result<Hash> {
    HashBackend::new(algo)
}
