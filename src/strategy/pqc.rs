use crate::error::{CryptoError, Result};
use crate::key::SharedKeyProvider;
use crate::strategy::{CryptoStrategy, StrategyType};
use crate::backend::{self, AeadBackend, HashBackend};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use hkdf::Hkdf;
use sha3::Sha3_256;
use pqcrypto_mlkem::mlkem1024::{PublicKey, SecretKey, Ciphertext, encapsulate, decapsulate};
use pqcrypto_traits::kem::{PublicKey as _, SecretKey as _, Ciphertext as _, SharedSecret as _};

pub struct PqcStrategy {
    key_provider: Option<SharedKeyProvider>,
    kem_algo: String,
    dsa_algo: String,
    digest_algo: String,
    
    // Abstract contexts
    aead_ctx: Option<backend::Aead>,
    hash_ctx: Option<backend::Hash>,
    
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
            kem_algo: "ML-KEM-1024".to_string(),
            dsa_algo: "ML-DSA-87".to_string(),
            digest_algo: "SHA3-512".to_string(),
            aead_ctx: None,
            hash_ctx: None,
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

    // Manual ASN.1 wrapping for ML-KEM-1024 (FIPS 203)
    fn wrap_spki(&self, raw_pub: &[u8]) -> Vec<u8> {
        let mut der = vec![0x30, 0x82, 0x06, 0x30]; // Total length: 1584
        der.extend_from_slice(&[0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x03, 0x05, 0x00]); // OID 2.16.840.1.101.3.4.4.3
        der.extend_from_slice(&[0x03, 0x82, 0x06, 0x21, 0x00]); // BIT STRING header
        der.extend_from_slice(raw_pub);
        der
    }

    fn unwrap_spki(&self, der: &[u8]) -> Result<Vec<u8>> {
        if der.len() < 1568 { return Err(CryptoError::Parameter("DER too short".to_string())); }
        Ok(der[der.len() - 1568..].to_vec())
    }

    fn wrap_pkcs8(&self, raw_priv: &[u8]) -> Vec<u8> {
        let mut der = vec![0x30, 0x82, 0x0c, 0x7a];
        der.extend_from_slice(&[0x02, 0x01, 0x00]);
        der.extend_from_slice(&[0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x03, 0x05, 0x00]);
        der.extend_from_slice(&[0x04, 0x82, 0x0c, 0x60]);
        der.extend_from_slice(raw_priv);
        der
    }

    fn unwrap_pkcs8(&self, der: &[u8]) -> Result<Vec<u8>> {
        if der.len() < 3168 { return Err(CryptoError::Parameter("DER too short".to_string())); }
        Ok(der[der.len() - 3168..].to_vec())
    }

    // ML-DSA-87 SPKI wrapping (OID 2.16.840.1.101.3.4.3.19)
    fn wrap_mldsa_spki(&self, raw_pub: &[u8]) -> Vec<u8> {
        let mut der = vec![0x30, 0x82, 0x0a, 0x32]; // Total: 2610
        der.extend_from_slice(&[0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13, 0x05, 0x00]); // OID 2.16.840.1.101.3.4.3.19
        der.extend_from_slice(&[0x03, 0x82, 0x0a, 0x21, 0x00]); // BIT STRING
        der.extend_from_slice(raw_pub);
        der
    }

    fn wrap_mldsa_pkcs8(&self, raw_priv: &[u8]) -> Vec<u8> {
        let mut der = vec![0x30, 0x82, 0x13, 0x35]; // Total: 4917
        der.extend_from_slice(&[0x02, 0x01, 0x00]); // Version
        der.extend_from_slice(&[0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13, 0x05, 0x00]);
        der.extend_from_slice(&[0x04, 0x82, 0x13, 0x22]); // OCTET STRING
        der.extend_from_slice(&[0x04, 0x82, 0x13, 0x20]); // Inner OCTET STRING
        der.extend_from_slice(raw_priv);
        der
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
        let pub_path = key_paths.get("public-key")
            .ok_or(CryptoError::Parameter("Missing public key path".to_string()))?;
        let priv_path = key_paths.get("private-key")
            .ok_or(CryptoError::Parameter("Missing private key path".to_string()))?;

        let use_tpm = key_paths.get("use-tpm").map(|s| s == "true").unwrap_or(false);
        let (pk, sk) = pqcrypto_mlkem::mlkem1024::keypair();
        
        let pub_pem = crate::utils::wrap_to_pem(&self.wrap_spki(pk.as_bytes()), "PUBLIC KEY");
        fs::write(pub_path, pub_pem)?;

        if use_tpm {
            let provider = self.key_provider.as_ref().ok_or(CryptoError::ProviderNotAvailable)?;
            let wrapped = provider.wrap_raw(sk.as_bytes(), passphrase)?;
            fs::write(priv_path, wrapped)?;
        } else {
            let priv_pem = crate::utils::wrap_to_pem(&self.wrap_pkcs8(sk.as_bytes()), "PRIVATE KEY");
            fs::write(priv_path, priv_pem)?;
        }

        Ok(())
    }

    fn generate_signing_key_pair(&self, key_paths: &HashMap<String, String>, passphrase: Option<&str>) -> Result<()> {
        let pub_path = key_paths.get("signing-public-key")
            .ok_or(CryptoError::Parameter("Missing public key path".to_string()))?;
        let priv_path = key_paths.get("signing-private-key")
            .ok_or(CryptoError::Parameter("Missing private key path".to_string()))?;

        let use_tpm = key_paths.get("use-tpm").map(|s| s == "true").unwrap_or(false);

        let (priv_der, pub_der) = {
            #[cfg(feature = "backend-openssl")]
            {
                use openssl::pkey::Id;
                use openssl::pkey_ctx::PkeyCtx;
                let mut pctx = PkeyCtx::new_id(Id::from_raw(1196))
                    .map_err(|e| CryptoError::OpenSSL(format!("ML-DSA-87 not supported via NID 1196: {}", e)))?;
                pctx.keygen_init().map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
                let pkey = pctx.keygen().map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
                (
                    pkey.private_key_to_der().map_err(|e| CryptoError::OpenSSL(e.to_string()))?,
                    pkey.public_key_to_der().map_err(|e| CryptoError::OpenSSL(e.to_string()))?
                )
            }
            #[cfg(not(feature = "backend-openssl"))]
            {
                use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _};
                let (pk, sk) = pqcrypto_mldsa::mldsa87::keypair();
                (self.wrap_mldsa_pkcs8(sk.as_bytes()), self.wrap_mldsa_spki(pk.as_bytes()))
            }
        };

        if use_tpm {
            let provider = self.key_provider.as_ref().ok_or(CryptoError::ProviderNotAvailable)?;
            let wrapped = provider.wrap_raw(&priv_der, passphrase)?;
            fs::write(priv_path, wrapped)?;
        } else {
            let priv_pem = crate::utils::wrap_to_pem(&priv_der, "PRIVATE KEY");
            fs::write(priv_path, priv_pem)?;
        }

        let pub_pem = crate::utils::wrap_to_pem(&pub_der, "PUBLIC KEY");
        fs::write(pub_path, pub_pem)?;

        Ok(())
    }

    fn prepare_encryption(&mut self, key_paths: &HashMap<String, String>) -> Result<()> {
        let pubkey_path = key_paths.get("recipient-pubkey")
            .or_else(|| key_paths.get("recipient-mlkem-pubkey"))
            .ok_or(CryptoError::PublicKeyLoad("Missing recipient public key".to_string()))?;

        let pem = fs::read_to_string(pubkey_path)?;
        let der = crate::utils::unwrap_from_pem(&pem, "PUBLIC KEY")?;
        let raw_pub = self.unwrap_spki(&der)?;
        
        let pk = PublicKey::from_bytes(&raw_pub)
            .map_err(|_| CryptoError::PublicKeyLoad("Invalid PQC public key".to_string()))?;

        let (ss, ct) = encapsulate(&pk);
        
        self.shared_secret = ss.as_bytes().to_vec();
        self.kem_ct = ct.as_bytes().to_vec();
        
        self.salt = vec![0u8; 16];
        self.iv = vec![0u8; 12];
        
        #[cfg(feature = "backend-openssl")]
        openssl::rand::rand_bytes(&mut self.salt).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        #[cfg(feature = "backend-openssl")]
        openssl::rand::rand_bytes(&mut self.iv).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        
        #[cfg(feature = "backend-rustcrypto")]
        {
            use rand_core::{RngCore, OsRng};
            OsRng.fill_bytes(&mut self.salt);
            OsRng.fill_bytes(&mut self.iv);
        }

        self.encryption_key = self.hkdf_derive(
            &self.shared_secret, 
            32, 
            &self.salt, 
            "pqc-encryption"
        )?;

        let ctx = backend::new_encrypt("AES-256-GCM", &self.encryption_key, &self.iv)?;
        self.aead_ctx = Some(ctx);

        Ok(())
    }

    fn prepare_decryption(&mut self, key_paths: &HashMap<String, String>, passphrase: Option<&str>) -> Result<()> {
        let privkey_path = key_paths.get("user-privkey")
            .or_else(|| key_paths.get("recipient-mlkem-privkey"))
            .ok_or(CryptoError::PrivateKeyLoad("Missing private key path".to_string()))?;

        let priv_bytes = fs::read(privkey_path)?;
        let pem_str = String::from_utf8_lossy(&priv_bytes);
        
        let raw_priv = if pem_str.contains("-----BEGIN TPM WRAPPED BLOB-----") {
            let provider = self.key_provider.as_ref().ok_or(CryptoError::ProviderNotAvailable)?;
            provider.unwrap_raw(&pem_str, passphrase)?
        } else {
            let der = crate::utils::unwrap_from_pem(&pem_str, "PRIVATE KEY")?;
            self.unwrap_pkcs8(&der)?
        };
        
        let sk = SecretKey::from_bytes(&raw_priv)
            .map_err(|_| CryptoError::PrivateKeyLoad("Invalid PQC private key".to_string()))?;

        let ct = Ciphertext::from_bytes(&self.kem_ct)
            .map_err(|_| CryptoError::FileRead("Invalid KEM ciphertext in header".to_string()))?;
        
        let ss = decapsulate(&ct, &sk);
        self.shared_secret = ss.as_bytes().to_vec();

        self.encryption_key = self.hkdf_derive(
            &self.shared_secret, 
            32, 
            &self.salt, 
            "pqc-encryption"
        )?;

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

    fn prepare_signing(&mut self, priv_key_path: &Path, passphrase: Option<&str>, digest_algo: &str) -> Result<()> {
        let priv_bytes = fs::read(priv_key_path)?;
        let pem_str = String::from_utf8_lossy(&priv_bytes);

        let priv_key_der = if pem_str.contains("-----BEGIN TPM WRAPPED BLOB-----") {
            let provider = self.key_provider.as_ref().ok_or(CryptoError::ProviderNotAvailable)?;
            provider.unwrap_raw(&pem_str, passphrase)?
        } else {
            crate::utils::unwrap_from_pem(&pem_str, "PRIVATE KEY")?
        };

        let mut ctx = backend::new_hash(digest_algo)?;
        ctx.init_sign(&priv_key_der)?;
        
        self.sign_key_der = Some(priv_key_der);
        self.hash_ctx = Some(ctx);
        self.digest_algo = digest_algo.to_string();
        Ok(())
    }

    fn prepare_verification(&mut self, pub_key_path: &Path, digest_algo: &str) -> Result<()> {
        let pub_bytes = fs::read(pub_key_path)?;
        let pub_der = crate::utils::unwrap_from_pem(&String::from_utf8_lossy(&pub_bytes), "PUBLIC KEY")?;

        let mut ctx = backend::new_hash(digest_algo)?;
        ctx.init_verify(&pub_der)?;
        
        self.verify_key_der = Some(pub_der);
        self.hash_ctx = Some(ctx);
        self.digest_algo = digest_algo.to_string();
        Ok(())
    }

    fn update_hash(&mut self, data: &[u8]) -> Result<()> {
        let ctx = self.hash_ctx.as_mut().ok_or(CryptoError::Parameter("Hash context not initialized".to_string()))?;
        ctx.update(data)
    }

    fn sign_hash(&mut self) -> Result<Vec<u8>> {
        let ctx = self.hash_ctx.as_mut().ok_or(CryptoError::Parameter("Hash context not initialized".to_string()))?;
        let key_der = self.sign_key_der.as_ref().ok_or(CryptoError::Parameter("Sign key missing".to_string()))?;
        ctx.finalize_sign(key_der)
    }

    fn verify_hash(&mut self, signature: &[u8]) -> Result<bool> {
        let ctx = self.hash_ctx.as_mut().ok_or(CryptoError::Parameter("Hash context not initialized".to_string()))?;
        let key_der = self.verify_key_der.as_ref().ok_or(CryptoError::Parameter("Verify key missing".to_string()))?;
        ctx.finalize_verify(key_der, signature)
    }

    fn serialize_signature_header(&self) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(b"NKCS");
        header.extend_from_slice(&1u16.to_le_bytes());
        header.push(self.get_strategy_type() as u8);

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
