use crate::error::{CryptoError, Result};
use crate::key::SharedKeyProvider;
use crate::strategy::{CryptoStrategy, StrategyType};
use openssl::cipher::Cipher;
use openssl::cipher_ctx::CipherCtx;
use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::md_ctx::MdCtx;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use openssl::rand::rand_bytes;
use openssl::symm::Cipher as SymmCipher;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use hkdf::Hkdf;
use sha3::Sha3_256;
use openssl_sys as ffi;
use std::ptr;
use foreign_types::ForeignType;

pub struct EccStrategy {
    key_provider: Option<SharedKeyProvider>,
    curve_name: String,
    digest_algo: String,
    
    // Cipher context for streaming
    cipher_ctx: Option<CipherCtx>,
    md_ctx: Option<MdCtx>,
    
    // Key states
    encryption_key: Vec<u8>,
    iv: Vec<u8>,
    salt: Vec<u8>,
    shared_secret: Vec<u8>,
    ephemeral_pubkey: Vec<u8>,
    
    // Signature/Verification keys
    sign_key: Option<PKey<Private>>,
    verify_key: Option<PKey<Public>>,

    // TPM state
    is_tpm_wrapped: bool,
}

impl EccStrategy {
    pub fn new() -> Self {
        Self {
            key_provider: None,
            curve_name: "prime256v1".to_string(),
            digest_algo: "SHA3-512".to_string(),
            cipher_ctx: None,
            md_ctx: None,
            encryption_key: Vec::new(),
            iv: Vec::new(),
            salt: Vec::new(),
            shared_secret: Vec::new(),
            ephemeral_pubkey: Vec::new(),
            sign_key: None,
            verify_key: None,
            is_tpm_wrapped: false,
        }
    }

    fn hkdf_derive(&self, secret: &[u8], out_len: usize, salt: &[u8], info: &str) -> Result<Vec<u8>> {
        let mut okm = vec![0u8; out_len];
        let hk = Hkdf::<Sha3_256>::new(Some(salt), secret);
        hk.expand(info.as_bytes(), &mut okm).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        Ok(okm)
    }
}

impl CryptoStrategy for EccStrategy {
    fn get_strategy_type(&self) -> StrategyType {
        StrategyType::ECC
    }

    fn set_key_provider(&mut self, provider: SharedKeyProvider) {
        self.key_provider = Some(provider);
    }

    fn generate_encryption_key_pair(&self, key_paths: &HashMap<String, String>, passphrase: Option<&str>) -> Result<()> {
        let pub_path = key_paths.get("public-key")
            .or_else(|| key_paths.get("signing-public-key"))
            .ok_or(CryptoError::Parameter("Missing public key path".to_string()))?;
        let priv_path = key_paths.get("private-key")
            .or_else(|| key_paths.get("signing-private-key"))
            .ok_or(CryptoError::Parameter("Missing private key path".to_string()))?;

        let use_tpm = key_paths.get("use-tpm").map(|s| s == "true").unwrap_or(false);

        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        let ec_key = EcKey::generate(&group)
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        let pkey = PKey::from_ec_key(ec_key)
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;

        if use_tpm {
            let provider = self.key_provider.as_ref().ok_or(CryptoError::ProviderNotAvailable)?;
            let wrapped = provider.wrap_key(&pkey, passphrase)?;
            fs::write(priv_path, wrapped)?;
        } else {
            let priv_pem = if let Some(pass) = passphrase {
                pkey.private_key_to_pem_pkcs8_passphrase(SymmCipher::aes_256_cbc(), pass.as_bytes())
            } else {
                pkey.private_key_to_pem_pkcs8()
            }.map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
            fs::write(priv_path, priv_pem)?;
        }

        let pub_pem = pkey.public_key_to_pem()
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        fs::write(pub_path, pub_pem)?;

        Ok(())
    }

    fn generate_signing_key_pair(&self, key_paths: &HashMap<String, String>, passphrase: Option<&str>) -> Result<()> {
        self.generate_encryption_key_pair(key_paths, passphrase)
    }

    fn prepare_encryption(&mut self, key_paths: &HashMap<String, String>) -> Result<()> {
        if let Some(algo) = key_paths.get("digest-algo") {
            self.digest_algo = algo.clone();
        }

        let pubkey_path = key_paths.get("recipient-pubkey")
            .or_else(|| key_paths.get("recipient-ecdh-pubkey"))
            .ok_or(CryptoError::PublicKeyLoad("Missing recipient public key".to_string()))?;

        let pubkey_bytes = fs::read(pubkey_path)?;
        let recipient_pub = PKey::public_key_from_pem(&pubkey_bytes)
            .map_err(|e| CryptoError::PublicKeyLoad(e.to_string()))?;

        // Generate ephemeral key
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        let ec_key = EcKey::generate(&group)
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        let ephemeral_key = PKey::from_ec_key(ec_key)
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;

        // ECDH
        let mut deriver = Deriver::new(&ephemeral_key)
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        deriver.set_peer(&recipient_pub)
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        
        self.shared_secret = deriver.derive_to_vec()
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;

        // Ephemeral public key bytes
        self.ephemeral_pubkey = ephemeral_key.public_key_to_pem()
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;

        // Salt and IV
        self.salt = vec![0u8; 16];
        self.iv = vec![0u8; 12];
        rand_bytes(&mut self.salt).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        rand_bytes(&mut self.iv).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;

        // HKDF
        self.encryption_key = self.hkdf_derive(
            &self.shared_secret, 
            32, 
            &self.salt, 
            "ecc-encryption"
        )?;

        // Initialize AES-GCM
        let mut ctx = CipherCtx::new()
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        ctx.encrypt_init(Some(Cipher::aes_256_gcm()), None, None)
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        ctx.set_iv_length(self.iv.len())
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        ctx.encrypt_init(None, Some(&self.encryption_key), Some(&self.iv))
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;

        self.cipher_ctx = Some(ctx);

        Ok(())
    }

    fn prepare_decryption(&mut self, key_paths: &HashMap<String, String>, passphrase: Option<&str>) -> Result<()> {
        let privkey_path = key_paths.get("user-privkey")
            .or_else(|| key_paths.get("recipient-ecdh-privkey"))
            .ok_or(CryptoError::PrivateKeyLoad("Missing private key path".to_string()))?;

        let priv_key = if self.is_tpm_wrapped {
            let provider = self.key_provider.as_ref().ok_or(CryptoError::ProviderNotAvailable)?;
            let wrapped_pem = fs::read_to_string(privkey_path)?;
            provider.unwrap_key(&wrapped_pem, passphrase)?
        } else {
            let priv_bytes = fs::read(privkey_path)?;
            if let Some(pass) = passphrase {
                PKey::private_key_from_pem_passphrase(&priv_bytes, pass.as_bytes())
                    .map_err(|e| CryptoError::PrivateKeyLoad(e.to_string()))?
            } else {
                PKey::private_key_from_pem(&priv_bytes)
                    .map_err(|e| CryptoError::PrivateKeyLoad(e.to_string()))?
            }
        };

        let recipient_pub = PKey::public_key_from_pem(&self.ephemeral_pubkey)
            .map_err(|e| CryptoError::PublicKeyLoad(e.to_string()))?;

        // ECDH
        let mut deriver = Deriver::new(&priv_key)
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        deriver.set_peer(&recipient_pub)
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        
        self.shared_secret = deriver.derive_to_vec()
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;

        // HKDF
        self.encryption_key = self.hkdf_derive(
            &self.shared_secret, 
            32, 
            &self.salt, 
            "ecc-encryption"
        )?;

        // Initialize AES-GCM for decryption
        let mut ctx = CipherCtx::new()
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        ctx.decrypt_init(Some(Cipher::aes_256_gcm()), None, None)
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        ctx.set_iv_length(self.iv.len())
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        ctx.decrypt_init(None, Some(&self.encryption_key), Some(&self.iv))
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;

        self.cipher_ctx = Some(ctx);

        Ok(())
    }

    fn encrypt_transform(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let ctx = self.cipher_ctx.as_mut().ok_or(CryptoError::OpenSSL("Cipher context not initialized".to_string()))?;
        let mut out = vec![0u8; data.len() + 16];
        let n = ctx.cipher_update(data, Some(&mut out))
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        out.truncate(n);
        Ok(out)
    }

    fn decrypt_transform(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let ctx = self.cipher_ctx.as_mut().ok_or(CryptoError::OpenSSL("Cipher context not initialized".to_string()))?;
        let mut out = vec![0u8; data.len() + 16];
        let n = ctx.cipher_update(data, Some(&mut out))
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        out.truncate(n);
        Ok(out)
    }

    fn finalize_encryption(&mut self) -> Result<Vec<u8>> {
        let ctx = self.cipher_ctx.as_mut().ok_or(CryptoError::OpenSSL("Cipher context not initialized".to_string()))?;
        let mut out = vec![0u8; 16];
        let n = ctx.cipher_final(&mut out)
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        out.truncate(n);
        
        let mut tag = vec![0u8; 16];
        ctx.tag(&mut tag).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        out.extend_from_slice(&tag);
        
        Ok(out)
    }

    fn finalize_decryption(&mut self, tag: &[u8]) -> Result<()> {
        let ctx = self.cipher_ctx.as_mut().ok_or(CryptoError::OpenSSL("Cipher context not initialized".to_string()))?;
        ctx.set_tag(tag).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        let mut out = vec![0u8; 16];
        ctx.cipher_final(&mut out)
            .map_err(|_| CryptoError::SignatureVerification)?;
        Ok(())
    }

    fn prepare_signing(&mut self, priv_key_path: &Path, passphrase: Option<&str>, digest_algo: &str) -> Result<()> {
        let priv_bytes = fs::read(priv_key_path)?;
        let pkey = if let Some(pass) = passphrase {
            PKey::private_key_from_pem_passphrase(&priv_bytes, pass.as_bytes())
                .map_err(|e| CryptoError::PrivateKeyLoad(e.to_string()))?
        } else {
            PKey::private_key_from_pem(&priv_bytes)
                .map_err(|e| CryptoError::PrivateKeyLoad(e.to_string()))?
        };

        let md = MessageDigest::from_name(digest_algo)
            .ok_or(CryptoError::Parameter(format!("Invalid digest: {}", digest_algo)))?;
        
        let ctx = MdCtx::new().map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        unsafe {
            if ffi::EVP_DigestSignInit(ctx.as_ptr(), ptr::null_mut(), md.as_ptr(), ptr::null_mut(), pkey.as_ptr()) != 1 {
                return Err(CryptoError::OpenSSL("EVP_DigestSignInit failed".to_string()));
            }
        }
        
        self.sign_key = Some(pkey);
        self.md_ctx = Some(ctx);
        self.digest_algo = digest_algo.to_string();
        Ok(())
    }

    fn prepare_verification(&mut self, pub_key_path: &Path, digest_algo: &str) -> Result<()> {
        let pub_bytes = fs::read(pub_key_path)?;
        let pkey = PKey::public_key_from_pem(&pub_bytes)
            .map_err(|e| CryptoError::PublicKeyLoad(e.to_string()))?;

        let md = MessageDigest::from_name(digest_algo)
            .ok_or(CryptoError::Parameter(format!("Invalid digest: {}", digest_algo)))?;
        
        let ctx = MdCtx::new().map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        unsafe {
            if ffi::EVP_DigestVerifyInit(ctx.as_ptr(), ptr::null_mut(), md.as_ptr(), ptr::null_mut(), pkey.as_ptr()) != 1 {
                return Err(CryptoError::OpenSSL("EVP_DigestVerifyInit failed".to_string()));
            }
        }
        
        self.verify_key = Some(pkey);
        self.md_ctx = Some(ctx);
        self.digest_algo = digest_algo.to_string();
        Ok(())
    }

    fn update_hash(&mut self, data: &[u8]) -> Result<()> {
        let ctx = self.md_ctx.as_mut().ok_or(CryptoError::OpenSSL("MD context not initialized".to_string()))?;
        if self.sign_key.is_some() {
            ctx.digest_sign_update(data).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        } else {
            ctx.digest_verify_update(data).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        }
        Ok(())
    }

    fn sign_hash(&mut self) -> Result<Vec<u8>> {
        let ctx = self.md_ctx.as_mut().ok_or(CryptoError::OpenSSL("MD context not initialized".to_string()))?;
        let mut sig_len = 0;
        unsafe {
            if ffi::EVP_DigestSignFinal(ctx.as_ptr(), ptr::null_mut(), &mut sig_len) != 1 {
                return Err(CryptoError::OpenSSL("EVP_DigestSignFinal failed to get length".to_string()));
            }
        }
        let mut sig = vec![0u8; sig_len];
        unsafe {
            if ffi::EVP_DigestSignFinal(ctx.as_ptr(), sig.as_mut_ptr(), &mut sig_len) != 1 {
                return Err(CryptoError::OpenSSL("EVP_DigestSignFinal failed".to_string()));
            }
        }
        sig.truncate(sig_len);
        Ok(sig)
    }

    fn verify_hash(&mut self, signature: &[u8]) -> Result<bool> {
        let ctx = self.md_ctx.as_mut().ok_or(CryptoError::OpenSSL("MD context not initialized".to_string()))?;
        unsafe {
            let r = ffi::EVP_DigestVerifyFinal(ctx.as_ptr(), signature.as_ptr(), signature.len());
            if r == 1 { Ok(true) }
            else if r == 0 { Ok(false) }
            else { Err(CryptoError::SignatureVerification) }
        }
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
        4 + 2 + 1 + 
        4 + self.curve_name.len() + 
        4 + self.digest_algo.len() + 
        4 + self.ephemeral_pubkey.len() + 4 + self.salt.len() + 4 + self.iv.len()
    }

    fn serialize_header(&self) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(b"NKCT");
        header.extend_from_slice(&1u16.to_le_bytes());
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

        self.curve_name = read_string(&mut pos)?;
        self.digest_algo = read_string(&mut pos)?;
        self.ephemeral_pubkey = read_vec(&mut pos)?;
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
