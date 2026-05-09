/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

use crate::error::{CryptoError, Result};
use rpassword::read_password;
use std::io::{self, Write};
use zeroize::{Zeroize, Zeroizing};

use pkcs8::der::Decode;
use std::ops::{Deref, DerefMut};

use std::path::Path;

pub fn extract_raw_private_key(
    priv_der: &[u8],
    passphrase: Option<&str>,
) -> Result<Zeroizing<Vec<u8>>> {
    use pkcs8::der::Decode;
    if let Ok(pki) = pkcs8::EncryptedPrivateKeyInfo::from_der(priv_der) {
        let pass = passphrase.ok_or_else(|| {
            CryptoError::Parameter("Encrypted private key requires a passphrase".to_string())
        })?;
        let decrypted = pki
            .decrypt(pass)
            .map_err(|e| CryptoError::PrivateKeyLoad(format!("Decryption failed: {}", e)))?;
        return Ok(Zeroizing::new(decrypted.as_bytes().to_vec()));
    }
    // If not encrypted, return as is. Caller (strategy) will handle if it's invalid plain PKCS#8.
    Ok(Zeroizing::new(priv_der.to_vec()))
}

pub fn secure_write<P: AsRef<Path>, C: AsRef<[u8]>>(path: P, contents: C, force: bool) -> Result<()> {
    let path_ref = path.as_ref();
    let dir = path_ref.parent().ok_or_else(|| {
        CryptoError::FileWrite("Failed to determine parent directory".to_string())
    })?;

    // F-48-10: Check directory writability for better error messages (F-49-2 improved)
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let c_path = std::ffi::CString::new(dir.as_os_str().as_bytes()).unwrap();
        let writable = unsafe { libc::access(c_path.as_ptr(), libc::W_OK) == 0 };
        if !writable {
            return Err(CryptoError::FileWrite(format!(
                "Directory {} is not writable. Cannot create secure file.",
                dir.display()
            )));
        }
    }
    #[cfg(not(unix))]
    {
        let dir_metadata = std::fs::metadata(dir).map_err(|e| {
            CryptoError::FileWrite(format!("Failed to access directory {}: {}", dir.display(), e))
        })?;
        if dir_metadata.permissions().readonly() {
            return Err(CryptoError::FileWrite(format!(
                "Directory {} is read-only. Cannot create secure file.",
                dir.display()
            )));
        }
    }

    use tempfile::NamedTempFile;
    let mut tmp = NamedTempFile::new_in(dir)
        .map_err(|e| CryptoError::FileWrite(format!("Failed to create temporary file: {}", e)))?;

    // F-48-2 Fix: Set 0600 permissions on the temp file using the file descriptor (fchmod equivalent)
    use std::os::unix::fs::PermissionsExt;
    tmp.as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|e| CryptoError::FileWrite(format!("Failed to set temp file permissions: {}", e)))?;

    use std::io::Write;
    tmp.as_file_mut()
        .write_all(contents.as_ref())
        .map_err(|e| CryptoError::FileWrite(e.to_string()))?;
    tmp.as_file_mut()
        .sync_all()
        .map_err(|e| CryptoError::FileWrite(e.to_string()))?;

    // F-48-1 Note: O_NOFOLLOW is not explicitly needed here because:
    // 1. NamedTempFile uses a random name with O_EXCL, preventing pre-existing symlink attacks.
    // 2. rename(2) (via persist) atomically replaces a destination symlink rather than following it.
    // 3. persist_noclobber uses linkat() which fails if the destination exists, preventing link following.
    if force {
        // POSIX atomic: rename overwrites existing file atomically
        tmp.persist(path_ref).map_err(|e| {
            CryptoError::FileWrite(format!("Failed to persist secure file {}: {}", path_ref.display(), e))
        })?;
    } else {
        // O_EXCL semantics: fail if destination already exists
        match tmp.persist_noclobber(path_ref) {
            Ok(_) => {}
            Err(e) if e.error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(CryptoError::FileWrite(format!(
                    "File already exists: {}. Please remove it manually or use --force to overwrite.",
                    path_ref.display()
                )));
            }
            Err(e) => {
                return Err(CryptoError::FileWrite(format!(
                    "Failed to create secure file {}: {}",
                    path_ref.display(),
                    e
                )));
            }
        }
    }
    Ok(())
}

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SecureBuffer(Vec<u8>);

impl SecureBuffer {
    pub fn new(size: usize) -> Result<Self> {
        let mut buf = Vec::with_capacity(size);
        buf.resize(size, 0);

        // Lock memory to prevent swapping
        unsafe {
            if libc::mlock(buf.as_ptr() as *const libc::c_void, buf.len()) != 0 {
                // We ignore mlock failure as in the C++ version,
                // but zeroize(drop) ensures it's cleared on drop.
            }
        }

        Ok(SecureBuffer(buf))
    }

    pub fn from_slice(data: &[u8]) -> Result<Self> {
        let mut me = Self::new(data.len())?;
        me.copy_from_slice(data);
        Ok(me)
    }

    pub fn with_capacity(capacity: usize) -> Result<Self> {
        let buf = Vec::with_capacity(capacity);
        if buf.capacity() > 0 {
            unsafe {
                let _ = libc::mlock(buf.as_ptr() as *const libc::c_void, buf.capacity());
            }
        }
        Ok(SecureBuffer(buf))
    }

    pub fn extend_from_slice(&mut self, data: &[u8]) {
        let old_ptr = self.0.as_ptr();
        let old_cap = self.0.capacity();
        self.0.extend_from_slice(data);
        let new_ptr = self.0.as_ptr();
        let new_cap = self.0.capacity();

        if new_ptr != old_ptr || new_cap != old_cap {
            unsafe {
                let _ = libc::mlock(new_ptr as *const libc::c_void, new_cap);
            }
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Deref for SecureBuffer {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SecureBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub fn get_masked_passphrase() -> Result<Zeroizing<String>> {
    if let Ok(pass) = std::env::var("NK_PASSPHRASE") {
        eprintln!("WARNING: Using passphrase from NK_PASSPHRASE environment variable. This is less secure than interactive entry.");
        return Ok(Zeroizing::new(pass));
    }
    print!("Enter passphrase: ");
    io::stdout().flush()?;
    let password = read_password()?;
    Ok(Zeroizing::new(password))
}

pub fn get_and_verify_passphrase(prompt: &str) -> Result<Option<Zeroizing<String>>> {
    if let Ok(pass) = std::env::var("NK_PASSPHRASE") {
        if pass.is_empty() {
            return Ok(None);
        }
        eprintln!("WARNING: Using passphrase from NK_PASSPHRASE environment variable. This is less secure than interactive entry.");
        return Ok(Some(Zeroizing::new(pass)));
    }
    println!("{}", prompt);
    println!("(Enter nothing to skip encryption and save key in plaintext)");
    print!("Enter passphrase: ");
    io::stdout().flush()?;
    let p1 = Zeroizing::new(read_password()?);

    if p1.is_empty() {
        return Ok(None);
    }

    print!("Verify passphrase: ");
    io::stdout().flush()?;
    let p2 = Zeroizing::new(read_password()?);

    if *p1 != *p2 {
        return Err(CryptoError::Parameter(
            "Passphrases do not match".to_string(),
        ));
    }

    Ok(Some(p1))
}

pub fn disable_core_dumps() {
    unsafe {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &limit) != 0 {
            eprintln!("Warning: Failed to disable core dumps via setrlimit");
        }
        #[cfg(target_os = "linux")]
        if libc::prctl(libc::PR_SET_DUMPABLE, 0) != 0 {
            eprintln!("Warning: Failed to disable core dumps via prctl");
        }
    }
}

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;

pub fn wrap_to_pem(data: &[u8], label: &str) -> String {
    let mut pem = format!("-----BEGIN {}-----\n", label);
    let b64 = BASE64.encode(data);
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {}-----\n", label));
    pem
}

pub fn unwrap_from_pem(pem: &str, label: &str) -> Result<Zeroizing<Vec<u8>>> {
    let begin = format!("-----BEGIN {}-----", label);
    let begin_enc = format!("-----BEGIN ENCRYPTED {}-----", label);
    let end = format!("-----END {}-----", label);
    let end_enc = format!("-----END ENCRYPTED {}-----", label);

    let (start_idx, actual_end) = if let Some(idx) = pem.find(&begin) {
        (idx + begin.len(), end)
    } else if let Some(idx) = pem.find(&begin_enc) {
        (idx + begin_enc.len(), end_enc)
    } else {
        return Err(CryptoError::Parameter(format!(
            "Missing PEM header for {}",
            label
        )));
    };

    let end_idx = pem[start_idx..]
        .find(&actual_end)
        .map(|rel| start_idx + rel)
        .ok_or(CryptoError::Parameter(format!(
            "Missing PEM footer for {}",
            label
        )))?;

    let b64_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(
        pem[start_idx..end_idx]
            .bytes()
            .filter(|&b| !b.is_ascii_whitespace())
            .collect(),
    );

    Ok(Zeroizing::new(BASE64.decode(&*b64_bytes).map_err(|e| {
        CryptoError::Parameter(format!("Base64 decode error: {}", e))
    })?))
}

pub fn is_encrypted_pem(pem: &str) -> bool {
    pem.contains("ENCRYPTED")
}

fn encode_der_length(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else {
        let mut b = Vec::new();
        let mut l = len;
        while l > 0 {
            b.push((l & 0xff) as u8);
            l >>= 8;
        }
        let mut res = vec![0x80 | (b.len() as u8)];
        res.extend(b.into_iter().rev());
        res
    }
}

fn encode_der_header(tag: u8, len: usize) -> Vec<u8> {
    let mut res = vec![tag];
    res.extend(encode_der_length(len));
    res
}

fn wrap_der_sequence(data: &[u8]) -> Vec<u8> {
    let mut res = encode_der_header(0x30, data.len());
    res.extend_from_slice(data);
    res
}

fn wrap_der_sequence_zeroizing(data: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut res = Zeroizing::new(encode_der_header(0x30, data.len()));
    res.extend_from_slice(data);
    res
}

fn encode_der_octet_string_zeroizing(data: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut res = Zeroizing::new(encode_der_header(0x04, data.len()));
    res.extend_from_slice(data);
    res
}

fn encode_der_bit_string(data: &[u8]) -> Vec<u8> {
    // Assuming 0 unused bits at the end
    let mut res = encode_der_header(0x03, data.len() + 1);
    res.push(0x00);
    res.extend_from_slice(data);
    res
}

fn get_pqc_oid(algo: &str) -> Result<Vec<u8>> {
    let oid = match algo {
        "ML-KEM-512" => vec![0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x01],
        "ML-KEM-768" => vec![0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02],
        "ML-KEM-1024" => vec![0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x03],
        "ML-DSA-44" => vec![0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11],
        "ML-DSA-65" => vec![0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12],
        "ML-DSA-87" => vec![0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13],
        _ => {
            return Err(CryptoError::Parameter(format!(
                "Unsupported PQC algorithm for OID: {}",
                algo
            )))
        }
    };
    let mut res = vec![0x06, oid.len() as u8];
    res.extend(oid);
    Ok(res)
}

pub fn wrap_pqc_priv_to_pkcs8(
    raw_priv: &[u8],
    algo: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let oid = get_pqc_oid(algo)?;
    // AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER, parameters ANY OPTIONAL }
    let alg_id = wrap_der_sequence(&oid);

    let mut pkcs8 = SecureBuffer::with_capacity(raw_priv.len() + 64)?;
    pkcs8.extend_from_slice(&[0x02, 0x01, 0x00]); // version 0
    pkcs8.extend_from_slice(&alg_id);
    pkcs8.extend_from_slice(&encode_der_octet_string_zeroizing(raw_priv));

    Ok(wrap_der_sequence_zeroizing(&pkcs8))
}

pub fn wrap_pqc_priv_to_pkcs8_encrypted(
    raw_priv: &[u8],
    algo: &str,
    passphrase: &str,
) -> Result<Vec<u8>> {
    let pkcs8_der = wrap_pqc_priv_to_pkcs8(raw_priv, algo)?;

    use pkcs8::PrivateKeyInfo;
    use rand_core::OsRng;
    let pki = PrivateKeyInfo::from_der(&pkcs8_der)
        .map_err(|e| CryptoError::PrivateKeyLoad(format!("PKCS#8 parse failed: {}", e)))?;
    
    // F-57: Use PBKDF2-SHA256 + AES-256-CBC for maximum interoperability.
    // Scrypt defaults can hit memory limits in some OpenSSL versions.
    use pkcs8::pkcs5::pbes2;
    let mut salt = [0u8; 16];
    use rand_core::RngCore;
    OsRng.fill_bytes(&mut salt);
    
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut iv);

    let params = pbes2::Parameters {
        kdf: pbes2::Kdf::Pbkdf2(pbes2::Pbkdf2Params {
            salt: &salt,
            iteration_count: 2048,
            key_length: Some(32),
            prf: pbes2::Pbkdf2Prf::HmacWithSha256,
        }),
        encryption: pbes2::EncryptionScheme::Aes256Cbc { iv: &iv },
    };

    let encrypted = pki
        .encrypt_with_params(params, passphrase)
        .map_err(|e| CryptoError::PrivateKeyLoad(format!("Encryption failed: {}", e)))?;

    Ok(encrypted.as_bytes().to_vec())
}

pub fn wrap_to_pem_zeroizing(data: &[u8], label: &str) -> Zeroizing<String> {
    let mut b64_buf = Zeroizing::new(vec![0u8; (data.len() + 2) / 3 * 4]);
    let n = BASE64
        .encode_slice(data, &mut *b64_buf)
        .map_err(|e| CryptoError::Parameter(format!("Base64 encode error: {}", e)))
        .unwrap();

    // Pre-calculate capacity to avoid reallocations
    let estimated_size = label.len() * 2 + n + (n / 64) + 40;
    let mut pem = String::with_capacity(estimated_size);

    pem.push_str("-----BEGIN ");
    pem.push_str(label);
    pem.push_str("-----\n");

    for chunk in b64_buf[..n].chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }

    pem.push_str("-----END ");
    pem.push_str(label);
    pem.push_str("-----\n");

    Zeroizing::new(pem)
}

pub fn wrap_pqc_pub_to_spki(raw_pub: &[u8], algo: &str) -> Result<Vec<u8>> {
    // SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
    let oid = get_pqc_oid(algo)?;
    let alg_id = wrap_der_sequence(&oid);
    let pub_bits = encode_der_bit_string(raw_pub);

    let mut spki = Vec::new();
    spki.extend(alg_id);
    spki.extend(pub_bits);

    Ok(wrap_der_sequence(&spki))
}

pub fn unwrap_pqc_pub_from_spki(der: &[u8], algo: &str) -> Result<Vec<u8>> {
    if der.is_empty() || der[0] != 0x30 {
        return Ok(der.to_vec());
    }

    use spki::SubjectPublicKeyInfoRef;
    let spki = SubjectPublicKeyInfoRef::try_from(der)
        .map_err(|e| CryptoError::Parameter(format!("Invalid SPKI: {}", e)))?;

    if algo != "any" {
        let expected_oid = get_pqc_oid_str(algo)?;
        if spki.algorithm.oid.to_string() != expected_oid {
            return Err(CryptoError::Parameter(format!(
                "OID mismatch: expected {}, got {}",
                expected_oid, spki.algorithm.oid
            )));
        }
    }

    Ok(spki.subject_public_key.raw_bytes().to_vec())
}

pub fn unwrap_pqc_priv_from_pkcs8(der: &[u8], algo: &str) -> Result<Zeroizing<Vec<u8>>> {
    if der.is_empty() || der[0] != 0x30 {
        return Ok(Zeroizing::new(der.to_vec()));
    }

    use pkcs8::PrivateKeyInfo;
    let pki = PrivateKeyInfo::try_from(der)
        .map_err(|e| CryptoError::Parameter(format!("Invalid PKCS#8: {}", e)))?;

    if algo != "any" {
        let expected_oid = get_pqc_oid_str(algo)?;
        if pki.algorithm.oid.to_string() != expected_oid {
            return Err(CryptoError::Parameter(format!(
                "OID mismatch: expected {}, got {}",
                expected_oid, pki.algorithm.oid
            )));
        }
    }

    // F-57 Fix: OpenSSL uses a SEQUENCE { seed, expandedKey } inside the privateKey OCTET STRING.
    // We need to extract the expanded key.
    let priv_key_bytes = pki.private_key;
    
    // If it's a SEQUENCE, it might be the "both" format
    if !priv_key_bytes.is_empty() && priv_key_bytes[0] == 0x30 {
        let expected_sizes = match algo {
            "ML-KEM-512" => vec![1632],
            "ML-KEM-768" => vec![2400],
            "ML-KEM-1024" => vec![3168],
            "ML-DSA-44" => vec![2560],
            "ML-DSA-65" => vec![4032],
            "ML-DSA-87" => vec![4896],
            _ => vec![1632, 2400, 3168, 2560, 4032, 4896],
        };
        
        // Use a simple scanner to find the expanded key in the sequence
        let mut best_sk = Zeroizing::new(Vec::new());
        // Skip SEQUENCE header
        if let Ok(len_info) = read_asn1_len_safe(priv_key_bytes, 1) {
            let mut i = len_info.1;
            while i < priv_key_bytes.len() {
                let tag = priv_key_bytes[i];
                i += 1;
                if let Ok((len, next_pos)) = read_asn1_len_safe(priv_key_bytes, i) {
                    if tag == 0x04 { // OCTET STRING
                        let chunk = &priv_key_bytes[next_pos..std::cmp::min(next_pos + len, priv_key_bytes.len())];
                        if expected_sizes.contains(&chunk.len()) {
                            return Ok(Zeroizing::new(chunk.to_vec()));
                        }
                        if chunk.len() > best_sk.len() {
                            best_sk.zeroize();
                            *best_sk = chunk.to_vec();
                        }
                    }
                    i = next_pos + len;
                } else {
                    break;
                }
            }
        }
        if !best_sk.is_empty() {
            return Ok(best_sk);
        }
    }

    Ok(Zeroizing::new(priv_key_bytes.to_vec()))
}

fn read_asn1_len_safe(der: &[u8], pos: usize) -> std::result::Result<(usize, usize), ()> {
    if pos >= der.len() {
        return Err(());
    }
    let b = der[pos];
    if b < 128 {
        return Ok((b as usize, pos + 1));
    }
    let n = (b & 0x7F) as usize;
    if n == 0 || n > 4 || pos + 1 + n > der.len() {
        return Err(());
    }
    let mut res = 0usize;
    for i in 0..n {
        res = (res << 8) | (der[pos + 1 + i] as usize);
    }
    Ok((res, pos + 1 + n))
}

fn get_pqc_oid_str(algo: &str) -> Result<&'static str> {
    match algo {
        "ML-KEM-512" => Ok("2.16.840.1.101.3.4.4.1"),
        "ML-KEM-768" => Ok("2.16.840.1.101.3.4.4.2"),
        "ML-KEM-1024" => Ok("2.16.840.1.101.3.4.4.3"),
        "ML-DSA-44" => Ok("2.16.840.1.101.3.4.3.17"),
        "ML-DSA-65" => Ok("2.16.840.1.101.3.4.3.18"),
        "ML-DSA-87" => Ok("2.16.840.1.101.3.4.3.19"),
        _ => Err(CryptoError::Parameter(format!(
            "Unsupported PQC algorithm for OID: {}",
            algo
        ))),
    }
}

pub fn get_passphrase_if_needed(
    content: &str,
    provided_passphrase: Option<&str>,
) -> Result<Option<Zeroizing<String>>> {
    if let Some(pass) = provided_passphrase {
        return Ok(Some(Zeroizing::new(pass.to_string())));
    }
    if is_encrypted_pem(content) {
        let pass = get_masked_passphrase()?;
        return Ok(Some(pass));
    }
    Ok(None)
}

#[cfg(all(test, feature = "backend-rustcrypto"))]
mod tests {
    use super::*;
    use crate::backend;

    fn test_kem_roundtrip(algo: &str) {
        let (sk, pk, _) = backend::pqc_keygen_kem(algo).unwrap();
        
        let pkcs8 = wrap_pqc_priv_to_pkcs8(&sk, algo).unwrap();
        let unwrapped_sk = unwrap_pqc_priv_from_pkcs8(&pkcs8, algo).unwrap();
        
        assert_eq!(&*unwrapped_sk, &*sk, "SK mismatch for {}", algo);
        
        let (ss1, ct) = backend::pqc_encap(algo, &pk).unwrap();
        let ss2 = backend::pqc_decap(algo, &unwrapped_sk, &ct, None).unwrap();
        
        assert_eq!(&*ss1, &*ss2, "SS mismatch for {}", algo);
    }

    fn test_dsa_roundtrip(algo: &str) {
        let (sk, pk, _) = backend::pqc_keygen_dsa(algo).unwrap();
        
        let pkcs8 = wrap_pqc_priv_to_pkcs8(&sk, algo).unwrap();
        let unwrapped_sk = unwrap_pqc_priv_from_pkcs8(&pkcs8, algo).unwrap();
        
        assert_eq!(&*unwrapped_sk, &*sk, "SK mismatch for {}", algo);
        
        let message = b"hello world";
        let sig = backend::pqc_sign(algo, &unwrapped_sk, message, None).unwrap();
        let ok = backend::pqc_verify(algo, &pk, message, &sig).unwrap();
        
        assert!(ok, "Verification failed for {}", algo);
    }

    #[test]
    fn test_pqc_kem_roundtrips() {
        test_kem_roundtrip("ML-KEM-512");
        test_kem_roundtrip("ML-KEM-768");
        test_kem_roundtrip("ML-KEM-1024");
    }

    #[test]
    fn test_pqc_dsa_roundtrips() {
        test_dsa_roundtrip("ML-DSA-44");
        test_dsa_roundtrip("ML-DSA-65");
        test_dsa_roundtrip("ML-DSA-87");
    }

    #[test]
    fn test_pem_cycle() {
        let data = b"Hello, unit test!";
        let label = "TEST LABEL";
        let pem = wrap_to_pem(data, label);
        assert!(pem.starts_with("-----BEGIN TEST LABEL-----"));
        assert!(pem.trim().ends_with("-----END TEST LABEL-----"));

        let unwrapped = unwrap_from_pem(&pem, label).unwrap();
        assert_eq!(&*unwrapped, data);
    }

    #[test]
    fn test_pem_wrap_long_data() {
        let data = vec![0x41u8; 128]; // 'A' repeated 128 times
        let pem = wrap_to_pem(&data, "LONG");
        let lines: Vec<&str> = pem.lines().collect();
        // Header + at least 2 lines of base64 + Footer
        assert!(lines.len() >= 4);
    }

    #[test]
    fn test_secure_buffer() {
        let buf = SecureBuffer::new(32).unwrap();
        assert_eq!(buf.as_slice().len(), 32);
        // We can't easily test mlock/zeroize in unit tests without more complex mocks,
        // but we ensure it doesn't crash.
    }

    #[test]
    fn test_unwrap_pqc_priv_structured() {
        let algo = "ML-KEM-768";
        let seed = vec![0x42u8; 64];
        let expanded = vec![0x43u8; 2400];

        // Construct the inner SEQUENCE { OCTET STRING (seed), OCTET STRING (expanded) }
        let mut inner = encode_der_header(0x04, seed.len());
        inner.extend_from_slice(&seed);
        inner.extend_from_slice(&encode_der_header(0x04, expanded.len()));
        inner.extend_from_slice(&expanded);
        let structured_priv = wrap_der_sequence(&inner);

        // Wrap in PKCS#8
        let oid = get_pqc_oid(algo).unwrap();
        let alg_id = wrap_der_sequence(&oid);
        let mut pkcs8_content = vec![0x02, 0x01, 0x00]; // version 0
        pkcs8_content.extend_from_slice(&alg_id);
        pkcs8_content.extend_from_slice(&encode_der_header(0x04, structured_priv.len()));
        pkcs8_content.extend_from_slice(&structured_priv);
        let pkcs8 = wrap_der_sequence(&pkcs8_content);

        let unwrapped = unwrap_pqc_priv_from_pkcs8(&pkcs8, algo).unwrap();
        assert_eq!(&*unwrapped, &expanded, "Should have extracted expanded key");
    }
}
