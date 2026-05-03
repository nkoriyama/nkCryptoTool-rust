/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

use crate::error::{CryptoError, Result};
use zeroize::Zeroize;
use std::io::{self, Write};
use rpassword::read_password;

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

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

pub fn get_masked_passphrase() -> Result<String> {
    if let Ok(pass) = std::env::var("NK_PASSPHRASE") {
        eprintln!("WARNING: Using passphrase from NK_PASSPHRASE environment variable. This is less secure than interactive entry.");
        return Ok(pass);
    }
    print!("Enter passphrase: ");
    io::stdout().flush()?;
    let password = read_password()?;
    Ok(password)
}

pub fn get_and_verify_passphrase(prompt: &str) -> Result<String> {
    if let Ok(pass) = std::env::var("NK_PASSPHRASE") {
        eprintln!("WARNING: Using passphrase from NK_PASSPHRASE environment variable. This is less secure than interactive entry.");
        return Ok(pass);
    }
    println!("{}", prompt);
    print!("Enter passphrase: ");
    io::stdout().flush()?;
    let p1 = read_password()?;
    
    print!("Verify passphrase: ");
    io::stdout().flush()?;
    let p2 = read_password()?;
    
    if p1 != p2 {
        return Err(CryptoError::Parameter("Passphrases do not match".to_string()));
    }
    
    Ok(p1)
}

pub fn disable_core_dumps() {
    unsafe {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &limit);
    }
}

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use std::os::unix::io::AsRawFd;

pub struct Mmap {
    ptr: *mut libc::c_void,
    len: usize,
}

impl Mmap {
    pub fn new(file: &std::fs::File) -> Result<Self> {
        let metadata = file.metadata().map_err(|e| CryptoError::FileRead(e.to_string()))?;
        let len = metadata.len() as usize;
        if len == 0 {
            return Ok(Self { ptr: std::ptr::null_mut(), len: 0 });
        }

        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };

        if ptr == libc::MAP_FAILED {
            return Err(CryptoError::FileRead("mmap failed".to_string()));
        }

        Ok(Self { ptr, len })
    }

    pub fn as_slice(&self) -> &[u8] {
        if self.len == 0 {
            return &[];
        }
        unsafe { std::slice::from_raw_parts(self.ptr as *const u8, self.len) }
    }
}

impl Drop for Mmap {
    fn drop(&mut self) {
        if !self.ptr.is_null() && self.ptr != libc::MAP_FAILED {
            unsafe {
                libc::munmap(self.ptr, self.len);
            }
        }
    }
}

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

pub fn unwrap_from_pem(pem: &str, label: &str) -> Result<Vec<u8>> {
    let begin = format!("-----BEGIN {}-----", label);
    let begin_enc = format!("-----BEGIN ENCRYPTED {}-----", label);
    let end = format!("-----END {}-----", label);
    let end_enc = format!("-----END ENCRYPTED {}-----", label);

    let (start_idx, actual_end) = if let Some(idx) = pem.find(&begin) {
        (idx + begin.len(), end)
    } else if let Some(idx) = pem.find(&begin_enc) {
        (idx + begin_enc.len(), end_enc)
    } else {
        return Err(CryptoError::Parameter(format!("Missing PEM header for {}", label)));
    };

    let end_idx = pem.find(&actual_end).ok_or(CryptoError::Parameter(format!("Missing PEM footer for {}", label)))?;

    let b64 = pem[start_idx..end_idx]
        .replace('\n', "")
        .replace('\r', "")
        .replace(' ', "");

    BASE64.decode(b64).map_err(|e| CryptoError::Parameter(format!("Base64 decode error: {}", e)))
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

fn encode_der_octet_string(data: &[u8]) -> Vec<u8> {
    let mut res = encode_der_header(0x04, data.len());
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
        _ => return Err(CryptoError::Parameter(format!("Unsupported PQC algorithm for OID: {}", algo))),
    };
    let mut res = vec![0x06, oid.len() as u8];
    res.extend(oid);
    Ok(res)
}

pub fn wrap_pqc_priv_to_pkcs8(raw_priv: &[u8], algo: &str, seed: Option<&[u8]>) -> Result<Vec<u8>> {
    // 1. Create the algorithm-specific PrivateKey structure
    // OpenSSL's observed structure: SEQUENCE { seeds OCTET STRING OPTIONAL, privateKey OCTET STRING }
    // Note: It seems version field is omitted in OpenSSL's current implementation for PQC.
    let mut inner = Vec::new();
    if let Some(s) = seed {
        inner.extend(encode_der_octet_string(s));
    }
    inner.extend(encode_der_octet_string(raw_priv));
    let inner_seq = wrap_der_sequence(&inner);

    // 2. Create the PKCS#8 structure
    // OneAsymmetricKey ::= SEQUENCE { version INTEGER(0), privateKeyAlgorithm AlgorithmIdentifier, privateKey OCTET STRING }
    let oid = get_pqc_oid(algo)?;
    let alg_id = wrap_der_sequence(&oid);
    
    let mut pkcs8 = vec![0x02, 0x01, 0x00]; // PKCS#8 version 0
    pkcs8.extend(alg_id);
    pkcs8.extend(encode_der_octet_string(&inner_seq));
    
    Ok(wrap_der_sequence(&pkcs8))
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

pub fn get_passphrase_if_needed(content: &str, provided_passphrase: Option<&str>) -> Result<Option<String>> {
    if let Some(pass) = provided_passphrase {
        return Ok(Some(pass.to_string()));
    }
    if is_encrypted_pem(content) {
        let pass = get_masked_passphrase()?;
        return Ok(Some(pass));
    }
    Ok(None)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pem_cycle() {
        let data = b"Hello, unit test!";
        let label = "TEST LABEL";
        let pem = wrap_to_pem(data, label);
        assert!(pem.starts_with("-----BEGIN TEST LABEL-----"));
        assert!(pem.trim().ends_with("-----END TEST LABEL-----"));
        
        let unwrapped = unwrap_from_pem(&pem, label).unwrap();
        assert_eq!(unwrapped, data);
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
}
