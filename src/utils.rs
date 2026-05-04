/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

use crate::error::{CryptoError, Result};
use zeroize::{Zeroize, Zeroizing};
use std::io::{self, Write};
use rpassword::read_password;

use std::ops::{Deref, DerefMut};

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

pub fn get_and_verify_passphrase(prompt: &str) -> Result<Zeroizing<String>> {
    if let Ok(pass) = std::env::var("NK_PASSPHRASE") {
        eprintln!("WARNING: Using passphrase from NK_PASSPHRASE environment variable. This is less secure than interactive entry.");
        return Ok(Zeroizing::new(pass));
    }
    println!("{}", prompt);
    print!("Enter passphrase: ");
    io::stdout().flush()?;
    let p1 = Zeroizing::new(read_password()?);
    
    print!("Verify passphrase: ");
    io::stdout().flush()?;
    let p2 = Zeroizing::new(read_password()?);
    
    if *p1 != *p2 {
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
        return Err(CryptoError::Parameter(format!("Missing PEM header for {}", label)));
    };

    let end_idx = pem.find(&actual_end).ok_or(CryptoError::Parameter(format!("Missing PEM footer for {}", label)))?;

    let b64 = pem[start_idx..end_idx]
        .replace('\n', "")
        .replace('\r', "")
        .replace(' ', "");

    Ok(Zeroizing::new(BASE64.decode(b64).map_err(|e| CryptoError::Parameter(format!("Base64 decode error: {}", e)))?))
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
        _ => return Err(CryptoError::Parameter(format!("Unsupported PQC algorithm for OID: {}", algo))),
    };
    let mut res = vec![0x06, oid.len() as u8];
    res.extend(oid);
    Ok(res)
}

pub fn wrap_pqc_priv_to_pkcs8(raw_priv: &[u8], algo: &str, seed: Option<&[u8]>) -> Result<Zeroizing<Vec<u8>>> {
    // 1. Create the algorithm-specific PrivateKey structure
    // OpenSSL's observed structure: SEQUENCE { seeds OCTET STRING OPTIONAL, privateKey OCTET STRING }
    let mut inner = SecureBuffer::with_capacity(raw_priv.len() + 128)?;
    if let Some(s) = seed {
        inner.extend_from_slice(&encode_der_octet_string_zeroizing(s));
    }
    inner.extend_from_slice(&encode_der_octet_string_zeroizing(raw_priv));
    let inner_seq = wrap_der_sequence_zeroizing(&inner);

    // 2. Create the PKCS#8 structure
    let oid = get_pqc_oid(algo)?;
    let alg_id = wrap_der_sequence(&oid);
    
    let mut pkcs8 = SecureBuffer::with_capacity(inner_seq.len() + 64)?;
    pkcs8.extend_from_slice(&[0x02, 0x01, 0x00]); // PKCS#8 version 0
    pkcs8.extend_from_slice(&alg_id);
    pkcs8.extend_from_slice(&encode_der_octet_string_zeroizing(&inner_seq));

    Ok(wrap_der_sequence_zeroizing(&pkcs8))
    }


pub fn wrap_to_pem_zeroizing(data: &[u8], label: &str) -> Zeroizing<String> {
    let mut b64_buf = Zeroizing::new(vec![0u8; (data.len() + 2) / 3 * 4]);
    let n = BASE64.encode_slice(data, &mut *b64_buf).map_err(|e| CryptoError::Parameter(format!("Base64 encode error: {}", e))).unwrap();
    
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

pub fn unwrap_pqc_priv_from_pkcs8(der: &[u8], _algo: &str) -> Result<(Zeroizing<Vec<u8>>, Option<Zeroizing<Vec<u8>>>)> {
    if der.is_empty() || der[0] != 0x30 { return Ok((Zeroizing::new(der.to_vec()), None)); }
    
    // Simple heuristic-based PQC PKCS#8 unwrap
    // Look for nested OCTET STRINGs that match expected sizes
    let mut best_sk = Zeroizing::new(Vec::new());
    let mut best_seed = None;
    
    for i in 0..der.len().saturating_sub(4) {
        if der[i] == 0x04 { // OCTET STRING
            let mut pos = i + 1;
            let len = read_asn1_len_internal(der, &mut pos);
            if len > 0 && pos + len <= der.len() {
                let chunk = &der[pos..pos + len];
                if [1632, 2400, 3168, 2560, 4032, 4896, 800, 1184, 1568, 1312, 1952, 2592].contains(&len) {
                    *best_sk = chunk.to_vec();
                } else if len == 32 || len == 64 {
                    best_seed = Some(Zeroizing::new(chunk.to_vec()));
                } else if chunk.starts_with(&[0x30]) {
                    // Try inner sequence
                    if let Ok((sk, s)) = unwrap_pqc_priv_from_pkcs8(chunk, _algo) {
                        if !sk.is_empty() { return Ok((sk, s)); }
                    }
                }
            }
        }
    }
    
    if !best_sk.is_empty() {
        Ok((best_sk, best_seed))
    } else {
        Ok((Zeroizing::new(der.to_vec()), None))
    }
}

fn read_asn1_len_internal(der: &[u8], pos: &mut usize) -> usize {
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

pub fn get_passphrase_if_needed(content: &str, provided_passphrase: Option<&str>) -> Result<Option<Zeroizing<String>>> {
    if let Some(pass) = provided_passphrase {
        return Ok(Some(Zeroizing::new(pass.to_string())));
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
}
