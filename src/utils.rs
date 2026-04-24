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
    print!("Enter passphrase: ");
    io::stdout().flush()?;
    let password = read_password()?;
    Ok(password)
}

pub fn get_and_verify_passphrase(prompt: &str) -> Result<String> {
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
    let end = format!("-----END {}-----", label);
    
    let start_idx = pem.find(&begin).ok_or(CryptoError::Parameter("Missing PEM header".to_string()))? + begin.len();
    let end_idx = pem.find(&end).ok_or(CryptoError::Parameter("Missing PEM footer".to_string()))?;
    
    let b64 = pem[start_idx..end_idx]
        .replace('\n', "")
        .replace('\r', "")
        .replace(' ', "");
        
    BASE64.decode(b64).map_err(|e| CryptoError::Parameter(format!("Invalid base64: {}", e)))
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
