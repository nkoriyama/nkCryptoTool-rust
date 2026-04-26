/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

use crate::error::{CryptoError, Result};
use crate::key::KeyProvider;
use crate::backend::{self, AeadBackend};
use std::process::{Command, Stdio};
use std::io::Write;
use std::fs;
use tempfile::NamedTempFile;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;

pub struct TpmKeyProvider;

impl TpmKeyProvider {
    pub fn new() -> Self {
        Self
    }

    fn run_tpm_cmd(&self, args: &[&str], stdin_data: Option<&[u8]>) -> Result<(String, String)> {
        let mut cmd = Command::new(args[0]);
        cmd.args(&args[1..]);
        cmd.env("TCTI", "device:/dev/tpmrm0");
        
        if stdin_data.is_some() {
            cmd.stdin(Stdio::piped());
        }
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd.spawn().map_err(|e| CryptoError::OpenSSL(format!("Failed to spawn TPM tool {}: {}", args[0], e)))?;

        if let Some(data) = stdin_data {
            let mut stdin = child.stdin.take().unwrap();
            stdin.write_all(data).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        }

        let output = child.wait_with_output().map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if !output.status.success() {
            return Err(CryptoError::OpenSSL(format!("TPM tool {} failed: {}", args[0], stderr)));
        }

        Ok((stdout, stderr))
    }
}

impl KeyProvider for TpmKeyProvider {
    fn is_available(&self) -> bool {
        Command::new("tpm2_getcap")
            .arg("properties-fixed")
            .env("TCTI", "device:/dev/tpmrm0")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn wrap_raw(&self, data: &[u8], passphrase: Option<&str>) -> Result<String> {
        let mut aes_key = vec![0u8; 32];
        let mut iv = vec![0u8; 12];
        
        #[cfg(feature = "backend-openssl")]
        openssl::rand::rand_bytes(&mut aes_key).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        #[cfg(feature = "backend-openssl")]
        openssl::rand::rand_bytes(&mut iv).map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        
        #[cfg(feature = "backend-rustcrypto")]
        {
            use rand_core::{RngCore, OsRng};
            OsRng.fill_bytes(&mut aes_key);
            OsRng.fill_bytes(&mut iv);
        }

        let mut ctx = backend::new_encrypt("AES-256-GCM", &aes_key, &iv)?;
        let mut ciphertext = vec![0u8; data.len() + 16];
        let n = ctx.update(data, &mut ciphertext)?;
        let final_n = ctx.finalize(&mut ciphertext[n..])?;
        ciphertext.truncate(n + final_n);
        let mut tag = vec![0u8; 16];
        ctx.get_tag(&mut tag)?;

        let primary_ctx = NamedTempFile::new().map_err(|e| CryptoError::FileWrite(e.to_string()))?;
        let aes_file = NamedTempFile::new().map_err(|e| CryptoError::FileWrite(e.to_string()))?;
        let pub_file = NamedTempFile::new().map_err(|e| CryptoError::FileWrite(e.to_string()))?;
        let priv_file = NamedTempFile::new().map_err(|e| CryptoError::FileWrite(e.to_string()))?;
        let session_file = NamedTempFile::new().map_err(|e| CryptoError::FileWrite(e.to_string()))?;

        fs::write(aes_file.path(), &aes_key).map_err(|e| CryptoError::FileWrite(e.to_string()))?;

        let sess_path = session_file.path().to_str().unwrap();
        let sess_arg = format!("session:{}", sess_path);
        let pctx_path = primary_ctx.path().to_str().unwrap();
        let aes_path_str = aes_file.path().to_str().unwrap();
        let upath = pub_file.path().to_str().unwrap();
        let rpath = priv_file.path().to_str().unwrap();

        self.run_tpm_cmd(&["tpm2_startauthsession", "--hmac-session", "-S", sess_path], None)?;
        self.run_tpm_cmd(&["tpm2_createprimary", "-C", "o", "-c", pctx_path, "-Q"], None)?;

        let mut create_args = vec![
            "tpm2_create", "-C", pctx_path,
            "-i", aes_path_str,
            "-u", upath,
            "-r", rpath,
            "-P", &sess_arg,
            "-Q"
        ];

        let mut pass_bytes = None;
        if let Some(pass) = passphrase {
            if !pass.is_empty() {
                create_args.push("-p");
                create_args.push("-");
                pass_bytes = Some(pass.as_bytes());
            }
        }

        self.run_tpm_cmd(&create_args, pass_bytes)?;
        Command::new("tpm2_flushcontext").arg(sess_path).env("TCTI", "device:/dev/tpmrm0").status().ok();

        let pub_blob = fs::read(upath).map_err(|e| CryptoError::FileRead(e.to_string()))?;
        let priv_blob = fs::read(rpath).map_err(|e| CryptoError::FileRead(e.to_string()))?;

        let mut output = String::new();
        output.push_str("-----BEGIN TPM WRAPPED BLOB-----\n");
        output.push_str(&format!("P={}\n", BASE64.encode(pub_blob)));
        output.push_str(&format!("R={}\n", BASE64.encode(priv_blob)));
        output.push_str(&format!("E={}\n", BASE64.encode(ciphertext)));
        output.push_str(&format!("I={}\n", BASE64.encode(iv)));
        output.push_str(&format!("T={}\n", BASE64.encode(tag)));
        output.push_str("-----END TPM WRAPPED BLOB-----\n");

        Ok(output)
    }

    fn unwrap_raw(&self, wrapped_pem: &str, passphrase: Option<&str>) -> Result<Vec<u8>> {
        let mut p_b64 = String::new();
        let mut r_b64 = String::new();
        let mut e_b64 = String::new();
        let mut i_b64 = String::new();
        let mut t_b64 = String::new();

        for line in wrapped_pem.lines() {
            if line.starts_with("P=") { p_b64 = line[2..].trim().to_string(); }
            else if line.starts_with("R=") { r_b64 = line[2..].trim().to_string(); }
            else if line.starts_with("E=") { e_b64 = line[2..].trim().to_string(); }
            else if line.starts_with("I=") { i_b64 = line[2..].trim().to_string(); }
            else if line.starts_with("T=") { t_b64 = line[2..].trim().to_string(); }
        }

        if p_b64.is_empty() || r_b64.is_empty() || e_b64.is_empty() {
            return Err(CryptoError::Parameter("Invalid TPM wrapped blob".to_string()));
        }

        let pub_blob = BASE64.decode(p_b64).map_err(|e| CryptoError::Parameter(e.to_string()))?;
        let priv_blob = BASE64.decode(r_b64).map_err(|e| CryptoError::Parameter(e.to_string()))?;
        let ciphertext = BASE64.decode(e_b64).map_err(|e| CryptoError::Parameter(e.to_string()))?;
        let iv = BASE64.decode(i_b64).map_err(|e| CryptoError::Parameter(e.to_string()))?;
        let tag = BASE64.decode(t_b64).map_err(|e| CryptoError::Parameter(e.to_string()))?;

        let primary_ctx = NamedTempFile::new().map_err(|e| CryptoError::FileWrite(e.to_string()))?;
        let pub_file = NamedTempFile::new().map_err(|e| CryptoError::FileWrite(e.to_string()))?;
        let priv_file = NamedTempFile::new().map_err(|e| CryptoError::FileWrite(e.to_string()))?;
        let key_ctx = NamedTempFile::new().map_err(|e| CryptoError::FileWrite(e.to_string()))?;
        let aes_file = NamedTempFile::new().map_err(|e| CryptoError::FileWrite(e.to_string()))?;
        let session_file = NamedTempFile::new().map_err(|e| CryptoError::FileWrite(e.to_string()))?;

        fs::write(pub_file.path(), pub_blob).map_err(|e| CryptoError::FileWrite(e.to_string()))?;
        fs::write(priv_file.path(), priv_blob).map_err(|e| CryptoError::FileWrite(e.to_string()))?;

        let sess_path = session_file.path().to_str().unwrap();
        let sess_arg = format!("session:{}", sess_path);
        let pctx_path = primary_ctx.path().to_str().unwrap();
        let upath = pub_file.path().to_str().unwrap();
        let rpath = priv_file.path().to_str().unwrap();
        let kctx_path = key_ctx.path().to_str().unwrap();
        let aes_path_str = aes_file.path().to_str().unwrap();

        self.run_tpm_cmd(&["tpm2_startauthsession", "--hmac-session", "-S", sess_path], None)?;
        self.run_tpm_cmd(&["tpm2_createprimary", "-C", "o", "-c", pctx_path, "-Q"], None)?;

        self.run_tpm_cmd(&[
            "tpm2_load", "-C", pctx_path,
            "-u", upath,
            "-r", rpath,
            "-c", kctx_path,
            "-P", &sess_arg,
            "-Q"
        ], None)?;

        let mut auth_arg = sess_arg;
        let mut pass_bytes = None;
        if let Some(pass) = passphrase {
            if !pass.is_empty() {
                auth_arg += "+-";
                pass_bytes = Some(pass.as_bytes());
            }
        }

        self.run_tpm_cmd(&[
            "tpm2_unseal", "-c", kctx_path,
            "-o", aes_path_str,
            "-p", &auth_arg, "-Q"
        ], pass_bytes)?;

        Command::new("tpm2_flushcontext").arg(sess_path).env("TCTI", "device:/dev/tpmrm0").status().ok();

        let aes_key = fs::read(aes_path_str).map_err(|e| CryptoError::FileRead(e.to_string()))?;
        let mut ctx = backend::new_decrypt("AES-256-GCM", &aes_key, &iv)?;
        ctx.set_tag(&tag)?;
        
        let mut decrypted = vec![0u8; ciphertext.len() + 16];
        let n = ctx.update(&ciphertext, &mut decrypted)?;
        let final_n = ctx.finalize(&mut decrypted[n..]).map_err(|_| CryptoError::SignatureVerification)?;
        decrypted.truncate(n + final_n);

        Ok(decrypted)
    }
}
