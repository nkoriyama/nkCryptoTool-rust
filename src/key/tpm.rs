/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

use crate::error::{CryptoError, Result};
use crate::key::KeyProvider;
use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

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

        let mut child = cmd.spawn().map_err(|e| {
            CryptoError::OpenSSL(format!("Failed to spawn TPM tool {}: {}", args[0], e))
        })?;

        if let Some(data) = stdin_data {
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| CryptoError::OpenSSL("stdin not piped".to_string()))?;
            stdin
                .write_all(data)
                .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        }

        let output = child
            .wait_with_output()
            .map_err(|e| CryptoError::OpenSSL(e.to_string()))?;
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if !output.status.success() {
            return Err(CryptoError::OpenSSL(format!(
                "TPM tool {} failed: {}",
                args[0], stderr
            )));
        }

        Ok((stdout, stderr))
    }
}

impl KeyProvider for TpmKeyProvider {
    fn is_available(&self) -> bool {
        self.run_tpm_cmd(&["tpm2_getcap", "properties-fixed"], None)
            .is_ok()
    }

    fn wrap_raw(&self, aes_key: &[u8], passphrase: Option<&str>) -> Result<String> {
        let primary_ctx =
            NamedTempFile::new().map_err(|e| CryptoError::FileWrite(e.to_string()))?;
        let pub_file = NamedTempFile::new().map_err(|e| CryptoError::FileWrite(e.to_string()))?;
        let priv_file = NamedTempFile::new().map_err(|e| CryptoError::FileWrite(e.to_string()))?;
        let aes_file = NamedTempFile::new().map_err(|e| CryptoError::FileWrite(e.to_string()))?;
        let session_file =
            NamedTempFile::new().map_err(|e| CryptoError::FileWrite(e.to_string()))?;
        let key_ctx = NamedTempFile::new().map_err(|e| CryptoError::FileWrite(e.to_string()))?;

        fs::write(aes_file.path(), aes_key).map_err(|e| CryptoError::FileWrite(e.to_string()))?;

        let sess_path = session_file
            .path()
            .to_str()
            .ok_or_else(|| CryptoError::FileRead("Invalid path".to_string()))?;
        let pctx_path = primary_ctx
            .path()
            .to_str()
            .ok_or_else(|| CryptoError::FileRead("Invalid path".to_string()))?;
        let upath = pub_file
            .path()
            .to_str()
            .ok_or_else(|| CryptoError::FileRead("Invalid path".to_string()))?;
        let rpath = priv_file
            .path()
            .to_str()
            .ok_or_else(|| CryptoError::FileRead("Invalid path".to_string()))?;
        let kctx_path = key_ctx
            .path()
            .to_str()
            .ok_or_else(|| CryptoError::FileRead("Invalid path".to_string()))?;
        let aes_path_str = aes_file
            .path()
            .to_str()
            .ok_or_else(|| CryptoError::FileRead("Invalid path".to_string()))?;

        self.run_tpm_cmd(
            &["tpm2_startauthsession", "--hmac-session", "-S", sess_path],
            None,
        )?;
        self.run_tpm_cmd(
            &["tpm2_createprimary", "-C", "o", "-c", pctx_path, "-Q"],
            None,
        )?;

        let mut create_args = vec![
            "tpm2_create",
            "-C",
            pctx_path,
            "-i",
            aes_path_str,
            "-u",
            upath,
            "-r",
            rpath,
            "-c",
            kctx_path,
            "-a",
            "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noauthread|decrypt|sign",
            "-Q",
        ];

        let pass_bytes = passphrase.map(|s| s.as_bytes());
        let auth_arg = if passphrase.is_some() {
            format!("session:{}+-", sess_path)
        } else {
            "".to_string()
        };
        if passphrase.is_some() {
            create_args.push("-p");
            create_args.push(&auth_arg);
        }

        self.run_tpm_cmd(&create_args, pass_bytes)?;

        let mut out_data = Vec::new();
        out_data.extend_from_slice(b"-----BEGIN TPM WRAPPED BLOB-----\n");
        let pub_blob =
            fs::read(pub_file.path()).map_err(|e| CryptoError::FileRead(e.to_string()))?;
        let priv_blob =
            fs::read(priv_file.path()).map_err(|e| CryptoError::FileRead(e.to_string()))?;

        let mut combined = Zeroizing::new(Vec::new());
        combined.extend_from_slice(&(pub_blob.len() as u32).to_le_bytes());
        combined.extend_from_slice(&pub_blob);
        combined.extend_from_slice(&priv_blob);

        use base64::{engine::general_purpose, Engine as _};
        let b64 = general_purpose::STANDARD.encode(&*combined);
        for chunk in b64.as_bytes().chunks(64) {
            out_data.extend_from_slice(chunk);
            out_data.push(b'\n');
        }
        out_data.extend_from_slice(b"-----END TPM WRAPPED BLOB-----\n");

        Command::new("tpm2_flushcontext")
            .arg(sess_path)
            .env("TCTI", "device:/dev/tpmrm0")
            .status()
            .ok();

        Ok(String::from_utf8_lossy(&out_data).to_string())
    }

    fn unwrap_raw(&self, pem_str: &str, passphrase: Option<&str>) -> Result<Zeroizing<Vec<u8>>> {
        let b64 = pem_str
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<String>();

        use base64::{engine::general_purpose, Engine as _};
        let combined = Zeroizing::new(
            general_purpose::STANDARD
                .decode(b64)
                .map_err(|_| CryptoError::Parameter("Invalid base64".to_string()))?,
        );

        if combined.len() < 4 {
            return Err(CryptoError::Parameter("TPM blob too short".to_string()));
        }
        let pub_len = u32::from_le_bytes(
            combined[0..4]
                .try_into()
                .map_err(|_| CryptoError::Parameter("Corrupted TPM blob".to_string()))?,
        ) as usize;
        if combined.len() < 4 + pub_len {
            return Err(CryptoError::Parameter("TPM blob corrupted".to_string()));
        }

        let pub_blob = &combined[4..4 + pub_len];
        let priv_blob = &combined[4 + pub_len..];

        let primary_ctx =
            NamedTempFile::new().map_err(|e| CryptoError::FileWrite(e.to_string()))?;
        let pub_file = NamedTempFile::new().map_err(|e| CryptoError::FileWrite(e.to_string()))?;
        let priv_file = NamedTempFile::new().map_err(|e| CryptoError::FileWrite(e.to_string()))?;
        let key_ctx = NamedTempFile::new().map_err(|e| CryptoError::FileWrite(e.to_string()))?;
        let aes_file = NamedTempFile::new().map_err(|e| CryptoError::FileWrite(e.to_string()))?;
        let session_file =
            NamedTempFile::new().map_err(|e| CryptoError::FileWrite(e.to_string()))?;

        fs::write(pub_file.path(), pub_blob).map_err(|e| CryptoError::FileWrite(e.to_string()))?;
        fs::write(priv_file.path(), priv_blob)
            .map_err(|e| CryptoError::FileWrite(e.to_string()))?;

        let sess_path = session_file
            .path()
            .to_str()
            .ok_or_else(|| CryptoError::FileRead("Invalid path".to_string()))?;
        let pctx_path = primary_ctx
            .path()
            .to_str()
            .ok_or_else(|| CryptoError::FileRead("Invalid path".to_string()))?;
        let upath = pub_file
            .path()
            .to_str()
            .ok_or_else(|| CryptoError::FileRead("Invalid path".to_string()))?;
        let rpath = priv_file
            .path()
            .to_str()
            .ok_or_else(|| CryptoError::FileRead("Invalid path".to_string()))?;
        let kctx_path = key_ctx
            .path()
            .to_str()
            .ok_or_else(|| CryptoError::FileRead("Invalid path".to_string()))?;
        let aes_path_str = aes_file
            .path()
            .to_str()
            .ok_or_else(|| CryptoError::FileRead("Invalid path".to_string()))?;

        self.run_tpm_cmd(
            &["tpm2_startauthsession", "--hmac-session", "-S", sess_path],
            None,
        )?;
        self.run_tpm_cmd(
            &["tpm2_createprimary", "-C", "o", "-c", pctx_path, "-Q"],
            None,
        )?;

        self.run_tpm_cmd(
            &[
                "tpm2_load",
                "-C",
                pctx_path,
                "-u",
                upath,
                "-r",
                rpath,
                "-c",
                kctx_path,
                "-Q",
            ],
            None,
        )?;

        let pass_bytes = passphrase.map(|s| s.as_bytes());
        let auth_arg = if passphrase.is_some() {
            format!("session:{}+-", sess_path)
        } else {
            "".to_string()
        };

        let res = self.run_tpm_cmd(
            &[
                "tpm2_unseal",
                "-c",
                kctx_path,
                "-o",
                aes_path_str,
                "-p",
                &auth_arg,
                "-Q",
            ],
            pass_bytes,
        );

        if res.is_err() && passphrase.is_none() {
            // If failed and no passphrase was provided, try asking for one
            if let Ok(pass) = crate::utils::get_masked_passphrase() {
                let retry_auth_arg = format!("session:{}+-", sess_path);
                self.run_tpm_cmd(
                    &[
                        "tpm2_unseal",
                        "-c",
                        kctx_path,
                        "-o",
                        aes_path_str,
                        "-p",
                        &retry_auth_arg,
                        "-Q",
                    ],
                    Some(pass.as_bytes()),
                )?;
            } else {
                res?;
            }
        } else {
            res?;
        }

        Command::new("tpm2_flushcontext")
            .arg(sess_path)
            .env("TCTI", "device:/dev/tpmrm0")
            .status()
            .ok();

        let aes_key = fs::read(aes_path_str).map_err(|e| CryptoError::FileRead(e.to_string()))?;
        Ok(Zeroizing::new(aes_key))
    }
}
