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

    fn run_tpm_cmd(&self, args: &[&str], stdin_data: Option<&[u8]>) -> Result<(Vec<u8>, String)> {
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
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if !output.status.success() {
            return Err(CryptoError::OpenSSL(format!(
                "TPM tool {} failed: {}",
                args[0], stderr
            )));
        }

        Ok((output.stdout, stderr))
    }

    /// Seal up to ~128 bytes of `data` (a KEK) into the TPM under a transient
    /// owner-hierarchy primary, authorised by `passphrase` (empty auth if None).
    /// Returns the sealed object's `(pub_blob, priv_blob)`. TPM sealed-data
    /// objects are size-limited, which is why callers seal a small KEK and
    /// envelope-encrypt the real (arbitrary-size) key material under it.
    fn tpm_seal(&self, data: &[u8], passphrase: Option<&str>) -> Result<(Vec<u8>, Vec<u8>)> {
        let primary_ctx =
            NamedTempFile::new().map_err(|e| CryptoError::FileWrite(e.to_string()))?;
        let pub_file = NamedTempFile::new().map_err(|e| CryptoError::FileWrite(e.to_string()))?;
        let priv_file = NamedTempFile::new().map_err(|e| CryptoError::FileWrite(e.to_string()))?;
        let key_ctx = NamedTempFile::new().map_err(|e| CryptoError::FileWrite(e.to_string()))?;

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

        self.run_tpm_cmd(
            &["tpm2_createprimary", "-C", "o", "-c", pctx_path, "-Q"],
            None,
        )?;

        // With a passphrase, the data goes via a temp file (`-i <file>`) because
        // stdin carries the passphrase for `-p file:-`; without, the data itself
        // is piped via stdin (`-i -`) and the object has empty auth.
        let data_file = if passphrase.is_some() {
            let tmp = NamedTempFile::new().map_err(|e| CryptoError::FileWrite(e.to_string()))?;
            fs::write(tmp.path(), data).map_err(|e| CryptoError::FileWrite(e.to_string()))?;
            Some(tmp)
        } else {
            None
        };
        let data_arg = if let Some(ref tmp) = data_file {
            tmp.path()
                .to_str()
                .ok_or_else(|| CryptoError::FileRead("Invalid path".to_string()))?
                .to_string()
        } else {
            "-".to_string()
        };

        let mut create_args = vec![
            "tpm2_create",
            "-C",
            pctx_path,
            "-i",
            &data_arg,
            "-u",
            upath,
            "-r",
            rpath,
            "-c",
            kctx_path,
            // Sealed keyedhash data object: bound to this TPM and parent, unsealed
            // with the caller's password (userwithauth). Key-object flags
            // (decrypt/sign) and sensitivedataorigin do not apply to sealed data.
            "-a",
            "fixedtpm|fixedparent|userwithauth",
            "-Q",
        ];
        let create_res = if passphrase.is_some() {
            create_args.push("-p");
            create_args.push("file:-");
            self.run_tpm_cmd(&create_args, passphrase.map(|s| s.as_bytes()))
        } else {
            self.run_tpm_cmd(&create_args, Some(data))
        };
        // Erase the staged plaintext KEK before anything else — including before
        // propagating a tpm2_create failure — so a failed seal never leaves it in
        // an unallocated sector after the NamedTempFile is unlinked on drop.
        if let Some(tmp) = &data_file {
            crate::utils::secure_erase_file(tmp.path());
        }
        create_res?;

        let pub_blob =
            fs::read(pub_file.path()).map_err(|e| CryptoError::FileRead(e.to_string()))?;
        let priv_blob =
            fs::read(priv_file.path()).map_err(|e| CryptoError::FileRead(e.to_string()))?;
        Ok((pub_blob, priv_blob))
    }

    /// Load and unseal a blob produced by [`Self::tpm_seal`], returning the KEK.
    /// Unseals to stdout (no `-o`) so the KEK never lands on disk.
    fn tpm_unseal(
        &self,
        pub_blob: &[u8],
        priv_blob: &[u8],
        passphrase: Option<&str>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let primary_ctx =
            NamedTempFile::new().map_err(|e| CryptoError::FileWrite(e.to_string()))?;
        let pub_file = NamedTempFile::new().map_err(|e| CryptoError::FileWrite(e.to_string()))?;
        let priv_file = NamedTempFile::new().map_err(|e| CryptoError::FileWrite(e.to_string()))?;
        let key_ctx = NamedTempFile::new().map_err(|e| CryptoError::FileWrite(e.to_string()))?;

        fs::write(pub_file.path(), pub_blob).map_err(|e| CryptoError::FileWrite(e.to_string()))?;
        fs::write(priv_file.path(), priv_blob)
            .map_err(|e| CryptoError::FileWrite(e.to_string()))?;

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

        self.run_tpm_cmd(
            &["tpm2_createprimary", "-C", "o", "-c", pctx_path, "-Q"],
            None,
        )?;
        self.run_tpm_cmd(
            &[
                "tpm2_load", "-C", pctx_path, "-u", upath, "-r", rpath, "-c", kctx_path, "-Q",
            ],
            None,
        )?;

        // With a passphrase the object's auth is read from stdin (`-p file:-`);
        // with no passphrase the object has empty auth and no `-p` is passed.
        let res = if passphrase.is_some() {
            self.run_tpm_cmd(
                &["tpm2_unseal", "-c", kctx_path, "-p", "file:-", "-Q"],
                passphrase.map(|s| s.as_bytes()),
            )
        } else {
            self.run_tpm_cmd(&["tpm2_unseal", "-c", kctx_path, "-Q"], None)
        };

        // Wrap the unsealed KEK in `Zeroizing` immediately (no intervening copy —
        // the stdout Vec is moved, not cloned) so its heap buffer is wiped on drop.
        let kek = match res {
            Ok((stdout, _)) => Zeroizing::new(stdout),
            Err(e) => {
                // Failed with no passphrase supplied → it may have been sealed under
                // one; prompt for it and retry with `-p file:-`.
                if passphrase.is_none() {
                    if let Ok(pass) = crate::utils::get_masked_passphrase() {
                        let (stdout, _) = self.run_tpm_cmd(
                            &["tpm2_unseal", "-c", kctx_path, "-p", "file:-", "-Q"],
                            Some(pass.as_bytes()),
                        )?;
                        Zeroizing::new(stdout)
                    } else {
                        return Err(e);
                    }
                } else {
                    return Err(e);
                }
            }
        };
        Ok(kek)
    }
}

impl KeyProvider for TpmKeyProvider {
    fn is_available(&self) -> bool {
        self.run_tpm_cmd(&["tpm2_getcap", "properties-fixed"], None)
            .is_ok()
    }

    fn wrap_raw(&self, key_material: &[u8], passphrase: Option<&str>) -> Result<String> {
        use crate::strategy::streaming_aead::aead_encrypt_chunk;
        use rand_core::{OsRng, RngCore};

        // 1. Fresh 32-byte KEK, sealed in the TPM. A KEK fits the TPM's sealed-
        //    data size limit; the arbitrary-size key material does not, so it is
        //    envelope-encrypted under the KEK rather than sealed directly.
        let mut kek = Zeroizing::new(vec![0u8; 32]);
        OsRng.fill_bytes(&mut kek);
        let (pub_blob, priv_blob) = self.tpm_seal(&kek, passphrase)?;

        // 2. AES-256-GCM the key material under the KEK with a fresh 96-bit nonce.
        //    The vetted one-shot returns ciphertext || tag(16); split so the blob
        //    keeps its nonce | tag | ct layout (byte-identical to the previous
        //    streaming path, so existing wrapped blobs still round-trip).
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let ct_tag = aead_encrypt_chunk("AES-256-GCM", &kek, &nonce, &[], key_material)?;
        let split = ct_tag.len() - 16;
        let ct = &ct_tag[..split];
        let tag = &ct_tag[split..];

        // 3. blob = u32 pub_len | pub | u32 priv_len | priv | nonce(12) | tag(16) | ct.
        //    None of this is secret (the TPM priv blob is TPM-encrypted, the rest is
        //    ciphertext/nonce/tag), so no zeroization is needed for `combined`.
        let mut combined = Vec::new();
        combined.extend_from_slice(&(pub_blob.len() as u32).to_le_bytes());
        combined.extend_from_slice(&pub_blob);
        combined.extend_from_slice(&(priv_blob.len() as u32).to_le_bytes());
        combined.extend_from_slice(&priv_blob);
        combined.extend_from_slice(&nonce);
        combined.extend_from_slice(tag);
        combined.extend_from_slice(ct);

        use base64::{engine::general_purpose, Engine as _};
        let mut out_data = Vec::new();
        out_data.extend_from_slice(b"-----BEGIN TPM WRAPPED BLOB-----\n");
        let b64 = general_purpose::STANDARD.encode(&combined);
        for chunk in b64.as_bytes().chunks(64) {
            out_data.extend_from_slice(chunk);
            out_data.push(b'\n');
        }
        out_data.extend_from_slice(b"-----END TPM WRAPPED BLOB-----\n");
        Ok(String::from_utf8_lossy(&out_data).to_string())
    }

    fn unwrap_raw(&self, pem_str: &str, passphrase: Option<&str>) -> Result<Zeroizing<Vec<u8>>> {
        use crate::strategy::streaming_aead::aead_decrypt_chunk;
        use base64::{engine::general_purpose, Engine as _};

        let b64 = pem_str
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<String>();
        let combined = general_purpose::STANDARD
            .decode(b64)
            .map_err(|_| CryptoError::Parameter("Invalid base64".to_string()))?;

        // Parse: u32 pub_len | pub | u32 priv_len | priv | nonce(12) | tag(16) | ct.
        // All offset arithmetic is checked, so a hostile length header can only
        // produce an error — never a wrapping add + out-of-bounds slice panic
        // (a DoS on 32-bit hosts).
        let take = |c: &[u8], o: &mut usize, n: usize| -> Result<Vec<u8>> {
            let end = o
                .checked_add(n)
                .filter(|e| *e <= c.len())
                .ok_or_else(|| CryptoError::Parameter("TPM blob truncated or corrupt".to_string()))?;
            let out = c[*o..end].to_vec();
            *o = end;
            Ok(out)
        };
        let mut off = 0usize;
        let pub_len =
            u32::from_le_bytes(take(&combined, &mut off, 4)?.try_into().unwrap()) as usize;
        let pub_blob = take(&combined, &mut off, pub_len)?;
        let priv_len =
            u32::from_le_bytes(take(&combined, &mut off, 4)?.try_into().unwrap()) as usize;
        let priv_blob = take(&combined, &mut off, priv_len)?;
        let nonce = take(&combined, &mut off, 12)?;
        let tag = take(&combined, &mut off, 16)?;
        let ct = combined.get(off..).unwrap_or(&[]).to_vec();

        // 1. Unseal the KEK from the TPM.
        let kek = self.tpm_unseal(&pub_blob, &priv_blob, passphrase)?;

        // 2. AES-256-GCM decrypt the key material; the vetted one-shot verifies
        //    the GCM tag, so a wrong KEK / tampered blob fails here rather than
        //    returning garbage. Reassemble ciphertext || tag for the call (the
        //    blob stores them separated as nonce | tag | ct). The plaintext is
        //    returned in a `Zeroizing` buffer.
        let mut ct_tag = ct;
        ct_tag.extend_from_slice(&tag);
        let pt = aead_decrypt_chunk("AES-256-GCM", &kek, &nonce, &[], &ct_tag)?;
        Ok(pt)
    }
}
