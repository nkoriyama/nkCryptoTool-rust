/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

//! redb-backed **keyring**: a local store of received/known KeyBundles, keyed by
//! handle, plus a fingerprint-keyed **allowlist** of per-service authorization
//! grants. Two tables in one DB:
//!
//! - `contacts` (`handle -> pinned fingerprint + bundle bytes`) — key material,
//!   replacing the per-file `<key-dir>/received/<handle>.nkkb` artefacts.
//! - `allowlist` (`fingerprint -> grants`) — transport authorization, replacing
//!   the plaintext `--peer-allowlist` file with per-service grants.
//!
//! **Not encrypted at rest**: a KeyBundle and a fingerprint are public data, so
//! there is no secret to protect — the store is plain redb, guarded by `0600`.
//! The anchor is the *integrity* of the file (who may write it), not
//! confidentiality. Tampering that changes a bundle but not its stored
//! fingerprint is caught at read time (the bundle no longer verifies against the
//! pin); changing either requires write access, which the file permissions
//! restrict.

use crate::error::CryptoError;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use std::path::Path;

type Result<T> = std::result::Result<T, CryptoError>;

/// `handle -> fingerprint(32) ‖ added_at(8 LE) ‖ keybundle_bytes`.
const CONTACTS: TableDefinition<&str, &[u8]> = TableDefinition::new("keyring_contacts_v1");

/// Reject a contact handle that is unsafe as a filename or as terminal output.
///
/// A handle is frequently authored by the peer whose bundle is being stored, and
/// it is displayed by `keyring list` — the table an operator reads to decide
/// which fingerprint owns which name before selecting one with `--recipient`.
/// Restricting it to `[A-Za-z0-9._-]` keeps a contact from embedding escape
/// sequences that repaint that table, and keeps the handle usable as a path
/// component. This is the single definition; `pairing` re-exports it so the
/// pairing path and the `add`/`import` paths cannot drift apart.
pub fn validate_handle(handle: &str) -> Result<()> {
    if handle.is_empty() || handle.len() > 128 {
        return Err(CryptoError::Parameter(
            "handle empty or too long".into(),
        ));
    }
    if handle == "." || handle == ".." || handle.starts_with('.') {
        return Err(CryptoError::Parameter(
            "handle must not start with a dot".into(),
        ));
    }
    if !handle
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return Err(CryptoError::Parameter(
            "handle may only contain [A-Za-z0-9._-]".into(),
        ));
    }
    Ok(())
}

/// `fingerprint(32) -> grants(u8)` — per-service transport authorization. Keyed
/// by fingerprint (the value the handshake proves), distinct from the
/// handle-keyed contacts table.
const ALLOWLIST: TableDefinition<&[u8], u8> = TableDefinition::new("keyring_allowlist_v1");

/// Grant bitflags for the allowlist. These gate *transport* access to a service;
/// the *capability* within a service (which shell commands, which scp paths)
/// stays in the per-service policy files (`--shell-policy` / `--scp-policy`).
pub const GRANT_SHELL: u8 = 1;
pub const GRANT_SCP: u8 = 2;
pub const GRANT_FORWARD: u8 = 4;
/// All transport grants — the default a freshly-paired peer receives, matching
/// the pre-keyring flat allowlist where membership authorized every service.
pub const GRANT_ALL: u8 = GRANT_SHELL | GRANT_SCP | GRANT_FORWARD;

/// `"{handle}:{role}:{algo}" -> fingerprint(32) ‖ added_at(8 LE) ‖
/// pub_len(4 LE) ‖ public_key_spki_der ‖ encrypted_private_key_pem` — the
/// user's OWN key pairs, GPG-keyring style. The private key is stored only in
/// its passphrase-encrypted PKCS#8 PEM form (exactly the bytes a key file
/// holds); the public half and fingerprint are plaintext so `list-my-keys`
/// and bundle generation need no passphrase. See `my_identity_key`.
const MY_IDENTITIES: TableDefinition<&str, &[u8]> =
    TableDefinition::new("keyring_my_identities_v1");

/// Fixed prefix of every contacts value: 32-byte fingerprint + 8-byte LE time.
const HEADER_LEN: usize = 32 + 8;

/// One stored keyring entry.
pub struct KeyringEntry {
    /// The trusted owner fingerprint (the pin) recorded when the entry was written.
    pub fingerprint: [u8; 32],
    /// Unix seconds when the entry was added.
    pub added_at: u64,
    /// The raw NKKB KeyBundle bytes.
    pub bundle: Vec<u8>,
}

/// Outcome of [`KeyringStore::add`].
#[derive(Debug, PartialEq, Eq)]
pub enum AddOutcome {
    /// A previously-unknown handle was registered.
    Added,
    /// The same handle + fingerprint was re-stored (idempotent update).
    Updated,
}

/// A plain (unencrypted) redb keyring of KeyBundles + authorization grants.
pub struct KeyringStore {
    db: Database,
}

impl KeyringStore {
    /// Open (or create) the keyring at `path`. Creates both tables on first use
    /// and tightens the file to `0600` on unix. A symlink at `path`, or a
    /// keyring carrying a second hard link, is refused rather than opened.
    pub fn open(path: &Path) -> Result<Self> {
        // Pre-create the file owner-only (exclusive, no-follow) so a fresh
        // keyring is never readable by other users even for an instant —
        // `Database::create` alone would create it under the default
        // umask/inherited ACL. An existing DB just falls through (create_new
        // is atomic, so this is race-safe). Same pattern as
        // `redb_storage::open_db_secure`.
        match crate::secure_fs::create_owner_only(path, false) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => {
                return Err(CryptoError::Parameter(format!(
                    "keyring: precreate {path:?}: {e}"
                )))
            }
        }
        // redb gets an already-resolved handle, never the path. The exclusive
        // create above also reports `AlreadyExists` for a symlink planted at
        // `path`, and a path-based `Database::create` then re-resolved and
        // followed the very link the create had refused — initializing a fresh
        // ~1 MiB database over whatever the link aimed at, since redb adopts
        // any empty file as a new database. Silently, at that: the
        // `harden_owner_only` below is best-effort, so `open` still returned
        // `Ok`. Here the path is resolved once, under no-follow, and a link is
        // refused before a byte is written.
        let file = crate::secure_fs::open_existing_no_follow_shared(path)
            .map_err(|e| CryptoError::Parameter(format!("keyring: open {path:?}: {e}")))?;
        let db = Database::builder()
            .create_file(file)
            .map_err(|e| CryptoError::Parameter(format!("keyring: open {path:?}: {e}")))?;
        // Ensure both tables exist so a read on a fresh DB does not error.
        {
            let w = db.begin_write().map_err(map_err)?;
            w.open_table(CONTACTS).map_err(map_err)?;
            w.open_table(ALLOWLIST).map_err(map_err)?;
            w.open_table(MY_IDENTITIES).map_err(map_err)?;
            w.commit().map_err(map_err)?;
        }
        // Best-effort tighten to owner-only (unix 0600 / windows owner-only
        // DACL) — the keyring db is plaintext, holding contacts and grants.
        let _ = crate::secure_fs::harden_owner_only(path);
        Ok(Self { db })
    }

    fn encode(fp: &[u8; 32], added_at: u64, bundle: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(HEADER_LEN + bundle.len());
        v.extend_from_slice(fp);
        v.extend_from_slice(&added_at.to_le_bytes());
        v.extend_from_slice(bundle);
        v
    }

    fn decode(raw: &[u8]) -> Result<KeyringEntry> {
        if raw.len() < HEADER_LEN {
            return Err(CryptoError::Parameter("keyring: truncated record".into()));
        }
        let mut fp = [0u8; 32];
        fp.copy_from_slice(&raw[..32]);
        let added_at = u64::from_le_bytes(raw[32..HEADER_LEN].try_into().unwrap());
        Ok(KeyringEntry { fingerprint: fp, added_at, bundle: raw[HEADER_LEN..].to_vec() })
    }

    /// Store `bundle` under `handle`, pinned to `fp`. Clobber-protected: if the
    /// handle already holds a bundle for a **different** fingerprint, the write is
    /// refused (a different identity must not hijack the handle). Re-storing under
    /// the same fingerprint is an idempotent update.
    ///
    /// The handle is validated here rather than at each caller: it is often
    /// chosen by the bundle's author, not by the operator, and `keyring list`
    /// renders it as the audit view that `--recipient <handle>` then selects
    /// from. Verifying the bundle's signature proves who wrote the handle, not
    /// that the handle is well-formed.
    pub fn add(&self, handle: &str, fp: &[u8; 32], bundle: &[u8], added_at: u64) -> Result<AddOutcome> {
        validate_handle(handle)?;
        let outcome = match self.get(handle)? {
            Some(e) if &e.fingerprint != fp => {
                return Err(CryptoError::Parameter(format!(
                    "keyring: handle {handle:?} is already registered to a different identity \
                     ({}…) — pick another handle",
                    hex::encode(&e.fingerprint[..8])
                )));
            }
            Some(_) => AddOutcome::Updated,
            None => AddOutcome::Added,
        };
        let val = Self::encode(fp, added_at, bundle);
        let w = self.db.begin_write().map_err(map_err)?;
        {
            let mut t = w.open_table(CONTACTS).map_err(map_err)?;
            t.insert(handle, val.as_slice()).map_err(map_err)?;
        }
        w.commit().map_err(map_err)?;
        Ok(outcome)
    }

    /// Fetch the entry for `handle`, if any.
    pub fn get(&self, handle: &str) -> Result<Option<KeyringEntry>> {
        let r = self.db.begin_read().map_err(map_err)?;
        let t = r.open_table(CONTACTS).map_err(map_err)?;
        match t.get(handle).map_err(map_err)? {
            Some(v) => Ok(Some(Self::decode(v.value())?)),
            None => Ok(None),
        }
    }

    /// `(handle, fingerprint)` for every entry, sorted by handle.
    pub fn list(&self) -> Result<Vec<(String, [u8; 32])>> {
        let r = self.db.begin_read().map_err(map_err)?;
        let t = r.open_table(CONTACTS).map_err(map_err)?;
        let mut out = Vec::new();
        for row in t.iter().map_err(map_err)? {
            let (k, v) = row.map_err(map_err)?;
            out.push((k.value().to_string(), Self::decode(v.value())?.fingerprint));
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }

    /// Remove `handle`. Returns whether a row existed.
    pub fn remove(&self, handle: &str) -> Result<bool> {
        let w = self.db.begin_write().map_err(map_err)?;
        let existed;
        {
            let mut t = w.open_table(CONTACTS).map_err(map_err)?;
            existed = t.remove(handle).map_err(map_err)?.is_some();
        }
        w.commit().map_err(map_err)?;
        Ok(existed)
    }

    // -- allowlist (authorization) --------------------------------------------

    /// Set `fp`'s grants (a `GRANT_*` bitmask), replacing any prior grants.
    pub fn authorize(&self, fp: &[u8; 32], grants: u8) -> Result<()> {
        let w = self.db.begin_write().map_err(map_err)?;
        {
            let mut t = w.open_table(ALLOWLIST).map_err(map_err)?;
            t.insert(fp.as_slice(), grants).map_err(map_err)?;
        }
        w.commit().map_err(map_err)?;
        Ok(())
    }

    /// The grants for `fp` (0 = not authorized / absent).
    pub fn grants(&self, fp: &[u8; 32]) -> Result<u8> {
        let r = self.db.begin_read().map_err(map_err)?;
        let t = r.open_table(ALLOWLIST).map_err(map_err)?;
        Ok(t.get(fp.as_slice()).map_err(map_err)?.map(|v| v.value()).unwrap_or(0))
    }

    /// Revoke all of `fp`'s grants (remove it). Returns whether it was present.
    pub fn deauthorize(&self, fp: &[u8; 32]) -> Result<bool> {
        let w = self.db.begin_write().map_err(map_err)?;
        let existed;
        {
            let mut t = w.open_table(ALLOWLIST).map_err(map_err)?;
            existed = t.remove(fp.as_slice()).map_err(map_err)?.is_some();
        }
        w.commit().map_err(map_err)?;
        Ok(existed)
    }

    /// Load the whole allowlist as `fingerprint -> grants` (for the authz preload).
    pub fn load_authz(&self) -> Result<std::collections::HashMap<[u8; 32], u8>> {
        let r = self.db.begin_read().map_err(map_err)?;
        let t = r.open_table(ALLOWLIST).map_err(map_err)?;
        let mut map = std::collections::HashMap::new();
        for row in t.iter().map_err(map_err)? {
            let (k, v) = row.map_err(map_err)?;
            let kb = k.value();
            if kb.len() == 32 {
                let mut fp = [0u8; 32];
                fp.copy_from_slice(kb);
                map.insert(fp, v.value());
            }
        }
        Ok(map)
    }

    /// `(fingerprint, grants)` for every authorized peer, sorted by fingerprint.
    pub fn list_grants(&self) -> Result<Vec<([u8; 32], u8)>> {
        let mut v: Vec<_> = self.load_authz()?.into_iter().collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(v)
    }

    // -- my identities (own key pairs, GPG-keyring style) ----------------------

    fn encode_identity(rec: &MyIdentityRecord) -> Vec<u8> {
        let mut v = Vec::with_capacity(
            HEADER_LEN + 4 + rec.public_key_der.len() + rec.encrypted_private_key_pem.len(),
        );
        v.extend_from_slice(&rec.fingerprint);
        v.extend_from_slice(&rec.added_at.to_le_bytes());
        v.extend_from_slice(&(rec.public_key_der.len() as u32).to_le_bytes());
        v.extend_from_slice(&rec.public_key_der);
        v.extend_from_slice(&rec.encrypted_private_key_pem);
        v
    }

    fn decode_identity(raw: &[u8]) -> Result<MyIdentityRecord> {
        if raw.len() < HEADER_LEN + 4 {
            return Err(CryptoError::Parameter("keyring: truncated identity record".into()));
        }
        let mut fp = [0u8; 32];
        fp.copy_from_slice(&raw[..32]);
        let added_at = u64::from_le_bytes(raw[32..HEADER_LEN].try_into().unwrap());
        let pub_len =
            u32::from_le_bytes(raw[HEADER_LEN..HEADER_LEN + 4].try_into().unwrap()) as usize;
        let pub_end = HEADER_LEN + 4 + pub_len;
        if raw.len() < pub_end {
            return Err(CryptoError::Parameter("keyring: truncated identity record".into()));
        }
        Ok(MyIdentityRecord {
            fingerprint: fp,
            added_at,
            public_key_der: raw[HEADER_LEN + 4..pub_end].to_vec(),
            encrypted_private_key_pem: raw[pub_end..].to_vec(),
        })
    }

    /// Store one of the user's own key pairs under `handle:role:algo`.
    /// Clobber-protected like [`KeyringStore::add`]: re-storing the same slot
    /// for a **different** fingerprint is refused (`remove-my-key` first); the
    /// same fingerprint is an idempotent update.
    pub fn put_my_identity(
        &self,
        handle: &str,
        role: &str,
        algo: &str,
        rec: &MyIdentityRecord,
    ) -> Result<AddOutcome> {
        let key = my_identity_key(handle, role, algo)?;
        let val = Self::encode_identity(rec);
        // Check-and-insert inside ONE write transaction, so a concurrent
        // writer cannot slip past the clobber protection between the check
        // and the insert.
        let w = self.db.begin_write().map_err(map_err)?;
        let outcome;
        {
            let mut t = w.open_table(MY_IDENTITIES).map_err(map_err)?;
            outcome = match t.get(key.as_str()).map_err(map_err)? {
                Some(v) => {
                    let existing = Self::decode_identity(v.value())?;
                    if existing.fingerprint != rec.fingerprint {
                        return Err(CryptoError::Parameter(format!(
                            "keyring: slot {key:?} already holds a different key \
                             ({}…) — remove-my-key it first",
                            hex::encode(&existing.fingerprint[..8])
                        )));
                    }
                    AddOutcome::Updated
                }
                None => AddOutcome::Added,
            };
            t.insert(key.as_str(), val.as_slice()).map_err(map_err)?;
        }
        w.commit().map_err(map_err)?;
        Ok(outcome)
    }

    /// Fetch the identity in slot `handle:role:algo`, if any.
    pub fn get_my_identity(
        &self,
        handle: &str,
        role: &str,
        algo: &str,
    ) -> Result<Option<MyIdentityRecord>> {
        let key = my_identity_key(handle, role, algo)?;
        let r = self.db.begin_read().map_err(map_err)?;
        let t = r.open_table(MY_IDENTITIES).map_err(map_err)?;
        match t.get(key.as_str()).map_err(map_err)? {
            Some(v) => Ok(Some(Self::decode_identity(v.value())?)),
            None => Ok(None),
        }
    }

    /// Every own-key slot as `(handle, role, algo, record)`, sorted by slot key.
    /// (Records include the encrypted private key; callers listing to a
    /// terminal only print the plaintext metadata.)
    pub fn list_my_identities(&self) -> Result<Vec<(String, String, String, MyIdentityRecord)>> {
        let r = self.db.begin_read().map_err(map_err)?;
        let t = r.open_table(MY_IDENTITIES).map_err(map_err)?;
        let mut out = Vec::new();
        for row in t.iter().map_err(map_err)? {
            let (k, v) = row.map_err(map_err)?;
            let key = k.value().to_string();
            let mut it = key.splitn(3, ':');
            let (h, ro, al) = (
                it.next().unwrap_or_default().to_string(),
                it.next().unwrap_or_default().to_string(),
                it.next().unwrap_or_default().to_string(),
            );
            out.push((h, ro, al, Self::decode_identity(v.value())?));
        }
        out.sort_by(|a, b| (&a.0, &a.1, &a.2).cmp(&(&b.0, &b.1, &b.2)));
        Ok(out)
    }

    /// Remove the identity slot `handle:role:algo`. Returns whether it existed.
    pub fn remove_my_identity(&self, handle: &str, role: &str, algo: &str) -> Result<bool> {
        let key = my_identity_key(handle, role, algo)?;
        let w = self.db.begin_write().map_err(map_err)?;
        let existed;
        {
            let mut t = w.open_table(MY_IDENTITIES).map_err(map_err)?;
            existed = t.remove(key.as_str()).map_err(map_err)?.is_some();
        }
        w.commit().map_err(map_err)?;
        Ok(existed)
    }
}

/// One of the user's own key pairs, encapsulated in the keyring.
/// (Debug is safe: the private key field only ever holds the
/// passphrase-encrypted PEM, the same bytes a key file exposes.)
#[derive(Debug)]
pub struct MyIdentityRecord {
    /// SHA3-256 of the RAW public key bytes — for a signing key this equals
    /// the KeyBundle owner fingerprint peers pin.
    pub fingerprint: [u8; 32],
    /// The public half as SPKI DER (plaintext: enables passphrase-less
    /// listing and bundle generation).
    pub public_key_der: Vec<u8>,
    /// The passphrase-encrypted PKCS#8 **PEM** bytes, exactly as a key file
    /// holds them. Never stored unencrypted — the importer rejects
    /// non-encrypted keys.
    pub encrypted_private_key_pem: Vec<u8>,
    /// Unix seconds when the key was imported.
    pub added_at: u64,
}

/// The `MY_IDENTITIES` slot key. `handle` must not contain `:` (it would be
/// ambiguous against the `handle:role:algo` framing); role/algo come from a
/// fixed internal vocabulary but are checked all the same.
pub fn my_identity_key(handle: &str, role: &str, algo: &str) -> Result<String> {
    if handle.is_empty() || handle.contains(':') {
        return Err(CryptoError::Parameter(format!(
            "keyring: invalid handle {handle:?} (must be non-empty, no ':')"
        )));
    }
    if role.is_empty() || role.contains(':') || algo.is_empty() {
        return Err(CryptoError::Parameter(format!(
            "keyring: invalid identity slot role={role:?} algo={algo:?}"
        )));
    }
    Ok(format!("{handle}:{role}:{algo}"))
}

// ---------------------------------------------------------------------------
// Identity import / auto-match helpers (lib-side so tests can drive them).
// ---------------------------------------------------------------------------

/// Classify a **decrypted** PKCS#8 `PrivateKeyInfo` by its algorithm OID:
/// `(algo, role)`. The role is `None` for EC keys — P-256 serves both ECDH
/// (enc) and ECDSA (sign) in nkCryptoTool, so the importer must be told.
pub fn classify_private_key(plain_pkcs8_der: &[u8]) -> Result<(String, Option<&'static str>)> {
    use pkcs8::der::Decode;
    let pki = pkcs8::PrivateKeyInfo::from_der(plain_pkcs8_der)
        .map_err(|e| CryptoError::Parameter(format!("PKCS#8 parse: {e}")))?;
    let oid = pki.algorithm.oid.to_string();
    Ok(match oid.as_str() {
        "2.16.840.1.101.3.4.4.1" => ("ML-KEM-512".into(), Some("enc")),
        "2.16.840.1.101.3.4.4.2" => ("ML-KEM-768".into(), Some("enc")),
        "2.16.840.1.101.3.4.4.3" => ("ML-KEM-1024".into(), Some("enc")),
        "2.16.840.1.101.3.4.3.17" => ("ML-DSA-44".into(), Some("sign")),
        "2.16.840.1.101.3.4.3.18" => ("ML-DSA-65".into(), Some("sign")),
        "2.16.840.1.101.3.4.3.19" => ("ML-DSA-87".into(), Some("sign")),
        // id-ecPublicKey is shared by every EC curve — the actual curve is a
        // named-curve OID in the parameters. Only P-256 is supported; anything
        // else must fail here, not as a confusing derive/decrypt error later.
        "1.2.840.10045.2.1" => {
            let curve = pki
                .algorithm
                .parameters
                .and_then(|p| p.decode_as::<pkcs8::ObjectIdentifier>().ok())
                .map(|oid| oid.to_string())
                .ok_or_else(|| {
                    CryptoError::Parameter("EC key has no named-curve parameter".into())
                })?;
            if curve != "1.2.840.10045.3.1.7" {
                return Err(CryptoError::Parameter(format!(
                    "unsupported EC curve OID {curve} (only P-256 / prime256v1)"
                )));
            }
            ("P-256".into(), None)
        }
        other => {
            return Err(CryptoError::Parameter(format!(
                "unsupported private-key algorithm OID {other}"
            )))
        }
    })
}

/// Derive `(spki_der, raw_pub)` from a **decrypted** PKCS#8 `PrivateKeyInfo`.
/// This is the binding check's ground truth: the public half is recomputed
/// from the private key, never trusted from the outside.
pub fn derive_public_from_private(
    plain_pkcs8_der: &[u8],
    algo: &str,
) -> Result<(Vec<u8>, Vec<u8>)> {
    match algo {
        "ML-KEM-512" | "ML-KEM-768" | "ML-KEM-1024" => {
            let raw_priv =
                crate::utils::unwrap_pqc_priv_from_pkcs8(plain_pkcs8_der, algo)?;
            let raw_pub = crate::backend::pqc_pub_from_priv_kem(algo, &raw_priv)?;
            let spki = crate::utils::wrap_pqc_pub_to_spki(&raw_pub, algo)?;
            Ok((spki, raw_pub))
        }
        "ML-DSA-44" | "ML-DSA-65" | "ML-DSA-87" => {
            let raw_priv =
                crate::utils::unwrap_pqc_priv_from_pkcs8(plain_pkcs8_der, algo)?;
            let raw_pub = crate::backend::pqc_pub_from_priv_dsa(algo, &raw_priv)?;
            let spki = crate::utils::wrap_pqc_pub_to_spki(&raw_pub, algo)?;
            Ok((spki, raw_pub))
        }
        "P-256" => {
            let spki = crate::backend::extract_public_key(plain_pkcs8_der, None)?;
            let raw = crate::utils::unwrap_pqc_pub_from_spki(&spki, "any")?;
            Ok((spki, raw))
        }
        other => Err(CryptoError::Parameter(format!(
            "unsupported algorithm {other}"
        ))),
    }
}

/// Validate an imported private-key PEM and build its keyring record.
///
/// - The PEM **must** hold a passphrase-encrypted PKCS#8 (`EncryptedPrivateKeyInfo`);
///   plaintext keys are refused — the keyring never stores an unprotected key.
/// - The passphrase must decrypt it (typo caught at import, not at first use).
/// - The public half is derived from the private key; when the caller supplies
///   an expected public key (from a pubkey file) it must match.
/// - ML-KEM keys additionally do an encap/decap round-trip as a functional
///   self-test.
///
/// Returns `(algo, inferred_role, record)`.
pub fn build_my_identity_record(
    encrypted_pem: &[u8],
    passphrase: &str,
    expected_pub_spki: Option<&[u8]>,
    added_at: u64,
) -> Result<(String, Option<&'static str>, MyIdentityRecord)> {
    use sha3::{Digest, Sha3_256};
    use zeroize::Zeroizing;

    let pem_str = std::str::from_utf8(encrypted_pem)
        .map_err(|_| CryptoError::Parameter("key file is not UTF-8 PEM".into()))?;
    let der = crate::utils::unwrap_from_pem(pem_str, "PRIVATE KEY")?;
    {
        use pkcs8::der::Decode;
        if pkcs8::EncryptedPrivateKeyInfo::from_der(&der).is_err() {
            return Err(CryptoError::Parameter(
                "refusing to import: the key is not passphrase-encrypted PKCS#8 \
                 (the keyring only stores encrypted private keys — re-export it \
                 with a passphrase first)"
                    .into(),
            ));
        }
    }
    let plain = Zeroizing::new(crate::utils::extract_raw_private_key(&der, Some(passphrase))?);
    let (algo, role) = classify_private_key(&plain)?;
    let (spki, raw_pub) = derive_public_from_private(&plain, &algo)?;

    if let Some(expected) = expected_pub_spki {
        // Compare on the raw public bytes so PEM/SPKI wrapping differences
        // cannot cause a false mismatch.
        let expected_raw = crate::utils::unwrap_pqc_pub_from_spki(expected, "any")?;
        if expected_raw != raw_pub {
            return Err(CryptoError::Parameter(
                "the supplied public key does not belong to this private key".into(),
            ));
        }
    }

    // Functional self-test for KEM keys: what we store must round-trip.
    if algo.starts_with("ML-KEM") {
        let raw_priv = crate::utils::unwrap_pqc_priv_from_pkcs8(&plain, &algo)?;
        let (ss1, ct) = crate::backend::pqc_encap(&algo, &raw_pub)?;
        let ss2 = crate::backend::pqc_decap(&algo, &raw_priv, &ct, None)?;
        if ss1.as_slice() != ss2.as_slice() {
            return Err(CryptoError::Parameter(
                "KEM self-test failed: encap/decap mismatch".into(),
            ));
        }
    }

    let fingerprint: [u8; 32] = Sha3_256::digest(&raw_pub).into();
    Ok((
        algo,
        role,
        MyIdentityRecord {
            fingerprint,
            public_key_der: spki,
            encrypted_private_key_pem: encrypted_pem.to_vec(),
            added_at,
        },
    ))
}

/// Unlock a stored identity for use: decrypt its PKCS#8 under `passphrase`,
/// re-derive the public half and require it to match the record (a swapped or
/// tampered record fails **before** any decryption output exists). Returns the
/// encrypted PEM text ready for in-memory injection into a strategy.
pub fn unlock_and_verify_identity(
    rec: &MyIdentityRecord,
    algo: &str,
    passphrase: &str,
) -> Result<zeroize::Zeroizing<String>> {
    use sha3::{Digest, Sha3_256};
    use zeroize::Zeroizing;

    let pem_str = std::str::from_utf8(&rec.encrypted_private_key_pem)
        .map_err(|_| CryptoError::Parameter("keyring: stored key is not UTF-8 PEM".into()))?;
    let der = crate::utils::unwrap_from_pem(pem_str, "PRIVATE KEY")?;
    let plain = Zeroizing::new(
        crate::utils::extract_raw_private_key(&der, Some(passphrase)).map_err(|e| {
            CryptoError::Parameter(format!(
                "could not unlock the keyring key (wrong passphrase, or the record \
                 was replaced): {e}"
            ))
        })?,
    );
    let (spki, raw_pub) = derive_public_from_private(&plain, algo)?;
    let fp: [u8; 32] = Sha3_256::digest(&raw_pub).into();
    if fp != rec.fingerprint || spki != rec.public_key_der {
        return Err(CryptoError::Parameter(
            "keyring: identity record failed its binding check (public key / \
             fingerprint do not match the private key) — the record may have \
             been tampered with"
                .into(),
        ));
    }
    Ok(Zeroizing::new(pem_str.to_string()))
}

/// What a v3 ciphertext header says about the keys needed to decrypt it.
#[derive(Debug, PartialEq, Eq)]
pub struct PeekedHeader {
    /// 1 = ECC, 2 = PQC, 3 = Hybrid (`StrategyType` discriminants).
    pub strategy: u8,
    /// The ECC curve (ECC and Hybrid files), keyring-algo form (`P-256`).
    pub ecc_algo: Option<String>,
    /// The ML-KEM algorithm (PQC and Hybrid files).
    pub kem_algo: Option<String>,
}

/// The keyring algo string for an on-wire ECC curve name.
fn curve_display(curve: &str) -> Result<String> {
    match curve {
        "prime256v1" | "P-256" => Ok("P-256".to_string()),
        other => Err(CryptoError::Parameter(format!(
            "unsupported ECC curve in header: {other}"
        ))),
    }
}

/// Peek `NKCT` v3 header fields needed for keyring auto-match, without
/// instantiating a strategy: magic, version, strategy byte, and the leading
/// algorithm string(s). Layout per `serialize_header` in ecc.rs / pqc.rs /
/// hybrid.rs.
pub fn peek_v3_header(bytes: &[u8]) -> Result<PeekedHeader> {
    fn read_u16(b: &[u8], p: &mut usize) -> Result<u16> {
        let v = b
            .get(*p..*p + 2)
            .ok_or_else(|| CryptoError::FileRead("truncated header".into()))?;
        *p += 2;
        Ok(u16::from_le_bytes(v.try_into().unwrap()))
    }
    fn read_u32(b: &[u8], p: &mut usize) -> Result<u32> {
        let v = b
            .get(*p..*p + 4)
            .ok_or_else(|| CryptoError::FileRead("truncated header".into()))?;
        *p += 4;
        Ok(u32::from_le_bytes(v.try_into().unwrap()))
    }
    fn read_string(b: &[u8], p: &mut usize) -> Result<String> {
        let len = read_u32(b, p)? as usize;
        if len > 256 {
            return Err(CryptoError::FileRead("implausible header string".into()));
        }
        let v = b
            .get(*p..*p + len)
            .ok_or_else(|| CryptoError::FileRead("truncated header".into()))?;
        *p += len;
        let s = String::from_utf8(v.to_vec())
            .map_err(|_| CryptoError::FileRead("non-UTF-8 header string".into()))?;
        // These are protocol constants, and the caller interpolates them into
        // errors that reach the operator's terminal (main.rs's keyring
        // auto-match path bails with the algorithm name in the message). The
        // length check above does not constrain the charset, so an ESC-laden
        // name would otherwise repaint the failure the operator is reading.
        crate::strategy::streaming_aead::validate_algo_name("header algorithm", &s)?;
        Ok(s)
    }

    if bytes.len() < 7 || &bytes[0..4] != b"NKCT" {
        return Err(CryptoError::FileRead("not an NKCT ciphertext".into()));
    }
    let mut p = 4;
    let version = read_u16(bytes, &mut p)?;
    if version != 3 {
        return Err(CryptoError::FileRead(format!(
            "unsupported NKCT version {version}"
        )));
    }
    let strategy = bytes[p];
    p += 1;
    match strategy {
        1 => Ok(PeekedHeader {
            strategy,
            ecc_algo: Some(curve_display(&read_string(bytes, &mut p)?)?),
            kem_algo: None,
        }),
        2 => Ok(PeekedHeader {
            strategy,
            ecc_algo: None,
            kem_algo: Some(read_string(bytes, &mut p)?),
        }),
        3 => {
            // Nested: u32 ecc_len ‖ ecc_header ‖ u32 pqc_len ‖ pqc_header.
            let ecc_len = read_u32(bytes, &mut p)? as usize;
            let ecc_h = bytes
                .get(p..p + ecc_len)
                .ok_or_else(|| CryptoError::FileRead("truncated hybrid header".into()))?;
            let inner = peek_v3_header(ecc_h)?;
            p += ecc_len;
            // Honor the declared inner length so the parse can never wander
            // into payload bytes; a peek buffer shorter than the declared
            // length is capped (the strings we need sit at the front).
            let pqc_len = read_u32(bytes, &mut p)? as usize;
            let end = p
                .checked_add(pqc_len)
                .ok_or_else(|| CryptoError::FileRead("implausible hybrid header".into()))?
                .min(bytes.len());
            let pqc_h = bytes
                .get(p..end)
                .ok_or_else(|| CryptoError::FileRead("truncated hybrid header".into()))?;
            let inner_pqc = peek_v3_header(pqc_h)?;
            Ok(PeekedHeader {
                strategy,
                ecc_algo: inner.ecc_algo,
                kem_algo: inner_pqc.kem_algo,
            })
        }
        other => Err(CryptoError::FileRead(format!(
            "unknown strategy type {other} in header"
        ))),
    }
}

fn map_err<E: std::fmt::Display>(e: E) -> CryptoError {
    CryptoError::Parameter(format!("keyring: redb: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("nkct-keyring-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.join("keyring.db")
    }

    /// A symlink planted at the keyring path must not be followed. The
    /// owner-only pre-create refuses the link with `AlreadyExists`, but handing
    /// redb the *path* afterwards let it re-resolve and follow the very link
    /// the create had refused, writing a fresh database over the target — and
    /// `open` returned `Ok`, because the only check that would have caught it
    /// (`harden_owner_only`) is best-effort here.
    #[cfg(unix)]
    #[test]
    fn keyring_path_symlink_is_refused_leaving_target_intact() {
        let path = tmp("symlink");
        // Zero length on purpose: redb adopts an empty file as a brand-new
        // database and initializes it in place, which is what turns a followed
        // link into the destruction of the target. A non-empty victim would be
        // rejected as a corrupt database and hide the defect entirely.
        let victim = path.parent().expect("dir").join("victim");
        std::fs::write(&victim, b"").expect("write victim");
        std::os::unix::fs::symlink(&victim, &path).expect("plant symlink");

        assert!(
            KeyringStore::open(&path).is_err(),
            "a symlink at the keyring path must not be opened"
        );

        assert_eq!(
            std::fs::metadata(&victim).expect("victim still present").len(),
            0,
            "the symlink target must not be written through by the keyring open"
        );
        // Refused, not deleted: the link itself is left exactly as planted.
        assert!(std::fs::symlink_metadata(&path)
            .expect("link still present")
            .file_type()
            .is_symlink());
    }

    /// The other direction of the no-follow open: refusing links must not cost
    /// the honest case. An existing keyring re-opens through the handle and
    /// still reads back what a previous session stored.
    #[test]
    fn existing_keyring_reopens_with_entries_intact() {
        // Distinct from `reopen_persists`'s tag: `tmp` wipes and recreates the
        // directory it names, so two tests sharing a tag race for one redb file
        // and collide on its exclusive lock when the suite runs in parallel.
        let path = tmp("reopen-intact");
        {
            let ks = KeyringStore::open(&path).expect("create");
            ks.add("alice", &[5u8; 32], b"bundle-a", 42).expect("add");
        }
        let ks = KeyringStore::open(&path).expect("reopen existing");
        let e = ks.get("alice").expect("get").expect("present");
        assert_eq!(e.fingerprint, [5u8; 32]);
        assert_eq!(e.bundle, b"bundle-a");
        assert_eq!(e.added_at, 42);
    }

    /// Deliberate behaviour change, pinned: `open` now refuses a keyring that
    /// carries a second hard link, which it used to accept — the refusal lives
    /// in `harden_owner_only`, whose result this call site discards. A second
    /// name for a secret file is the aliasing primitive `secure_fs` exists to
    /// refuse, and `nlink > 1` taints *both* names, so a keyring a
    /// hard-linking backup has touched needs the extra name dropped (or a real
    /// copy taken) before it opens again. Nothing is damaged by the refusal.
    #[cfg(unix)]
    #[test]
    fn hard_linked_keyring_is_refused() {
        let path = tmp("hardlink");
        {
            let ks = KeyringStore::open(&path).expect("create");
            ks.add("alice", &[5u8; 32], b"bundle-a", 42).expect("add");
        }
        let alias = path.parent().expect("dir").join("alias.db");
        std::fs::hard_link(&path, &alias).expect("hard link");

        assert!(
            KeyringStore::open(&path).is_err(),
            "a multi-hard-linked keyring must be refused"
        );

        std::fs::remove_file(&alias).expect("unlink alias");
        let ks = KeyringStore::open(&path).expect("reopen once the extra link is gone");
        assert_eq!(ks.get("alice").expect("get").expect("present").bundle, b"bundle-a");
    }

    #[test]
    fn add_rejects_a_handle_that_could_repaint_keyring_list() {
        // The handle is usually authored by the bundle's owner, and `keyring
        // list` is the table an operator reads before `--recipient <handle>`.
        // Signature verification proves who wrote the handle, not that it is
        // well-formed, so the charset gate has to live in `add` itself.
        let path = tmp("handle");
        let ks = KeyringStore::open(&path).unwrap();
        let fp = [3u8; 32];
        let hostile = "mallory\u{1b}[1A\u{1b}[2K0000  alice";
        assert!(ks.add(hostile, &fp, b"bundle", 1).is_err());
        assert!(ks.get(hostile).unwrap().is_none(), "hostile handle was stored");

        // Sibling rejections and the shapes that must keep working.
        assert!(ks.add("with space", &fp, b"b", 1).is_err());
        assert!(ks.add(".hidden", &fp, b"b", 1).is_err());
        assert!(ks.add("", &fp, b"b", 1).is_err());
        assert!(ks.add("alice", &fp, b"b", 1).is_ok());
        assert!(ks.add("alice.laptop-2_v3", &fp, b"b", 1).is_ok());
    }

    #[test]
    fn add_get_list_remove_roundtrip() {
        let path = tmp("rt");
        let ks = KeyringStore::open(&path).unwrap();
        let fp_a = [1u8; 32];
        let fp_b = [2u8; 32];
        assert_eq!(ks.add("alice", &fp_a, b"bundle-a", 100).unwrap(), AddOutcome::Added);
        assert_eq!(ks.add("bob", &fp_b, b"bundle-b", 200).unwrap(), AddOutcome::Added);

        let e = ks.get("alice").unwrap().unwrap();
        assert_eq!(e.fingerprint, fp_a);
        assert_eq!(e.added_at, 100);
        assert_eq!(e.bundle, b"bundle-a");
        assert!(ks.get("nobody").unwrap().is_none());

        let list = ks.list().unwrap();
        assert_eq!(list, vec![("alice".into(), fp_a), ("bob".into(), fp_b)]);

        assert!(ks.remove("alice").unwrap());
        assert!(!ks.remove("alice").unwrap());
        assert!(ks.get("alice").unwrap().is_none());
    }

    #[test]
    fn same_identity_updates_idempotently() {
        let path = tmp("idem");
        let ks = KeyringStore::open(&path).unwrap();
        let fp = [7u8; 32];
        assert_eq!(ks.add("x", &fp, b"v1", 1).unwrap(), AddOutcome::Added);
        assert_eq!(ks.add("x", &fp, b"v2", 2).unwrap(), AddOutcome::Updated);
        let e = ks.get("x").unwrap().unwrap();
        assert_eq!(e.bundle, b"v2");
        assert_eq!(e.added_at, 2);
    }

    #[test]
    fn different_identity_cannot_clobber_a_handle() {
        let path = tmp("clobber");
        let ks = KeyringStore::open(&path).unwrap();
        ks.add("shared", &[1u8; 32], b"a", 1).unwrap();
        let r = ks.add("shared", &[9u8; 32], b"b", 2);
        assert!(r.is_err(), "a different fingerprint must not overwrite the handle");
        // The original entry is intact.
        assert_eq!(ks.get("shared").unwrap().unwrap().bundle, b"a");
    }

    #[test]
    fn allowlist_grants_roundtrip() {
        let path = tmp("authz");
        let ks = KeyringStore::open(&path).unwrap();
        let a = [0xAAu8; 32];
        let b = [0xBBu8; 32];
        assert_eq!(ks.grants(&a).unwrap(), 0, "absent fp has no grants");
        ks.authorize(&a, GRANT_SHELL | GRANT_SCP).unwrap();
        ks.authorize(&b, GRANT_ALL).unwrap();
        assert_eq!(ks.grants(&a).unwrap(), GRANT_SHELL | GRANT_SCP);
        assert_eq!(ks.grants(&a).unwrap() & GRANT_FORWARD, 0, "a is not forward-granted");
        assert_eq!(ks.grants(&b).unwrap(), GRANT_ALL);

        let authz = ks.load_authz().unwrap();
        assert_eq!(authz.get(&a).copied(), Some(GRANT_SHELL | GRANT_SCP));
        assert_eq!(authz.get(&b).copied(), Some(GRANT_ALL));

        // re-authorize replaces grants; deauthorize removes.
        ks.authorize(&a, GRANT_FORWARD).unwrap();
        assert_eq!(ks.grants(&a).unwrap(), GRANT_FORWARD);
        assert!(ks.deauthorize(&a).unwrap());
        assert!(!ks.deauthorize(&a).unwrap());
        assert_eq!(ks.grants(&a).unwrap(), 0);
    }

    #[test]
    fn reopen_persists() {
        let path = tmp("reopen");
        {
            let ks = KeyringStore::open(&path).unwrap();
            ks.add("p", &[3u8; 32], b"persisted", 5).unwrap();
        }
        let ks = KeyringStore::open(&path).unwrap();
        assert_eq!(ks.get("p").unwrap().unwrap().bundle, b"persisted");
    }

    fn ident(fp_byte: u8) -> MyIdentityRecord {
        MyIdentityRecord {
            fingerprint: [fp_byte; 32],
            public_key_der: vec![0x30, 0x03, 0x01, 0x02, fp_byte],
            encrypted_private_key_pem: b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nAA\n-----END ENCRYPTED PRIVATE KEY-----\n".to_vec(),
            added_at: 42,
        }
    }

    #[test]
    fn my_identity_roundtrip_and_clobber_protection() {
        let path = tmp("ident");
        let ks = KeyringStore::open(&path).unwrap();
        assert_eq!(
            ks.put_my_identity("me", "enc", "ML-KEM-768", &ident(7)).unwrap(),
            AddOutcome::Added
        );
        // Same slot + same fingerprint → idempotent update.
        assert_eq!(
            ks.put_my_identity("me", "enc", "ML-KEM-768", &ident(7)).unwrap(),
            AddOutcome::Updated
        );
        // Same slot, different key → refused.
        assert!(ks.put_my_identity("me", "enc", "ML-KEM-768", &ident(8)).is_err());
        // Distinct role/algo slots coexist under one handle.
        ks.put_my_identity("me", "sign", "ML-DSA-65", &ident(9)).unwrap();

        let got = ks.get_my_identity("me", "enc", "ML-KEM-768").unwrap().unwrap();
        assert_eq!(got.fingerprint, [7u8; 32]);
        assert_eq!(got.public_key_der, ident(7).public_key_der);
        assert_eq!(got.encrypted_private_key_pem, ident(7).encrypted_private_key_pem);
        assert_eq!(got.added_at, 42);

        let all = ks.list_my_identities().unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(
            (all[0].0.as_str(), all[0].1.as_str(), all[0].2.as_str()),
            ("me", "enc", "ML-KEM-768")
        );
        assert_eq!(
            (all[1].0.as_str(), all[1].1.as_str(), all[1].2.as_str()),
            ("me", "sign", "ML-DSA-65")
        );

        assert!(ks.remove_my_identity("me", "enc", "ML-KEM-768").unwrap());
        assert!(!ks.remove_my_identity("me", "enc", "ML-KEM-768").unwrap());
        assert!(ks.get_my_identity("me", "enc", "ML-KEM-768").unwrap().is_none());
    }

    #[test]
    fn my_identity_key_rejects_colon_handle() {
        assert!(my_identity_key("a:b", "enc", "ML-KEM-768").is_err());
        assert!(my_identity_key("", "enc", "ML-KEM-768").is_err());
        assert!(my_identity_key("me", "enc", "ML-KEM-768").is_ok());
    }

    /// A freshly generated ML-KEM key as encrypted PKCS#8 PEM bytes plus its
    /// raw public key.
    fn gen_encrypted_kem_pem(pass: &str) -> (Vec<u8>, Vec<u8>) {
        let (raw_priv, raw_pub, _) = crate::backend::pqc_keygen_kem("ML-KEM-768").unwrap();
        let enc_der =
            crate::utils::wrap_pqc_priv_to_pkcs8_encrypted(&raw_priv, "ML-KEM-768", pass)
                .unwrap();
        let pem = crate::utils::wrap_to_pem(&enc_der, "ENCRYPTED PRIVATE KEY");
        (pem.into_bytes(), raw_pub)
    }

    #[test]
    fn import_classifies_derives_and_binds() {
        use sha3::{Digest, Sha3_256};
        let (pem, raw_pub) = gen_encrypted_kem_pem("pw-1");

        let (algo, role, rec) = build_my_identity_record(&pem, "pw-1", None, 7).unwrap();
        assert_eq!(algo, "ML-KEM-768");
        assert_eq!(role, Some("enc"));
        let expected_fp: [u8; 32] = Sha3_256::digest(&raw_pub).into();
        assert_eq!(rec.fingerprint, expected_fp, "fingerprint = SHA3-256(raw pub)");
        assert_eq!(rec.encrypted_private_key_pem, pem);

        // Wrong passphrase is caught at import.
        assert!(build_my_identity_record(&pem, "wrong", None, 7).is_err());

        // A mismatched expected-pubkey is caught.
        let (_, other_pub, _) = crate::backend::pqc_keygen_kem("ML-KEM-768").unwrap();
        let other_spki = crate::utils::wrap_pqc_pub_to_spki(&other_pub, "ML-KEM-768").unwrap();
        assert!(build_my_identity_record(&pem, "pw-1", Some(&other_spki), 7).is_err());
        // The matching one passes.
        let spki = crate::utils::wrap_pqc_pub_to_spki(&raw_pub, "ML-KEM-768").unwrap();
        assert!(build_my_identity_record(&pem, "pw-1", Some(&spki), 7).is_ok());
    }

    #[test]
    fn import_refuses_plaintext_key() {
        let (raw_priv, _, _) = crate::backend::pqc_keygen_kem("ML-KEM-768").unwrap();
        let plain_der = crate::utils::wrap_pqc_priv_to_pkcs8(&raw_priv, "ML-KEM-768").unwrap();
        let pem = crate::utils::wrap_to_pem(&plain_der, "PRIVATE KEY");
        let err = build_my_identity_record(pem.as_bytes(), "pw", None, 7).unwrap_err();
        assert!(err.to_string().contains("not passphrase-encrypted"), "{err}");
    }

    #[test]
    fn unlock_verifies_binding_and_rejects_tamper() {
        let (pem, _) = gen_encrypted_kem_pem("pw-2");
        let (algo, _, mut rec) = build_my_identity_record(&pem, "pw-2", None, 7).unwrap();

        // Genuine record + right passphrase unlocks.
        assert!(unlock_and_verify_identity(&rec, &algo, "pw-2").is_ok());
        // Wrong passphrase fails closed.
        assert!(unlock_and_verify_identity(&rec, &algo, "nope").is_err());

        // A tampered public half (as an attacker with DB write access could
        // plant) fails the binding check even with the right passphrase.
        rec.public_key_der[40] ^= 1;
        let err = unlock_and_verify_identity(&rec, &algo, "pw-2").unwrap_err();
        assert!(err.to_string().contains("binding"), "{err}");
    }

    #[test]
    fn peek_v3_header_parses_all_strategies() {
        fn lp(s: &str) -> Vec<u8> {
            let mut v = (s.len() as u32).to_le_bytes().to_vec();
            v.extend_from_slice(s.as_bytes());
            v
        }
        // ECC: magic ‖ ver ‖ 1 ‖ lp(curve)
        let mut ecc = b"NKCT".to_vec();
        ecc.extend_from_slice(&3u16.to_le_bytes());
        ecc.push(1);
        ecc.extend(lp("prime256v1"));
        let p = peek_v3_header(&ecc).unwrap();
        assert_eq!(
            p,
            PeekedHeader { strategy: 1, ecc_algo: Some("P-256".into()), kem_algo: None }
        );

        // PQC: magic ‖ ver ‖ 2 ‖ lp(kem)
        let mut pqc = b"NKCT".to_vec();
        pqc.extend_from_slice(&3u16.to_le_bytes());
        pqc.push(2);
        pqc.extend(lp("ML-KEM-768"));
        let p = peek_v3_header(&pqc).unwrap();
        assert_eq!(
            p,
            PeekedHeader { strategy: 2, ecc_algo: None, kem_algo: Some("ML-KEM-768".into()) }
        );

        // Hybrid: magic ‖ ver ‖ 3 ‖ u32(ecc_len) ‖ ecc_h ‖ u32(pqc_len) ‖ pqc_h
        let mut hy = b"NKCT".to_vec();
        hy.extend_from_slice(&3u16.to_le_bytes());
        hy.push(3);
        hy.extend_from_slice(&(ecc.len() as u32).to_le_bytes());
        hy.extend_from_slice(&ecc);
        hy.extend_from_slice(&(pqc.len() as u32).to_le_bytes());
        hy.extend_from_slice(&pqc);
        let p = peek_v3_header(&hy).unwrap();
        assert_eq!(
            p,
            PeekedHeader {
                strategy: 3,
                ecc_algo: Some("P-256".into()),
                kem_algo: Some("ML-KEM-768".into()),
            }
        );

        // Garbage / truncation fail closed.
        assert!(peek_v3_header(b"NOPE").is_err());
        assert!(peek_v3_header(&ecc[..8]).is_err());
    }
}
