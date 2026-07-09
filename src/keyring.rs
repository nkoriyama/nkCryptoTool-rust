/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

//! redb-backed **keyring**: a local store of received/known KeyBundles, keyed by
//! handle. Replaces the per-file `<key-dir>/received/<handle>.nkkb` artefacts
//! pairing used to write. Each entry records the **trusted owner fingerprint**
//! (the pin, established when the entry was written) alongside the bundle bytes,
//! so a consumer can `parse_and_verify` the stored bundle against the stored pin
//! at use time.
//!
//! **Not encrypted at rest**: a KeyBundle is public data (self-signed public
//! keys), so there is no secret to protect — the store is plain redb, guarded by
//! `0600` like `--peer-allowlist`. The anchor is the *integrity* of the file
//! (who may write it), not confidentiality. Tampering that changes a bundle but
//! not its stored fingerprint is caught at read time (the bundle no longer
//! verifies against the pin); changing both requires write access, which the
//! file permissions restrict.

use crate::error::CryptoError;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use std::path::Path;

type Result<T> = std::result::Result<T, CryptoError>;

/// `handle -> fingerprint(32) ‖ added_at(8 LE) ‖ keybundle_bytes`.
const CONTACTS: TableDefinition<&str, &[u8]> = TableDefinition::new("keyring_contacts_v1");

/// Fixed prefix of every value: 32-byte fingerprint + 8-byte little-endian time.
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

/// A plain (unencrypted) redb keyring of KeyBundles.
pub struct KeyringStore {
    db: Database,
}

impl KeyringStore {
    /// Open (or create) the keyring at `path`. Creates the table on first use and
    /// tightens the file to `0600` on unix.
    pub fn open(path: &Path) -> Result<Self> {
        let db = Database::create(path)
            .map_err(|e| CryptoError::Parameter(format!("keyring: open {path:?}: {e}")))?;
        // Ensure the table exists so a read on a fresh DB does not error.
        {
            let w = db.begin_write().map_err(map_err)?;
            w.open_table(CONTACTS).map_err(map_err)?;
            w.commit().map_err(map_err)?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
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
    pub fn add(&self, handle: &str, fp: &[u8; 32], bundle: &[u8], added_at: u64) -> Result<AddOutcome> {
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
    fn reopen_persists() {
        let path = tmp("reopen");
        {
            let ks = KeyringStore::open(&path).unwrap();
            ks.add("p", &[3u8; 32], b"persisted", 5).unwrap();
        }
        let ks = KeyringStore::open(&path).unwrap();
        assert_eq!(ks.get("p").unwrap().unwrap().bundle, b"persisted");
    }
}
