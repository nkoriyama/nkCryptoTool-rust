//! Pure-Rust MLS storage backend (P1 prototype) — SQLCipher replacement.
//!
//! This module implements the three `mls-rs-core` storage traits
//! ([`GroupStateStorage`], [`KeyPackageStorage`], [`PreSharedKeyStorage`])
//! over [`redb`](https://docs.rs/redb), a pure-Rust embedded key-value store,
//! with **application-layer authenticated encryption** of every stored value.
//!
//! ## Why
//!
//! The existing [`crate::group::storage`] uses `mls-rs-provider-sqlite` with
//! SQLCipher, which dynamically links the system `libcrypto` even when the
//! `openssl` crate is absent (the SQLCipher C code provides page encryption via
//! OpenSSL). That blocks Android/iOS cross-compilation. redb is pure Rust, so
//! the `mls` storage layer becomes fully C-free. See `DB_PURERUST_DESIGN.md`.
//!
//! ## Encryption design (see `DB_PURERUST_DESIGN.md` §3)
//!
//! SQLCipher encrypted whole *pages* transparently. Here we instead encrypt
//! each *value* at the application layer:
//!
//! - **Cipher**: XChaCha20-Poly1305. Its 192-bit nonce lets us pick a fresh
//!   random nonce per record with `OsRng` and ignore birthday-bound collisions
//!   (unlike AES-GCM's 96-bit nonce).
//! - **Keys**: the 32-byte at-rest DEK is never used directly. Two subkeys are
//!   derived with HKDF-SHA256 and distinct `info` labels:
//!     - `k_value` — value encryption key.
//!     - `k_bi` — HMAC-SHA256 key for the *blind index* used as the redb key.
//! - **Blind index**: logical identifiers (group_id, key-package id, psk_id)
//!   are not stored in the clear. Each becomes `HMAC-SHA256(k_bi, id)` — a
//!   fixed 32-byte key. This (a) blinds identifiers at rest and (b) makes all
//!   composite keys fixed-length, so epoch range scans are prefix-safe.
//! - **AAD**: every value is sealed with
//!   `aad = db_binding ‖ table_id ‖ redb_key`, binding the ciphertext to its
//!   exact slot. A relay/attacker that copies one record's bytes into another
//!   slot fails AEAD tag verification on read (swap-attack detection).
//!
//! ## Record layout
//!
//! ```text
//! record = VERSION(1) ‖ nonce(24) ‖ ciphertext‖tag
//! ```
//!
//! ## Sync-only
//!
//! `mls-rs` is built in its default synchronous mode in this crate, so the
//! storage trait methods are plain `fn` (the upstream `maybe_async` macro
//! lowers the `async fn` trait definitions to sync). If this crate ever enables
//! `mls-rs`'s `async` feature these impls must grow the same `maybe_async`
//! attributes the sqlite provider uses.

use std::path::Path;
use std::sync::Arc;

use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use mls_rs_core::group::{EpochRecord, GroupState, GroupStateStorage};
use mls_rs_core::key_package::{KeyPackageData, KeyPackageStorage};
use mls_rs_core::mls_rs_codec::{MlsDecode, MlsEncode};
use mls_rs_core::psk::{ExternalPskId, PreSharedKey, PreSharedKeyStorage};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use sha2::Sha256;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// Default number of prior epochs retained per group, mirroring
/// `mls-rs-provider-sqlite`'s `DEFAULT_EPOCH_RETENTION_LIMIT`.
const DEFAULT_EPOCH_RETENTION_LIMIT: u64 = 3;

/// Record format version byte (first byte of every sealed value).
const RECORD_VERSION: u8 = 1;
const NONCE_LEN: usize = 24; // XChaCha20-Poly1305 nonce

// Table ids — also folded into the AEAD AAD for cross-table domain separation.
const TID_GROUP: u8 = 1;
const TID_EPOCH: u8 = 2;
const TID_KEY_PACKAGE: u8 = 3;
const TID_PSK: u8 = 4;

const TBL_GROUP: TableDefinition<&[u8], &[u8]> = TableDefinition::new("mls_group_state");
const TBL_EPOCH: TableDefinition<&[u8], &[u8]> = TableDefinition::new("mls_epoch");
const TBL_KEY_PACKAGE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("mls_key_package");
const TBL_PSK: TableDefinition<&[u8], &[u8]> = TableDefinition::new("mls_psk");

const BLIND_INDEX_LEN: usize = 32;

/// Errors from the redb storage backend.
#[derive(Debug, thiserror::Error)]
pub enum RedbStorageError {
    #[error("redb backend error: {0}")]
    Backend(String),
    #[error("record decrypt/verify failed (bad key or tampered record)")]
    Decrypt,
    #[error("encrypt failed")]
    Encrypt,
    #[error("codec error: {0}")]
    Codec(String),
    #[error("malformed record: {0}")]
    Malformed(String),
}

// `mls-rs-core` needs the storage error to be convertible into its erased
// `AnyError`. The default `into_any_error` would format via `Debug`; provide
// `into_dyn_error` so the real `std::error::Error` chain is preserved.
impl mls_rs_core::error::IntoAnyError for RedbStorageError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(Box::new(self))
    }
}

/// Subkeys derived from the at-rest DEK. Never holds the DEK itself.
struct RecordKeys {
    k_value: Zeroizing<[u8; 32]>,
    k_bi: Zeroizing<[u8; 32]>,
}

impl RecordKeys {
    fn derive(dek: &[u8; 32]) -> Self {
        let hk = Hkdf::<Sha256>::new(None, dek);
        let mut k_value = Zeroizing::new([0u8; 32]);
        let mut k_bi = Zeroizing::new([0u8; 32]);
        // `expand` only fails for absurd output lengths; 32 bytes never fails.
        hk.expand(b"nkct-redb-value-v1", k_value.as_mut_slice())
            .expect("hkdf expand k_value");
        hk.expand(b"nkct-redb-blindindex-v1", k_bi.as_mut_slice())
            .expect("hkdf expand k_bi");
        Self { k_value, k_bi }
    }
}

/// Shared, cloneable handle to the encrypted redb database.
///
/// Cloning shares the underlying [`Database`] (via `Arc`) and re-derives no
/// keys — the three storage structs each hold a clone so they can be stacked
/// into an `mls_rs::Client`.
#[derive(Clone)]
pub struct RedbBackend {
    db: Arc<Database>,
    keys: Arc<RecordKeys>,
    /// Bound into the AEAD AAD so the same DEK used for two different DB files
    /// cannot cross-decrypt. Derived from the DB file name.
    db_binding: Arc<Vec<u8>>,
    max_epoch_retention: u64,
}

impl std::fmt::Debug for RedbBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedbBackend")
            .field("max_epoch_retention", &self.max_epoch_retention)
            .finish_non_exhaustive()
    }
}

impl RedbBackend {
    /// Open (or create) the encrypted redb database at `path`, deriving the
    /// value/blind-index subkeys from the 32-byte at-rest `dek`.
    ///
    /// All tables are created eagerly so later read transactions never hit
    /// `TableDoesNotExist` on a fresh database.
    pub fn open(path: impl AsRef<Path>, dek: &[u8; 32]) -> Result<Self, RedbStorageError> {
        let path = path.as_ref();
        let db_binding = path
            .file_name()
            .map(|n| n.as_encoded_bytes().to_vec())
            .unwrap_or_default();
        let db = Database::create(path).map_err(|e| RedbStorageError::Backend(e.to_string()))?;

        let me = Self {
            db: Arc::new(db),
            keys: Arc::new(RecordKeys::derive(dek)),
            db_binding: Arc::new(db_binding),
            max_epoch_retention: DEFAULT_EPOCH_RETENTION_LIMIT,
        };
        me.create_tables()?;
        me.tighten_permissions(path)?;
        Ok(me)
    }

    fn create_tables(&self) -> Result<(), RedbStorageError> {
        let wtx = self
            .db
            .begin_write()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        {
            wtx.open_table(TBL_GROUP)
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            wtx.open_table(TBL_EPOCH)
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            wtx.open_table(TBL_KEY_PACKAGE)
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            wtx.open_table(TBL_PSK)
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        }
        wtx.commit()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))
    }

    /// Tighten the DB file to `0o600` on Unix (defence in depth, matching the
    /// sqlite path). No-op elsewhere.
    fn tighten_permissions(&self, path: &Path) -> Result<(), RedbStorageError> {
        #[cfg(unix)]
        if path.exists() {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(path)
                .map_err(|e| RedbStorageError::Backend(format!("metadata: {e}")))?
                .permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(path, perms)
                .map_err(|e| RedbStorageError::Backend(format!("chmod: {e}")))?;
        }
        let _ = path;
        Ok(())
    }

    /// Override the prior-epoch retention limit (mainly for tests).
    #[must_use]
    pub fn with_max_epoch_retention(mut self, n: u64) -> Self {
        self.max_epoch_retention = n;
        self
    }

    pub fn group_state_storage(&self) -> RedbGroupStateStorage {
        RedbGroupStateStorage(self.clone())
    }

    pub fn key_package_storage(&self) -> RedbKeyPackageStorage {
        RedbKeyPackageStorage(self.clone())
    }

    pub fn pre_shared_key_storage(&self) -> RedbPreSharedKeyStorage {
        RedbPreSharedKeyStorage(self.clone())
    }

    // --- crypto helpers ---------------------------------------------------

    /// Blind index for a logical identifier: `HMAC-SHA256(k_bi, id)`.
    fn blind_index(&self, id: &[u8]) -> [u8; BLIND_INDEX_LEN] {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(self.keys.k_bi.as_slice())
            .expect("HMAC accepts any key length");
        mac.update(id);
        mac.finalize().into_bytes().into()
    }

    fn aad(&self, table_id: u8, redb_key: &[u8]) -> Vec<u8> {
        let mut aad = Vec::with_capacity(self.db_binding.len() + 1 + redb_key.len());
        aad.extend_from_slice(&self.db_binding);
        aad.push(table_id);
        aad.extend_from_slice(redb_key);
        aad
    }

    /// Encrypt `plaintext` into a self-describing record bound to its slot.
    fn seal(
        &self,
        table_id: u8,
        redb_key: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, RedbStorageError> {
        let cipher = XChaCha20Poly1305::new_from_slice(self.keys.k_value.as_slice())
            .map_err(|_| RedbStorageError::Encrypt)?;
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let aad = self.aad(table_id, redb_key);
        let ct = cipher
            .encrypt(&nonce, Payload { msg: plaintext, aad: &aad })
            .map_err(|_| RedbStorageError::Encrypt)?;

        let mut out = Vec::with_capacity(1 + NONCE_LEN + ct.len());
        out.push(RECORD_VERSION);
        out.extend_from_slice(nonce.as_slice());
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Decrypt a record produced by [`Self::seal`], verifying the slot binding.
    fn open_record(
        &self,
        table_id: u8,
        redb_key: &[u8],
        record: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, RedbStorageError> {
        if record.len() < 1 + NONCE_LEN {
            return Err(RedbStorageError::Malformed("record too short".into()));
        }
        if record[0] != RECORD_VERSION {
            return Err(RedbStorageError::Malformed(format!(
                "unknown record version {}",
                record[0]
            )));
        }
        let nonce = XNonce::from_slice(&record[1..1 + NONCE_LEN]);
        let ct = &record[1 + NONCE_LEN..];
        let cipher = XChaCha20Poly1305::new_from_slice(self.keys.k_value.as_slice())
            .map_err(|_| RedbStorageError::Decrypt)?;
        let aad = self.aad(table_id, redb_key);
        let pt = cipher
            .decrypt(nonce, Payload { msg: ct, aad: &aad })
            .map_err(|_| RedbStorageError::Decrypt)?;
        Ok(Zeroizing::new(pt))
    }

    // --- typed get/put helpers -------------------------------------------

    fn put(&self, def: TableDefinition<&[u8], &[u8]>, key: &[u8], value: &[u8]) -> Result<(), RedbStorageError> {
        let wtx = self
            .db
            .begin_write()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        {
            let mut table = wtx
                .open_table(def)
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            table
                .insert(key, value)
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        }
        wtx.commit()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))
    }

    fn get_raw(
        &self,
        def: TableDefinition<&[u8], &[u8]>,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, RedbStorageError> {
        let rtx = self
            .db
            .begin_read()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        let table = rtx
            .open_table(def)
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        let got = table
            .get(key)
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        Ok(got.map(|g| g.value().to_vec()))
    }

    fn delete(&self, def: TableDefinition<&[u8], &[u8]>, key: &[u8]) -> Result<(), RedbStorageError> {
        let wtx = self
            .db
            .begin_write()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        {
            let mut table = wtx
                .open_table(def)
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            table
                .remove(key)
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        }
        wtx.commit()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))
    }
}

/// Build the fixed-length composite epoch key: `blind_index(group) ‖ epoch_be`.
fn epoch_key(gkey: &[u8; BLIND_INDEX_LEN], epoch_id: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(BLIND_INDEX_LEN + 8);
    k.extend_from_slice(gkey);
    k.extend_from_slice(&epoch_id.to_be_bytes());
    k
}

// ===================== GroupStateStorage =============================

/// redb-backed [`GroupStateStorage`].
#[derive(Clone, Debug)]
pub struct RedbGroupStateStorage(RedbBackend);

impl RedbGroupStateStorage {
    fn write_inner(
        &self,
        state: GroupState,
        inserts: Vec<EpochRecord>,
        updates: Vec<EpochRecord>,
    ) -> Result<(), RedbStorageError> {
        let b = &self.0;
        let gkey = b.blind_index(&state.id);

        let wtx = b
            .db
            .begin_write()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        {
            // Snapshot upsert.
            let mut gtable = wtx
                .open_table(TBL_GROUP)
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            let sealed = b.seal(TID_GROUP, &gkey, &state.data)?;
            gtable
                .insert(gkey.as_slice(), sealed.as_slice())
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        }
        {
            let mut etable = wtx
                .open_table(TBL_EPOCH)
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;

            let mut max_epoch_id: Option<u64> = None;
            for epoch in inserts.iter().chain(updates.iter()) {
                max_epoch_id = Some(max_epoch_id.map_or(epoch.id, |m| m.max(epoch.id)));
                let ekey = epoch_key(&gkey, epoch.id);
                let sealed = b.seal(TID_EPOCH, &ekey, &epoch.data)?;
                etable
                    .insert(ekey.as_slice(), sealed.as_slice())
                    .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            }

            // Prior-epoch retention: drop epochs with id <= max - retention.
            if let Some(max_id) = max_epoch_id {
                if max_id >= b.max_epoch_retention {
                    let delete_under = max_id - b.max_epoch_retention;
                    let lo = epoch_key(&gkey, 0);
                    let hi = epoch_key(&gkey, delete_under);
                    let mut to_delete: Vec<Vec<u8>> = Vec::new();
                    {
                        let range = etable
                            .range::<&[u8]>(lo.as_slice()..=hi.as_slice())
                            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
                        for entry in range {
                            let (k, _v) =
                                entry.map_err(|e| RedbStorageError::Backend(e.to_string()))?;
                            to_delete.push(k.value().to_vec());
                        }
                    }
                    for k in &to_delete {
                        etable
                            .remove(k.as_slice())
                            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
                    }
                }
            }
        }
        wtx.commit()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))
    }

    fn max_epoch_id_inner(&self, group_id: &[u8]) -> Result<Option<u64>, RedbStorageError> {
        let b = &self.0;
        let gkey = b.blind_index(group_id);
        let lo = epoch_key(&gkey, 0);
        let hi = epoch_key(&gkey, u64::MAX);
        let rtx = b
            .db
            .begin_read()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        let table = rtx
            .open_table(TBL_EPOCH)
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        let mut range = table
            .range::<&[u8]>(lo.as_slice()..=hi.as_slice())
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        // Keys are ordered; the last entry carries the max epoch id.
        let last = range.next_back();
        match last {
            None => Ok(None),
            Some(entry) => {
                let (k, _v) = entry.map_err(|e| RedbStorageError::Backend(e.to_string()))?;
                let kb = k.value();
                if kb.len() != BLIND_INDEX_LEN + 8 {
                    return Err(RedbStorageError::Malformed("epoch key length".into()));
                }
                let mut id = [0u8; 8];
                id.copy_from_slice(&kb[BLIND_INDEX_LEN..]);
                Ok(Some(u64::from_be_bytes(id)))
            }
        }
    }
}

impl GroupStateStorage for RedbGroupStateStorage {
    type Error = RedbStorageError;

    fn state(&self, group_id: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        let b = &self.0;
        let gkey = b.blind_index(group_id);
        match b.get_raw(TBL_GROUP, &gkey)? {
            None => Ok(None),
            Some(rec) => Ok(Some(b.open_record(TID_GROUP, &gkey, &rec)?)),
        }
    }

    fn epoch(
        &self,
        group_id: &[u8],
        epoch_id: u64,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        let b = &self.0;
        let gkey = b.blind_index(group_id);
        let ekey = epoch_key(&gkey, epoch_id);
        match b.get_raw(TBL_EPOCH, &ekey)? {
            None => Ok(None),
            Some(rec) => Ok(Some(b.open_record(TID_EPOCH, &ekey, &rec)?)),
        }
    }

    fn write(
        &mut self,
        state: GroupState,
        epoch_inserts: Vec<EpochRecord>,
        epoch_updates: Vec<EpochRecord>,
    ) -> Result<(), Self::Error> {
        self.write_inner(state, epoch_inserts, epoch_updates)
    }

    fn max_epoch_id(&self, group_id: &[u8]) -> Result<Option<u64>, Self::Error> {
        self.max_epoch_id_inner(group_id)
    }
}

// ===================== KeyPackageStorage =============================

/// redb-backed [`KeyPackageStorage`].
#[derive(Clone, Debug)]
pub struct RedbKeyPackageStorage(RedbBackend);

impl KeyPackageStorage for RedbKeyPackageStorage {
    type Error = RedbStorageError;

    fn delete(&mut self, id: &[u8]) -> Result<(), Self::Error> {
        let kkey = self.0.blind_index(id);
        self.0.delete(TBL_KEY_PACKAGE, &kkey)
    }

    fn insert(&mut self, id: Vec<u8>, pkg: KeyPackageData) -> Result<(), Self::Error> {
        let b = &self.0;
        let kkey = b.blind_index(&id);
        let encoded = pkg
            .mls_encode_to_vec()
            .map_err(|e| RedbStorageError::Codec(e.to_string()))?;
        let sealed = b.seal(TID_KEY_PACKAGE, &kkey, &encoded)?;
        b.put(TBL_KEY_PACKAGE, &kkey, &sealed)
    }

    fn get(&self, id: &[u8]) -> Result<Option<KeyPackageData>, Self::Error> {
        let b = &self.0;
        let kkey = b.blind_index(id);
        match b.get_raw(TBL_KEY_PACKAGE, &kkey)? {
            None => Ok(None),
            Some(rec) => {
                let pt = b.open_record(TID_KEY_PACKAGE, &kkey, &rec)?;
                let pkg = KeyPackageData::mls_decode(&mut pt.as_slice())
                    .map_err(|e| RedbStorageError::Codec(e.to_string()))?;
                Ok(Some(pkg))
            }
        }
    }
}

// ===================== PreSharedKeyStorage ==========================

/// redb-backed [`PreSharedKeyStorage`].
#[derive(Clone, Debug)]
pub struct RedbPreSharedKeyStorage(RedbBackend);

impl PreSharedKeyStorage for RedbPreSharedKeyStorage {
    type Error = RedbStorageError;

    fn get(&self, id: &ExternalPskId) -> Result<Option<PreSharedKey>, Self::Error> {
        let b = &self.0;
        let pkey = b.blind_index(id);
        match b.get_raw(TBL_PSK, &pkey)? {
            None => Ok(None),
            Some(rec) => {
                let pt = b.open_record(TID_PSK, &pkey, &rec)?;
                Ok(Some(PreSharedKey::new(pt.to_vec())))
            }
        }
    }
}

impl RedbPreSharedKeyStorage {
    /// Insert a PSK. Not part of the `PreSharedKeyStorage` trait (which is
    /// read-only); the application inserts external PSKs directly.
    pub fn insert(&self, id: &[u8], psk: &PreSharedKey) -> Result<(), RedbStorageError> {
        use std::ops::Deref;
        let b = &self.0;
        let pkey = b.blind_index(id);
        let sealed = b.seal(TID_PSK, &pkey, psk.deref())?;
        b.put(TBL_PSK, &pkey, &sealed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn backend() -> (tempfile::TempDir, RedbBackend) {
        let dir = tempdir().expect("tempdir");
        let dek = [0x37u8; 32];
        let b = RedbBackend::open(dir.path().join("groups.redb"), &dek).expect("open");
        (dir, b)
    }

    #[test]
    fn group_state_roundtrip() {
        let (_dir, b) = backend();
        let mut gs = b.group_state_storage();
        let state = GroupState {
            id: vec![1, 2, 3, 4],
            data: Zeroizing::new(vec![9u8; 512]),
        };
        gs.write(state.clone(), vec![], vec![]).expect("write");
        let got = gs.state(&state.id).expect("state").expect("present");
        assert_eq!(&*got, &*state.data);
        // Unknown group → None.
        assert!(gs.state(&[7, 7]).expect("state none").is_none());
    }

    #[test]
    fn epoch_roundtrip_and_max() {
        let (_dir, b) = backend();
        let mut gs = b.group_state_storage();
        let gid = vec![0xaa; 32];
        let state = GroupState { id: gid.clone(), data: Zeroizing::new(vec![1u8; 16]) };
        let inserts = (0u64..3)
            .map(|i| EpochRecord::new(i, Zeroizing::new(vec![i as u8; 32])))
            .collect();
        gs.write(state, inserts, vec![]).expect("write");

        assert_eq!(gs.max_epoch_id(&gid).expect("max"), Some(2));
        let e1 = gs.epoch(&gid, 1).expect("epoch").expect("present");
        assert_eq!(&*e1, &vec![1u8; 32]);
    }

    #[test]
    fn epoch_retention_drops_old() {
        let (_dir, b) = backend();
        let b = b.with_max_epoch_retention(2);
        let mut gs = b.group_state_storage();
        let gid = vec![0xbb; 32];
        let state = GroupState { id: gid.clone(), data: Zeroizing::new(vec![1u8; 16]) };
        // Insert epochs 0..=5; with retention 2 and max 5, anything <= 3 is dropped.
        let inserts = (0u64..=5)
            .map(|i| EpochRecord::new(i, Zeroizing::new(vec![i as u8; 8])))
            .collect();
        gs.write(state, inserts, vec![]).expect("write");

        for dropped in 0..=3 {
            assert!(
                gs.epoch(&gid, dropped).expect("epoch").is_none(),
                "epoch {dropped} should have been retained-out"
            );
        }
        for kept in 4..=5 {
            assert!(gs.epoch(&gid, kept).expect("epoch").is_some(), "epoch {kept} kept");
        }
        assert_eq!(gs.max_epoch_id(&gid).expect("max"), Some(5));
    }

    #[test]
    fn key_package_roundtrip_and_delete() {
        let (_dir, b) = backend();
        let mut kp = b.key_package_storage();
        let id = vec![0x11, 0x22];
        let data = KeyPackageData::new(
            vec![1, 2, 3],
            vec![4, 5, 6].into(),
            vec![7, 8, 9].into(),
            1234,
        );
        kp.insert(id.clone(), data.clone()).expect("insert");
        let got = kp.get(&id).expect("get").expect("present");
        assert_eq!(got, data);
        kp.delete(&id).expect("delete");
        assert!(kp.get(&id).expect("get none").is_none());
    }

    #[test]
    fn psk_roundtrip() {
        let (_dir, b) = backend();
        let psk = b.pre_shared_key_storage();
        let id = vec![0xcd; 32];
        let secret = PreSharedKey::new(vec![0xee; 64]);
        psk.insert(&id, &secret).expect("insert");
        let got = psk.get(&ExternalPskId::new(id.clone())).expect("get").expect("present");
        assert_eq!(got, secret);
        assert!(psk
            .get(&ExternalPskId::new(vec![0x00; 32]))
            .expect("get none")
            .is_none());
    }

    #[test]
    fn aad_binding_rejects_swapped_record() {
        // A record sealed for one slot must not decrypt in another slot, even
        // with the same key material — the AAD binds it to (table, key).
        let (_dir, b) = backend();
        let rec = b.seal(TID_GROUP, b"slotA", b"secret").expect("seal");
        // Right slot decrypts.
        assert!(b.open_record(TID_GROUP, b"slotA", &rec).is_ok());
        // Wrong logical key (swap) fails.
        assert!(matches!(
            b.open_record(TID_GROUP, b"slotB", &rec),
            Err(RedbStorageError::Decrypt)
        ));
        // Wrong table id fails.
        assert!(matches!(
            b.open_record(TID_EPOCH, b"slotA", &rec),
            Err(RedbStorageError::Decrypt)
        ));
    }

    #[test]
    fn plugs_into_mls_client_builder() {
        // Compile-time wiring check: the three redb storage types must satisfy
        // the trait bounds `mls_rs::Client::builder()` requires for its
        // group-state / key-package / psk slots. We stack them but stop short
        // of `.build()` (which would also need crypto + identity providers) —
        // the point is that the setters accept our types at all.
        let (_dir, b) = backend();
        let _builder = mls_rs::Client::builder()
            .group_state_storage(b.group_state_storage())
            .key_package_repo(b.key_package_storage())
            .psk_store(b.pre_shared_key_storage());
    }

    #[test]
    fn wrong_dek_cannot_read() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("groups.redb");
        {
            let b = RedbBackend::open(&path, &[0x01; 32]).expect("open");
            let mut gs = b.group_state_storage();
            gs.write(
                GroupState { id: vec![1], data: Zeroizing::new(vec![42u8; 32]) },
                vec![],
                vec![],
            )
            .expect("write");
        }
        // Reopen with a different DEK: blind index differs (so lookup misses)
        // AND any matching record would fail AEAD — either way, no plaintext.
        let b2 = RedbBackend::open(&path, &[0x02; 32]).expect("reopen");
        let gs2 = b2.group_state_storage();
        assert!(gs2.state(&[1]).expect("state").is_none());
    }
}
