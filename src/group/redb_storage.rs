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
//! - **Keys**: the **group DB** uses the *cleartext* logical id as the redb key
//!   (group_id, key-package id, psk_id — all random, low-sensitivity values, so
//!   blind-indexing buys ~no at-rest hygiene; keeping them cleartext lets DEK
//!   rotation re-seal values without re-keying). The **inbox** instead uses a
//!   **blind index** `HMAC-SHA256(k_bi, recipient)` because the recipient is a
//!   real identity (NodeId) whose presence/correlation must be hidden at rest.
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
use redb::{
    Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition,
    WriteTransaction,
};
use std::ops::Bound;
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
const TID_APP: u8 = 8;
const TID_SENTINEL: u8 = 9;
const TID_PK_ONETIME: u8 = 10;
const TID_PK_STATIC: u8 = 11;
const TID_GROUP_COMMITS: u8 = 12;
const TID_MEMBER_ADDR: u8 = 13;

const TBL_GROUP: TableDefinition<&[u8], &[u8]> = TableDefinition::new("mls_group_state");
const TBL_EPOCH: TableDefinition<&[u8], &[u8]> = TableDefinition::new("mls_epoch");
const TBL_KEY_PACKAGE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("mls_key_package");
const TBL_PSK: TableDefinition<&[u8], &[u8]> = TableDefinition::new("mls_psk");
/// Application-data KV (signing identity etc.), keyed by `blind_index(key)`.
const TBL_APP: TableDefinition<&[u8], &[u8]> = TableDefinition::new("mls_app");
/// Applied-commit history for delta resync (MLS_P2P_SYNC_DESIGN.md §4), keyed
/// by `group_epoch_key` = `gid_len ‖ gid ‖ epoch`. Only the canonical commit
/// that advanced local state to `epoch` is stored.
const TBL_GROUP_COMMITS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("mls_group_commits");
/// Number of newest commit-epochs retained for delta resync before pruning.
pub const DEFAULT_COMMIT_RETENTION: u64 = 100;
/// Per-group member *delivery hints* (an address book), keyed by
/// `group_member_key` = `gid_len ‖ gid ‖ node_id(32)`. The value is the peer's
/// ticket string. These are only hints used to default the recipient set when
/// the user does not pass `--mls-recipient-ticket`; MLS still authenticates and
/// encrypts every message, so a stale or wrong hint can at worst fail to deliver
/// (it cannot leak plaintext to the wrong node).
const TBL_MEMBER_ADDR: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("mls_member_addr");

// Inbox (store-and-forward) tables and their AAD table ids.
const TID_ENVELOPE: u8 = 5;
const TID_PREKEY: u8 = 6;
const TID_CHECKPOINT: u8 = 7;
const TBL_ENV: TableDefinition<&[u8], &[u8]> = TableDefinition::new("inbox_env");
const TBL_PREKEY: TableDefinition<&[u8], &[u8]> = TableDefinition::new("inbox_prekey");
const TBL_CHECKPOINT: TableDefinition<&[u8], &[u8]> = TableDefinition::new("inbox_checkpoint");
/// Plaintext meta table: monotonic row-id counter (`b"next_id"` → u64 BE).
/// The counter value is not secret, so it is stored unencrypted.
const TBL_META: TableDefinition<&[u8], &[u8]> = TableDefinition::new("inbox_meta");

// Prekey store (local one-time/static prekey secret keys; see `crate::prekey`).
const TBL_PK_ONETIME: TableDefinition<&[u8], &[u8]> = TableDefinition::new("pk_onetime");
const TBL_PK_STATIC: TableDefinition<&[u8], &[u8]> = TableDefinition::new("pk_static");
/// Plaintext meta for the prekey store: monotonic id high-water mark
/// (`b"seq_next"` → u64 BE) and the inbox poll cursor (`b"inbox_cursor"`).
const TBL_PK_META: TableDefinition<&[u8], &[u8]> = TableDefinition::new("pk_meta");
const PK_SEQ_KEY: &[u8] = b"seq_next";
const PK_CURSOR_KEY: &[u8] = b"inbox_cursor";
const PK_STATIC_KEY: &[u8] = b"static";

/// Sentinel table: a single encrypted record used to verify the DEK is correct
/// on open (and to probe candidate DEKs during rekey recovery). Present in all
/// (group / inbox / prekey) databases.
const TBL_SENTINEL: TableDefinition<&[u8], &[u8]> = TableDefinition::new("dek_sentinel");
const SENTINEL_KEY: &[u8] = b"dek-check";
const SENTINEL_PLAINTEXT: &[u8] = b"nkct-redb-sentinel-v1";

/// Group-DB encrypted tables and their AAD ids — the set DEK rotation re-seals.
const GROUP_ENCRYPTED_TABLES: [(TableDefinition<&[u8], &[u8]>, u8); 8] = [
    (TBL_GROUP, TID_GROUP),
    (TBL_EPOCH, TID_EPOCH),
    (TBL_KEY_PACKAGE, TID_KEY_PACKAGE),
    (TBL_PSK, TID_PSK),
    (TBL_APP, TID_APP),
    (TBL_GROUP_COMMITS, TID_GROUP_COMMITS),
    (TBL_MEMBER_ADDR, TID_MEMBER_ADDR),
    (TBL_SENTINEL, TID_SENTINEL),
];

const BLIND_INDEX_LEN: usize = 32;
/// Envelope value header: `sender(32) ‖ created_at_be(8)` precedes the payload.
const ENV_HEADER_LEN: usize = 32 + 8;
/// Prekey value header: `created_at_be(8)` precedes the opaque blob.
const PREKEY_HEADER_LEN: usize = 8;

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
    /// Open (or create) the encrypted redb database at `path` for **MLS group
    /// storage** (group state / key packages / psks), deriving the
    /// value/blind-index subkeys from the 32-byte at-rest `dek`.
    ///
    /// Tables are created eagerly so later read transactions never hit
    /// `TableDoesNotExist` on a fresh database.
    pub fn open(path: impl AsRef<Path>, dek: &[u8; 32]) -> Result<Self, RedbStorageError> {
        let path = path.as_ref();
        let me = Self::new_core(path, dek)?;
        me.create_tables_in(&[
            TBL_GROUP,
            TBL_EPOCH,
            TBL_KEY_PACKAGE,
            TBL_PSK,
            TBL_APP,
            TBL_GROUP_COMMITS,
            TBL_MEMBER_ADDR,
            TBL_SENTINEL,
        ])?;
        me.ensure_sentinel()?;
        me.tighten_permissions(path)?;
        Ok(me)
    }

    /// Open (or create) the encrypted redb database at `path` for the
    /// **store-and-forward inbox** (envelopes / prekeys / checkpoints / meta).
    /// Same crypto core as [`Self::open`]; only the table set differs.
    pub fn open_inbox(path: impl AsRef<Path>, dek: &[u8; 32]) -> Result<Self, RedbStorageError> {
        let path = path.as_ref();
        let me = Self::new_core(path, dek)?;
        me.create_tables_in(&[TBL_ENV, TBL_PREKEY, TBL_CHECKPOINT, TBL_META, TBL_SENTINEL])?;
        me.ensure_sentinel()?;
        me.tighten_permissions(path)?;
        Ok(me)
    }

    fn new_core(path: &Path, dek: &[u8; 32]) -> Result<Self, RedbStorageError> {
        let db_binding = path
            .file_name()
            .map(|n| n.as_encoded_bytes().to_vec())
            .unwrap_or_default();
        let db = open_db_secure(path)?;
        Ok(Self {
            db: Arc::new(db),
            keys: Arc::new(RecordKeys::derive(dek)),
            db_binding: Arc::new(db_binding),
            max_epoch_retention: DEFAULT_EPOCH_RETENTION_LIMIT,
        })
    }

    fn create_tables_in(
        &self,
        defs: &[TableDefinition<&'static [u8], &'static [u8]>],
    ) -> Result<(), RedbStorageError> {
        let wtx = self
            .db
            .begin_write()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        {
            for def in defs {
                wtx.open_table(*def)
                    .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            }
        }
        wtx.commit()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))
    }

    /// Tighten the DB file to owner-only (unix `0o600` / windows owner-only
    /// DACL) — defence in depth, matching the sqlite path.
    fn tighten_permissions(&self, path: &Path) -> Result<(), RedbStorageError> {
        if path.exists() {
            crate::secure_fs::harden_owner_only(path)
                .map_err(|e| RedbStorageError::Backend(format!("tighten perms: {e}")))?;
        }
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

    pub fn application_data_storage(&self) -> RedbApplicationStorage {
        RedbApplicationStorage(self.clone())
    }

    // --- crypto helpers ---------------------------------------------------

    /// Blind index for a logical identifier: `HMAC-SHA256(k_bi, id)`.
    fn blind_index(&self, id: &[u8]) -> [u8; BLIND_INDEX_LEN] {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(self.keys.k_bi.as_slice())
            .expect("HMAC accepts any key length");
        mac.update(id);
        mac.finalize().into_bytes().into()
    }

    /// Encrypt `plaintext` into a self-describing record bound to its slot.
    fn seal(
        &self,
        table_id: u8,
        redb_key: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, RedbStorageError> {
        seal_value(&self.keys.k_value, &self.db_binding, table_id, redb_key, plaintext)
    }

    /// Decrypt a record produced by [`Self::seal`], verifying the slot binding.
    fn open_record(
        &self,
        table_id: u8,
        redb_key: &[u8],
        record: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, RedbStorageError> {
        open_value(&self.keys.k_value, &self.db_binding, table_id, redb_key, record)
    }

    /// On open: write the sentinel if absent, or verify it decrypts under the
    /// current `k_value` if present. A wrong DEK surfaces here as a `Decrypt`
    /// error, so the database fails fast on open instead of returning garbage.
    fn ensure_sentinel(&self) -> Result<(), RedbStorageError> {
        match self.get_raw(TBL_SENTINEL, SENTINEL_KEY)? {
            Some(rec) => {
                self.open_record(TID_SENTINEL, SENTINEL_KEY, &rec)
                    .map_err(|_| RedbStorageError::Decrypt)?;
                Ok(())
            }
            None => {
                let sealed = self.seal(TID_SENTINEL, SENTINEL_KEY, SENTINEL_PLAINTEXT)?;
                self.put(TBL_SENTINEL, SENTINEL_KEY, &sealed)
            }
        }
    }

    /// Probe whether `dek` is the DEK an existing database at `path` was sealed
    /// under, by decrypting its sentinel. Returns `Ok(false)` if the DEK is
    /// wrong, the DB has no sentinel, or the DB does not exist — never an error
    /// for a "wrong key" outcome. Used by the at-rest rekey recovery to decide
    /// which DEK a crash left the DB under.
    pub fn dek_opens(path: impl AsRef<Path>, dek: &[u8; 32]) -> Result<bool, RedbStorageError> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(false);
        }
        let db_binding = path
            .file_name()
            .map(|n| n.as_encoded_bytes().to_vec())
            .unwrap_or_default();
        let db = open_db_secure(path)?;
        let keys = RecordKeys::derive(dek);
        let rtx = db
            .begin_read()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        let table = match rtx.open_table(TBL_SENTINEL) {
            Ok(t) => t,
            Err(_) => return Ok(false), // no sentinel table → can't verify
        };
        let got = table
            .get(SENTINEL_KEY)
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        match got {
            None => Ok(false),
            Some(g) => Ok(
                open_value(&keys.k_value, &db_binding, TID_SENTINEL, SENTINEL_KEY, g.value())
                    .is_ok(),
            ),
        }
    }

    /// Rotate the group database at `path` from `old_dek` to `new_dek`: re-seal
    /// every encrypted record under the new `k_value`. Keys are cleartext logical
    /// ids, so they are unchanged — only the ciphertext is rewritten. The whole
    /// rotation runs in a single redb write transaction, so a crash leaves the
    /// DB entirely on the old DEK (uncommitted) or entirely on the new one
    /// (committed) — never half-rotated. Verifies `old_dek` is correct (the
    /// records won't decrypt otherwise) before writing anything.
    pub fn rotate_group_dek(
        path: impl AsRef<Path>,
        old_dek: &[u8; 32],
        new_dek: &[u8; 32],
    ) -> Result<(), RedbStorageError> {
        let path = path.as_ref();
        let db_binding = path
            .file_name()
            .map(|n| n.as_encoded_bytes().to_vec())
            .unwrap_or_default();
        let db = open_db_secure(path)?;
        let old = RecordKeys::derive(old_dek);
        let new = RecordKeys::derive(new_dek);

        let wtx = db
            .begin_write()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        for (def, tid) in GROUP_ENCRYPTED_TABLES {
            let mut table = wtx
                .open_table(def)
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            // Decrypt every record under the old key first (this also proves
            // old_dek is correct), collecting (key, plaintext).
            let mut items: Vec<(Vec<u8>, Zeroizing<Vec<u8>>)> = Vec::new();
            {
                let range = table
                    .range::<&[u8]>(..)
                    .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
                for entry in range {
                    let (k, v) = entry.map_err(|e| RedbStorageError::Backend(e.to_string()))?;
                    let key = k.value().to_vec();
                    let pt = open_value(&old.k_value, &db_binding, tid, &key, v.value())?;
                    items.push((key, pt));
                }
            }
            // Re-seal each under the new key (same slot → same AAD).
            for (key, pt) in items {
                let sealed = seal_value(&new.k_value, &db_binding, tid, &key, &pt)?;
                table
                    .insert(key.as_slice(), sealed.as_slice())
                    .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            }
        }
        wtx.commit()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))
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

    // ---- MLS commit history (delta resync, MLS_P2P_SYNC_DESIGN.md §4) --------

    /// Persist the canonical commit that advanced `group_id` to `epoch`, so a
    /// straggler can later be replayed the commits it missed. The value is
    /// AEAD-sealed like every other record; the key is `group_epoch_key`. Only
    /// the commit actually applied to local state should be stored (one per
    /// epoch). Auto-prunes to [`DEFAULT_COMMIT_RETENTION`].
    pub fn store_commit(
        &self,
        group_id: &[u8],
        epoch: u64,
        commit_bytes: &[u8],
    ) -> Result<(), RedbStorageError> {
        // The key length-prefixes the group id as u16; a >64KiB id would
        // truncate and could collide across groups, so reject it outright.
        if group_id.len() > u16::MAX as usize {
            return Err(RedbStorageError::Malformed(
                "group id exceeds 65535 bytes".into(),
            ));
        }
        let key = group_epoch_key(group_id, epoch);
        // Each epoch has exactly one canonical commit. Re-storing identical
        // bytes is a no-op; refusing *different* bytes stops a stored canonical
        // commit from being silently replaced (fork / tamper guard).
        if let Some(existing) = self.get_raw(TBL_GROUP_COMMITS, &key)? {
            let existing_pt = self.open_record(TID_GROUP_COMMITS, &key, &existing)?;
            if existing_pt.as_slice() == commit_bytes {
                return Ok(());
            }
            return Err(RedbStorageError::Backend(format!(
                "refusing to overwrite the canonical commit at epoch {epoch} with different bytes"
            )));
        }
        let sealed = self.seal(TID_GROUP_COMMITS, &key, commit_bytes)?;
        let wtx = self
            .db
            .begin_write()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        {
            let mut t = wtx
                .open_table(TBL_GROUP_COMMITS)
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            t.insert(key.as_slice(), sealed.as_slice())
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        }
        wtx.commit()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        // Prune is opportunistic cleanup; the commit is already durably stored,
        // so a prune failure must not fail the store (it self-heals next call).
        if let Err(e) = self.prune_commits(group_id, DEFAULT_COMMIT_RETENTION) {
            eprintln!("[redb] commit-history prune failed (non-fatal): {e}");
        }
        Ok(())
    }

    /// Load applied commits for `group_id` with
    /// `from_epoch_exclusive < epoch <= to_epoch_inclusive`, ascending by epoch
    /// — the commits a straggler at `from_epoch_exclusive` must replay to reach
    /// `to_epoch_inclusive` (Case B delta resync).
    pub fn load_commits(
        &self,
        group_id: &[u8],
        from_epoch_exclusive: u64,
        to_epoch_inclusive: u64,
    ) -> Result<Vec<(u64, Zeroizing<Vec<u8>>)>, RedbStorageError> {
        if group_id.len() > u16::MAX as usize {
            return Err(RedbStorageError::Malformed(
                "group id exceeds 65535 bytes".into(),
            ));
        }
        // An empty or inverted range has no commits — return early so the
        // attacker-influenced `(from, to)` cannot reach redb's range() with
        // start > end (which would panic).
        if from_epoch_exclusive >= to_epoch_inclusive {
            return Ok(Vec::new());
        }
        let lo = group_epoch_key(group_id, from_epoch_exclusive);
        let hi = group_epoch_key(group_id, to_epoch_inclusive);
        let rtx = self
            .db
            .begin_read()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        let table = rtx
            .open_table(TBL_GROUP_COMMITS)
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        // The length-prefixed group id makes [lo, hi] a contiguous block of the
        // same group, so the range is group-scoped.
        let range = table
            .range::<&[u8]>((Bound::Excluded(lo.as_slice()), Bound::Included(hi.as_slice())))
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        let mut out = Vec::new();
        for entry in range {
            let (k, v) = entry.map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            let kbytes = k.value();
            let epoch = epoch_from_group_key(kbytes)?;
            let pt = self.open_record(TID_GROUP_COMMITS, kbytes, v.value())?;
            out.push((epoch, pt));
        }
        Ok(out)
    }

    pub fn oldest_retained_epoch(&self, group_id: &[u8]) -> Result<Option<u64>, RedbStorageError> {
        if group_id.len() > u16::MAX as usize {
            return Err(RedbStorageError::Malformed(
                "group id exceeds 65535 bytes".into(),
            ));
        }
        let lo = group_epoch_key(group_id, 0);
        let hi = group_epoch_key(group_id, u64::MAX);
        let rtx = self
            .db
            .begin_read()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        let table = rtx
            .open_table(TBL_GROUP_COMMITS)
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        let mut range = table
            .range::<&[u8]>(lo.as_slice()..=hi.as_slice())
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        match range.next().transpose().map_err(|e| RedbStorageError::Backend(e.to_string()))? {
            Some((k, _)) => Ok(Some(epoch_from_group_key(k.value())?)),
            None => Ok(None),
        }
    }

    /// Prune commit history for `group_id`, keeping only the newest `keep`
    /// epochs. Returns the number of commits deleted (so callers can log what
    /// was dropped rather than silently bounding coverage).
    pub fn prune_commits(&self, group_id: &[u8], keep: u64) -> Result<u64, RedbStorageError> {
        if group_id.len() > u16::MAX as usize {
            return Err(RedbStorageError::Malformed(
                "group id exceeds 65535 bytes".into(),
            ));
        }
        let lo = group_epoch_key(group_id, 0);
        let hi = group_epoch_key(group_id, u64::MAX);
        let wtx = self
            .db
            .begin_write()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        let mut deleted = 0u64;
        {
            let mut t = wtx
                .open_table(TBL_GROUP_COMMITS)
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            let max_epoch: Option<u64> = {
                let mut range = t
                    .range::<&[u8]>(lo.as_slice()..=hi.as_slice())
                    .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
                match range
                    .next_back()
                    .transpose()
                    .map_err(|e| RedbStorageError::Backend(e.to_string()))?
                {
                    Some((k, _)) => Some(epoch_from_group_key(k.value())?),
                    None => None,
                }
            };
            if let Some(max_epoch) = max_epoch {
                if max_epoch >= keep {
                    let cutoff = max_epoch - keep; // delete epochs <= cutoff
                    let del_hi = group_epoch_key(group_id, cutoff);
                    let mut to_delete: Vec<Vec<u8>> = Vec::new();
                    {
                        let range = t
                            .range::<&[u8]>(lo.as_slice()..=del_hi.as_slice())
                            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
                        for entry in range {
                            let (k, _) =
                                entry.map_err(|e| RedbStorageError::Backend(e.to_string()))?;
                            to_delete.push(k.value().to_vec());
                        }
                    }
                    for k in &to_delete {
                        t.remove(k.as_slice())
                            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
                        deleted += 1;
                    }
                }
            }
        }
        wtx.commit()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        Ok(deleted)
    }

    /// Upsert a member's delivery hint (its ticket string) for `group_id`.
    /// Overwriting is intended: a peer's reachable address changes over time, so
    /// the newest hint wins.
    pub fn put_member_addr(
        &self,
        group_id: &[u8],
        node_id: &[u8; 32],
        ticket: &str,
    ) -> Result<(), RedbStorageError> {
        if group_id.len() > u16::MAX as usize {
            return Err(RedbStorageError::Malformed(
                "group id exceeds 65535 bytes".into(),
            ));
        }
        let key = group_member_key(group_id, node_id);
        let sealed = self.seal(TID_MEMBER_ADDR, &key, ticket.as_bytes())?;
        let wtx = self
            .db
            .begin_write()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        {
            let mut t = wtx
                .open_table(TBL_MEMBER_ADDR)
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            t.insert(key.as_slice(), sealed.as_slice())
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        }
        wtx.commit()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        Ok(())
    }

    /// Forget a member's delivery hint (e.g. after the member is removed from
    /// the group), so later auto-resolved sends do not keep targeting them.
    /// A missing entry is not an error (idempotent).
    pub fn forget_member_addr(
        &self,
        group_id: &[u8],
        node_id: &[u8; 32],
    ) -> Result<(), RedbStorageError> {
        if group_id.len() > u16::MAX as usize {
            return Err(RedbStorageError::Malformed(
                "group id exceeds 65535 bytes".into(),
            ));
        }
        let key = group_member_key(group_id, node_id);
        let wtx = self
            .db
            .begin_write()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        {
            let mut t = wtx
                .open_table(TBL_MEMBER_ADDR)
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            t.remove(key.as_slice())
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        }
        wtx.commit()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        Ok(())
    }

    /// List all stored member delivery hints (ticket strings) for `group_id`.
    /// A record whose ticket fails to decode as UTF-8 is skipped rather than
    /// failing the whole lookup (one bad entry must not break delivery).
    pub fn list_member_addrs(
        &self,
        group_id: &[u8],
    ) -> Result<Vec<([u8; 32], String)>, RedbStorageError> {
        if group_id.len() > u16::MAX as usize {
            return Err(RedbStorageError::Malformed(
                "group id exceeds 65535 bytes".into(),
            ));
        }
        let lo = group_member_key(group_id, &[0u8; 32]);
        let hi = group_member_key(group_id, &[0xffu8; 32]);
        let rtx = self
            .db
            .begin_read()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        let table = rtx
            .open_table(TBL_MEMBER_ADDR)
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        // The length-prefixed group id makes [lo, hi] a contiguous, group-scoped
        // block (the 32-byte node id is the only thing that varies within it).
        let range = table
            .range::<&[u8]>(lo.as_slice()..=hi.as_slice())
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        let mut out = Vec::new();
        for entry in range {
            let (k, v) = entry.map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            let kbytes = k.value();
            let node_id = node_id_from_member_key(kbytes)?;
            let pt = self.open_record(TID_MEMBER_ADDR, kbytes, v.value())?;
            match std::str::from_utf8(&pt) {
                Ok(s) => out.push((node_id, s.to_string())),
                Err(_) => eprintln!("[redb] skipping member-addr hint with non-UTF8 ticket"),
            }
        }
        Ok(out)
    }
}

/// AAD binding a record to its slot: `db_binding ‖ table_id ‖ redb_key`.
fn aad_bytes(db_binding: &[u8], table_id: u8, redb_key: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(db_binding.len() + 1 + redb_key.len());
    aad.extend_from_slice(db_binding);
    aad.push(table_id);
    aad.extend_from_slice(redb_key);
    aad
}

/// Encrypt `plaintext` into a self-describing record bound to its slot, under
/// the given value key. Record = `VERSION(1) ‖ nonce(24) ‖ ciphertext‖tag`.
fn seal_value(
    k_value: &[u8; 32],
    db_binding: &[u8],
    table_id: u8,
    redb_key: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, RedbStorageError> {
    let cipher = XChaCha20Poly1305::new_from_slice(k_value).map_err(|_| RedbStorageError::Encrypt)?;
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let aad = aad_bytes(db_binding, table_id, redb_key);
    let ct = cipher
        .encrypt(&nonce, Payload { msg: plaintext, aad: &aad })
        .map_err(|_| RedbStorageError::Encrypt)?;
    let mut out = Vec::with_capacity(1 + NONCE_LEN + ct.len());
    out.push(RECORD_VERSION);
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open (or create) a redb database, ensuring the file is owner-only from the
/// moment it exists. `Database::create` alone would create the file under the
/// default umask / inherited ACL and leave a brief window before
/// `tighten_permissions` re-locks it; pre-creating exclusively with owner-only
/// permissions (unix 0600 / windows owner-only DACL) closes that window. An
/// already-present DB is opened as-is (then still tightened by the caller).
fn open_db_secure(path: &Path) -> Result<Database, RedbStorageError> {
    match crate::secure_fs::create_owner_only(path, false) {
        // Pre-created an empty owner-only file; redb initializes it as a new DB.
        Ok(_) => {}
        // Existing DB — open it (race-safe: exclusive create is atomic).
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(RedbStorageError::Backend(format!("precreate db: {e}"))),
    }
    Database::create(path).map_err(|e| RedbStorageError::Backend(e.to_string()))
}

/// Decrypt a record produced by [`seal_value`], verifying the slot binding.
fn open_value(
    k_value: &[u8; 32],
    db_binding: &[u8],
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
    let cipher = XChaCha20Poly1305::new_from_slice(k_value).map_err(|_| RedbStorageError::Decrypt)?;
    let aad = aad_bytes(db_binding, table_id, redb_key);
    let pt = cipher
        .decrypt(nonce, Payload { msg: ct, aad: &aad })
        .map_err(|_| RedbStorageError::Decrypt)?;
    Ok(Zeroizing::new(pt))
}

/// Build the fixed-length composite key for the **inbox** (blind-indexed):
/// `blind_index(recipient) ‖ id_be`. The 32-byte blind-index prefix is fixed
/// length, so per-recipient range scans are collision-free.
fn composite_key(gkey: &[u8; BLIND_INDEX_LEN], id: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(BLIND_INDEX_LEN + 8);
    k.extend_from_slice(gkey);
    k.extend_from_slice(&id.to_be_bytes());
    k
}

/// Build the composite epoch key for the **group DB**, where the redb key is
/// the *cleartext* group id (group ids are random, low-sensitivity values, so
/// blind-indexing them buys ~no at-rest hygiene; keeping them cleartext lets
/// DEK rotation re-seal values without re-keying — see DB_PURERUST_DESIGN.md).
/// The group id is length-prefixed so variable-length ids cannot collide in a
/// range scan: `gid_len(u16 BE) ‖ gid ‖ epoch_be(8)`.
fn group_epoch_key(group_id: &[u8], epoch_id: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(2 + group_id.len() + 8);
    k.extend_from_slice(&(group_id.len() as u16).to_be_bytes());
    k.extend_from_slice(group_id);
    k.extend_from_slice(&epoch_id.to_be_bytes());
    k
}

/// Recover the epoch id (trailing 8 bytes) from a [`group_epoch_key`].
fn epoch_from_group_key(key: &[u8]) -> Result<u64, RedbStorageError> {
    if key.len() < 8 {
        return Err(RedbStorageError::Malformed("group epoch key too short".into()));
    }
    let mut id = [0u8; 8];
    id.copy_from_slice(&key[key.len() - 8..]);
    Ok(u64::from_be_bytes(id))
}

/// Member-addr key: `gid_len(be16) ‖ gid ‖ node_id(32)`. The length-prefixed
/// group id keeps one group's hints in a contiguous, non-colliding key range.
fn group_member_key(group_id: &[u8], node_id: &[u8; 32]) -> Vec<u8> {
    let mut k = Vec::with_capacity(2 + group_id.len() + 32);
    k.extend_from_slice(&(group_id.len() as u16).to_be_bytes());
    k.extend_from_slice(group_id);
    k.extend_from_slice(node_id);
    k
}

/// Recover the 32-byte node id (trailing bytes) from a [`group_member_key`].
fn node_id_from_member_key(key: &[u8]) -> Result<[u8; 32], RedbStorageError> {
    if key.len() < 32 {
        return Err(RedbStorageError::Malformed("member-addr key too short".into()));
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&key[key.len() - 32..]);
    Ok(id)
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
        // Group DB keys are the *cleartext* group id (see `group_epoch_key`):
        // random low-sensitivity ids, kept cleartext so DEK rotation re-seals
        // values without re-keying.
        let gkey = &state.id;

        let wtx = b
            .db
            .begin_write()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        {
            // Snapshot upsert. `list_group_ids` reads the key directly.
            let mut gtable = wtx
                .open_table(TBL_GROUP)
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            let sealed = b.seal(TID_GROUP, gkey, &state.data)?;
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
                let ekey = group_epoch_key(&state.id, epoch.id);
                let sealed = b.seal(TID_EPOCH, &ekey, &epoch.data)?;
                etable
                    .insert(ekey.as_slice(), sealed.as_slice())
                    .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            }

            // Prior-epoch retention: drop epochs with id <= max - retention.
            if let Some(max_id) = max_epoch_id {
                if max_id >= b.max_epoch_retention {
                    let delete_under = max_id - b.max_epoch_retention;
                    let lo = group_epoch_key(&state.id, 0);
                    let hi = group_epoch_key(&state.id, delete_under);
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
        let lo = group_epoch_key(group_id, 0);
        let hi = group_epoch_key(group_id, u64::MAX);
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
        match range.next_back() {
            None => Ok(None),
            Some(entry) => {
                let (k, _v) = entry.map_err(|e| RedbStorageError::Backend(e.to_string()))?;
                Ok(Some(epoch_from_group_key(k.value())?))
            }
        }
    }

    /// Enumerate the group ids of all stored groups (replaces the sqlite
    /// `SELECT group_id FROM mls_group`). The redb key *is* the cleartext
    /// group id, so this is a plain key scan.
    pub fn list_group_ids(&self) -> Result<Vec<Vec<u8>>, RedbStorageError> {
        let b = &self.0;
        let rtx = b
            .db
            .begin_read()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        let table = rtx
            .open_table(TBL_GROUP)
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        let range = table
            .range::<&[u8]>(..)
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        let mut out = Vec::new();
        for entry in range {
            let (k, _v) = entry.map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            out.push(k.value().to_vec());
        }
        Ok(out)
    }
}

impl GroupStateStorage for RedbGroupStateStorage {
    type Error = RedbStorageError;

    fn state(&self, group_id: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        let b = &self.0;
        match b.get_raw(TBL_GROUP, group_id)? {
            None => Ok(None),
            Some(rec) => Ok(Some(b.open_record(TID_GROUP, group_id, &rec)?)),
        }
    }

    fn epoch(
        &self,
        group_id: &[u8],
        epoch_id: u64,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        let b = &self.0;
        let ekey = group_epoch_key(group_id, epoch_id);
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
        // Group DB keys are the cleartext logical id (kp id is random).
        self.0.delete(TBL_KEY_PACKAGE, id)
    }

    fn insert(&mut self, id: Vec<u8>, pkg: KeyPackageData) -> Result<(), Self::Error> {
        let b = &self.0;
        let encoded = pkg
            .mls_encode_to_vec()
            .map_err(|e| RedbStorageError::Codec(e.to_string()))?;
        let sealed = b.seal(TID_KEY_PACKAGE, &id, &encoded)?;
        b.put(TBL_KEY_PACKAGE, &id, &sealed)
    }

    fn get(&self, id: &[u8]) -> Result<Option<KeyPackageData>, Self::Error> {
        let b = &self.0;
        match b.get_raw(TBL_KEY_PACKAGE, id)? {
            None => Ok(None),
            Some(rec) => {
                let pt = b.open_record(TID_KEY_PACKAGE, id, &rec)?;
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
        let pkey: &[u8] = id;
        match b.get_raw(TBL_PSK, pkey)? {
            None => Ok(None),
            Some(rec) => {
                let pt = b.open_record(TID_PSK, pkey, &rec)?;
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
        let sealed = b.seal(TID_PSK, id, psk.deref())?;
        b.put(TBL_PSK, id, &sealed)
    }
}

// ===================== Application data (KV) =========================

/// redb-backed application-data key-value store. Used by the processor for the
/// persistent signing identity (`mls:identity:sk` / `:pk`). Mirrors the sqlite
/// provider's `SqLiteApplicationStorage` get/insert API. The key (a fixed
/// app-defined string like `mls:identity:sk`) is the cleartext redb key;
/// values are encrypted like every other table.
#[derive(Clone, Debug)]
pub struct RedbApplicationStorage(RedbBackend);

impl RedbApplicationStorage {
    /// Returns the value in a `Zeroizing<Vec<u8>>` so a long-term secret read
    /// here — notably the MLS signing identity SK — is wiped from the heap on
    /// drop instead of lingering in a plain `Vec` (audit L3). `open_record`
    /// already yields a `Zeroizing<Vec<u8>>`; we simply stop unwrapping it.
    pub fn get(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, RedbStorageError> {
        let b = &self.0;
        let k = key.as_bytes();
        match b.get_raw(TBL_APP, k)? {
            None => Ok(None),
            Some(rec) => Ok(Some(b.open_record(TID_APP, k, &rec)?)),
        }
    }

    pub fn insert(&self, key: &str, value: &[u8]) -> Result<(), RedbStorageError> {
        let b = &self.0;
        let k = key.as_bytes();
        let sealed = b.seal(TID_APP, k, value)?;
        b.put(TBL_APP, k, &sealed)
    }
}

// ===================== Inbox (store-and-forward) =====================

/// Outcome of a [`RedbInboxStore::checkpoint`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointOutcome {
    /// Stored (or already at/above the supplied epoch).
    Ok,
    /// The supplied epoch was below the stored one — a rollback; not stored.
    Rollback,
}

/// redb-backed store for the `nkct/inbox/1` store-and-forward relay
/// ([`crate::network::inbox`]). Mirrors the SQLCipher schema's semantics
/// (per-recipient monotonic cursor, prekey FIFO pool with a cap, rollback-safe
/// checkpoints) but on pure-Rust redb with the same app-layer AEAD as the MLS
/// storage. Every value (payload + sender + timestamps) is encrypted; only the
/// `blind_index(recipient)` and the monotonic id remain in the clear.
///
/// Keys are `blind_index(recipient)(32) ‖ id_be(8)`, so a recipient's records
/// form a contiguous, ordered range. The id is a global monotonic counter (the
/// poll cursor), matching the sqlite `AUTOINCREMENT` rowid.
#[derive(Clone, Debug)]
pub struct RedbInboxStore {
    b: RedbBackend,
    /// Per-recipient prekey pool cap (newest win). Mirrors `MAX_PREKEYS_STORED`.
    max_prekeys: usize,
    /// Per-recipient envelope count cap (newest win). With the global byte
    /// budget below this bounds the unauthenticated DEPOSIT disk-exhaustion vector.
    max_envelopes: usize,
}

const META_NEXT_ID: &[u8] = b"next_id";
/// Cached running total of sealed envelope bytes (lazily initialised).
const META_ENV_BYTES: &[u8] = b"env_bytes";
/// Global cap on total sealed envelope bytes across all recipients. DEPOSIT is
/// unauthenticated and accepts large payloads to arbitrary recipient ids, so a
/// per-recipient count cap alone cannot stop a spray across many ids — this
/// bounds the store's total on-disk size. `deposit` is the only writer of
/// `TBL_ENV` (POLL is read-only), so a counter maintained there stays accurate.
const MAX_TOTAL_ENVELOPE_BYTES: u64 = 1 << 30; // 1 GiB

impl RedbInboxStore {
    /// Open (or create) the encrypted inbox database at `path`.
    pub fn open(
        path: impl AsRef<Path>,
        dek: &[u8; 32],
        max_prekeys: usize,
        max_envelopes: usize,
    ) -> Result<Self, RedbStorageError> {
        Ok(Self {
            b: RedbBackend::open_inbox(path, dek)?,
            max_prekeys,
            max_envelopes,
        })
    }

    /// Reserve the next monotonic id within an open write transaction. Ids start
    /// at 1 (so `since_cursor = 0` drains the whole backlog, like sqlite).
    fn next_id(&self, wtx: &WriteTransaction) -> Result<u64, RedbStorageError> {
        let mut meta = wtx
            .open_table(TBL_META)
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        let cur = meta
            .get(META_NEXT_ID)
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?
            .map(|g| {
                let v = g.value();
                let mut b = [0u8; 8];
                b.copy_from_slice(&v[..8.min(v.len())]);
                u64::from_be_bytes(b)
            })
            .unwrap_or(0);
        let id = cur + 1;
        meta.insert(META_NEXT_ID, id.to_be_bytes().as_slice())
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        Ok(id)
    }

    /// DEPOSIT: store an envelope for `recipient`; returns the assigned cursor id.
    pub fn deposit(
        &self,
        recipient: &[u8; 32],
        sender: &[u8; 32],
        payload: &[u8],
        created_at: i64,
    ) -> Result<u64, RedbStorageError> {
        let bi = self.b.blind_index(recipient);
        let wtx = self
            .b
            .db
            .begin_write()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        let id = self.next_id(&wtx)?;
        let key = composite_key(&bi, id);
        let mut plain = Vec::with_capacity(ENV_HEADER_LEN + payload.len());
        plain.extend_from_slice(sender);
        plain.extend_from_slice(&created_at.to_be_bytes());
        plain.extend_from_slice(payload);
        let sealed = self.b.seal(TID_ENVELOPE, &key, &plain)?;
        {
            let mut t = wtx
                .open_table(TBL_ENV)
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;

            // Running total of sealed envelope bytes, read from TBL_META and
            // lazily initialised by one full scan the first time (older DBs
            // predate the counter). `deposit` is the only writer, so it stays
            // accurate thereafter.
            let cached: Option<u64> = {
                let meta = wtx
                    .open_table(TBL_META)
                    .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
                let x = meta
                    .get(META_ENV_BYTES)
                    .map_err(|e| RedbStorageError::Backend(e.to_string()))?
                    .map(|v| {
                        let raw = v.value();
                        let mut b = [0u8; 8];
                        // Copy only what's present (dst and src must match length,
                        // so a short/corrupt value can never panic here).
                        let n = raw.len().min(8);
                        b[..n].copy_from_slice(&raw[..n]);
                        u64::from_be_bytes(b)
                    });
                x
            };
            let mut total_bytes = match cached {
                Some(n) => n,
                None => {
                    let mut sum = 0u64;
                    for entry in t
                        .iter()
                        .map_err(|e| RedbStorageError::Backend(e.to_string()))?
                    {
                        let (_k, v) =
                            entry.map_err(|e| RedbStorageError::Backend(e.to_string()))?;
                        sum = sum.saturating_add(v.value().len() as u64);
                    }
                    sum
                }
            };

            t.insert(key.as_slice(), sealed.as_slice())
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            total_bytes = total_bytes.saturating_add(sealed.len() as u64);

            // (1) Per-recipient count cap: evict this recipient's oldest (lowest
            // id) beyond the cap so one recipient id cannot accumulate forever.
            let lo = composite_key(&bi, 0);
            let hi = composite_key(&bi, u64::MAX);
            let mut rkeys: Vec<(Vec<u8>, u64)> = Vec::new();
            {
                let range = t
                    .range::<&[u8]>(lo.as_slice()..=hi.as_slice())
                    .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
                for entry in range {
                    let (k, v) =
                        entry.map_err(|e| RedbStorageError::Backend(e.to_string()))?;
                    rkeys.push((k.value().to_vec(), v.value().len() as u64));
                }
            }
            if rkeys.len() > self.max_envelopes {
                for (k, sz) in rkeys.iter().take(rkeys.len() - self.max_envelopes) {
                    t.remove(k.as_slice())
                        .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
                    total_bytes = total_bytes.saturating_sub(*sz);
                }
            }

            // (2) Global byte budget: evict the lowest-keyed envelopes until the
            // total is under the cap, so a spray across many recipient ids cannot
            // exhaust the disk either.
            if total_bytes > MAX_TOTAL_ENVELOPE_BYTES {
                let mut over = total_bytes - MAX_TOTAL_ENVELOPE_BYTES;
                let mut gkeys: Vec<Vec<u8>> = Vec::new();
                {
                    let iter = t
                        .iter()
                        .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
                    for entry in iter {
                        if over == 0 {
                            break;
                        }
                        let (k, v) =
                            entry.map_err(|e| RedbStorageError::Backend(e.to_string()))?;
                        let sz = v.value().len() as u64;
                        gkeys.push(k.value().to_vec());
                        over = over.saturating_sub(sz);
                        total_bytes = total_bytes.saturating_sub(sz);
                    }
                }
                for k in gkeys {
                    t.remove(k.as_slice())
                        .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
                }
            }
            drop(t);

            let mut meta = wtx
                .open_table(TBL_META)
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            meta.insert(META_ENV_BYTES, total_bytes.to_be_bytes().as_slice())
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        }
        wtx.commit()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        Ok(id)
    }

    /// POLL: return up to `max` envelopes for `recipient` with id > `since`,
    /// oldest first, as `(cursor, payload)`.
    pub fn poll(
        &self,
        recipient: &[u8; 32],
        since: u64,
        max: usize,
    ) -> Result<Vec<(u64, Vec<u8>)>, RedbStorageError> {
        let bi = self.b.blind_index(recipient);
        let lo = composite_key(&bi, since); // excluded → strictly id > since
        let hi = composite_key(&bi, u64::MAX);
        let rtx = self
            .b
            .db
            .begin_read()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        let table = rtx
            .open_table(TBL_ENV)
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        let range = table
            .range::<&[u8]>((Bound::Excluded(lo.as_slice()), Bound::Included(hi.as_slice())))
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        let mut out = Vec::new();
        for entry in range.take(max) {
            let (k, v) = entry.map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            let id = id_from_key(k.value())?;
            let key = composite_key(&bi, id);
            let pt = self.b.open_record(TID_ENVELOPE, &key, v.value())?;
            if pt.len() < ENV_HEADER_LEN {
                return Err(RedbStorageError::Malformed("envelope too short".into()));
            }
            out.push((id, pt[ENV_HEADER_LEN..].to_vec()));
        }
        Ok(out)
    }

    /// CHECKPOINT: advance `peer`'s stored epoch monotonically; reject rollbacks.
    pub fn checkpoint(
        &self,
        peer: &[u8; 32],
        epoch: u64,
    ) -> Result<CheckpointOutcome, RedbStorageError> {
        let key = self.b.blind_index(peer);
        let wtx = self
            .b
            .db
            .begin_write()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        // Read the (encrypted) stored record into an owned buffer first so the
        // table/guard borrow ends before we decrypt or reopen the table.
        let raw: Option<Vec<u8>> = {
            let t = wtx
                .open_table(TBL_CHECKPOINT)
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            let got = t
                .get(key.as_slice())
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            got.map(|g| g.value().to_vec())
        };
        let stored: Option<u64> = match raw {
            None => None,
            Some(v) => {
                let pt = self.b.open_record(TID_CHECKPOINT, &key, &v)?;
                if pt.len() < 8 {
                    return Err(RedbStorageError::Malformed("checkpoint too short".into()));
                }
                let mut b = [0u8; 8];
                b.copy_from_slice(&pt[..8]);
                Some(u64::from_be_bytes(b))
            }
        };
        if let Some(s) = stored {
            if epoch < s {
                // Regression — drop the txn uncommitted (redb aborts on drop),
                // leaving the stored value untouched.
                drop(wtx);
                return Ok(CheckpointOutcome::Rollback);
            }
        }
        let newv = stored.map_or(epoch, |s| s.max(epoch));
        let sealed = self.b.seal(TID_CHECKPOINT, &key, &newv.to_be_bytes())?;
        {
            let mut t = wtx
                .open_table(TBL_CHECKPOINT)
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            t.insert(key.as_slice(), sealed.as_slice())
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        }
        wtx.commit()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        Ok(CheckpointOutcome::Ok)
    }

    /// PUBLISH: append signed prekey `blobs` to `recipient`'s pool, then evict
    /// the oldest so at most `max_prekeys` remain (newest win).
    pub fn publish_prekeys(
        &self,
        recipient: &[u8; 32],
        blobs: &[Vec<u8>],
        created_at: i64,
    ) -> Result<(), RedbStorageError> {
        let bi = self.b.blind_index(recipient);
        let wtx = self
            .b
            .db
            .begin_write()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        for blob in blobs {
            let id = self.next_id(&wtx)?;
            let key = composite_key(&bi, id);
            let mut plain = Vec::with_capacity(PREKEY_HEADER_LEN + blob.len());
            plain.extend_from_slice(&created_at.to_be_bytes());
            plain.extend_from_slice(blob);
            let sealed = self.b.seal(TID_PREKEY, &key, &plain)?;
            let mut t = wtx
                .open_table(TBL_PREKEY)
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            t.insert(key.as_slice(), sealed.as_slice())
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        }
        // Evict oldest beyond the cap.
        {
            let mut t = wtx
                .open_table(TBL_PREKEY)
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            let lo = composite_key(&bi, 0);
            let hi = composite_key(&bi, u64::MAX);
            let mut keys: Vec<Vec<u8>> = Vec::new();
            {
                let range = t
                    .range::<&[u8]>(lo.as_slice()..=hi.as_slice())
                    .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
                for entry in range {
                    let (k, _v) = entry.map_err(|e| RedbStorageError::Backend(e.to_string()))?;
                    keys.push(k.value().to_vec());
                }
            }
            if keys.len() > self.max_prekeys {
                let drop_count = keys.len() - self.max_prekeys;
                for k in keys.iter().take(drop_count) {
                    t.remove(k.as_slice())
                        .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
                }
            }
        }
        wtx.commit()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))
    }

    /// FETCH: atomically pop the oldest prekey for `recipient` (one-time use).
    pub fn fetch_prekey(
        &self,
        recipient: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, RedbStorageError> {
        let bi = self.b.blind_index(recipient);
        let lo = composite_key(&bi, 0);
        let hi = composite_key(&bi, u64::MAX);
        let wtx = self
            .b
            .db
            .begin_write()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        let result = {
            let mut t = wtx
                .open_table(TBL_PREKEY)
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            // Lowest-id entry in the recipient range.
            let first: Option<(Vec<u8>, Vec<u8>)> = {
                let mut range = t
                    .range::<&[u8]>(lo.as_slice()..=hi.as_slice())
                    .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
                match range.next() {
                    None => None,
                    Some(entry) => {
                        let (k, v) =
                            entry.map_err(|e| RedbStorageError::Backend(e.to_string()))?;
                        Some((k.value().to_vec(), v.value().to_vec()))
                    }
                }
            };
            match first {
                None => None,
                Some((k, v)) => {
                    t.remove(k.as_slice())
                        .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
                    let pt = self.b.open_record(TID_PREKEY, &k, &v)?;
                    if pt.len() < PREKEY_HEADER_LEN {
                        return Err(RedbStorageError::Malformed("prekey too short".into()));
                    }
                    Some(pt[PREKEY_HEADER_LEN..].to_vec())
                }
            }
        };
        wtx.commit()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        Ok(result)
    }

    /// COUNT: number of prekeys remaining in `recipient`'s pool.
    pub fn count_prekeys(&self, recipient: &[u8; 32]) -> Result<usize, RedbStorageError> {
        let bi = self.b.blind_index(recipient);
        let lo = composite_key(&bi, 0);
        let hi = composite_key(&bi, u64::MAX);
        let rtx = self
            .b
            .db
            .begin_read()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        let table = rtx
            .open_table(TBL_PREKEY)
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        let range = table
            .range::<&[u8]>(lo.as_slice()..=hi.as_slice())
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        Ok(range.count())
    }
}

// ===================== Prekey store (local secret keys) ==============

/// redb-backed store for a node's own one-time + static prekey secret keys
/// ([`crate::prekey`]). Replaces the SQLCipher store; values are encrypted with
/// the same app-layer AEAD as the rest.
///
/// **Forward secrecy / secure delete**: consuming a one-time prekey must
/// physically retire its secret so a later DEK compromise cannot recover it to
/// break a past session's FS. SQLCipher used `PRAGMA secure_delete`; redb is
/// copy-on-write, so [`delete`](Self::delete) / [`delete_all`](Self::delete_all)
/// follow the remove with [`Database::compact`], which rewrites the file
/// dropping the freed pages — matching SQLCipher's *logical* guarantee. (Both
/// are best-effort against physical recovery on wear-levelled SSDs.)
///
/// Holds the `Database` behind a `Mutex` so the `&self` API can still take the
/// `&mut` that `compact` requires.
pub struct RedbPrekeyStore {
    db: std::sync::Mutex<Database>,
    keys: RecordKeys,
    db_binding: Vec<u8>,
}

impl std::fmt::Debug for RedbPrekeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedbPrekeyStore").finish_non_exhaustive()
    }
}

impl RedbPrekeyStore {
    pub fn open(path: impl AsRef<Path>, dek: &[u8; 32]) -> Result<Self, RedbStorageError> {
        let path = path.as_ref();
        let db_binding = path
            .file_name()
            .map(|n| n.as_encoded_bytes().to_vec())
            .unwrap_or_default();
        let db = open_db_secure(path)?;
        // Create tables + write/verify the DEK sentinel.
        {
            let wtx = db
                .begin_write()
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            for def in [TBL_PK_ONETIME, TBL_PK_STATIC, TBL_PK_META, TBL_SENTINEL] {
                wtx.open_table(def)
                    .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            }
            wtx.commit()
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        }
        let me = Self {
            db: std::sync::Mutex::new(db),
            keys: RecordKeys::derive(dek),
            db_binding,
        };
        me.ensure_sentinel()?;
        me.tighten(path)?;
        Ok(me)
    }

    fn tighten(&self, path: &Path) -> Result<(), RedbStorageError> {
        if path.exists() {
            crate::secure_fs::harden_owner_only(path)
                .map_err(|e| RedbStorageError::Backend(format!("tighten perms: {e}")))?;
        }
        Ok(())
    }

    fn ensure_sentinel(&self) -> Result<(), RedbStorageError> {
        let db = self.db.lock().unwrap();
        let existing = {
            let rtx = db
                .begin_read()
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            let t = rtx
                .open_table(TBL_SENTINEL)
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            t.get(SENTINEL_KEY)
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?
                .map(|g| g.value().to_vec())
        };
        match existing {
            Some(rec) => {
                open_value(&self.keys.k_value, &self.db_binding, TID_SENTINEL, SENTINEL_KEY, &rec)
                    .map_err(|_| RedbStorageError::Decrypt)?;
                Ok(())
            }
            None => {
                let sealed = seal_value(
                    &self.keys.k_value,
                    &self.db_binding,
                    TID_SENTINEL,
                    SENTINEL_KEY,
                    SENTINEL_PLAINTEXT,
                )?;
                let wtx = db
                    .begin_write()
                    .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
                {
                    let mut t = wtx
                        .open_table(TBL_SENTINEL)
                        .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
                    t.insert(SENTINEL_KEY, sealed.as_slice())
                        .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
                }
                wtx.commit()
                    .map_err(|e| RedbStorageError::Backend(e.to_string()))
            }
        }
    }

    fn meta_get_u64(&self, key: &[u8]) -> Result<Option<u64>, RedbStorageError> {
        let db = self.db.lock().unwrap();
        let rtx = db
            .begin_read()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        let t = rtx
            .open_table(TBL_PK_META)
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        let got = t
            .get(key)
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        Ok(got.map(|g| {
            let v = g.value();
            let mut b = [0u8; 8];
            b.copy_from_slice(&v[..8.min(v.len())]);
            u64::from_be_bytes(b)
        }))
    }

    fn meta_set_u64(&self, key: &[u8], val: u64) -> Result<(), RedbStorageError> {
        let db = self.db.lock().unwrap();
        let wtx = db
            .begin_write()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        {
            let mut t = wtx
                .open_table(TBL_PK_META)
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            t.insert(key, val.to_be_bytes().as_slice())
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        }
        wtx.commit()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))
    }

    /// Reserve `count` consecutive ids, returning the first. The counter is a
    /// persistent high-water mark that never rewinds (ids are never reused).
    pub fn reserve_ids(&self, count: u32) -> Result<u32, RedbStorageError> {
        let cur = self.meta_get_u64(PK_SEQ_KEY)?.unwrap_or(0);
        let start = u32::try_from(cur)
            .map_err(|_| RedbStorageError::Malformed("prekey id space exhausted".into()))?;
        let new_next = cur
            .checked_add(u64::from(count))
            .ok_or_else(|| RedbStorageError::Malformed("prekey id overflow".into()))?;
        u32::try_from(new_next)
            .map_err(|_| RedbStorageError::Malformed("prekey id space exhausted".into()))?;
        self.meta_set_u64(PK_SEQ_KEY, new_next)?;
        Ok(start)
    }

    pub fn insert(&self, prekey_id: u32, xwing_priv: &[u8]) -> Result<(), RedbStorageError> {
        let key = prekey_id.to_be_bytes();
        let sealed = seal_value(
            &self.keys.k_value,
            &self.db_binding,
            TID_PK_ONETIME,
            &key,
            xwing_priv,
        )?;
        let db = self.db.lock().unwrap();
        let wtx = db
            .begin_write()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        {
            let mut t = wtx
                .open_table(TBL_PK_ONETIME)
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            t.insert(key.as_slice(), sealed.as_slice())
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        }
        wtx.commit()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))
    }

    pub fn count(&self) -> Result<u64, RedbStorageError> {
        let db = self.db.lock().unwrap();
        let rtx = db
            .begin_read()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        let t = rtx
            .open_table(TBL_PK_ONETIME)
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        t.len().map_err(|e| RedbStorageError::Backend(e.to_string()))
    }

    pub fn list_ids(&self) -> Result<Vec<u32>, RedbStorageError> {
        let db = self.db.lock().unwrap();
        let rtx = db
            .begin_read()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        let t = rtx
            .open_table(TBL_PK_ONETIME)
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        let mut out = Vec::new();
        for entry in t
            .range::<&[u8]>(..)
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?
        {
            let (k, _v) = entry.map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            let kb = k.value();
            if kb.len() != 4 {
                return Err(RedbStorageError::Malformed("prekey id key length".into()));
            }
            out.push(u32::from_be_bytes([kb[0], kb[1], kb[2], kb[3]]));
        }
        Ok(out)
    }

    pub fn load(&self, prekey_id: u32) -> Result<Option<Vec<u8>>, RedbStorageError> {
        let key = prekey_id.to_be_bytes();
        let db = self.db.lock().unwrap();
        let rtx = db
            .begin_read()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        let t = rtx
            .open_table(TBL_PK_ONETIME)
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        let got = t
            .get(key.as_slice())
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?
            .map(|g| g.value().to_vec());
        drop(t);
        drop(rtx);
        match got {
            None => Ok(None),
            Some(rec) => {
                let pt = open_value(
                    &self.keys.k_value,
                    &self.db_binding,
                    TID_PK_ONETIME,
                    &key,
                    &rec,
                )?;
                Ok(Some(pt.to_vec()))
            }
        }
    }

    /// Delete a consumed prekey and compact to physically reclaim its page
    /// (logical secure-delete; see the struct doc). Returns whether a row went.
    pub fn delete(&self, prekey_id: u32) -> Result<bool, RedbStorageError> {
        let key = prekey_id.to_be_bytes();
        let mut db = self.db.lock().unwrap();
        let removed = {
            let wtx = db
                .begin_write()
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            let existed = {
                let mut t = wtx
                    .open_table(TBL_PK_ONETIME)
                    .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
                // Bind to a `let` (ending the statement) so the `?` temporary
                // holding the AccessGuard is dropped before `t` is.
                let removed = t
                    .remove(key.as_slice())
                    .map_err(|e| RedbStorageError::Backend(e.to_string()))?
                    .is_some();
                removed
            };
            wtx.commit()
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            existed
        };
        if removed {
            db.compact()
                .map_err(|e| RedbStorageError::Backend(format!("compact: {e}")))?;
        }
        Ok(removed)
    }

    /// Delete every one-time prekey and compact. Returns the number removed.
    pub fn delete_all(&self) -> Result<u64, RedbStorageError> {
        let mut db = self.db.lock().unwrap();
        let n = {
            let wtx = db
                .begin_write()
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            let count = {
                let mut t = wtx
                    .open_table(TBL_PK_ONETIME)
                    .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
                let keys: Vec<Vec<u8>> = {
                    let range = t
                        .range::<&[u8]>(..)
                        .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
                    let mut ks = Vec::new();
                    for entry in range {
                        let (k, _v) =
                            entry.map_err(|e| RedbStorageError::Backend(e.to_string()))?;
                        ks.push(k.value().to_vec());
                    }
                    ks
                };
                for k in &keys {
                    t.remove(k.as_slice())
                        .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
                }
                keys.len() as u64
            };
            wtx.commit()
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            count
        };
        if n > 0 {
            db.compact()
                .map_err(|e| RedbStorageError::Backend(format!("compact: {e}")))?;
        }
        Ok(n)
    }

    /// Store the long-term static keypair (sealed `priv_len ‖ priv ‖ pub`).
    /// Errors if one already exists (rotation is delete + re-init).
    pub fn store_identity(&self, sk: &[u8], pk: &[u8]) -> Result<(), RedbStorageError> {
        let db = self.db.lock().unwrap();
        {
            let rtx = db
                .begin_read()
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            let t = rtx
                .open_table(TBL_PK_STATIC)
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            if t.get(PK_STATIC_KEY)
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?
                .is_some()
            {
                return Err(RedbStorageError::Malformed(
                    "a static identity already exists in this store".into(),
                ));
            }
        }
        let mut plain = Vec::with_capacity(4 + sk.len() + pk.len());
        plain.extend_from_slice(&(sk.len() as u32).to_be_bytes());
        plain.extend_from_slice(sk);
        plain.extend_from_slice(pk);
        let sealed = seal_value(
            &self.keys.k_value,
            &self.db_binding,
            TID_PK_STATIC,
            PK_STATIC_KEY,
            &plain,
        )?;
        let wtx = db
            .begin_write()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        {
            let mut t = wtx
                .open_table(TBL_PK_STATIC)
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            t.insert(PK_STATIC_KEY, sealed.as_slice())
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        }
        wtx.commit()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))
    }

    /// Load the static keypair as `(priv, pub)`, or `None`.
    pub fn load_identity(&self) -> Result<Option<(Vec<u8>, Vec<u8>)>, RedbStorageError> {
        let db = self.db.lock().unwrap();
        let raw = {
            let rtx = db
                .begin_read()
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            let t = rtx
                .open_table(TBL_PK_STATIC)
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            t.get(PK_STATIC_KEY)
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?
                .map(|g| g.value().to_vec())
        };
        match raw {
            None => Ok(None),
            Some(rec) => {
                let pt = open_value(
                    &self.keys.k_value,
                    &self.db_binding,
                    TID_PK_STATIC,
                    PK_STATIC_KEY,
                    &rec,
                )?;
                if pt.len() < 4 {
                    return Err(RedbStorageError::Malformed("static identity too short".into()));
                }
                let sk_len = u32::from_be_bytes([pt[0], pt[1], pt[2], pt[3]]) as usize;
                if pt.len() < 4 + sk_len {
                    return Err(RedbStorageError::Malformed("static identity truncated".into()));
                }
                let sk = pt[4..4 + sk_len].to_vec();
                let pk = pt[4 + sk_len..].to_vec();
                Ok(Some((sk, pk)))
            }
        }
    }

    pub fn inbox_cursor(&self) -> Result<u64, RedbStorageError> {
        Ok(self.meta_get_u64(PK_CURSOR_KEY)?.unwrap_or(0))
    }

    pub fn set_inbox_cursor(&self, cursor: u64) -> Result<(), RedbStorageError> {
        self.meta_set_u64(PK_CURSOR_KEY, cursor)
    }
}

/// Extract the trailing 8-byte big-endian id from a `bi ‖ id_be` composite key.
fn id_from_key(key: &[u8]) -> Result<u64, RedbStorageError> {
    if key.len() != BLIND_INDEX_LEN + 8 {
        return Err(RedbStorageError::Malformed("composite key length".into()));
    }
    let mut id = [0u8; 8];
    id.copy_from_slice(&key[BLIND_INDEX_LEN..]);
    Ok(u64::from_be_bytes(id))
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
    fn group_commits_store_load_roundtrip_and_range() {
        let (_d, b) = backend();
        let gid = b"group-A";
        b.store_commit(gid, 1, b"commit-1").unwrap();
        b.store_commit(gid, 2, b"commit-2").unwrap();
        b.store_commit(gid, 3, b"commit-3").unwrap();

        // (0, 3] -> all three, ascending by epoch.
        let all: Vec<(u64, Vec<u8>)> = b
            .load_commits(gid, 0, 3)
            .unwrap()
            .iter()
            .map(|(e, c)| (*e, c.to_vec()))
            .collect();
        assert_eq!(
            all,
            vec![
                (1, b"commit-1".to_vec()),
                (2, b"commit-2".to_vec()),
                (3, b"commit-3".to_vec()),
            ]
        );

        // (1, 3] -> the delta a straggler at epoch 1 must replay: 2 and 3.
        let delta: Vec<u64> = b
            .load_commits(gid, 1, 3)
            .unwrap()
            .iter()
            .map(|(e, _)| *e)
            .collect();
        assert_eq!(delta, vec![2, 3]);
    }

    #[test]
    fn member_addr_put_list_roundtrip_overwrite_and_group_scoped() {
        let (_d, b) = backend();
        let ga = b"group-A";
        let gb = b"group-B";
        let n1 = [0x11u8; 32];
        let n2 = [0x22u8; 32];

        b.put_member_addr(ga, &n1, "nkct1-bob").unwrap();
        b.put_member_addr(ga, &n2, "nkct1-carol").unwrap();
        b.put_member_addr(gb, &n1, "nkct1-other").unwrap();

        // group-A has exactly its two members, keyed by node id.
        let mut a = b.list_member_addrs(ga).unwrap();
        a.sort();
        assert_eq!(
            a,
            vec![(n1, "nkct1-bob".to_string()), (n2, "nkct1-carol".to_string())]
        );

        // group scoping: group-B is independent.
        let bb = b.list_member_addrs(gb).unwrap();
        assert_eq!(bb, vec![(n1, "nkct1-other".to_string())]);

        // overwrite: a peer's address changes -> newest hint wins.
        b.put_member_addr(ga, &n1, "nkct1-bob-moved").unwrap();
        let a2 = b.list_member_addrs(ga).unwrap();
        let bob = a2.iter().find(|(nid, _)| *nid == n1).unwrap();
        assert_eq!(bob.1, "nkct1-bob-moved");
        assert_eq!(a2.len(), 2, "overwrite must not add a duplicate entry");

        // an empty group has no hints.
        assert!(b.list_member_addrs(b"group-empty").unwrap().is_empty());

        // forget removes only the targeted member; idempotent on a missing one.
        b.forget_member_addr(ga, &n1).unwrap();
        let a3 = b.list_member_addrs(ga).unwrap();
        assert_eq!(a3, vec![(n2, "nkct1-carol".to_string())]);
        b.forget_member_addr(ga, &n1).unwrap(); // no-op, must not error
        // group-B (same node id n1) is untouched by group-A's forget.
        assert_eq!(
            b.list_member_addrs(gb).unwrap(),
            vec![(n1, "nkct1-other".to_string())]
        );
    }

    #[test]
    fn group_commits_are_group_scoped() {
        let (_d, b) = backend();
        b.store_commit(b"group-A", 1, b"a1").unwrap();
        b.store_commit(b"group-B", 1, b"b1").unwrap();
        let a = b.load_commits(b"group-A", 0, u64::MAX).unwrap();
        assert_eq!(a.len(), 1, "range must not bleed into another group");
        assert_eq!(a[0].1.to_vec(), b"a1".to_vec());
    }

    #[test]
    fn group_commits_prune_keeps_newest() {
        let (_d, b) = backend();
        let gid = b"g";
        for e in 1..=5u64 {
            b.store_commit(gid, e, format!("c{e}").as_bytes()).unwrap();
        }
        // max=5, keep=2 -> cutoff=3, delete epochs <=3 (i.e. 1,2,3).
        let deleted = b.prune_commits(gid, 2).unwrap();
        assert_eq!(deleted, 3);
        let remaining: Vec<u64> = b
            .load_commits(gid, 0, u64::MAX)
            .unwrap()
            .iter()
            .map(|(e, _)| *e)
            .collect();
        assert_eq!(remaining, vec![4, 5]);
    }

    #[test]
    fn store_commit_is_idempotent_but_rejects_clobber() {
        let (_d, b) = backend();
        let gid = b"g";
        b.store_commit(gid, 1, b"canonical").unwrap();
        b.store_commit(gid, 1, b"canonical").unwrap(); // identical -> Ok (no-op)
        assert!(
            b.store_commit(gid, 1, b"forged").is_err(),
            "must refuse to replace a stored canonical commit with different bytes"
        );
        let c = b.load_commits(gid, 0, 1).unwrap();
        assert_eq!(c[0].1.to_vec(), b"canonical".to_vec(), "original intact");
    }

    #[test]
    fn load_commits_empty_on_invalid_range() {
        let (_d, b) = backend();
        let gid = b"g";
        b.store_commit(gid, 5, b"c5").unwrap();
        // Empty / inverted ranges yield no commits and must not panic.
        assert!(b.load_commits(gid, 5, 5).unwrap().is_empty());
        assert!(b.load_commits(gid, 9, 3).unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn new_db_file_is_private_from_creation() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("groups.redb");
        let _b = RedbBackend::open(&path, &[0x37u8; 32]).expect("open");
        // open_db_secure pre-creates the file at 0o600, so it is never group/
        // world readable — not even in the window before tighten_permissions.
        let mode = std::fs::metadata(&path).expect("metadata").permissions().mode();
        assert_eq!(mode & 0o077, 0, "redb DB file must not be group/other accessible (mode {mode:o})");
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
    fn wrong_dek_fails_open_via_sentinel() {
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
        // Reopen with a different DEK: the sentinel fails to decrypt, so open
        // fails fast rather than returning garbage.
        assert!(matches!(
            RedbBackend::open(&path, &[0x02; 32]),
            Err(RedbStorageError::Decrypt)
        ));
    }

    #[test]
    fn dek_opens_probe() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("groups.redb");
        drop(RedbBackend::open(&path, &[0x01; 32]).expect("open"));
        assert!(RedbBackend::dek_opens(&path, &[0x01; 32]).expect("probe ok"));
        assert!(!RedbBackend::dek_opens(&path, &[0x02; 32]).expect("probe wrong"));
        // Nonexistent DB → false, not an error.
        assert!(!RedbBackend::dek_opens(dir.path().join("nope.redb"), &[0x01; 32]).expect("absent"));
    }

    #[test]
    fn rotate_group_dek_reseals_under_new_key() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("groups.redb");
        let old = [0x11u8; 32];
        let new = [0x22u8; 32];
        // Seed a group, epoch, key package, psk, and app value under `old`.
        {
            let b = RedbBackend::open(&path, &old).expect("open");
            let mut gs = b.group_state_storage();
            gs.write(
                GroupState { id: vec![7; 32], data: Zeroizing::new(vec![0xab; 64]) },
                vec![EpochRecord::new(0, Zeroizing::new(vec![1; 16]))],
                vec![],
            )
            .expect("write");
            let mut kp = b.key_package_storage();
            kp.insert(vec![1, 2], KeyPackageData::new(vec![3], vec![4].into(), vec![5].into(), 9))
                .expect("kp");
            b.application_data_storage().insert("mls:identity:sk", &[0xcd; 32]).expect("app");
        }
        // Rotate old -> new.
        RedbBackend::rotate_group_dek(&path, &old, &new).expect("rotate");
        // Old DEK no longer opens; new DEK does, and all data survives.
        assert!(!RedbBackend::dek_opens(&path, &old).expect("old probe"));
        assert!(RedbBackend::dek_opens(&path, &new).expect("new probe"));
        let b2 = RedbBackend::open(&path, &new).expect("open new");
        let gs2 = b2.group_state_storage();
        assert_eq!(&*gs2.state(&[7; 32]).expect("state").unwrap(), &vec![0xab; 64]);
        assert_eq!(&*gs2.epoch(&[7; 32], 0).expect("epoch").unwrap(), &vec![1; 16]);
        assert!(b2.key_package_storage().get(&[1, 2]).expect("kp").is_some());
        assert_eq!(
            b2.application_data_storage().get("mls:identity:sk").expect("app").unwrap(),
            vec![0xcdu8; 32].into()
        );
    }

    #[test]
    fn rotate_with_wrong_old_dek_fails() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("groups.redb");
        {
            let b = RedbBackend::open(&path, &[0x11; 32]).expect("open");
            b.application_data_storage().insert("k", &[1, 2, 3]).expect("app");
        }
        // Wrong old DEK → the records won't decrypt → rotation errors, and the
        // single-transaction design means nothing is committed.
        assert!(RedbBackend::rotate_group_dek(&path, &[0x99; 32], &[0x22; 32]).is_err());
        // Original DEK still opens and data is intact.
        let b = RedbBackend::open(&path, &[0x11; 32]).expect("reopen old");
        assert_eq!(b.application_data_storage().get("k").expect("app").unwrap(), vec![1u8, 2, 3].into());
    }

    #[test]
    fn list_group_ids_enumerates() {
        let (_dir, b) = backend();
        let mut gs = b.group_state_storage();
        assert!(gs.list_group_ids().expect("list empty").is_empty());
        for gid in [vec![1, 2, 3], vec![9; 32], vec![0xde, 0xad]] {
            gs.write(
                GroupState { id: gid.clone(), data: Zeroizing::new(vec![1u8; 8]) },
                vec![],
                vec![],
            )
            .expect("write");
        }
        let mut ids = gs.list_group_ids().expect("list");
        ids.sort();
        let mut want = vec![vec![1, 2, 3], vec![9; 32], vec![0xde, 0xad]];
        want.sort();
        assert_eq!(ids, want);
        // state() still returns just the snapshot, not the embedded gid.
        let s = gs.state(&[1, 2, 3]).expect("state").expect("present");
        assert_eq!(&*s, &vec![1u8; 8]);
    }

    #[test]
    fn application_data_roundtrip() {
        let (_dir, b) = backend();
        let app = b.application_data_storage();
        assert!(app.get("mls:identity:sk").expect("get none").is_none());
        app.insert("mls:identity:sk", &[0xaa; 32]).expect("insert");
        app.insert("mls:identity:pk", &[0xbb; 32]).expect("insert");
        assert_eq!(app.get("mls:identity:sk").expect("get").unwrap(), vec![0xaau8; 32].into());
        assert_eq!(app.get("mls:identity:pk").expect("get").unwrap(), vec![0xbbu8; 32].into());
        // Overwrite.
        app.insert("mls:identity:sk", &[0xcc; 32]).expect("insert");
        assert_eq!(app.get("mls:identity:sk").expect("get").unwrap(), vec![0xccu8; 32].into());
    }

    // ---------------- inbox store ----------------

    fn inbox(max_prekeys: usize) -> (tempfile::TempDir, RedbInboxStore) {
        let dir = tempdir().expect("tempdir");
        let s = RedbInboxStore::open(dir.path().join("inbox.redb"), &[0x55u8; 32], max_prekeys, 256)
            .expect("open inbox");
        (dir, s)
    }

    #[test]
    fn inbox_envelope_cap_evicts_oldest() {
        // Per-recipient envelope cap = 3: after 5 deposits the two oldest
        // (ids 1,2) must be evicted, leaving only the three newest (3,4,5).
        let dir = tempdir().expect("tempdir");
        let s = RedbInboxStore::open(dir.path().join("inbox.redb"), &[0x55u8; 32], 256, 3)
            .expect("open inbox");
        let rcpt = [0x11u8; 32];
        for i in 1..=5u8 {
            s.deposit(&rcpt, &rcpt, &[i; 8], i as i64).expect("deposit");
        }
        let ids: Vec<u64> = s
            .poll(&rcpt, 0, 100)
            .expect("poll")
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        assert_eq!(ids, vec![3, 4, 5], "per-recipient cap should evict the oldest");
    }

    #[test]
    fn inbox_deposit_poll_cursor() {
        let (_d, s) = inbox(100);
        let rcpt = [0xa1u8; 32];
        let sender = [0xb2u8; 32];
        let id1 = s.deposit(&rcpt, &sender, b"m1", 100).expect("dep1");
        let id2 = s.deposit(&rcpt, &sender, b"m2", 101).expect("dep2");
        assert_eq!((id1, id2), (1, 2), "ids are monotonic from 1");

        // Drain from cursor 0.
        let all = s.poll(&rcpt, 0, 10).expect("poll");
        assert_eq!(all, vec![(1, b"m1".to_vec()), (2, b"m2".to_vec())]);

        // Incremental poll past the first cursor returns only the newer one.
        let newer = s.poll(&rcpt, 1, 10).expect("poll since 1");
        assert_eq!(newer, vec![(2, b"m2".to_vec())]);

        // max limits the batch.
        assert_eq!(s.poll(&rcpt, 0, 1).expect("poll max1").len(), 1);

        // A different recipient sees nothing.
        assert!(s.poll(&[0x00; 32], 0, 10).expect("poll other").is_empty());
    }

    #[test]
    fn inbox_poll_isolates_recipients() {
        let (_d, s) = inbox(100);
        let a = [0x01u8; 32];
        let b = [0x02u8; 32];
        s.deposit(&a, &a, b"for-a", 1).expect("dep a");
        s.deposit(&b, &b, b"for-b", 1).expect("dep b");
        let pa = s.poll(&a, 0, 10).expect("poll a");
        assert_eq!(pa.len(), 1);
        assert_eq!(pa[0].1, b"for-a".to_vec());
    }

    #[test]
    fn inbox_checkpoint_rollback() {
        let (_d, s) = inbox(100);
        let peer = [0xc3u8; 32];
        assert_eq!(s.checkpoint(&peer, 5).expect("cp5"), CheckpointOutcome::Ok);
        assert_eq!(s.checkpoint(&peer, 7).expect("cp7"), CheckpointOutcome::Ok);
        // Regression is rejected and does not lower the stored epoch.
        assert_eq!(
            s.checkpoint(&peer, 6).expect("cp6"),
            CheckpointOutcome::Rollback
        );
        // Re-advancing to the high-water mark or beyond still works.
        assert_eq!(s.checkpoint(&peer, 7).expect("cp7b"), CheckpointOutcome::Ok);
        assert_eq!(s.checkpoint(&peer, 9).expect("cp9"), CheckpointOutcome::Ok);
    }

    #[test]
    fn inbox_prekey_fifo_and_cap() {
        let (_d, s) = inbox(3); // cap = 3
        let rcpt = [0xd4u8; 32];
        // Publish 5; only the newest 3 survive the cap.
        let blobs: Vec<Vec<u8>> = (0u8..5).map(|i| vec![i; 4]).collect();
        s.publish_prekeys(&rcpt, &blobs, 10).expect("publish");
        assert_eq!(s.count_prekeys(&rcpt).expect("count"), 3);

        // FIFO pop returns the oldest surviving (blob #2, then #3, #4).
        assert_eq!(s.fetch_prekey(&rcpt).expect("f1"), Some(vec![2u8; 4]));
        assert_eq!(s.fetch_prekey(&rcpt).expect("f2"), Some(vec![3u8; 4]));
        assert_eq!(s.fetch_prekey(&rcpt).expect("f3"), Some(vec![4u8; 4]));
        assert_eq!(s.fetch_prekey(&rcpt).expect("f4"), None);
        assert_eq!(s.count_prekeys(&rcpt).expect("count0"), 0);
    }

    #[test]
    fn inbox_persists_across_reopen() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("inbox.redb");
        let dek = [0x77u8; 32];
        let rcpt = [0xe5u8; 32];
        {
            let s = RedbInboxStore::open(&path, &dek, 50, 256).expect("open");
            s.deposit(&rcpt, &rcpt, b"persisted", 1).expect("dep");
        }
        let s2 = RedbInboxStore::open(&path, &dek, 50, 256).expect("reopen");
        let got = s2.poll(&rcpt, 0, 10).expect("poll");
        assert_eq!(got, vec![(1, b"persisted".to_vec())]);
        // Cursor counter also persisted: next id is 2, not a reset to 1.
        let id = s2.deposit(&rcpt, &rcpt, b"again", 2).expect("dep2");
        assert_eq!(id, 2);
    }
}
