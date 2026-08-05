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

use std::path::{Path, PathBuf};
use std::sync::Arc;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use rand_core::{OsRng, RngCore};
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
const TID_ENV_TS: u8 = 14;
const TBL_ENV: TableDefinition<&[u8], &[u8]> = TableDefinition::new("inbox_env");
/// Side index over [`TBL_ENV`], one row per envelope under the *same* key, so
/// the expiry sweep and the byte ledgers can work without decrypting a single
/// envelope. Its own AAD table id ([`TID_ENV_TS`]) domain-separates it from the
/// envelope it indexes: neither record opens in the other's slot.
///
/// Holding the age and the size out here is what keeps a DEPOSIT cheap. The
/// alternative — deriving them from the envelopes themselves — makes every
/// request read and AEAD-open a table an unauthenticated depositor sizes, which
/// at the [`MAX_TOTAL_ENVELOPE_BYTES`] budget is ~1 GiB of work bought with one
/// small request.
const TBL_ENV_TS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("inbox_env_ts");
const TBL_PREKEY: TableDefinition<&[u8], &[u8]> = TableDefinition::new("inbox_prekey");
const TBL_CHECKPOINT: TableDefinition<&[u8], &[u8]> = TableDefinition::new("inbox_checkpoint");
/// Plaintext meta table: monotonic row-id counter (`b"next_id"` → u64 BE), the
/// byte ledgers, and the sweep/upgrade bookmarks. None of these values is
/// secret (the ledger keys are blind indexes, like the envelope keys), so they
/// are stored unencrypted.
const TBL_META: TableDefinition<&[u8], &[u8]> = TableDefinition::new("inbox_meta");

// Prekey store (local one-time/static prekey secret keys; see `crate::prekey`).
const TBL_PK_ONETIME: TableDefinition<&[u8], &[u8]> = TableDefinition::new("pk_onetime");
const TBL_PK_STATIC: TableDefinition<&[u8], &[u8]> = TableDefinition::new("pk_static");
/// Single-use gate for static-only one-shot envelopes (`crate::one_shot`):
/// `blind_index(envelope_tag)` → empty value (the key is the whole record). A
/// static-only envelope consumes no one-time prekey, so it has no natural
/// replay gate; this table is it. Keyed by a blind index so a stolen DB file
/// does not reveal which envelope digests were received.
///
/// **It is the only table that does not live in the prekey database.** It sits
/// alone in a sidecar redb file, `<prekey-db-path>.seen`
/// ([`RedbPrekeyStore::seen_db_path`]), created on the first static-only open.
/// Both reasons follow from this being the one artifact an *unauthenticated*
/// depositor can grow without bound:
///
/// * [`RedbPrekeyStore::delete`] calls [`Database::compact`] after every
///   consumed one-time prekey, to physically scrub the deleted secret's pages.
///   `compact` rewrites every page of every table in the file. Had the cache
///   shared that file, each legitimate `MODE_FULL` receipt — the
///   forward-secrecy path — would pay a cost proportional to a table the
///   attacker chooses the size of. In the sidecar, `compact` stays
///   proportional to the prekey material it exists to scrub.
/// * The prekey database also holds the long-term static X-Wing identity
///   (`TBL_PK_STATIC`). Reclaiming cache space must not mean deleting that
///   identity and orphaning every `NKB1` bundle already handed out. Deleting
///   the sidecar re-opens replay for previously seen envelopes and costs
///   nothing else; anyone able to delete it could equally delete the prekey
///   database itself, so this adds no reach.
///
/// **Nothing is ever evicted, deliberately.** Any capacity bound here would be
/// steerable by the very attacker this table exists to stop: the delivery
/// service can mint fresh static-only envelopes for us from public data alone
/// (our static X-Wing key out of our own `NKB1` bundle; `open` authenticates no
/// sender), so under any eviction rule keyed to arrival it just deposits enough
/// fresh envelopes to push a victim's tag out and then replays it. Retaining
/// every tag removes the steering entirely rather than pricing it.
///
/// **Residual, stated plainly.** The table grows monotonically in the number of
/// *distinct* static-only envelopes this recipient has opened, nothing prunes
/// it, and a depositor we never authenticate can drive that growth. What is
/// bounded is only the exchange rate: a measured row costs ~59 B at 10k rows
/// and ~74 B at 1M, against the ~1.2 KB envelope the attacker had to transmit
/// and we had to X-Wing-decapsulate — roughly 17 bytes on the wire per byte of
/// cache. So the residual is disk, and only disk: it is off the compaction path
/// and out of the identity file, and rows appear only in the degraded
/// static-only mode, never for a recipient whose prekey pool is kept stocked.
const TBL_PK_SEEN: TableDefinition<&[u8], &[u8]> = TableDefinition::new("pk_seen");
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
/// Poly1305 tag appended by XChaCha20-Poly1305.
const AEAD_TAG_LEN: usize = 16;

/// Exact stored size of the record [`seal_value`] produces for a plaintext of
/// `plaintext_len` bytes: `VERSION(1) ‖ nonce(24) ‖ ciphertext ‖ tag(16)`.
///
/// XChaCha20 is a stream cipher, so the ciphertext is byte-for-byte the length
/// of the plaintext and the stored size is known *before* anything is
/// encrypted. That is what lets [`RedbInboxStore::deposit`] settle its byte
/// quotas before it pays for a seal it may be about to refuse. Kept exact —
/// never an estimate — because the same number is charged to the ledgers; see
/// `sealed_len_predictor_is_exact`.
const fn sealed_len_for(plaintext_len: usize) -> u64 {
    (1 + NONCE_LEN + plaintext_len + AEAD_TAG_LEN) as u64
}

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
    #[error(
        "refusing to persist group state at epoch {incoming}: storage already holds epoch \
         {stored} (a concurrent writer would have rolled the group back)"
    )]
    EpochRollback { stored: u64, incoming: u64 },
    /// A DEPOSIT was refused because storing it would have exceeded a quota.
    /// The store **removed nothing** to make room: the request is turned away
    /// instead, so an unauthenticated depositor can never evict a row that is
    /// not its own. See [`RedbInboxStore::deposit`].
    #[error("inbox quota exceeded: {0}")]
    QuotaExceeded(&'static str),
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
        me.create_tables_in(&[
            TBL_ENV,
            TBL_ENV_TS,
            TBL_PREKEY,
            TBL_CHECKPOINT,
            TBL_META,
            TBL_SENTINEL,
        ])?;
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
    let mut nonce = XNonce::default();
    OsRng.fill_bytes(&mut nonce);
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
/// moment it exists and that no link at `path` is ever followed.
///
/// Two properties, and both need redb to be kept away from the path.
/// `Database::create` alone would create the file under the default umask /
/// inherited ACL and leave a window before `tighten_permissions` re-locks it,
/// so the file is pre-created exclusively at unix 0600 / a windows owner-only
/// DACL. But the exclusive create *also* fails with `AlreadyExists` against a
/// symlink planted at `path`, and handing redb the path after that let it
/// re-resolve and follow the very link the create had refused — initializing a
/// fresh ~1 MiB database over whatever the link aimed at, since redb adopts any
/// empty file as a new database. So redb is given an already-validated handle
/// via `create_file` instead: the path is resolved only by `secure_fs`, only
/// under no-follow, and a link is refused before a byte is written rather than
/// by the caller's `harden_owner_only` after the damage. Permissions on an
/// already-present database are still the caller's to tighten.
fn open_db_secure(path: &Path) -> Result<Database, RedbStorageError> {
    match crate::secure_fs::create_owner_only(path, false) {
        // Pre-created an empty owner-only file; redb initializes it as a new DB.
        Ok(_) => {}
        // Existing DB — open it (race-safe: exclusive create is atomic).
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(RedbStorageError::Backend(format!("precreate db: {e}"))),
    }
    // Reopened rather than kept from the create above, whose handle is
    // write-only on both platforms while redb needs read+write. This open is
    // no-follow too, so losing the race to a link swapped in behind the create
    // costs an error, never the target file.
    let file = crate::secure_fs::open_existing_no_follow_shared(path)
        .map_err(|e| RedbStorageError::Backend(format!("open db: {e}")))?;
    Database::builder()
        .create_file(file)
        .map_err(|e| RedbStorageError::Backend(e.to_string()))
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
    let nonce = XNonce::try_from(&record[1..1 + NONCE_LEN])
        .map_err(|_| RedbStorageError::Malformed("bad nonce length".into()))?;
    let ct = &record[1 + NONCE_LEN..];
    let cipher = XChaCha20Poly1305::new_from_slice(k_value).map_err(|_| RedbStorageError::Decrypt)?;
    let aad = aad_bytes(db_binding, table_id, redb_key);
    let pt = cipher
        .decrypt(&nonce, Payload { msg: ct, aad: &aad })
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
        // Epoch this write is carrying. `write_to_storage` always ships the
        // epoch records belonging to the snapshot, so the highest of them
        // identifies how far along the state being persisted is.
        let incoming_epoch = inserts.iter().chain(updates.iter()).map(|e| e.id).max();

        let wtx = b
            .db
            .begin_write()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        {
            // Compare-and-swap on the epoch, inside the same write transaction
            // as the writes below so two writers cannot interleave here.
            //
            // The snapshot upsert is unconditional, so without this a task
            // holding an older in-memory copy of the group could write it back
            // over a newer one and silently undo whatever the newer state
            // contained — including a Commit that removed a member, which would
            // reinstate the removed member on the roster and keep the old epoch
            // secrets live. Failing loudly is the point: a lost update here is
            // a membership-revocation failure, not a cache miss.
            if let Some(incoming) = incoming_epoch {
                let etable = wtx
                    .open_table(TBL_EPOCH)
                    .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
                let lo = group_epoch_key(gkey, 0);
                let hi = group_epoch_key(gkey, u64::MAX);
                let stored_max: Option<u64> = {
                    let mut range = etable
                        .range::<&[u8]>(lo.as_slice()..=hi.as_slice())
                        .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
                    match range.next_back() {
                        Some(entry) => {
                            let (k, _v) =
                                entry.map_err(|e| RedbStorageError::Backend(e.to_string()))?;
                            Some(epoch_from_group_key(k.value())?)
                        }
                        None => None,
                    }
                };
                if let Some(stored) = stored_max {
                    if incoming < stored {
                        return Err(RedbStorageError::EpochRollback { stored, incoming });
                    }
                }
            }
        }
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
    /// Per-recipient envelope count cap. A DEPOSIT into a slot already holding
    /// this many envelopes is **refused**; nothing is evicted to make room.
    max_envelopes: usize,
    /// Byte budgets for [`Self::deposit`]. Overridable in tests only, so a
    /// quota test need not move a gigabyte through the store.
    budget: ByteBudget,
}

/// The concrete redb table handle every inbox table uses.
type BytesTable<'txn> = redb::Table<'txn, &'static [u8], &'static [u8]>;

const META_NEXT_ID: &[u8] = b"next_id";
/// Running total of the ledger cost of every stored envelope (see
/// [`EnvTs::cost`]). Exact, not an estimate: it is only ever moved by
/// [`charge_ledgers`] / [`refund_ledgers`], both of which take the amount from
/// that one function.
const META_ENV_BYTES: &[u8] = b"env_bytes";
/// Schema version of the inbox database (u64 BE). Absent or lower than
/// [`INBOX_SCHEMA_VERSION`] means [`TBL_ENV_TS`] and the byte ledgers have not
/// been built for the rows already present; see `RedbInboxStore::upgrade_*`.
const META_SCHEMA: &[u8] = b"schema";
/// Wrapping position of the expiry sweep in [`TBL_ENV_TS`]: the last key it
/// looked at, or absent/empty to start from the beginning.
const META_SWEEP_CURSOR: &[u8] = b"sweep_cursor";
/// Unix time (i64 BE) of the last expiry sweep — the rate gate's only state.
const META_SWEEP_AT: &[u8] = b"sweep_at";
/// Resume position of the chunked [`TBL_ENV_TS`] upgrade. Present means the
/// upgrade has started (and the ledgers have been zeroed for it); absent
/// together with `META_SCHEMA == INBOX_SCHEMA_VERSION` means it finished.
const META_UPGRADE_CURSOR: &[u8] = b"ts_upgrade_cursor";
/// Prefix of a per-depositor byte-ledger key: `b"sb:" ‖ blind_index(sender)`.
const META_SENDER_PREFIX: &[u8] = b"sb:";
/// One past the last key of the `META_SENDER_PREFIX` range (`b"sb;"`), for
/// prefix scans over the ledger rows.
const META_SENDER_PREFIX_END: &[u8] = b"sb;";
const INBOX_SCHEMA_VERSION: u64 = 2;

/// Global cap on the total ledger cost of stored envelopes. DEPOSIT is
/// unauthenticated and accepts large payloads to arbitrary recipient ids, so a
/// per-recipient count cap alone cannot stop a spray across many ids — this
/// bounds the store's total on-disk size. `deposit` is the only writer of
/// `TBL_ENV` (POLL is read-only), so a counter maintained there stays accurate.
const MAX_TOTAL_ENVELOPE_BYTES: u64 = 1 << 30; // 1 GiB

/// Above this much of the budget in use the store is *congested* and switches
/// to the tighter per-depositor share below. Everything between it and
/// [`MAX_TOTAL_ENVELOPE_BYTES`] is the **congestion reserve**.
const ENVELOPE_CONGESTION_BYTES: u64 = MAX_TOTAL_ENVELOPE_BYTES / 4 * 3; // 768 MiB

/// Uncongested share of the byte budget one authenticated depositor may hold in
/// undelivered envelopes at once.
const MAX_ENVELOPE_BYTES_PER_SENDER: u64 = MAX_TOTAL_ENVELOPE_BYTES / 16; // 64 MiB

/// Share of the byte budget one depositor may hold **once the store is
/// congested**. This is what the congestion reserve buys, and it is all it
/// buys: every identity that helped fill the first
/// [`ENVELOPE_CONGESTION_BYTES`] is already far over this line, so none of them
/// can follow its own bytes into the reserve, and a depositor holding no
/// backlog — every honest one — is admitted ahead of them.
///
/// It does **not** put the reserve out of a fleet's reach. NodeIds are free to
/// mint and this share is exactly what one fresh identity may take, so the
/// reserve costs an attacker one new identity per slice: 256 of them consume
/// it, after which the global check in [`RedbInboxStore::deposit_in`] refuses
/// every depositor, honest ones included. Tightening this constant only raises
/// that identity count; no share keyed on a free-to-mint identity can do
/// better. Recorded as a residual in `KNOWN_ISSUES.md` (item 10).
///
/// One honest consequence to note: while the store is congested this share is
/// smaller than one [`crate::network::inbox::MAX_PAYLOAD`] envelope, so a
/// single legitimate 16 MiB deposit is refused even from an identity holding
/// nothing.
const MAX_ENVELOPE_BYTES_PER_SENDER_CONGESTED: u64 = MAX_TOTAL_ENVELOPE_BYTES / 1024; // 1 MiB

/// How long an undelivered envelope is kept before a sweep may reclaim it.
/// Reclamation *is* expiry now that a full slot refuses instead of evicting, so
/// this is the only thing that frees space: a week is long enough for a
/// recipient that polls occasionally, short enough to bound how long a flood
/// keeps a slot occupied.
///
/// Two sweeps apply it, and they are **not** equally prompt — do not read one
/// bound off the other:
/// - A **slot** is freed by the deposit addressed to it:
///   [`RedbInboxStore::sweep_recipient_expired`] walks that recipient's own key
///   range before the row cap is counted, so a backlog this old stops occupying
///   the slot on the very next deposit to that recipient.
/// - The **global byte budget** is given back by the table-wide
///   [`RedbInboxStore::sweep_expired`], which resumes from one shared wrapping
///   cursor at [`SWEEP_BUDGET_ROWS`] rows per rate-gated step and runs only
///   inside a DEPOSIT. Expired bytes elsewhere in the table therefore come back
///   as that cursor walks, not at the moment they expire, and not at all while
///   nobody is depositing.
///
/// Two behaviour changes come with it, both accepted and recorded in
/// `KNOWN_ISSUES.md` (item 10). Undelivered mail is now **deleted** after this
/// window, where the previous version kept it indefinitely — a recipient
/// offline for longer than a week loses whatever was waiting. And because POLL
/// does not delete what it returns, a delivered envelope still occupies its
/// recipient's slot until it expires, so a recipient can be sent at most
/// `max_envelopes` (256) envelopes per rolling window — all its correspondents
/// together — however promptly it drains them.
const ENVELOPE_TTL_SECS: i64 = 7 * 24 * 60 * 60;

/// The sweep runs at most this often, so hammering a full slot cannot buy more
/// than one bounded sweep per second however many DEPOSITs arrive.
const SWEEP_MIN_INTERVAL_SECS: i64 = 1;

/// Shared budget for one sweep: it stops at whichever of these it reaches
/// first. 512 rows is two full recipient slots, so one sweep can clear a
/// victim's expired backlog outright, and costs ~512 AEAD opens of a
/// [`ENV_TS_ROW_BYTES`]-byte row — no envelope is read, let alone decrypted.
const SWEEP_BUDGET_ROWS: usize = 512;
const SWEEP_BUDGET_BYTES: u64 = 32 << 20; // 32 MiB reclaimed per sweep

/// Rows the **per-recipient** pass ([`RedbInboxStore::sweep_recipient_expired`])
/// may examine. Mirrors `crate::network::inbox::MAX_ENVELOPES_PER_RECIPIENT` —
/// the value production passes as `max_envelopes` — the same way `max_prekeys`
/// mirrors `MAX_PREKEYS_STORED`, rather than reaching across into a module
/// gated on a different feature.
///
/// The row cap keeps one recipient's key range at most `max_envelopes` long, so
/// this covers a whole slot in one pass. (A caller that configured
/// `max_envelopes` *above* it would get the first 256 rows of such a slot swept
/// rather than all of it — never more work, only less.) It is a budget of its
/// own, *not* a slice of [`SWEEP_BUDGET_ROWS`]: the per-recipient pass can
/// therefore never leave the global pass with less than its full 512 rows, and
/// the two together examine at most 768 index rows per deposit.
const SWEEP_RECIPIENT_BUDGET_ROWS: usize = 256;

/// Envelope rows stamped per upgrade transaction. Each chunk commits its rows,
/// its ledger charges and its resume cursor together, so a crash costs at most
/// one chunk and never repeats one.
const UPGRADE_CHUNK_ROWS: usize = 512;

/// Depositor blind index recorded on rows the upgrade stamped. Their real
/// depositor is inside the envelope, and reading it would mean decrypting every
/// envelope in the store — the cost this side table exists to avoid. Their
/// bytes are therefore ledgered together under this reserved index; no live
/// sender shares it, since reaching it would take an HMAC-SHA256 preimage.
const LEGACY_SENDER_BI: [u8; BLIND_INDEX_LEN] = [0u8; BLIND_INDEX_LEN];

/// `TBL_ENV_TS` row plaintext:
/// `flags(1) ‖ created_at_be(8) ‖ sealed_len_be(8) ‖ sender_bi(32)`.
const ENV_TS_PLAIN_LEN: usize = 1 + 8 + 8 + BLIND_INDEX_LEN;

/// Stored size of one [`TBL_ENV_TS`] row. Constant, because every row's
/// plaintext is the same fixed length.
const ENV_TS_ROW_BYTES: u64 = sealed_len_for(ENV_TS_PLAIN_LEN);

/// [`EnvTs`] flag bit 0: this row's own storage was charged to the ledgers.
/// Clear on rows stamped by the upgrade — see [`EnvTs::cost`].
const ENV_TS_FLAG_INDEX_CHARGED: u8 = 0b0000_0001;

/// The [`TBL_ENV_TS`] row indexing one envelope: everything the expiry sweep
/// and the byte ledgers need, so neither ever opens the envelope itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EnvTs {
    /// Deposit time, in the same units as `deposit`'s `created_at`.
    created_at: i64,
    /// Stored size of the envelope record this row indexes.
    sealed_len: u64,
    /// `blind_index(sender)` of the depositor, for the per-sender ledger.
    sender_bi: [u8; BLIND_INDEX_LEN],
    /// Whether this row's own [`ENV_TS_ROW_BYTES`] were charged when it was
    /// written. False only for rows the upgrade stamped.
    index_charged: bool,
}

impl EnvTs {
    /// **The** definition of what one envelope costs the byte ledgers.
    ///
    /// Every charge (in `deposit`) and every refund (in the sweep) takes its
    /// amount from here, from the row itself, so the running totals cannot
    /// drift from the rows they are counting.
    ///
    /// A row the upgrade stamped pays only for the envelope that was already
    /// there. Retroactively adding this version's per-row index overhead would
    /// push a store that was exactly healthy under the old cap over the new
    /// budget the moment it was opened, and every deposit would then be refused
    /// until the sweep caught up.
    ///
    /// The price of that choice, stated so it is not a surprise: those
    /// [`ENV_TS_ROW_BYTES`] (~90 B per envelope) are real bytes on disk that no
    /// budget counts, so upgrading a large legacy inbox grows the file by about
    /// 90 B per stored envelope beyond [`MAX_TOTAL_ENVELOPE_BYTES`]. It is
    /// bounded by the legacy backlog and self-correcting: every such row is
    /// gone one [`ENVELOPE_TTL_SECS`] window after the upgrade, and its
    /// replacement is charged in full.
    fn cost(&self) -> u64 {
        if self.index_charged {
            self.sealed_len.saturating_add(ENV_TS_ROW_BYTES)
        } else {
            self.sealed_len
        }
    }

    fn to_plaintext(self) -> [u8; ENV_TS_PLAIN_LEN] {
        let mut out = [0u8; ENV_TS_PLAIN_LEN];
        out[0] = if self.index_charged {
            ENV_TS_FLAG_INDEX_CHARGED
        } else {
            0
        };
        out[1..9].copy_from_slice(&self.created_at.to_be_bytes());
        out[9..17].copy_from_slice(&self.sealed_len.to_be_bytes());
        out[17..].copy_from_slice(&self.sender_bi);
        out
    }

    fn from_plaintext(pt: &[u8]) -> Result<Self, RedbStorageError> {
        if pt.len() != ENV_TS_PLAIN_LEN {
            return Err(RedbStorageError::Malformed("env index row".into()));
        }
        let mut created = [0u8; 8];
        created.copy_from_slice(&pt[1..9]);
        let mut len = [0u8; 8];
        len.copy_from_slice(&pt[9..17]);
        let mut bi = [0u8; BLIND_INDEX_LEN];
        bi.copy_from_slice(&pt[17..]);
        Ok(Self {
            created_at: i64::from_be_bytes(created),
            sealed_len: u64::from_be_bytes(len),
            sender_bi: bi,
            index_charged: pt[0] & ENV_TS_FLAG_INDEX_CHARGED != 0,
        })
    }
}

/// The byte budgets [`RedbInboxStore::deposit`] enforces.
#[derive(Clone, Copy, Debug)]
struct ByteBudget {
    total: u64,
    congested_above: u64,
    per_sender: u64,
    per_sender_congested: u64,
}

impl Default for ByteBudget {
    fn default() -> Self {
        Self {
            total: MAX_TOTAL_ENVELOPE_BYTES,
            congested_above: ENVELOPE_CONGESTION_BYTES,
            per_sender: MAX_ENVELOPE_BYTES_PER_SENDER,
            per_sender_congested: MAX_ENVELOPE_BYTES_PER_SENDER_CONGESTED,
        }
    }
}

/// What one DEPOSIT did.
enum DepositOutcome {
    /// Stored, with the assigned cursor id.
    Stored(u64),
    /// Refused for the named quota. Nothing was removed to make room; the
    /// caller still commits, because the sweep that ran first must not be
    /// rolled back with it.
    Refused(&'static str),
}

/// Ledger key for one depositor: `b"sb:" ‖ blind_index(sender)`.
///
/// These rows are themselves uncounted: ~43 B of `TBL_META` (35 B of key, 8 B
/// of value) per depositor holding anything, which no budget charges. Bounded
/// by the number of distinct depositors with a live backlog, and
/// [`refund_ledgers`] drops a row the moment it reaches zero, so the set tracks
/// the envelopes rather than the identities that have ever deposited. Noted in
/// `KNOWN_ISSUES.md` (item 10) with the index-row overhead above.
fn sender_ledger_key(sender_bi: &[u8; BLIND_INDEX_LEN]) -> Vec<u8> {
    let mut k = Vec::with_capacity(META_SENDER_PREFIX.len() + BLIND_INDEX_LEN);
    k.extend_from_slice(META_SENDER_PREFIX);
    k.extend_from_slice(sender_bi);
    k
}

fn meta_read_u64<T>(meta: &T, key: &[u8]) -> Result<Option<u64>, RedbStorageError>
where
    T: ReadableTable<&'static [u8], &'static [u8]>,
{
    let got = meta
        .get(key)
        .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
    Ok(got.map(|g| {
        let raw = g.value();
        let mut b = [0u8; 8];
        // Copy only what is present, so a short/corrupt value cannot panic.
        let n = raw.len().min(8);
        b[..n].copy_from_slice(&raw[..n]);
        u64::from_be_bytes(b)
    }))
}

fn meta_write_u64(
    meta: &mut BytesTable<'_>,
    key: &[u8],
    val: u64,
) -> Result<(), RedbStorageError> {
    meta.insert(key, val.to_be_bytes().as_slice())
        .map(|_| ())
        .map_err(|e| RedbStorageError::Backend(e.to_string()))
}

/// Add `amount` to the global total and to `sender_bi`'s ledger.
fn charge_ledgers(
    meta: &mut BytesTable<'_>,
    sender_bi: &[u8; BLIND_INDEX_LEN],
    amount: u64,
) -> Result<(), RedbStorageError> {
    let total = meta_read_u64(meta, META_ENV_BYTES)?
        .unwrap_or(0)
        .saturating_add(amount);
    meta_write_u64(meta, META_ENV_BYTES, total)?;
    let key = sender_ledger_key(sender_bi);
    let mine = meta_read_u64(meta, &key)?.unwrap_or(0).saturating_add(amount);
    meta_write_u64(meta, &key, mine)
}

/// Give `amount` back to the global total and to `sender_bi`'s ledger, dropping
/// the ledger row once it reaches zero so the meta table cannot accumulate
/// entries for depositors with nothing stored.
fn refund_ledgers(
    meta: &mut BytesTable<'_>,
    sender_bi: &[u8; BLIND_INDEX_LEN],
    amount: u64,
) -> Result<(), RedbStorageError> {
    let total = meta_read_u64(meta, META_ENV_BYTES)?
        .unwrap_or(0)
        .saturating_sub(amount);
    meta_write_u64(meta, META_ENV_BYTES, total)?;
    let key = sender_ledger_key(sender_bi);
    let mine = meta_read_u64(meta, &key)?.unwrap_or(0).saturating_sub(amount);
    if mine == 0 {
        meta.remove(key.as_slice())
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        Ok(())
    } else {
        meta_write_u64(meta, &key, mine)
    }
}

/// Reserve the next monotonic id from an already-open meta table. Ids start at
/// 1 (so `since_cursor = 0` drains the whole backlog, like sqlite).
fn next_id_in(meta: &mut BytesTable<'_>) -> Result<u64, RedbStorageError> {
    let id = meta_read_u64(meta, META_NEXT_ID)?.unwrap_or(0).saturating_add(1);
    meta_write_u64(meta, META_NEXT_ID, id)?;
    Ok(id)
}

impl RedbInboxStore {
    /// Open (or create) the encrypted inbox database at `path`.
    pub fn open(
        path: impl AsRef<Path>,
        dek: &[u8; 32],
        max_prekeys: usize,
        max_envelopes: usize,
    ) -> Result<Self, RedbStorageError> {
        let me = Self {
            b: RedbBackend::open_inbox(path, dek)?,
            max_prekeys,
            max_envelopes,
            budget: ByteBudget::default(),
        };
        me.upgrade_env_index()?;
        Ok(me)
    }

    /// Shrink the byte budgets so a test can reach them without moving a
    /// gigabyte. Test-only: production always uses [`ByteBudget::default`].
    #[cfg(test)]
    #[must_use]
    fn with_byte_budget(
        mut self,
        total: u64,
        congested_above: u64,
        per_sender: u64,
        per_sender_congested: u64,
    ) -> Self {
        self.budget = ByteBudget {
            total,
            congested_above,
            per_sender,
            per_sender_congested,
        };
        self
    }

    /// Reserve the next monotonic id within an open write transaction.
    fn next_id(&self, wtx: &WriteTransaction) -> Result<u64, RedbStorageError> {
        let mut meta = wtx
            .open_table(TBL_META)
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        next_id_in(&mut meta)
    }

    /// DEPOSIT: store an envelope for `recipient`; returns the assigned cursor id.
    ///
    /// **Nothing is ever evicted to make room.** DEPOSIT is unauthenticated in
    /// the recipient it names — any peer that can dial `nkct/inbox/1` writes a
    /// 32-byte recipient field of its choosing — so a cap that made room by
    /// deleting would hand that peer a way to flush a victim's undelivered
    /// queue, silently: POLL's `id > since_cursor` semantics mean the victim
    /// never learns the messages existed. Every cap here therefore **refuses**
    /// the incoming deposit ([`RedbStorageError::QuotaExceeded`], answered on
    /// the wire with `REPLY_FAIL`) and leaves stored rows untouched.
    ///
    /// Reclamation is expiry instead. Each call first runs two bounded sweeps of
    /// envelopes older than [`ENVELOPE_TTL_SECS`], both committed **even when
    /// the deposit itself is refused** — otherwise a store full enough to refuse
    /// would roll its own reclamation back and never recover:
    ///
    /// - a rate-gated step of the table-wide, wrapping sweep
    ///   ([`Self::sweep_expired`]), which is what gives the **global** byte
    ///   budget back; then
    /// - a pass over **this recipient's own key range**
    ///   ([`Self::sweep_recipient_expired`]), run before the row cap below is
    ///   counted, which is what gives **this slot** back.
    ///
    /// Only the second is a promise about a particular slot, and the difference
    /// matters: a slot whose backlog is past [`ENVELOPE_TTL_SECS`] admits the
    /// very next deposit addressed to it, whereas the global total returns only
    /// as the shared cursor walks — `ceil(rows / SWEEP_BUDGET_ROWS)` gated
    /// sweeps, none of them while nobody is depositing.
    ///
    /// The caps, in the order they are applied:
    ///
    /// 1. **Per-recipient rows** (`max_envelopes`, 256): one slot cannot grow
    ///    without bound. This is the cap an unauthenticated depositor can reach
    ///    for someone else, and holding a victim's slot full costs more than the
    ///    full slot until the backlog expires: an honest sender spends a
    ///    one-time prekey at FETCH *before* it can learn the deposit will be
    ///    refused, so each attempt is one destroyed prekey and zero deliveries,
    ///    and enough of them exhaust the pool — after which the default profile
    ///    seals `MODE_STATIC_ONLY` (no PQ-FS) until the recipient republishes.
    ///    The hold does end at expiry, and by this deposit's own doing: the
    ///    per-recipient sweep above runs before this count, so keeping a slot
    ///    held means refilling it inside every [`ENVELOPE_TTL_SECS`] window.
    ///    Accepted trade, recorded in `KNOWN_ISSUES.md` (item 9).
    /// 2. **Global bytes**: the store's total on-disk bound. This one is
    ///    checked *before* the per-depositor share, so a store at
    ///    [`MAX_TOTAL_ENVELOPE_BYTES`] refuses **every** depositor, including a
    ///    fresh one holding nothing. A fleet of minted NodeIds can drive it
    ///    there; the reserve below raises the identity count, not the
    ///    possibility. Residual, recorded in `KNOWN_ISSUES.md` (item 10).
    /// 3. **Per-depositor bytes**, keyed by the *handshake-authenticated*
    ///    `sender` — a field no wire request can forge — so no one *identity*
    ///    can spend the whole store's budget on its own. Above
    ///    [`ByteBudget::congested_above`] the tighter congested share applies,
    ///    holding the top of the budget open for depositors with little or
    ///    nothing stored. Neither is a bound on a fleet: see cap 2.
    ///
    /// Both byte caps are settled *before* the payload is sealed, so a refusal
    /// costs no encryption.
    pub fn deposit(
        &self,
        recipient: &[u8; 32],
        sender: &[u8; 32],
        payload: &[u8],
        created_at: i64,
    ) -> Result<u64, RedbStorageError> {
        let bi = self.b.blind_index(recipient);
        let sender_bi = self.b.blind_index(sender);
        let wtx = self
            .b
            .db
            .begin_write()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        let outcome = self.deposit_in(&wtx, &bi, sender, &sender_bi, payload, created_at);
        match outcome {
            // A real storage error: drop the transaction (redb aborts on drop)
            // so a half-applied sweep or insert is never committed.
            Err(e) => {
                drop(wtx);
                Err(e)
            }
            // Refused — but the sweep above it must survive, so commit first.
            Ok(DepositOutcome::Refused(why)) => {
                wtx.commit()
                    .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
                Err(RedbStorageError::QuotaExceeded(why))
            }
            Ok(DepositOutcome::Stored(id)) => {
                wtx.commit()
                    .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
                Ok(id)
            }
        }
    }

    /// The body of [`Self::deposit`], inside its write transaction. Split out so
    /// every table handle is dropped before the caller commits.
    // allow(clippy::too_many_arguments): the seven parameters are the transaction
    // plus the six values one deposit is priced and keyed on; grouping them in a
    // struct would only move the same fields behind a name that adds nothing, and
    // the split exists to bound table-handle lifetimes, not to shape an API.
    // Future: revisit if deposit gains further inputs (no issue open).
    #[allow(clippy::too_many_arguments)]
    fn deposit_in(
        &self,
        wtx: &WriteTransaction,
        bi: &[u8; BLIND_INDEX_LEN],
        sender: &[u8; 32],
        sender_bi: &[u8; BLIND_INDEX_LEN],
        payload: &[u8],
        created_at: i64,
    ) -> Result<DepositOutcome, RedbStorageError> {
        let mut meta = wtx
            .open_table(TBL_META)
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        let mut env = wtx
            .open_table(TBL_ENV)
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        let mut ts = wtx
            .open_table(TBL_ENV_TS)
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;

        // (0a) Reclaim first, so an expired backlog does not refuse a deposit
        // the store actually has room for. Rate-gated to once a second, which
        // is what keeps a repeated, certain refusal cheap.
        self.sweep_expired(&mut meta, &mut env, &mut ts, created_at)?;

        // (0b) ...and reclaim *this recipient's* expired rows, which the sweep
        // above reaches only when its one shared cursor happens to walk their
        // range. Before the count below, so the slot this deposit is addressed
        // to is freed by this deposit — see `sweep_recipient_expired`.
        self.sweep_recipient_expired(&mut meta, &mut env, &mut ts, bi, created_at)?;

        // (1) Per-recipient row cap. Counted, not collected: the scan stops at
        // the cap, so it never walks a whole slot's values.
        let lo = composite_key(bi, 0);
        let hi = composite_key(bi, u64::MAX);
        let mut rows = 0usize;
        {
            let range = env
                .range::<&[u8]>(lo.as_slice()..=hi.as_slice())
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            for entry in range {
                entry.map_err(|e| RedbStorageError::Backend(e.to_string()))?;
                rows += 1;
                if rows >= self.max_envelopes {
                    break;
                }
            }
        }
        if rows >= self.max_envelopes {
            return Ok(DepositOutcome::Refused("recipient slot is full"));
        }

        // (2)+(3) Byte budgets, settled before anything is encrypted. The
        // sealed size is exact arithmetic on the payload length, so this needs
        // no trial seal (see `sealed_len_for`).
        let projected_cost = EnvTs {
            created_at,
            sealed_len: sealed_len_for(ENV_HEADER_LEN + payload.len()),
            sender_bi: *sender_bi,
            index_charged: true,
        }
        .cost();
        let total = meta_read_u64(&meta, META_ENV_BYTES)?.unwrap_or(0);
        let projected_total = total.saturating_add(projected_cost);
        if projected_total > self.budget.total {
            return Ok(DepositOutcome::Refused("store byte budget"));
        }
        let share = if projected_total > self.budget.congested_above {
            self.budget.per_sender_congested
        } else {
            self.budget.per_sender
        };
        let mine = meta_read_u64(&meta, &sender_ledger_key(sender_bi))?.unwrap_or(0);
        if mine.saturating_add(projected_cost) > share {
            return Ok(DepositOutcome::Refused("per-depositor byte budget"));
        }

        // Accepted: assign the cursor id, seal, and write the envelope with its
        // index row under the same key but a different AAD table id.
        let id = next_id_in(&mut meta)?;
        let key = composite_key(bi, id);
        let mut plain = Vec::with_capacity(ENV_HEADER_LEN + payload.len());
        plain.extend_from_slice(sender);
        plain.extend_from_slice(&created_at.to_be_bytes());
        plain.extend_from_slice(payload);
        let sealed = self.b.seal(TID_ENVELOPE, &key, &plain)?;
        debug_assert_eq!(
            sealed.len() as u64,
            sealed_len_for(plain.len()),
            "sealed-size predictor must be exact or the ledger drifts"
        );
        // Charged from the *stored* length, so the ledger stays exact even if
        // the predictor above were ever to disagree with the cipher.
        let row = EnvTs {
            created_at,
            sealed_len: sealed.len() as u64,
            sender_bi: *sender_bi,
            index_charged: true,
        };
        let ts_sealed = self.b.seal(TID_ENV_TS, &key, &row.to_plaintext())?;
        env.insert(key.as_slice(), sealed.as_slice())
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        ts.insert(key.as_slice(), ts_sealed.as_slice())
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        charge_ledgers(&mut meta, sender_bi, row.cost())?;
        Ok(DepositOutcome::Stored(id))
    }

    /// Delete envelopes older than [`ENVELOPE_TTL_SECS`] **anywhere in the
    /// table**, refunding their cost to the ledgers. This is what reclaims the
    /// *global* byte budget now that a full slot refuses rather than evicts.
    ///
    /// What it is not is a bound on how long any *particular* slot stays
    /// occupied: it walks from one shared cursor, so it reaches a given
    /// recipient only when that cursor gets there. That promise belongs to
    /// [`Self::sweep_recipient_expired`], which every deposit runs over its own
    /// recipient's range.
    ///
    /// Bounded three ways so it can never become the expensive half of a cheap
    /// request: a rate gate ([`SWEEP_MIN_INTERVAL_SECS`]) means a flood of
    /// DEPOSITs buys at most one sweep per second; a shared row/byte budget
    /// ([`SWEEP_BUDGET_ROWS`] / [`SWEEP_BUDGET_BYTES`]) caps one sweep; and a
    /// wrapping cursor means successive sweeps continue around the table
    /// instead of re-walking its start. It reads only [`TBL_ENV_TS`], so no
    /// envelope is ever decrypted — the whole reason that side table exists.
    fn sweep_expired(
        &self,
        meta: &mut BytesTable<'_>,
        env: &mut BytesTable<'_>,
        ts: &mut BytesTable<'_>,
        now: i64,
    ) -> Result<(), RedbStorageError> {
        if let Some(last) = meta_read_u64(meta, META_SWEEP_AT)?.map(|v| v as i64) {
            // A clock that stepped backwards leaves a mark in the future; treat
            // that as due rather than stalling reclamation until it catches up.
            if now >= last && now.saturating_sub(last) < SWEEP_MIN_INTERVAL_SECS {
                return Ok(());
            }
        }
        meta_write_u64(meta, META_SWEEP_AT, now as u64)?;

        let cursor: Vec<u8> = meta
            .get(META_SWEEP_CURSOR)
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?
            .map(|g| g.value().to_vec())
            .unwrap_or_default();

        let mut expired: Vec<(Vec<u8>, EnvTs)> = Vec::new();
        let mut examined = 0usize;
        let mut reclaimed = 0u64;
        let mut resume: Vec<u8> = Vec::new();
        let mut wrapped = true;
        {
            // An empty cursor excludes nothing (no key is empty), so it means
            // "from the beginning" — which is also where the wrap lands.
            let range = ts
                .range::<&[u8]>((Bound::Excluded(cursor.as_slice()), Bound::Unbounded))
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            for entry in range {
                let (k, v) = entry.map_err(|e| RedbStorageError::Backend(e.to_string()))?;
                let key = k.value().to_vec();
                let raw = v.value().to_vec();
                examined += 1;
                resume = key.clone();
                // A row that will not open is left alone rather than failing the
                // deposit: the cursor still advances past it, so a single
                // damaged row cannot wedge every future sweep behind it.
                if let Ok(pt) = self.b.open_record(TID_ENV_TS, &key, &raw) {
                    if let Ok(row) = EnvTs::from_plaintext(&pt) {
                        if now.saturating_sub(row.created_at) > ENVELOPE_TTL_SECS {
                            reclaimed = reclaimed.saturating_add(row.cost());
                            expired.push((key, row));
                        }
                    }
                }
                if examined >= SWEEP_BUDGET_ROWS || reclaimed >= SWEEP_BUDGET_BYTES {
                    wrapped = false;
                    break;
                }
            }
        }
        for (key, row) in expired {
            ts.remove(key.as_slice())
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            env.remove(key.as_slice())
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            refund_ledgers(meta, &row.sender_bi, row.cost())?;
        }
        // Ran off the end → start the next sweep at the beginning.
        let next = if wrapped { Vec::new() } else { resume };
        meta.insert(META_SWEEP_CURSOR, next.as_slice())
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        Ok(())
    }

    /// Delete **one recipient's** envelopes older than [`ENVELOPE_TTL_SECS`],
    /// refunding their cost, before [`Self::deposit_in`] counts the row cap.
    ///
    /// This is what makes the bound the refusal leans on real. Refusing a full
    /// slot is only an acceptable trade because the slot frees itself when its
    /// backlog expires, and [`Self::sweep_expired`] cannot deliver that: it
    /// resumes from one shared wrapping cursor at [`SWEEP_BUDGET_ROWS`] rows per
    /// rate-gated step, so a victim's expired rows wait for
    /// `ceil(rows / SWEEP_BUDGET_ROWS)` further deposit-driven sweeps — a
    /// distance the flooder itself sets, by how many unrelated rows it stored
    /// elsewhere in the table (millions fit inside the byte budget). That turns
    /// a one-week slot hold into an open-ended one. Sweeping the range the
    /// deposit is *addressed to* costs the attacker its whole advantage: it must
    /// refill the slot inside every [`ENVELOPE_TTL_SECS`] window, and no amount
    /// of junk stored elsewhere postpones the next honest delivery.
    ///
    /// Bounded by the range it walks — at most `max_envelopes` rows, since that
    /// is the cap [`Self::deposit_in`] enforces on every slot — and explicitly by
    /// [`SWEEP_RECIPIENT_BUDGET_ROWS`] examined rows or [`SWEEP_BUDGET_BYTES`]
    /// reclaimed, whichever comes first. Stopping early still deletes every
    /// expired row already collected, so a slot full of expired mail is left
    /// under its cap either way and the deposit lands. The budget is its own:
    /// this pass neither spends nor moves [`META_SWEEP_CURSOR`], so it can never
    /// starve the global pass, which keeps all of its 512 rows.
    ///
    /// Deliberately **not** behind [`SWEEP_MIN_INTERVAL_SECS`]. That gate exists
    /// so a flood cannot make every request pay for a walk of the whole table —
    /// shared work, which one sweep per second already advances no matter how
    /// many requests arrive. This pass is the opposite: it is the only thing
    /// that can free the slot *this* deposit names, so a closed gate would
    /// refuse a deposit the store has room for and hand back exactly the
    /// open-ended hold above. Its cost is bounded by the named slot's own
    /// occupancy — which the row cap caps, and which nobody raises except by
    /// making accepted deposits out of its own byte budget.
    ///
    /// No row is swept twice or refunded twice across the two passes: they share
    /// one write transaction, so rows the global pass removed are already gone
    /// from [`TBL_ENV_TS`] when this one ranges over it, and both take the
    /// amount they refund from the same [`EnvTs::cost`].
    fn sweep_recipient_expired(
        &self,
        meta: &mut BytesTable<'_>,
        env: &mut BytesTable<'_>,
        ts: &mut BytesTable<'_>,
        bi: &[u8; BLIND_INDEX_LEN],
        now: i64,
    ) -> Result<(), RedbStorageError> {
        let lo = composite_key(bi, 0);
        let hi = composite_key(bi, u64::MAX);
        let mut expired: Vec<(Vec<u8>, EnvTs)> = Vec::new();
        let mut examined = 0usize;
        let mut reclaimed = 0u64;
        {
            let range = ts
                .range::<&[u8]>(lo.as_slice()..=hi.as_slice())
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            for entry in range {
                let (k, v) = entry.map_err(|e| RedbStorageError::Backend(e.to_string()))?;
                let key = k.value().to_vec();
                let raw = v.value().to_vec();
                examined += 1;
                // A row that will not open is left alone rather than failing the
                // deposit, exactly as in the global pass.
                if let Ok(pt) = self.b.open_record(TID_ENV_TS, &key, &raw) {
                    if let Ok(row) = EnvTs::from_plaintext(&pt) {
                        if now.saturating_sub(row.created_at) > ENVELOPE_TTL_SECS {
                            reclaimed = reclaimed.saturating_add(row.cost());
                            expired.push((key, row));
                        }
                    }
                }
                if examined >= SWEEP_RECIPIENT_BUDGET_ROWS || reclaimed >= SWEEP_BUDGET_BYTES {
                    break;
                }
            }
        }
        for (key, row) in expired {
            ts.remove(key.as_slice())
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            env.remove(key.as_slice())
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            refund_ledgers(meta, &row.sender_bi, row.cost())?;
        }
        Ok(())
    }

    /// Build [`TBL_ENV_TS`] and the byte ledgers for envelopes written before
    /// this version, then mark the database [`INBOX_SCHEMA_VERSION`].
    ///
    /// Runs in chunks that each commit their rows, their charges and their
    /// resume cursor in one transaction, so an interrupted upgrade resumes
    /// where it stopped and never stamps a row twice. It never decrypts an
    /// envelope: a legacy row's size is its stored length, its age is the time
    /// of the upgrade, and its depositor — which only the envelope knows — is
    /// ledgered under [`LEGACY_SENDER_BI`].
    fn upgrade_env_index(&self) -> Result<(), RedbStorageError> {
        {
            let rtx = self
                .b
                .db
                .begin_read()
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            let meta = rtx
                .open_table(TBL_META)
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            if meta_read_u64(&meta, META_SCHEMA)?.unwrap_or(0) >= INBOX_SCHEMA_VERSION {
                return Ok(());
            }
        }
        let stamped_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        while !self.upgrade_chunk(stamped_at, UPGRADE_CHUNK_ROWS)? {}
        Ok(())
    }

    /// One chunk of [`Self::upgrade_env_index`]. Returns `true` when the
    /// upgrade is complete.
    fn upgrade_chunk(&self, stamped_at: i64, chunk: usize) -> Result<bool, RedbStorageError> {
        let wtx = self
            .b
            .db
            .begin_write()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        let done = self.upgrade_chunk_in(&wtx, stamped_at, chunk)?;
        wtx.commit()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        Ok(done)
    }

    fn upgrade_chunk_in(
        &self,
        wtx: &WriteTransaction,
        stamped_at: i64,
        chunk: usize,
    ) -> Result<bool, RedbStorageError> {
        let mut meta = wtx
            .open_table(TBL_META)
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        let env = wtx
            .open_table(TBL_ENV)
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        let mut ts = wtx
            .open_table(TBL_ENV_TS)
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;

        let started = meta
            .get(META_UPGRADE_CURSOR)
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?
            .map(|g| g.value().to_vec());
        let cursor = match started {
            Some(c) => c,
            None => {
                // First chunk: the totals are rebuilt from the rows themselves,
                // so any figure an older version left behind is discarded.
                meta_write_u64(&mut meta, META_ENV_BYTES, 0)?;
                let stale: Vec<Vec<u8>> = {
                    let range = meta
                        .range::<&[u8]>(META_SENDER_PREFIX..META_SENDER_PREFIX_END)
                        .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
                    let mut out = Vec::new();
                    for entry in range {
                        let (k, _) =
                            entry.map_err(|e| RedbStorageError::Backend(e.to_string()))?;
                        out.push(k.value().to_vec());
                    }
                    out
                };
                for k in stale {
                    meta.remove(k.as_slice())
                        .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
                }
                meta.insert(META_UPGRADE_CURSOR, [].as_slice())
                    .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
                Vec::new()
            }
        };

        let mut batch: Vec<(Vec<u8>, u64)> = Vec::new();
        let mut exhausted = true;
        {
            let range = env
                .range::<&[u8]>((Bound::Excluded(cursor.as_slice()), Bound::Unbounded))
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            for entry in range {
                let (k, v) = entry.map_err(|e| RedbStorageError::Backend(e.to_string()))?;
                batch.push((k.value().to_vec(), v.value().len() as u64));
                if batch.len() >= chunk {
                    exhausted = false;
                    break;
                }
            }
        }

        let mut resume = cursor;
        for (key, sealed_len) in batch {
            // Every envelope this loop walks past is charged, whatever state its
            // index row is in. The first chunk zeroed the ledgers, so skipping a
            // row that happened to be there already would finish the upgrade
            // with envelopes intact and the global budget counting none of them
            // — a store presenting an old schema with index rows present
            // (corruption, or a restored partial file) would come up with its
            // byte cap silently disabled.
            let existing = ts
                .get(key.as_slice())
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?
                .map(|g| g.value().to_vec());
            let readable = existing.as_ref().and_then(|raw| {
                let pt = self.b.open_record(TID_ENV_TS, &key, raw).ok()?;
                EnvTs::from_plaintext(&pt).ok()
            });
            let row = match readable {
                // Keep the row that is there — its real deposit time and
                // depositor beat anything this upgrade could invent — and
                // charge what it says it costs.
                Some(row) => row,
                // Absent, or present but unreadable. An unreadable row is worse
                // than none: the sweep skips what it cannot open, so its
                // envelope would never expire and a charge against it would
                // never be refunded. Stamp a fresh legacy row over it, which is
                // both charged and sweepable.
                None => {
                    let row = EnvTs {
                        created_at: stamped_at,
                        sealed_len,
                        sender_bi: LEGACY_SENDER_BI,
                        index_charged: false,
                    };
                    let sealed = self.b.seal(TID_ENV_TS, &key, &row.to_plaintext())?;
                    ts.insert(key.as_slice(), sealed.as_slice())
                        .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
                    row
                }
            };
            charge_ledgers(&mut meta, &row.sender_bi, row.cost())?;
            resume = key;
        }

        if exhausted {
            meta_write_u64(&mut meta, META_SCHEMA, INBOX_SCHEMA_VERSION)?;
            meta.remove(META_UPGRADE_CURSOR)
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        } else {
            meta.insert(META_UPGRADE_CURSOR, resume.as_slice())
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        }
        Ok(exhausted)
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
/// are best-effort against physical recovery on wear-levelled SSDs.) Because
/// that rewrite touches every page in the file, this database deliberately
/// holds prekey material only: the static-only replay cache is a sidecar file
/// (see `TBL_PK_SEEN`) so `compact`'s cost never tracks anything a remote
/// depositor can grow.
///
/// Holds the `Database` behind a `Mutex` so the `&self` API can still take the
/// `&mut` that `compact` requires.
pub struct RedbPrekeyStore {
    db: std::sync::Mutex<Database>,
    /// Sidecar database holding `TBL_PK_SEEN` and nothing else, opened lazily
    /// on the first static-only open so a recipient that never receives a
    /// downgraded envelope never creates the file. Laziness costs no
    /// atomicity: this `Mutex` is held across the create *and* the whole
    /// check-and-insert transaction (see [`Self::record_static_only_seen`]).
    seen_db: std::sync::Mutex<Option<Database>>,
    seen_path: PathBuf,
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
            // The static-only replay cache belongs in the sidecar DB, never
            // here (see `TBL_PK_SEEN`). `delete_table` returns `false` without
            // creating anything when the table is absent, which is every file
            // written by a released build; it only bites on a `prekeys.db` from
            // the unreleased intermediate revision that did put `pk_seen`
            // inline, where it drops the dead table so it stops being rewritten
            // by `delete`'s compaction. Those rows are not migrated: they are
            // replay-cache state from a build that never shipped, and losing
            // them only means envelopes opened under that build could be
            // replayed once more.
            wtx.delete_table(TBL_PK_SEEN)
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            wtx.commit()
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        }
        let me = Self {
            db: std::sync::Mutex::new(db),
            seen_db: std::sync::Mutex::new(None),
            seen_path: Self::seen_db_path(path),
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

    /// Path of the sidecar database that holds the static-only replay cache:
    /// the prekey database path with `.seen` appended, the same way
    /// [`AtRestPaths::beside_db`](crate::group::at_rest::AtRestPaths::beside_db)
    /// names `prekeys.db.at-rest.key` beside `prekeys.db`. Derived, never
    /// configured — which file the cache lives in is an internal storage
    /// detail, not an operator knob.
    pub(crate) fn seen_db_path(path: &Path) -> PathBuf {
        let mut s = path.to_path_buf().into_os_string();
        s.push(".seen");
        PathBuf::from(s)
    }

    /// Create/open the sidecar and make sure its one table exists. It carries
    /// no DEK sentinel because it stores no sealed values — only blind-index
    /// keys, which a wrong DEK would simply fail to match. A wrong DEK is
    /// already rejected by the prekey database's own sentinel long before any
    /// static-only envelope reaches here.
    fn open_seen_db(&self) -> Result<Database, RedbStorageError> {
        let db = open_db_secure(&self.seen_path)?;
        let wtx = db
            .begin_write()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        wtx.open_table(TBL_PK_SEEN)
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        wtx.commit()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        self.tighten(&self.seen_path)?;
        Ok(db)
    }

    /// Blind index for the seen-envelope cache: `HMAC-SHA256(k_bi, tag)`, the
    /// same construction [`RedbBackend::blind_index`] uses for recipient ids.
    /// `RedbPrekeyStore` carries its own [`RecordKeys`] rather than a backend
    /// handle, so the two-line HMAC lives here instead of being plumbed in.
    fn seen_index(&self, tag: &[u8]) -> [u8; BLIND_INDEX_LEN] {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(self.keys.k_bi.as_slice())
            .expect("HMAC accepts any key length");
        mac.update(tag);
        mac.finalize().into_bytes().into()
    }

    /// Record `tag` (a digest of a *verified* static-only one-shot envelope) in
    /// the single-use cache, returning `true` if it was **already** there —
    /// i.e. this exact envelope has been opened before and is being
    /// re-delivered.
    ///
    /// The membership test and the insert share one redb write transaction, so
    /// two concurrent opens of the same envelope serialize and exactly one of
    /// them observes `false` — the same serialization point [`Self::delete`]
    /// gives full-mode envelopes via the consumed one-time prekey.
    ///
    /// The record is permanent: see `TBL_PK_SEEN` for why an eviction rule
    /// would hand the gate's bypass back to the delivery service, for why the
    /// cache is a sidecar database rather than a table in this store, and for
    /// the residual that retaining every tag leaves.
    pub fn record_static_only_seen(&self, tag: &[u8]) -> Result<bool, RedbStorageError> {
        let key = self.seen_index(tag);
        // Held across the lazy create and the transaction below, so the
        // check-and-insert stays a single serialization point.
        let mut slot = self.seen_db.lock().unwrap();
        if slot.is_none() {
            *slot = Some(self.open_seen_db()?);
        }
        let db = slot.as_ref().expect("just populated");
        let wtx = db
            .begin_write()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        let already = {
            let mut seen = wtx
                .open_table(TBL_PK_SEEN)
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            let present = seen
                .get(key.as_slice())
                .map_err(|e| RedbStorageError::Backend(e.to_string()))?
                .is_some();
            if !present {
                seen.insert(key.as_slice(), [].as_slice())
                    .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
            }
            present
        };
        wtx.commit()
            .map_err(|e| RedbStorageError::Backend(e.to_string()))?;
        Ok(already)
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

    /// The F8 scenario at the storage layer: two writers each loaded the group
    /// at epoch N, one advanced it to N+1 and persisted, and the other then
    /// writes its stale epoch-N snapshot back. That write must be REFUSED, not
    /// silently accepted — accepting it is what reinstates a removed member and
    /// rewinds the sender ratchet. The per-group async lock normally prevents
    /// the interleave; this is the backstop for any path that bypasses it.
    #[test]
    fn stale_snapshot_write_is_refused() {
        let (_d, b) = backend();
        let gss = b.group_state_storage();
        let gid = b"group-race".to_vec();

        let state = |data: &[u8]| GroupState {
            id: gid.clone(),
            data: data.to_vec().into(),
        };
        let epoch = |id: u64, data: &[u8]| EpochRecord {
            id,
            data: data.to_vec().into(),
        };

        // Both tasks loaded epoch 5. The inbound task applies a Remove and
        // persists epoch 6.
        gss.write_inner(state(b"at-5"), vec![epoch(5, b"e5")], vec![])
            .expect("initial write");
        gss.write_inner(state(b"at-6-remove-applied"), vec![epoch(6, b"e6")], vec![])
            .expect("advancing write");

        // The REPL task, still holding its epoch-5 copy, writes back.
        let err = gss
            .write_inner(state(b"at-5-stale"), vec![], vec![epoch(5, b"e5")])
            .expect_err("a stale snapshot must not be persisted");
        match err {
            RedbStorageError::EpochRollback { stored, incoming } => {
                assert_eq!(stored, 6);
                assert_eq!(incoming, 5);
            }
            other => panic!("expected EpochRollback, got {other:?}"),
        }

        // The advanced state survived the attempt.
        let loaded = gss.state(&gid).expect("state").expect("present");
        assert_eq!(loaded.to_vec(), b"at-6-remove-applied".to_vec());
    }

    /// Normal forward progress, and re-writing the *current* epoch (the sender
    /// ratchet advancing within an epoch), must both still be accepted.
    #[test]
    fn same_and_advancing_epoch_writes_are_accepted() {
        let (_d, b) = backend();
        let gss = b.group_state_storage();
        let gid = b"group-ok".to_vec();
        let state = |data: &[u8]| GroupState {
            id: gid.clone(),
            data: data.to_vec().into(),
        };
        let epoch = |id: u64, data: &[u8]| EpochRecord {
            id,
            data: data.to_vec().into(),
        };

        for (n, payload) in [(1u64, &b"s1"[..]), (2, b"s2"), (3, b"s3")] {
            gss.write_inner(state(payload), vec![epoch(n, b"e")], vec![])
                .expect("advancing write must be accepted");
        }
        // Same epoch again (ratchet advanced, epoch unchanged).
        gss.write_inner(state(b"s3-again"), vec![], vec![epoch(3, b"e")])
            .expect("same-epoch write must be accepted");

        let loaded = gss.state(&gid).expect("state").expect("present");
        assert_eq!(loaded.to_vec(), b"s3-again".to_vec());
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

    /// A symlink planted at a database path must not be followed. Handing
    /// `redb` the *path* let it re-resolve what the owner-only pre-create had
    /// already refused, so a link aimed at any file the victim could write was
    /// overwritten with a fresh database; the engine now only ever receives an
    /// already-validated no-follow handle. Covers every `open_db_secure`
    /// caller, the lazily-created `.seen` sidecar included.
    #[cfg(unix)]
    #[test]
    fn db_path_symlink_is_refused_leaving_target_intact() {
        let dir = tempdir().expect("tempdir");
        // Zero length on purpose: redb treats an empty file as "no database
        // yet" and initializes it in place, which is what turns a followed
        // link into the destruction of the target. A non-empty target would be
        // rejected as a corrupt database and hide the defect.
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"").expect("write victim");
        let path = dir.path().join("groups.redb");
        std::os::unix::fs::symlink(&victim, &path).expect("plant symlink");

        RedbBackend::open(&path, &[0x37u8; 32])
            .expect_err("a symlink at the DB path must not be opened");

        assert_eq!(
            std::fs::metadata(&victim).expect("victim still present").len(),
            0,
            "the symlink target must not be written through by the DB open"
        );
        // Refused, not deleted: the link itself is left exactly as planted.
        assert!(
            std::fs::symlink_metadata(&path)
                .expect("link still present")
                .file_type()
                .is_symlink()
        );
    }

    /// The other direction of the no-follow open: refusing links must not cost
    /// the honest case. An existing database re-opens through the handle and
    /// still reads back what a previous session committed.
    #[test]
    fn existing_db_reopens_with_records_intact() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("groups.redb");
        let dek = [0x37u8; 32];
        let state = GroupState {
            id: vec![1, 2, 3, 4],
            data: Zeroizing::new(vec![9u8; 512]),
        };
        {
            let b = RedbBackend::open(&path, &dek).expect("create");
            let mut gs = b.group_state_storage();
            gs.write(state.clone(), vec![], vec![]).expect("write");
        }
        let b = RedbBackend::open(&path, &dek).expect("reopen existing");
        let gs = b.group_state_storage();
        let got = gs.state(&state.id).expect("state").expect("present");
        assert_eq!(&*got, &*state.data);
    }

    /// Deliberate behaviour change, pinned: `dek_opens` and `rotate_group_dek`
    /// now refuse a database carrying a second hard link, which they used to
    /// accept — only `RedbBackend::open` refused it before, and only later, via
    /// `tighten_permissions`. A second name for a secret database is the
    /// aliasing primitive `secure_fs` exists to refuse, and `nlink > 1` taints
    /// *both* names, so a database a hard-linking backup has touched needs the
    /// extra name dropped (or a real copy taken) before it opens again.
    /// Refusal costs nothing: the rotation in particular is turned away before
    /// it rewrites a single record, which the re-probe under the *old* DEK
    /// proves.
    #[cfg(unix)]
    #[test]
    fn hard_linked_db_is_refused_by_every_open_path() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("groups.redb");
        let dek = [0x37u8; 32];
        drop(RedbBackend::open(&path, &dek).expect("create"));
        assert!(RedbBackend::dek_opens(&path, &dek).expect("probe before the link"));

        let alias = dir.path().join("alias.redb");
        std::fs::hard_link(&path, &alias).expect("hard link");

        RedbBackend::dek_opens(&path, &dek).expect_err("dek_opens must refuse nlink > 1");
        RedbBackend::rotate_group_dek(&path, &dek, &[0x38u8; 32])
            .expect_err("rotate_group_dek must refuse nlink > 1");
        RedbBackend::open(&path, &dek).expect_err("open must refuse nlink > 1");

        std::fs::remove_file(&alias).expect("unlink alias");
        assert!(
            RedbBackend::dek_opens(&path, &dek).expect("probe after the link is gone"),
            "the refused rotation must not have re-sealed anything"
        );
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

    /// An inbox whose per-recipient row cap is `max_envelopes`.
    fn inbox_capped(max_envelopes: usize) -> (tempfile::TempDir, RedbInboxStore) {
        let dir = tempdir().expect("tempdir");
        let s = RedbInboxStore::open(
            dir.path().join("inbox.redb"),
            &[0x55u8; 32],
            256,
            max_envelopes,
        )
        .expect("open inbox");
        (dir, s)
    }

    /// Every key in one of the inbox's tables, in order.
    fn keys_of(s: &RedbInboxStore, def: TableDefinition<&[u8], &[u8]>) -> Vec<Vec<u8>> {
        let rtx = s.b.db.begin_read().expect("read txn");
        let t = rtx.open_table(def).expect("open table");
        t.iter()
            .expect("iter")
            .map(|e| e.expect("entry").0.value().to_vec())
            .collect()
    }

    fn meta_of(s: &RedbInboxStore, key: &[u8]) -> Option<u64> {
        let rtx = s.b.db.begin_read().expect("read txn");
        let t = rtx.open_table(TBL_META).expect("open meta");
        meta_read_u64(&t, key).expect("read meta")
    }

    /// What one depositor's ledger says it is holding.
    fn ledger_of(s: &RedbInboxStore, sender: &[u8; 32]) -> u64 {
        meta_of(s, &sender_ledger_key(&s.b.blind_index(sender))).unwrap_or(0)
    }

    /// The ledger recomputed from the rows themselves, via the same
    /// [`EnvTs::cost`] the store charges and refunds with.
    fn recomputed_total(s: &RedbInboxStore) -> u64 {
        let rtx = s.b.db.begin_read().expect("read txn");
        let t = rtx.open_table(TBL_ENV_TS).expect("open ts");
        let mut sum = 0u64;
        for entry in t.iter().expect("iter") {
            let (k, v) = entry.expect("entry");
            let key = k.value().to_vec();
            let pt = s
                .b
                .open_record(TID_ENV_TS, &key, v.value())
                .expect("open index row");
            sum += EnvTs::from_plaintext(&pt).expect("decode").cost();
        }
        sum
    }

    /// Sum of every per-depositor ledger row.
    fn sum_of_sender_ledgers(s: &RedbInboxStore) -> u64 {
        let rtx = s.b.db.begin_read().expect("read txn");
        let t = rtx.open_table(TBL_META).expect("open meta");
        let mut sum = 0u64;
        for entry in t
            .range::<&[u8]>(META_SENDER_PREFIX..META_SENDER_PREFIX_END)
            .expect("range")
        {
            let (_k, v) = entry.expect("entry");
            let raw = v.value();
            let mut b = [0u8; 8];
            b[..8].copy_from_slice(&raw[..8]);
            sum += u64::from_be_bytes(b);
        }
        sum
    }

    /// The byte ledgers agree with the rows, with each other, and with nothing
    /// left over. Called after every interesting transition below.
    fn assert_ledger_exact(s: &RedbInboxStore, label: &str) {
        let total = meta_of(s, META_ENV_BYTES).unwrap_or(0);
        assert_eq!(
            total,
            recomputed_total(s),
            "{label}: the running total must equal the cost of the rows it counts"
        );
        assert_eq!(
            total,
            sum_of_sender_ledgers(s),
            "{label}: the per-depositor ledgers must partition the total"
        );
        assert_eq!(
            keys_of(s, TBL_ENV),
            keys_of(s, TBL_ENV_TS),
            "{label}: the index must hold exactly one row per envelope"
        );
    }

    /// The sealed-size arithmetic `deposit` settles its byte quotas with, before
    /// it encrypts anything, must be exact — the same number is charged to the
    /// ledgers, so an estimate here would be a drift there.
    #[test]
    fn sealed_len_predictor_is_exact() {
        let (_d, b) = backend();
        for n in [0usize, 1, ENV_HEADER_LEN, ENV_TS_PLAIN_LEN, 4096] {
            let sealed = b.seal(TID_APP, b"k", &vec![0x5au8; n]).expect("seal");
            assert_eq!(sealed.len() as u64, sealed_len_for(n), "plaintext len {n}");
        }
        assert_eq!(
            ENV_TS_ROW_BYTES,
            sealed_len_for(ENV_TS_PLAIN_LEN),
            "the index row's cost constant must match its real size"
        );
    }

    /// The F2 fix at the storage layer: a DEPOSIT into a full slot is REFUSED
    /// and removes nothing.
    ///
    /// The old cap made room by deleting this recipient's oldest rows, so any
    /// peer that could name the recipient on the wire — DEPOSIT authenticates
    /// no such field — could flush a queue it did not own, invisibly: POLL only
    /// ever returns ids above the caller's cursor, so the victim never learns
    /// the messages existed.
    #[test]
    fn inbox_full_slot_refuses_and_evicts_nothing() {
        let (_d, s) = inbox_capped(3);
        let victim = [0x11u8; 32];
        let honest = [0x22u8; 32];
        let attacker = [0x33u8; 32];
        for i in 1..=3u8 {
            s.deposit(&victim, &honest, &[i; 8], 1_000).expect("deposit");
        }
        let before = s.poll(&victim, 0, 100).expect("poll");

        let err = s
            .deposit(&victim, &attacker, b"make room for me", 1_100)
            .expect_err("a full slot must refuse");
        assert!(
            matches!(err, RedbStorageError::QuotaExceeded("recipient slot is full")),
            "unexpected error: {err:?}"
        );

        let after = s.poll(&victim, 0, 100).expect("poll");
        assert_eq!(before, after, "a refused deposit must delete nothing");
        assert_eq!(
            after.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
            vec![1, 2, 3],
            "the cursors of stored envelopes must be untouched"
        );
        assert_ledger_exact(&s, "after a refusal");
        // The refusal cost the attacker nothing in the ledger either: refusing
        // happens before the payload is sealed, so no bytes were charged.
        assert_eq!(ledger_of(&s, &attacker), 0);
    }

    /// Reclamation is expiry, not eviction: once the backlog occupying a slot is
    /// older than the TTL, the sweep that runs inside the next deposit's own
    /// transaction frees it, and the deposit that was refused a moment ago is
    /// accepted.
    #[test]
    fn expired_backlog_is_swept_and_the_refused_deposit_then_succeeds() {
        let (_d, s) = inbox_capped(3);
        let rcpt = [0xa7u8; 32];
        let sender = [0xb8u8; 32];
        let t0 = 1_000_000i64;
        for i in 1..=3u8 {
            s.deposit(&rcpt, &sender, &[i; 8], t0).expect("deposit");
        }
        // Not yet expired: still refused, still nothing deleted.
        let err = s
            .deposit(&rcpt, &sender, b"too soon", t0 + 1)
            .expect_err("slot is full");
        assert!(matches!(err, RedbStorageError::QuotaExceeded(_)), "{err:?}");
        assert_eq!(s.poll(&rcpt, 0, 100).expect("poll").len(), 3);
        assert_ledger_exact(&s, "after the early refusal");

        // Past the TTL the same deposit lands, because the sweep reclaimed the
        // backlog first.
        let later = t0 + ENVELOPE_TTL_SECS + 2;
        let id = s.deposit(&rcpt, &sender, b"now there is room", later).expect("deposit");
        let rows = s.poll(&rcpt, 0, 100).expect("poll");
        assert_eq!(
            rows,
            vec![(id, b"now there is room".to_vec())],
            "the expired backlog must be gone and only the new envelope left"
        );
        assert_ledger_exact(&s, "after the sweep");
    }

    /// The same promise when the *global* sweep is nowhere near the victim —
    /// which is the case an attacker can arrange, and the reason the deposit
    /// path sweeps the recipient's own range as well.
    ///
    /// `sweep_expired` walks the whole table from one shared wrapping cursor,
    /// at most `SWEEP_BUDGET_ROWS` rows per rate-gated step, and runs only
    /// inside a DEPOSIT. So a flooder that parks a lot of *unexpired* rows ahead
    /// of the victim in key order keeps that cursor away from the victim's range
    /// for as many sweeps as its junk is long — weeks, if it stores enough,
    /// during which every honest send to the victim burns a one-time prekey for
    /// nothing (`KNOWN_ISSUES.md` item 9). Here the junk is longer than one
    /// whole global sweep, so the global pass provably cannot reach the victim
    /// in this deposit; the deposit must land anyway.
    #[test]
    fn an_expired_slot_is_freed_even_when_the_global_sweep_is_far_away() {
        // 4 rows per slot x 140 junk recipients = 560 rows before the victim's
        // range, more than one global sweep can examine.
        const JUNK_RECIPIENTS: u32 = 140;
        const SLOT: u8 = 4;
        assert!(
            JUNK_RECIPIENTS as usize * SLOT as usize > SWEEP_BUDGET_ROWS,
            "the junk must outlast one whole global sweep or this proves nothing"
        );
        let (_d, s) = inbox_capped(SLOT as usize);
        let id_at = |n: u32| {
            let mut a = [0u8; 32];
            a[..4].copy_from_slice(&n.to_be_bytes());
            a
        };
        // Blind indexes are pseudorandom, so the ordering is chosen by picking
        // ids: a victim near the end of the key space, junk strictly below it.
        let victim = (0u32..100_000)
            .map(id_at)
            .find(|r| s.b.blind_index(r)[0] == 0xff)
            .expect("a recipient near the end of the key space");
        let vbi = s.b.blind_index(&victim);
        let junk: Vec<[u8; 32]> = (0u32..100_000)
            .map(id_at)
            .filter(|r| s.b.blind_index(r) < vbi)
            .take(JUNK_RECIPIENTS as usize)
            .collect();
        assert_eq!(junk.len(), JUNK_RECIPIENTS as usize);

        let flooder = [0xf1u8; 32];
        let honest = [0x0eu8; 32];
        let t0 = 2_000_000i64;

        // The victim's slot is filled at t0...
        for i in 0..SLOT {
            s.deposit(&victim, &flooder, &[i; 8], t0).expect("fill the victim's slot");
        }
        // ...and the junk one second later, so that at `later` below the
        // victim's backlog is expired and every junk row is not.
        for (n, r) in junk.iter().enumerate() {
            for i in 0..SLOT {
                s.deposit(r, &flooder, &[i; 8], t0 + 1)
                    .unwrap_or_else(|e| panic!("junk {n}/{i}: {e}"));
            }
        }
        let junk_rows = JUNK_RECIPIENTS as u64 * SLOT as u64;
        let one = sealed_len_for(ENV_HEADER_LEN + 8) + ENV_TS_ROW_BYTES;

        let later = t0 + ENVELOPE_TTL_SECS + 1;
        let id = s
            .deposit(&victim, &honest, b"deliver", later)
            .expect("an expired slot must accept the next honest deposit");
        assert_eq!(
            s.poll(&victim, 0, 100).expect("poll"),
            vec![(id, b"deliver".to_vec())],
            "the expired backlog must be gone and only the new envelope left"
        );

        // The global sweep did not do this work: its cursor is still inside the
        // junk, below the victim's range, and every junk row is still there.
        let cursor = {
            let rtx = s.b.db.begin_read().expect("read txn");
            let t = rtx.open_table(TBL_META).expect("meta");
            t.get(META_SWEEP_CURSOR)
                .expect("get")
                .map(|g| g.value().to_vec())
                .unwrap_or_default()
        };
        assert!(
            cursor.len() >= BLIND_INDEX_LEN && cursor[..BLIND_INDEX_LEN] < vbi[..],
            "the global cursor must still be short of the victim's range"
        );
        assert_eq!(
            keys_of(&s, TBL_ENV).len() as u64,
            junk_rows + 1,
            "no junk row may be swept — only the victim's own expired backlog"
        );

        // And the refund happened exactly once, through the shared cost.
        assert_ledger_exact(&s, "after the per-recipient sweep");
        assert_eq!(
            meta_of(&s, META_ENV_BYTES).unwrap_or(0),
            junk_rows * one + sealed_len_for(ENV_HEADER_LEN + 7) + ENV_TS_ROW_BYTES,
            "the victim's four rows must be refunded once, and nothing else"
        );
    }

    /// The ledgers stay exact across every transition — deposit, refusal and
    /// sweep — and a depositor's row disappears once it holds nothing.
    #[test]
    fn inbox_byte_ledger_stays_exact() {
        let (_d, s) = inbox_capped(2);
        let rcpt = [0x01u8; 32];
        let a = [0x0au8; 32];
        let b = [0x0bu8; 32];
        let t0 = 500_000i64;

        s.deposit(&rcpt, &a, b"first", t0).expect("dep a1");
        s.deposit(&rcpt, &b, b"second", t0).expect("dep b1");
        assert_ledger_exact(&s, "after two deposits");
        assert_eq!(
            ledger_of(&s, &a),
            sealed_len_for(ENV_HEADER_LEN + 5) + ENV_TS_ROW_BYTES,
            "a depositor is charged its envelope plus the row that indexes it"
        );

        // Slot is full (cap 2) — the refusal charges nobody.
        let total_before = meta_of(&s, META_ENV_BYTES).unwrap_or(0);
        assert!(s.deposit(&rcpt, &a, b"third", t0 + 2).is_err());
        assert_eq!(meta_of(&s, META_ENV_BYTES).unwrap_or(0), total_before);
        assert_ledger_exact(&s, "after a refusal");

        // Expire everything: the sweep gives every byte back and drops the
        // ledger rows of depositors that now hold nothing.
        let later = t0 + ENVELOPE_TTL_SECS + 5;
        let id = s.deposit(&rcpt, &a, b"survivor", later).expect("dep after sweep");
        assert_eq!(s.poll(&rcpt, 0, 10).expect("poll"), vec![(id, b"survivor".to_vec())]);
        assert_ledger_exact(&s, "after the sweep");
        assert_eq!(ledger_of(&s, &b), 0, "b holds nothing and must have no ledger row");
        assert_eq!(
            meta_of(&s, &sender_ledger_key(&s.b.blind_index(&b))),
            None,
            "an empty ledger row must be removed, not left at zero"
        );
        assert_eq!(
            meta_of(&s, META_ENV_BYTES).unwrap_or(0),
            sealed_len_for(ENV_HEADER_LEN + 8) + ENV_TS_ROW_BYTES,
            "only the surviving envelope may still be charged"
        );
    }

    /// The index row and the envelope it indexes share a key but not an AAD
    /// table id, so neither opens in the other's slot. That domain separation
    /// is what lets the sweep trust a row it reads from the cheap table.
    #[test]
    fn env_and_index_rows_cannot_be_opened_as_each_other() {
        let (_d, s) = inbox_capped(4);
        let rcpt = [0xc9u8; 32];
        s.deposit(&rcpt, &rcpt, b"payload", 42).expect("deposit");

        let key = keys_of(&s, TBL_ENV).pop().expect("one envelope");
        assert_eq!(keys_of(&s, TBL_ENV_TS), vec![key.clone()], "same key, two tables");

        let rtx = s.b.db.begin_read().expect("read txn");
        let env_raw = rtx
            .open_table(TBL_ENV)
            .expect("env")
            .get(key.as_slice())
            .expect("get")
            .expect("present")
            .value()
            .to_vec();
        let ts_raw = rtx
            .open_table(TBL_ENV_TS)
            .expect("ts")
            .get(key.as_slice())
            .expect("get")
            .expect("present")
            .value()
            .to_vec();
        drop(rtx);

        // Each opens under its own table id...
        assert!(s.b.open_record(TID_ENVELOPE, &key, &env_raw).is_ok());
        assert!(s.b.open_record(TID_ENV_TS, &key, &ts_raw).is_ok());
        // ...and neither under the other's.
        assert!(
            s.b.open_record(TID_ENV_TS, &key, &env_raw).is_err(),
            "an envelope must not open as an index row"
        );
        assert!(
            s.b.open_record(TID_ENVELOPE, &key, &ts_raw).is_err(),
            "an index row must not open as an envelope"
        );
    }

    /// The byte budget is partitioned by the **handshake-authenticated**
    /// depositor, so one depositor spending its share refuses only its own
    /// deposits — everyone else keeps working, to the same recipient.
    #[test]
    fn per_depositor_byte_quota_isolates_one_depositor() {
        let (_d, s) = inbox_capped(64);
        // Room for many envelopes overall, but only a couple per depositor.
        let one = sealed_len_for(ENV_HEADER_LEN + 8) + ENV_TS_ROW_BYTES;
        let s = s.with_byte_budget(one * 64, one * 64, one * 2, one * 2);
        let rcpt = [0x02u8; 32];
        let hog = [0xf0u8; 32];
        let honest = [0x0fu8; 32];
        let t0 = 900_000i64;

        s.deposit(&rcpt, &hog, b"hog-0001", t0).expect("hog 1");
        s.deposit(&rcpt, &hog, b"hog-0002", t0).expect("hog 2");
        let err = s
            .deposit(&rcpt, &hog, b"hog-0003", t0)
            .expect_err("the hog's share is spent");
        assert!(
            matches!(err, RedbStorageError::QuotaExceeded("per-depositor byte budget")),
            "unexpected error: {err:?}"
        );

        // A different depositor, same recipient, is unaffected.
        s.deposit(&rcpt, &honest, b"mail-001", t0).expect("honest 1");
        s.deposit(&rcpt, &honest, b"mail-002", t0).expect("honest 2");
        assert_eq!(s.poll(&rcpt, 0, 100).expect("poll").len(), 4);
        assert_ledger_exact(&s, "after a per-depositor refusal");
    }

    /// Above the soft limit only the congestion reserve is left, and it is
    /// reachable on a much tighter per-depositor share: an identity that helped
    /// fill the store cannot follow its own bytes into the reserve, while a
    /// depositor holding nothing still gets in.
    ///
    /// **And the reserve is consumable.** The tighter share is exactly what one
    /// fresh identity may take, so each new identity takes a slice and the
    /// reserve runs out after as many of them as it holds slices — four here,
    /// 256 with the production constants. The last assertion is the residual,
    /// not a bound: once the global total is spent, the store refuses *every*
    /// depositor, including one holding nothing. NodeIds are free to mint, so a
    /// fleet can reach that state; see `KNOWN_ISSUES.md` (item 10).
    #[test]
    fn congestion_reserve_admits_a_fresh_depositor_until_a_fleet_consumes_it() {
        let (_d, s) = inbox_capped(64);
        let one = sealed_len_for(ENV_HEADER_LEN + 8) + ENV_TS_ROW_BYTES;
        // Total 8 envelopes; congested past 4; a depositor may hold 4
        // uncongested but only 1 once congested.
        let s = s.with_byte_budget(one * 8, one * 4, one * 4, one);
        let rcpt = [0x03u8; 32];
        let flooder = [0xe1u8; 32];
        let t0 = 800_000i64;

        // The flooder fills the store up to the soft limit.
        for i in 0..4 {
            s.deposit(&rcpt, &flooder, format!("flood-{i:02}").as_bytes(), t0)
                .unwrap_or_else(|e| panic!("flood {i}: {e}"));
        }
        // It cannot follow its own bytes into the reserve.
        let err = s
            .deposit(&rcpt, &flooder, b"flood-04", t0)
            .expect_err("the reserve is not for a depositor already over the line");
        assert!(matches!(err, RedbStorageError::QuotaExceeded(_)), "{err:?}");

        // A depositor holding nothing still gets in — that is the reserve.
        for i in 0..4u8 {
            let fresh = [0x40 + i; 32];
            s.deposit(&rcpt, &fresh, b"honest-1", t0)
                .unwrap_or_else(|e| panic!("light depositor {i}: {e}"));
            // ...but only for its congested share, so the reserve is not one
            // identity's to take either.
            assert!(s.deposit(&rcpt, &fresh, b"honest-2", t0).is_err());
        }

        // Four fresh identities took four slices and the reserve is gone. The
        // fifth is refused on the *global* budget, which is checked before any
        // per-depositor share — so from here every depositor is refused, this
        // one having stored nothing at all. That is the residual the fix
        // accepts, asserted rather than assumed.
        let err = s
            .deposit(&rcpt, &[0x50u8; 32], b"honest-9", t0)
            .expect_err("a spent store refuses a depositor holding nothing");
        assert!(
            matches!(err, RedbStorageError::QuotaExceeded("store byte budget")),
            "unexpected error: {err:?}"
        );
        assert_ledger_exact(&s, "at the byte budget");
    }

    /// Strip a store back to the pre-`TBL_ENV_TS` layout: envelopes and their
    /// cursor counter, no index rows, no ledgers, no schema marker.
    fn make_legacy(s: &RedbInboxStore) {
        let wtx = s.b.db.begin_write().expect("write txn");
        {
            let mut meta = wtx.open_table(TBL_META).expect("meta");
            let mut ts = wtx.open_table(TBL_ENV_TS).expect("ts");
            let keys: Vec<Vec<u8>> = ts
                .iter()
                .expect("iter")
                .map(|e| e.expect("entry").0.value().to_vec())
                .collect();
            for k in keys {
                ts.remove(k.as_slice()).expect("remove");
            }
            let stale: Vec<Vec<u8>> = meta
                .range::<&[u8]>(META_SENDER_PREFIX..META_SENDER_PREFIX_END)
                .expect("range")
                .map(|e| e.expect("entry").0.value().to_vec())
                .collect();
            for k in stale {
                meta.remove(k.as_slice()).expect("remove");
            }
            meta.remove(META_SCHEMA).expect("remove schema");
            meta.remove(META_UPGRADE_CURSOR).expect("remove cursor");
            meta.remove(META_SWEEP_AT).expect("remove sweep mark");
            // What the old code kept here: the sum of sealed envelope bytes.
            let mut sum = 0u64;
            let env = wtx.open_table(TBL_ENV).expect("env");
            for entry in env.iter().expect("iter") {
                sum += entry.expect("entry").1.value().len() as u64;
            }
            meta_write_u64(&mut meta, META_ENV_BYTES, sum).expect("write total");
        }
        wtx.commit().expect("commit");
    }

    /// The upgrade that builds the index for a database written by the previous
    /// version: resumable chunk by chunk, and charging legacy rows at their real
    /// sealed length only.
    ///
    /// Retroactively charging them the new per-row overhead too would push a
    /// store that was exactly healthy under the old cap over the new budget the
    /// moment it opened, and every deposit would be refused until the sweep
    /// caught up — a self-inflicted outage on upgrade.
    #[test]
    fn env_index_upgrade_is_resumable_and_does_not_recharge_legacy_rows() {
        let (_d, s) = inbox_capped(64);
        let rcpt = [0xd1u8; 32];
        let sender = [0xd2u8; 32];
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        for i in 0..5u8 {
            s.deposit(&rcpt, &sender, &[i; 16], now).expect("deposit");
        }
        let sealed_only: u64 = 5 * sealed_len_for(ENV_HEADER_LEN + 16);
        make_legacy(&s);
        assert!(keys_of(&s, TBL_ENV_TS).is_empty(), "legacy stores have no index");

        // Chunk one: partial, and it says so.
        assert!(!s.upgrade_chunk(now, 2).expect("chunk 1"));
        assert_eq!(keys_of(&s, TBL_ENV_TS).len(), 2);
        assert_eq!(meta_of(&s, META_SCHEMA), None, "not finished, not marked");
        assert!(
            meta_of(&s, META_UPGRADE_CURSOR).is_some(),
            "a partial upgrade must leave its resume point"
        );
        assert_eq!(meta_of(&s, META_ENV_BYTES).unwrap_or(0), 2 * sealed_len_for(ENV_HEADER_LEN + 16));

        // Chunk two picks up where it stopped rather than starting over.
        assert!(!s.upgrade_chunk(now, 2).expect("chunk 2"));
        assert_eq!(keys_of(&s, TBL_ENV_TS).len(), 4);

        // Reopening finishes it — the path a crash mid-upgrade actually takes.
        s.upgrade_env_index().expect("resume to completion");
        assert_eq!(keys_of(&s, TBL_ENV), keys_of(&s, TBL_ENV_TS));
        assert_eq!(meta_of(&s, META_SCHEMA), Some(INBOX_SCHEMA_VERSION));
        assert_eq!(meta_of(&s, META_UPGRADE_CURSOR), None);

        // Charged at the envelopes' real sealed length: no row was counted
        // twice, and none was charged the new index overhead.
        assert_eq!(
            meta_of(&s, META_ENV_BYTES).unwrap_or(0),
            sealed_only,
            "legacy rows must be charged exactly what they already occupied"
        );
        assert!(sealed_only < 5 * (sealed_len_for(ENV_HEADER_LEN + 16) + ENV_TS_ROW_BYTES));
        assert_ledger_exact(&s, "after the upgrade");

        // Idempotent: a second run charges nothing further.
        s.upgrade_env_index().expect("second run");
        assert_eq!(meta_of(&s, META_ENV_BYTES).unwrap_or(0), sealed_only);

        // And the refund is the same amount as the charge, so sweeping the
        // upgraded rows returns the ledger to just what is left.
        let later = now + ENVELOPE_TTL_SECS + 10;
        s.deposit(&rcpt, &sender, b"fresh", later).expect("deposit after upgrade");
        assert_eq!(s.poll(&rcpt, 0, 100).expect("poll").len(), 1);
        assert_eq!(
            meta_of(&s, META_ENV_BYTES).unwrap_or(0),
            sealed_len_for(ENV_HEADER_LEN + 5) + ENV_TS_ROW_BYTES
        );
        assert_ledger_exact(&s, "after sweeping upgraded rows");
    }

    /// A store that presents an old schema but *already has* index rows —
    /// corruption, or a partially restored file. The upgrade zeroes the ledgers
    /// before it walks, so a row it skipped would be a row the byte budget had
    /// stopped counting: it must charge what is already there, not only what it
    /// stamps, or such a store comes up with its global cap silently disabled.
    #[test]
    fn upgrade_charges_envelopes_that_are_already_indexed() {
        let (_d, s) = inbox_capped(64);
        let rcpt = [0xe7u8; 32];
        let sender = [0xe8u8; 32];
        let now = 1_700_000_000i64;
        for i in 0..4u8 {
            s.deposit(&rcpt, &sender, &[i; 32], now).expect("deposit");
        }
        let healthy = meta_of(&s, META_ENV_BYTES).unwrap_or(0);
        assert!(healthy > 0, "the ledger must count these deposits");

        // Roll the schema marker back but leave TBL_ENV_TS populated, and leave
        // ledgers that have nothing to do with the rows.
        {
            let wtx = s.b.db.begin_write().expect("write txn");
            {
                let mut meta = wtx.open_table(TBL_META).expect("meta");
                meta.remove(META_SCHEMA).expect("remove schema");
                let stale: Vec<Vec<u8>> = meta
                    .range::<&[u8]>(META_SENDER_PREFIX..META_SENDER_PREFIX_END)
                    .expect("range")
                    .map(|e| e.expect("entry").0.value().to_vec())
                    .collect();
                for k in stale {
                    meta.remove(k.as_slice()).expect("remove");
                }
                meta_write_u64(&mut meta, META_ENV_BYTES, 0).expect("zero the total");
            }
            wtx.commit().expect("commit");
        }
        assert_eq!(
            keys_of(&s, TBL_ENV),
            keys_of(&s, TBL_ENV_TS),
            "this store's index rows survive the rollback"
        );

        s.upgrade_env_index().expect("upgrade");

        // Rebuilt from the rows that were there, each at its own recorded cost
        // and against its own depositor.
        assert_eq!(
            meta_of(&s, META_ENV_BYTES).unwrap_or(0),
            healthy,
            "an already-indexed envelope must still be charged"
        );
        assert_ledger_exact(&s, "after upgrading a store that kept its index rows");
        assert_eq!(meta_of(&s, META_SCHEMA), Some(INBOX_SCHEMA_VERSION));
    }

    /// A store opened by this version is already at the current schema, so the
    /// upgrade never runs for it and the deposit path is not paying for a scan
    /// on every open.
    #[test]
    fn a_fresh_inbox_is_marked_current_on_open() {
        let (_d, s) = inbox_capped(4);
        assert_eq!(meta_of(&s, META_SCHEMA), Some(INBOX_SCHEMA_VERSION));
        assert_eq!(meta_of(&s, META_UPGRADE_CURSOR), None);
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

    /// Sorted table names of a redb file, opened raw (no store handle, so the
    /// caller must have dropped it — redb holds the file lock for a `Database`).
    fn table_names(path: &Path) -> Vec<String> {
        use redb::TableHandle;
        let db = Database::open(path).expect("raw open");
        let rtx = db.begin_read().expect("read txn");
        let mut names: Vec<String> = rtx
            .list_tables()
            .expect("list tables")
            .map(|t| t.name().to_string())
            .collect();
        names.sort();
        names
    }

    /// The static-only replay cache must NOT live in the prekey database.
    /// Two reasons, both load-bearing: [`RedbPrekeyStore::delete`] compacts
    /// that file — rewriting every page of every table — after every consumed
    /// one-time prekey, so a table an unauthenticated depositor grows without
    /// bound would tax the forward-secrecy path forever; and the same file
    /// holds the long-term static X-Wing identity, which must not have to be
    /// destroyed to reclaim cache space.
    ///
    /// Asserts both halves: the prekey DB's table set is exactly the set it
    /// had before the cache existed, and the cache is a `.seen` sidecar that
    /// is created lazily and actually gates.
    #[test]
    fn replay_cache_lives_in_a_sidecar_db_not_the_prekey_db() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("prekeys.redb");
        let seen_path = RedbPrekeyStore::seen_db_path(&path);
        let store = RedbPrekeyStore::open(&path, &[0x21u8; 32]).expect("open");

        // Lazy: a recipient that never receives a downgraded envelope never
        // creates the file.
        assert!(!seen_path.exists(), "sidecar must not exist before first use");

        assert!(!store.record_static_only_seen(b"tag-a").expect("first a"));
        assert!(store.record_static_only_seen(b"tag-a").expect("replay a"));
        assert!(!store.record_static_only_seen(b"tag-b").expect("first b"));
        assert!(seen_path.exists(), "sidecar must exist once the gate is used");

        drop(store);
        assert_eq!(
            table_names(&path),
            vec!["dek_sentinel", "pk_meta", "pk_onetime", "pk_static"],
            "the prekey DB must carry prekey material only — no replay cache \
             riding along in delete()'s compaction, and none to strand the \
             static identity"
        );
        assert_eq!(table_names(&seen_path), vec!["pk_seen"]);

        // Durable across a reopen: the DS can simply wait before replaying.
        let store = RedbPrekeyStore::open(&path, &[0x21u8; 32]).expect("reopen");
        assert!(store.record_static_only_seen(b"tag-a").expect("replay after reopen"));
        assert!(!store.record_static_only_seen(b"tag-c").expect("first c"));
    }

    /// A `prekeys.db` written by the unreleased intermediate revision has an
    /// inline `pk_seen` table. Opening it must not break, and must drop the
    /// dead table so it stops being rewritten by `delete`'s compaction. Its
    /// rows are deliberately not migrated (see [`RedbPrekeyStore::open`]).
    #[test]
    fn inline_pk_seen_from_the_intermediate_layout_is_dropped_on_open() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("prekeys.redb");
        RedbPrekeyStore::open(&path, &[0x22u8; 32]).expect("open");
        {
            // Reconstruct the intermediate layout by hand.
            let db = Database::create(&path).expect("raw open");
            let wtx = db.begin_write().expect("write txn");
            {
                let mut t = wtx.open_table(TBL_PK_SEEN).expect("create pk_seen");
                t.insert(b"stale".as_slice(), [].as_slice()).expect("insert");
            }
            wtx.commit().expect("commit");
            drop(db); // redb holds the file lock for the life of the handle
            assert!(table_names(&path).contains(&"pk_seen".to_string()));
        }

        let store = RedbPrekeyStore::open(&path, &[0x22u8; 32]).expect("open intermediate file");
        // Still fully functional, and now gating through the sidecar.
        assert!(!store.record_static_only_seen(b"tag").expect("record"));
        assert!(store.record_static_only_seen(b"tag").expect("replay"));
        drop(store);
        assert_eq!(
            table_names(&path),
            vec!["dek_sentinel", "pk_meta", "pk_onetime", "pk_static"],
            "the dead inline pk_seen table must be dropped on open"
        );
        assert_eq!(table_names(&RedbPrekeyStore::seen_db_path(&path)), vec!["pk_seen"]);
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
