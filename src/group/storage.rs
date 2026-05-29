//! Persistent storage for MLS group state (P2).
//!
//! Wraps `mls-rs-provider-sqlite`'s `SqLiteDataStorageEngine` with a
//! custom [`ConnectionStrategy`] that:
//!
//! 1. Configures SQLCipher 4 at-rest encryption via `PRAGMA key = 'X'`
//!    on every freshly opened connection. SQLCipher derives the page
//!    key from the passphrase with PBKDF2-HMAC-SHA512 (256 000 iters
//!    by default) and encrypts each page with AES-256-CBC + HMAC-SHA512.
//! 2. Applies `PRAGMA busy_timeout = 5000` — wait up to 5 s when another
//!    writer holds the lock instead of failing with `database is locked`.
//! 3. Applies `PRAGMA synchronous = NORMAL` — documented safe-with-WAL
//!    setting that skips per-transaction fsync but keeps integrity
//!    across crashes.
//!
//! Additionally, file-backed databases are opened in WAL journal mode
//! via the engine's own `with_journal_mode` setter — WAL is a database-
//! level setting that persists, but applying it on every connection is
//! idempotent so we set it eagerly.
//!
//! At-rest protection therefore has two layers:
//!
//! - **SQLCipher**: encrypts every page (group trees, signing keys,
//!   key packages, PSKs, application_data kvs) so a stolen DB file is
//!   useless without the passphrase.
//! - **File mode `0o600`**: defence in depth — even if the SQLCipher
//!   passphrase is weak, the OS prevents other local users from
//!   reading the ciphertext.
//!
//! See SECURITY_PROFILE.md §7.3 for the threat model.
//!
//! ## Scope
//!
//! This module exposes only what `MLS_GROUP_CHAT_PLAN.md` §P2 calls
//! for: group state, key package, and PSK storage, plus a custom
//! `list_group_ids` helper. Application-level metadata (group name,
//! created_at) is deferred — `mls-rs` itself records enough to
//! reconstruct an MLS group fully, and the app-side display name
//! lives in CLI/GUI memory only until P3 wires up the invite UX.

use std::path::{Path, PathBuf};
use std::time::Duration;

use mls_rs_provider_sqlite::connection_strategy::ConnectionStrategy;
use mls_rs_provider_sqlite::storage::{
    SqLiteApplicationStorage, SqLiteGroupStateStorage, SqLiteKeyPackageStorage,
    SqLitePreSharedKeyStorage,
};
use mls_rs_provider_sqlite::{
    JournalMode, SqLiteDataStorageEngine, SqLiteDataStorageError,
};
use rusqlite::Connection;
use zeroize::Zeroizing;

use crate::group::types::{GroupError, GroupId};

/// How the SQLCipher page key is delivered to the database.
///
/// Two modes are supported:
///
/// - [`Passphrase`](SqlcipherKey::Passphrase) — SQLCipher derives the
///   page key with PBKDF2-HMAC-SHA512 (256 000 iters) internally. Used
///   by tests and as a fall-back path when the at-rest PQC key-wrap
///   layer is not wired up.
/// - [`RawHex32`](SqlcipherKey::RawHex32) — caller supplies a 32-byte
///   key directly as lowercase hex; SQLCipher uses it as the page key
///   without further derivation. This is the path the PQC at-rest layer
///   takes: the DEK is a fresh random 256-bit value protected by the
///   hybrid X25519+ML-KEM-768 KEK file. See `at_rest.rs`.
#[derive(Clone)]
enum SqlcipherKey {
    Passphrase(Zeroizing<String>),
    /// 64 lowercase hex digits. Constructor validates the length and
    /// alphabet so [`TunedFileStrategy::make_connection`] can interpolate
    /// directly without further escaping.
    RawHex32(Zeroizing<String>),
}

/// Connection strategy that opens a file-backed sqlite database with
/// SQLCipher at-rest encryption and applies our tuned PRAGMAs on every
/// connection.
///
/// Cloneable so [`GroupStorage`] can both hand the strategy to the
/// underlying engine (which consumes it) *and* keep its own copy for
/// our custom queries (`list_group_ids`). The cloned key material is
/// still `Zeroizing` so each clone clears its buffer on drop.
#[derive(Clone)]
pub struct TunedFileStrategy {
    path: PathBuf,
    key: SqlcipherKey,
}

impl std::fmt::Debug for TunedFileStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material — even into a Debug formatter that
        // might end up in a panic message or log line.
        f.debug_struct("TunedFileStrategy")
            .field("path", &self.path)
            .field("key", &"<redacted>")
            .finish()
    }
}

impl TunedFileStrategy {
    /// Construct a strategy that hands `passphrase` to SQLCipher as a
    /// text key. SQLCipher will derive the page key internally via
    /// PBKDF2-HMAC-SHA512.
    pub fn new(path: impl Into<PathBuf>, passphrase: Zeroizing<String>) -> Self {
        Self {
            path: path.into(),
            key: SqlcipherKey::Passphrase(passphrase),
        }
    }

    /// Construct a strategy that hands `dek` to SQLCipher as a raw
    /// 256-bit key. SQLCipher skips PBKDF2 and uses the bytes directly.
    pub fn new_with_raw_key(path: impl Into<PathBuf>, dek: &[u8; 32]) -> Self {
        // Pre-format as lowercase hex; validated alphabet means the
        // string is safe to splice into the PRAGMA statement.
        let hex = Zeroizing::new(hex::encode(dek));
        Self {
            path: path.into(),
            key: SqlcipherKey::RawHex32(hex),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl ConnectionStrategy for TunedFileStrategy {
    fn make_connection(&self) -> Result<Connection, SqLiteDataStorageError> {
        let conn = Connection::open(&self.path)
            .map_err(|e| SqLiteDataStorageError::SqlEngineError(e.into()))?;
        // SQLCipher: `PRAGMA key` MUST be the first statement executed
        // against the connection — it unlocks the database for all
        // subsequent queries.
        match &self.key {
            SqlcipherKey::Passphrase(p) => {
                // rusqlite's `pragma_update` handles single-quote
                // escaping inside the passphrase string.
                conn.pragma_update(None, "key", p.as_str())
                    .map_err(|e| SqLiteDataStorageError::SqlEngineError(e.into()))?;
            }
            SqlcipherKey::RawHex32(hex) => {
                // 64 lowercase ASCII hex digits (enforced by the
                // constructor). Safe to interpolate. SQLCipher reads
                // `PRAGMA key = "x'<hex>'"` as a raw 256-bit key and
                // skips PBKDF2 — exactly what we want when the key has
                // already been derived via the PQC at-rest layer.
                debug_assert_eq!(hex.len(), 64);
                debug_assert!(hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
                let stmt = format!("PRAGMA key = \"x'{}'\";", hex.as_str());
                conn.execute_batch(&stmt)
                    .map_err(|e| SqLiteDataStorageError::SqlEngineError(e.into()))?;
            }
        }
        // PRAGMA busy_timeout: how long sqlite should sleep-retry when
        // another writer holds the lock. 5 s is enough for the busiest
        // add_member / commit_builder paths even on contended disks.
        conn.busy_timeout(Duration::from_millis(5_000))
            .map_err(|e| SqLiteDataStorageError::SqlEngineError(e.into()))?;
        // PRAGMA synchronous = NORMAL: safe pairing with WAL. Skips
        // per-transaction fsync but maintains DB integrity across power
        // loss (only the most recent committed txn may be lost).
        conn.pragma_update(None, "synchronous", "NORMAL")
            .map_err(|e| SqLiteDataStorageError::SqlEngineError(e.into()))?;
        Ok(conn)
    }
}

/// File-backed sqlite storage for an MLS client.
///
/// Constructed once per `GroupChatProcessor` and held for its lifetime.
/// Internally backed by `mls-rs-provider-sqlite` — group state, key
/// packages, PSKs, and application_data kvs all live in a single
/// SQLCipher-encrypted sqlite file under `path`.
pub struct GroupStorage {
    engine: SqLiteDataStorageEngine<TunedFileStrategy>,
    /// Independent strategy retained so [`list_group_ids`] can open a
    /// fresh connection without piercing the engine's encapsulation.
    /// The engine's own field is private and has no accessor.
    ///
    /// [`list_group_ids`]: GroupStorage::list_group_ids
    strategy: TunedFileStrategy,
    path: PathBuf,
}

impl GroupStorage {
    /// Open (or create) the SQLCipher-encrypted sqlite database at `path`.
    ///
    /// `passphrase` is used to derive the SQLCipher page key. An empty
    /// string is rejected — the project policy requires at-rest
    /// encryption (see SECURITY_PROFILE.md §7.3). For interactive use,
    /// pass [`crate::utils::get_masked_passphrase`]; for tests, pass a
    /// fixed non-empty string.
    ///
    /// On first open, the schema is created lazily by
    /// `mls-rs-provider-sqlite` the first time any storage component is
    /// requested. We pro-actively trigger that by asking for the group
    /// state storage once during construction so subsequent
    /// `list_group_ids` calls don't fail on a missing `mls_group` table.
    /// This first query is also what proves the passphrase is correct:
    /// SQLCipher returns `SQLITE_NOTADB` (mapped to a Storage error) on
    /// any subsequent query if the key is wrong, since the page header
    /// MAC doesn't validate.
    ///
    /// File permissions are tightened to `0o600` on Unix after the file
    /// is created.
    pub fn open_at(
        path: impl AsRef<Path>,
        passphrase: Zeroizing<String>,
    ) -> Result<Self, GroupError> {
        if passphrase.is_empty() {
            return Err(GroupError::Storage(
                "SQLCipher passphrase must not be empty — set NK_PASSPHRASE or enter one interactively".to_string(),
            ));
        }
        let path = path.as_ref().to_owned();
        if let Some(parent) = path.parent() {
            // Empty parent (relative path with single component) means
            // "current directory", which already exists.
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    GroupError::Storage(format!("create_dir_all {parent:?}: {e}"))
                })?;
            }
        }

        let strategy = TunedFileStrategy::new(&path, passphrase);
        Self::open_with_strategy(strategy, path)
    }

    /// Open (or create) the SQLCipher-encrypted sqlite database at `path`
    /// using a pre-derived 256-bit key. This is the path the PQC at-rest
    /// key-wrap layer takes — see `at_rest.rs`. SQLCipher skips its own
    /// PBKDF2 and uses `dek` directly as the page key.
    ///
    /// `dek` is consumed via reference and immediately formatted into a
    /// `Zeroizing<String>` (hex) held by the strategy. The caller is
    /// expected to manage its own copy of `dek` (likely
    /// `Zeroizing<[u8; 32]>`).
    pub fn open_at_with_raw_key(
        path: impl AsRef<Path>,
        dek: &[u8; 32],
    ) -> Result<Self, GroupError> {
        let path = path.as_ref().to_owned();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    GroupError::Storage(format!("create_dir_all {parent:?}: {e}"))
                })?;
            }
        }
        let strategy = TunedFileStrategy::new_with_raw_key(&path, dek);
        Self::open_with_strategy(strategy, path)
    }

    /// Shared finishing path for both [`open_at`] and
    /// [`open_at_with_raw_key`].
    fn open_with_strategy(
        strategy: TunedFileStrategy,
        path: PathBuf,
    ) -> Result<Self, GroupError> {
        let engine = SqLiteDataStorageEngine::new(strategy.clone())
            .map_err(|e| GroupError::Storage(format!("engine init: {e}")))?
            .with_journal_mode(Some(JournalMode::Wal));

        let me = Self {
            engine,
            strategy,
            path,
        };

        // Force schema creation now (engine's `create_tables_v1` runs
        // inside `create_connection`, which is invoked by any storage
        // accessor). Drop the result; we just want the side effect.
        // This also proves the SQLCipher key is correct: a wrong key
        // surfaces as an `SqlEngineError` from the first real query.
        let _ = me.group_state_storage()?;

        me.tighten_permissions()?;
        Ok(me)
    }

    /// Apply `0o600` mode to the sqlite file on Unix. On other
    /// platforms this is a no-op — SQLCipher remains the primary
    /// at-rest boundary there.
    fn tighten_permissions(&self) -> Result<(), GroupError> {
        #[cfg(unix)]
        if self.path.exists() {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&self.path)
                .map_err(|e| GroupError::Storage(format!("metadata {:?}: {e}", self.path)))?
                .permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&self.path, perms)
                .map_err(|e| GroupError::Storage(format!("chmod {:?}: {e}", self.path)))?;
        }
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn group_state_storage(&self) -> Result<SqLiteGroupStateStorage, GroupError> {
        self.engine
            .group_state_storage()
            .map_err(|e| GroupError::Storage(format!("group_state_storage: {e}")))
    }

    pub fn key_package_storage(&self) -> Result<SqLiteKeyPackageStorage, GroupError> {
        self.engine
            .key_package_storage()
            .map_err(|e| GroupError::Storage(format!("key_package_storage: {e}")))
    }

    pub fn pre_shared_key_storage(&self) -> Result<SqLitePreSharedKeyStorage, GroupError> {
        self.engine
            .pre_shared_key_storage()
            .map_err(|e| GroupError::Storage(format!("pre_shared_key_storage: {e}")))
    }

    /// Application-data kv table — used by [`GroupChatProcessor`] for
    /// the persistent signing identity (`mls:identity:sk` /
    /// `mls:identity:pk`). Exposed publicly so future revisions can
    /// hang their own metadata (display name, address book, etc.) off
    /// the same connection.
    pub fn application_data_storage(&self) -> Result<SqLiteApplicationStorage, GroupError> {
        self.engine
            .application_data_storage()
            .map_err(|e| GroupError::Storage(format!("application_data_storage: {e}")))
    }

    /// List the IDs of all groups whose state is stored in this
    /// database. Reads the `mls_group` table directly — this depends
    /// on `mls-rs-provider-sqlite`'s schema (`group_id BLOB PRIMARY
    /// KEY`). If the upstream provider changes the schema in a future
    /// major version, this query must be re-checked.
    ///
    /// Group IDs in this codebase are always 32 bytes (newly created
    /// groups use a 32-byte random group_id per MLS convention); rows
    /// with other lengths are rejected with a `Storage` error so the
    /// caller can investigate corruption rather than silently truncate.
    pub fn list_group_ids(&self) -> Result<Vec<GroupId>, GroupError> {
        let conn = self
            .strategy
            .make_connection()
            .map_err(|e| GroupError::Storage(format!("list_group_ids connect: {e}")))?;
        let mut stmt = conn
            .prepare("SELECT group_id FROM mls_group")
            .map_err(|e| GroupError::Storage(format!("list_group_ids prepare: {e}")))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .map_err(|e| GroupError::Storage(format!("list_group_ids query: {e}")))?;
        let mut out = Vec::new();
        for row in rows {
            let bytes =
                row.map_err(|e| GroupError::Storage(format!("list_group_ids row: {e}")))?;
            if bytes.len() != 32 {
                return Err(GroupError::Storage(format!(
                    "stored group_id has length {} (expected 32)",
                    bytes.len()
                )));
            }
            let mut id = [0u8; 32];
            id.copy_from_slice(&bytes);
            out.push(GroupId::new(id));
        }
        Ok(out)
    }
}

impl std::fmt::Debug for GroupStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Engine doesn't impl Debug; print just the user-visible state.
        f.debug_struct("GroupStorage")
            .field("path", &self.path)
            .finish()
    }
}

/// Fixed SQLCipher passphrase used by every test in the `group` module.
/// Not a secret — sharing one value across tests lets us round-trip a
/// DB file (open, drop, reopen) without orchestrating a per-test key.
#[cfg(test)]
pub(crate) fn test_passphrase() -> Zeroizing<String> {
    Zeroizing::new("nkct-test-passphrase".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_pass() -> Zeroizing<String> {
        test_passphrase()
    }

    #[test]
    fn open_creates_file_with_tight_permissions() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("groups.db");
        let _storage = GroupStorage::open_at(&path, test_pass()).expect("open");
        assert!(path.exists(), "sqlite file should be created on open");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(&path).expect("metadata");
            // Lower 9 bits hold the rwx octets. We want exactly 0o600
            // (read/write owner only).
            assert_eq!(
                meta.permissions().mode() & 0o777,
                0o600,
                "sqlite file should be 0o600"
            );
        }
    }

    #[test]
    fn list_group_ids_empty_on_fresh_db() {
        let dir = tempdir().expect("tempdir");
        let storage =
            GroupStorage::open_at(dir.path().join("groups.db"), test_pass()).expect("open");
        let ids = storage.list_group_ids().expect("list");
        assert!(
            ids.is_empty(),
            "fresh database should have no groups, got {ids:?}"
        );
    }

    #[test]
    fn reopen_same_path_preserves_schema() {
        // Round-tripping the *schema* (no group data yet) confirms our
        // PRAGMA wiring doesn't reject the file on reopen. The full
        // create→drop→reload group test lives in `processor::tests`.
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("groups.db");
        drop(GroupStorage::open_at(&path, test_pass()).expect("first open"));
        let storage = GroupStorage::open_at(&path, test_pass()).expect("second open");
        assert!(storage.list_group_ids().expect("list").is_empty());
    }

    #[test]
    fn empty_passphrase_is_rejected() {
        // SQLCipher would silently treat an empty passphrase as
        // "no encryption", which violates the at-rest invariant. We
        // catch that at the API boundary instead of trusting the user.
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("groups.db");
        let err = GroupStorage::open_at(&path, Zeroizing::new(String::new()))
            .expect_err("empty passphrase must be rejected");
        match err {
            GroupError::Storage(msg) => {
                assert!(
                    msg.contains("passphrase"),
                    "error should mention passphrase, got: {msg}"
                );
            }
            other => panic!("expected Storage error, got {other:?}"),
        }
    }

    #[test]
    fn open_with_raw_key_roundtrips() {
        // The raw-key path is what the PQC at-rest layer drives. Confirm
        // that a DB written under a 32-byte raw key can be reopened with
        // the same key, and that the schema initialisation succeeds.
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("groups.db");
        let dek = [0x42u8; 32];
        drop(GroupStorage::open_at_with_raw_key(&path, &dek).expect("first open"));
        let storage =
            GroupStorage::open_at_with_raw_key(&path, &dek).expect("second open");
        assert!(storage.list_group_ids().expect("list").is_empty());
    }

    #[test]
    fn raw_key_and_passphrase_are_distinct_credentials() {
        // A DB initialised with a raw key cannot be reopened with that
        // same byte sequence as a passphrase (and vice versa). This is
        // the SQLCipher contract: `PRAGMA key = "x'…'"` and
        // `PRAGMA key = '…'` derive different page keys.
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("groups.db");
        let dek = [0xABu8; 32];
        drop(GroupStorage::open_at_with_raw_key(&path, &dek).expect("init"));

        // Reopening via passphrase mode with the hex string would yield a
        // different page key, so first query fails.
        let hex_pass = Zeroizing::new(hex::encode(dek));
        let err = GroupStorage::open_at(&path, hex_pass)
            .expect_err("passphrase mode must not unlock a raw-key DB");
        assert!(matches!(err, GroupError::Storage(_)));
    }

    #[test]
    fn wrong_passphrase_fails_to_open() {
        // Create a DB with one passphrase, then try to reopen with a
        // different one. SQLCipher rejects the second open at the first
        // real query (schema initialisation) with SQLITE_NOTADB.
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("groups.db");
        drop(
            GroupStorage::open_at(&path, Zeroizing::new("right".to_string()))
                .expect("first open"),
        );
        let err = GroupStorage::open_at(&path, Zeroizing::new("wrong".to_string()))
            .expect_err("wrong passphrase must fail");
        assert!(
            matches!(err, GroupError::Storage(_)),
            "expected Storage error, got {err:?}"
        );
    }
}
