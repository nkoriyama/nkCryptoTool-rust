//! Persistent storage for MLS group state (P2).
//!
//! Wraps `mls-rs-provider-sqlite`'s `SqLiteDataStorageEngine` with a
//! custom [`ConnectionStrategy`] that applies the PRAGMAs we want on
//! every freshly opened connection:
//!
//! - `PRAGMA busy_timeout = 5000` — wait up to 5 s when another writer
//!   holds the lock instead of failing with `database is locked`.
//! - `PRAGMA synchronous = NORMAL` — documented safe-with-WAL setting
//!   that skips per-transaction fsync but keeps integrity across crashes.
//!
//! Additionally, file-backed databases are opened in WAL journal mode
//! via the engine's own `with_journal_mode` setter — WAL is a database-
//! level setting that persists, but applying it on every connection is
//! idempotent so we set it eagerly.
//!
//! File-mode `0o600` is enforced after creation. SQLCipher (at-rest
//! encryption) is intentionally **not** used in this revision —
//! protection comes from filesystem permissions and the passphrase-
//! wrapped signing key. The `mls-rs-provider-sqlite` `sqlcipher-bundled`
//! feature remains available for a future upgrade.
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

use crate::group::types::{GroupError, GroupId};

/// Connection strategy that opens a file-backed sqlite database and
/// applies our tuned PRAGMAs on every connection.
///
/// Cloneable so [`GroupStorage`] can both hand the strategy to the
/// underlying engine (which consumes it) *and* keep its own copy for
/// our custom queries (`list_group_ids`).
#[derive(Clone, Debug)]
pub struct TunedFileStrategy {
    path: PathBuf,
}

impl TunedFileStrategy {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl ConnectionStrategy for TunedFileStrategy {
    fn make_connection(&self) -> Result<Connection, SqLiteDataStorageError> {
        let conn = Connection::open(&self.path)
            .map_err(|e| SqLiteDataStorageError::SqlEngineError(e.into()))?;
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
/// packages, and pre-shared keys all live in a single sqlite file under
/// `path`.
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
    /// Open (or create) the sqlite database at `path`.
    ///
    /// On first open, the schema is created lazily by `mls-rs-provider-sqlite`
    /// the first time any storage component is requested. We
    /// pro-actively trigger that by asking for the group state storage
    /// once during construction so subsequent `list_group_ids` calls
    /// don't fail on a missing `mls_group` table.
    ///
    /// File permissions are tightened to `0o600` on Unix after the file
    /// is created.
    pub fn open_at(path: impl AsRef<Path>) -> Result<Self, GroupError> {
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

        let strategy = TunedFileStrategy::new(&path);
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
        let _ = me.group_state_storage()?;

        me.tighten_permissions()?;
        Ok(me)
    }

    /// Apply `0o600` mode to the sqlite file on Unix. On other
    /// platforms this is a no-op — callers are expected to rely on
    /// the OS keystore for at-rest protection there.
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn open_creates_file_with_tight_permissions() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("groups.db");
        let _storage = GroupStorage::open_at(&path).expect("open");
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
        let storage = GroupStorage::open_at(dir.path().join("groups.db")).expect("open");
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
        drop(GroupStorage::open_at(&path).expect("first open"));
        let storage = GroupStorage::open_at(&path).expect("second open");
        assert!(storage.list_group_ids().expect("list").is_empty());
    }
}
