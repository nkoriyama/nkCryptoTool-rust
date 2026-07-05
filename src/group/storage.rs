//! Persistent storage for MLS group state — pure-Rust redb backend.
//!
//! Thin wrapper over [`crate::group::redb_storage::RedbBackend`] that keeps the
//! public surface the rest of the group stack expects (`open_at`,
//! `open_at_with_raw_key`, the three mls-rs storage accessors,
//! `application_data_storage`, and `list_group_ids`).
//!
//! At-rest protection has two layers:
//!
//! - **Application-layer AEAD**: every stored value is sealed with
//!   XChaCha20-Poly1305 under a key derived from the 256-bit DEK (which the PQC
//!   at-rest key-wrap layer in [`crate::group::at_rest`] protects). A DEK
//!   sentinel makes a wrong DEK fail fast on open. See `redb_storage`.
//! - **File mode `0o600`** (Unix): defence in depth, applied by `RedbBackend`.
//!
//! The previous SQLCipher backend is gone; its libcrypto dependency blocked
//! mobile cross-compilation (see `DB_PURERUST_DESIGN.md`). The one-time reader
//! for legacy SQLCipher databases lives behind the
//! `legacy-sqlcipher-migration` feature (P3 migration tool).

use std::path::{Path, PathBuf};

use sha2::Sha256;
use zeroize::Zeroizing;

use crate::group::redb_storage::{
    RedbApplicationStorage, RedbBackend, RedbGroupStateStorage, RedbKeyPackageStorage,
    RedbPreSharedKeyStorage,
};
use crate::group::types::{GroupError, GroupId};

/// File-backed redb storage for an MLS client.
///
/// Constructed once per `GroupChatProcessor` and held for its lifetime. Group
/// state, key packages, PSKs, and application-data KVs all live in a single
/// encrypted redb file under `path`.
pub struct GroupStorage {
    backend: RedbBackend,
    path: PathBuf,
}

impl GroupStorage {
    /// Open (or create) the encrypted redb database at `path`, deriving the
    /// value key from `passphrase`.
    ///
    /// This is a convenience entry point used by tests and any caller that
    /// holds only a passphrase. Production opens via
    /// [`crate::group::at_rest::open_at_rest_storage`], which recovers a random
    /// 256-bit DEK through the PQC at-rest key hierarchy and calls
    /// [`Self::open_at_with_raw_key`]. An empty passphrase is rejected.
    pub fn open_at(
        path: impl AsRef<Path>,
        passphrase: Zeroizing<String>,
    ) -> Result<Self, GroupError> {
        if passphrase.is_empty() {
            return Err(GroupError::Storage(
                "passphrase must not be empty — set NK_PASSPHRASE or enter one interactively"
                    .to_string(),
            ));
        }
        let dek = passphrase_to_dek(&passphrase);
        Self::open_at_with_raw_key(path, &dek)
    }

    /// Open (or create) the encrypted redb database at `path` using a
    /// pre-derived 256-bit key. This is the path the PQC at-rest key-wrap layer
    /// takes — see `at_rest.rs`.
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
        let backend = RedbBackend::open(&path, dek)
            .map_err(|e| GroupError::Storage(format!("open redb: {e}")))?;
        Ok(Self { backend, path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn group_state_storage(&self) -> Result<RedbGroupStateStorage, GroupError> {
        Ok(self.backend.group_state_storage())
    }

    pub fn key_package_storage(&self) -> Result<RedbKeyPackageStorage, GroupError> {
        Ok(self.backend.key_package_storage())
    }

    pub fn pre_shared_key_storage(&self) -> Result<RedbPreSharedKeyStorage, GroupError> {
        Ok(self.backend.pre_shared_key_storage())
    }

    /// Application-data KV — used by [`crate::group::processor::GroupChatProcessor`]
    /// for the persistent signing identity (`mls:identity:sk` / `:pk`).
    pub fn application_data_storage(&self) -> Result<RedbApplicationStorage, GroupError> {
        Ok(self.backend.application_data_storage())
    }

    /// List the IDs of all groups whose state is stored in this database.
    ///
    /// Group IDs in this codebase are always 32 bytes (newly created groups use
    /// a 32-byte random group_id per MLS convention); rows with other lengths
    /// are rejected with a `Storage` error so the caller can investigate
    /// corruption rather than silently truncate.
    pub fn list_group_ids(&self) -> Result<Vec<GroupId>, GroupError> {
        let raw = self
            .backend
            .group_state_storage()
            .list_group_ids()
            .map_err(|e| GroupError::Storage(format!("list_group_ids: {e}")))?;
        let mut out = Vec::with_capacity(raw.len());
        for bytes in raw {
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

    pub fn store_commit(
        &self,
        group_id: &[u8],
        epoch: u64,
        commit_bytes: &[u8],
    ) -> Result<(), GroupError> {
        self.backend
            .store_commit(group_id, epoch, commit_bytes)
            .map_err(|e| GroupError::Storage(format!("store_commit: {e}")))
    }

    pub fn load_commits(
        &self,
        group_id: &[u8],
        from_epoch_exclusive: u64,
        to_epoch_inclusive: u64,
    ) -> Result<Vec<(u64, Zeroizing<Vec<u8>>)>, GroupError> {
        self.backend
            .load_commits(group_id, from_epoch_exclusive, to_epoch_inclusive)
            .map_err(|e| GroupError::Storage(format!("load_commits: {e}")))
    }

    pub fn oldest_retained_epoch(&self, group_id: &[u8]) -> Result<Option<u64>, GroupError> {
        self.backend
            .oldest_retained_epoch(group_id)
            .map_err(|e| GroupError::Storage(format!("oldest_retained_epoch: {e}")))
    }

    pub fn prune_commits(&self, group_id: &[u8], keep: u64) -> Result<u64, GroupError> {
        self.backend
            .prune_commits(group_id, keep)
            .map_err(|e| GroupError::Storage(format!("prune_commits: {e}")))
    }

    /// Remember a member's delivery hint (ticket string) for `group_id`, keyed
    /// by its transport node id. See [`RedbBackend::put_member_addr`].
    pub fn put_member_addr(
        &self,
        group_id: &[u8],
        node_id: &[u8; 32],
        ticket: &str,
    ) -> Result<(), GroupError> {
        self.backend
            .put_member_addr(group_id, node_id, ticket)
            .map_err(|e| GroupError::Storage(format!("put_member_addr: {e}")))
    }

    /// List remembered member delivery hints (ticket strings) for `group_id`.
    pub fn list_member_addrs(&self, group_id: &[u8]) -> Result<Vec<([u8; 32], String)>, GroupError> {
        self.backend
            .list_member_addrs(group_id)
            .map_err(|e| GroupError::Storage(format!("list_member_addrs: {e}")))
    }

    /// Forget a member's delivery hint (e.g. after removal from the group).
    pub fn forget_member_addr(&self, group_id: &[u8], node_id: &[u8; 32]) -> Result<(), GroupError> {
        self.backend
            .forget_member_addr(group_id, node_id)
            .map_err(|e| GroupError::Storage(format!("forget_member_addr: {e}")))
    }
}

/// Derive a 256-bit value key from a passphrase for the convenience
/// [`GroupStorage::open_at`] entry point. The security-bearing key path is the
/// PQC at-rest hierarchy (random DEK in `at-rest.key`/`<db>.kek`); this is only
/// for callers that drive the DB directly by passphrase.
///
/// Uses PBKDF2-HMAC-SHA256 (audit L4): a single-round SHA-256 made a
/// passphrase-driven DB trivially brute-forceable, a real footgun on this `pub`
/// path if a frontend ever fed it a low-entropy passphrase. The high iteration
/// count removes that cheap offline guess.
///
/// The salt is a fixed domain-separated label. There is no per-DB salt on this
/// passphrase-only convenience path: a *stored* random salt is the production
/// PQC at-rest hierarchy's job, and mixing the DB *path* into the salt was
/// rejected because it would make a moved/renamed database permanently
/// undecryptable (a far worse, data-losing footgun than the residual it would
/// close). The residual: a common passphrase yields the same DEK across DBs, so
/// an attacker with several DB files could amortize a dictionary attack — but
/// only against low-entropy passphrases on this non-production path, and the
/// iteration count keeps each guess expensive. Production never takes this path.
fn passphrase_to_dek(passphrase: &str) -> [u8; 32] {
    const KDF_SALT: &[u8] = b"nkct-redb-passphrase-v1";
    const KDF_ITERATIONS: u32 = 256_000; // matches the at-rest PBKDF2 default
    let mut dek = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), KDF_SALT, KDF_ITERATIONS, &mut dek);
    dek
}

impl std::fmt::Debug for GroupStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupStorage").field("path", &self.path).finish()
    }
}

/// Fixed passphrase used by every test in the `group` module. Not a secret —
/// sharing one value lets tests round-trip a DB file (open, drop, reopen).
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
        let path = dir.path().join("groups.redb");
        let _storage = GroupStorage::open_at(&path, test_pass()).expect("open");
        assert!(path.exists(), "redb file should be created on open");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(&path).expect("metadata");
            assert_eq!(meta.permissions().mode() & 0o777, 0o600, "file should be 0o600");
        }
    }

    #[test]
    fn list_group_ids_empty_on_fresh_db() {
        let dir = tempdir().expect("tempdir");
        let storage =
            GroupStorage::open_at(dir.path().join("groups.redb"), test_pass()).expect("open");
        assert!(storage.list_group_ids().expect("list").is_empty());
    }

    #[test]
    fn reopen_same_path_preserves_data() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("groups.redb");
        drop(GroupStorage::open_at(&path, test_pass()).expect("first open"));
        let storage = GroupStorage::open_at(&path, test_pass()).expect("second open");
        assert!(storage.list_group_ids().expect("list").is_empty());
    }

    #[test]
    fn empty_passphrase_is_rejected() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("groups.redb");
        let err = GroupStorage::open_at(&path, Zeroizing::new(String::new()))
            .expect_err("empty passphrase must be rejected");
        match err {
            GroupError::Storage(msg) => assert!(msg.contains("passphrase")),
            other => panic!("expected Storage error, got {other:?}"),
        }
    }

    #[test]
    fn open_with_raw_key_roundtrips() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("groups.redb");
        let dek = [0x42u8; 32];
        drop(GroupStorage::open_at_with_raw_key(&path, &dek).expect("first open"));
        let storage = GroupStorage::open_at_with_raw_key(&path, &dek).expect("second open");
        assert!(storage.list_group_ids().expect("list").is_empty());
    }

    #[test]
    fn wrong_passphrase_fails_to_open() {
        // The DEK sentinel makes a wrong key fail fast on open.
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("groups.redb");
        drop(
            GroupStorage::open_at(&path, Zeroizing::new("right".to_string())).expect("first open"),
        );
        let err = GroupStorage::open_at(&path, Zeroizing::new("wrong".to_string()))
            .expect_err("wrong passphrase must fail");
        assert!(matches!(err, GroupError::Storage(_)), "expected Storage error, got {err:?}");
    }
}
