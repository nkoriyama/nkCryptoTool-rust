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
    /// Every stored group key, exactly as it sits in the table — including any
    /// that is not a well-formed 32-byte id.
    ///
    /// Used by the join path to detect a group id that already exists before
    /// persisting over it, which must work regardless of whether some other
    /// row is malformed.
    pub fn list_group_ids_raw(&self) -> Result<Vec<Vec<u8>>, GroupError> {
        self.backend
            .group_state_storage()
            .list_group_ids()
            .map_err(|e| GroupError::Storage(format!("list_group_ids: {e}")))
    }

    /// The well-formed group ids in storage.
    ///
    /// A row whose key is not 32 bytes is **skipped with a warning**, not
    /// treated as a fatal error for the whole scan. It used to abort the
    /// listing, which meant a single malformed key — one an attacker could
    /// plant with a crafted Welcome — permanently broke `list_groups` for every
    /// real group, with no CLI or FFI operation able to remove it. Skipping
    /// keeps one bad row from denying access to the rest; the join path now
    /// also refuses to create such a row in the first place.
    pub fn list_group_ids(&self) -> Result<Vec<GroupId>, GroupError> {
        let raw = self.list_group_ids_raw()?;
        let mut out = Vec::with_capacity(raw.len());
        for bytes in raw {
            if bytes.len() != 32 {
                eprintln!(
                    "[nkct] warning: skipping stored group with malformed id ({} bytes, expected 32)",
                    bytes.len()
                );
                continue;
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

    /// Application-KV key for a member's witnessed join epoch. Hex on both
    /// halves so the `:` separator cannot appear inside either field.
    fn member_join_epoch_key(group_id: &[u8], node_id: &[u8; 32]) -> String {
        format!(
            "mls:joined:{}:{}",
            hex::encode(group_id),
            hex::encode(node_id)
        )
    }

    /// Record that `node_id` joined `group_id` at `epoch` — i.e. that *we*
    /// applied the Add commit which produced `epoch` and saw that member appear
    /// on the roster for the first time.
    ///
    /// This is what lets the SYNC responder clamp a requester's `claimed_epoch`
    /// to its own admission, so a member cannot be streamed commit history from
    /// before it was in the group. It rides on the existing application-data KV
    /// (same AEAD sealing, same table) rather than a new table, so an existing
    /// database gains the records the first time it witnesses an Add and needs
    /// no migration.
    ///
    /// Re-recording overwrites: a member removed and later re-added has the
    /// *later* epoch, which is the conservative bound (its current state starts
    /// there, so it needs nothing older).
    pub fn put_member_join_epoch(
        &self,
        group_id: &[u8],
        node_id: &[u8; 32],
        epoch: u64,
    ) -> Result<(), GroupError> {
        self.backend
            .application_data_storage()
            .insert(
                &Self::member_join_epoch_key(group_id, node_id),
                &epoch.to_be_bytes(),
            )
            .map_err(|e| GroupError::Storage(format!("put_member_join_epoch: {e}")))
    }

    /// The epoch at which we witnessed `node_id` joining `group_id`, if we
    /// witnessed it.
    ///
    /// `None` means "not known", not "epoch 0", and is the normal answer in
    /// three cases: a database written before this record existed, a member
    /// that was already on the roster when *we* joined (we were handed a
    /// Welcome, not their Add commit), and a group whose adds we have simply
    /// never applied.
    ///
    /// **`None` is not "no clamp".** It carries no entitlement, so a caller
    /// deciding what history to disclose must fall back to the group-wide
    /// [`history_floor`](Self::history_floor) — which bounds the span this node
    /// can vouch for without knowing who joined when — and must disclose
    /// nothing where even that is absent. Reading `None` as "serve from
    /// whatever the requester asked for" is the disclosure this record exists
    /// to stop.
    ///
    /// A malformed value (not exactly 8 bytes) is reported as `None`: it is
    /// the answer that discloses least.
    pub fn member_join_epoch(
        &self,
        group_id: &[u8],
        node_id: &[u8; 32],
    ) -> Result<Option<u64>, GroupError> {
        let raw = self
            .backend
            .application_data_storage()
            .get(&Self::member_join_epoch_key(group_id, node_id))
            .map_err(|e| GroupError::Storage(format!("member_join_epoch: {e}")))?;
        Ok(raw.and_then(|v| {
            <[u8; 8]>::try_from(v.as_slice())
                .ok()
                .map(u64::from_be_bytes)
        }))
    }

    /// Application-KV key for a group's history floor.
    fn history_floor_key(group_id: &[u8]) -> String {
        format!("mls:histfloor:{}", hex::encode(group_id))
    }

    /// The **exclusive** lower bound of the epoch span over which this node's
    /// [`member_join_epoch`](Self::member_join_epoch) records are complete: for
    /// every epoch strictly greater than the floor, every Add we applied at that
    /// epoch was recorded.
    ///
    /// That is what makes a *missing* join record informative. Below the floor
    /// we know nothing; above it, "no record" means "this member did not join in
    /// that span", so history from above the floor is safe to serve to a member
    /// we cannot date. `None` means we cannot vouch for any span at all — a
    /// database whose retained commits all predate this record and which has
    /// applied no commit since — and discloses nothing.
    ///
    /// A malformed value (not exactly 8 bytes) is reported as `None` for the
    /// same reason it is on `member_join_epoch`: it is the answer that
    /// discloses least.
    pub fn history_floor(&self, group_id: &[u8]) -> Result<Option<u64>, GroupError> {
        let raw = self
            .backend
            .application_data_storage()
            .get(&Self::history_floor_key(group_id))
            .map_err(|e| GroupError::Storage(format!("history_floor: {e}")))?;
        Ok(raw.and_then(|v| {
            <[u8; 8]>::try_from(v.as_slice())
                .ok()
                .map(u64::from_be_bytes)
        }))
    }

    /// Pin the floor at `floor` if none is recorded yet, leaving an existing one
    /// untouched.
    ///
    /// Called with `epoch - 1` each time we apply a commit landing at `epoch`
    /// whose Adds we recorded in full. Only the *first* such call after the
    /// record existed can move it: the floor must stay as low as we can honestly
    /// vouch for, or every later commit would ratchet it up and starve the delta
    /// resync this whole path exists to serve.
    ///
    /// An unreadable (malformed) existing value is replaced, which can only
    /// raise the floor — the replacement is derived from the epoch we are at
    /// now, which is at or above anything an earlier pin could have written.
    pub fn pin_history_floor_if_absent(
        &self,
        group_id: &[u8],
        floor: u64,
    ) -> Result<(), GroupError> {
        if self.history_floor(group_id)?.is_some() {
            return Ok(());
        }
        self.backend
            .application_data_storage()
            .insert(&Self::history_floor_key(group_id), &floor.to_be_bytes())
            .map_err(|e| GroupError::Storage(format!("pin_history_floor_if_absent: {e}")))
    }

    /// Raise the floor to at least `floor`; never lower it.
    ///
    /// Called with the epoch of a commit whose join records we failed to write:
    /// we can no longer claim completeness at or below it, and the floor has to
    /// move up to stay honest. Raising only ever discloses less.
    pub fn raise_history_floor(&self, group_id: &[u8], floor: u64) -> Result<(), GroupError> {
        if self.history_floor(group_id)?.is_some_and(|cur| cur >= floor) {
            return Ok(());
        }
        self.backend
            .application_data_storage()
            .insert(&Self::history_floor_key(group_id), &floor.to_be_bytes())
            .map_err(|e| GroupError::Storage(format!("raise_history_floor: {e}")))
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

    /// The join-epoch record round-trips, is scoped per (group, member), and —
    /// the property the SYNC clamp depends on for backward compatibility — is
    /// `None` rather than `0` for a member we never witnessed joining, which is
    /// what every database written before this record contains.
    #[test]
    fn member_join_epoch_roundtrips_and_defaults_to_unknown() {
        let dir = tempdir().expect("tempdir");
        let storage =
            GroupStorage::open_at(dir.path().join("groups.redb"), test_pass()).expect("open");
        let gid = [7u8; 32];
        let member = [9u8; 32];
        let other = [8u8; 32];

        assert_eq!(
            storage.member_join_epoch(&gid, &member).expect("get"),
            None,
            "an unrecorded member must read as unknown, never as epoch 0"
        );

        storage
            .put_member_join_epoch(&gid, &member, 42)
            .expect("put");
        assert_eq!(
            storage.member_join_epoch(&gid, &member).expect("get"),
            Some(42)
        );
        assert_eq!(
            storage.member_join_epoch(&gid, &other).expect("get"),
            None,
            "records are per member"
        );
        assert_eq!(
            storage.member_join_epoch(&[1u8; 32], &member).expect("get"),
            None,
            "records are per group"
        );

        // Re-add: the later epoch wins (the member's state starts there).
        storage
            .put_member_join_epoch(&gid, &member, 77)
            .expect("re-put");
        assert_eq!(
            storage.member_join_epoch(&gid, &member).expect("get"),
            Some(77)
        );
    }

    /// The history floor is per group, pins once, and only ever moves up.
    ///
    /// The two directions are not symmetric on purpose: the pin must *not*
    /// ratchet (each commit we apply offers `epoch - 1`, and taking the latest
    /// would starve every legitimate delta), while a failed join-record must
    /// raise it (we can no longer claim our records are complete at that epoch).
    #[test]
    fn history_floor_pins_once_and_never_moves_down() {
        let dir = tempdir().expect("tempdir");
        let storage =
            GroupStorage::open_at(dir.path().join("groups.redb"), test_pass()).expect("open");
        let gid = [7u8; 32];
        let other_gid = [1u8; 32];

        assert_eq!(
            storage.history_floor(&gid).expect("get"),
            None,
            "a group we have never vouched for must read as unknown, never as epoch 0"
        );

        storage.pin_history_floor_if_absent(&gid, 10).expect("pin");
        assert_eq!(storage.history_floor(&gid).expect("get"), Some(10));
        assert_eq!(
            storage.history_floor(&other_gid).expect("get"),
            None,
            "the floor is per group"
        );

        // Every later commit offers its own `epoch - 1`; none of them may move
        // a floor that is already pinned, in either direction.
        storage.pin_history_floor_if_absent(&gid, 99).expect("pin again");
        storage.pin_history_floor_if_absent(&gid, 3).expect("pin lower");
        assert_eq!(storage.history_floor(&gid).expect("get"), Some(10));

        // A failed join-record raises it; a stale raise does not lower it.
        storage.raise_history_floor(&gid, 5).expect("raise below");
        assert_eq!(storage.history_floor(&gid).expect("get"), Some(10));
        storage.raise_history_floor(&gid, 20).expect("raise above");
        assert_eq!(storage.history_floor(&gid).expect("get"), Some(20));

        // Raising a group that has no floor yet establishes one.
        storage.raise_history_floor(&other_gid, 4).expect("raise fresh");
        assert_eq!(storage.history_floor(&other_gid).expect("get"), Some(4));
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
