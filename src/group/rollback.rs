//! Anti-rollback monotonic counter for the at-rest layer.
//!
//! ## Why
//!
//! The at-rest crypto (SQLCipher + the PQC-wrapped DEK) makes a stolen DB
//! file useless without the passphrase, but it does **not** stop an
//! attacker who can *write* the storage directory from restoring an older,
//! internally-consistent `(groups.db, groups.db.kek)` snapshot — silently
//! reverting the user to a past state (re-admitting a removed member,
//! resurrecting deleted data, rewinding the MLS ratchet). See
//! SECURITY_PROFILE.md §7.5 and ATREST_ANTIROLLBACK_DESIGN.md.
//!
//! ## Mechanism
//!
//! A per-DB monotonic counter is mixed into the KEK's HPKE `info` (KEK
//! version `0x03`, see [`crate::group::at_rest`]). The counter advances on
//! every rekey. On open we read the current counter and try to decapsulate
//! the on-disk KEK against it; a restored old KEK was sealed under a
//! *smaller* counter, so the `info` mismatch fails the HPKE AEAD check and
//! the rollback is detected.
//!
//! The counter lives **outside** the storage directory (under
//! `$XDG_STATE_HOME`), so restoring the storage dir alone does not restore
//! it. An attacker who also restores the state file defeats the software
//! counter — that residual risk is closed only by a hardware-backed
//! counter (TPM NV; a future provider).
//!
//! ## Policy
//!
//! Controlled by `NK_ROLLBACK_POLICY`:
//! - `off` (default) — no counter; KEKs stay version `0x02`. Zero change to
//!   existing behaviour.
//! - `permissive` — use the [`SoftwareCounter`]. Enabling it on an existing
//!   DB upgrades the KEK to `0x03` on the next rekey.
//! - `strict` — require a hardware-backed counter. Not yet implemented;
//!   currently errors so the operator is never silently downgraded.

use std::fs;
use std::path::{Path, PathBuf};

use openssl::hash::{hash, MessageDigest};
use rand_core::{OsRng, RngCore};

use crate::group::types::GroupError;

/// Operator-selected anti-rollback strength.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RollbackPolicy {
    /// No rollback counter — KEKs stay at the per-DB-bound version `0x02`.
    Off,
    /// Software counter (best-effort; defeated if the attacker also
    /// restores the out-of-storage-dir state file).
    Permissive,
    /// Hardware-backed counter required. Not yet implemented.
    Strict,
}

impl RollbackPolicy {
    /// Read the policy from `NK_ROLLBACK_POLICY` (default [`Off`]).
    pub fn from_env() -> Self {
        match std::env::var("NK_ROLLBACK_POLICY").ok().as_deref() {
            Some(v) if v.eq_ignore_ascii_case("permissive") => RollbackPolicy::Permissive,
            Some(v) if v.eq_ignore_ascii_case("strict") => RollbackPolicy::Strict,
            _ => RollbackPolicy::Off,
        }
    }
}

/// A monotonic counter bound into the KEK to detect at-rest rollback.
///
/// Implementations must be durable and never decrease across process
/// restarts (modulo the documented software residual risk).
pub trait RollbackCounter: Send + Sync {
    /// The current counter value (0 if it has never been advanced).
    fn current(&self) -> Result<u64, GroupError>;
    /// Atomically advance the counter and return the new value.
    fn advance(&self) -> Result<u64, GroupError>;
    /// Short identifier for diagnostics/logging.
    fn kind(&self) -> &'static str;
}

/// Resolve the counter to use for the database at `db_path` under `policy`.
///
/// `Off` → `None` (callers keep the current, counter-free KEK path).
/// `Permissive` → a [`SoftwareCounter`] keyed to this DB.
/// `Strict` → an error until a hardware counter exists.
pub fn counter_for(
    policy: RollbackPolicy,
    db_path: &Path,
) -> Result<Option<Box<dyn RollbackCounter>>, GroupError> {
    match policy {
        RollbackPolicy::Off => Ok(None),
        RollbackPolicy::Permissive => Ok(Some(Box::new(SoftwareCounter::for_db(db_path)?))),
        RollbackPolicy::Strict => Err(GroupError::Storage(
            "NK_ROLLBACK_POLICY=strict requires a hardware-backed rollback counter, \
             which is not yet implemented (TPM NV is a future provider); \
             use 'permissive' for the software counter"
                .into(),
        )),
    }
}

// -----------------------------------------------------------------------------
// SoftwareCounter
// -----------------------------------------------------------------------------

/// A per-DB monotonic counter persisted as a single big-endian `u64` in a
/// file under `$XDG_STATE_HOME/nkct/rollback/`, **outside** the DB's
/// storage directory.
pub struct SoftwareCounter {
    path: PathBuf,
}

impl SoftwareCounter {
    /// Counter file for `db_path`: `<state>/nkct/rollback/<hex>.ctr` where
    /// `<hex>` is the first 16 bytes of SHA-256 over the absolute DB path.
    /// Keying by absolute path keeps co-located DBs (e.g. `groups.db` and
    /// `inbox.db`) on independent counters.
    pub fn for_db(db_path: &Path) -> Result<Self, GroupError> {
        let abs = absolutize(db_path);
        let digest = hash(MessageDigest::sha256(), abs.as_os_str().as_encoded_bytes())
            .map_err(|e| GroupError::Storage(format!("rollback path hash: {e}")))?;
        let name = format!("{}.ctr", hex::encode(&digest[..16]));
        let dir = state_dir().join("nkct").join("rollback");
        Ok(Self {
            path: dir.join(name),
        })
    }

    /// Construct directly from a counter-file path (tests / custom layouts).
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    fn read_raw(&self) -> Result<u64, GroupError> {
        match fs::read(&self.path) {
            Ok(bytes) => {
                let arr: [u8; 8] = bytes.as_slice().try_into().map_err(|_| {
                    GroupError::Storage(format!(
                        "rollback counter {:?} is corrupt ({} bytes, expected 8)",
                        self.path,
                        bytes.len()
                    ))
                })?;
                Ok(u64::from_be_bytes(arr))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(e) => Err(GroupError::Storage(format!(
                "read rollback counter {:?}: {e}",
                self.path
            ))),
        }
    }

    fn write_raw(&self, value: u64) -> Result<(), GroupError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                GroupError::Storage(format!("create rollback dir {parent:?}: {e}"))
            })?;
        }
        // Atomic write-to-temp + rename, with an unpredictable temp name and
        // 0o600 on Unix (the counter is integrity-sensitive, not secret).
        let mut rnd = [0u8; 8];
        OsRng.fill_bytes(&mut rnd);
        let tmp = self.path.with_extension(format!("ctr.{}.tmp", hex::encode(rnd)));
        write_file_0600(&tmp, &value.to_be_bytes())?;
        if let Err(e) = fs::rename(&tmp, &self.path) {
            let _ = fs::remove_file(&tmp);
            return Err(GroupError::Storage(format!(
                "promote rollback counter {:?}: {e}",
                self.path
            )));
        }
        Ok(())
    }
}

impl RollbackCounter for SoftwareCounter {
    fn current(&self) -> Result<u64, GroupError> {
        self.read_raw()
    }

    fn advance(&self) -> Result<u64, GroupError> {
        let next = self.read_raw()?.checked_add(1).ok_or_else(|| {
            GroupError::Storage("rollback counter overflow".into())
        })?;
        self.write_raw(next)?;
        Ok(next)
    }

    fn kind(&self) -> &'static str {
        "software"
    }
}

// -----------------------------------------------------------------------------
// Internals
// -----------------------------------------------------------------------------

/// `$XDG_STATE_HOME`, else `$HOME/.local/state`, else the current dir.
fn state_dir() -> PathBuf {
    if let Some(x) = std::env::var_os("XDG_STATE_HOME").filter(|v| !v.is_empty()) {
        return PathBuf::from(x);
    }
    if let Some(home) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
        return PathBuf::from(home).join(".local").join("state");
    }
    PathBuf::from(".")
}

/// Make `p` absolute without requiring it to exist (canonicalize fails on a
/// not-yet-created DB). A relative path is joined onto the current dir.
fn absolutize(p: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(p)
    }
}

#[cfg(unix)]
fn write_file_0600(path: &Path, data: &[u8]) -> Result<(), GroupError> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| GroupError::Storage(format!("create {path:?}: {e}")))?;
    f.write_all(data)
        .and_then(|()| f.sync_all())
        .map_err(|e| GroupError::Storage(format!("write {path:?}: {e}")))
}

#[cfg(not(unix))]
fn write_file_0600(path: &Path, data: &[u8]) -> Result<(), GroupError> {
    use std::io::Write as _;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| GroupError::Storage(format!("create {path:?}: {e}")))?;
    f.write_all(data)
        .and_then(|()| f.sync_all())
        .map_err(|e| GroupError::Storage(format!("write {path:?}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tempfile::tempdir;

    /// In-memory counter for exercising the at-rest logic without touching
    /// the filesystem.
    pub struct MemoryCounter {
        value: Mutex<u64>,
    }

    impl MemoryCounter {
        pub fn new(start: u64) -> Self {
            Self {
                value: Mutex::new(start),
            }
        }
    }

    impl RollbackCounter for MemoryCounter {
        fn current(&self) -> Result<u64, GroupError> {
            Ok(*self.value.lock().unwrap())
        }
        fn advance(&self) -> Result<u64, GroupError> {
            let mut v = self.value.lock().unwrap();
            *v += 1;
            Ok(*v)
        }
        fn kind(&self) -> &'static str {
            "memory"
        }
    }

    #[test]
    fn software_counter_starts_at_zero_and_advances() {
        let dir = tempdir().expect("tempdir");
        let c = SoftwareCounter::at(dir.path().join("x.ctr"));
        assert_eq!(c.current().unwrap(), 0, "missing file reads as 0");
        assert_eq!(c.advance().unwrap(), 1);
        assert_eq!(c.advance().unwrap(), 2);
        assert_eq!(c.current().unwrap(), 2);
    }

    #[test]
    fn software_counter_persists_across_instances() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("x.ctr");
        SoftwareCounter::at(&path).advance().unwrap();
        SoftwareCounter::at(&path).advance().unwrap();
        assert_eq!(SoftwareCounter::at(&path).current().unwrap(), 2);
    }

    #[test]
    fn for_db_keys_distinct_dbs_separately() {
        let a = SoftwareCounter::for_db(Path::new("/tmp/dir/groups.db")).unwrap();
        let b = SoftwareCounter::for_db(Path::new("/tmp/dir/inbox.db")).unwrap();
        assert_ne!(a.path, b.path, "co-located DBs get independent counters");
    }

    #[test]
    fn policy_from_env_parsing() {
        assert_eq!(RollbackPolicy::from_env(), RollbackPolicy::Off); // unset in test
    }

    #[test]
    fn off_policy_yields_no_counter() {
        let c = counter_for(RollbackPolicy::Off, Path::new("groups.db")).unwrap();
        assert!(c.is_none());
    }

    #[test]
    fn strict_policy_errors_without_hardware() {
        match counter_for(RollbackPolicy::Strict, Path::new("groups.db")) {
            Err(GroupError::Storage(_)) => {}
            Ok(_) => panic!("strict must error without hardware"),
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }
}

#[cfg(test)]
pub(crate) use tests::MemoryCounter;
