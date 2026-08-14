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

use sha2::{Digest, Sha256};
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
        // Software counter (always available, best-effort). Deterministic
        // per policy: a DB created under `permissive` is always opened with
        // the software counter, never silently switched to TPM.
        RollbackPolicy::Permissive => Ok(Some(Box::new(SoftwareCounter::for_db(db_path)?))),
        // Hardware-backed counter. A true hardware monotonic counter usable
        // by a non-elevated app exists only on Linux (TPM 2.0 NV). macOS and
        // Windows have no such facility (see `strict_counter`), so the policy
        // is dispatched per platform rather than pretending otherwise.
        RollbackPolicy::Strict => strict_counter(db_path),
    }
}

/// `Strict` on Linux: a TPM 2.0 NV monotonic counter, or a fail-fast error if
/// no TPM is present. Constructing the counter does no TPM I/O (the NV index
/// is allocated lazily on first use), so we gate on a cheap availability probe.
#[cfg(target_os = "linux")]
fn strict_counter(db_path: &Path) -> Result<Option<Box<dyn RollbackCounter>>, GroupError> {
    if tpm_available() {
        Ok(Some(Box::new(TpmCounter::for_db(db_path)?)))
    } else {
        Err(GroupError::Storage(
            "NK_ROLLBACK_POLICY=strict requires a working TPM 2.0 (tpm2-tools + \
             /dev/tpmrm0); none was detected. Use 'permissive' for the software \
             counter, or 'off' to disable rollback protection"
                .into(),
        ))
    }
}

/// `Strict` on macOS / Windows: refused, honestly. Neither platform exposes an
/// application-accessible hardware monotonic counter:
///
/// * **macOS** — the Secure Enclave keeps monotonic counters *internally* but
///   exposes none through any public API (CryptoKit `SecureEnclave` is
///   key-only; `kSecAttrTokenIDSecureEnclave` is a storage-location attribute).
/// * **Windows** — the TPM exists, but its driver *blocks* the NV counter
///   commands (`NV_Increment` / `NV_DefineSpace`) for the owner hierarchy,
///   hardcoded since Windows 10 1809, even for administrators.
///
/// So rather than fall back to a software counter under a name that promises
/// hardware, we refuse and point at the realistic anti-rollback story on these
/// platforms: `permissive` (software counter) plus the online inbox CHECKPOINT
/// for cross-device rollback detection. See ATREST_ANTIROLLBACK_DESIGN.md §5.
#[cfg(not(target_os = "linux"))]
fn strict_counter(_db_path: &Path) -> Result<Option<Box<dyn RollbackCounter>>, GroupError> {
    Err(GroupError::Storage(
        "NK_ROLLBACK_POLICY=strict is unavailable on this platform: no \
         application-accessible hardware monotonic counter exists on macOS \
         (the Secure Enclave exposes none) or Windows (the TPM driver blocks \
         NV counter commands). A true hardware anti-rollback counter is \
         supported only on Linux via TPM 2.0. On this OS use \
         NK_ROLLBACK_POLICY=permissive (software counter), ideally paired with \
         the online inbox CHECKPOINT for cross-device rollback detection, or \
         'off' to disable. See ATREST_ANTIROLLBACK_DESIGN.md §5"
            .into(),
    ))
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
        let digest = Sha256::digest(abs.as_os_str().as_encoded_bytes());
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
// TpmCounter (TPM 2.0 NV monotonic counter)
// -----------------------------------------------------------------------------

/// TCTI used to reach the in-kernel resource manager. Matches
/// [`crate::key::tpm`].
const TPM_TCTI: &str = "device:/dev/tpmrm0";
/// Owner-hierarchy NV-index base for per-DB rollback counters. The low 20
/// bits are derived from the DB path, so co-located DBs get independent
/// counters. Range `0x0150_0000..=0x0150_FFFFF` (≡ `0x0150_0000` |
/// 20-bit) lives in the owner-defined NV space, above the TCG-reserved
/// `0x0140_xxxx` block and below the platform range (`0x0180_0000+`).
const TPM_NV_BASE: u32 = 0x0150_0000;
/// Mask of DB-derived index bits (20). Path collision is ≈1/2^20 per DB
/// pair; a true collision shares one TPM counter, so rekeying one DB would
/// invalidate the other's KEK. Acceptable for the single-user / few-DB
/// target (a registry-free design); documented in SECURITY_PROFILE.md §7.5.
const TPM_NV_SUB_MASK: u32 = 0x000F_FFFF;

/// Run a `tpm2-tools` command against [`TPM_TCTI`], returning raw stdout.
/// `LC_ALL=C` pins message text so error-code matching (e.g. the
/// uninitialized-NV probe) is locale-independent.
fn tpm2(args: &[&str]) -> Result<Vec<u8>, GroupError> {
    let out = std::process::Command::new(args[0])
        .args(&args[1..])
        .env("TCTI", TPM_TCTI)
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .output()
        .map_err(|e| GroupError::Backend(format!("spawn {}: {e}", args[0])))?;
    if !out.status.success() {
        return Err(GroupError::Backend(format!(
            "{} failed: {}",
            args[0],
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(out.stdout)
}

/// Cheap probe: is a usable TPM 2.0 present?
pub fn tpm_available() -> bool {
    tpm2(&["tpm2_getcap", "properties-fixed"]).is_ok()
}

/// A monotonic counter backed by a TPM 2.0 NV counter index.
///
/// A TPM NV counter is hardware-enforced monotonic and survives a wipe of
/// the storage directory entirely, so it closes the software counter's
/// residual risk (an attacker who also restores the out-of-dir state file).
/// Each increment advances the value by exactly 1; a freshly defined index
/// is primed (incremented once) so it is immediately readable.
pub struct TpmCounter {
    /// NV index as a `tpm2-tools` argument, e.g. `0x01710A3F`.
    index_arg: String,
}

impl TpmCounter {
    /// Derive the per-DB NV index from the absolute DB path. Two DBs whose
    /// paths collide in the low 16 bits of SHA-256 would share a counter
    /// (≈1/65536 per pair) — acceptable for the single-user, few-DB target.
    pub fn for_db(db_path: &Path) -> Result<Self, GroupError> {
        let abs = absolutize(db_path);
        let digest = Sha256::digest(abs.as_os_str().as_encoded_bytes());
        let sub = u32::from_be_bytes([0, digest[0], digest[1], digest[2]]) & TPM_NV_SUB_MASK;
        Ok(Self::with_index(TPM_NV_BASE | sub))
    }

    /// Construct for an explicit NV index (tests / custom layouts).
    pub fn with_index(index: u32) -> Self {
        Self {
            index_arg: format!("0x{index:08X}"),
        }
    }

    fn is_defined(&self) -> bool {
        tpm2(&["tpm2_nvreadpublic", &self.index_arg]).is_ok()
    }

    /// Read the counter, or `None` if it has been defined but never
    /// incremented (a TPM counter is unreadable until its first increment —
    /// `tpm2_nvread` fails with TPM error `0x14A`, "used before being
    /// initialized", which we map to `None`).
    fn read_value(&self) -> Result<Option<u64>, GroupError> {
        let bytes = match tpm2(&["tpm2_nvread", &self.index_arg, "-C", "o"]) {
            Ok(b) => b,
            Err(GroupError::Backend(msg))
                if msg.contains("0x14A") || msg.contains("before being initialized") =>
            {
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        let arr: [u8; 8] = bytes.get(..8).and_then(|b| b.try_into().ok()).ok_or_else(|| {
            GroupError::Backend(format!("tpm nvread returned {} bytes (expected 8)", bytes.len()))
        })?;
        Ok(Some(u64::from_be_bytes(arr)))
    }

    fn increment(&self) -> Result<(), GroupError> {
        tpm2(&["tpm2_nvincrement", &self.index_arg, "-C", "o"]).map(|_| ())
    }

    /// Ensure the NV counter exists and is readable (define it if missing,
    /// prime it with one increment if it has never been incremented). Safe
    /// to call repeatedly; only writes the TPM the first time.
    fn ensure_ready(&self) -> Result<(), GroupError> {
        if !self.is_defined() {
            tpm2(&[
                "tpm2_nvdefine",
                &self.index_arg,
                "-C",
                "o",
                "-s",
                "8",
                "-a",
                "ownerread|ownerwrite|authread|authwrite|nt=counter",
            ])?;
        }
        // Prime: a just-defined (or define-then-crash) counter is unreadable
        // until its first increment. Priming makes `current()` always return
        // a real value and keeps per-increment deltas at exactly +1.
        if self.read_value()?.is_none() {
            self.increment()?;
        }
        Ok(())
    }
}

impl RollbackCounter for TpmCounter {
    fn current(&self) -> Result<u64, GroupError> {
        self.ensure_ready()?;
        self.read_value()?
            .ok_or_else(|| GroupError::Backend("tpm counter unreadable after priming".into()))
    }

    fn advance(&self) -> Result<u64, GroupError> {
        self.ensure_ready()?;
        self.increment()?;
        self.read_value()?
            .ok_or_else(|| GroupError::Backend("tpm counter unreadable after increment".into()))
    }

    fn kind(&self) -> &'static str {
        "tpm"
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

/// Make `p` absolute and as canonical as possible without requiring the DB
/// file itself to exist (it may not yet on first init). A relative path is
/// joined onto the current dir; the **parent** directory is canonicalized
/// best-effort so the same DB reached via a symlinked or relative directory
/// resolves to one stable counter (otherwise distinct paths to the same DB
/// would derive distinct counters, which could bypass rollback detection).
/// The file-name component is not symlink-resolved.
fn absolutize(p: &Path) -> PathBuf {
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(p)
    };
    match (abs.parent(), abs.file_name()) {
        (Some(parent), Some(name)) => match fs::canonicalize(parent) {
            Ok(canon) => canon.join(name),
            Err(_) => abs, // parent doesn't exist yet; use the plain absolute path
        },
        _ => abs,
    }
}

fn write_file_0600(path: &Path, data: &[u8]) -> Result<(), GroupError> {
    use std::io::Write as _;
    let mut f = crate::secure_fs::create_owner_only(path, false)
        .map_err(|e| GroupError::Storage(format!("create {path:?}: {e}")))?;
    f.write_all(data)
        .and_then(|()| f.sync_all())
        .map_err(|e| GroupError::Storage(format!("write {path:?}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
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

    #[cfg(target_os = "linux")]
    #[test]
    #[serial(tpm)]
    fn strict_policy_matches_tpm_availability() {
        // Constructing the strict counter does no TPM I/O; it just reflects
        // whether a TPM is present. (No NV index is allocated here.)
        let r = counter_for(RollbackPolicy::Strict, Path::new("groups.db"));
        if tpm_available() {
            assert!(matches!(r, Ok(Some(_))), "TPM present → counter");
        } else {
            assert!(matches!(r, Err(GroupError::Storage(_))), "no TPM → error");
        }
    }

    /// On macOS / Windows there is no application-accessible hardware monotonic
    /// counter, so Strict is refused with an honest explanation — never
    /// silently downgraded to the software counter under a hardware name.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn strict_policy_refused_off_linux() {
        match counter_for(RollbackPolicy::Strict, Path::new("groups.db")) {
            Err(GroupError::Storage(msg)) => {
                assert!(
                    msg.contains("unavailable on this platform"),
                    "expected the honest platform message, got: {msg}"
                );
            }
            other => panic!("Strict off Linux must be a Storage error, got {other:?}"),
        }
    }

    /// Undefine an NV index so TPM tests leave no residue, even on panic.
    ///
    /// A failure here is reported rather than swallowed: it leaves a defined
    /// index behind, and the next run of this test starts from a counter that
    /// is already primed instead of a fresh one. Silently dropping the error
    /// turned that into an unexplained intermittent failure. `Drop` must not
    /// panic, so this is a diagnostic, not an assertion.
    struct NvCleanup(u32);
    impl Drop for NvCleanup {
        fn drop(&mut self) {
            let arg = format!("0x{:08X}", self.0);
            if let Err(e) = tpm2(&["tpm2_nvundefine", &arg, "-C", "o"]) {
                eprintln!("NvCleanup: {arg} was not undefined, next run inherits it: {e}");
            }
        }
    }

    /// `#[serial]` because the TPM tests share one `/dev/tpmrm0`. They use
    /// distinct NV indices, so this is not an index collision — it keeps two
    /// tests from driving the same device through `tpm2-tools` subprocesses at
    /// once. This is the only cross-test coupling that was left; it has not
    /// been shown to be the cause of the intermittent failure seen during the
    /// 2026-08 audit, which was never reproduced.
    #[test]
    #[serial(tpm)]
    fn tpm_counter_advances_monotonically() {
        if !tpm_available() {
            eprintln!("skipping: no TPM 2.0 available");
            return;
        }
        // Dedicated test index, cleaned up via the drop guard.
        let index = TPM_NV_BASE | 0xFE01;
        let _guard = NvCleanup(index);
        let _ = tpm2(&["tpm2_nvundefine", &format!("0x{index:08X}"), "-C", "o"]); // stale

        let c = TpmCounter::with_index(index);
        let v0 = c.current().expect("current primes + reads");
        let v1 = c.advance().expect("advance");
        let v2 = c.advance().expect("advance");
        assert_eq!(v1, v0 + 1, "increments by exactly 1");
        assert_eq!(v2, v0 + 2);
        // A fresh handle to the same index observes the persisted value.
        assert_eq!(TpmCounter::with_index(index).current().unwrap(), v2);
    }
}

#[cfg(test)]
pub(crate) use tests::MemoryCounter;
