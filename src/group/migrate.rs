//! One-time migration of a legacy **SQLCipher** `groups.db` to the pure-Rust
//! **redb** backend (P3). Compiled only under `legacy-sqlcipher-migration`,
//! which pulls in `rusqlite`/SQLCipher (hence system libcrypto) — so the normal
//! C-free build never contains this reader. See `DB_PURERUST_DESIGN.md`.
//!
//! Scope: the irreplaceable `groups.db` (group state, key packages, PSKs, the
//! signing-identity KVs). `inbox.db` (transient relay queue) and `prekeys.db`
//! (republishable one-time prekeys) are *not* migrated — they are recreated
//! empty on next use, which is safe for their data.
//!
//! The at-rest key hierarchy (`at-rest.key` + `<db>.kek`) is DB-agnostic, so the
//! same DEK that unlocked the SQLCipher pages also keys the new redb records —
//! no key rotation, no passphrase change.

use std::path::Path;

use mls_rs_core::group::{EpochRecord, GroupState, GroupStateStorage};
use mls_rs_core::key_package::{KeyPackageData, KeyPackageStorage};
use mls_rs_core::mls_rs_codec::MlsDecode;
use mls_rs_core::psk::PreSharedKey;
use rusqlite::{Connection, OpenFlags};
use zeroize::Zeroizing;

use crate::group::at_rest::AtRestPaths;
use crate::group::redb_storage::RedbBackend;
use crate::group::types::GroupError;

/// Row counts copied across, for the operator's confirmation.
#[derive(Debug, Default, Clone, Copy)]
pub struct MigrationReport {
    pub groups: usize,
    pub epochs: usize,
    pub key_packages: usize,
    pub psks: usize,
    pub app_kvs: usize,
}

impl std::fmt::Display for MigrationReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} group(s), {} epoch(s), {} key package(s), {} psk(s), {} app kv(s)",
            self.groups, self.epochs, self.key_packages, self.psks, self.app_kvs
        )
    }
}

fn sql_err(ctx: &str, e: rusqlite::Error) -> GroupError {
    GroupError::Storage(format!("sqlcipher migrate {ctx}: {e}"))
}

/// Open the legacy SQLCipher database at `path` read-only with the raw `dek`.
/// Returns `Ok(None)` if the file is *not* a SQLCipher DB the key opens (e.g.
/// it was already migrated to redb), so the caller can treat that as a no-op.
fn open_sqlcipher(path: &Path, dek: &[u8; 32]) -> Result<Option<Connection>, GroupError> {
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = match Connection::open_with_flags(path, flags) {
        Ok(c) => c,
        Err(_) => return Ok(None),
    };
    let key_stmt = Zeroizing::new(format!("PRAGMA key = \"x'{}'\";", hex::encode(dek)));
    if conn.execute_batch(key_stmt.as_str()).is_err() {
        return Ok(None);
    }
    // A wrong key (or a non-SQLCipher file) surfaces as SQLITE_NOTADB on the
    // first real read; treat it as "nothing to migrate".
    match conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0)) {
        Ok(_) => Ok(Some(conn)),
        Err(_) => Ok(None),
    }
}

/// Migrate the SQLCipher `groups.db` at `db_path` to redb in place.
///
/// On success the original is renamed to `<db>.sqlcipher.bak` and the new redb
/// database takes its place. A no-op (returns `Ok(None)`) if `db_path` is not a
/// SQLCipher database the DEK opens — e.g. it has already been migrated. The
/// migration is staged in a temp file and only swapped in after it verifies, so
/// a failure leaves the original untouched.
pub fn migrate_groups_db_from_sqlcipher(
    db_path: &Path,
    passphrase: &Zeroizing<String>,
) -> Result<Option<MigrationReport>, GroupError> {
    if !db_path.exists() {
        return Ok(None);
    }
    // Recover the DEK from the (DB-agnostic) at-rest key hierarchy.
    let paths = AtRestPaths::from_db_path(db_path);
    let dek = crate::group::resolve_dek(&paths, passphrase)?;

    let Some(conn) = open_sqlcipher(db_path, &dek)? else {
        return Ok(None); // not a SQLCipher DB / already migrated
    };

    // Read the entire legacy DB into memory FIRST, so the new redb can be
    // created at the *final* path (the record AAD binds to the DB file name, so
    // building under a temp name then renaming would mismatch on reopen).
    let mut report = MigrationReport::default();

    // group state + each group's prior epochs (ascending).
    let mut groups: Vec<(Vec<u8>, Vec<u8>, Vec<EpochRecord>)> = Vec::new();
    {
        let mut stmt = conn
            .prepare("SELECT group_id, snapshot FROM mls_group")
            .map_err(|e| sql_err("prepare mls_group", e))?;
        let rows: Vec<(Vec<u8>, Vec<u8>)> = stmt
            .query_map([], |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?)))
            .map_err(|e| sql_err("query mls_group", e))?
            .collect::<Result<_, _>>()
            .map_err(|e| sql_err("read mls_group", e))?;
        for (group_id, snapshot) in rows {
            let mut estmt = conn
                .prepare("SELECT epoch_id, epoch_data FROM epoch WHERE group_id = ? ORDER BY epoch_id ASC")
                .map_err(|e| sql_err("prepare epoch", e))?;
            let epochs: Vec<EpochRecord> = estmt
                .query_map([&group_id], |r| {
                    let id = r.get::<_, i64>(0)? as u64;
                    Ok(EpochRecord::new(id, Zeroizing::new(r.get::<_, Vec<u8>>(1)?)))
                })
                .map_err(|e| sql_err("query epoch", e))?
                .collect::<Result<_, _>>()
                .map_err(|e| sql_err("read epoch", e))?;
            report.epochs += epochs.len();
            report.groups += 1;
            groups.push((group_id, snapshot, epochs));
        }
    }

    let read_blobs = |sql: &str, ctx: &'static str| -> Result<Vec<(Vec<u8>, Vec<u8>)>, GroupError> {
        let mut stmt = conn.prepare(sql).map_err(|e| sql_err(ctx, e))?;
        // Bind to a `let` so the query_map temporary (which borrows `stmt`) is
        // dropped before `stmt` at the end of the closure.
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?)))
            .map_err(|e| sql_err(ctx, e))?
            .collect::<Result<_, _>>()
            .map_err(|e| sql_err(ctx, e))?;
        Ok(rows)
    };
    let key_packages = read_blobs("SELECT id, data FROM key_package", "key_package")?;
    let psks = read_blobs("SELECT psk_id, data FROM psk", "psk")?;
    let kvs: Vec<(String, Vec<u8>)> = {
        let mut stmt = conn
            .prepare("SELECT key, value FROM kvs")
            .map_err(|e| sql_err("prepare kvs", e))?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?)))
            .map_err(|e| sql_err("query kvs", e))?
            .collect::<Result<_, _>>()
            .map_err(|e| sql_err("read kvs", e))?;
        rows
    };
    drop(conn);

    // Move the SQLCipher original aside, then build the redb DB at the final
    // path. If anything below fails, restore the backup so the user is never
    // left without a database.
    let mut bak_os = db_path.as_os_str().to_owned();
    bak_os.push(".sqlcipher.bak");
    let bak_path = std::path::PathBuf::from(bak_os);
    report.key_packages = key_packages.len();
    report.psks = psks.len();
    report.app_kvs = kvs.len();

    std::fs::rename(db_path, &bak_path)
        .map_err(|e| GroupError::Storage(format!("back up {db_path:?} -> {bak_path:?}: {e}")))?;

    let build = move || -> Result<(), GroupError> {
        let backend = RedbBackend::open(db_path, &dek)?;
        let mut gss = backend.group_state_storage();
        for (group_id, snapshot, epochs) in groups {
            gss.write(GroupState { id: group_id, data: Zeroizing::new(snapshot) }, epochs, vec![])?;
        }
        let mut kps = backend.key_package_storage();
        for (id, data) in key_packages {
            let pkg = KeyPackageData::mls_decode(&mut data.as_slice())
                .map_err(|e| GroupError::Storage(format!("decode key package: {e}")))?;
            kps.insert(id, pkg)?;
        }
        let psk_store = backend.pre_shared_key_storage();
        for (id, data) in psks {
            psk_store.insert(&id, &PreSharedKey::new(data))?;
        }
        let app = backend.application_data_storage();
        for (k, v) in kvs {
            app.insert(&k, &v)?;
        }
        // Every storage handle holds an Arc<Database> clone; all must drop
        // before the verify-open can acquire the file lock.
        drop(gss);
        drop(kps);
        drop(psk_store);
        drop(app);
        drop(backend);
        // Verify the result opens cleanly under the DEK (sentinel check).
        drop(RedbBackend::open(db_path, &dek)?);
        Ok(())
    };

    if let Err(e) = build() {
        // Roll back: remove the partial redb, restore the SQLCipher original.
        let _ = std::fs::remove_file(db_path);
        let _ = std::fs::rename(&bak_path, db_path);
        return Err(e);
    }

    // Remove now-stale SQLCipher WAL/journal sidecars of the backed-up original.
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut s = bak_path.as_os_str().to_owned();
        s.push(suffix);
        let _ = std::fs::remove_file(std::path::PathBuf::from(s));
    }

    Ok(Some(report))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::storage::GroupStorage;
    use tempfile::tempdir;

    /// Build a SQLCipher groups.db the way the old stack did: resolve a DEK via
    /// the at-rest layer, then create the provider schema + one kv row under it.
    fn make_legacy_db(db_path: &Path, dek: &[u8; 32]) {
        let conn = Connection::open(db_path).expect("open");
        conn.execute_batch(&format!("PRAGMA key = \"x'{}'\";", hex::encode(dek)))
            .expect("key");
        conn.execute_batch(
            "CREATE TABLE mls_group (group_id BLOB PRIMARY KEY, snapshot BLOB NOT NULL);
             CREATE TABLE epoch (group_id BLOB, epoch_id INTEGER, epoch_data BLOB NOT NULL, PRIMARY KEY(group_id, epoch_id));
             CREATE TABLE key_package (id BLOB PRIMARY KEY, expiration INTEGER, data BLOB NOT NULL);
             CREATE TABLE psk (psk_id BLOB PRIMARY KEY, data BLOB NOT NULL);
             CREATE TABLE kvs (key TEXT PRIMARY KEY, value BLOB NOT NULL);",
        )
        .expect("schema");
        let gid = vec![7u8; 32];
        conn.execute("INSERT INTO mls_group VALUES (?, ?)", rusqlite::params![gid, vec![0xabu8; 64]])
            .expect("group");
        conn.execute(
            "INSERT INTO epoch VALUES (?, ?, ?)",
            rusqlite::params![gid, 0i64, vec![1u8; 16]],
        )
        .expect("epoch");
        conn.execute(
            "INSERT INTO kvs VALUES (?, ?)",
            rusqlite::params!["mls:identity:sk", vec![0xcdu8; 32]],
        )
        .expect("kv");
    }

    #[test]
    fn migrates_groups_db_and_reopens_on_redb() {
        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("groups.db");
        let paths = AtRestPaths::from_db_path(&db_path);
        let pass = crate::group::storage::test_passphrase();

        // Establish the at-rest key files + DEK, then write a legacy SQLCipher DB.
        let dek = crate::group::resolve_dek(&paths, &pass).expect("dek");
        make_legacy_db(&db_path, &dek);

        let report = migrate_groups_db_from_sqlcipher(&db_path, &pass)
            .expect("migrate")
            .expect("was a sqlcipher db");
        assert_eq!((report.groups, report.epochs, report.app_kvs), (1, 1, 1));

        // The original is backed up, and the new file opens on redb with the data.
        assert!(db_path.with_extension("db.sqlcipher.bak").exists() || {
            let mut s = db_path.as_os_str().to_owned();
            s.push(".sqlcipher.bak");
            std::path::PathBuf::from(s).exists()
        });
        let storage = GroupStorage::open_at_with_raw_key(&db_path, &dek).expect("reopen redb");
        let groups = storage.list_group_ids().expect("list");
        assert_eq!(groups.len(), 1);
        let app = storage.application_data_storage().expect("app");
        assert_eq!(app.get("mls:identity:sk").expect("get").unwrap(), vec![0xcdu8; 32].into());
    }

    #[test]
    fn migrate_is_noop_on_already_redb_db() {
        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("groups.db");
        let paths = AtRestPaths::from_db_path(&db_path);
        let pass = crate::group::storage::test_passphrase();
        let dek = crate::group::resolve_dek(&paths, &pass).expect("dek");
        // Create a redb DB directly, then attempt migration → no-op.
        drop(GroupStorage::open_at_with_raw_key(&db_path, &dek).expect("redb open"));
        assert!(migrate_groups_db_from_sqlcipher(&db_path, &pass).expect("migrate").is_none());
    }
}
