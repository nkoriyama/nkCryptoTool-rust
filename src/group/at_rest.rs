//! Post-Quantum at-rest key wrap for the MLS storage DB.
//!
//! The MLS sqlite database (`groups.db`) is encrypted by SQLCipher 4
//! (AES-256-CBC + HMAC-SHA512) using a 256-bit **data encryption key**
//! (DEK). This module wraps that DEK with a **hybrid X25519 + ML-KEM-768
//! X-Wing KEM** so the on-disk material is protected by both classical
//! and post-quantum hardness.
//!
//! ## Why
//!
//! SQLCipher alone uses only classical AES, so an adversary who copies
//! the `.db` file today and waits for a cryptographically-relevant
//! quantum computer could decrypt it later (*harvest now, decrypt
//! later*). Wrapping the DEK with ML-KEM-768 closes that gap and keeps
//! the at-rest layer consistent with the MLS protocol layer (which
//! already uses the same X-Wing KEM for Welcome / path-secret
//! encryption).
//!
//! ## Key hierarchy
//!
//! ```text
//!   passphrase (user)
//!     │
//!     │  PBKDF2-HMAC-SHA512 (256 000 iters) + AES-256-GCM
//!     ▼
//!   at-rest hybrid SK (X25519 SK || ML-KEM-768 DK)    ← `at-rest.key` file
//!     │
//!     │  X-Wing hpke_open against the KEK file
//!     ▼
//!   DEK (256-bit)                                     ← derived in memory
//!     │
//!     │  PRAGMA key = "x'<hex>'"
//!     ▼
//!   SQLCipher page key                                ← unlocks groups.db
//! ```
//!
//! ## File layout
//!
//! Three files live side-by-side under the user's MLS storage directory
//! (e.g. `~/.local/share/nkct/mls/`):
//!
//! | File           | Content                                                       |
//! |----------------|---------------------------------------------------------------|
//! | `at-rest.key`  | passphrase-encrypted hybrid SK (this module's envelope)       |
//! | `groups.db`    | SQLCipher-encrypted MLS state                                 |
//! | `groups.db.kek`| HPKE-sealed DEK (X-Wing KEM ciphertext + AEAD ciphertext)     |
//!
//! Losing any one of `at-rest.key`, `groups.db.kek`, or the passphrase
//! makes `groups.db` unrecoverable. The user must back up the first two
//! alongside the DB.
//!
//! ## at-rest.key envelope format
//!
//! ```text
//!   offset size  field
//!     0    8     magic = b"NKCT-AR1"
//!     8    1     version = 0x01
//!     9    1     KDF id  = 0x01 (PBKDF2-HMAC-SHA512)
//!    10    4     iterations (u32 BE) — default 256_000
//!    14   16     salt
//!    30   12     AEAD nonce
//!    42    N     AES-256-GCM ciphertext of (hybrid_sk(2432) || hybrid_pk(1216))
//!  42+N   16     AEAD tag
//! ```
//!
//! The 42-byte header is included as additional authenticated data
//! (AAD) on the AES-256-GCM operation, so any modification of KDF
//! params, salt, or nonce invalidates the tag check.
//!
//! ## KEK file format
//!
//! ```text
//!   offset size  field
//!     0    8     magic = b"NKCT-KEK"
//!     8    1     version = 0x01
//!     9    1     suite  = 0x01 (X-Wing X25519+ML-KEM-768)
//!    10    …     MLS-codec encoded HpkeCiphertext { kem_output, ciphertext }
//! ```
//!
//! Tampering with the KEK file is implicitly detected: a corrupted
//! `kem_output` decapsulates to a different shared secret, so the
//! HPKE AEAD on `ciphertext` fails to authenticate; a corrupted
//! `ciphertext` fails the same AEAD check directly.

use std::fs;
use std::path::{Path, PathBuf};

use mls_rs::CipherSuiteProvider;
use mls_rs_codec::{MlsDecode, MlsEncode};
use mls_rs_core::crypto::{CryptoProvider, HpkeCiphertext, HpkePublicKey, HpkeSecretKey};
use openssl::hash::MessageDigest;
use openssl::pkcs5::pbkdf2_hmac;
use openssl::symm::{Cipher, Crypter, Mode};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::group::crypto_adapter::{hybrid_cipher_suite, HybridCryptoProvider};
use crate::group::storage::GroupStorage;
use crate::group::types::GroupError;

// -----------------------------------------------------------------------------
// at-rest.key envelope constants
// -----------------------------------------------------------------------------

const ATREST_MAGIC: [u8; 8] = *b"NKCT-AR1";
const ATREST_VERSION: u8 = 0x01;
const ATREST_KDF_PBKDF2_SHA512: u8 = 0x01;
/// PBKDF2 iterations. Matches SQLCipher 4's own default so the user's
/// passphrase enjoys the same brute-force resistance at both layers.
const ATREST_KDF_ITERATIONS: u32 = 256_000;
const ATREST_SALT_LEN: usize = 16;
const ATREST_NONCE_LEN: usize = 12;
const ATREST_TAG_LEN: usize = 16;
const ATREST_HEADER_LEN: usize =
    8 /* magic */ + 1 /* version */ + 1 /* kdf id */ + 4 /* iters */ + ATREST_SALT_LEN + ATREST_NONCE_LEN;
const ATREST_AEAD_KEY_LEN: usize = 32;

/// Hybrid SK length: X25519 (32 B) || ML-KEM-768 decapsulation key (2400 B).
const HYBRID_SK_LEN: usize = 32 + 2400;
/// Hybrid PK length: X25519 (32 B) || ML-KEM-768 encapsulation key (1184 B).
const HYBRID_PK_LEN: usize = 32 + 1184;

// -----------------------------------------------------------------------------
// KEK file constants
// -----------------------------------------------------------------------------

const KEK_MAGIC: [u8; 8] = *b"NKCT-KEK";
const KEK_VERSION: u8 = 0x01;
const KEK_SUITE_XWING: u8 = 0x01;
const KEK_HEADER_LEN: usize = 8 + 1 + 1;

/// HPKE `info` string. Domain-separates the at-rest DEK encapsulation
/// from any other use of the hybrid suite (MLS Welcome, etc).
const HPKE_INFO: &[u8] = b"nkct-mls-at-rest-v1";

/// Length of the SQLCipher raw key (matches `PRAGMA key = "x'<64 hex>'"`).
pub const DEK_LEN: usize = 32;

// -----------------------------------------------------------------------------
// AtRestKey
// -----------------------------------------------------------------------------

/// Hybrid X25519 + ML-KEM-768 keypair used to wrap the SQLCipher DEK.
///
/// Generated once per device, persisted to `at-rest.key` (encrypted with
/// the user's passphrase via [`save_encrypted`](Self::save_encrypted)),
/// and reloaded on every CLI invocation via
/// [`load_encrypted`](Self::load_encrypted).
pub struct AtRestKey {
    sk: HpkeSecretKey,
    pk: HpkePublicKey,
}

impl std::fmt::Debug for AtRestKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the hybrid SK — it is the root of the at-rest
        // protection. The PK is technically safe to print but there is
        // no use case where we want to dump it through a Debug formatter.
        f.debug_struct("AtRestKey")
            .field("sk", &"<redacted>")
            .field("pk", &"<redacted>")
            .finish()
    }
}

impl AtRestKey {
    /// Generate a fresh hybrid keypair via the same X-Wing KEM the MLS
    /// protocol layer uses.
    pub fn generate() -> Result<Self, GroupError> {
        let suite = hybrid_suite()?;
        let (sk, pk) = suite
            .kem_generate()
            .map_err(|e| GroupError::Backend(format!("at-rest kem_generate: {e}")))?;
        debug_assert_eq!(sk.as_ref().len(), HYBRID_SK_LEN);
        debug_assert_eq!(pk.as_ref().len(), HYBRID_PK_LEN);
        Ok(Self { sk, pk })
    }

    /// Save this keypair to `path`, encrypted with `passphrase`. Existing
    /// content at `path` is overwritten atomically (write-to-temp +
    /// rename). On Unix, the file is created with `0o600` permissions.
    pub fn save_encrypted(
        &self,
        path: &Path,
        passphrase: &str,
    ) -> Result<(), GroupError> {
        if self.sk.as_ref().len() != HYBRID_SK_LEN || self.pk.as_ref().len() != HYBRID_PK_LEN {
            return Err(GroupError::Backend(format!(
                "hybrid key size mismatch: sk={} pk={} (expected {} / {})",
                self.sk.as_ref().len(),
                self.pk.as_ref().len(),
                HYBRID_SK_LEN,
                HYBRID_PK_LEN,
            )));
        }

        let mut salt = [0u8; ATREST_SALT_LEN];
        let mut nonce = [0u8; ATREST_NONCE_LEN];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);

        let mut header = Vec::with_capacity(ATREST_HEADER_LEN);
        header.extend_from_slice(&ATREST_MAGIC);
        header.push(ATREST_VERSION);
        header.push(ATREST_KDF_PBKDF2_SHA512);
        header.extend_from_slice(&ATREST_KDF_ITERATIONS.to_be_bytes());
        header.extend_from_slice(&salt);
        header.extend_from_slice(&nonce);
        debug_assert_eq!(header.len(), ATREST_HEADER_LEN);

        let key = derive_aead_key(passphrase, &salt, ATREST_KDF_ITERATIONS)?;

        let mut plaintext =
            Zeroizing::new(Vec::with_capacity(HYBRID_SK_LEN + HYBRID_PK_LEN));
        plaintext.extend_from_slice(self.sk.as_ref());
        plaintext.extend_from_slice(self.pk.as_ref());

        let (ciphertext, tag) = aes256gcm_encrypt(&key, &nonce, &header, &plaintext)?;

        let mut out = Vec::with_capacity(header.len() + ciphertext.len() + ATREST_TAG_LEN);
        out.extend_from_slice(&header);
        out.extend_from_slice(&ciphertext);
        out.extend_from_slice(&tag);

        write_atomic_secret(path, &out)?;
        Ok(())
    }

    /// Load and decrypt a keypair previously written by
    /// [`save_encrypted`](Self::save_encrypted).
    ///
    /// Returns `GroupError::Storage` on file errors, bad magic, version
    /// mismatch, or a passphrase that fails the AEAD tag check.
    pub fn load_encrypted(path: &Path, passphrase: &str) -> Result<Self, GroupError> {
        let bytes = fs::read(path)
            .map_err(|e| GroupError::Storage(format!("at-rest read {path:?}: {e}")))?;
        if bytes.len() < ATREST_HEADER_LEN + ATREST_TAG_LEN {
            return Err(GroupError::Storage(format!(
                "at-rest file too short: {} bytes",
                bytes.len()
            )));
        }

        if bytes[0..8] != ATREST_MAGIC {
            return Err(GroupError::Storage("at-rest file: bad magic".into()));
        }
        if bytes[8] != ATREST_VERSION {
            return Err(GroupError::Storage(format!(
                "at-rest file: unsupported version {:#x}",
                bytes[8]
            )));
        }
        if bytes[9] != ATREST_KDF_PBKDF2_SHA512 {
            return Err(GroupError::Storage(format!(
                "at-rest file: unsupported KDF id {:#x}",
                bytes[9]
            )));
        }
        let iters = u32::from_be_bytes(bytes[10..14].try_into().unwrap());
        let salt: [u8; ATREST_SALT_LEN] =
            bytes[14..14 + ATREST_SALT_LEN].try_into().unwrap();
        let nonce: [u8; ATREST_NONCE_LEN] = bytes
            [14 + ATREST_SALT_LEN..14 + ATREST_SALT_LEN + ATREST_NONCE_LEN]
            .try_into()
            .unwrap();

        let header = &bytes[..ATREST_HEADER_LEN];
        let body = &bytes[ATREST_HEADER_LEN..];
        let (ciphertext, tag) = body.split_at(body.len() - ATREST_TAG_LEN);

        let key = derive_aead_key(passphrase, &salt, iters)?;
        let plaintext = aes256gcm_decrypt(&key, &nonce, header, ciphertext, tag)?;

        if plaintext.len() != HYBRID_SK_LEN + HYBRID_PK_LEN {
            return Err(GroupError::Storage(format!(
                "at-rest payload size mismatch: {} (expected {})",
                plaintext.len(),
                HYBRID_SK_LEN + HYBRID_PK_LEN
            )));
        }

        let sk_bytes = plaintext[..HYBRID_SK_LEN].to_vec();
        let pk_bytes = plaintext[HYBRID_SK_LEN..].to_vec();
        Ok(Self {
            sk: HpkeSecretKey::from(sk_bytes),
            pk: HpkePublicKey::from(pk_bytes),
        })
    }

    /// Encapsulate a fresh 256-bit DEK against this key's public half
    /// and return both the serialized KEK file bytes and the DEK.
    ///
    /// The DEK is freshly random; callers store the KEK bytes alongside
    /// the SQLCipher DB (as `groups.db.kek`) and hand the DEK directly
    /// to [`GroupStorage::open_at_with_raw_key`].
    pub fn encapsulate_dek(
        &self,
    ) -> Result<(Vec<u8>, Zeroizing<[u8; DEK_LEN]>), GroupError> {
        let mut dek = Zeroizing::new([0u8; DEK_LEN]);
        OsRng.fill_bytes(dek.as_mut_slice());

        let suite = hybrid_suite()?;
        let hpke_ct = suite
            .hpke_seal(&self.pk, HPKE_INFO, None, dek.as_ref())
            .map_err(|e| GroupError::Backend(format!("at-rest hpke_seal: {e}")))?;

        let inner = hpke_ct
            .mls_encode_to_vec()
            .map_err(|e| GroupError::Storage(format!("KEK encode: {e}")))?;
        let mut bytes = Vec::with_capacity(KEK_HEADER_LEN + inner.len());
        bytes.extend_from_slice(&KEK_MAGIC);
        bytes.push(KEK_VERSION);
        bytes.push(KEK_SUITE_XWING);
        bytes.extend_from_slice(&inner);

        Ok((bytes, dek))
    }

    /// Decapsulate a previously-saved KEK file into the 256-bit DEK.
    ///
    /// A wrong at-rest key, a tampered KEK file, or a domain-separator
    /// mismatch will fail the HPKE AEAD check and surface as
    /// `GroupError::Backend`.
    pub fn decapsulate_dek(
        &self,
        kek_bytes: &[u8],
    ) -> Result<Zeroizing<[u8; DEK_LEN]>, GroupError> {
        if kek_bytes.len() < KEK_HEADER_LEN {
            return Err(GroupError::Storage("KEK file too short".into()));
        }
        if kek_bytes[0..8] != KEK_MAGIC {
            return Err(GroupError::Storage("KEK file: bad magic".into()));
        }
        if kek_bytes[8] != KEK_VERSION {
            return Err(GroupError::Storage(format!(
                "KEK file: unsupported version {:#x}",
                kek_bytes[8]
            )));
        }
        if kek_bytes[9] != KEK_SUITE_XWING {
            return Err(GroupError::Storage(format!(
                "KEK file: unsupported suite {:#x}",
                kek_bytes[9]
            )));
        }

        let mut inner = &kek_bytes[KEK_HEADER_LEN..];
        let hpke_ct = HpkeCiphertext::mls_decode(&mut inner)
            .map_err(|e| GroupError::Storage(format!("KEK decode: {e}")))?;

        let suite = hybrid_suite()?;
        let plaintext = suite
            .hpke_open(&hpke_ct, &self.sk, &self.pk, HPKE_INFO, None)
            .map_err(|e| {
                GroupError::Backend(format!(
                    "at-rest hpke_open (wrong key, tampered KEK, or wrong info?): {e}"
                ))
            })?;

        if plaintext.len() != DEK_LEN {
            return Err(GroupError::Backend(format!(
                "DEK size mismatch: {} (expected {})",
                plaintext.len(),
                DEK_LEN
            )));
        }
        let mut dek = Zeroizing::new([0u8; DEK_LEN]);
        dek.as_mut_slice().copy_from_slice(&plaintext);
        Ok(dek)
    }
}

// -----------------------------------------------------------------------------
// Orchestration
// -----------------------------------------------------------------------------

/// File paths for the three at-rest artefacts.
///
/// Convention: given a sqlite path `/foo/groups.db`, the at-rest key is
/// `/foo/at-rest.key` and the KEK is `/foo/groups.db.kek`. Callers that
/// need a different layout can construct this struct manually.
#[derive(Clone, Debug)]
pub struct AtRestPaths {
    pub db: PathBuf,
    pub kek: PathBuf,
    pub key: PathBuf,
}

impl AtRestPaths {
    /// Derive a default layout from a sqlite DB path.
    pub fn from_db_path(db: impl Into<PathBuf>) -> Self {
        let db = db.into();
        let kek = {
            let mut p = db.clone();
            p.as_mut_os_string().push(".kek");
            p
        };
        let key = db
            .parent()
            .map(|p| p.join("at-rest.key"))
            .unwrap_or_else(|| PathBuf::from("at-rest.key"));
        Self { db, kek, key }
    }
}

/// Open (or initialise) a SQLCipher-encrypted MLS storage with PQC
/// at-rest key wrapping.
///
/// On first use (when `paths.key` does not exist), generates a fresh
/// hybrid keypair and a fresh DEK, writing both `at-rest.key` and
/// `groups.db.kek` before opening the DB. On subsequent uses, loads
/// both files and recovers the DEK before opening the DB.
///
/// `passphrase` is the user-supplied secret. An empty passphrase is
/// rejected — the project policy mandates at-rest protection.
pub fn open_at_rest_storage(
    paths: &AtRestPaths,
    passphrase: &Zeroizing<String>,
) -> Result<GroupStorage, GroupError> {
    if passphrase.is_empty() {
        return Err(GroupError::Storage(
            "at-rest passphrase must not be empty — set NK_PASSPHRASE or enter one interactively".into(),
        ));
    }

    // Ensure parent dir exists for all three files. They share the same
    // parent under the default layout, so one create_dir_all suffices.
    if let Some(parent) = paths.db.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .map_err(|e| GroupError::Storage(format!("create_dir_all {parent:?}: {e}")))?;
        }
    }

    // 1. Load or generate the at-rest hybrid keypair.
    let at_rest_key = if paths.key.exists() {
        AtRestKey::load_encrypted(&paths.key, passphrase.as_str())?
    } else {
        let k = AtRestKey::generate()?;
        k.save_encrypted(&paths.key, passphrase.as_str())?;
        k
    };

    // 2. Load or generate the KEK (which carries the DEK).
    let dek = if paths.kek.exists() {
        let kek_bytes = fs::read(&paths.kek).map_err(|e| {
            GroupError::Storage(format!("read KEK {:?}: {e}", paths.kek))
        })?;
        at_rest_key.decapsulate_dek(&kek_bytes)?
    } else {
        let (kek_bytes, dek) = at_rest_key.encapsulate_dek()?;
        write_atomic_secret(&paths.kek, &kek_bytes)?;
        dek
    };

    // 3. Migrate a pre-SQLCipher plaintext DB in place, if one is found.
    //    Older builds shipped `groups.db` as an unencrypted sqlite file
    //    (the `sqlite-bundled` feature). Such a file cannot be opened with
    //    a SQLCipher key, so on upgrade we transparently re-encrypt it
    //    under the freshly-derived DEK before the open below. A no-op when
    //    `groups.db` is absent or already SQLCipher-encrypted.
    if is_plaintext_sqlite(&paths.db) {
        migrate_plaintext_to_sqlcipher(&paths.db, &dek)?;
    }

    // 4. Open SQLCipher with the raw DEK.
    GroupStorage::open_at_with_raw_key(&paths.db, &dek)
}

/// Return `true` if `path` is an **unencrypted** sqlite database — i.e.
/// its first 16 bytes are the literal `b"SQLite format 3\0"` header.
///
/// A SQLCipher-encrypted DB has those 16 bytes occupied by the random
/// per-database salt instead, so the magic never matches. A missing,
/// empty, or sub-16-byte file is treated as "not a plaintext DB" (the
/// caller's normal open path then creates/initialises it).
fn is_plaintext_sqlite(path: &Path) -> bool {
    const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";
    let mut hdr = [0u8; 16];
    match fs::File::open(path).and_then(|mut f| {
        use std::io::Read as _;
        f.read_exact(&mut hdr)
    }) {
        Ok(()) => &hdr == SQLITE_MAGIC,
        Err(_) => false,
    }
}

/// Re-encrypt the plaintext sqlite database at `db` into a SQLCipher
/// database keyed by `dek`, replacing the original file atomically.
///
/// Uses SQLCipher's `sqlcipher_export()`: the plaintext DB is opened with
/// no key, a fresh encrypted target is `ATTACH`ed under the raw DEK, all
/// schema and data are copied across, and the target is then verified to
/// open under the same key before it atomically replaces `db`. The
/// original plaintext is only unlinked (via the rename) **after** the
/// encrypted copy is proven readable, so a failure at any step leaves the
/// plaintext untouched for a retry.
///
/// Stale rollback-journal / WAL sidecars of the old plaintext DB are
/// removed afterwards so they cannot be mis-applied to the new encrypted
/// file on the next open.
fn migrate_plaintext_to_sqlcipher(
    db: &Path,
    dek: &[u8; 32],
) -> Result<(), GroupError> {
    use rusqlite::Connection;

    // 64 lowercase hex digits — safe to splice into the SQL `KEY` clause.
    let hex = Zeroizing::new(hex::encode(dek));
    debug_assert_eq!(hex.len(), 64);

    // Encrypted output goes to an unpredictable temp name beside the DB,
    // matching write_atomic_secret's anti-symlink / anti-collision policy.
    let mut rand_suffix = [0u8; 16];
    OsRng.fill_bytes(&mut rand_suffix);
    let tmp = {
        let base = db.file_name().and_then(|s| s.to_str()).unwrap_or("groups.db");
        let name = format!(".{base}.sqlcipher-mig.{}.tmp", hex::encode(rand_suffix));
        match db.parent().filter(|p| !p.as_os_str().is_empty()) {
            Some(dir) => dir.join(name),
            None => PathBuf::from(name),
        }
    };
    // ATTACH refuses to overwrite, and a stale temp would corrupt the
    // export, so clear any leftover from a previous crashed run.
    let _ = fs::remove_file(&tmp);

    let export = || -> Result<(), GroupError> {
        let conn = Connection::open(db)
            .map_err(|e| GroupError::Storage(format!("open plaintext {db:?}: {e}")))?;
        // Fold any committed WAL frames back into the main file so the
        // export sees the complete committed state.
        let _ = conn.pragma_update(None, "wal_checkpoint", "TRUNCATE");
        // The assembled SQL embeds the raw key, so keep the whole
        // statement string in a Zeroizing buffer — `hex` alone being
        // Zeroizing is not enough once it is spliced into a plain String.
        let attach = Zeroizing::new(format!(
            "ATTACH DATABASE ?1 AS encrypted KEY \"x'{}'\"",
            hex.as_str()
        ));
        conn.execute(attach.as_str(), rusqlite::params![tmp.to_string_lossy()])
            .map_err(|e| GroupError::Storage(format!("attach encrypted target: {e}")))?;
        conn.query_row("SELECT sqlcipher_export('encrypted')", [], |_| Ok(()))
            .map_err(|e| GroupError::Storage(format!("sqlcipher_export: {e}")))?;
        conn.execute_batch("DETACH DATABASE encrypted")
            .map_err(|e| GroupError::Storage(format!("detach encrypted target: {e}")))?;
        Ok(())
    };

    if let Err(e) = export() {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }

    // Verify the encrypted copy actually opens under the DEK before we
    // destroy the plaintext. A read of sqlite_master fails (NOTADB) if the
    // key or file is wrong.
    let verify = || -> Result<(), GroupError> {
        let conn = Connection::open(&tmp)
            .map_err(|e| GroupError::Storage(format!("verify open {tmp:?}: {e}")))?;
        let pragma = Zeroizing::new(format!("PRAGMA key = \"x'{}'\";", hex.as_str()));
        conn.execute_batch(pragma.as_str())
            .map_err(|e| GroupError::Storage(format!("verify key: {e}")))?;
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
            r.get::<_, i64>(0)
        })
        .map(|_| ())
        .map_err(|e| GroupError::Storage(format!("verify read (bad migration?): {e}")))
    };
    if let Err(e) = verify() {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }

    // Point of no return: atomically swap the encrypted copy over the
    // plaintext original.
    if let Err(e) = fs::rename(&tmp, db) {
        let _ = fs::remove_file(&tmp);
        return Err(GroupError::Storage(format!(
            "replace {db:?} with migrated copy: {e}"
        )));
    }

    // Drop now-stale plaintext sidecars (best-effort).
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar = db.as_os_str().to_owned();
        sidecar.push(suffix);
        let _ = fs::remove_file(PathBuf::from(sidecar));
    }

    eprintln!(
        "[at-rest] migrated plaintext {db:?} to SQLCipher (PQC-wrapped DEK)"
    );
    Ok(())
}

// -----------------------------------------------------------------------------
// Internals
// -----------------------------------------------------------------------------

fn hybrid_suite(
) -> Result<<HybridCryptoProvider as CryptoProvider>::CipherSuiteProvider, GroupError> {
    HybridCryptoProvider::new()
        .cipher_suite_provider(hybrid_cipher_suite())
        .ok_or_else(|| {
            GroupError::Backend(
                "hybrid cipher suite (0xF101) construction failed; \
                 is OpenSSL configured with X25519 + SHA-256 + AES-128-GCM?"
                    .into(),
            )
        })
}

fn derive_aead_key(
    passphrase: &str,
    salt: &[u8],
    iters: u32,
) -> Result<Zeroizing<[u8; ATREST_AEAD_KEY_LEN]>, GroupError> {
    let mut key = Zeroizing::new([0u8; ATREST_AEAD_KEY_LEN]);
    pbkdf2_hmac(
        passphrase.as_bytes(),
        salt,
        iters as usize,
        MessageDigest::sha512(),
        key.as_mut_slice(),
    )
    .map_err(|e| GroupError::Storage(format!("at-rest PBKDF2: {e}")))?;
    Ok(key)
}

fn aes256gcm_encrypt(
    key: &[u8; ATREST_AEAD_KEY_LEN],
    nonce: &[u8; ATREST_NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; ATREST_TAG_LEN]), GroupError> {
    let mut crypter = Crypter::new(Cipher::aes_256_gcm(), Mode::Encrypt, key, Some(nonce))
        .map_err(|e| GroupError::Storage(format!("at-rest aes init: {e}")))?;
    crypter
        .aad_update(aad)
        .map_err(|e| GroupError::Storage(format!("at-rest aes aad: {e}")))?;

    let mut out = vec![0u8; plaintext.len() + Cipher::aes_256_gcm().block_size()];
    let n1 = crypter
        .update(plaintext, &mut out)
        .map_err(|e| GroupError::Storage(format!("at-rest aes update: {e}")))?;
    let n2 = crypter
        .finalize(&mut out[n1..])
        .map_err(|e| GroupError::Storage(format!("at-rest aes finalize: {e}")))?;
    out.truncate(n1 + n2);

    let mut tag = [0u8; ATREST_TAG_LEN];
    crypter
        .get_tag(&mut tag)
        .map_err(|e| GroupError::Storage(format!("at-rest aes get_tag: {e}")))?;
    Ok((out, tag))
}

fn aes256gcm_decrypt(
    key: &[u8; ATREST_AEAD_KEY_LEN],
    nonce: &[u8; ATREST_NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>, GroupError> {
    let mut crypter = Crypter::new(Cipher::aes_256_gcm(), Mode::Decrypt, key, Some(nonce))
        .map_err(|e| GroupError::Storage(format!("at-rest aes init: {e}")))?;
    crypter
        .aad_update(aad)
        .map_err(|e| GroupError::Storage(format!("at-rest aes aad: {e}")))?;
    crypter
        .set_tag(tag)
        .map_err(|e| GroupError::Storage(format!("at-rest aes set_tag: {e}")))?;

    let mut out = Zeroizing::new(vec![
        0u8;
        ciphertext.len() + Cipher::aes_256_gcm().block_size()
    ]);
    // A bad passphrase, tampered ciphertext, or tampered AAD all fail at
    // `finalize` time (GCM tag mismatch). Don't reveal which it was.
    let n1 = crypter.update(ciphertext, &mut out).map_err(|_| {
        GroupError::Storage(
            "at-rest decrypt failed (bad passphrase or corrupted file)".into(),
        )
    })?;
    let n2 = crypter.finalize(&mut out[n1..]).map_err(|_| {
        GroupError::Storage(
            "at-rest decrypt failed (bad passphrase or corrupted file)".into(),
        )
    })?;
    out.truncate(n1 + n2);
    Ok(out)
}

/// Write `data` to `path` atomically with `0o600` permissions on Unix.
/// Uses the temp-file-then-rename pattern so a half-written file never
/// replaces a good one.
///
/// The temp file is created with `O_CREAT | O_EXCL` and mode `0o600`
/// **in a single open** on Unix — there is no create-then-chmod window
/// during which the file is world-readable, and `O_EXCL` makes the open
/// fail rather than follow a symlink an attacker pre-planted at the temp
/// path. The temp name carries a 128-bit random suffix so a local
/// attacker cannot guess it ahead of time (and so a stale temp file from
/// a crashed run never collides with `O_EXCL`).
fn write_atomic_secret(path: &Path, data: &[u8]) -> Result<(), GroupError> {
    use std::io::Write as _;

    let base = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("at-rest");
    let mut rand_suffix = [0u8; 16];
    OsRng.fill_bytes(&mut rand_suffix);
    let tmp_name = format!(".{base}.{}.tmp", hex::encode(rand_suffix));
    let tmp = match path.parent().filter(|p| !p.as_os_str().is_empty()) {
        Some(dir) => dir.join(tmp_name),
        None => PathBuf::from(tmp_name),
    };

    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    let mut file = opts
        .open(&tmp)
        .map_err(|e| GroupError::Storage(format!("create temp {tmp:?}: {e}")))?;

    // Best-effort cleanup of the temp file if the write or rename fails,
    // so a partial secret blob is never left behind on disk.
    let write_res = file
        .write_all(data)
        .and_then(|()| file.sync_all())
        .map_err(|e| GroupError::Storage(format!("write {tmp:?}: {e}")));
    if let Err(e) = write_res {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    drop(file);

    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(GroupError::Storage(format!(
            "rename {tmp:?} -> {path:?}: {e}"
        )));
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    const TEST_PASS: &str = "nkct-at-rest-test-passphrase";

    #[test]
    fn generate_then_encapsulate_decapsulate_roundtrips_dek() {
        let key = AtRestKey::generate().expect("generate");
        let (kek_bytes, dek_a) = key.encapsulate_dek().expect("encapsulate");
        let dek_b = key.decapsulate_dek(&kek_bytes).expect("decapsulate");
        assert_eq!(dek_a.as_ref(), dek_b.as_ref(), "DEK must round-trip");
        assert_eq!(dek_a.len(), DEK_LEN);
    }

    #[test]
    fn save_load_roundtrip_preserves_encapsulation() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("at-rest.key");

        let original = AtRestKey::generate().expect("generate");
        let (kek_bytes, dek) = original.encapsulate_dek().expect("encap");

        original.save_encrypted(&path, TEST_PASS).expect("save");
        assert!(path.exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = fs::metadata(&path).expect("metadata");
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }

        let reloaded = AtRestKey::load_encrypted(&path, TEST_PASS).expect("load");
        let dek_from_reload = reloaded.decapsulate_dek(&kek_bytes).expect("decap");
        assert_eq!(
            dek.as_ref(),
            dek_from_reload.as_ref(),
            "reloaded key must decapsulate the same DEK"
        );
    }

    #[test]
    fn wrong_passphrase_fails_load() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("at-rest.key");
        let original = AtRestKey::generate().expect("generate");
        original.save_encrypted(&path, "right").expect("save");

        let err = AtRestKey::load_encrypted(&path, "wrong")
            .expect_err("wrong passphrase must fail");
        match err {
            GroupError::Storage(msg) => {
                assert!(
                    msg.contains("at-rest decrypt"),
                    "expected at-rest decrypt error, got: {msg}"
                );
            }
            other => panic!("expected Storage error, got {other:?}"),
        }
    }

    #[test]
    fn tampered_kek_fails_decapsulation() {
        let key = AtRestKey::generate().expect("generate");
        let (mut kek_bytes, _dek) = key.encapsulate_dek().expect("encap");

        // Flip a byte inside the HPKE ciphertext portion (skip our
        // 10-byte header).
        let idx = KEK_HEADER_LEN + (kek_bytes.len() - KEK_HEADER_LEN) / 2;
        kek_bytes[idx] ^= 0x01;

        let err = key
            .decapsulate_dek(&kek_bytes)
            .expect_err("tampered KEK must fail");
        match err {
            GroupError::Backend(msg) => {
                assert!(
                    msg.contains("hpke_open"),
                    "expected hpke_open error, got: {msg}"
                );
            }
            // Decode error is also acceptable if the tamper hit a
            // length-prefixed field instead of an AEAD-protected one.
            GroupError::Storage(msg) => {
                assert!(
                    msg.contains("KEK decode") || msg.contains("size mismatch"),
                    "unexpected Storage error: {msg}"
                );
            }
            other => panic!("expected Backend or Storage error, got {other:?}"),
        }
    }

    #[test]
    fn bad_magic_is_rejected() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("at-rest.key");
        let original = AtRestKey::generate().expect("generate");
        original.save_encrypted(&path, TEST_PASS).expect("save");

        // Corrupt the magic.
        let mut bytes = fs::read(&path).expect("read");
        bytes[0] = b'X';
        fs::write(&path, &bytes).expect("write");

        let err = AtRestKey::load_encrypted(&path, TEST_PASS).expect_err("bad magic");
        match err {
            GroupError::Storage(msg) => assert!(msg.contains("bad magic")),
            other => panic!("expected Storage error, got {other:?}"),
        }
    }

    #[test]
    fn cross_key_decapsulation_fails() {
        let key_a = AtRestKey::generate().expect("a");
        let key_b = AtRestKey::generate().expect("b");
        let (kek, _dek) = key_a.encapsulate_dek().expect("encap by a");

        let err = key_b
            .decapsulate_dek(&kek)
            .expect_err("decap with wrong key must fail");
        assert!(matches!(err, GroupError::Backend(_)));
    }

    #[test]
    fn open_at_rest_storage_first_use_creates_all_artefacts() {
        let dir = tempdir().expect("tempdir");
        let paths = AtRestPaths::from_db_path(dir.path().join("groups.db"));
        let pass = Zeroizing::new(TEST_PASS.to_string());

        let storage = open_at_rest_storage(&paths, &pass).expect("first open");
        assert!(paths.db.exists(), "DB created");
        assert!(paths.kek.exists(), "KEK created");
        assert!(paths.key.exists(), "at-rest key created");

        // List should work — i.e. the SQLCipher key matches and schema
        // initialisation succeeded.
        assert!(storage.list_group_ids().expect("list").is_empty());
    }

    #[test]
    fn open_at_rest_storage_second_use_reopens() {
        let dir = tempdir().expect("tempdir");
        let paths = AtRestPaths::from_db_path(dir.path().join("groups.db"));
        let pass = Zeroizing::new(TEST_PASS.to_string());

        drop(open_at_rest_storage(&paths, &pass).expect("first"));
        let storage2 = open_at_rest_storage(&paths, &pass).expect("second");
        assert!(storage2.list_group_ids().expect("list").is_empty());
    }

    #[test]
    fn open_at_rest_storage_wrong_passphrase_fails() {
        let dir = tempdir().expect("tempdir");
        let paths = AtRestPaths::from_db_path(dir.path().join("groups.db"));

        drop(
            open_at_rest_storage(&paths, &Zeroizing::new("right".to_string()))
                .expect("first"),
        );
        let err = open_at_rest_storage(&paths, &Zeroizing::new("wrong".to_string()))
            .expect_err("wrong pass");
        assert!(matches!(err, GroupError::Storage(_)));
    }

    #[test]
    fn empty_passphrase_is_rejected() {
        let dir = tempdir().expect("tempdir");
        let paths = AtRestPaths::from_db_path(dir.path().join("groups.db"));
        let err = open_at_rest_storage(&paths, &Zeroizing::new(String::new()))
            .expect_err("empty pass");
        match err {
            GroupError::Storage(msg) => assert!(msg.contains("passphrase")),
            other => panic!("expected Storage error, got {other:?}"),
        }
    }

    #[test]
    fn at_rest_paths_layout_under_db_dir() {
        let paths = AtRestPaths::from_db_path("/tmp/example/groups.db");
        assert_eq!(paths.db, PathBuf::from("/tmp/example/groups.db"));
        assert_eq!(paths.kek, PathBuf::from("/tmp/example/groups.db.kek"));
        assert_eq!(paths.key, PathBuf::from("/tmp/example/at-rest.key"));
    }

    /// Create a plaintext (unencrypted) sqlite DB with one table + row.
    fn make_plaintext_db(path: &Path) {
        let conn = rusqlite::Connection::open(path).expect("open plaintext");
        conn.execute_batch(
            "CREATE TABLE legacy (id INTEGER PRIMARY KEY, note TEXT);
             INSERT INTO legacy (note) VALUES ('pre-sqlcipher row');",
        )
        .expect("seed plaintext");
    }

    #[test]
    fn is_plaintext_sqlite_detects_unencrypted_db() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("groups.db");
        make_plaintext_db(&path);
        assert!(is_plaintext_sqlite(&path), "fresh sqlite must be detected");

        // Missing file is not plaintext.
        assert!(!is_plaintext_sqlite(&dir.path().join("absent.db")));
    }

    #[test]
    fn is_plaintext_sqlite_rejects_sqlcipher_db() {
        // A SQLCipher-encrypted DB has a random salt where the magic
        // header would be, so detection must return false.
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("groups.db");
        let dek = [0x5Au8; 32];
        drop(GroupStorage::open_at_with_raw_key(&path, &dek).expect("encrypted open"));
        assert!(
            !is_plaintext_sqlite(&path),
            "encrypted DB must not be flagged as plaintext"
        );
    }

    #[test]
    fn migrate_plaintext_preserves_data_and_encrypts() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("groups.db");
        make_plaintext_db(&path);
        let dek = [0x11u8; 32];

        migrate_plaintext_to_sqlcipher(&path, &dek).expect("migrate");

        // No longer plaintext on disk.
        assert!(!is_plaintext_sqlite(&path), "DB must be encrypted post-migration");

        // Data survived and is readable only under the DEK.
        let hex = hex::encode(dek);
        let conn = rusqlite::Connection::open(&path).expect("reopen");
        conn.execute_batch(&format!("PRAGMA key = \"x'{hex}'\";"))
            .expect("key");
        let note: String = conn
            .query_row("SELECT note FROM legacy WHERE id = 1", [], |r| r.get(0))
            .expect("row survived");
        assert_eq!(note, "pre-sqlcipher row");
    }

    #[test]
    fn open_at_rest_storage_migrates_legacy_plaintext_db() {
        let dir = tempdir().expect("tempdir");
        let paths = AtRestPaths::from_db_path(dir.path().join("groups.db"));
        // Simulate an upgrade: a plaintext groups.db with no at-rest.key
        // or KEK alongside it.
        make_plaintext_db(&paths.db);
        assert!(is_plaintext_sqlite(&paths.db));

        let pass = Zeroizing::new(TEST_PASS.to_string());
        let storage = open_at_rest_storage(&paths, &pass).expect("open migrates");

        // All three artefacts now exist and the DB is encrypted.
        assert!(paths.key.exists() && paths.kek.exists());
        assert!(!is_plaintext_sqlite(&paths.db));
        // MLS schema initialised on top of the migrated tables.
        assert!(storage.list_group_ids().expect("list").is_empty());

        // Reopening with the same passphrase still works (DEK round-trips
        // through the KEK we just wrote).
        drop(storage);
        let storage2 = open_at_rest_storage(&paths, &pass).expect("reopen");
        assert!(storage2.list_group_ids().expect("list").is_empty());
    }
}
