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
use mls_rs_core::crypto::{HpkeCiphertext, HpkePublicKey, HpkeSecretKey};
use openssl::hash::MessageDigest;
use openssl::pkcs5::pbkdf2_hmac;
use openssl::symm::{Cipher, Crypter, Mode};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::group::crypto_adapter::{
    build_at_rest_suite, build_at_rest_suite_legacy, HybridCipherSuiteProvider, HybridSuite,
};
use crate::group::rollback;
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
/// Legacy KEK version: HPKE `info` is the bare [`HPKE_INFO`] constant, with
/// no per-DB binding. Still readable so DBs written before per-DB binding
/// existed keep opening; rewritten as [`KEK_VERSION_BOUND`] on the next
/// rekey.
const KEK_VERSION_LEGACY: u8 = 0x01;
/// Current KEK version: HPKE `info` is `HPKE_INFO || binding`, where the
/// binding is a per-DB identifier (the DB file name). This stops a KEK
/// from one DB being swapped in for another when several DBs share one
/// at-rest hybrid key — the `info` mismatch fails the HPKE AEAD check.
const KEK_VERSION_BOUND: u8 = 0x02;
/// Legacy KEK suite: X-Wing KEM with an HKDF-SHA256 / AES-128-GCM HPKE
/// (the `0xF101` MLS suite's parameters). Still readable; rewritten as
/// [`KEK_SUITE_XWING_AES256`] on the next rekey.
const KEK_SUITE_XWING: u8 = 0x01;
/// Current KEK suite: X-Wing KEM with an HKDF-SHA512 / AES-256-GCM HPKE
/// (`0xF102`). The AES-256 AEAD removes the Grover halving concern on the
/// key that wraps the DEK, making the at-rest layer PQ-safe end to end.
const KEK_SUITE_XWING_AES256: u8 = 0x02;
/// Anti-rollback KEK version: HPKE `info` is `bound_info(binding) ||
/// counter(u64 BE)`, where `counter` is the per-DB monotonic rollback
/// counter (see [`crate::group::rollback`]). A KEK sealed under counter `c`
/// only decapsulates when the current counter is still `c`; a restored
/// older KEK (sealed under a smaller `c`) fails the AEAD check, detecting
/// the rollback. Written only when `NK_ROLLBACK_POLICY` is enabled.
const KEK_VERSION_COUNTER_BOUND: u8 = 0x03;
const KEK_HEADER_LEN: usize = 8 + 1 + 1;

/// HPKE `info` prefix. Domain-separates the at-rest DEK encapsulation
/// from any other use of the hybrid suite (MLS Welcome, etc). For
/// [`KEK_VERSION_BOUND`] KEKs the per-DB binding is appended to this.
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
    /// protocol layer uses. (The KEM is identical across at-rest suite
    /// versions, so the keypair is valid for both AES-128 and AES-256
    /// KEKs.)
    pub fn generate() -> Result<Self, GroupError> {
        let suite = at_rest_suite()?;
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
    /// `binding` is a per-DB identifier (the DB file name) mixed into the
    /// HPKE `info`, so the resulting KEK only decapsulates for a DB opened
    /// with the same binding. `counter` is the optional anti-rollback
    /// monotonic counter (see [`crate::group::rollback`]): `Some(c)` writes
    /// a version-`0x03` KEK whose `info` also binds `c`, so a restored older
    /// KEK (sealed under a smaller counter) fails to decapsulate; `None`
    /// writes the version-`0x02` per-DB-bound KEK. The DEK is freshly
    /// random; callers store the KEK bytes alongside the SQLCipher DB (as
    /// `groups.db.kek`) and hand the DEK directly to
    /// [`GroupStorage::open_at_with_raw_key`].
    pub fn encapsulate_dek(
        &self,
        binding: &[u8],
        counter: Option<u64>,
    ) -> Result<(Vec<u8>, Zeroizing<[u8; DEK_LEN]>), GroupError> {
        let mut dek = Zeroizing::new([0u8; DEK_LEN]);
        OsRng.fill_bytes(dek.as_mut_slice());

        let (version, info) = match counter {
            None => (KEK_VERSION_BOUND, bound_info(binding)),
            Some(c) => (KEK_VERSION_COUNTER_BOUND, counter_bound_info(binding, c)),
        };
        let suite = at_rest_suite()?;
        let hpke_ct = suite
            .hpke_seal(&self.pk, &info, None, dek.as_ref())
            .map_err(|e| GroupError::Backend(format!("at-rest hpke_seal: {e}")))?;

        let inner = hpke_ct
            .mls_encode_to_vec()
            .map_err(|e| GroupError::Storage(format!("KEK encode: {e}")))?;
        let mut bytes = Vec::with_capacity(KEK_HEADER_LEN + inner.len());
        bytes.extend_from_slice(&KEK_MAGIC);
        bytes.push(version);
        bytes.push(KEK_SUITE_XWING_AES256);
        bytes.extend_from_slice(&inner);

        Ok((bytes, dek))
    }

    /// Decapsulate a previously-saved KEK file into the 256-bit DEK.
    ///
    /// `binding` must match the value passed to [`encapsulate_dek`] for a
    /// bound KEK; it is ignored for a legacy [`KEK_VERSION_LEGACY`] KEK. For
    /// a [`KEK_VERSION_COUNTER_BOUND`] (`0x03`) KEK, `counter` must be
    /// `Some` and equal to the value the KEK was sealed under, else the HPKE
    /// AEAD check fails (this is how an at-rest rollback is detected). A
    /// wrong at-rest key, tampered KEK, wrong binding, or wrong counter all
    /// surface as `GroupError::Backend`.
    pub fn decapsulate_dek(
        &self,
        kek_bytes: &[u8],
        binding: &[u8],
        counter: Option<u64>,
    ) -> Result<Zeroizing<[u8; DEK_LEN]>, GroupError> {
        if kek_bytes.len() < KEK_HEADER_LEN {
            return Err(GroupError::Storage("KEK file too short".into()));
        }
        if kek_bytes[0..8] != KEK_MAGIC {
            return Err(GroupError::Storage("KEK file: bad magic".into()));
        }
        let info = match kek_bytes[8] {
            KEK_VERSION_LEGACY => HPKE_INFO.to_vec(),
            KEK_VERSION_BOUND => bound_info(binding),
            KEK_VERSION_COUNTER_BOUND => {
                let c = counter.ok_or_else(|| {
                    GroupError::Storage(
                        "KEK is anti-rollback (v0x03) but no rollback counter is available; \
                         set NK_ROLLBACK_POLICY to the policy this DB was created under"
                            .into(),
                    )
                })?;
                counter_bound_info(binding, c)
            }
            other => {
                return Err(GroupError::Storage(format!(
                    "KEK file: unsupported version {other:#x}"
                )))
            }
        };
        // The suite byte selects the HPKE crypto used to seal this KEK.
        // Legacy `0x01` KEKs (AES-128) stay readable; new KEKs are `0x02`
        // (AES-256). The KEM is identical across both, so `self`'s keypair
        // opens either.
        let suite = match kek_bytes[9] {
            KEK_SUITE_XWING => at_rest_suite_legacy()?,
            KEK_SUITE_XWING_AES256 => at_rest_suite()?,
            other => {
                return Err(GroupError::Storage(format!(
                    "KEK file: unsupported suite {other:#x}"
                )))
            }
        };

        let mut inner = &kek_bytes[KEK_HEADER_LEN..];
        let hpke_ct = HpkeCiphertext::mls_decode(&mut inner)
            .map_err(|e| GroupError::Storage(format!("KEK decode: {e}")))?;
        if !inner.is_empty() {
            // A well-formed KEK is exactly header + one MLS-encoded
            // HpkeCiphertext. Trailing bytes mean corruption or tampering.
            return Err(GroupError::Storage(format!(
                "KEK file: {} trailing byte(s) after ciphertext",
                inner.len()
            )));
        }

        // hpke_open returns a plain Vec<u8> holding the DEK; wrap it so the
        // root key is wiped from the heap when this function returns rather
        // than lingering in a freed allocation.
        let plaintext = Zeroizing::new(
            suite
                .hpke_open(&hpke_ct, &self.sk, &self.pk, &info, None)
                .map_err(|e| {
                    GroupError::Backend(format!(
                        "at-rest hpke_open (wrong key, tampered KEK, or wrong info?): {e}"
                    ))
                })?,
        );

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

    /// Like [`from_db_path`](Self::from_db_path) but keeps the hybrid key
    /// file beside the DB as `<db>.at-rest.key` instead of a shared
    /// `at-rest.key` in the parent directory.
    ///
    /// Use this when several independent databases live in one directory:
    /// a shared `at-rest.key` would otherwise be a hazard if two of them
    /// are initialised concurrently (both would generate and race to write
    /// the single key file, leaving one DB's KEK wrapped under a hybrid key
    /// that no longer exists on disk). A DB-specific key file keeps each
    /// at-rest triple self-contained. The same passphrase still unlocks
    /// every per-DB key file.
    pub fn beside_db(db: impl Into<PathBuf>) -> Self {
        let db = db.into();
        let with_suffix = |suffix: &str| {
            let mut s = db.clone().into_os_string();
            s.push(suffix);
            PathBuf::from(s)
        };
        Self {
            kek: with_suffix(".kek"),
            key: with_suffix(".at-rest.key"),
            db,
        }
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
    let dek = resolve_dek(paths, passphrase)?;
    GroupStorage::open_at_with_raw_key(&paths.db, &dek)
}

/// Resolve the SQLCipher DEK for the database at `paths.db`, performing all
/// the at-rest housekeeping a caller needs before opening their own
/// connection: it ensures the parent directory exists, loads or generates
/// the hybrid keypair (`at-rest.key`) and KEK (`<db>.kek`), finishes any
/// rekey interrupted by a crash, and migrates a legacy plaintext DB in
/// place. The returned raw DEK is fed to `PRAGMA key = "x'<hex>'"`.
///
/// This is the database-agnostic core of [`open_at_rest_storage`]; the
/// inbox server reuses it to protect its own sqlite file (see
/// `network::inbox`). An empty passphrase is rejected — the project policy
/// mandates at-rest protection.
pub fn resolve_dek(
    paths: &AtRestPaths,
    passphrase: &Zeroizing<String>,
) -> Result<Zeroizing<[u8; DEK_LEN]>, GroupError> {
    let counter = rollback::counter_for(rollback::RollbackPolicy::from_env(), &paths.db)?;
    resolve_dek_with(paths, passphrase, counter.as_deref())
}

/// [`resolve_dek`] with an explicit (optional) anti-rollback counter. The
/// public wrapper builds the counter from `NK_ROLLBACK_POLICY`; this seam
/// lets tests inject an in-memory counter. `None` reproduces the exact
/// counter-free behaviour (version-`0x02` KEKs).
pub(crate) fn resolve_dek_with(
    paths: &AtRestPaths,
    passphrase: &Zeroizing<String>,
    counter: Option<&dyn rollback::RollbackCounter>,
) -> Result<Zeroizing<[u8; DEK_LEN]>, GroupError> {
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

    // 2. Load or generate the KEK (which carries the DEK), resolving any
    //    crash-interrupted rekey and detecting an at-rest rollback when a
    //    counter is in play.
    let binding = db_binding(&paths.db);
    let dek = if paths.kek.exists() {
        resolve_kek_to_dek(paths, &at_rest_key, &binding, counter)?
    } else {
        // First use: seal the KEK under the counter's *current* value
        // (0 if never advanced — there is no earlier state to roll back to
        // yet). The counter only advances on rekey.
        let cval = counter.map(|c| c.current()).transpose()?;
        let (kek_bytes, dek) = at_rest_key.encapsulate_dek(&binding, cval)?;
        write_atomic_secret(&paths.kek, &kek_bytes)?;
        dek
    };

    // 3. Migrate a pre-SQLCipher plaintext DB in place, if one is found.
    //    Older builds shipped the DB as an unencrypted sqlite file (the
    //    `sqlite-bundled` feature). Such a file cannot be opened with a
    //    SQLCipher key, so on upgrade we transparently re-encrypt it under
    //    the freshly-derived DEK before the caller opens it. A no-op when
    //    the DB is absent or already SQLCipher-encrypted.
    if is_plaintext_sqlite(&paths.db) {
        migrate_plaintext_to_sqlcipher(&paths.db, &dek)?;
    }

    Ok(dek)
}

/// Decapsulate the live KEK to the DEK, resolving any crash-interrupted
/// rekey on the way. Two paths:
///
/// - **No counter** (`NK_ROLLBACK_POLICY=off`): decapsulate the live KEK,
///   then run [`finalize_pending_rekey`] (which probes candidate DEKs
///   against the DB) — exactly the pre-anti-rollback behaviour.
/// - **With counter**: read the current counter `c` and reconcile the live
///   KEK, an optional `.pending` KEK, and the DB, also rolling the counter
///   forward if a rekey committed the DB but crashed before advancing it.
///   A live KEK that opens under no candidate counter is reported as a
///   rollback.
fn resolve_kek_to_dek(
    paths: &AtRestPaths,
    at_rest_key: &AtRestKey,
    binding: &[u8],
    counter: Option<&dyn rollback::RollbackCounter>,
) -> Result<Zeroizing<[u8; DEK_LEN]>, GroupError> {
    let live = fs::read(&paths.kek)
        .map_err(|e| GroupError::Storage(format!("read KEK {:?}: {e}", paths.kek)))?;

    let Some(counter) = counter else {
        // Counter-free path.
        let dek = at_rest_key.decapsulate_dek(&live, binding, None)?;
        return finalize_pending_rekey(paths, at_rest_key, dek);
    };

    let c = counter.current()?;
    let pending = kek_pending_path(&paths.kek);

    // 1) Live KEK at the current counter.
    if let Ok(dek) = at_rest_key.decapsulate_dek(&live, binding, Some(c)) {
        if !pending.exists() {
            return Ok(dek); // steady state
        }
        // A pending exists: the live KEK still decapsulating at `c` means
        // the counter was not advanced, so the rekey did not commit. If the
        // live DEK opens the DB, discard the stale staging file.
        if dek_opens_db(&paths.db, &dek) {
            if let Err(e) = fs::remove_file(&pending) {
                eprintln!("[at-rest] warning: could not remove stale {pending:?}: {e}");
            }
            return Ok(dek);
        }
        // Else fall through to pending recovery (DB was rekeyed).
    }

    // 2) Recovery from the staged KEK.
    if pending.exists() {
        let pend = fs::read(&pending)
            .map_err(|e| GroupError::Storage(format!("read pending KEK {pending:?}: {e}")))?;
        // 2a) Counter already advanced (crash after advance, before rename):
        //     pending sealed at the current `c`.
        if let Ok(dek) = at_rest_key.decapsulate_dek(&pend, binding, Some(c)) {
            if dek_opens_db(&paths.db, &dek) {
                fs::rename(&pending, &paths.kek).map_err(|e| {
                    GroupError::Storage(format!("finish rekey promotion {pending:?}: {e}"))
                })?;
                return Ok(dek);
            }
        }
        // 2b) DB rekeyed but counter not yet advanced (crash between rekey
        //     and advance): pending sealed at `c + 1`. Roll forward.
        if let Some(c1) = c.checked_add(1) {
            if let Ok(dek) = at_rest_key.decapsulate_dek(&pend, binding, Some(c1)) {
                if dek_opens_db(&paths.db, &dek) {
                    counter.advance()?;
                    fs::rename(&pending, &paths.kek).map_err(|e| {
                        GroupError::Storage(format!("finish rekey promotion {pending:?}: {e}"))
                    })?;
                    return Ok(dek);
                }
            }
        }
    }

    // 3) The live KEK does not match the current counter and no pending KEK
    //    recovers the DB: an at-rest rollback (or counter-state loss /
    //    corruption).
    Err(GroupError::Storage(
        "at-rest rollback detected: the on-disk KEK does not match the current rollback \
         counter (NK_ROLLBACK_POLICY). The storage may have been reverted to an older \
         snapshot, or the rollback counter state was lost."
            .into(),
    ))
}

/// Path of the staging KEK written during a rekey (`<kek>.pending`).
fn kek_pending_path(kek: &Path) -> PathBuf {
    let mut s = kek.as_os_str().to_owned();
    s.push(".pending");
    PathBuf::from(s)
}

/// Rotate the SQLCipher DEK in place: re-encrypt every page of `groups.db`
/// under a fresh 256-bit DEK and re-wrap that DEK into a new KEK file.
///
/// This mitigates a *suspected DEK exposure* (e.g. the old `groups.db.kek`
/// leaked): future copies of the DB are protected by a key the attacker
/// never saw. It does **not** retroactively protect a copy of the old
/// ciphertext the attacker may already hold, and it does not rotate the
/// at-rest hybrid keypair or passphrase (regenerate `at-rest.key` for
/// that).
///
/// ## Crash safety
///
/// The DB page key (`groups.db`) and its wrapper (`groups.db.kek`) live in
/// two separate files that must change together. To survive a crash at any
/// point, the new KEK is first staged to `groups.db.kek.pending`, then the
/// DB is rekeyed via `PRAGMA rekey`, then the staging file is atomically
/// promoted over `groups.db.kek`. [`finalize_pending_rekey`] (run on every
/// open) resolves a leftover `.pending` by testing which DEK actually
/// opens the DB, so no crash window leaves the DB unrecoverable. On any
/// error the staging file is left in place for that recovery to consume.
pub fn rotate_dek(
    paths: &AtRestPaths,
    passphrase: &Zeroizing<String>,
) -> Result<(), GroupError> {
    let counter = rollback::counter_for(rollback::RollbackPolicy::from_env(), &paths.db)?;
    rotate_dek_with(paths, passphrase, counter.as_deref())
}

/// [`rotate_dek`] with an explicit (optional) anti-rollback counter. When a
/// counter is present the new KEK is sealed under `current + 1` and the
/// counter is advanced **after** the DB is re-encrypted but **before** the
/// KEK is promoted, so [`resolve_kek_to_dek`] can recover from a crash at
/// any step (see its 2a/2b cases).
pub(crate) fn rotate_dek_with(
    paths: &AtRestPaths,
    passphrase: &Zeroizing<String>,
    counter: Option<&dyn rollback::RollbackCounter>,
) -> Result<(), GroupError> {
    if passphrase.is_empty() {
        return Err(GroupError::Storage(
            "at-rest passphrase must not be empty".into(),
        ));
    }
    if !paths.key.exists() || !paths.kek.exists() || !paths.db.exists() {
        return Err(GroupError::Storage(
            "rekey requires an existing at-rest.key, groups.db.kek, and groups.db".into(),
        ));
    }
    if is_plaintext_sqlite(&paths.db) {
        return Err(GroupError::Storage(
            "groups.db is not encrypted yet — open it once to migrate before rekey".into(),
        ));
    }

    let at_rest_key = AtRestKey::load_encrypted(&paths.key, passphrase.as_str())?;

    // Recover the current DEK, finishing any prior interrupted rekey first
    // so we start from a consistent DB/KEK pair.
    let binding = db_binding(&paths.db);
    let old_dek = resolve_kek_to_dek(paths, &at_rest_key, &binding, counter)?;

    // The new KEK binds the next counter value (if any), so the just-retired
    // KEK can no longer decapsulate once the counter advances.
    let new_counter_val = counter.map(|c| c.current()).transpose()?.map(|c| c + 1);
    let (new_kek_bytes, new_dek) = at_rest_key.encapsulate_dek(&binding, new_counter_val)?;

    // Stage the new KEK before touching the DB.
    let pending = kek_pending_path(&paths.kek);
    write_atomic_secret(&pending, &new_kek_bytes)?;

    // Re-encrypt the DB from old to new DEK. SQLCipher wraps `PRAGMA rekey`
    // in its own transaction, so a failure here rolls back to the old DEK;
    // the stale `.pending` is then discarded by the next open's recovery.
    {
        use rusqlite::Connection;
        let old_hex = Zeroizing::new(hex::encode(old_dek.as_ref()));
        let new_hex = Zeroizing::new(hex::encode(new_dek.as_ref()));
        let conn = Connection::open_with_flags(&paths.db, db_rw_no_create_flags())
            .map_err(|e| GroupError::Storage(format!("open {:?}: {e}", paths.db)))?;
        let key_stmt = Zeroizing::new(format!("PRAGMA key = \"x'{}'\";", old_hex.as_str()));
        conn.execute_batch(key_stmt.as_str())
            .map_err(|e| GroupError::Storage(format!("rekey set old key: {e}")))?;
        // Confirm the old key actually opens it before rekeying.
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0))
            .map_err(|e| GroupError::Storage(format!("rekey verify old key: {e}")))?;
        // Re-encrypt under a rollback journal rather than WAL: a WAL-mode
        // rekey writes the new-key pages to the -wal and leaves the OLD-key
        // pages in the main file until a checkpoint, so a failed checkpoint
        // would leave old-DEK data readable in the main file. Switching to
        // DELETE journalling first folds any pre-existing WAL frames into
        // the main file and then writes the re-encrypted pages straight to
        // it, with a rollback journal that is removed on commit — no -wal
        // residue under either key. GroupStorage re-enables WAL on the next
        // open.
        conn.execute_batch("PRAGMA journal_mode=DELETE;")
            .map_err(|e| GroupError::Storage(format!("rekey set rollback journal: {e}")))?;
        let rekey_stmt = Zeroizing::new(format!("PRAGMA rekey = \"x'{}'\";", new_hex.as_str()));
        conn.execute_batch(rekey_stmt.as_str())
            .map_err(|e| GroupError::Storage(format!("PRAGMA rekey: {e}")))?;
        // Confirm the new key is now active.
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0))
            .map_err(|e| GroupError::Storage(format!("rekey verify new key: {e}")))?;
    }

    // Advance the rollback counter now that the DB is on the new DEK but
    // before promoting the KEK. This is the irreversible step; a crash
    // here leaves a `.pending` sealed at the (already-current) counter,
    // which `resolve_kek_to_dek` case 2a promotes on the next open. (A
    // crash *before* this advance is recovered by case 2b, which rolls the
    // counter forward.)
    if let Some(c) = counter {
        c.advance()?;
    }

    // Promote the staged KEK over the live one. After this rename the DB
    // and KEK are both on the new DEK.
    fs::rename(&pending, &paths.kek).map_err(|e| {
        GroupError::Storage(format!(
            "promote {pending:?} -> {:?}: {e} (the DB is now on the new DEK; \
             reopen to let recovery finish the promotion)",
            paths.kek
        ))
    })?;
    Ok(())
}

/// If a `<kek>.pending` staging file from an interrupted [`rotate_dek`] is
/// present, decide which DEK the DB is encrypted under and return it,
/// finishing the promotion (or discarding a stale staging file) as needed.
///
/// A no-op (returns `current_dek` unchanged) when there is no staging file,
/// the DB does not exist, or the DB is still plaintext.
fn finalize_pending_rekey(
    paths: &AtRestPaths,
    at_rest_key: &AtRestKey,
    current_dek: Zeroizing<[u8; DEK_LEN]>,
) -> Result<Zeroizing<[u8; DEK_LEN]>, GroupError> {
    let pending = kek_pending_path(&paths.kek);
    if !pending.exists() || !paths.db.exists() || is_plaintext_sqlite(&paths.db) {
        return Ok(current_dek);
    }

    // Case 1: the live KEK already matches the DB — the rekey never
    // committed (or already finished). Discard the stale staging file.
    if dek_opens_db(&paths.db, &current_dek) {
        if let Err(e) = fs::remove_file(&pending) {
            // Non-fatal: the DB opens under the live KEK regardless. Warn
            // so the leftover (which would re-trigger this probe next open)
            // is visible rather than silently ignored.
            eprintln!("[at-rest] warning: could not remove stale {pending:?}: {e}");
        }
        return Ok(current_dek);
    }

    // Case 2: the live KEK does not open the DB. The rekey committed but
    // the promotion did not — the staging KEK should match.
    let pending_bytes = fs::read(&pending)
        .map_err(|e| GroupError::Storage(format!("read pending KEK {pending:?}: {e}")))?;
    let pending_dek =
        at_rest_key.decapsulate_dek(&pending_bytes, &db_binding(&paths.db), None)?;
    if dek_opens_db(&paths.db, &pending_dek) {
        fs::rename(&pending, &paths.kek).map_err(|e| {
            GroupError::Storage(format!("finish rekey promotion {pending:?}: {e}"))
        })?;
        return Ok(pending_dek);
    }

    // Neither DEK opens the DB: corruption or a wrong passphrase upstream.
    // Leave the staging file in place for manual recovery.
    Err(GroupError::Storage(
        "interrupted rekey: neither the current nor the pending KEK opens groups.db; \
         restore the three at-rest files from a backup"
            .into(),
    ))
}

/// Open flags for opening an **existing** database read-write without ever
/// creating it. Used by probes and the rekey path so a file that vanished
/// between an `exists()` check and the open surfaces as an error instead of
/// silently leaving behind a stray empty sqlite file.
fn db_rw_no_create_flags() -> rusqlite::OpenFlags {
    rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
        | rusqlite::OpenFlags::SQLITE_OPEN_URI
        | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
}

/// Cheap probe: does `dek` unlock `db`? Opens a throwaway connection,
/// applies the raw key, and reads `sqlite_master`. Returns `false` on any
/// error (wrong key surfaces as `SQLITE_NOTADB`).
///
/// Opens without `SQLITE_OPEN_CREATE`, so probing a missing DB returns
/// `false` rather than materialising an empty file.
fn dek_opens_db(db: &Path, dek: &[u8; DEK_LEN]) -> bool {
    use rusqlite::Connection;
    let hex = Zeroizing::new(hex::encode(dek));
    let probe = || -> rusqlite::Result<i64> {
        let conn = Connection::open_with_flags(db, db_rw_no_create_flags())?;
        let stmt = Zeroizing::new(format!("PRAGMA key = \"x'{}'\";", hex.as_str()));
        conn.execute_batch(stmt.as_str())?;
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get(0))
    };
    probe().is_ok()
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

/// Build the HPKE `info` for a [`KEK_VERSION_BOUND`] KEK: the domain
/// separator followed by a length-prefixed per-DB binding. The length
/// prefix keeps `HPKE_INFO || binding` unambiguous (no binding can forge a
/// different (prefix, binding) split).
fn bound_info(binding: &[u8]) -> Vec<u8> {
    let mut info = Vec::with_capacity(HPKE_INFO.len() + 4 + binding.len());
    info.extend_from_slice(HPKE_INFO);
    info.extend_from_slice(&(binding.len() as u32).to_be_bytes());
    info.extend_from_slice(binding);
    info
}

/// Build the HPKE `info` for a [`KEK_VERSION_COUNTER_BOUND`] KEK:
/// [`bound_info`] followed by the 8-byte big-endian rollback counter. The
/// counter is appended after the (already length-prefixed) per-DB binding,
/// so the concatenation stays unambiguous.
fn counter_bound_info(binding: &[u8], counter: u64) -> Vec<u8> {
    let mut info = bound_info(binding);
    info.extend_from_slice(&counter.to_be_bytes());
    info
}

/// Per-DB binding for the KEK `info`: the DB file name (not the full path,
/// so moving the whole at-rest triple to another directory keeps the KEK
/// valid while still distinguishing co-located DBs). Empty if the path has
/// no file-name component.
fn db_binding(db: &Path) -> Vec<u8> {
    db.file_name()
        .map(|s| s.as_encoded_bytes().to_vec())
        .unwrap_or_default()
}

/// The current at-rest HPKE suite: X-Wing KEM, HKDF-SHA512 key schedule,
/// AES-256-GCM AEAD (KEK suite byte [`KEK_SUITE_XWING_AES256`]). Used for
/// key generation, sealing, and opening `0x02` KEKs.
fn at_rest_suite() -> Result<HybridCipherSuiteProvider<HybridSuite>, GroupError> {
    build_at_rest_suite().ok_or_else(|| {
        GroupError::Backend(
            "at-rest hybrid suite (0xF102) construction failed; \
             is OpenSSL configured with X25519 + SHA-512 + AES-256-GCM?"
                .into(),
        )
    })
}

/// The legacy at-rest HPKE suite: X-Wing KEM, HKDF-SHA256, AES-128-GCM
/// (KEK suite byte [`KEK_SUITE_XWING`]). Used only to open KEKs written
/// before the AES-256 upgrade.
fn at_rest_suite_legacy() -> Result<HybridCipherSuiteProvider<HybridSuite>, GroupError> {
    build_at_rest_suite_legacy().ok_or_else(|| {
        GroupError::Backend(
            "legacy at-rest hybrid suite (0xF101 params) construction failed".into(),
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
    const TEST_BINDING: &[u8] = b"groups.db";

    #[test]
    fn generate_then_encapsulate_decapsulate_roundtrips_dek() {
        let key = AtRestKey::generate().expect("generate");
        let (kek_bytes, dek_a) = key.encapsulate_dek(TEST_BINDING, None).expect("encapsulate");
        let dek_b = key.decapsulate_dek(&kek_bytes, TEST_BINDING, None).expect("decapsulate");
        assert_eq!(dek_a.as_ref(), dek_b.as_ref(), "DEK must round-trip");
        assert_eq!(dek_a.len(), DEK_LEN);
    }

    #[test]
    fn wrong_binding_fails_decapsulation() {
        // A KEK sealed for one DB name must not decapsulate under another
        // — this is the per-DB binding that stops KEK-swap attacks when
        // several DBs share one at-rest key.
        let key = AtRestKey::generate().expect("generate");
        let (kek_bytes, _dek) = key.encapsulate_dek(b"groups.db", None).expect("encap");
        let err = key
            .decapsulate_dek(&kek_bytes, b"inbox.db", None)
            .expect_err("wrong binding must fail");
        assert!(matches!(err, GroupError::Backend(_)));
    }

    #[test]
    fn legacy_unbound_kek_still_decapsulates() {
        // A v0x01 KEK written before per-DB binding existed (HPKE info =
        // bare HPKE_INFO) must keep opening regardless of the binding
        // passed in, so existing on-disk DBs are not orphaned.
        let key = AtRestKey::generate().expect("generate");
        let mut dek = Zeroizing::new([0u8; DEK_LEN]);
        OsRng.fill_bytes(dek.as_mut_slice());
        // Hand-build a legacy KEK: version 0x01 (unbound info), suite 0x01
        // (AES-128), info = bare HPKE_INFO, sealed with the legacy suite.
        let suite = at_rest_suite_legacy().expect("suite");
        let ct = suite
            .hpke_seal(&key.pk, HPKE_INFO, None, dek.as_ref())
            .expect("seal");
        let mut kek = Vec::new();
        kek.extend_from_slice(&KEK_MAGIC);
        kek.push(KEK_VERSION_LEGACY);
        kek.push(KEK_SUITE_XWING);
        kek.extend_from_slice(&ct.mls_encode_to_vec().expect("encode"));

        // Any binding is ignored for a legacy KEK.
        let recovered = key
            .decapsulate_dek(&kek, b"whatever.db", None)
            .expect("legacy KEK must decapsulate");
        assert_eq!(recovered.as_ref(), dek.as_ref());
    }

    #[test]
    fn new_kek_uses_aes256_suite_byte() {
        // A freshly encapsulated KEK must advertise the AES-256 suite
        // (0x02) and the bound version (0x02).
        let key = AtRestKey::generate().expect("generate");
        let (kek, _dek) = key.encapsulate_dek(TEST_BINDING, None).expect("encap");
        assert_eq!(kek[8], KEK_VERSION_BOUND, "version byte");
        assert_eq!(kek[9], KEK_SUITE_XWING_AES256, "suite byte");
    }

    #[test]
    fn bound_aes128_kek_still_decapsulates() {
        // KEKs written between the per-DB-binding change and the AES-256
        // upgrade are version 0x02 (bound) + suite 0x01 (AES-128). They
        // must keep opening under the legacy suite with the matching
        // binding.
        let key = AtRestKey::generate().expect("generate");
        let mut dek = Zeroizing::new([0u8; DEK_LEN]);
        OsRng.fill_bytes(dek.as_mut_slice());
        let suite = at_rest_suite_legacy().expect("legacy suite");
        let ct = suite
            .hpke_seal(&key.pk, &bound_info(TEST_BINDING), None, dek.as_ref())
            .expect("seal");
        let mut kek = Vec::new();
        kek.extend_from_slice(&KEK_MAGIC);
        kek.push(KEK_VERSION_BOUND);
        kek.push(KEK_SUITE_XWING);
        kek.extend_from_slice(&ct.mls_encode_to_vec().expect("encode"));

        let recovered = key
            .decapsulate_dek(&kek, TEST_BINDING, None)
            .expect("bound AES-128 KEK must decapsulate");
        assert_eq!(recovered.as_ref(), dek.as_ref());
        // And the wrong binding must still fail even for the legacy suite.
        assert!(key.decapsulate_dek(&kek, b"other.db", None).is_err());
    }

    #[test]
    fn aes256_kek_not_openable_by_legacy_suite() {
        // Positive proof that the AES-256 suite is cryptographically
        // distinct from AES-128 (the explicit SHA-512 KDF + AES-256 AEAD
        // really take effect, not a silent 128-bit downgrade): a KEK
        // sealed AES-256 must not open under the legacy AES-128 suite.
        let key = AtRestKey::generate().expect("gen");
        let (kek, dek) = key.encapsulate_dek(TEST_BINDING, None).expect("encap");
        assert_eq!(kek[9], KEK_SUITE_XWING_AES256);

        let mut forced = kek.clone();
        forced[9] = KEK_SUITE_XWING; // pretend it's an AES-128 KEK
        assert!(
            key.decapsulate_dek(&forced, TEST_BINDING, None).is_err(),
            "AES-256 KEK must fail under the AES-128 suite"
        );

        // Sanity: it opens correctly under its real suite.
        let ok = key.decapsulate_dek(&kek, TEST_BINDING, None).expect("real suite");
        assert_eq!(ok.as_ref(), dek.as_ref());
    }

    #[test]
    fn trailing_bytes_in_kek_are_rejected() {
        let key = AtRestKey::generate().expect("gen");
        let (mut kek, _dek) = key.encapsulate_dek(TEST_BINDING, None).expect("encap");
        kek.push(0x00); // append junk
        match key.decapsulate_dek(&kek, TEST_BINDING, None) {
            Err(GroupError::Storage(msg)) => assert!(msg.contains("trailing")),
            other => panic!("expected trailing-byte rejection, got {other:?}"),
        }
    }

    #[test]
    fn save_load_roundtrip_preserves_encapsulation() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("at-rest.key");

        let original = AtRestKey::generate().expect("generate");
        let (kek_bytes, dek) = original.encapsulate_dek(TEST_BINDING, None).expect("encap");

        original.save_encrypted(&path, TEST_PASS).expect("save");
        assert!(path.exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = fs::metadata(&path).expect("metadata");
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }

        let reloaded = AtRestKey::load_encrypted(&path, TEST_PASS).expect("load");
        let dek_from_reload = reloaded.decapsulate_dek(&kek_bytes, TEST_BINDING, None).expect("decap");
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
        let (mut kek_bytes, _dek) = key.encapsulate_dek(TEST_BINDING, None).expect("encap");

        // Flip a byte inside the HPKE ciphertext portion (skip our
        // 10-byte header).
        let idx = KEK_HEADER_LEN + (kek_bytes.len() - KEK_HEADER_LEN) / 2;
        kek_bytes[idx] ^= 0x01;

        let err = key
            .decapsulate_dek(&kek_bytes, TEST_BINDING, None)
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
        let (kek, _dek) = key_a.encapsulate_dek(TEST_BINDING, None).expect("encap by a");

        let err = key_b
            .decapsulate_dek(&kek, TEST_BINDING, None)
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

    /// Open an at-rest storage, seed one application_data row, and return
    /// the paths so a test can rekey and re-verify the row survived.
    fn seed_storage(dir: &Path) -> (AtRestPaths, Zeroizing<String>) {
        let paths = AtRestPaths::from_db_path(dir.join("groups.db"));
        let pass = Zeroizing::new(TEST_PASS.to_string());
        let storage = open_at_rest_storage(&paths, &pass).expect("seed open");
        // list_group_ids proves the schema initialised; an empty DB is
        // enough to exercise rekey's page re-encryption.
        assert!(storage.list_group_ids().expect("list").is_empty());
        drop(storage);
        (paths, pass)
    }

    #[test]
    fn rotate_dek_changes_kek_but_keeps_db_openable() {
        let dir = tempdir().expect("tempdir");
        let (paths, pass) = seed_storage(dir.path());

        let kek_before = fs::read(&paths.kek).expect("kek before");
        rotate_dek(&paths, &pass).expect("rekey");
        let kek_after = fs::read(&paths.kek).expect("kek after");

        assert_ne!(kek_before, kek_after, "KEK must change after rekey");
        assert!(
            !kek_pending_path(&paths.kek).exists(),
            "no staging file should remain after a clean rekey"
        );
        // The DB still opens via the normal path (DEK recovered from the
        // new KEK matches the rekeyed pages).
        let storage = open_at_rest_storage(&paths, &pass).expect("reopen after rekey");
        assert!(storage.list_group_ids().expect("list").is_empty());
    }

    #[test]
    fn rotate_dek_rejects_plaintext_db() {
        let dir = tempdir().expect("tempdir");
        let paths = AtRestPaths::from_db_path(dir.path().join("groups.db"));
        // at-rest.key + KEK exist (generate them), but groups.db is plaintext.
        let key = AtRestKey::generate().expect("gen");
        key.save_encrypted(&paths.key, TEST_PASS).expect("save key");
        let (kek, _dek) = key.encapsulate_dek(&db_binding(&paths.db), None).expect("encap");
        write_atomic_secret(&paths.kek, &kek).expect("write kek");
        make_plaintext_db(&paths.db);

        let err = rotate_dek(&paths, &Zeroizing::new(TEST_PASS.to_string()))
            .expect_err("rekey on plaintext must fail");
        match err {
            GroupError::Storage(msg) => assert!(msg.contains("not encrypted")),
            other => panic!("expected Storage error, got {other:?}"),
        }
    }

    #[test]
    fn finalize_pending_rekey_completes_committed_promotion() {
        // Simulate a crash *after* PRAGMA rekey committed but *before* the
        // KEK was promoted: the live KEK holds the OLD dek, a `.pending`
        // holds the NEW dek, and the DB is encrypted under the NEW dek.
        let dir = tempdir().expect("tempdir");
        let (paths, pass) = seed_storage(dir.path());
        let at_rest_key = AtRestKey::load_encrypted(&paths.key, pass.as_str()).expect("load");

        // Old dek = current KEK contents.
        let binding = db_binding(&paths.db);
        let old_kek = fs::read(&paths.kek).expect("old kek");
        let old_dek = at_rest_key.decapsulate_dek(&old_kek, &binding, None).expect("old dek");

        // Manually rekey the DB to a fresh dek and stage its KEK as pending,
        // leaving the live KEK on the old dek (the interrupted state).
        let (new_kek, new_dek) = at_rest_key.encapsulate_dek(&binding, None).expect("encap new");
        {
            use rusqlite::Connection;
            let conn = Connection::open(&paths.db).expect("open db");
            conn.execute_batch(&format!("PRAGMA key = \"x'{}'\";", hex::encode(old_dek.as_ref())))
                .expect("old key");
            conn.execute_batch(&format!("PRAGMA rekey = \"x'{}'\";", hex::encode(new_dek.as_ref())))
                .expect("rekey");
        }
        write_atomic_secret(&kek_pending_path(&paths.kek), &new_kek).expect("stage pending");

        // Recovery: current (old) dek no longer opens the DB, so the
        // pending (new) dek must be adopted and promoted.
        let resolved = finalize_pending_rekey(&paths, &at_rest_key, old_dek).expect("recover");
        assert_eq!(resolved.as_ref(), new_dek.as_ref(), "must adopt the new dek");
        assert!(!kek_pending_path(&paths.kek).exists(), "pending promoted away");
        // The promoted KEK now decapsulates to the new dek.
        let promoted = at_rest_key
            .decapsulate_dek(&fs::read(&paths.kek).expect("kek"), &binding, None)
            .expect("promoted dek");
        assert_eq!(promoted.as_ref(), new_dek.as_ref());
        // And a normal open works end-to-end.
        let storage = open_at_rest_storage(&paths, &pass).expect("open after recovery");
        assert!(storage.list_group_ids().expect("list").is_empty());
    }

    #[test]
    fn finalize_pending_rekey_discards_stale_staging() {
        // Simulate a crash *before* PRAGMA rekey committed: the DB is still
        // on the OLD dek, but a `.pending` (NEW dek) was already staged.
        // Recovery must keep the old dek and delete the stale staging file.
        let dir = tempdir().expect("tempdir");
        let (paths, pass) = seed_storage(dir.path());
        let at_rest_key = AtRestKey::load_encrypted(&paths.key, pass.as_str()).expect("load");
        let binding = db_binding(&paths.db);
        let old_dek = at_rest_key
            .decapsulate_dek(&fs::read(&paths.kek).expect("kek"), &binding, None)
            .expect("old dek");

        // Stage a pending KEK for some other dek, but DO NOT rekey the DB.
        let (stale_kek, _stale_dek) = at_rest_key.encapsulate_dek(&binding, None).expect("encap stale");
        write_atomic_secret(&kek_pending_path(&paths.kek), &stale_kek).expect("stage");

        let resolved = finalize_pending_rekey(&paths, &at_rest_key, old_dek.clone())
            .expect("recover");
        assert_eq!(resolved.as_ref(), old_dek.as_ref(), "must keep the old dek");
        assert!(
            !kek_pending_path(&paths.kek).exists(),
            "stale staging file must be discarded"
        );
    }

    // -------------------------------------------------------------------------
    // Anti-rollback (counter-bound) tests
    // -------------------------------------------------------------------------

    use crate::group::rollback::{MemoryCounter, RollbackCounter, SoftwareCounter};

    fn anti_rollback_paths(dir: &Path) -> (AtRestPaths, Zeroizing<String>) {
        (
            AtRestPaths::from_db_path(dir.join("groups.db")),
            Zeroizing::new(TEST_PASS.to_string()),
        )
    }

    /// Resolve the DEK *and* materialise the SQLCipher DB file (resolve_dek
    /// alone only derives the key; the .db is created on first open).
    fn init_db_with_counter(
        paths: &AtRestPaths,
        pass: &Zeroizing<String>,
        counter: &dyn RollbackCounter,
    ) {
        let dek = resolve_dek_with(paths, pass, Some(counter)).expect("init dek");
        drop(GroupStorage::open_at_with_raw_key(&paths.db, &dek).expect("init open"));
    }

    #[test]
    fn counter_kek_is_v3_and_roundtrips() {
        let dir = tempdir().expect("tempdir");
        let (paths, pass) = anti_rollback_paths(dir.path());
        let counter = MemoryCounter::new(0);

        init_db_with_counter(&paths, &pass, &counter);
        let kek = fs::read(&paths.kek).expect("kek");
        assert_eq!(kek[8], KEK_VERSION_COUNTER_BOUND, "v0x03 when counter present");

        // Normal reopen at the same counter works.
        drop(resolve_dek_with(&paths, &pass, Some(&counter)).expect("reopen"));
    }

    #[test]
    fn v3_kek_requires_a_counter_to_open() {
        let dir = tempdir().expect("tempdir");
        let (paths, pass) = anti_rollback_paths(dir.path());
        let counter = MemoryCounter::new(0);
        init_db_with_counter(&paths, &pass, &counter);

        // Opening a v0x03 KEK with the policy disabled (no counter) must fail
        // rather than silently bypass rollback protection.
        match resolve_dek_with(&paths, &pass, None) {
            Err(GroupError::Storage(m)) => assert!(m.contains("anti-rollback") || m.contains("counter")),
            other => panic!("expected counter-required error, got {other:?}"),
        }
    }

    #[test]
    fn rekey_advances_counter_and_detects_restored_old_kek() {
        let dir = tempdir().expect("tempdir");
        let (paths, pass) = anti_rollback_paths(dir.path());
        let counter = MemoryCounter::new(0);

        init_db_with_counter(&paths, &pass, &counter);
        let old_kek = fs::read(&paths.kek).expect("kek@0");

        rotate_dek_with(&paths, &pass, Some(&counter)).expect("rekey");
        assert_eq!(counter.current().unwrap(), 1, "rekey advances the counter");
        // Steady-state reopen at counter 1 works.
        drop(resolve_dek_with(&paths, &pass, Some(&counter)).expect("reopen@1"));

        // Roll back: restore the pre-rekey KEK (sealed at counter 0) while the
        // counter has advanced to 1.
        fs::write(&paths.kek, &old_kek).expect("restore old kek");
        match resolve_dek_with(&paths, &pass, Some(&counter)) {
            Err(GroupError::Storage(m)) => assert!(m.contains("rollback"), "got: {m}"),
            other => panic!("rollback must be detected, got {other:?}"),
        }
    }

    #[test]
    fn recovery_rolls_forward_when_db_rekeyed_but_counter_not_advanced() {
        // Crash case 2b: pending sealed at c+1, DB already rekeyed, counter
        // still at c. Recovery must adopt the pending DEK and advance.
        let dir = tempdir().expect("tempdir");
        let (paths, pass) = anti_rollback_paths(dir.path());
        let counter = MemoryCounter::new(0);
        init_db_with_counter(&paths, &pass, &counter);

        let key = AtRestKey::load_encrypted(&paths.key, pass.as_str()).expect("load");
        let binding = db_binding(&paths.db);
        let c = counter.current().unwrap(); // 0
        let old_dek = key
            .decapsulate_dek(&fs::read(&paths.kek).unwrap(), &binding, Some(c))
            .expect("old dek");

        // Stage a new KEK at c+1 and rekey the DB, but leave the counter at c
        // and do not promote (the 2b crash window).
        let (new_kek, new_dek) = key.encapsulate_dek(&binding, Some(c + 1)).expect("encap");
        {
            use rusqlite::Connection;
            let conn = Connection::open(&paths.db).expect("open");
            conn.execute_batch(&format!("PRAGMA key = \"x'{}'\";", hex::encode(old_dek.as_ref()))).unwrap();
            conn.execute_batch(&format!("PRAGMA rekey = \"x'{}'\";", hex::encode(new_dek.as_ref()))).unwrap();
        }
        write_atomic_secret(&kek_pending_path(&paths.kek), &new_kek).expect("stage");

        let dek = resolve_kek_to_dek(&paths, &key, &binding, Some(&counter)).expect("recover");
        assert_eq!(dek.as_ref(), new_dek.as_ref(), "adopts the new dek");
        assert_eq!(counter.current().unwrap(), c + 1, "counter rolled forward");
        assert!(!kek_pending_path(&paths.kek).exists(), "pending promoted");
    }

    #[test]
    fn recovery_promotes_when_counter_already_advanced() {
        // Crash case 2a: pending sealed at c, DB rekeyed, counter already
        // advanced to c. Recovery promotes pending without re-advancing.
        let dir = tempdir().expect("tempdir");
        let (paths, pass) = anti_rollback_paths(dir.path());
        let counter = MemoryCounter::new(0);
        init_db_with_counter(&paths, &pass, &counter);

        let key = AtRestKey::load_encrypted(&paths.key, pass.as_str()).expect("load");
        let binding = db_binding(&paths.db);
        let old_dek = key
            .decapsulate_dek(&fs::read(&paths.kek).unwrap(), &binding, Some(0))
            .expect("old dek");

        // Advance the counter to 1, seal pending at 1, rekey DB, no promote.
        let c1 = counter.advance().unwrap(); // 1
        let (new_kek, new_dek) = key.encapsulate_dek(&binding, Some(c1)).expect("encap");
        {
            use rusqlite::Connection;
            let conn = Connection::open(&paths.db).expect("open");
            conn.execute_batch(&format!("PRAGMA key = \"x'{}'\";", hex::encode(old_dek.as_ref()))).unwrap();
            conn.execute_batch(&format!("PRAGMA rekey = \"x'{}'\";", hex::encode(new_dek.as_ref()))).unwrap();
        }
        write_atomic_secret(&kek_pending_path(&paths.kek), &new_kek).expect("stage");

        let dek = resolve_kek_to_dek(&paths, &key, &binding, Some(&counter)).expect("recover");
        assert_eq!(dek.as_ref(), new_dek.as_ref(), "adopts the new dek");
        assert_eq!(counter.current().unwrap(), 1, "counter unchanged (already advanced)");
        assert!(!kek_pending_path(&paths.kek).exists(), "pending promoted");
    }

    #[test]
    fn software_counter_end_to_end_rekey() {
        // Exercise the file-backed SoftwareCounter through the public-ish
        // *_with seam: init, rekey, reopen.
        let dir = tempdir().expect("tempdir");
        let state = tempdir().expect("state");
        let (paths, pass) = anti_rollback_paths(dir.path());
        let counter = SoftwareCounter::at(state.path().join("groups.ctr"));

        init_db_with_counter(&paths, &pass, &counter);
        assert_eq!(counter.current().unwrap(), 0);
        rotate_dek_with(&paths, &pass, Some(&counter)).expect("rekey");
        assert_eq!(counter.current().unwrap(), 1);
        let storage = {
            let dek = resolve_dek_with(&paths, &pass, Some(&counter)).expect("reopen");
            GroupStorage::open_at_with_raw_key(&paths.db, &dek).expect("open")
        };
        assert!(storage.list_group_ids().expect("list").is_empty());
    }

    #[test]
    fn tpm_strict_end_to_end_detects_rollback() {
        use crate::group::rollback::{tpm_available, TpmCounter};
        if !tpm_available() {
            eprintln!("skipping tpm_strict_end_to_end_detects_rollback: no TPM 2.0");
            return;
        }
        let index = 0x0171_0000u32 | 0xFE02;
        fn undefine(i: u32) {
            let _ = std::process::Command::new("tpm2_nvundefine")
                .arg(format!("0x{i:08X}"))
                .args(["-C", "o"])
                .env("TCTI", "device:/dev/tpmrm0")
                .output();
        }
        struct Guard(u32);
        impl Drop for Guard {
            fn drop(&mut self) {
                undefine(self.0);
            }
        }
        undefine(index); // clear any stale test index
        let _guard = Guard(index);

        let dir = tempdir().expect("tempdir");
        let (paths, pass) = anti_rollback_paths(dir.path());
        let counter = TpmCounter::with_index(index);

        // Init under the TPM counter → v0x03 KEK; materialise the DB.
        init_db_with_counter(&paths, &pass, &counter);
        let kek0 = fs::read(&paths.kek).expect("kek@init");
        assert_eq!(kek0[8], KEK_VERSION_COUNTER_BOUND, "TPM-bound KEK is v0x03");

        // Rekey advances the hardware counter; steady-state reopen works.
        rotate_dek_with(&paths, &pass, Some(&counter)).expect("rekey");
        drop(resolve_dek_with(&paths, &pass, Some(&counter)).expect("reopen"));

        // Roll back the KEK to its pre-rekey snapshot: the TPM counter has
        // advanced, so the restored KEK no longer decapsulates.
        fs::write(&paths.kek, &kek0).expect("restore old kek");
        match resolve_dek_with(&paths, &pass, Some(&counter)) {
            Err(GroupError::Storage(m)) => assert!(m.contains("rollback"), "got: {m}"),
            other => panic!("TPM rollback must be detected, got {other:?}"),
        }
    }
}
