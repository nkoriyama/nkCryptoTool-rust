/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

//! Cross-platform owner-only creation of secret-bearing files.
//!
//! Every function here enforces two properties on the *final path component*:
//!
//! 1. **Owner-only access** — unix: mode `0o600` (dirs `0o700`); windows: a
//!    protected DACL granting `FILE_ALL_ACCESS` to the owner, `SYSTEM` and
//!    `Administrators` only (the Win32-OpenSSH private-key convention), applied
//!    **atomically at creation time** through `SECURITY_ATTRIBUTES` — there is
//!    no create-then-SetSecurityInfo window in which another local user could
//!    open the file under the directory's inherited ACL.
//! 2. **No link following** — unix: `O_NOFOLLOW` / `O_EXCL`; windows: the file
//!    is opened with `FILE_FLAG_OPEN_REPARSE_POINT` (a planted symlink or
//!    junction is opened as the link *entity*, never followed) and the handle
//!    is then rejected if it refers to a reparse point. A junction (always a
//!    directory) additionally fails the plain-file open outright.
//!
//! Like `O_NOFOLLOW`, this protects the final component only; symlinks in
//! *intermediate* directory components are out of scope here (the scp server
//! handles that separately with post-open real-path re-verification).
//!
//! Targets that are neither unix nor windows get no silent fallback: secret
//! writes there **fail closed** with `ErrorKind::Unsupported`.

use std::fs::File;
use std::io;
use std::path::Path;

/// Create `path` exclusively (fail if *anything* — file, symlink, junction —
/// already exists there) and write `bytes` owner-only. The `O_EXCL` analog:
/// never follows a pre-planted link and never clobbers a concurrent file.
pub fn write_owner_only_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let mut f = create_owner_only(path, false)?;
    f.write_all(bytes)?;
    f.flush()
}

/// Create-or-truncate `path` and write `bytes` owner-only, refusing to follow
/// a link at the final component. Overwriting an existing *regular* file is
/// allowed (idempotent re-runs) and its permissions are re-locked to
/// owner-only even on that overwrite path.
pub fn write_owner_only_replace(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let mut f = create_owner_only(path, true)?;
    f.write_all(bytes)?;
    f.flush()
}

/// Open a fresh owner-only file for writing. `replace = false` is exclusive
/// creation (`O_EXCL` semantics); `replace = true` is create-or-truncate with
/// no-follow. Callers that need to stream use this directly; most call the
/// `write_owner_only_*` wrappers.
pub fn create_owner_only(path: &Path, replace: bool) -> io::Result<File> {
    imp::create_owner_only(path, replace)
}

/// Re-lock an *existing* regular file to owner-only. For files whose creation
/// this module does not control (e.g. a database created by `redb`). The file
/// is addressed through a no-follow handle, not by path, so the target cannot
/// be swapped for a link between check and apply.
pub fn harden_owner_only(path: &Path) -> io::Result<()> {
    imp::harden_owner_only(path)
}

/// Re-lock an already-open handle to owner-only. For temp files created by
/// another library (e.g. `tempfile::NamedTempFile`) that must be locked down
/// *before* secret bytes are written into them. fd/handle-based on both
/// platforms, so there is no path to race.
pub fn harden_owner_only_handle(f: &File) -> io::Result<()> {
    imp::harden_owner_only_handle(f)
}

/// Open `path` for owner-only appending, creating it owner-only if absent
/// (audit logs). An already-existing file is re-locked to owner-only on every
/// open and must be owned by the caller (unix: fchmod, whose EPERM refuses
/// foreign-owned files; windows: ownership check + DACL re-lock). A link at
/// the path is refused on both platforms.
pub fn open_append_owner_only(path: &Path) -> io::Result<File> {
    imp::open_append_owner_only(path)
}

/// Create a directory with owner-only access (`0o700` analog). Errors if the
/// path already exists, like `fs::create_dir`.
pub fn create_dir_owner_only(path: &Path) -> io::Result<()> {
    imp::create_dir_owner_only(path)
}

/// Open an *existing* file without following a link at the final component
/// (unix: `O_NOFOLLOW`; windows: reparse-point refusal), read-only or
/// read-write. Permissions are left untouched — this is for operating on a
/// user-supplied file through a stable handle (e.g. read-then-shred without a
/// path race), not for creating secrets.
pub fn open_existing_no_follow(path: &Path, write: bool) -> io::Result<File> {
    imp::open_existing_no_follow(path, write)
}

#[cfg(unix)]
mod imp {
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};

    /// A hard link is not caught by O_NOFOLLOW: a link planted at the path
    /// aliases the victim file itself, and truncating/re-chmodding through it
    /// would hit the victim (fs.protected_hardlinks blocks creation on modern
    /// Linux, but not on every unix or misconfigured system). A secret file
    /// has no legitimate reason to carry extra links — refuse.
    fn reject_multilink(f: &File) -> io::Result<()> {
        if f.metadata()?.nlink() > 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "refusing to write secret to a multi-hard-linked file",
            ));
        }
        Ok(())
    }

    pub fn create_owner_only(path: &Path, replace: bool) -> io::Result<File> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).mode(0o600);
        if replace {
            // O_NOFOLLOW: fail (ELOOP) instead of following a symlink planted
            // at the target — atomic, no TOCTOU. Deliberately NO truncate here:
            // nothing is destroyed until the ownership gate below has passed.
            opts.create(true).custom_flags(libc::O_NOFOLLOW);
        } else {
            // O_CREAT|O_EXCL refuses to follow (or clobber) anything existing,
            // symlinks included — even dangling ones. O_NOFOLLOW is redundant
            // with O_EXCL but kept as belt-and-braces.
            opts.create_new(true).custom_flags(libc::O_NOFOLLOW);
        }
        let f = opts.open(path)?;
        if replace {
            // mode() above seeds 0600 on creation only; when an existing file
            // was opened instead, re-lock it here (fd-based, so no path race).
            // fchmod fails with EPERM unless we OWN the file — an
            // attacker-planted writable file is refused, untouched, before the
            // truncation below can destroy anything or a secret is written.
            reject_multilink(&f)?;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            f.set_len(0)?;
        }
        Ok(f)
    }

    pub fn harden_owner_only(path: &Path) -> io::Result<()> {
        let mut opts = std::fs::OpenOptions::new();
        // Read access is enough to own an fd for fchmod; O_NOFOLLOW keeps a
        // swapped-in symlink from redirecting the chmod.
        opts.read(true).custom_flags(libc::O_NOFOLLOW);
        let f = opts.open(path)?;
        reject_multilink(&f)?;
        harden_owner_only_handle(&f)
    }

    pub fn harden_owner_only_handle(f: &File) -> io::Result<()> {
        f.set_permissions(std::fs::Permissions::from_mode(0o600))
    }

    pub fn open_append_owner_only(path: &Path) -> io::Result<File> {
        let mut opts = std::fs::OpenOptions::new();
        // O_NOFOLLOW: a symlink planted at the log path must not redirect
        // appends into some other file (matches the windows reparse refusal).
        opts.create(true)
            .append(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW);
        let f = opts.open(path)?;
        // Re-lock an existing log to owner-only on every open; fchmod's EPERM
        // doubles as the ownership gate (a foreign-owned file is refused, so
        // audit records are never appended into another user's file).
        reject_multilink(&f)?;
        harden_owner_only_handle(&f)?;
        Ok(f)
    }

    pub fn create_dir_owner_only(path: &Path) -> io::Result<()> {
        std::fs::DirBuilder::new().mode(0o700).create(path)
    }

    pub fn open_existing_no_follow(path: &Path, write: bool) -> io::Result<File> {
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true).write(write).custom_flags(libc::O_NOFOLLOW);
        opts.open(path)
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use windows_sys::Win32::Foundation::{
        CloseHandle, LocalFree, ERROR_SUCCESS, GENERIC_WRITE, HANDLE, HLOCAL,
        INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SetSecurityInfo,
        SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        EqualSid, GetSecurityDescriptorDacl, GetTokenInformation, TokenOwner, TokenUser, ACL,
        DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
        TOKEN_OWNER, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateDirectoryW, CreateFileW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
        CREATE_NEW, FILE_APPEND_DATA, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE,
        OPEN_ALWAYS, OPEN_EXISTING, READ_CONTROL, WRITE_DAC,
    };

    /// Protected (non-inheriting) DACL granting FILE_ALL_ACCESS to the file's
    /// owner (`OW` = OWNER_RIGHTS, resolved dynamically), `SYSTEM` and
    /// `Administrators` — the 0o600 analog, matching what Win32-OpenSSH
    /// requires of private keys. Everyone else (other local users, network
    /// logons) gets nothing.
    const OWNER_ONLY_SDDL: &str = "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)";

    /// A security descriptor allocated by the SDDL converter; freed with
    /// `LocalFree`.
    struct LocalSd(PSECURITY_DESCRIPTOR);

    impl Drop for LocalSd {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0 as HLOCAL);
            }
        }
    }

    fn owner_only_sd() -> io::Result<LocalSd> {
        let sddl: Vec<u16> = OWNER_ONLY_SDDL.encode_utf16().chain(Some(0)).collect();
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(LocalSd(sd))
    }

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(Some(0)).collect()
    }

    /// The `O_NOFOLLOW` analog: `FILE_FLAG_OPEN_REPARSE_POINT` made CreateFileW
    /// open any symlink at the final component as the link *entity* instead of
    /// following it; refuse such a handle. (A junction is a directory, so the
    /// plain-file open above already failed for it.)
    fn reject_reparse(f: &File, path: &Path) -> io::Result<()> {
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(f.as_raw_handle() as HANDLE, &mut info) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "refusing to write secret through a reparse point (symlink/junction): {}",
                    path.display()
                ),
            ));
        }
        // A hard link is not a reparse point, so the flag above cannot catch
        // it: a link planted at the path aliases the victim file itself, and
        // truncating/re-ACLing through it would hit the victim. A secret file
        // has no legitimate reason to carry extra links — refuse.
        if info.nNumberOfLinks > 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "refusing to write secret to a multi-hard-linked file: {}",
                    path.display()
                ),
            ));
        }
        Ok(())
    }

    /// CreateFileW with the owner-only DACL applied atomically at creation
    /// (through `SECURITY_ATTRIBUTES`) plus the no-follow open flag.
    fn open_secure(
        path: &Path,
        access: u32,
        share: u32,
        disposition: u32,
        flags: u32,
        with_sa: bool,
    ) -> io::Result<File> {
        // Hold the SD (and its allocation) across the CreateFileW call.
        let sd = if with_sa { Some(owner_only_sd()?) } else { None };
        let sa = sd.as_ref().map(|sd| SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: 0,
        });
        let handle = unsafe {
            CreateFileW(
                wide(path).as_ptr(),
                access,
                share,
                sa.as_ref()
                    .map_or(std::ptr::null(), |sa| sa as *const SECURITY_ATTRIBUTES),
                disposition,
                flags | FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `handle` is a freshly opened, owned, valid file handle; the
        // returned File closes it on every subsequent error path.
        let f = unsafe { File::from_raw_handle(handle as _) };
        reject_reparse(&f, path)?;
        Ok(f)
    }

    pub fn create_owner_only(path: &Path, replace: bool) -> io::Result<File> {
        // replace mode opens WITHOUT truncation (OPEN_ALWAYS, not
        // CREATE_ALWAYS): nothing is destroyed until the reparse check has
        // passed, so a planted link makes the call fail with the link intact —
        // the same fail-first semantics O_NOFOLLOW gives the unix twin.
        let disposition = if replace { OPEN_ALWAYS } else { CREATE_NEW };
        // The replace path re-locks the DACL through this handle, which needs
        // WRITE_DAC (SetSecurityInfo) + READ_CONTROL (owner lookup). An owner
        // is always granted both in the access check regardless of the DACL;
        // a foreign-owned file that grants them is rejected right after by
        // the ownership gate in harden_owner_only_handle.
        let access = if replace {
            GENERIC_WRITE | FILE_READ_ATTRIBUTES | WRITE_DAC | READ_CONTROL
        } else {
            GENERIC_WRITE | FILE_READ_ATTRIBUTES
        };
        let f = open_secure(
            path,
            access,
            0, // no sharing while we hold the handle
            disposition,
            FILE_ATTRIBUTE_NORMAL,
            true,
        )?;
        if replace {
            // OPEN_ALWAYS applies the SECURITY_ATTRIBUTES only when the file
            // is newly created; an existing regular file keeps its old DACL,
            // so re-lock it — handle-based, no path race — and only then
            // truncate. (The unix twin re-chmods 0600 on this same branch.)
            harden_owner_only_handle(&f)?;
            f.set_len(0)?;
        }
        Ok(f)
    }

    pub fn open_append_owner_only(path: &Path) -> io::Result<File> {
        // FILE_APPEND_DATA (not GENERIC_WRITE): append-only, like unix append
        // mode. OPEN_ALWAYS applies the owner-only DACL when it creates the
        // file; an existing audit log is re-locked (and its ownership
        // verified) below, matching the unix twin's fchmod-on-every-open.
        let f = open_secure(
            path,
            FILE_APPEND_DATA | FILE_READ_ATTRIBUTES | WRITE_DAC | READ_CONTROL,
            0,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            true,
        )?;
        harden_owner_only_handle(&f)?;
        Ok(f)
    }

    /// One process-token information block (e.g. `TokenUser` / `TokenOwner`)
    /// as an owned buffer; SID pointers inside point into the returned Vec.
    /// Allocated as `u64` words so the buffer start satisfies the 8-byte
    /// alignment of `TOKEN_USER` / `TOKEN_OWNER` (a `Vec<u8>` would not,
    /// making the later struct casts unaligned reads).
    fn token_info_buf(class: i32) -> io::Result<Vec<u64>> {
        struct Tok(HANDLE);
        impl Drop for Tok {
            fn drop(&mut self) {
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
        let mut raw: HANDLE = std::ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let tok = Tok(raw);
        let mut len = 0u32;
        unsafe { GetTokenInformation(tok.0, class, std::ptr::null_mut(), 0, &mut len) };
        if len == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buf = vec![0u64; (len as usize).div_ceil(8)];
        if unsafe { GetTokenInformation(tok.0, class, buf.as_mut_ptr() as *mut _, len, &mut len) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(buf)
    }

    /// Fail unless the file behind `handle` is OWNED by the current user. The
    /// owner of a windows file holds implicit READ_CONTROL + WRITE_DAC no
    /// matter what the DACL says, so re-locking the DACL on a foreign-owned
    /// file protects nothing — the owner can simply grant themselves access
    /// again. This is the analog of fchmod's EPERM-unless-owner on unix.
    fn assert_owned_by_me(handle: HANDLE) -> io::Result<()> {
        let user_buf = token_info_buf(TokenUser)?;
        // SAFETY: each buffer was filled by GetTokenInformation for the
        // matching class and outlives every use of the SID pointers below.
        let user_sid: PSID = unsafe { (*(user_buf.as_ptr() as *const TOKEN_USER)).User.Sid };
        // TokenOwner is the DEFAULT OWNER stamped on objects this token
        // creates — for an elevated administrator that is the Administrators
        // GROUP, not the individual user (a Windows policy default), so a
        // TokenUser-only comparison would reject files this very process just
        // created.
        let owner_buf = token_info_buf(TokenOwner)?;
        let default_owner_sid: PSID =
            unsafe { (*(owner_buf.as_ptr() as *const TOKEN_OWNER)).Owner };
        let mut owner: PSID = std::ptr::null_mut();
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let status = unsafe {
            GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut sd,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        // `owner` points into `sd`; keep the SD alive until after EqualSid.
        let _sd = LocalSd(sd);
        let owned_by_me = !owner.is_null()
            && (unsafe { EqualSid(owner, user_sid) } != 0
                || unsafe { EqualSid(owner, default_owner_sid) } != 0);
        if !owned_by_me {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "refusing to harden a file owned by another user",
            ));
        }
        Ok(())
    }

    /// Replace the DACL on an already-open handle with the owner-only one,
    /// refusing foreign-owned files (see [`assert_owned_by_me`]).
    pub fn harden_owner_only_handle(f: &File) -> io::Result<()> {
        let handle = f.as_raw_handle() as HANDLE;
        assert_owned_by_me(handle)?;
        let sd = owner_only_sd()?;
        let mut dacl_present = 0i32;
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut dacl_defaulted = 0i32;
        if unsafe {
            GetSecurityDescriptorDacl(sd.0, &mut dacl_present, &mut dacl, &mut dacl_defaulted)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if dacl_present == 0 || dacl.is_null() {
            return Err(io::Error::other("owner-only SDDL produced no DACL"));
        }
        let status = unsafe {
            SetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                dacl,
                std::ptr::null_mut(),
            )
        };
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        Ok(())
    }

    pub fn harden_owner_only(path: &Path) -> io::Result<()> {
        // The owner keeps WRITE_DAC even under the new DACL; opening with the
        // reparse flag and re-checking pins the object identity before the ACL
        // swap. Share read/write so a live database handle keeps working.
        let f = open_secure(
            path,
            WRITE_DAC | READ_CONTROL | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            OPEN_EXISTING,
            0,
            false,
        )?;
        harden_owner_only_handle(&f)
    }

    pub fn create_dir_owner_only(path: &Path) -> io::Result<()> {
        let sd = owner_only_sd()?;
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: 0,
        };
        if unsafe { CreateDirectoryW(wide(path).as_ptr(), &sa) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn open_existing_no_follow(path: &Path, write: bool) -> io::Result<File> {
        use windows_sys::Win32::Foundation::GENERIC_READ;
        let access = if write {
            GENERIC_READ | GENERIC_WRITE
        } else {
            GENERIC_READ
        };
        open_secure(path, access, 0, OPEN_EXISTING, 0, false)
    }
}

// No silent degradation on exotic targets: a secret write that cannot be
// protected must not happen at all.
#[cfg(not(any(unix, windows)))]
mod imp {
    use super::*;

    fn unsupported() -> io::Error {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "owner-only secret files are not supported on this platform",
        )
    }

    pub fn create_owner_only(_path: &Path, _replace: bool) -> io::Result<File> {
        Err(unsupported())
    }
    pub fn harden_owner_only(_path: &Path) -> io::Result<()> {
        Err(unsupported())
    }
    pub fn harden_owner_only_handle(_f: &File) -> io::Result<()> {
        Err(unsupported())
    }
    pub fn open_append_owner_only(_path: &Path) -> io::Result<File> {
        Err(unsupported())
    }
    pub fn open_existing_no_follow(_path: &Path, _write: bool) -> io::Result<File> {
        Err(unsupported())
    }
    pub fn create_dir_owner_only(_path: &Path) -> io::Result<()> {
        Err(unsupported())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_refuses_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("k");
        write_owner_only_new(&p, b"a").unwrap();
        assert!(write_owner_only_new(&p, b"b").is_err());
        assert_eq!(std::fs::read(&p).unwrap(), b"a");
    }

    #[test]
    fn replace_overwrites_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("k");
        write_owner_only_replace(&p, b"first").unwrap();
        write_owner_only_replace(&p, b"second").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"second");
    }

    #[cfg(unix)]
    #[test]
    fn unix_modes_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("k");
        write_owner_only_replace(&f, b"x").unwrap();
        assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o600);
        let d = dir.path().join("sub");
        create_dir_owner_only(&d).unwrap();
        assert_eq!(std::fs::metadata(&d).unwrap().permissions().mode() & 0o777, 0o700);
        // harden: loosen then re-lock
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        harden_owner_only(&f).unwrap();
        assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn replace_refuses_hard_link() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"precious").unwrap();
        let link = dir.path().join("link");
        std::fs::hard_link(&victim, &link).unwrap();
        assert!(write_owner_only_replace(&link, b"evil").is_err());
        // The victim is neither truncated nor overwritten.
        assert_eq!(std::fs::read(&victim).unwrap(), b"precious");
    }

    #[cfg(unix)]
    #[test]
    fn unix_replace_refuses_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, b"victim").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(write_owner_only_replace(&link, b"evil").is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"victim");
    }

    /// Windows analog of the symlink test. Creating a file symlink needs
    /// SeCreateSymbolicLinkPrivilege (admin or Developer Mode); GitHub's
    /// windows runners are elevated, so this runs there. Skips (rather than
    /// fails) where the privilege is missing so local dev boxes stay green.
    #[cfg(windows)]
    #[test]
    fn windows_replace_refuses_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, b"victim").unwrap();
        let link = dir.path().join("link");
        if std::os::windows::fs::symlink_file(&target, &link).is_err() {
            eprintln!("skipping: no symlink privilege");
            return;
        }
        assert!(write_owner_only_replace(&link, b"evil").is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"victim");
    }

    /// The DACL on a created secret must list exactly the three principals of
    /// [`OWNER_ONLY_SDDL`] and nothing else (no inherited Users/Everyone ACE).
    /// Verified through `icacls`, which resolves the effective DACL the same
    /// way any other tool would.
    #[cfg(windows)]
    #[test]
    fn windows_dacl_is_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("k");
        write_owner_only_new(&p, b"x").unwrap();
        let out = std::process::Command::new("icacls")
            .arg(&p)
            .output()
            .expect("icacls");
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        // Expected grants only: OWNER RIGHTS, SYSTEM, Administrators — each (F),
        // none inherited (no "(I)").
        assert!(text.contains("OWNER RIGHTS:(F)"), "missing owner grant: {text}");
        assert!(text.contains("NT AUTHORITY\\SYSTEM:(F)"), "missing SYSTEM: {text}");
        assert!(
            text.contains("BUILTIN\\Administrators:(F)"),
            "missing Administrators: {text}"
        );
        assert!(!text.contains("(I)"), "unexpected inherited ACE: {text}");
        assert!(!text.contains("Users:"), "unexpected Users ACE: {text}");
        assert!(!text.contains("Everyone:"), "unexpected Everyone ACE: {text}");
        // And the replace path re-locks an existing file's ACL too.
        let loose = dir.path().join("loose");
        std::fs::write(&loose, b"old").unwrap();
        write_owner_only_replace(&loose, b"new").unwrap();
        let out2 = std::process::Command::new("icacls").arg(&loose).output().unwrap();
        let text2 = String::from_utf8_lossy(&out2.stdout).to_string();
        assert!(!text2.contains("Users:"), "replace left loose ACL: {text2}");
    }
}
