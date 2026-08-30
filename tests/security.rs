use nkct::strategy::CryptoStrategy;
use nkct::utils::{secure_erase_file, secure_write, SecureBuffer};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

// Every test in this binary is #[serial]: VmLck in /proc/self/status is
// process-global, so ANY concurrently-running test that holds a SecureBuffer
// (e.g. test_preload_encrypted_pem) races the absolute-value assertions in the
// VmLck-observing tests below. A mutex around only those two is not enough.
use serial_test::serial;

fn read_vm_lck_kb() -> Option<usize> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmLck:") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

#[test]
#[serial]
fn secure_buffer_drop_releases_mlock() {
    let Some(baseline) = read_vm_lck_kb() else {
        return;
    };

    let buf = SecureBuffer::new(8192).expect("alloc");
    let during = read_vm_lck_kb().unwrap_or(baseline);
    if during == baseline {
        // mlock failed (likely RLIMIT_MEMLOCK = 0 on this host).
        // Without an actual lock acquired, the release path cannot
        // be observed; skip rather than pass on a false negative.
        return;
    }
    drop(buf);
    let after = read_vm_lck_kb().expect("read /proc/self/status after drop");
    assert_eq!(
        after, baseline,
        "munlock did not release the lock (baseline={} during={} after={})",
        baseline, during, after
    );
}

#[test]
#[serial]
fn secure_buffer_repeated_alloc_does_not_accumulate_locks() {
    let Some(baseline) = read_vm_lck_kb() else {
        return;
    };

    for _ in 0..64 {
        let buf = SecureBuffer::new(8192).expect("alloc");
        assert_eq!(buf.as_slice().len(), 8192);
    }

    let after = read_vm_lck_kb().expect("read /proc/self/status after loop");
    assert_eq!(
        after, baseline,
        "locked memory accumulated across alloc/drop cycles: baseline={} after={}",
        baseline, after
    );
}

#[test]
#[serial]
fn secure_erase_file_overwrites_with_zeros() {
    use std::io::Write as _;
    let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
    let secret = b"plaintext-aes-key-material-abcdef0123456789";
    tmp.write_all(secret).expect("write");
    tmp.as_file_mut().sync_all().expect("fsync");
    let path = tmp.path().to_path_buf();

    secure_erase_file(&path);

    let after = std::fs::read(&path).expect("read after erase");
    assert_eq!(after.len(), secret.len(), "file length must be preserved");
    assert!(
        after.iter().all(|&b| b == 0),
        "file contents must be all zeros after secure_erase_file"
    );
}

#[test]
#[serial]
fn secure_erase_file_handles_missing_path() {
    // Must not panic when the path does not exist.
    secure_erase_file("/nonexistent/secure-erase-target");
}

#[test]
#[serial]
fn secure_erase_file_handles_empty_file() {
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    secure_erase_file(tmp.path());
    let after = std::fs::read(tmp.path()).expect("read");
    assert!(after.is_empty());
}

#[tokio::test]
#[serial]
async fn test_secure_write_atomic_force() {
    let test_dir = "tests/temp_security";
    let _ = fs::remove_dir_all(test_dir);
    fs::create_dir_all(test_dir).unwrap();

    let path = Path::new(test_dir).join("test.key");
    let content1 = b"initial content";
    let content2 = b"overwritten content";

    // 1. Initial write (no existing file)
    secure_write(&path, content1, false).expect("Initial write failed");
    assert_eq!(fs::read(&path).unwrap(), content1);

    // 2. Second write (fails without force)
    let res = secure_write(&path, content2, false);
    assert!(res.is_err());
    assert_eq!(fs::read(&path).unwrap(), content1);

    // 3. Third write (success with force)
    secure_write(&path, content2, true).expect("Force write failed");
    assert_eq!(fs::read(&path).unwrap(), content2);

    // 4. Verify permissions (unix mode bits; the windows owner-only DACL
    // equivalent is covered by secure_fs's native windows tests).
    #[cfg(unix)]
    {
        let metadata = fs::metadata(&path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    }

    let _ = fs::remove_dir_all(test_dir);
}

#[tokio::test]
#[serial]
async fn test_preload_encrypted_pem() {
    use nkct::config::{CryptoConfig, Operation};

    let test_dir = "tests/temp_encrypted_key";
    let _ = fs::remove_dir_all(test_dir);
    fs::create_dir_all(test_dir).unwrap();

    // 1. Generate an encrypted PQC key pair
    let mut config = CryptoConfig::default();
    config.mode = nkct::config::CryptoMode::PQC;
    config.operation = Operation::GenerateSignKey;
    config.key_dir = test_dir.to_string();
    config.passphrase = Some(zeroize::Zeroizing::new("testpass".to_string()));
    config.pqc_dsa_algo = "ML-DSA-65".to_string();

    let mut key_paths = std::collections::HashMap::new();
    key_paths.insert(
        "private-key".to_string(),
        format!("{}/private_sign_pqc.key", test_dir),
    );
    key_paths.insert(
        "public-key".to_string(),
        format!("{}/public_sign_pqc.key", test_dir),
    );

    let strategy = nkct::strategy::pqc::PqcStrategy::new();
    strategy
        .generate_signing_key_pair(
            &key_paths,
            config.passphrase.as_deref().map(|s| s.as_str()),
            config.force,
        )
        .expect("Failed to gen encrypted key");

    let priv_path = key_paths.get("private-key").unwrap().clone();

    // 2. Test extraction with correct passphrase
    let priv_bytes = fs::read(&priv_path).unwrap();
    let pem_str = String::from_utf8(priv_bytes).unwrap();
    let der = nkct::utils::unwrap_from_pem(&pem_str, "PRIVATE KEY").unwrap();
    
    let res = nkct::utils::extract_raw_private_key(&der, Some("testpass"));
    assert!(res.is_ok(), "Extraction failed with correct pass: {:?}", res.err());

    // 3. Test extraction with WRONG passphrase
    let res_wrong = nkct::utils::extract_raw_private_key(&der, Some("wrongpass"));
    assert!(res_wrong.is_err(), "Extraction should fail with wrong pass");
    let err_msg = format!("{}", res_wrong.err().unwrap());
    assert!(err_msg.contains("Decryption failed") || err_msg.contains("Wrong passphrase"), "Error message should be descriptive: {}", err_msg);

    let _ = fs::remove_dir_all(test_dir);
}
