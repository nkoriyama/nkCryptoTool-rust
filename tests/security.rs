use nk_crypto_tool::strategy::CryptoStrategy;
use nk_crypto_tool::utils::secure_write;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

#[tokio::test]
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

    // 4. Verify permissions
    let metadata = fs::metadata(&path).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

    let _ = fs::remove_dir_all(test_dir);
}

#[tokio::test]
async fn test_preload_encrypted_pem() {
    use nk_crypto_tool::config::{CryptoConfig, Operation};

    let test_dir = "tests/temp_encrypted_key";
    let _ = fs::remove_dir_all(test_dir);
    fs::create_dir_all(test_dir).unwrap();

    // 1. Generate an encrypted PQC key pair
    let mut config = CryptoConfig::default();
    config.mode = nk_crypto_tool::config::CryptoMode::PQC;
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

    let strategy = nk_crypto_tool::strategy::pqc::PqcStrategy::new();
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
    let der = nk_crypto_tool::utils::unwrap_from_pem(&pem_str, "PRIVATE KEY").unwrap();
    
    let res = nk_crypto_tool::utils::extract_raw_private_key(&der, Some("testpass"));
    assert!(res.is_ok(), "Extraction failed with correct pass: {:?}", res.err());

    // 3. Test extraction with WRONG passphrase
    let res_wrong = nk_crypto_tool::utils::extract_raw_private_key(&der, Some("wrongpass"));
    assert!(res_wrong.is_err(), "Extraction should fail with wrong pass");
    let err_msg = format!("{}", res_wrong.err().unwrap());
    assert!(err_msg.contains("Decryption failed") || err_msg.contains("Wrong passphrase"), "Error message should be descriptive: {}", err_msg);

    let _ = fs::remove_dir_all(test_dir);
}
