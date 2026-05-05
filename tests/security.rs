use nk_crypto_tool::utils::secure_write;
use nk_crypto_tool::strategy::CryptoStrategy;
use std::fs;
use std::path::Path;
use std::os::unix::fs::PermissionsExt;

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
    
    let metadata = fs::metadata(&path).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

    // 2. Overwrite without force (should fail)
    let res = secure_write(&path, content2, false);
    assert!(res.is_err());
    assert_eq!(fs::read(&path).unwrap(), content1); // Content should be unchanged

    // 3. Overwrite with force (should succeed)
    secure_write(&path, content2, true).expect("Overwriting with force failed");
    assert_eq!(fs::read(&path).unwrap(), content2);
    
    let metadata = fs::metadata(&path).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

    // 4. Overwrite file with wrong permissions (should become 0600)
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    secure_write(&path, content1, true).expect("Force overwrite failed");
    let metadata = fs::metadata(&path).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

    let _ = fs::remove_dir_all(test_dir);
}

#[cfg(feature = "backend-rustcrypto")]
#[tokio::test]
async fn test_preload_encrypted_pem() {
    use nk_crypto_tool::config::{CryptoConfig, Operation};
    use nk_crypto_tool::network::NetworkProcessor;

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

    let _strategy = nk_crypto_tool::strategy::pqc::PqcStrategy::new();
    _strategy
        .generate_signing_key_pair(
            &key_paths,
            config.passphrase.as_deref().map(|s| s.as_str()),
            config.force,
        )
        .expect("Failed to gen encrypted key");

    let priv_path = key_paths.get("private-key").unwrap().clone();

    // 2. Test preloading with correct passphrase
    let mut net_config = CryptoConfig::default();
    net_config.signing_privkey = Some(priv_path.clone());
    net_config.passphrase = Some(zeroize::Zeroizing::new("testpass".to_string()));
    net_config.pqc_dsa_algo = "ML-DSA-65".to_string();

    let mut net_processor = NetworkProcessor::new(net_config);
    net_processor.preload_signing_key().await.expect("Preload failed with correct pass");
    assert!(net_processor.has_cached_signing_key());

    // 3. Test preloading with WRONG passphrase
    let mut net_config_wrong = CryptoConfig::default();
    net_config_wrong.signing_privkey = Some(priv_path.clone());
    net_config_wrong.passphrase = Some(zeroize::Zeroizing::new("wrongpass".to_string()));
    net_config_wrong.pqc_dsa_algo = "ML-DSA-65".to_string();

    let mut net_processor_wrong = NetworkProcessor::new(net_config_wrong);
    let res = net_processor_wrong.preload_signing_key().await;
    assert!(res.is_err(), "Preload should fail with wrong pass");
    let err_msg = format!("{}", res.err().unwrap());
    assert!(err_msg.contains("Decryption failed") || err_msg.contains("Wrong passphrase"), "Error message should be descriptive: {}", err_msg);

    let _ = fs::remove_dir_all(test_dir);
}
