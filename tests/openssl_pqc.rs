#![cfg(feature = "backend-openssl")]

use nk_crypto_tool::backend;

#[test]
fn test_openssl_pqc_kem_roundtrip() {
    for algo in ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"] {
        println!("Testing {}", algo);
        let (sk, pk, _) = backend::pqc_keygen_kem(algo).expect(algo);
        let (ss1, ct) = backend::pqc_encap(algo, &pk).expect(algo);
        let ss2 = backend::pqc_decap(algo, &sk, &ct, None).expect(algo);
        assert_eq!(&*ss1, &*ss2, "SS mismatch for {}", algo);
    }
}

#[test]
fn test_openssl_pqc_dsa_roundtrip() {
    for algo in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"] {
        println!("Testing {}", algo);
        let (sk, pk, _) = backend::pqc_keygen_dsa(algo).expect(algo);
        let msg = b"hello world";
        let sig = backend::pqc_sign(algo, &sk, msg, None).expect(algo);
        let ok = backend::pqc_verify(algo, &pk, msg, &sig).expect(algo);
        assert!(ok, "Verify failed for {}", algo);
    }
}

#[cfg(all(feature = "backend-openssl", feature = "backend-rustcrypto"))]
#[test]
fn test_pqc_interop_rustcrypto_openssl() {
    use nk_crypto_tool::backend::{openssl_impl, rustcrypto_impl};

    // KEM Interop
    for algo in ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"] {
        println!("Interoperability KEM: {}", algo);
        // 1. RC keygen -> OS encap -> RC decap
        let (sk_rc, pk_rc, _) = rustcrypto_impl::pqc_keygen_kem(algo).unwrap();
        let (ss_os, ct_os) = openssl_impl::pqc_encap(algo, &pk_rc).unwrap();
        let ss_rc = rustcrypto_impl::pqc_decap(algo, &sk_rc, &ct_os, None).unwrap();
        assert_eq!(&*ss_os, &*ss_rc, "Interop KEM RC->OS->RC failed for {}", algo);

        // 2. OS keygen -> RC encap -> OS decap
        let (sk_os, pk_os, _) = openssl_impl::pqc_keygen_kem(algo).unwrap();
        let (ss_rc, ct_rc) = rustcrypto_impl::pqc_encap(algo, &pk_os).unwrap();
        let ss_os = openssl_impl::pqc_decap(algo, &sk_os, &ct_rc, None).unwrap();
        assert_eq!(&*ss_rc, &*ss_os, "Interop KEM OS->RC->OS failed for {}", algo);
    }

    // DSA Interop
    for algo in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"] {
        println!("Interoperability DSA: {}", algo);
        let msg = b"interop test message";

        // 1. RC keygen -> RC sign -> OS verify
        let (sk_rc, pk_rc, _) = rustcrypto_impl::pqc_keygen_dsa(algo).unwrap();
        let sig_rc = rustcrypto_impl::pqc_sign(algo, &sk_rc, msg, None).unwrap();
        let ok_os = openssl_impl::pqc_verify(algo, &pk_rc, msg, &sig_rc).unwrap();
        assert!(ok_os, "Interop DSA RC->OS verify failed for {}", algo);

        // 2. OS keygen -> OS sign -> RC verify
        let (sk_os, pk_os, _) = openssl_impl::pqc_keygen_dsa(algo).unwrap();
        let sig_os = openssl_impl::pqc_sign(algo, &sk_os, msg, None).unwrap();
        let ok_rc = rustcrypto_impl::pqc_verify(algo, &pk_os, msg, &sig_os).unwrap();
        assert!(ok_rc, "Interop DSA OS->RC verify failed for {}", algo);
    }
}
