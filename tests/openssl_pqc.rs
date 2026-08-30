#![cfg(feature = "backend-openssl")]

use nkct::backend;

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
        let sig = backend::pqc_sign(algo, &sk, msg, &[]).expect(algo);
        let ok = backend::pqc_verify(algo, &pk, msg, &sig, &[]).expect(algo);
        assert!(ok, "Verify failed for {}", algo);
    }
}

#[cfg(all(feature = "backend-openssl", feature = "backend-rustcrypto"))]
#[test]
fn test_pqc_interop_rustcrypto_openssl() {
    use nkct::backend::{openssl_impl, rustcrypto_impl};

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
        let sig_rc = rustcrypto_impl::pqc_sign(algo, &sk_rc, msg, &[]).unwrap();
        let ok_os = openssl_impl::pqc_verify(algo, &pk_rc, msg, &sig_rc, &[]).unwrap();
        assert!(ok_os, "Interop DSA RC->OS verify failed for {}", algo);

        // 2. OS keygen -> OS sign -> RC verify
        let (sk_os, pk_os, _) = openssl_impl::pqc_keygen_dsa(algo).unwrap();
        let sig_os = openssl_impl::pqc_sign(algo, &sk_os, msg, &[]).unwrap();
        let ok_rc = rustcrypto_impl::pqc_verify(algo, &pk_os, msg, &sig_os, &[]).unwrap();
        assert!(ok_rc, "Interop DSA OS->RC verify failed for {}", algo);
    }
}

/// Cross-backend **context-string** interop (KEY_EXCHANGE_DESIGN.md §2/§8, point C).
/// Both backends must implement FIPS 204 *pure* ML-DSA with the same `ctx`
/// encoding (`M' = 0x00 ‖ len(ctx) ‖ ctx ‖ M`), so a signature made with `ctx=X`
/// on one backend verifies under the other with `ctx=X`, and NOT with a different
/// or empty ctx (proving the ctx is actually bound and not silently dropped).
#[cfg(all(feature = "backend-openssl", feature = "backend-rustcrypto"))]
#[test]
fn mldsa_ctx_interop_both_backends() {
    use nkct::backend::{openssl_impl, rustcrypto_impl};
    // Parameterized over EVERY ML-DSA algorithm the tool supports: OpenSSL's
    // `context-string` param must bind the ctx identically to fips204 for all
    // three, or one parameter set could silently drop the ctx (a quiet loss of
    // domain separation). Each algo asserts "different / empty ctx MUST fail".
    let msg = b"context-string interop message";
    let ctx_a: &[u8] = b"nkct-handshake-iroh-v1";
    let ctx_b: &[u8] = b"nkct-handshake-tcp-v1";
    for algo in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"] {
        println!("ctx interop: {algo}");
        // RC sign(ctx_a) -> OS verify: ctx_a OK, ctx_b / empty fail.
        let (sk_rc, pk_rc, _) = rustcrypto_impl::pqc_keygen_dsa(algo).unwrap();
        let sig = rustcrypto_impl::pqc_sign(algo, &sk_rc, msg, ctx_a).unwrap();
        assert!(openssl_impl::pqc_verify(algo, &pk_rc, msg, &sig, ctx_a).unwrap(), "{algo} RC->OS same ctx");
        assert!(!openssl_impl::pqc_verify(algo, &pk_rc, msg, &sig, ctx_b).unwrap(), "{algo} RC->OS diff ctx must fail");
        assert!(!openssl_impl::pqc_verify(algo, &pk_rc, msg, &sig, &[]).unwrap(), "{algo} RC->OS empty ctx must fail");
        assert!(!rustcrypto_impl::pqc_verify(algo, &pk_rc, msg, &sig, ctx_b).unwrap(), "{algo} RC same-backend diff ctx must fail");

        // OS sign(ctx_a) -> RC verify: ctx_a OK, ctx_b / empty fail.
        let (sk_os, pk_os, _) = openssl_impl::pqc_keygen_dsa(algo).unwrap();
        let sig2 = openssl_impl::pqc_sign(algo, &sk_os, msg, ctx_a).unwrap();
        assert!(rustcrypto_impl::pqc_verify(algo, &pk_os, msg, &sig2, ctx_a).unwrap(), "{algo} OS->RC same ctx");
        assert!(!rustcrypto_impl::pqc_verify(algo, &pk_os, msg, &sig2, ctx_b).unwrap(), "{algo} OS->RC diff ctx must fail");
        assert!(!rustcrypto_impl::pqc_verify(algo, &pk_os, msg, &sig2, &[]).unwrap(), "{algo} OS->RC empty ctx must fail");
        // OpenSSL same-backend cross-ctx sanity (the OSSL_PARAM path itself binds ctx).
        assert!(!openssl_impl::pqc_verify(algo, &pk_os, msg, &sig2, ctx_b).unwrap(), "{algo} OS same-backend diff ctx must fail");
    }
}
