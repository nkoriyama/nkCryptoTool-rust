//! ML-DSA FIPS 204 context-string plumbing (KEY_EXCHANGE_DESIGN.md §2, phase-3
//! increment 1). Runs against whichever backend is active. Proves the `ctx`
//! argument is actually bound into the signature (domain separation), not
//! silently dropped: a signature made under `ctx=A` verifies only under `ctx=A`.

use nk_crypto_tool::backend;

#[test]
fn mldsa_ctx_binds_the_signature() {
    let msg = b"domain separation message";
    let ctx_a: &[u8] = b"nkct-handshake-iroh-v1";
    let ctx_b: &[u8] = b"nkct-keybind-v1";
    // All supported ML-DSA algorithms: the ctx must bind for each (no parameter
    // set may silently ignore it).
    for algo in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"] {
        let (sk, pk, _) = backend::pqc_keygen_dsa(algo).expect("keygen");
        let sig = backend::pqc_sign(algo, &sk, msg, ctx_a).expect("sign");
        assert!(
            backend::pqc_verify(algo, &pk, msg, &sig, ctx_a).expect("verify a"),
            "{algo}: signature must verify under the same ctx",
        );
        assert!(
            !backend::pqc_verify(algo, &pk, msg, &sig, ctx_b).expect("verify b"),
            "{algo}: signature must NOT verify under a different ctx",
        );
        assert!(
            !backend::pqc_verify(algo, &pk, msg, &sig, &[]).expect("verify empty"),
            "{algo}: signature made with a ctx must NOT verify under empty ctx",
        );
    }
}

#[test]
fn mldsa_ctx_over_255_rejected() {
    // FIPS 204 caps the context string at 255 bytes; the wrapper must reject a
    // longer one up front rather than truncate / error opaquely in a backend.
    let algo = "ML-DSA-65";
    let msg = b"m";
    let (sk, pk, _) = backend::pqc_keygen_dsa(algo).expect("keygen");
    let too_long = vec![0x61u8; 256];
    assert!(backend::pqc_sign(algo, &sk, msg, &too_long).is_err(), "256-byte ctx sign must error");
    // 255 is allowed.
    let ok_ctx = vec![0x61u8; 255];
    let sig = backend::pqc_sign(algo, &sk, msg, &ok_ctx).expect("255-byte ctx sign ok");
    assert!(backend::pqc_verify(algo, &pk, msg, &sig, &ok_ctx).expect("verify 255"));
    assert!(backend::pqc_verify(algo, &pk, msg, &sig, &too_long).is_err(), "256-byte ctx verify must error");
}

#[test]
fn mldsa_empty_ctx_roundtrips() {
    // The `ctx=""` path (all callers in increment 1) must still round-trip —
    // i.e. no behaviour change for the pre-context signatures.
    let algo = "ML-DSA-65";
    let msg = b"empty ctx message";
    let (sk, pk, _) = backend::pqc_keygen_dsa(algo).expect("keygen");
    let sig = backend::pqc_sign(algo, &sk, msg, &[]).expect("sign");
    assert!(backend::pqc_verify(algo, &pk, msg, &sig, &[]).expect("verify"));
}
