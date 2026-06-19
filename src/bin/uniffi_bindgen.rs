//! Thin entry point for UniFFI's binding generator. Build with the
//! `mobile-ffi` feature, then e.g.:
//!
//! ```sh
//! cargo run --features "backend-rustcrypto mls mobile-ffi" --bin uniffi-bindgen -- \
//!   generate --library target/debug/libnk_crypto_tool.so --language kotlin --out-dir bindings/kotlin
//! ```
//!
//! See `BUILD_ANDROID.md`.

fn main() {
    uniffi::uniffi_bindgen_main()
}
