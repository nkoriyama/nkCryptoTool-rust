#!/usr/bin/env bash
#
# Build the Rust core as Android .so files (per ABI) and generate the matching
# UniFFI Kotlin bindings, placing both where the Gradle app picks them up:
#
#   android/app/src/main/jniLibs/<abi>/libnkct.so   (staged here)
#   android/app/src/main/java/uniffi/nkct/...kt      (generated here)
#
# Both are gitignored — run this before building the APK. Requires the Android
# NDK (set ANDROID_NDK_HOME) + `cargo-ndk` + the aarch64/x86_64 rust targets.
# See ../docs/guides/BUILD_ANDROID.md for the one-time toolchain setup.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$HOME/android-ndk-r27c}"
FEATURES="backend-rustcrypto mls mobile-ffi"
JNILIBS="android/app/src/main/jniLibs"
JAVA_SRC="android/app/src/main/java"

echo "==> building libnkct.so (arm64-v8a, x86_64)"
# `-o` copies each built .so into <JNILIBS>/<abi>/.
cargo ndk -t arm64-v8a -t x86_64 -o "$JNILIBS" \
    build --release --no-default-features --features "$FEATURES"

# cargo-ndk also copies intermediate dependency dylibs (libiroh*.so etc.) that
# our cdylib statically links and does NOT dlopen — drop everything but ours so
# the APK ships only the one library it actually loads.
find "$JNILIBS" -name '*.so' ! -name 'libnkct.so' -delete

echo "==> generating Kotlin bindings"
cargo run --no-default-features --features "$FEATURES" --bin uniffi-bindgen -- \
    generate \
    --library "$JNILIBS/arm64-v8a/libnkct.so" \
    --language kotlin \
    --out-dir "$JAVA_SRC"

echo "==> staged:"
find "$JNILIBS" -name '*.so'
find "$JAVA_SRC/uniffi" -name '*.kt'
echo "Now build the app:  cd android && ./gradlew assembleDebug   (or open in Android Studio)"
