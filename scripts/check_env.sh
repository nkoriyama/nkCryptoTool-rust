#!/usr/bin/env bash
# Phase 5 P1 environment pre-flight check (P1-R5).
#
# Advisory script that reports OS-specific build requirements for the
# three crypto backends (backend-openssl / backend-openssl-vendored /
# backend-rustcrypto) and the four GUI features (gui-camera / gui-notifications
# / gui-screen-protection / gui-file-transfer).
#
# This script is INFORMATIONAL: missing optional dependencies produce
# warnings rather than failures, since a developer building only a subset
# of features need not satisfy every system requirement. Hard failures are
# limited to truly catastrophic gaps (no Rust toolchain, no C compiler).
#
# In Phase 5 P1 commit 4, this script will be invoked from mandate_check.sh
# as item #13, gating release readiness on exit status.
#
# Usage:
#   bash scripts/check_env.sh
#
# Exit:
#   0 = environment is workable (warnings allowed)
#   1 = environment is unworkable (missing Rust / C compiler / etc.)
#   2 = unknown OS (script does not know how to advise)

set -uo pipefail

ERROR_COUNT=0
WARN_COUNT=0
OK_COUNT=0

ok()    { printf '[check_env] %s .. \033[32mOK\033[0m   %s\n' "$1" "${2:-}";   OK_COUNT=$((OK_COUNT + 1)); }
warn()  { printf '[check_env] %s .. \033[33mWARN\033[0m %s\n' "$1" "${2:-}"; WARN_COUNT=$((WARN_COUNT + 1)); }
err()   { printf '[check_env] %s .. \033[31mERR\033[0m  %s\n' "$1" "${2:-}";  ERROR_COUNT=$((ERROR_COUNT + 1)); }

has_cmd() { command -v "$1" >/dev/null 2>&1; }
has_pkg() { has_cmd pkg-config && pkg-config --exists "$1" 2>/dev/null; }

# ----------------------------------------------------------------------------
# 1. OS detection
# ----------------------------------------------------------------------------
case "$(uname -s 2>/dev/null || echo unknown)" in
    Linux*)               OS=linux ;;
    Darwin*)              OS=macos ;;
    MINGW*|MSYS*|CYGWIN*) OS=windows ;;
    *)
        err "OS detection" "unknown OS: $(uname -s 2>/dev/null || echo unknown)"
        exit 2
        ;;
esac
ok "OS detection" "$OS ($(uname -sr 2>/dev/null))"

# ----------------------------------------------------------------------------
# 2. Rust toolchain (mandatory for all backends)
# ----------------------------------------------------------------------------
if has_cmd cargo; then
    ok "cargo" "$(cargo --version 2>/dev/null | head -1)"
else
    err "cargo" "Rust toolchain not found. Install from https://rustup.rs/"
fi

if has_cmd rustc; then
    ok "rustc" "$(rustc --version 2>/dev/null | head -1)"
else
    err "rustc" "Rust compiler not found"
fi

# ----------------------------------------------------------------------------
# 3. C compiler (mandatory: openssl-sys, ring, fips203/204 link C code)
# ----------------------------------------------------------------------------
if has_cmd cc || has_cmd gcc || has_cmd clang; then
    if has_cmd cc;    then ok "cc"    "$(cc    --version 2>/dev/null | head -1)"; fi
    if has_cmd gcc;   then ok "gcc"   "$(gcc   --version 2>/dev/null | head -1)"; fi
    if has_cmd clang; then ok "clang" "$(clang --version 2>/dev/null | head -1)"; fi
else
    err "C compiler" "no cc / gcc / clang found. Required for openssl-sys, ring, fips203."
fi

# ----------------------------------------------------------------------------
# 4. pkg-config (for backend-openssl on Linux/macOS, and several GUI features)
# ----------------------------------------------------------------------------
case "$OS" in
    linux|macos)
        if has_cmd pkg-config; then
            ok "pkg-config" "$(pkg-config --version 2>/dev/null)"
        else
            warn "pkg-config" "not found. Required for --features backend-openssl, gui-file-transfer, gui-notifications, gui-camera. Install via package manager (pkg-config / pkgconf)."
        fi
        ;;
esac

# ----------------------------------------------------------------------------
# 5. backend-openssl: system OpenSSL >= 3.5 for PQC
# ----------------------------------------------------------------------------
case "$OS" in
    linux|macos)
        if has_pkg openssl; then
            OPENSSL_VER="$(pkg-config --modversion openssl 2>/dev/null)"
            HIGHEST="$(printf '%s\n3.5.0\n' "$OPENSSL_VER" | sort -V | tail -1)"
            if [ "$HIGHEST" = "$OPENSSL_VER" ] && [ "$OPENSSL_VER" != "3.5.0" ] || [ "$OPENSSL_VER" = "3.5.0" ]; then
                ok "openssl (backend-openssl)" "$OPENSSL_VER (PQC-capable)"
            else
                warn "openssl (backend-openssl)" "$OPENSSL_VER < 3.5. --features backend-openssl will lack ML-KEM/ML-DSA. Use --features backend-openssl-vendored or backend-rustcrypto instead."
            fi
        else
            warn "openssl (backend-openssl)" "not found via pkg-config. --features backend-openssl will fail to link. Install libssl-dev (Debian/Ubuntu), openssl-devel (Fedora/RHEL), or 'brew install openssl@3' (macOS)."
        fi
        ;;
    windows)
        warn "openssl (backend-openssl)" "system OpenSSL on Windows is unusual. Prefer --features backend-openssl-vendored."
        ;;
esac

# ----------------------------------------------------------------------------
# 6. backend-openssl-vendored: perl + (Windows: NASM)
# ----------------------------------------------------------------------------
if has_cmd perl; then
    ok "perl (backend-openssl-vendored)" "$(perl -e 'print $^V' 2>/dev/null)"
else
    warn "perl (backend-openssl-vendored)" "not found. Required to build vendored OpenSSL 3.6.2 from source."
fi

case "$OS" in
    windows)
        if has_cmd nasm; then
            ok "nasm (backend-openssl-vendored, Windows)" "$(nasm -v 2>/dev/null | head -1)"
        else
            warn "nasm (backend-openssl-vendored, Windows)" "not found. Required for OpenSSL assembly on Windows."
        fi
        ;;
esac

# ----------------------------------------------------------------------------
# 7. backend-rustcrypto: pure Rust, no extra OS dependencies (informational)
# ----------------------------------------------------------------------------
ok "backend-rustcrypto" "pure Rust, no external system dependencies required"

# ----------------------------------------------------------------------------
# 8. GUI features: gui-file-transfer (rfd) — GTK3 on Linux
# ----------------------------------------------------------------------------
case "$OS" in
    linux)
        if has_pkg gtk+-3.0; then
            ok "gtk+-3.0 (gui-file-transfer)" "$(pkg-config --modversion gtk+-3.0 2>/dev/null)"
        else
            warn "gtk+-3.0 (gui-file-transfer)" "not found. Required for rfd native file dialog. Install libgtk-3-dev (Debian/Ubuntu) or gtk3-devel (Fedora)."
        fi
        ;;
esac

# ----------------------------------------------------------------------------
# 9. GUI features: gui-notifications (notify-rust) — DBus on Linux
# ----------------------------------------------------------------------------
case "$OS" in
    linux)
        if has_pkg dbus-1; then
            ok "dbus-1 (gui-notifications)" "$(pkg-config --modversion dbus-1 2>/dev/null)"
        else
            warn "dbus-1 (gui-notifications)" "not found. Required for notify-rust on Linux. Install libdbus-1-dev (Debian/Ubuntu) or dbus-devel (Fedora)."
        fi
        ;;
esac

# ----------------------------------------------------------------------------
# 10. GUI features: gui-camera (nokhwa) — GStreamer on Linux
# ----------------------------------------------------------------------------
case "$OS" in
    linux)
        if has_pkg gstreamer-1.0; then
            ok "gstreamer-1.0 (gui-camera)" "$(pkg-config --modversion gstreamer-1.0 2>/dev/null)"
        else
            warn "gstreamer-1.0 (gui-camera)" "not found. Required for nokhwa camera capture on Linux. Install libgstreamer1.0-dev + libgstreamer-plugins-base1.0-dev (Debian/Ubuntu) or gstreamer1-devel + gstreamer1-plugins-base-devel (Fedora)."
        fi
        ;;
esac

# ----------------------------------------------------------------------------
# Summary
# ----------------------------------------------------------------------------
echo
printf '[check_env] summary: \033[32m%d OK\033[0m, \033[33m%d WARN\033[0m, \033[31m%d ERR\033[0m\n' \
    "$OK_COUNT" "$WARN_COUNT" "$ERROR_COUNT"

if [ "$ERROR_COUNT" -gt 0 ]; then
    echo "[check_env] hard failure: cannot build any backend. Resolve ERR entries above before proceeding."
    exit 1
fi

if [ "$WARN_COUNT" -gt 0 ]; then
    echo "[check_env] advisory: some feature combinations may fail to build. Resolve WARN entries above if those features are needed."
fi

exit 0
