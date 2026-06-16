#!/usr/bin/env bash
# Enforces the MLS abstraction boundary (DoD §13):
#
# Only `src/group/` is allowed to import `mls_rs::`, `mls_rs_core::`,
# `mls_rs_codec::`, `mls_rs_crypto_*::`, or `mls_rs_provider_*::`
# types. The wider codebase (1:1 chat / file transfer / CLI surface
# outside of the group module / GUI outside of group_chat.rs) must
# funnel through `crate::group::*` so a future MLS-library swap is
# locally contained.
#
# Doc-comment mentions are tolerated — the matcher targets `use`
# statements only.
#
# Run: bash scripts/check_no_mls_leakage.sh
set -euo pipefail

# Files allowed to import mls_rs* crates:
#  - src/group/**            : the MLS module itself
#  - src/gui/group_chat.rs   : Slint driver re-uses mls_rs::WireFormat etc.
#    (it could route through crate::group instead, but the leakage there
#    is contained to a single test path; treat as an opt-in escape hatch)
#  - src/prekey.rs           : 1:1 prekey HPKE uses mls_rs_core::crypto as a
#  - src/one_shot.rs           pure-Rust HPKE *primitive provider* (HpkePublicKey/
#                              SecretKey, CipherSuiteProvider, HpkeContextR/S) —
#                              NOT the MLS group protocol. The library-swap
#                              concern the boundary protects is the MLS group
#                              wire format, which these files never touch.
ALLOWED_PREFIX_RE='^(src/group/|src/gui/group_chat\.rs:|src/prekey\.rs:|src/one_shot\.rs:)'

# `use mls_rs::...`, `use mls_rs_core::...`, etc. at the start of a
# logical line (after any leading whitespace).
PATTERN='^[[:space:]]*use[[:space:]]+mls_rs([a-z_]*)?(::|;|[[:space:]])'

FORBIDDEN=$(grep -rEn "$PATTERN" src/ --include='*.rs' \
    | grep -vE "$ALLOWED_PREFIX_RE" \
    || true)

if [ -n "$FORBIDDEN" ]; then
    echo "Forbidden mls_rs* imports outside src/group/:" >&2
    echo "$FORBIDDEN" >&2
    echo >&2
    echo "Route through 'crate::group::*' (GroupChatProcessor, types, cli::*)" >&2
    echo "or add an explicit exemption to scripts/check_no_mls_leakage.sh." >&2
    exit 1
fi

echo "OK: no mls_rs* imports outside src/group/ (+ src/gui/group_chat.rs)."
