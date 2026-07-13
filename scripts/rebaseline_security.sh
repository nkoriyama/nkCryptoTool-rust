#!/usr/bin/env bash
# Regenerate .security-baseline.sha256 (consumed by mandate_check.sh §19).
#
# The baseline pins the exact contents of the security-critical source files
# so that any later change to them is surfaced for explicit review. Running
# this script BLESSES the current working-tree contents as the new trusted
# reference — only do so after reviewing the diff of every listed file and
# confirming no vulnerability was introduced. Record the rationale in the
# commit message (see HANDOFF §1.7.3).
#
# Run from the repo root: bash scripts/rebaseline_security.sh
set -euo pipefail

# Security-critical files. Keep this list in sync with the codebase layout.
# (iroh transport moved src/network/iroh.rs -> src/p2p/backend/iroh.rs during
#  the p2p abstraction refactor.)
#
# INVARIANT: this list MUST include the handshake body (src/p2p/processor.rs) —
# the mutual-auth transcript signing lives there. This list and the entries in
# .security-baseline.sha256 must be identical sets; a mismatch means a security-
# critical file silently drops out of coverage on the next rebaseline.
# (src/network/tcp.rs was removed here when the deprecated TCP transport was
# deleted — iroh is the only transport. That is an INTENTIONAL deletion, not the
# silent-drop drift #24 guarded against: the file no longer exists.)
FILES=(
    src/backend/mod.rs
    src/backend/openssl_impl.rs
    src/backend/rustcrypto_impl.rs
    src/p2p/backend/iroh.rs
    src/p2p/processor.rs
    src/network/mod.rs
    src/processor.rs
    src/secure_fs.rs
    src/utils.rs
)

missing=0
for f in "${FILES[@]}"; do
    if [ ! -f "$f" ]; then
        echo "ERROR: listed security-critical file not found: $f" >&2
        missing=1
    fi
done
[ "$missing" -eq 0 ] || { echo "Fix the FILES list before rebaselining." >&2; exit 1; }

sha256sum "${FILES[@]}" > .security-baseline.sha256
echo "Regenerated .security-baseline.sha256 (${#FILES[@]} files):"
cat .security-baseline.sha256
