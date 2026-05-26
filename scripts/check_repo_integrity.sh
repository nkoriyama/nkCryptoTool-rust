#!/usr/bin/env bash
# Repository integrity check.
#
# Catches the failure mode where jj/git accidentally stops tracking
# critical source files while those files still exist on disk locally
# (so the developer's cargo build keeps passing, but anyone who clones
# the repo gets a broken tree).
#
# Real incident that motivated this script (2026-05-24 → 2026-05-26):
# a Phase 3 file-rename commit silently dropped 14 files from the
# tracked tree. cargo build and cargo test continued to pass locally
# because the files remained on disk. The breakage was discovered
# only two days later during an unrelated MLS implementation audit.
#
# This check should run *early* in CI so a fresh-clone build that
# would actually exercise the missing files isn't even needed to flag
# the regression.
#
# Usage: bash scripts/check_repo_integrity.sh
set -euo pipefail

# Files that must always exist in the tracked tree. Removal of any of
# these is almost certainly a snapshotting accident; intentional
# removal would warrant updating this list in the same commit.
MUST_EXIST=(
    "Cargo.toml"
    "Cargo.lock"
    "src/lib.rs"
    "src/main.rs"
    "src/processor.rs"
    "src/ticket.rs"
    "src/utils.rs"
    "src/config.rs"
    "src/error.rs"
    "src/network/mod.rs"
    "src/p2p/mod.rs"
    "src/p2p/traits.rs"
    "src/p2p/types.rs"
    "src/p2p/processor.rs"
    "src/p2p/backend/iroh.rs"
    "src/p2p/backend/mock.rs"
    "src/strategy/mod.rs"
    "src/backend/mod.rs"
)

# Floor for tracked .rs file count under src/. Currently 36; the floor
# allows minor legitimate removals while catching mass-deletes (the
# real incident lost 14 files at once, well below this floor).
SRC_MIN=30

missing=()
for f in "${MUST_EXIST[@]}"; do
    if ! git cat-file -e "HEAD:$f" 2>/dev/null; then
        missing+=("$f")
    fi
done

if (( ${#missing[@]} > 0 )); then
    echo "ERROR: required files missing from the tracked tree at HEAD:" >&2
    printf '  %s\n' "${missing[@]}" >&2
    echo >&2
    echo "This usually means a VCS snapshot dropped tracked files." >&2
    echo "Recovery: 'git add' the missing files (they likely still" >&2
    echo "exist on disk), verify with 'git ls-tree -r HEAD src/'," >&2
    echo "and commit." >&2
    exit 1
fi

src_count=$(git ls-tree -r HEAD -- src/ | wc -l)
if (( src_count < SRC_MIN )); then
    echo "ERROR: tracked src/ file count is ${src_count}, below floor ${SRC_MIN}." >&2
    echo "Mass-deletion safeguard: check 'git ls-tree -r HEAD src/' and" >&2
    echo "compare to the previous commit ('git diff --name-status HEAD~1 HEAD')." >&2
    exit 1
fi

echo "OK: repository integrity check passed (src/ files: ${src_count}, all required files present)."
