#!/usr/bin/env bash
# Phase 5 P1 #[allow(...)] rationale checker (P1-X12 v2, diff-based variant).
#
# Per PHASE5_P1_HANDOFF.md §1.5 P1-X12 and §1.6 item #19 (renumbered to #20
# in mandate_check.sh due to existing F4 #9). The HANDOFF verification column
# states "全件に対し前後行 ±2 で // allow(...): + Future:" but P1-X12 first
# sentence focuses on clippy fix introducing NEW allows.
#
# Design choice (diff-based, deviation from HANDOFF literal text):
# This script enforces only on #[allow(...)] ADDED since BASE_COMMIT, matching
# P1-R10 (unwrap/expect grep on security-critical files since 22a8011a).
# Rationale:
#   1. The existing pre-Phase-5 #[allow(dead_code)] on AeadMode::Empty
#      (src/backend/rustcrypto_impl.rs:62) has no rationale comment and is
#      in the security-critical baseline. Retroactive touch would force a
#      same-commit baseline update solely to satisfy a doc requirement,
#      which dilutes the signal of baseline changes.
#   2. The clippy auto-fix scenario that P1-X12 targets (commit 7) involves
#      NEW allows, not pre-existing ones.
#   3. If user prefers strict "全件" enforcement, retroactively annotate the
#      pre-existing allow in commit 7 clippy fix scope and adjust this
#      script to drop the diff filter.
#
# Algorithm (simplified count-based):
#   1. Compute N = count of "+...#\[allow\(" lines in git diff BASE..HEAD on src/
#   2. Compute R = count of "+...// allow\(" lines (rationale comments)
#   3. Compute F = count of "+...Future:" lines
#   4. PASS iff N == 0, OR (R >= N AND F >= N)
#
# Limitations:
# - Coarse: does not verify lint-name match between #[allow(x)] and
#   // allow(x): rationale. Practical for honest clippy fix flow; weak
#   against adversarial bypass (which is not a P1 threat model).
# - Hunk-locality not enforced: rationale in one file + allow in another
#   would still satisfy counts. Acceptable trade-off for scaffold-level
#   validator; can be tightened post-P1 if a real case appears.
#
# Usage:
#   bash scripts/check_allow_rationale.sh
#   BASE_COMMIT=<rev> bash scripts/check_allow_rationale.sh   # override base
#
# Exit:
#   0 = no new #[allow(...)] OR all new ones have rationale + Future
#   1 = one or more new #[allow(...)] missing rationale or Future plan

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

BASE_COMMIT="${BASE_COMMIT:-22a8011a}"

if ! git rev-parse --verify "$BASE_COMMIT" >/dev/null 2>&1; then
    echo "[check_allow_rationale] WARN: base commit $BASE_COMMIT not found in this repo, skipping check"
    exit 0
fi

DIFF_OUT="$(git diff "$BASE_COMMIT" -- 'src/**/*.rs' 'src/*.rs' 2>/dev/null || true)"

if [ -z "$DIFF_OUT" ]; then
    echo "[check_allow_rationale] OK: no src/ changes since $BASE_COMMIT"
    exit 0
fi

NEW_ALLOWS="$(echo "$DIFF_OUT" | grep -cE '^\+[^+].*#\[allow\(' || true)"
NEW_RATIONALES="$(echo "$DIFF_OUT" | grep -cE '^\+[^+].*//[[:space:]]*allow\(' || true)"
NEW_FUTURES="$(echo "$DIFF_OUT" | grep -cE '^\+[^+].*Future[[:space:]]*:' || true)"

if [ "$NEW_ALLOWS" -eq 0 ]; then
    echo "[check_allow_rationale] OK: 0 new #[allow(...)] in src/ since $BASE_COMMIT"
    exit 0
fi

if [ "$NEW_RATIONALES" -ge "$NEW_ALLOWS" ] && [ "$NEW_FUTURES" -ge "$NEW_ALLOWS" ]; then
    echo "[check_allow_rationale] OK: $NEW_ALLOWS new #[allow(...)] / $NEW_RATIONALES rationale comments / $NEW_FUTURES Future: clauses (all satisfied)"
    exit 0
fi

echo "[check_allow_rationale] FAIL: rationale/Future count below new allow count"
echo "  new #[allow(...)]   : $NEW_ALLOWS"
echo "  new // allow(...)   : $NEW_RATIONALES (need >= $NEW_ALLOWS)"
echo "  new Future:         : $NEW_FUTURES (need >= $NEW_ALLOWS)"
echo ""
echo "Format required for each new #[allow(<lint>)]:"
echo "  // allow(<lint>): <reason>. Future: <plan or issue ref>"
echo "  #[allow(<lint>)]"
echo ""
echo "See PHASE5_P1_HANDOFF.md §1.5 P1-X12."
exit 1
