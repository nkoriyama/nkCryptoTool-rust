#!/usr/bin/env bash
# Phase 5 P1 #[allow(...)] rationale + future plan checker (P1-X12 v2).
#
# Verifies that every `#[allow(<lint>)]` attribute in src/ has an accompanying
# rationale comment in the form:
#   // allow(<lint>): <reason>. Future: <plan or issue ref>
#
# Per PHASE5_P1_HANDOFF.md §1.5 P1-X12 (v2 strengthening, Gemini P1 §3.4#3
# reflected). The Future: clause prevents indefinite accumulation of suppressed
# warnings without follow-up plans.
#
# STATUS: scaffold only — empty implementation that exits 0 to keep
# mandate_check.sh (item #19) functional while the full validator is
# being designed. Phase 5 P1 commit 4 will replace this with the real
# implementation that:
#   1. Greps src/**/*.rs for `#[allow(...)]` occurrences
#   2. For each hit, checks ±2 lines for `// allow(<same lint>):` + `Future:`
#   3. Reports missing rationale or missing Future plan
#   4. Exits 1 if any violation, 0 otherwise
#
# Usage:
#   bash scripts/check_allow_rationale.sh
#
# Exit:
#   0 = all #[allow(...)] have rationale + Future plan (or scaffold mode)
#   1 = one or more #[allow(...)] missing rationale or Future plan

set -uo pipefail

echo "[check_allow_rationale] scaffold mode: validation not yet implemented (commit 4 follow-up)"
echo "[check_allow_rationale] reference: PHASE5_P1_HANDOFF.md §1.5 P1-X12, §1.6 item #19"

# TODO (Phase 5 P1 commit 4): implement actual validation per the algorithm
# described in the module docstring above. Until then, this script is a
# placeholder so that mandate_check.sh item #19 has something to invoke
# without erroring.

exit 0
