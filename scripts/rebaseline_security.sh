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

# Security-critical files. The list itself lives in
# scripts/security_critical_files.txt — see that file for what belongs in it and
# why — because the gate that checks this script's output reads the same list.
# When the list lived here, only this script knew the covered set: mandate_check
# §19 verified whatever entries .security-baseline.sha256 happened to contain,
# so a deleted entry deleted the coverage with the gate none the wiser.
LIST='scripts/security_critical_files.txt'
[ -f "$LIST" ] || { echo "ERROR: $LIST not found — run this from the repo root." >&2; exit 1; }

# Format: one path per line, '#' comments and blank lines ignored. Keep this
# parse identical to the one in scripts/check_security_baseline.sh. (A read
# loop rather than `mapfile`, which the bash 3.2 shipped on macOS lacks.)
FILES=()
while IFS= read -r f; do FILES+=("$f"); done \
    < <(grep -vE '^[[:space:]]*(#|$)' "$LIST")
[ "${#FILES[@]}" -gt 0 ] || { echo "ERROR: $LIST names no files." >&2; exit 1; }

missing=0
for f in "${FILES[@]}"; do
    if [ ! -f "$f" ]; then
        echo "ERROR: listed security-critical file not found: $f" >&2
        missing=1
    fi
done
[ "$missing" -eq 0 ] || { echo "Fix $LIST before rebaselining." >&2; exit 1; }

sha256sum "${FILES[@]}" > .security-baseline.sha256
echo "Regenerated .security-baseline.sha256 (${#FILES[@]} files):"
cat .security-baseline.sha256
