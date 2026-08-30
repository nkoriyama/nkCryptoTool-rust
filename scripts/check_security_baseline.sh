#!/usr/bin/env bash
# Verify .security-baseline.sha256 against the list of files it must cover.
#
# `sha256sum --check` answers one question: do the lines in this file match the
# tree? It has no opinion about which lines ought to be there. The file handing
# it those lines is .security-baseline.sha256, which arrives with the very
# commit being judged -- ci.yml checks out the PR head and runs mandate_check.sh
# on it. So a contributor who wants a security-critical file to stop being
# watched never has to defeat a hash: he deletes that file's line. Every
# remaining line still matches, and the gate that exists to notice his change to
# src/utils.rs prints OK having never looked at it.
#
# The fix is to stop letting the checked file decide what gets checked. The set
# of covered paths comes from scripts/security_critical_files.txt -- the same
# list scripts/rebaseline_security.sh regenerates the baseline from, so the two
# cannot drift apart -- and the comparison runs in BOTH directions before a
# single hash is looked at:
#   - in the list but not the baseline: a file dropped out of coverage;
#   - in the baseline but not the list: a file nobody agreed to cover, which is
#     the padding you would add to keep a total looking healthy.
#
# What this deliberately does NOT do, so it is not read as more than it is:
# there is no floor on how many files are covered. A commit that genuinely
# deletes a security-critical file, drops it from the list and rebaselines is
# legitimate and has happened here (src/network/tcp.rs), and a floor would fail
# that maintainer while an attacker walks around it by swapping one path for a
# decoy in the same breath. Shrinking coverage is a decision, and the place it
# is caught is the diff of scripts/security_critical_files.txt, by a human.
# What this check guarantees is the narrower, mechanical property: the baseline
# covers exactly the set the list names, no more and no less.
#
# Malformed lines are rejected here rather than left to sha256sum. Measured on
# GNU coreutils 9.10: a line with 63 hex characters instead of 64 is warned
# about on stderr, skipped, and the exit status is still 0 -- i.e. the same
# silent loss of coverage in a different shape. --strict is passed as well, but
# it is the parse below that makes the set comparison total: every line either
# names a path or is an error.
#
# Fails closed. A missing list, a missing baseline, or an empty list is an
# error, not a pass; each of them would otherwise make any tree acceptable.
#
# Run from the repo root: bash scripts/check_security_baseline.sh
set -uo pipefail

LIST='scripts/security_critical_files.txt'
BASELINE='.security-baseline.sha256'

# Both files above are tree-controlled and everything quoted from them lands in
# a CI log, so nothing from them is printed raw: an ESC sequence in a crafted
# entry cannot change this script's verdict, but it can repaint the log lines
# around it. Non-printable bytes become '?'.
plain() { LC_ALL=C tr -c '[:print:]\n' '?'; }

if [ ! -f "$LIST" ]; then
    echo "FAIL: $LIST not found." >&2
    echo "  It is tracked, so this means deletion, and without it there is nothing" >&2
    echo "  to compare the baseline against. Restore it with 'git checkout -- $LIST'." >&2
    exit 1
fi

if [ ! -f "$BASELINE" ]; then
    echo "FAIL: $BASELINE not found." >&2
    echo "  Restore it with 'git checkout -- $BASELINE', or regenerate it with" >&2
    echo "  'bash scripts/rebaseline_security.sh' if the baseline is intentionally" >&2
    echo "  being renewed (HANDOFF §1.7.3)." >&2
    exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# The list format, shared with scripts/rebaseline_security.sh: one path per
# line, '#' comments and blank lines ignored. Keep the two parses identical.
grep -vE '^[[:space:]]*(#|$)' "$LIST" | LC_ALL=C sort > "$TMP/want"
if [ ! -s "$TMP/want" ]; then
    echo "FAIL: $LIST names no files -- an empty list makes every baseline pass." >&2
    exit 1
fi

# Every baseline line must be exactly '<64 hex><two spaces><path>', the form
# sha256sum writes. Anything else is reported by line number only: the content
# is attacker-chosen and the number is what locates it.
BAD_LINES="$(grep -cvE '^[0-9a-fA-F]{64}  [^[:space:]]' "$BASELINE" || true)"
if [ "$BAD_LINES" -ne 0 ]; then
    echo "FAIL: $BASELINE has $BAD_LINES line(s) that are not sha256sum entries:" >&2
    grep -nvE '^[0-9a-fA-F]{64}  [^[:space:]]' "$BASELINE" | cut -d: -f1 \
        | sed 's/^/  line /' >&2
    echo "  sha256sum skips lines it cannot parse and still exits 0, so a mangled" >&2
    echo "  entry is a file quietly leaving coverage. Regenerate the baseline with" >&2
    echo "  'bash scripts/rebaseline_security.sh'." >&2
    exit 1
fi

sed -E 's/^[0-9a-fA-F]{64}  //' "$BASELINE" | LC_ALL=C sort > "$TMP/got"

MISSING="$(comm -23 "$TMP/want" "$TMP/got")"
EXTRA="$(comm -13 "$TMP/want" "$TMP/got")"
if [ -n "$MISSING" ] || [ -n "$EXTRA" ]; then
    echo "FAIL: $BASELINE does not cover the set named by $LIST." >&2
    if [ -n "$MISSING" ]; then
        echo "  listed but NOT in the baseline (dropped out of coverage):" >&2
        printf '%s\n' "$MISSING" | sed 's/^/    /' | plain >&2
    fi
    if [ -n "$EXTRA" ]; then
        echo "  in the baseline but NOT listed (nobody agreed to cover these):" >&2
        printf '%s\n' "$EXTRA" | sed 's/^/    /' | plain >&2
    fi
    echo "  If the change to the covered set is intended, edit $LIST first and say" >&2
    echo "  why, then run 'bash scripts/rebaseline_security.sh' (HANDOFF §1.7.3)." >&2
    exit 1
fi

# Only now the hashes. --strict makes an unparseable line an error rather than a
# skip; the parse above should already have rejected every such line, and this
# is the second lock on that door. stderr is left attached rather than sent to
# /dev/null so anything sha256sum still objects to is visible in the CI log.
if ! sha256sum --check --strict --quiet "$BASELINE" 2>&1 | plain; then
    echo "FAIL: baselined file contents changed (see the FAILED lines above)." >&2
    echo "  Review the diff of each file, confirm no vulnerability was introduced," >&2
    echo "  then bless it with 'bash scripts/rebaseline_security.sh' and record the" >&2
    echo "  rationale in the commit message (HANDOFF §1.7.3)." >&2
    exit 1
fi

echo "OK: $BASELINE covers exactly the $(wc -l < "$TMP/want") file(s) named by $LIST, and every hash matches."
