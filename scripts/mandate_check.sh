#!/usr/bin/env bash
# Phase 4 F4 release-blocking pre-flight check (F4-R6).
#
# Mechanically verifies invariants that no implementation cycle should violate:
#   - Cargo.toml version unchanged (or release-mode v2.1.0)
#   - No premature release tags (v2.1.*)
#   - Test count not regressed
#   - Security-critical files not significantly shrunk
#   - No placeholder comments (Simplified for brevity / hacky way / etc.)
#   - main commits since v2.0.4 are linear (no merge / rebase / squash)
#   - CI yaml does not contain forbidden patterns (pull_request_target,
#     write-all permissions, secret echo)
#
# Usage:
#   bash scripts/mandate_check.sh           # default (development) mode
#   RELEASE_MODE=1 bash scripts/mandate_check.sh   # release readiness mode
#
# Exit:
#   0 = all checks PASS, ready to commit / release
#   1 = one or more checks FAILED, must investigate

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

pass() { printf '[mandate] %s .. \033[32mOK\033[0m\n' "$1"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { printf '[mandate] %s .. \033[31mFAIL\033[0m %s\n' "$1" "${2:-}"; FAIL_COUNT=$((FAIL_COUNT + 1)); }
warn() { printf '[mandate] %s .. \033[33mWARN\033[0m %s\n' "$1" "${2:-}"; WARN_COUNT=$((WARN_COUNT + 1)); }

# 1. Cargo.toml version
# Default (development) mode accepts the most recent shipped baseline (2.1.0,
# the v2.1.0 release) OR its predecessor (2.0.4, the previous baseline).
# This way the script tolerates the version transition while still preventing
# arbitrary version bumps. RELEASE_MODE=1 expects exactly the next release
# (2.1.0 prior to its tag, will be bumped per release).
if [ "${RELEASE_MODE:-0}" = "1" ]; then
    if grep -qE '^version = "(2\.1\.0|2\.2\.0)"$' Cargo.toml; then
        pass "Cargo.toml version (release mode): $(grep '^version' Cargo.toml | head -1)"
    else
        fail "Cargo.toml version" "expected 2.1.0 or 2.2.0 in RELEASE_MODE, got: $(grep '^version' Cargo.toml | head -1)"
    fi
else
    if grep -qE '^version = "(2\.0\.4|2\.1\.0)"$' Cargo.toml; then
        pass "Cargo.toml version (dev mode, accepted baseline): $(grep '^version' Cargo.toml | head -1)"
    else
        fail "Cargo.toml version" "expected 2.0.4 or 2.1.0 baseline, got: $(grep '^version' Cargo.toml | head -1)"
    fi
fi

# 2. Tag check: ensure no PREMATURE tags exist for unreleased versions.
# The "released" set after v2.1.0 = v2.1.0 + all v2.0.x. Future versions
# (v2.1.1, v2.2.0, etc.) must NOT be tagged before their respective release.
# RELEASE_MODE=1 additionally allows the next release (v2.2.0 etc.) to be
# tagged simultaneously with the release commit.
ALL_TAGS="$(git tag -l 'v2.*' 2>/dev/null || true)"
PREMATURE="$(echo "$ALL_TAGS" | grep -vE '^v2\.0\.[0-9]+$|^v2\.1\.0$' || true)"
if [ "${RELEASE_MODE:-0}" = "1" ]; then
    # Allow the upcoming release tags (broaden as needed at release time).
    PREMATURE="$(echo "$PREMATURE" | grep -vE '^v2\.1\.[1-9][0-9]*$|^v2\.2\.0$' || true)"
fi
if [ -z "$PREMATURE" ] || [ "$PREMATURE" = "" ]; then
    pass "no premature future-version tags"
else
    fail "premature tags" "$(echo "$PREMATURE" | tr '\n' ' ')"
fi

# 3. gui_test fn count >= 33
GUI_TEST_COUNT="$(grep -cE '^    (#\[test\]|#\[tokio::test\])' tests/gui_test.rs || echo 0)"
if [ "$GUI_TEST_COUNT" -ge 33 ]; then
    pass "gui_test fn count >= 33 (actual $GUI_TEST_COUNT)"
else
    fail "gui_test fn count" "expected >= 33, got $GUI_TEST_COUNT"
fi

# 4. iroh backend >= 700 lines
# (Phase 4 retrospective: F3 v1 deleted the handshake. After the p2p
#  abstraction refactor the iroh transport moved src/network/iroh.rs ->
#  src/p2p/backend/iroh.rs and was split, so the floor was lowered from
#  1100 to 700 to still catch accidental deletion under the new layout.)
IROH_LINES="$(wc -l < src/p2p/backend/iroh.rs)"
if [ "$IROH_LINES" -ge 700 ]; then
    pass "src/p2p/backend/iroh.rs >= 700 lines (actual $IROH_LINES)"
else
    fail "src/p2p/backend/iroh.rs line count" "expected >= 700, got $IROH_LINES (Phase 4 retrospective: F3 v1 deleted handshake)"
fi

# 5. network/mod.rs >= 800 lines
NETMOD_LINES="$(wc -l < src/network/mod.rs)"
if [ "$NETMOD_LINES" -ge 800 ]; then
    pass "src/network/mod.rs >= 800 lines (actual $NETMOD_LINES)"
else
    fail "src/network/mod.rs line count" "expected >= 800, got $NETMOD_LINES"
fi

# 6. Placeholder comments absent (Gemini §3.2#1 + Trigger 2 §4.4 reflection).
# Patterns are chosen to catch known stub-ish phrasings while avoiding
# false positives on benign descriptive comments. F3 v1's "For now, we'll
# use a hacky way" is caught by the "hacky way" pattern, so the more
# generic "For now," is intentionally not listed here.
# Trigger 2 §4.4 additions: temp comments, FIXME, cleanup later — common
# LLM "temporary escape hatch" patterns.
PLACEHOLDER_HITS="$(grep -rE \
    'Simplified for brevity|Shortened for brevity|Omitted for brevity|for brevity|hacky way|In a real implementation|we would start|// placeholder|// stub: implement|// temp:|// cleanup later|// FIXME' \
    src/ 2>/dev/null || true)"
if [ -z "$PLACEHOLDER_HITS" ]; then
    pass "no placeholder phrases in src/"
else
    fail "placeholder phrases" "$(echo "$PLACEHOLDER_HITS" | head -3)"
fi

# 7. main history linear since v2.0.4 (no merge / rebase / squash)
# v2.0.4 = b9ec19a; check no merge commits since then.
# Use `rev-list --count` (one integer = number of merge COMMITS). The old
# `git log --merges | wc -l` counted LINES: a single merge commit's default
# `git log` output is ~6 lines, so under a PR's synthetic merge ref it reported
# a false "6 merge commits". `--count` is immune to that.
MERGE_COUNT="$(git rev-list --merges --count b9ec19a..HEAD 2>/dev/null || echo 0)"
if [ "$MERGE_COUNT" -eq 0 ]; then
    pass "main history linear since v2.0.4"
else
    fail "main history" "$MERGE_COUNT merge commit(s) found"
fi

# 8. CI yaml forbidden patterns
#
# Enumerate BOTH extensions. GitHub Actions runs `.yaml` exactly as it runs
# `.yml`, but every check here used to read `.github/workflows/*.yml` only, so
# adding one character to a filename removed a workflow from all three checks
# at once. Nothing in the repository is named `.yaml` today; that is a fact
# about the present tree, not a property of the gate.
#
# An array, not a glob string: the old `$CI_YAML_GLOB` was deliberately
# unquoted so the shell would split and expand it, which also word-split any
# path containing a space. `-f` filters the literal pattern that bash leaves
# behind when a glob matches nothing, so no `shopt -s nullglob` is needed --
# setting that globally would change how every other check in this file
# expands.
CI_YAML_FILES=()
for _ci_yaml in .github/workflows/*.yml .github/workflows/*.yaml; do
    [ -f "$_ci_yaml" ] && CI_YAML_FILES+=("$_ci_yaml")
done
unset _ci_yaml

if [ "${#CI_YAML_FILES[@]}" -gt 0 ]; then
    # 8a. pull_request_target trigger.
    #
    # Delegated to a parser. The regex this replaces required a trailing colon,
    # so it saw `on:\n  pull_request_target:` and missed `on: [push,
    # pull_request_target]` entirely; two attempts to widen it were rejected by
    # an independent verifier for reddening legitimate workflows -- the
    # defensive `if: github.event_name != 'pull_request_target'` among them.
    # A text match cannot separate a trigger declaration from a mention.
    # scripts/check_workflow_triggers.py explains the design and the YAML 1.1
    # `on:`-is-a-boolean trap; scripts/test_check_workflow_triggers.sh pins all
    # sixteen cases, including the three that caused the rejections.
    PRT_OUT="$(python3 scripts/check_workflow_triggers.py 2>&1)"
    case $? in
        0) pass "CI yaml: no pull_request_target trigger (parsed, .yml + .yaml)" ;;
        1) fail "CI yaml: pull_request_target" "$(printf '%s' "$PRT_OUT" | head -3)" ;;
        *) fail "CI yaml: pull_request_target" "check could not run: $(printf '%s' "$PRT_OUT" | head -3)" ;;
    esac
    unset PRT_OUT

    # 8b. permissions: write-all
    #
    # Matches the literal `write-all` only, so a workflow with no `permissions:`
    # block at all passes -- which .github/workflows/rust.yml is today. That
    # gap is real and is NOT closed here: closing it means requiring a
    # `permissions:` declaration, which is a change to the workflows rather
    # than to the gate. Recorded so the pass is not read as "every workflow
    # declares least privilege".
    if grep -lE 'permissions:\s*write-all' "${CI_YAML_FILES[@]}" >/dev/null 2>&1; then
        fail "CI yaml: write-all permissions" "$(grep -lE 'write-all' "${CI_YAML_FILES[@]}" | head -3)"
    else
        pass "CI yaml: no write-all permissions (literal match only; a missing permissions block also passes)"
    fi

    # 8c. secret echo
    if grep -lE '(echo|printf|cat).*\$\{\{\s*secrets\.' "${CI_YAML_FILES[@]}" >/dev/null 2>&1; then
        fail "CI yaml: secret echo" "$(grep -lE '(echo|printf|cat).*\$\{\{\s*secrets\.' "${CI_YAML_FILES[@]}" | head -3)"
    else
        pass "CI yaml: no secret echo"
    fi
else
    warn "CI yaml" "no .github/workflows/*.yml or *.yaml present"
fi

# 9. Cargo.lock baseline check (Gemini §3.2#3 + Trigger 2 §4.4 reflection).
# Detect unintended bumps for security-critical deps since v2.0.4 baseline.
# Trigger 2 §4.4 escalation: in RELEASE_MODE, unexpected security-critical
# dep drift is FAIL (must be intentional and documented in commit message
# or CHANGELOG). In dev mode it remains WARN.
#
# Compare the resolved versions themselves rather than grepping the diff text:
#   - `git diff ... | grep -qE ...` was inverted by the `set -o pipefail` above.
#     `grep -q` exits at its first match and closes the pipe, git dies of EPIPE
#     (141), pipefail hands that status to the `if`, so the check took the
#     "no drift" branch precisely when a match WAS found.
#   - `^[+-]name = "..."` only fires when a whole package block is added or
#     removed. An in-place version bump leaves the `name =` line as unchanged
#     context, so it was invisible even to a non-inverted grep.
# A crate may legitimately resolve to several [[package]] blocks (two majors in
# the tree at once), so every block is listed and the sorted lists compared.
LOCK_CRITICAL_CRATES='slint|iroh|tokio|rfd|sha2|aes-gcm|chacha20poly1305|fips203|fips204'

lock_critical_versions() {
    # stdin: a Cargo.lock. stdout: sorted "<crate> <version>" lines, one per
    # [[package]] block of a security-critical dep.
    awk -F'"' '
        /^name = "/    { pkg = $2; next }
        /^version = "/ { if (pkg != "") { print pkg " " $2; pkg = "" } }
    ' | grep -E "^($LOCK_CRITICAL_CRATES) " | sort
}

LOCK_BASELINE="$(git show b9ec19a:Cargo.lock 2>/dev/null | lock_critical_versions)"
LOCK_CURRENT="$(lock_critical_versions < Cargo.lock)"
# An unreadable baseline (shallow clone, missing object) leaves nothing to
# compare against, which is the previous behaviour of this check: stay quiet.
if [ -n "$LOCK_BASELINE" ] && [ "$LOCK_BASELINE" != "$LOCK_CURRENT" ]; then
    if [ "${RELEASE_MODE:-0}" = "1" ]; then
        # In release mode require explicit ALLOW_LOCK_DRIFT=1 to bypass.
        if [ "${ALLOW_LOCK_DRIFT:-0}" = "1" ]; then
            warn "Cargo.lock" "RELEASE_MODE: security-critical deps drifted; ALLOW_LOCK_DRIFT=1 acknowledged"
        else
            fail "Cargo.lock" "RELEASE_MODE: security-critical deps drifted vs v2.0.4. If intentional, set ALLOW_LOCK_DRIFT=1 and document in CHANGELOG"
        fi
    else
        warn "Cargo.lock" "security-critical deps drifted vs v2.0.4 baseline; manual review required (slint/iroh/tokio/rfd/sha2/aes-gcm/chacha20poly1305/fips*)"
    fi
else
    pass "Cargo.lock: no security-critical dep drift since v2.0.4"
fi

# ---- Phase 5 P1 additions (items 10-20) ----
# Per PHASE5_P1_HANDOFF.md §1.6 + §2 commit 4. Spec numbers items 9-19;
# code shifts to 10-20 to avoid conflict with existing F4 item #9 (Cargo.lock).
#
# Many items use SKIP semantics (warn instead of fail) when their prerequisite
# commit has not yet landed, so mandate_check stays exit 0 throughout the P1
# development loop. Final P1 completion requires all items pass (no warns).

# 10. iroh internal test 8 件の #[ignore] 不在 (P1-R1, lands in commit 8)
# Pattern note: matches both `#[ignore]` and `#[ignore = "..."]` (rust syntax
# allows both; the message form is more common in this codebase).
if [ -f src/p2p/backend/iroh.rs ]; then
    IROH_IGNORE_COUNT="$(grep -B1 'fn test_iroh_' src/p2p/backend/iroh.rs 2>/dev/null | grep -c '#\[ignore' || true)"
    if [ "$IROH_IGNORE_COUNT" -eq 0 ]; then
        pass "iroh internal tests: no #[ignore]"
    else
        warn "iroh internal tests: $IROH_IGNORE_COUNT #[ignore...] present (lifted in P1 commit 8)"
    fi
else
    warn "src/p2p/backend/iroh.rs not found, skipping iroh #[ignore] check"
fi

# 11. subprocess e2e #[ignore] 不在 (P1-R2, lands in commit 9)
# Pattern matches both #[ignore] and #[ignore = "..."] forms.
if [ -f tests/e2e.rs ]; then
    SUBPROC_IGNORE_COUNT="$(grep -B1 -E 'fn (test_pqc_e2e_cycle|test_hybrid_e2e_cycle)' tests/e2e.rs 2>/dev/null | grep -c '#\[ignore' || true)"
    if [ "$SUBPROC_IGNORE_COUNT" -eq 0 ]; then
        pass "subprocess e2e: no #[ignore]"
    else
        warn "subprocess e2e: $SUBPROC_IGNORE_COUNT #[ignore...] present (lifted in P1 commit 9)"
    fi
else
    warn "tests/e2e.rs not found, skipping subprocess e2e #[ignore] check"
fi

# 12. 異常系 E2E 3 件存在 (P1-R3, landed in commit 10)
# These tests are present in the tree, so a shortfall now means they were
# deleted or renamed, not that they have not landed yet: fail, don't warn.
ADV_FT=0
[ -f tests/e2e_file_transfer.rs ] && \
    ADV_FT="$(grep -cE '\basync fn test_e2e_(aead_tampering|chunk_len_forgery)' tests/e2e_file_transfer.rs 2>/dev/null || true)"
ADV_HS=0
[ -f tests/e2e_handshake_tampering.rs ] && \
    ADV_HS="$(grep -cE '\basync fn test_handshake_signature_tampering' tests/e2e_handshake_tampering.rs 2>/dev/null || true)"
if [ "$ADV_FT" -ge 2 ] && [ "$ADV_HS" -ge 1 ]; then
    pass "adversarial E2E: $((ADV_FT + ADV_HS)) tests present (file_transfer:$ADV_FT, handshake:$ADV_HS)"
else
    fail "adversarial E2E" "found file_transfer:$ADV_FT handshake:$ADV_HS, need >=2 + >=1 — expected tests/e2e_file_transfer.rs::test_e2e_aead_tampering + test_e2e_chunk_len_forgery and tests/e2e_handshake_tampering.rs::test_handshake_signature_tampering"
fi

# 13. CI yaml で clippy step に continue-on-error: true 不在 (P1-R4, lands in commit 7)
if [ "${#CI_YAML_FILES[@]}" -gt 0 ]; then
    # 単純化: ファイル全体で "clippy" を含む行の前後 5 行以内に continue-on-error: true
    # が現れたら advisory モードと判定 (false positive 許容、保守的に warn)
    CLIPPY_ADVISORY=0
    for f in "${CI_YAML_FILES[@]}"; do
        if grep -nE 'clippy' "$f" >/dev/null 2>&1; then
            if awk '/clippy/{c=NR} /continue-on-error:[[:space:]]*true/{e=NR; if(c && e-c<10 && e>c){found=1}} END{exit !found}' "$f"; then
                CLIPPY_ADVISORY=1
                break
            fi
        fi
    done
    if [ "$CLIPPY_ADVISORY" -eq 0 ]; then
        pass "CI yaml: clippy is release-blocking (no continue-on-error near clippy step)"
    else
        warn "CI yaml: clippy has continue-on-error: true (removed in P1 commit 7)"
    fi
else
    warn "CI yaml not present, skipping clippy advisory check"
fi

# 14. scripts/check_env.sh 存在 + executable + exit 0 (P1-R5)
if [ -x scripts/check_env.sh ]; then
    if bash scripts/check_env.sh >/dev/null 2>&1; then
        pass "scripts/check_env.sh: present, executable, exit 0"
    else
        fail "scripts/check_env.sh" "invocation returned non-zero (re-run manually for details)"
    fi
else
    fail "scripts/check_env.sh" "missing or not executable"
fi

# 15. Supply-chain config present (P1-R7, landed in commit 5)
# Presence only. `cargo deny` is NOT run by any workflow, so deny.toml's
# licenses/bans/sources sections are unenforced config; only its advisories
# overlap with something that runs, and that is `cargo audit` reading
# .cargo/audit.toml instead. The advisory gate itself lives in ci.yml and is
# release-blocking as of 2026-08-19 — this check does not stand in for it.
DENY_MISSING=""
[ -f deny.toml ] || DENY_MISSING="$DENY_MISSING deny.toml"
[ -f .github/dependabot.yml ] || DENY_MISSING="$DENY_MISSING .github/dependabot.yml"
if [ -z "$DENY_MISSING" ]; then
    pass "supply-chain config present: deny.toml + .github/dependabot.yml (presence only; cargo deny is not run)"
else
    fail "supply-chain config" "missing$DENY_MISSING"
fi

# 16. serial_test の [dev-dependencies] 配置 (P1-R6, lands in commit 6)
if grep -qE '^serial_test[[:space:]]*=' Cargo.toml; then
    SERIAL_IN_DEV=$(awk '
        /^\[dev-dependencies\]/ { in_dev=1; next }
        /^\[/ { in_dev=0 }
        in_dev && /^serial_test[[:space:]]*=/ { found=1 }
        END { print found+0 }
    ' Cargo.toml)
    if [ "$SERIAL_IN_DEV" -eq 1 ]; then
        pass "serial_test placed in [dev-dependencies]"
    else
        warn "serial_test still in [dependencies] (moved to dev-dep in P1 commit 6)"
    fi
else
    pass "serial_test absent from Cargo.toml"
fi

# 17. v2.4_DEFERRED.md 存在 (P1-R11, landed in commit 1 of sibling issue/ repo).
# Cross-repo path: from REPO_ROOT (= src/nkCryptoTool-rust/), the issue
# docs repo is sibling at ../issue/nkCryptoTool-rust/. Override via
# NKCT_ISSUE_DIR env var if layout differs.
ISSUE_DIR="${NKCT_ISSUE_DIR:-../issue/nkCryptoTool-rust}"
if [ -f "$ISSUE_DIR/v2.4_DEFERRED.md" ]; then
    pass "v2.4_DEFERRED.md present at $ISSUE_DIR"
else
    warn "v2.4_DEFERRED.md not found at $ISSUE_DIR (override NKCT_ISSUE_DIR if needed)"
fi

# 18. security-critical files: no NEW unwrap()/expect() in PRODUCTION code
# (P1-R10, count-based vs the 22a8011a baseline).
# Scope: src/network/ + src/processor.rs + src/utils.rs + src/backend/ (.rs).
# Two classes are intentionally excluded from the production count:
#   - test modules: everything from the first `#[cfg(...test...)]` attribute
#     to EOF (idiomatic .expect() in tests is fine and was previously inflating
#     the count — e.g. the new src/network/inbox.rs test suite).
#   - lines annotated `// ALLOW-UNWRAP: <reason>`: idiomatic unrecoverable
#     panics (poisoned Mutex lock(), fatal thread-spawn at startup, …).
# The remaining production count must not exceed the baseline. (A file moving
# out of scope — e.g. iroh.rs -> src/p2p/ — only loosens the bound, never
# tightens it, so it cannot cause a false FAIL.)
prod_unwrap_count() {  # $1: git ref, or "" for the working tree
    local ref="$1" total=0 f files src
    if [ -z "$ref" ]; then
        files="$(git ls-files -- src/network src/processor.rs src/utils.rs src/backend | grep '\.rs$' || true)"
    else
        files="$(git ls-tree -r --name-only "$ref" -- src/network src/processor.rs src/utils.rs src/backend 2>/dev/null | grep '\.rs$' || true)"
    fi
    for f in $files; do
        if [ -z "$ref" ]; then src="$(cat "$f")"; else src="$(git show "$ref:$f" 2>/dev/null || true)"; fi
        n="$(printf '%s\n' "$src" \
            | sed -E '/#\[cfg\([^)]*test/,$d' \
            | grep -E '\.(unwrap|expect)\(' \
            | grep -vc 'ALLOW-UNWRAP' || true)"
        total=$((total + n))
    done
    echo "$total"
}
BASE_UNWRAPS="$(prod_unwrap_count 22a8011a)"
CUR_UNWRAPS="$(prod_unwrap_count "")"
if [ "$CUR_UNWRAPS" -le "$BASE_UNWRAPS" ]; then
    pass "no new prod unwrap/expect in security-critical files (cur=$CUR_UNWRAPS <= base=$BASE_UNWRAPS @22a8011a)"
else
    fail "unwrap/expect grep" "$((CUR_UNWRAPS - BASE_UNWRAPS)) new prod occurrence(s) since 22a8011a (cur=$CUR_UNWRAPS base=$BASE_UNWRAPS); annotate idiomatic ones with '// ALLOW-UNWRAP: <reason>'"
fi

# 18b. The workflow-trigger checker's own unit test (F5).
# Check 8a delegates to a parser, and a parser can be edited into a fail-open
# that still prints a pass. Measured, not assumed: deleting one line -- the
# branch handling YAML 1.1's `on:`-is-boolean-True -- makes the checker report
# every workflow clean, and nothing else in this file notices. So the test runs
# here, where the gate is, rather than sitting in the tree hoping to be run.
# Cheap: sixteen cases against temp files, well under a second.
if [ -f scripts/test_check_workflow_triggers.sh ]; then
    if bash scripts/test_check_workflow_triggers.sh >/dev/null 2>&1; then
        pass "check_workflow_triggers.py: 16/16 self-tests (incl. the 3 false positives that rejected the regex)"
    else
        fail "check_workflow_triggers.py self-test" "run 'bash scripts/test_check_workflow_triggers.sh' for the failing cases"
    fi
else
    fail "check_workflow_triggers.py self-test" "scripts/test_check_workflow_triggers.sh missing — it is tracked, so this means deletion"
fi

# 19. .security-baseline.sha256 covers the listed set, and matches (P1-R12;
#     coverage-set comparison added by the 2026-08 turn-11 audit, F1)
# The baseline file is tracked in git, so its absence means it was deleted,
# not that it has yet to be initialised: fail, don't warn. Skipping here would
# let `rm .security-baseline.sha256` silence the whole integrity check.
#
# `sha256sum --check` used to be the whole check, and it verifies the lines it
# is handed and nothing else. The file handing them over arrives with the commit
# being judged — ci.yml checks out the PR head and runs this script on it — so
# deleting one line took a file out of coverage while every remaining line still
# matched and this check still printed OK. scripts/check_security_baseline.sh
# compares the baseline's entries against scripts/security_critical_files.txt in
# both directions before it looks at a hash; read its header for the property it
# does guarantee and the one it deliberately leaves to the reviewer.
#
# Its output is printed on failure rather than dropped: sha256sum's stderr, which
# used to go to /dev/null, is where "improperly formatted line" appears.
if [ -f .security-baseline.sha256 ]; then
    if BASELINE_OUT="$(bash scripts/check_security_baseline.sh 2>&1)"; then
        pass ".security-baseline.sha256: covers the listed files, strict match"
    else
        fail ".security-baseline.sha256" "see HANDOFF §1.7.3 baseline reconstruction protocol"
        printf '%s\n' "$BASELINE_OUT"
    fi
else
    fail ".security-baseline.sha256" "missing — the file is tracked; restore it with 'git checkout -- .security-baseline.sha256', or regenerate it with scripts/rebaseline_security.sh if the baseline is intentionally being renewed"
fi

# 19b. The baseline gate's own self-test (F1).
# Check 19 delegates to a script now, and a script can be edited into a
# fail-open that still prints a pass — the same reasoning as 18b above. The
# test pins the moves the coverage-set comparison exists to stop (an entry
# deleted from the baseline, an entry the list never named, a hash mangled into
# the malformed line sha256sum skips with exit 0) and, just as important, the
# legitimate deletion that must keep passing. Cheap: eleven fixtures in a temp
# directory, well under a second.
if [ -f scripts/test_check_security_baseline.sh ]; then
    if bash scripts/test_check_security_baseline.sh >/dev/null 2>&1; then
        pass "check_security_baseline.sh: 11/11 self-tests (incl. the legitimate deletion that must stay clean)"
    else
        fail "check_security_baseline.sh self-test" "run 'bash scripts/test_check_security_baseline.sh' for the failing cases"
    fi
else
    fail "check_security_baseline.sh self-test" "scripts/test_check_security_baseline.sh missing — it is tracked, so this means deletion"
fi

# 20. clippy #[allow(...)] rationale + Future plan (P1-X12 v2, diff-based)
# Delegated to scripts/check_allow_rationale.sh which enforces rationale +
# Future on NEW #[allow(...)] added since 22a8011a (diff-based, matches
# P1-R10 unwrap pattern; pre-existing allows grandfathered).
if [ -x scripts/check_allow_rationale.sh ]; then
    if bash scripts/check_allow_rationale.sh >/dev/null 2>&1; then
        pass "check_allow_rationale.sh: new #[allow(...)] have rationale + Future plan"
    else
        fail "check_allow_rationale.sh" "one or more new #[allow(...)] missing rationale or Future (re-run manually for details)"
    fi
else
    fail "check_allow_rationale.sh" "missing or not executable"
fi

# 21. Roster-map critical sections stay synchronous (2026-08 audit, S8 follow-up)
# The compiler already enforces "no .await inside" by those functions not being
# async; this guards the hole that leaves -- making them async again. Fails
# closed: a missing anchor is an error, not a pass.
if [ -x scripts/check_roster_sync_sections.sh ]; then
    if bash scripts/check_roster_sync_sections.sh >/dev/null 2>&1; then
        pass "check_roster_sync_sections.sh: roster critical sections are non-async"
    else
        fail "check_roster_sync_sections.sh" "a roster critical section became async, or its anchor moved (re-run manually for details)"
    fi
else
    fail "check_roster_sync_sections.sh" "missing or not executable"
fi

# ---- End Phase 5 P1 additions ----

# 22. Check-count floor (2026-08 turn-8 audit, F2).
#
# Every check above reports FAIL only when it runs and objects. A check that
# stops running reports nothing, and this file's summary never noticed: deleting
# a whole block took PASS from 22 to 21 and still printed "all required checks
# passed". The two branches F2 demonstrated were promoted to FAIL, but that
# closes the two, not the class -- the class is "the gate got smaller".
#
# The floor is on the TOTAL, not on PASS, and that is measured rather than
# preferred. At b955c49e the same tree reports PASS=22 WARN=2 locally and
# PASS=21 WARN=3 in CI, because check 19 looks for ../issue/nkCryptoTool-rust,
# a path outside the repository that no runner has. The split moves with the
# environment; the number of checks that ran does not. A floor on PASS would be
# wrong in one of the two places no matter which value it held.
#
# Note this cannot be gamed the way a documented PASS total can. Weakening a
# check -- turning a FAIL into a WARN -- leaves the total untouched, so it buys
# nothing here; only deleting a check moves it, which is the thing being caught.
#
# That is also the limitation, stated so the floor is not read as more than it
# is: a weakened check still runs, still counts, and the floor stays silent.
# Measured -- reverting check 19's missing-baseline branch to WARN and then
# deleting .security-baseline.sha256 gives 24 checks, floor satisfied, exit 0.
# That case is carried by the FAIL promotion in check 19, not by this. The two
# are complementary and neither subsumes the other.
#
# Below the floor is FAIL: a check vanished. Above it is WARN, not FAIL, so that
# adding a check never blocks the commit that adds it; the warning says to raise
# the floor, and until someone does, the floor still catches any removal down to
# its own value. That WARN cannot hide a removal, which is the property F2's
# WARN class lacked.
CHECKS_RUN=$((PASS_COUNT + FAIL_COUNT + WARN_COUNT))
EXPECTED_CHECKS=25
if [ "$CHECKS_RUN" -lt "$EXPECTED_CHECKS" ]; then
    fail "check-count floor" "only $CHECKS_RUN checks ran, expected >= $EXPECTED_CHECKS — a check was deleted, renamed, or silently skipped. Compare this run's lines against git show HEAD:scripts/mandate_check.sh"
elif [ "$CHECKS_RUN" -gt "$EXPECTED_CHECKS" ]; then
    warn "check-count floor" "$CHECKS_RUN checks ran, floor is $EXPECTED_CHECKS — raise EXPECTED_CHECKS in this file to $CHECKS_RUN so the new check is protected too"
fi

# Summary
echo ""
echo "[mandate] summary: PASS=$PASS_COUNT FAIL=$FAIL_COUNT WARN=$WARN_COUNT (checks run: $CHECKS_RUN, floor: $EXPECTED_CHECKS)"
if [ "$FAIL_COUNT" -gt 0 ]; then
    echo "[mandate] FAIL: cannot proceed to commit / release"
    exit 1
fi
echo "[mandate] all required checks passed"
exit 0
