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

# 4. iroh.rs >= 1100 lines
IROH_LINES="$(wc -l < src/network/iroh.rs)"
if [ "$IROH_LINES" -ge 1100 ]; then
    pass "src/network/iroh.rs >= 1100 lines (actual $IROH_LINES)"
else
    fail "src/network/iroh.rs line count" "expected >= 1100, got $IROH_LINES (Phase 4 retrospective: F3 v1 deleted handshake)"
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
# v2.0.4 = b9ec19a; check no merge commits since then
MERGE_COUNT="$(git log --merges b9ec19a..HEAD 2>/dev/null | wc -l || echo 0)"
if [ "$MERGE_COUNT" -eq 0 ]; then
    pass "main history linear since v2.0.4"
else
    fail "main history" "$MERGE_COUNT merge commit(s) found"
fi

# 8. CI yaml forbidden patterns
CI_YAML_GLOB=".github/workflows/*.yml"
if compgen -G "$CI_YAML_GLOB" > /dev/null; then
    # 8a. pull_request_target trigger
    if grep -lE '^\s*-?\s*pull_request_target\s*:' $CI_YAML_GLOB >/dev/null 2>&1; then
        fail "CI yaml: pull_request_target" "$(grep -lE 'pull_request_target' $CI_YAML_GLOB | head -3)"
    else
        pass "CI yaml: no pull_request_target"
    fi

    # 8b. permissions: write-all
    if grep -lE 'permissions:\s*write-all' $CI_YAML_GLOB >/dev/null 2>&1; then
        fail "CI yaml: write-all permissions" "$(grep -lE 'write-all' $CI_YAML_GLOB | head -3)"
    else
        pass "CI yaml: no write-all permissions"
    fi

    # 8c. secret echo
    if grep -lE '(echo|printf|cat).*\$\{\{\s*secrets\.' $CI_YAML_GLOB >/dev/null 2>&1; then
        fail "CI yaml: secret echo" "$(grep -lE '(echo|printf|cat).*\$\{\{\s*secrets\.' $CI_YAML_GLOB | head -3)"
    else
        pass "CI yaml: no secret echo"
    fi
else
    warn "CI yaml" "no .github/workflows/*.yml present yet (F4 in progress)"
fi

# 9. Cargo.lock baseline check (Gemini §3.2#3 + Trigger 2 §4.4 reflection).
# Detect unintended bumps for security-critical deps since v2.0.4 baseline.
# Trigger 2 §4.4 escalation: in RELEASE_MODE, unexpected security-critical
# dep drift is FAIL (must be intentional and documented in commit message
# or CHANGELOG). In dev mode it remains WARN.
if git diff b9ec19a -- Cargo.lock 2>/dev/null | grep -qE '^[+-]name = "(slint|iroh|tokio|rfd|sha2|aes-gcm|chacha20poly1305|fips203|fips204)"'; then
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

# Summary
echo ""
echo "[mandate] summary: PASS=$PASS_COUNT FAIL=$FAIL_COUNT WARN=$WARN_COUNT"
if [ "$FAIL_COUNT" -gt 0 ]; then
    echo "[mandate] FAIL: cannot proceed to commit / release"
    exit 1
fi
echo "[mandate] all required checks passed"
exit 0
