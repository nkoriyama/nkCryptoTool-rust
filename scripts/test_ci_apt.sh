#!/usr/bin/env bash
# Unit test for scripts/ci_apt.sh.
#
# The wrapper's entire reason to exist is that a hung `apt-get` is not a failed
# one: on 2026-08-18 three CI jobs sat in silence because apt had no timeout,
# and re-running by hand fixed it. So the case that matters here is "hangs, then
# succeeds" -- if a future edit drops the `timeout`, every test that only checks
# the happy path still passes while the wrapper stops doing its one job.
#
# `apt-get` is injected via APT_GET, so this runs anywhere: no sudo, no network,
# no package manager.
#
# Run: bash scripts/test_ci_apt.sh
set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUT="$REPO_ROOT/scripts/ci_apt.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export CI_APT_STATE="$WORK"

PASS=0
FAIL=0

check() {
    local desc="$1" want="$2" got="$3" out="${4:-}"
    if [ "$want" = "$got" ]; then
        PASS=$((PASS + 1)); printf '  ok    (exit %s) %s\n' "$got" "$desc"
    else
        FAIL=$((FAIL + 1)); printf '  FAIL  want exit %s, got %s: %s\n%s\n' "$want" "$got" "$desc" "$out"
    fi
}

# always_ok: succeeds immediately.
cat > "$WORK/always_ok" <<'F'
#!/bin/bash
exit 0
F
# always_hangs: accepts the call and then never returns -- the observed outage.
cat > "$WORK/always_hangs" <<'F'
#!/bin/bash
sleep 600
F
# hangs_once: the transient case. First call hangs, every later call succeeds.
cat > "$WORK/hangs_once" <<'F'
#!/bin/bash
n="$CI_APT_STATE/attempts"
c=$(cat "$n" 2>/dev/null || echo 0)
echo $((c + 1)) > "$n"
[ "$c" = "0" ] && sleep 600
exit 0
F
# always_fails: a real apt error, not a hang. Must be retried and then reported.
cat > "$WORK/always_fails" <<'F'
#!/bin/bash
echo "E: Unable to locate package" >&2
exit 100
F
chmod +x "$WORK"/always_ok "$WORK"/always_hangs "$WORK"/hangs_once "$WORK"/always_fails

out=$(APT_GET="$WORK/always_ok" bash "$SUT" clang lld 2>&1); check "healthy mirror installs" 0 $? "$out"

# The outer `timeout 60` is deliberate: if the wrapper loses its own timeout,
# this call blocks for 600s, and a test that HANGS where it should FAIL teaches
# nothing -- it just moves the stall from the apt step to the test step. With
# the bound, that mutation reports a failure in a minute instead.
start=$(date +%s)
out=$(CI_APT_UPDATE_TIMEOUT=2 CI_APT_ATTEMPTS=2 APT_GET="$WORK/always_hangs" \
      timeout 60 bash "$SUT" clang 2>&1)
rc=$?; elapsed=$(( $(date +%s) - start ))
if [ "$rc" = "124" ]; then
    FAIL=$((FAIL + 1))
    printf '  FAIL  the wrapper itself hung -- its `timeout` is gone: %s\n' "a permanent hang is killed"
else
    check "a permanent hang is killed, not waited on" 1 $rc "$out"
fi
# The guard that matters: without `timeout` this is 600s and the job dies on its
# own budget instead, which is the bug being fixed.
if [ "$elapsed" -lt 60 ]; then
    PASS=$((PASS + 1)); printf '  ok    (%ss) gave up promptly rather than blocking (bare apt would be 600s)\n' "$elapsed"
else
    FAIL=$((FAIL + 1)); printf '  FAIL  took %ss -- the timeout did not fire\n' "$elapsed"
fi

rm -f "$WORK/attempts"
# Bounded for the same reason as the case above: with the wrapper's `timeout`
# removed this blocks on the first attempt forever.
out=$(CI_APT_UPDATE_TIMEOUT=2 APT_GET="$WORK/hangs_once" timeout 60 bash "$SUT" clang 2>&1)
rc=$?
[ "$rc" = "124" ] && rc="124 (the wrapper hung -- its \`timeout\` is gone)"
check "THE CASE: hangs once, then succeeds (2026-08-18's manual re-run)" 0 "$rc" "$out"

out=$(CI_APT_ATTEMPTS=2 APT_GET="$WORK/always_fails" bash "$SUT" clang 2>&1)
check "a genuine apt failure still fails after its retries" 1 $? "$out"

out=$(bash "$SUT" 2>&1); check "no packages named is a usage error" 2 $? "$out"

echo "summary: pass=$PASS fail=$FAIL"
[ "$FAIL" -eq 0 ]
