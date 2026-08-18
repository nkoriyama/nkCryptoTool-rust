#!/usr/bin/env bash
# apt-get update + install for CI runners, with the timeouts and retries the
# plain calls did not have.
#
# WHY THIS EXISTS
# ---------------
# On 2026-08-18 the Azure package mirror stopped answering on the GitHub
# runners. apt fell back to archive.ubuntu.com and then blocked, mid-fetch,
# with no further output:
#
#   18:45:04  Get:5 https://archive.ubuntu.com/ubuntu noble-security InRelease
#             ... 39 minutes of complete silence ...
#   19:24:05  ##[error]The operation was canceled.
#
# Three jobs across two workflows hung on it. `apt-get` has no default
# per-connection timeout, so a mirror that accepts a connection and then stops
# sending blocks forever; the job's own `timeout-minutes` is the only thing
# that ends it, and the two rust.yml jobs had none, so they sat for over an
# hour reporting nothing until a person killed them.
#
# A retry alone would not have helped -- nothing failed, it hung. The fix is
# the Acquire timeouts, which turn the hang into a failure apt can retry. The
# outer `timeout` is a backstop for the case those do not fire.
#
# Re-running by hand cleared it, so the outage was transient. That is exactly
# the case worth automating: the recovery was "retry", and a human did it.
#
# Usage:  bash scripts/ci_apt.sh <package>...
#         APT_GET=<cmd> bash scripts/ci_apt.sh ...   (for the self-test)
set -uo pipefail

APT_GET="${APT_GET:-sudo apt-get}"

# Per-connection limits. Without these a stalled mirror is indistinguishable
# from a slow one and apt waits forever. Acquire::Retries makes apt try another
# mirror/attempt itself, which is cheaper than restarting the whole update.
APT_OPTS=(
    -o Acquire::Retries=3
    -o Acquire::http::Timeout=20
    -o Acquire::https::Timeout=20
    -o Acquire::ftp::Timeout=20
)

# Hard backstops, in seconds, per attempt. Generous next to the ~30 s an update
# and ~2 min an install take when the mirrors are healthy: the point is to cap
# a hang, not to police slowness.
UPDATE_TIMEOUT="${CI_APT_UPDATE_TIMEOUT:-180}"
INSTALL_TIMEOUT="${CI_APT_INSTALL_TIMEOUT:-600}"
ATTEMPTS="${CI_APT_ATTEMPTS:-3}"

run_with_retry() {
    local label="$1" limit="$2"; shift 2
    local attempt rc
    for attempt in $(seq 1 "$ATTEMPTS"); do
        # `timeout` returns 124 when it fires, which is why the hang and a
        # genuine apt failure are distinguishable in the log below.
        timeout "$limit" "$@"
        rc=$?
        if [ "$rc" -eq 0 ]; then
            [ "$attempt" -gt 1 ] && echo "ci_apt: $label succeeded on attempt $attempt"
            return 0
        fi
        if [ "$rc" -eq 124 ]; then
            echo "ci_apt: $label hung and was killed after ${limit}s (attempt $attempt/$ATTEMPTS)" >&2
        else
            echo "ci_apt: $label failed with status $rc (attempt $attempt/$ATTEMPTS)" >&2
        fi
        [ "$attempt" -lt "$ATTEMPTS" ] && sleep $((attempt * 10))
    done
    echo "ci_apt: $label did not succeed in $ATTEMPTS attempts" >&2
    return 1
}

if [ "$#" -eq 0 ]; then
    echo "usage: bash scripts/ci_apt.sh <package>..." >&2
    exit 2
fi

# shellcheck disable=SC2086  # APT_GET is intentionally word-split (`sudo apt-get`)
run_with_retry "apt-get update" "$UPDATE_TIMEOUT" \
    $APT_GET "${APT_OPTS[@]}" update || exit 1

# shellcheck disable=SC2086
run_with_retry "apt-get install" "$INSTALL_TIMEOUT" \
    $APT_GET "${APT_OPTS[@]}" install -y --no-install-recommends "$@" || exit 1

echo "ci_apt: installed: $*"
