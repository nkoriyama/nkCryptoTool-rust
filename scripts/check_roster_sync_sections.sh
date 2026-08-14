#!/usr/bin/env bash
# Enforces that the two roster-map critical sections stay synchronous.
#
# `listen_loop` hands the `RosterSnapshots` mutex to both the inbound task and
# the inbox-poll task with nothing serialising them, so the read-modify-write on
# a group's baseline has to complete with no suspension point in it. If it does
# not, the later writer clobbers the earlier one and a member dropped from the
# baseline can never be pruned again, however many times he is later removed.
#
# `decide_departures` and `seed_roster_locked` hold that whole section, and both
# are deliberately NOT `async` -- inside a non-async fn an `.await` is a compile
# error, so the invariant is a property the build checks rather than a convention
# a comment asks for. This script guards the one hole that leaves: someone making
# the functions `async` again and "fixing" the call sites.
#
# Why a script at all, when the compiler does the real work: the invariant is
# otherwise invisible to CI. Every test stays green when it breaks, and
# `clippy::await_holding_lock` does not fire -- it targets `std::sync` guards and
# deliberately does not flag a `tokio::sync::MutexGuard` held across an await,
# which is normally legal.
#
# The check FAILS CLOSED: if either function cannot be found at all -- renamed,
# moved, deleted -- that is an error, not a pass. A guard that silently retires
# itself when its anchor moves is worse than no guard.
#
# Run: bash scripts/check_roster_sync_sections.sh
set -euo pipefail

FILE='src/group/cli.rs'
FUNCS=('decide_departures' 'seed_roster_locked')

if [ ! -f "$FILE" ]; then
    echo "FAIL: ${FILE} not found -- this check's anchor has moved." >&2
    exit 1
fi

STATUS=0
for fn in "${FUNCS[@]}"; do
    # Match the definition at any visibility, async or not, so a converted
    # signature is found rather than missed.
    DEF=$(grep -nE "^[[:space:]]*(pub(\([^)]*\))?[[:space:]]+)?(async[[:space:]]+)?fn[[:space:]]+${fn}\b" "$FILE" || true)

    if [ -z "$DEF" ]; then
        echo "FAIL: ${fn} not found in ${FILE}." >&2
        echo "  This check exists to keep that function synchronous. If it was renamed" >&2
        echo "  or moved, update FUNCS here -- do not delete the check." >&2
        STATUS=1
        continue
    fi

    COUNT=$(printf '%s\n' "$DEF" | grep -c . || true)
    if [ "$COUNT" -ne 1 ]; then
        echo "FAIL: expected exactly one definition of ${fn} in ${FILE}, found ${COUNT}:" >&2
        printf '%s\n' "$DEF" >&2
        STATUS=1
        continue
    fi

    if printf '%s\n' "$DEF" | grep -qE '\basync[[:space:]]+fn\b'; then
        echo "FAIL: ${fn} is 'async fn':" >&2
        printf '  %s\n' "$DEF" >&2
        echo "  It holds the roster-map critical section and must stay synchronous." >&2
        echo "  Making it async re-opens the lost update its non-asyncness prevents," >&2
        echo "  and nothing else in CI will notice: the tests stay green and" >&2
        echo "  clippy::await_holding_lock does not flag tokio guards." >&2
        echo "  See the doc comment on decide_departures." >&2
        STATUS=1
    fi
done

if [ "$STATUS" -ne 0 ]; then
    exit 1
fi

echo "OK: decide_departures and seed_roster_locked are both synchronous."
