#!/usr/bin/env bash
# Run a built artifact through a real P2P round-trip: start a shell server,
# connect to it over iroh, execute a remote command, and require the output back.
#
# WHY THIS EXISTS
# ---------------
# v2.2.0's musl artifacts were built, hashed, published, and completely unable to
# do P2P. `noq-udp` enables SO_TIMESTAMPNS on its socket and then decodes the
# resulting cmsg with `assert!(align_of::<T>() <= align_of::<C>())`; on musl
# `cmsghdr` aligns to 4 while `timespec` aligns to 8, so the process aborted on
# the first packet it received (n0-computer/noq#774).
#
# Every gate passed. `cargo package`, the reproducible double-build, the hash
# comparison, `--version`, even encrypt/decrypt and sign/verify on real hardware
# -- none of them open a socket. CI's own tests never caught it either, because
# they run against a *gnu* build; the musl binary was compiled in a container and
# never executed by anything.
#
# So the artifact has to be run, and it has to be run doing the thing the tool is
# for. Anything less tests a different binary than the one that ships.
set -euo pipefail

BIN="${1:?usage: artifact_p2p_smoke.sh <path-to-nkct>}"
[ -x "$BIN" ] || { echo "not executable: $BIN" >&2; exit 1; }

D="$(mktemp -d)"
SRV=""
cleanup() { [ -n "$SRV" ] && kill "$SRV" 2>/dev/null || true; rm -rf "$D"; }
trap cleanup EXIT

export NK_PASSPHRASE=""   # smoke only: an unencrypted throwaway key
"$BIN" --mode pqc --gen-sign-key --key-dir "$D" --dsa-algo ML-DSA-65 >/dev/null 2>&1

# Both ends pin the same identity; this checks the transport, not authorization.
"$BIN" --serve-shell --mode pqc --key-dir "$D" \
    --signing-privkey "$D/private_sign_pqc.key" \
    --signing-pubkey  "$D/public_sign_pqc.key" > "$D/srv.log" 2>&1 &
SRV=$!

TICKET=""
for _ in $(seq 1 60); do
    TICKET="$(grep -aoE 'nkct1[0-9A-Za-z]+' "$D/srv.log" | head -1 || true)"
    [ -n "$TICKET" ] && break
    # A server that aborted will never print one; say so instead of timing out.
    kill -0 "$SRV" 2>/dev/null || { echo "server died before publishing a ticket:" >&2; cat "$D/srv.log" >&2; exit 1; }
    sleep 1
done
[ -n "$TICKET" ] || { echo "no ticket after 60s:" >&2; cat "$D/srv.log" >&2; exit 1; }

MARK="p2p-smoke-$$-$RANDOM"
OUT="$(timeout 120 "$BIN" --shell --shell-cmd "echo $MARK" --connect "$TICKET" \
        --mode pqc --key-dir "$D" \
        --signing-privkey "$D/private_sign_pqc.key" \
        --signing-pubkey  "$D/public_sign_pqc.key" 2>&1)" || true

if printf '%s' "$OUT" | grep -q "$MARK"; then
    echo "P2P smoke OK: remote command output came back over iroh"
    exit 0
fi

echo "P2P smoke FAILED -- the artifact could not complete a round-trip." >&2
echo "--- client ---" >&2; printf '%s\n' "$OUT" >&2
echo "--- server ---" >&2; cat "$D/srv.log" >&2
exit 1
