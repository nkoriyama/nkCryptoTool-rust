#!/usr/bin/env bash
# Smoke test for .github/workflows/windows-cross-wine.yml.
#
# Runs the cross-built Windows .exe under Wine as a bastion-less PQC P2P *client*
# against a Linux-native server: iroh transport + mutual ML-DSA-65 auth + a
# remote shell command round-trip. No real Windows needed. (The .exe as a shell
# *server* is intentionally not exercised — that needs ConPTY, which Wine
# emulates incompletely; the transport/crypto path is what this validates.)
set -euo pipefail

LIN=target/release/nkct
EXE=target/x86_64-pc-windows-msvc/release/nkct.exe

[ -x "$LIN" ] || { echo "missing linux binary: $LIN"; exit 1; }
[ -f "$EXE" ] || { echo "missing windows exe: $EXE"; exit 1; }

# Locate wine64 (the ubuntu `wine64` package installs it under /usr/lib/wine).
WINE="$(command -v wine64 || command -v wine || true)"
[ -x "${WINE:-}" ] || WINE="$(dpkg -L wine64 2>/dev/null | grep -m1 -E '/wine64$' || true)"
[ -x "${WINE:-}" ] || { echo "wine64 not found"; exit 1; }
echo "wine: $WINE ($("$WINE" --version 2>/dev/null))"

export WINEDEBUG="${WINEDEBUG:--all}"
export NK_PASSPHRASE="${NK_PASSPHRASE:-ci-wine-smoke}"

D="$(mktemp -d)"
SRV=""
cleanup() { [ -n "$SRV" ] && kill "$SRV" 2>/dev/null || true; rm -rf "$D"; }
trap cleanup EXIT

# Initialise the wineprefix up front so its first-run cost is not charged to the
# connection attempt.
timeout 120 "$WINE" wineboot -i >/dev/null 2>&1 || true

# Server + client signing keys (the on-disk format the .exe reads is identical).
"$LIN" --mode pqc --gen-sign-key --key-dir "$D/s" --dsa-algo ML-DSA-65
"$LIN" --mode pqc --gen-sign-key --key-dir "$D/c" --dsa-algo ML-DSA-65

# Linux-native P2P shell server, pinning the client's public key (default-deny).
"$LIN" --serve-shell --mode pqc \
  --signing-privkey "$D/s/private_sign_pqc.key" \
  --signing-pubkey  "$D/c/public_sign_pqc.key" > "$D/srv.log" 2>&1 &
SRV=$!

TICKET=""
for _ in $(seq 1 80); do
  TICKET="$(grep -aoE 'nkct1[A-Z2-7]+' "$D/srv.log" | head -1 || true)"
  [ -n "$TICKET" ] && break
  sleep 0.25
done
[ -n "$TICKET" ] || { echo "server never printed a ticket:"; cat "$D/srv.log"; exit 1; }
echo "server up; ticket ${TICKET:0:32}..."

# The Windows .exe, under Wine, runs a command on the remote Linux shell.
set +e
OUT="$(timeout 90 "$WINE" "$EXE" --shell --shell-cmd 'echo WINE_P2P_OK; uname -m' \
  --connect "$TICKET" --mode pqc \
  --signing-privkey "$D/c/private_sign_pqc.key" \
  --signing-pubkey  "$D/s/public_sign_pqc.key" 2>"$D/cli.log")"
set -e

echo "--- remote output ---"; printf '%s\n' "$OUT"
echo "--- client log (tail) ---"; tail -6 "$D/cli.log" || true

grep -q 'authenticated successfully' "$D/cli.log" \
  || { echo "FAIL: no mutual PQC auth under Wine"; exit 1; }
printf '%s' "$OUT" | grep -q 'WINE_P2P_OK' \
  || { echo "FAIL: remote shell command produced no output"; exit 1; }

echo "PASS: Windows .exe under Wine completed bastion-less PQC P2P + remote shell"
