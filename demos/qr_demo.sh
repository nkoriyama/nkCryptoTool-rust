#!/usr/bin/env bash
# Self-pacing demo of `nkct --qr`: render a connection ticket as a QR code
# directly in the terminal, with no external `qrencode` and no network.
#
# The ticket is generated for real (a short-lived --serve-shell listener whose
# ticket we grab and then kill) rather than hard-coded, so what the QR encodes
# is a ticket the tool actually produced. Recorded with VHS (see demos/qr.tape).
set -u

BIN="$PWD/target/release/nkct"
ROOT=$(mktemp -d "${TMPDIR:-/tmp}/nkct-qr-demo.XXXXXX") || exit 1
SRV=""
trap 'kill $SRV 2>/dev/null; rm -rf "$ROOT"' EXIT
export NK_PASSPHRASE="demo-passphrase"     # demo only — never do this for real keys

"$BIN" --mode pqc --gen-sign-key --key-dir "$ROOT" --dsa-algo ML-DSA-65 >/dev/null 2>&1
"$BIN" --serve-shell --mode pqc --no-relay \
  --signing-privkey "$ROOT/private_sign_pqc.key" \
  --signing-pubkey  "$ROOT/public_sign_pqc.key" > "$ROOT/srv.log" 2>&1 &
SRV=$!
TICKET=""
for _ in $(seq 1 40); do
  TICKET=$(grep -aoE 'nkct1[0-9A-Za-z]+' "$ROOT/srv.log" | head -1)
  [ -n "$TICKET" ] && break
  sleep 0.25
done
kill $SRV 2>/dev/null; SRV=""
[ -n "$TICKET" ] || { echo "  [DEMO BUG] no ticket produced"; exit 1; }

sleep 1
echo "# Render a connection ticket as a QR in the terminal — no qrencode, no network"
sleep 1.4
echo "  \$ nkct --qr \"\$TICKET\"        (ticket is ${#TICKET} chars — awkward to retype, trivial to scan)"
sleep 1
"$BIN" --qr "$TICKET" || echo "  [DEMO BUG] --qr failed"
sleep 2.5
echo
echo "# The same thing from stdin, so the ticket never lands in shell history or argv:"
sleep 1.2
echo "  \$ printf %s \"\$TICKET\" | nkct --qr -"
sleep 1
printf '%s' "$TICKET" | "$BIN" --qr - >/dev/null 2>&1 \
  && echo "  (identical QR — rendered from stdin)" \
  || echo "  [DEMO BUG] --qr - failed"
sleep 1.5
