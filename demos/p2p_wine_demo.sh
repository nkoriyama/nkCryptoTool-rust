#!/usr/bin/env bash
# Self-pacing demo: the WINDOWS build of nkct, run under Wine on Linux, doing
# bastion-less PQC P2P. As a client it connects to a Linux-native shell server
# over iroh, completes mutual ML-DSA-65 auth, and runs a command on the remote
# shell. Meant to be recorded with VHS (see p2p_wine.tape); run inside the
# `winbuild` distrobox where wine64 lives.
set -u

WINE=/usr/lib/wine/wine64
export WINEDEBUG=-all WINEPREFIX="$HOME/.wine-nkct"
unset RUST_LOG
REPO="/var/home/bazzite/ドキュメント/src/nkCryptoTool-rust"
LINBIN="$REPO/target/release/nkct"
EXE="$REPO/target/x86_64-pc-windows-msvc/release/nkct.exe"
export NK_PASSPHRASE=demo-passphrase
D="$(mktemp -d)"
SRV=""
trap 'kill $SRV 2>/dev/null; rm -rf "$D"' EXIT

sleep 1
echo "# The CLIENT is the Windows .exe, running under Wine on Linux:"
sleep 0.8
echo "  client binary : $(basename "$EXE")  (x86_64 Windows PE)"
echo "  runtime       : $("$WINE" --version)"
sleep 1.6
echo

echo "# 1) start a Linux-native PQC P2P shell server (loopback iroh, no open port)"
sleep 0.8
"$LINBIN" --mode pqc --gen-sign-key --key-dir "$D/server" --dsa-algo ML-DSA-65 >/dev/null 2>&1
"$LINBIN" --mode pqc --gen-sign-key --key-dir "$D/client" --dsa-algo ML-DSA-65 >/dev/null 2>&1
"$LINBIN" --serve-shell --mode pqc \
  --signing-privkey "$D/server/private_sign_pqc.key" \
  --signing-pubkey  "$D/client/public_sign_pqc.key" > "$D/srv.log" 2>&1 &
SRV=$!
TICKET=""
for _ in $(seq 1 40); do
  TICKET="$(grep -aoE 'nkct1[A-Z2-7]+' "$D/srv.log" | head -1)"
  [ -n "$TICKET" ] && break; sleep 0.25
done
echo "  server up (client key pinned), ticket: ${TICKET:0:46}..."
sleep 1.6
echo

echo "# 2) the Wine client connects over iroh -> path kind + mutual PQC auth"
sleep 0.8
"$WINE" "$EXE" --conn-metrics --connect "$TICKET" --mode pqc \
  --signing-privkey "$D/client/private_sign_pqc.key" \
  --signing-pubkey  "$D/server/public_sign_pqc.key" 2>&1 \
  | grep -aE 'authenticated|nkct-metrics' | sed 's/^/  /'
sleep 1.8
echo

echo "# 3) run a command on the remote Linux shell, from the Wine client"
sleep 0.8
"$WINE" "$EXE" --shell --shell-cmd "uname -srm; id -un" --connect "$TICKET" --mode pqc \
  --signing-privkey "$D/client/private_sign_pqc.key" \
  --signing-pubkey  "$D/server/public_sign_pqc.key" 2>/dev/null \
  | sed 's/^/  remote> /'
sleep 2
echo
echo "# Windows binary, under Wine, bastion-less PQC P2P: it works."
sleep 2.5
