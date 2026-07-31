#!/usr/bin/env bash
# Self-pacing demo of *nested / chained* bastion-less PQC P2P: shell into "host
# A", launch `nkct --serve-scp` INSIDE that shell (A becomes a fresh scp
# endpoint), then have an outside scp client fetch A's file through that new
# ticket. Two independent PQC P2P hops, each mutually authenticated, no open
# inbound port anywhere. Recorded with VHS (see p2p_nested.tape).
set -u

BIN="$PWD/target/release/nk-crypto-tool"
unset NK_PASSPHRASE RUST_LOG
ROOT=$(mktemp -d "${TMPDIR:-/tmp}/nkct-nested-demo.XXXXXX") || exit 1
mkdir -p "$ROOT"/{shk,shc,sck,scc,A}
SHSRV=""; SHCLI=""
trap 'kill $SHCLI $SHSRV 2>/dev/null; rm -rf "$ROOT"' EXIT

gen() { NK_PASSPHRASE="" "$BIN" --mode pqc --gen-sign-key --key-dir "$1" --dsa-algo ML-DSA-65 >/dev/null 2>&1; }
gen "$ROOT/shk"; gen "$ROOT/shc"; gen "$ROOT/sck"; gen "$ROOT/scc"
fp() { "$BIN" --mode pqc --fingerprint --signing-pubkey "$1" 2>/dev/null | grep -aoE '[0-9a-f]{64}' | head -1; }
SCP_CFP=$(fp "$ROOT/scc/public_sign_pqc.key")
echo "secret file that lives on host A" > "$ROOT/A/on-A.txt"
printf '%s  read="%s"  write="%s"\n' "$SCP_CFP" "$ROOT/A" "$ROOT/A" > "$ROOT/scp.policy"

sleep 1
echo "# Nested PQC P2P:  shell into host A  ->  run 'nkct --serve-scp' INSIDE A  ->  fetch A's file"
sleep 1.5

echo "# [1] start a p2p shell server (= host A)"
sleep 0.7
"$BIN" --serve-shell --mode pqc \
  --signing-privkey "$ROOT/shk/private_sign_pqc.key" \
  --signing-pubkey  "$ROOT/shc/public_sign_pqc.key" > "$ROOT/shell-srv.log" 2>&1 &
SHSRV=$!
SHT=""; for _ in $(seq 1 40); do SHT=$(grep -aoE 'nkct1[A-Z2-7]+' "$ROOT/shell-srv.log"|head -1); [ -n "$SHT" ] && break; sleep 0.25; done
echo "      host A shell ticket: ${SHT:0:40}..."
sleep 1.4

echo "# [2] shell INTO A and, inside that shell, launch an scp server:"
sleep 0.6
echo "      \$ nkct --shell --shell-cmd 'nkct --serve-scp ...' --connect <A-ticket>"
sleep 1.1
"$BIN" --shell --shell-cmd "$BIN --serve-scp --mode pqc --signing-privkey $ROOT/sck/private_sign_pqc.key --signing-pubkey $ROOT/scc/public_sign_pqc.key --scp-policy $ROOT/scp.policy" \
  --connect "$SHT" --mode pqc \
  --signing-privkey "$ROOT/shc/private_sign_pqc.key" --signing-pubkey "$ROOT/shk/public_sign_pqc.key" \
  > "$ROOT/inside-A.out" 2>&1 &
SHCLI=$!
SCT=""; for _ in $(seq 1 60); do SCT=$(grep -aoE 'nkct1[A-Z2-7]+' "$ROOT/inside-A.out" | grep -v "^${SHT}$" | tail -1); [ -n "$SCT" ] && break; sleep 0.25; done
echo "      (inside A) [nkct] Ticket: $(printf '%s' "$SCT" | cut -c1-40)..."
echo "      ^ the scp server's own ticket, printed from INSIDE A's shell"
sleep 1.7

echo "# [3] from outside, fetch A's file through that inside-A ticket:"
sleep 0.6
echo "      \$ nkct --scp-get /A/on-A.txt got.txt --connect <inside-A-ticket>"
sleep 1.1
timeout 30 "$BIN" --scp-get "$ROOT/A/on-A.txt" "$ROOT/got.txt" --connect "$SCT" --mode pqc \
  --signing-privkey "$ROOT/scc/private_sign_pqc.key" --signing-pubkey "$ROOT/sck/public_sign_pqc.key" 2>&1 \
  | grep -aE 'authenticated|downloaded' | sed -E "s#$ROOT/##g; s/^/      /"
sleep 1.4

echo "# pulled from inside A:  \"$(cat "$ROOT/got.txt" 2>/dev/null)\"   — two PQC P2P hops, no open port"
sleep 3
