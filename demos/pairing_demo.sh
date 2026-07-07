#!/usr/bin/env bash
# Self-pacing demo of bastion-less PQC P2P *pairing* (ssh-copy-id equivalent) and
# what it unlocks. An UNREGISTERED client bootstraps trust over a one-time token
# on a dedicated ALPN (nkct/pairing/1): it sends its signed KeyBundle, the server
# verifies it against the *connecting* identity's fingerprint (self-signed, so a
# token holder cannot register someone else's bundle) and appends that
# fingerprint to its --peer-allowlist. Pairing adds to the allowlist ONLY — the
# admin must still grant what the peer may DO, so default-deny is preserved. Then
# the same fingerprint drives a policy-confined shell and an scp path jail over
# the same iroh transport + mutual ML-DSA-65 auth. Loopback (one host); recorded
# with VHS (see pairing.tape).
set -u

BIN="$PWD/target/release/nk-crypto-tool"
unset RUST_LOG
export NK_PASSPHRASE=""   # unencrypted demo keys: nothing prompts, no warning prints
ROOT=$(mktemp -d "${TMPDIR:-/tmp}/nkct-pairing-demo.XXXXXX") || exit 1
mkdir -p "$ROOT/srv" "$ROOT/cli" "$ROOT/srv/jail"
SRV=""
trap 'kill $SRV 2>/dev/null; rm -rf "$ROOT"' EXIT

# start_server <logfile> <args...> : launch a backgrounded server, echo its ticket
start_server() {
  local log="$1"; shift
  "$BIN" "$@" > "$log" 2>&1 &
  SRV=$!
  TICKET=""
  for _ in $(seq 1 80); do
    TICKET=$(grep -aoE 'nkct1[A-Z2-7]+' "$log" | head -1)
    [ -n "$TICKET" ] && break; sleep 0.25
  done
}

# The server's long-term ML-DSA-65 identity, and the client's identity + KEM key.
"$BIN" --mode pqc --gen-sign-key --key-dir "$ROOT/srv" --dsa-algo ML-DSA-65 >/dev/null 2>&1
"$BIN" --mode pqc --gen-sign-key --key-dir "$ROOT/cli" --dsa-algo ML-DSA-65 >/dev/null 2>&1
"$BIN" --mode pqc --gen-enc-key  --key-dir "$ROOT/cli"                      >/dev/null 2>&1
CFP=$("$BIN" --mode pqc --fingerprint --signing-pubkey "$ROOT/cli/public_sign_pqc.key" 2>/dev/null \
        | grep -aoE '[0-9a-f]{64}' | head -1)
: > "$ROOT/srv/allowlist"   # the client is NOT pre-registered

sleep 1
echo "# ssh-copy-id for bastion-less PQC P2P: pair once, then shell + scp over iroh + ML-DSA-65"
sleep 1.4

# ── 1. PAIR: an unregistered client registers itself over a one-time token ────
echo "# [1/4] PAIR  — allowlist starts EMPTY; client self-registers via a one-time token"
sleep 0.7
start_server "$ROOT/pair.log" --serve-pairing --mode pqc \
  --signing-privkey "$ROOT/srv/private_sign_pqc.key" \
  --peer-allowlist "$ROOT/srv/allowlist" --key-dir "$ROOT/srv"
OTP=$(grep -aoE 'one-time token: [A-Z2-7]+' "$ROOT/pair.log" | awk '{print $3}' | head -1)
echo "  server issued a one-time token (out-of-band):  $OTP"
sleep 1
"$BIN" --copy-bundle --mode pqc --connect "$TICKET" --token "$OTP" \
  --signing-privkey "$ROOT/cli/private_sign_pqc.key" --keybundle-handle laptop \
  --key-dir "$ROOT/cli" 2>&1 | grep -aiE 'registered'
sleep 0.6
echo "  --peer-allowlist now pins the client that PROVED it holds the bundle's key:"
echo "    $(cat "$ROOT/srv/allowlist")"
sleep 1.6

# ── 2. AUTHORIZE: pairing only added to the allowlist — grant what it may DO ──
echo "# [2/4] AUTHORIZE — pairing added to the allowlist ONLY; admin grants capability (default-deny)"
sleep 0.7
printf '%s cmd-allow="id,uname -a"\n' "$CFP" > "$ROOT/shell.policy"
printf '%s read="%s" write="%s"\n' "$CFP" "$ROOT/srv/jail" "$ROOT/srv/jail" > "$ROOT/scp.policy"
echo "  shell-policy:  ${CFP:0:20}...  cmd-allow=\"id,uname -a\""
echo "  scp-policy:    ${CFP:0:20}...  read=\"jail/\"  write=\"jail/\""
sleep 1.6

# ── 3. SHELL: the paired fingerprint drives a command-confined shell ─────────
echo "# [3/4] SHELL — paired fingerprint + policy: allowed command runs, anything else is refused"
sleep 0.7
start_server "$ROOT/shell.log" --serve-shell --mode pqc \
  --signing-privkey "$ROOT/srv/private_sign_pqc.key" \
  --peer-allowlist "$ROOT/srv/allowlist" --shell-policy "$ROOT/shell.policy"
echo "  \$ nk-crypto-tool --shell --shell-cmd 'uname -a'   (allowed)"
sleep 0.5
"$BIN" --shell --mode pqc --connect "$TICKET" --shell-cmd "uname -a" \
  --signing-privkey "$ROOT/cli/private_sign_pqc.key" --key-dir "$ROOT/cli" 2>&1 | grep -aiE 'Linux|GNU'
sleep 1
echo "  \$ nk-crypto-tool --shell --shell-cmd 'cat /etc/shadow'   (NOT in cmd-allow)"
sleep 0.5
# A denied command is refused server-side: the client just gets a closed session,
# so surface the server's audit line to show the refusal.
"$BIN" --shell --mode pqc --connect "$TICKET" --shell-cmd "cat /etc/shadow" \
  --signing-privkey "$ROOT/cli/private_sign_pqc.key" --key-dir "$ROOT/cli" >/dev/null 2>&1
sleep 0.5
grep -ai 'denied' "$ROOT/shell.log" | tail -1 | sed -E 's/.*(shell denied[^"]*)/  server refused: \1/'
kill $SRV 2>/dev/null; SRV=""
sleep 1.6

# ── 4. SCP: the same fingerprint gets a path-jailed file transfer ────────────
echo "# [4/4] SCP — same fingerprint, path-jailed transfer (write confined to jail/)"
sleep 0.7
start_server "$ROOT/scp.log" --serve-scp --mode pqc \
  --signing-privkey "$ROOT/srv/private_sign_pqc.key" \
  --peer-allowlist "$ROOT/srv/allowlist" --scp-policy "$ROOT/scp.policy"
printf 'deploy key + config, delivered over nkct/scp/1\n' > "$ROOT/cli/release.txt"
echo "  \$ scp-put release.txt -> jail/release.txt      (inside the jail: allowed)"
sleep 0.5
"$BIN" --scp-put "$ROOT/cli/release.txt" "$ROOT/srv/jail/release.txt" --connect "$TICKET" --mode pqc \
  --signing-privkey "$ROOT/cli/private_sign_pqc.key" --key-dir "$ROOT/cli" 2>&1 | grep -aiE 'uploaded'
sleep 0.8
echo "  \$ scp-put release.txt -> /tmp/escape.txt       (outside the jail: refused)"
sleep 0.5
"$BIN" --scp-put "$ROOT/cli/release.txt" "/tmp/escape.txt" --connect "$TICKET" --mode pqc \
  --signing-privkey "$ROOT/cli/private_sign_pqc.key" --key-dir "$ROOT/cli" 2>&1 \
  | grep -aiE 'denied|outside|not permitted|policy' | head -1 | sed 's/^.*\(denied\|outside\|policy\).*/  refused: outside the write jail/'
sleep 1
if cmp -s "$ROOT/cli/release.txt" "$ROOT/srv/jail/release.txt"; then
  echo "# paired over a one-time token, then confined shell + scp — one ML-DSA-65 anchor, no open port"
fi
sleep 3
