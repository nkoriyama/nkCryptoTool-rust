#!/usr/bin/env bash
# Self-pacing demo of bastion-less PQC P2P *pairing* (ssh-copy-id equivalent) and
# what it unlocks. An UNREGISTERED client bootstraps trust over a one-time token
# on a dedicated ALPN (nkct/pairing/1): it sends its signed KeyBundle, the server
# verifies it against the *connecting* identity's fingerprint (self-signed, so a
# token holder cannot register someone else's bundle) and records that
# fingerprint with per-service grants in its redb keyring. Pairing grants
# TRANSPORT only — the admin must still grant what the peer may DO via policy,
# so default-deny is preserved. Then
# the same fingerprint drives a policy-confined shell and an scp path jail over
# the same iroh transport + mutual ML-DSA-65 auth. Loopback (one host); recorded
# with VHS (see pairing.tape).
#
# Robustness: every refusal is asserted, not merely printed — if a negative case
# stops producing its expected line (e.g. the server wording drifts) the demo
# prints a loud "[DEMO BUG]" instead of a blank frame that would read as "the
# attack silently succeeded".
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
# The client's identity fingerprint (== SHA3-256 of its ML-DSA pub) — the single
# join key that threads pair -> authorize -> shell -> scp. Pairing authorizes
# THIS value in the server's keyring; the policies below key on it too.
CFP=$("$BIN" --mode pqc --fingerprint --signing-pubkey "$ROOT/cli/public_sign_pqc.key" 2>/dev/null \
        | grep -aoE '[0-9a-f]{64}' | head -1)
KEYRING="$ROOT/srv/keyring.db"   # pairing writes authz + bundle here (redb, 0600)

sleep 1
echo "# ssh-copy-id for bastion-less PQC P2P: pair once, then shell + scp over iroh + ML-DSA-65"
sleep 1.4

# ── 1. PAIR: an unregistered client registers itself over a one-time token ────
echo "# [1/4] PAIR  — keyring authz starts EMPTY; only the holder of the out-of-band token registers"
sleep 0.7

# 1a. NEGATIVE: a client that does NOT hold the real token is refused — enrollment
#     is default-deny, so the allowlist stays empty. (Each --serve-pairing is
#     single-shot, so a token is one-use by construction. The stronger property —
#     that a *token holder* still cannot register SOMEONE ELSE's bundle — is
#     enforced structurally, not shown here: --copy-bundle always self-signs the
#     bundle with the connecting ML-DSA key, so bundle-owner == handshake-identity
#     by construction; the cross-identity rejection is covered by the
#     `register_rejects_bundle_from_a_different_identity_refinement_1` unit test.)
start_server "$ROOT/pair_bad.log" --serve-pairing --mode pqc \
  --signing-privkey "$ROOT/srv/private_sign_pqc.key" --key-dir "$ROOT/srv"
echo "  \$ --copy-bundle --token WRONGTOK   (does not hold the real token)"
sleep 0.5
REFUSAL=$("$BIN" --copy-bundle --mode pqc --connect "$TICKET" --token "AAAA2345" \
  --signing-privkey "$ROOT/cli/private_sign_pqc.key" --keybundle-handle laptop \
  --key-dir "$ROOT/cli" 2>&1 | grep -aioE 'invalid pairing token' | head -1)
kill $SRV 2>/dev/null; SRV=""
if [ -n "$REFUSAL" ]; then
  echo "  server refused: $REFUSAL  (keyring authorizes no one)"
else
  echo "  [DEMO BUG] wrong-token refusal not observed"
fi
sleep 1.3

# 1b. The real token registers the client — and the bundle is pinned to the
#     handshake-verified fingerprint (proof-of-possession), not merely the token.
start_server "$ROOT/pair.log" --serve-pairing --mode pqc \
  --signing-privkey "$ROOT/srv/private_sign_pqc.key" --key-dir "$ROOT/srv"
OTP=$(grep -aoE 'one-time token: [A-Z2-7]+' "$ROOT/pair.log" | awk '{print $3}' | head -1)
echo "  server issued a one-time token (out-of-band):  $OTP"
sleep 1
"$BIN" --copy-bundle --mode pqc --connect "$TICKET" --token "$OTP" \
  --signing-privkey "$ROOT/cli/private_sign_pqc.key" --keybundle-handle laptop \
  --key-dir "$ROOT/cli" 2>&1 | grep -aiE 'registered' \
  || echo "  [DEMO BUG] registration not confirmed"
sleep 0.6
# `laptop` is a label AND the key the saved bundle blob lands under in the redb
# keyring (<key-dir>/keyring.db); a different identity cannot clobber it — the
# server refuses a handle already owned by another fingerprint. The allowlist, by
# contrast, is keyed by the 64-hex fingerprint: the single join key that threads
# pair -> authorize -> shell -> scp.
echo "  keyring now authorizes the client that PROVED it holds the bundle's key:"
echo "    $CFP  (grants: shell,scp,forward — default; restrict with --pairing-grant)"
sleep 1.6

# ── 2. AUTHORIZE: pairing granted TRANSPORT in the keyring — grant CAPABILITY ──
echo "# [2/4] AUTHORIZE — pairing granted transport; admin grants capability via policy (default-deny)"
sleep 0.7
# The client's fingerprint is the single join key: pairing authorized it in the
# keyring, and both policies key on it too.
FP="$CFP"
printf '%s cmd-allow="id,uname -a"\n' "$FP" > "$ROOT/shell.policy"
printf '%s read="%s" write="%s"\n' "$FP" "$ROOT/srv/jail" "$ROOT/srv/jail" > "$ROOT/scp.policy"
echo "  shell-policy:  ${FP:0:20}...  cmd-allow=\"id,uname -a\""
echo "  scp-policy:    ${FP:0:20}...  read=\"jail/\"  write=\"jail/\""
sleep 1.6

# ── 3. SHELL: the paired fingerprint drives a command-confined shell ─────────
echo "# [3/4] SHELL — paired fingerprint + policy: allowed command runs, anything else is refused"
sleep 0.7
start_server "$ROOT/shell.log" --serve-shell --mode pqc \
  --signing-privkey "$ROOT/srv/private_sign_pqc.key" \
  --keyring-db "$KEYRING" --shell-policy "$ROOT/shell.policy"
echo "  \$ nk-crypto-tool --shell --shell-cmd 'uname -a'   (allowed)"
sleep 0.5
"$BIN" --shell --mode pqc --connect "$TICKET" --shell-cmd "uname -a" \
  --signing-privkey "$ROOT/cli/private_sign_pqc.key" --key-dir "$ROOT/cli" 2>&1 | grep -aiE 'Linux|GNU' \
  || echo "  [DEMO BUG] allowed command produced no output"
sleep 1
echo "  \$ nk-crypto-tool --shell --shell-cmd 'cat /etc/shadow'   (NOT in cmd-allow)"
sleep 0.5
# A denied command is refused server-side: the client just gets a closed session,
# so surface the server's audit line to show the refusal — and assert it appeared.
"$BIN" --shell --mode pqc --connect "$TICKET" --shell-cmd "cat /etc/shadow" \
  --signing-privkey "$ROOT/cli/private_sign_pqc.key" --key-dir "$ROOT/cli" >/dev/null 2>&1
# The server logs the refusal only after it drains the client's close
# (deny_and_drain), which can lag the client's return by a beat — poll the log
# instead of a fixed sleep so a slow drain doesn't read as "no refusal".
DENY=""
for _ in $(seq 1 56); do   # ~14s: comfortably past deny_and_drain's 10s drain cap
  DENY=$(grep -ai 'denied' "$ROOT/shell.log" | tail -1 | sed -E 's/.*(shell denied[^"]*)/  server refused: \1/')
  [ -n "$DENY" ] && break; sleep 0.25
done
if [ -n "$DENY" ]; then echo "$DENY"; else echo "  [DEMO BUG] shell refusal not observed"; fi
kill $SRV 2>/dev/null; SRV=""
sleep 1.6

# ── 4. SCP: the same fingerprint gets a path-jailed file transfer ────────────
echo "# [4/4] SCP — same fingerprint, path-jailed transfer (write confined to jail/)"
sleep 0.7
start_server "$ROOT/scp.log" --serve-scp --mode pqc \
  --signing-privkey "$ROOT/srv/private_sign_pqc.key" \
  --keyring-db "$KEYRING" --scp-policy "$ROOT/scp.policy"
printf 'deploy key + config, delivered over nkct/scp/1\n' > "$ROOT/cli/release.txt"
echo "  \$ scp-put release.txt -> jail/release.txt      (inside the jail: allowed)"
sleep 0.5
"$BIN" --scp-put "$ROOT/cli/release.txt" "$ROOT/srv/jail/release.txt" --connect "$TICKET" --mode pqc \
  --signing-privkey "$ROOT/cli/private_sign_pqc.key" --key-dir "$ROOT/cli" 2>&1 | grep -aiE 'uploaded' \
  || echo "  [DEMO BUG] in-jail upload not confirmed"
sleep 0.8
echo "  \$ scp-put release.txt -> /tmp/escape.txt       (outside the jail: refused)"
sleep 0.5
JAIL_DENY=$("$BIN" --scp-put "$ROOT/cli/release.txt" "/tmp/escape.txt" --connect "$TICKET" --mode pqc \
  --signing-privkey "$ROOT/cli/private_sign_pqc.key" --key-dir "$ROOT/cli" 2>&1 \
  | grep -aioE 'denied|outside|not permitted|policy' | head -1)
if [ -n "$JAIL_DENY" ]; then echo "  refused: outside the write jail"; else echo "  [DEMO BUG] jail refusal not observed"; fi
sleep 1
if cmp -s "$ROOT/cli/release.txt" "$ROOT/srv/jail/release.txt"; then
  echo "# paired over a one-time token, then confined shell + scp — one ML-DSA-65 anchor, no open port"
fi
sleep 3
