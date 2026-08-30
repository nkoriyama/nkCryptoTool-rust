#!/usr/bin/env bash
# Self-pacing demo of the full keyring workflow on ONE loopback host:
#   1. PAIR    — a client copies its KeyBundle to the server (ssh-copy-id), so the
#                server's keyring now holds the client's *encryption* keys + an scp
#                grant.
#   2. ENCRYPT — the server encrypts a file TO that client by handle (`--recipient
#                laptop`), pulling the bundle + pinned fingerprint from the keyring
#                — no separate key exchange.
#   3. SCP     — the client fetches the ciphertext over nkct/scp/1 (path-jailed,
#                the same paired fingerprint, per-service grant).
#   4. DECRYPT — only the client can open it (it holds the ML-KEM private key).
# One ML-DSA-65 identity threads all four; no open port. Recorded with VHS
# (copy_encrypt_scp.tape).
set -u

BIN="$PWD/target/release/nkct"
unset RUST_LOG
export NK_PASSPHRASE=""   # unencrypted demo keys: nothing prompts
ROOT=$(mktemp -d "${TMPDIR:-/tmp}/nkct-ces-demo.XXXXXX") || exit 1
mkdir -p "$ROOT/srv" "$ROOT/srv/share" "$ROOT/cli"
SRV=""
trap 'kill $SRV 2>/dev/null; rm -rf "$ROOT"' EXIT

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

# Server identity (ML-DSA-65). Client identity + ML-KEM encryption key (the one it
# will receive ciphertext under).
"$BIN" --mode pqc --gen-sign-key --key-dir "$ROOT/srv" --dsa-algo ML-DSA-65 >/dev/null 2>&1
"$BIN" --mode pqc --gen-sign-key --key-dir "$ROOT/cli" --dsa-algo ML-DSA-65 >/dev/null 2>&1
"$BIN" --mode pqc --gen-enc-key  --key-dir "$ROOT/cli"                      >/dev/null 2>&1
CFP=$("$BIN" --mode pqc --fingerprint --signing-pubkey "$ROOT/cli/public_sign_pqc.key" 2>/dev/null \
        | grep -aoE '[0-9a-f]{64}' | head -1)
KEYRING="$ROOT/srv/keyring.db"

sleep 1
echo "# keyring workflow: copy-bundle -> encrypt-to-handle -> scp -> decrypt (iroh, ML-DSA-65, no open port)"
sleep 1.4

# ── 1. PAIR: the client copies its KeyBundle to the server ───────────────────
echo "# [1/4] PAIR  — client copies its KeyBundle; server keyring gets its enc keys + an scp grant"
sleep 0.7
start_server "$ROOT/pair.log" --serve-pairing --mode pqc \
  --signing-privkey "$ROOT/srv/private_sign_pqc.key" --key-dir "$ROOT/srv" \
  --pairing-grant scp
OTP=$(grep -aoE 'one-time token: [A-Z2-7]+' "$ROOT/pair.log" | awk '{print $3}' | head -1)
echo "  \$ nkct --copy-bundle --keybundle-handle laptop   (one-time token: $OTP)"
sleep 0.6
printf '%s' "$OTP" | "$BIN" --copy-bundle --mode pqc --connect "$TICKET" --token - \
  --signing-privkey "$ROOT/cli/private_sign_pqc.key" --keybundle-handle laptop \
  --key-dir "$ROOT/cli" 2>&1 | grep -aiE 'registered' \
  || echo "  [DEMO BUG] pairing not confirmed"
kill $SRV 2>/dev/null; SRV=""
echo "  server keyring now holds laptop's bundle (enc keys) + scp grant — pinned to ${CFP:0:16}…"
sleep 1.6

# ── 2. ENCRYPT: the server encrypts a file TO laptop, by handle ──────────────
echo "# [2/4] ENCRYPT — server encrypts to 'laptop' via the keyring (no separate key exchange)"
sleep 0.7
printf 'deploy secret: rotate the prod token before Friday\n' > "$ROOT/srv/secret.txt"
echo "  \$ nkct --encrypt --recipient laptop  secret.txt -> share/secret.enc"
sleep 0.6
"$BIN" --encrypt --mode pqc --recipient laptop --key-dir "$ROOT/srv" \
  "$ROOT/srv/secret.txt" --output-file "$ROOT/srv/share/secret.enc" 2>&1 \
  | grep -aiE 'completed|error' | head -1
echo "  → ciphertext $(wc -c < "$ROOT/srv/share/secret.enc") bytes (only laptop's ML-KEM key can open it)"
sleep 1.6

# ── 3. SCP: the client fetches the ciphertext over nkct/scp/1 ────────────────
echo "# [3/4] SCP — client fetches the ciphertext (path-jailed to share/, scp grant)"
sleep 0.7
printf '%s read="%s" write="%s"\n' "$CFP" "$ROOT/srv/share" "$ROOT/srv/share" > "$ROOT/srv/scp.policy"
start_server "$ROOT/scp.log" --serve-scp --mode pqc \
  --signing-privkey "$ROOT/srv/private_sign_pqc.key" \
  --keyring-db "$KEYRING" --scp-policy "$ROOT/srv/scp.policy"
echo "  \$ nkct --scp-get share/secret.enc  ->  cli/secret.enc"
sleep 0.6
"$BIN" --scp-get "$ROOT/srv/share/secret.enc" "$ROOT/cli/secret.enc" --connect "$TICKET" --mode pqc \
  --signing-privkey "$ROOT/cli/private_sign_pqc.key" --key-dir "$ROOT/cli" 2>&1 \
  | grep -aiE 'downloaded|received|error' | head -1
kill $SRV 2>/dev/null; SRV=""
sleep 1.6

# ── 4. DECRYPT: only the client can open it ─────────────────────────────────
echo "# [4/4] DECRYPT — laptop opens it with its ML-KEM private key"
sleep 0.7
"$BIN" --decrypt --mode pqc --user-privkey "$ROOT/cli/private_enc_pqc.key" \
  "$ROOT/cli/secret.enc" --output-file "$ROOT/cli/secret.txt" 2>&1 \
  | grep -aiE 'completed|error' | head -1
sleep 0.6
if cmp -s "$ROOT/srv/secret.txt" "$ROOT/cli/secret.txt"; then
  echo "  recovered plaintext: \"$(cat "$ROOT/cli/secret.txt")\""
  echo "# copy-bundle -> encrypt-to-handle -> scp -> decrypt: byte-identical, one ML-DSA-65 anchor"
else
  echo "  [DEMO BUG] roundtrip mismatch"
fi
sleep 3
