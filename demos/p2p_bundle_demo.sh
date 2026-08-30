#!/usr/bin/env bash
# Self-pacing demo of *asynchronous* bastion-less PQC file delivery via a signed
# recipient bundle + One-Time Prekey inbox (PQXDH-style, PQ forward secret).
#
# Unlike the live scp/shell demos, sender and recipient are never online at the
# same moment: the recipient publishes a signed bundle (their ML-DSA-65 identity
# anchors a static X-Wing key, a NodeId, and an inbox slot) and stocks one-time
# prekeys in an untrusted store-and-forward inbox. Later the sender verifies the
# bundle against a pinned fingerprint, fetches one prekey, seals the file with
# full PQ-FS, and drops the envelope in the inbox. Later still the recipient
# polls the inbox and decrypts. The inbox never sees plaintext or keys.
#
# native ctx `nkct-recipient-bundle-v1` domain-separates the bundle signature
# from file / prekey / handshake signatures made by the same identity key.
# Recorded with VHS (see p2p_bundle.tape).
set -u

BIN="$PWD/target/release/nkct"
unset RUST_LOG
export NK_PASSPHRASE="demo-passphrase"   # one demo secret unlocks the prekey/inbox stores — nothing prompts
# mktemp -d gives a 0700, unpredictable dir: no fixed /tmp name for a local
# attacker to pre-plant symlinks in (CWE-59), and the other-unreadable parent
# keeps the inbox slot ticket out of other users' reach regardless of umask.
ROOT=$(mktemp -d "${TMPDIR:-/tmp}/nkct-bundle-demo.XXXXXX") || exit 1
mkdir -p "$ROOT/keys" "$ROOT/rcpt" "$ROOT/inbox" "$ROOT/send" "$ROOT/out"
INBOX_PID=""
trap 'kill $INBOX_PID 2>/dev/null; rm -rf "$ROOT"' EXIT

# The recipient's long-term ML-DSA-65 signing identity (the single anchor).
"$BIN" --mode pqc --gen-sign-key --key-dir "$ROOT/keys" --dsa-algo ML-DSA-65 >/dev/null 2>&1

# The secret the sender will deliver while the recipient is offline.
printf 'launch-codes: 0000  —  sealed to a bundle, delivered through an untrusted inbox\n' \
  > "$ROOT/send/secret.txt"

sleep 1
echo "# Asynchronous PQC delivery: signed recipient bundle + One-Time Prekey inbox (PQ-FS)"
sleep 1
echo "# sender and recipient are NEVER online together — an untrusted inbox relays the envelope"
sleep 1.4

# ── 1. untrusted store-and-forward inbox ────────────────────────────────────
echo "# [1/4] start the untrusted inbox (store-and-forward; never sees plaintext or keys)"
sleep 0.7
"$BIN" --inbox-server --transport iroh --mls-storage "$ROOT/inbox/inbox.db" \
  > "$ROOT/inbox.log" 2>&1 &
INBOX_PID=$!
INBOX=""
for _ in $(seq 1 60); do
  INBOX=$(grep -aoE 'nkct1[A-Z2-7]+' "$ROOT/inbox.log" | head -1)
  [ -n "$INBOX" ] && break; sleep 0.25
done
echo "  inbox up, slot ticket: ${INBOX:0:44}..."
sleep 1.3

# ── 2. recipient: publish signed bundle + stock one-time prekeys, then go dark ─
echo "# [2/4] RECIPIENT: publish a signed bundle + stock 4 one-time prekeys, then go offline"
sleep 0.7
"$BIN" --prekey-cmd init-identity --transport iroh \
  --signing-privkey "$ROOT/keys/private_sign_pqc.key" \
  --prekey-storage  "$ROOT/rcpt/prekeys.db" \
  --prekey-output   "$ROOT/rcpt/bundle.nkb1" \
  --prekey-count 4 --inbox-url "$INBOX" > "$ROOT/rcpt.log" 2>&1
FP=$(grep -aoE '[0-9a-f]{64}' "$ROOT/rcpt.log" | head -1)
echo "  bundle written; recipient fingerprint (shared out-of-band):"
echo "    ${FP}"
sleep 1.4

# ── 3. sender: verify bundle against pinned fingerprint, seal, deposit ───────
echo "# [3/4] SENDER: pin the fingerprint, seal secret.txt with full PQ-FS, drop in the inbox"
sleep 0.7
"$BIN" --prekey-cmd seal --transport iroh \
  --recipient-bundle "$ROOT/rcpt/bundle.nkb1" \
  --recipient-fingerprint "$FP" \
  --strict-pqfs \
  "$ROOT/send/secret.txt" 2>&1 | grep -aE 'verified|Sealed'
sleep 1.4

# ── 4. recipient: come back online, poll the inbox, decrypt ──────────────────
echo "# [4/4] RECIPIENT: back online — poll the inbox and decrypt"
sleep 0.7
"$BIN" --prekey-cmd recv --transport iroh \
  --prekey-storage "$ROOT/rcpt/prekeys.db" \
  --output-file "$ROOT/out/msg" --inbox-url "$INBOX" 2>&1 | grep -aE 'Decrypted|recv complete'
sleep 1

GOT=$(cat "$ROOT"/out/msg.* 2>/dev/null)
if [ "$GOT" = "$(cat "$ROOT/send/secret.txt")" ]; then
  echo "# delivered byte-identical through an untrusted inbox — PQ forward secret, single ML-DSA anchor"
  echo "  \"${GOT}\""
fi
sleep 3
