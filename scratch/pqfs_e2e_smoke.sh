#!/usr/bin/env bash
# Real-network E2E smoke for the one-shot PQ-FS CLI flow.
# Exercises: inbox-server, gen-sign-key, prekey init-identity (publish +
# bundle), seal (fetch+seal+deposit), recv (poll+open) over iroh/no-relay.
set -u
BIN=target/debug/nk-crypto-tool
W=$(mktemp -d "${TMPDIR:-/tmp}/pqfs-smoke.XXXXXX")
export NK_PASSPHRASE=smoke-pass
echo "workdir: $W"

cleanup() { [ -n "${INBOX_PID:-}" ] && kill "$INBOX_PID" 2>/dev/null; }
trap cleanup EXIT

# 1. Inbox server in the background; capture its ticket.
"$BIN" --inbox-server --transport iroh --no-relay --mls-storage "$W/inbox.db" \
    >"$W/inbox.log" 2>&1 &
INBOX_PID=$!
for i in $(seq 1 50); do
    TICKET=$(grep -oE 'nkct1[A-Z2-7]+' "$W/inbox.log" | head -1)
    [ -n "$TICKET" ] && break
    sleep 0.2
done
[ -z "$TICKET" ] && { echo "FAIL: no inbox ticket"; cat "$W/inbox.log"; exit 1; }
# The ticket is printed as soon as the endpoint binds; give iroh a moment to
# settle direct-address discovery before clients connect (no-relay loopback).
sleep 3
echo "inbox ticket: ${TICKET:0:24}..."

# 2. Recipient signing identity (ML-DSA-65).
"$BIN" --gen-sign-key --mode pqc --key-dir "$W/rkeys" >/dev/null 2>&1 \
    || { echo "FAIL: gen-sign-key"; exit 1; }

# 3. Recipient init-identity: static key + 5 prekeys published + bundle out.
timeout 60 "$BIN" --prekey-cmd init-identity --transport iroh --no-relay \
    --prekey-storage "$W/prekeys.db" --node-key "$W/rnode.key" \
    --signing-privkey "$W/rkeys/private_sign_pqc.key" \
    --inbox-url "$TICKET" --prekey-output "$W/bundle.pub" --prekey-count 5 \
    || { echo "FAIL: init-identity"; exit 1; }

# 4. Sender: verify bundle, fetch a prekey, seal, deposit (strict PQ-FS).
echo "forward-secret hello over inbox" > "$W/msg.txt"
timeout 60 "$BIN" --prekey-cmd seal --transport iroh --no-relay \
    --recipient-bundle "$W/bundle.pub" --node-key "$W/snode.key" \
    --strict-pqfs "$W/msg.txt" \
    || { echo "FAIL: seal"; exit 1; }

# 5. Recipient: poll + open.
timeout 60 "$BIN" --prekey-cmd recv --transport iroh --no-relay \
    --prekey-storage "$W/prekeys.db" --node-key "$W/rnode.key" \
    --inbox-url "$TICKET" --output-file "$W/out" --strict-pqfs \
    || { echo "FAIL: recv"; exit 1; }

# 6. Verify plaintext round-trips.
if [ -f "$W/out.0" ] && diff -q "$W/out.0" "$W/msg.txt" >/dev/null; then
    echo "PASS: plaintext round-trips ($(cat "$W/out.0"))"
else
    echo "FAIL: plaintext mismatch"; ls -la "$W"; exit 1
fi
