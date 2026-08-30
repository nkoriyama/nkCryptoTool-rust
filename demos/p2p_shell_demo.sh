#!/usr/bin/env bash
# Source me:  source demos/p2p_shell_demo.sh
#
# Sets up the bastion-less PQC P2P shell demo on ONE Linux host (the two
# endpoints talk over loopback iroh; the README's cross-arch demo shows a real
# hole-punch). Generates a server + a client ML-DSA-65 signing keypair, pins the
# client's public key on the server, starts the shell server in the background,
# and exports $TICKET / $CKEY / $SPUB for the client command. Non-interactive:
# keys use a fixed demo passphrase via NK_PASSPHRASE so nothing prompts.
set -u

BIN="$PWD/target/release/nkct"
STATE="$PWD/demos/.state"
export NK_PASSPHRASE="demo-passphrase"     # demo only — never do this for real keys
export PATH="$PWD/target/release:$PATH"

rm -rf "$STATE"; mkdir -p "$STATE/server" "$STATE/client"

# 1. keypairs (server authenticates itself; client is pinned by the server)
"$BIN" --mode pqc --gen-sign-key --key-dir "$STATE/server" --dsa-algo ML-DSA-65 >/dev/null 2>&1
"$BIN" --mode pqc --gen-sign-key --key-dir "$STATE/client" --dsa-algo ML-DSA-65 >/dev/null 2>&1

export CKEY="$STATE/client/private_sign_pqc.key"
export SPUB="$STATE/server/public_sign_pqc.key"

# 2. start the shell server, pinning the client's public key (default-deny auth)
"$BIN" --serve-shell --mode pqc \
    --signing-privkey "$STATE/server/private_sign_pqc.key" \
    --signing-pubkey  "$STATE/client/public_sign_pqc.key" \
    > "$STATE/server.log" 2>&1 &
export SRV_PID=$!

# 3. wait for the ticket to appear
TICKET=""
for _ in $(seq 1 40); do
    TICKET="$(grep -aoE 'nkct1[0-9A-Za-z]+' "$STATE/server.log" | head -1)"
    [ -n "$TICKET" ] && break
    sleep 0.25
done
export TICKET

if [ -n "$TICKET" ]; then
    printf 'server up (pid %s), client key pinned. ticket: %s...\n' "$SRV_PID" "${TICKET:0:44}"
else
    echo "server did not print a ticket; see $STATE/server.log" >&2
fi
