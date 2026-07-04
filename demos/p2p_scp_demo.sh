#!/usr/bin/env bash
# Self-pacing demo of bastion-less PQC P2P *file transfer* (scp mode) with a live
# progress bar: a client uploads and downloads a 1 GiB file over the same iroh
# transport + ML-DSA-65 mutual auth as the shell, gated by a per-fingerprint
# read/write policy. The `[scp] send/recv NN% .. MiB/s` line renders only on a
# TTY (a backgrounded server never draws it), so the scp commands run directly —
# not through a pipe, which would hide it. scp is a separate server mode from
# --serve-shell (one role per process). Recorded with VHS (see p2p_scp.tape).
set -u

BIN="$PWD/target/release/nk-crypto-tool"
unset RUST_LOG NK_PASSPHRASE
ROOT=/tmp/scp
rm -rf "$ROOT"; mkdir -p "$ROOT/srv" "$ROOT/cli" "$ROOT/keys"
SRV=""
trap 'kill $SRV 2>/dev/null; rm -rf "$ROOT"' EXIT

# unencrypted demo keys (empty passphrase) so nothing prompts and no warning prints
NK_PASSPHRASE="" "$BIN" --mode pqc --gen-sign-key --key-dir "$ROOT/keys/s" --dsa-algo ML-DSA-65 >/dev/null 2>&1
NK_PASSPHRASE="" "$BIN" --mode pqc --gen-sign-key --key-dir "$ROOT/keys/c" --dsa-algo ML-DSA-65 >/dev/null 2>&1
CFP=$("$BIN" --mode pqc --fingerprint --signing-pubkey "$ROOT/keys/c/public_sign_pqc.key" 2>/dev/null \
        | grep -aoE '[0-9a-f]{64}' | head -1)

head -c 1073741824 /dev/zero > "$ROOT/cli/db-backup.tar"    # 1 GiB payload (tmpfs)
printf '%s  read="%s"  write="%s"\n' "$CFP" "$ROOT/srv" "$ROOT/srv" > "$ROOT/scp.policy"

sleep 1
echo "# Bastion-less PQC P2P file transfer (scp) with a live progress bar  —  Linux <-> Linux"
sleep 1
echo "# default-deny policy: this client's fingerprint may read+write /srv only"
sleep 0.6
echo "  ${CFP:0:24}...  read=\"srv/\"  write=\"srv/\""
sleep 1.3

echo "# start the scp server  (separate mode from --serve-shell: one role per process)"
sleep 0.7
"$BIN" --serve-scp --mode pqc \
  --signing-privkey "$ROOT/keys/s/private_sign_pqc.key" \
  --signing-pubkey  "$ROOT/keys/c/public_sign_pqc.key" \
  --scp-policy "$ROOT/scp.policy" > "$ROOT/srv.log" 2>&1 &
SRV=$!
T=""; for _ in $(seq 1 40); do T=$(grep -aoE 'nkct1[A-Z2-7]+' "$ROOT/srv.log"|head -1); [ -n "$T" ] && break; sleep 0.25; done
echo "  server up, ticket: ${T:0:44}..."
sleep 1.3

cd "$ROOT/cli"
echo "# UPLOAD   db-backup.tar (1 GiB)  -->  srv/   (scp-put, live progress bar)"
sleep 0.7
"$BIN" --scp-put db-backup.tar "$ROOT/srv/db-backup.tar" --connect "$T" --mode pqc \
  --signing-privkey "$ROOT/keys/c/private_sign_pqc.key" --signing-pubkey "$ROOT/keys/s/public_sign_pqc.key"
sleep 1.3

echo "# DOWNLOAD db-backup.tar (1 GiB) from srv/  -->  copy.tar   (scp-get, live progress bar)"
sleep 0.7
"$BIN" --scp-get "$ROOT/srv/db-backup.tar" copy.tar --connect "$T" --mode pqc \
  --signing-privkey "$ROOT/keys/c/private_sign_pqc.key" --signing-pubkey "$ROOT/keys/s/public_sign_pqc.key"
sleep 1.3

if cmp -s db-backup.tar copy.tar; then
  echo "# 1 GiB round-tripped, bytes identical — mutual ML-DSA-65 auth, no open port"
fi
sleep 3
