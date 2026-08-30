#!/usr/bin/env bash
# Self-pacing demo of bastion-less P2P interop between the C++ and the Rust
# nkCryptoTool, over one iroh transport + the V3.1 ML-DSA-65 mutual-auth
# handshake. Every role is exercised C++ <-> Rust, both directions:
#
#   scp      C++ client  --scp-get     <-  Rust server --serve-scp
#   shell    C++ client  --shell-cmd   ->  Rust server --serve-shell
#            Rust client --shell-cmd   ->  C++  server --serve-shell
#   pairing  C++ client  --copy-bundle ->  Rust server --serve-pairing
#            Rust client --copy-bundle ->  C++  server --serve-pairing
#
# The C++ binary must be built with both features:
#   cmake -B build-both -DUSE_BACKEND=OpenSSL -DNKCT_ENABLE_P2P=ON -DNKCT_ENABLE_KEYRING=ON
# Recorded with VHS (see p2p_cpp_rust_interop.tape).
set -u

RUST="$PWD/target/release/nkct"
CPP="$PWD/../nkCryptoTool/build-both/nkCryptoTool"
unset RUST_LOG NK_PASSPHRASE
ROOT=$(mktemp -d "${TMPDIR:-/tmp}/nkct-xrole-demo.XXXXXX") || exit 1
mkdir -p "$ROOT"/{srv,cli,rdb,cdb} "$ROOT"/keys/{s,c}
SRV=""
trap 'kill $SRV 2>/dev/null; rm -rf "$ROOT"' EXIT

if [ ! -x "$CPP" ]; then
  echo "# C++ binary not found at $CPP — build it with:"
  echo "#   cmake -B build-both -DUSE_BACKEND=OpenSSL -DNKCT_ENABLE_P2P=ON -DNKCT_ENABLE_KEYRING=ON && cmake --build build-both"
  exit 1
fi

grab_ticket(){ local f=$1 t=""; for _ in $(seq 1 60); do t=$(grep -aoE 'nkct1[A-Z2-7]+' "$f"|head -1); [ -n "$t" ] && { echo "$t"; return; }; sleep 0.2; done; }
grab_otp(){ grep -aoE '[A-Z2-7]{8}' "$1" | head -1; }

# Identities: Rust node = keys/s, C++ node = keys/c. Each gets a sign + enc key.
NK_PASSPHRASE="" "$RUST" --mode pqc --gen-sign-key --key-dir "$ROOT/keys/s" --dsa-algo ML-DSA-65 >/dev/null 2>&1
NK_PASSPHRASE="" "$RUST" --mode pqc --gen-enc-key  --key-dir "$ROOT/keys/s"                        >/dev/null 2>&1
NK_PASSPHRASE="" "$CPP"  --gen-sign-key --mode pqc --key-dir "$ROOT/keys/c"                        >/dev/null 2>&1
NK_PASSPHRASE="" "$CPP"  --gen-enc-key  --mode pqc --key-dir "$ROOT/keys/c"                        >/dev/null 2>&1
SFP=$("$RUST" --mode pqc --fingerprint --signing-pubkey "$ROOT/keys/s/public_sign_pqc.key" 2>/dev/null | grep -aoE '[0-9a-f]{64}' | head -1)
CFP=$("$RUST" --mode pqc --fingerprint --signing-pubkey "$ROOT/keys/c/public_sign_pqc.key" 2>/dev/null | grep -aoE '[0-9a-f]{64}' | head -1)

sleep 1
echo "#  nkCryptoTool  C++  <->  Rust   —  every P2P role, both directions"
sleep 0.7
echo "#  one iroh transport, V3.1 handshake: P-256 + ML-KEM-768 + ML-DSA-65 mutual auth"
sleep 1.4
echo

# ===== scp: C++ client <- Rust server =====================================
echo "===  scp    C++ --scp-get   <-   Rust --serve-scp  ==========================="
sleep 0.7
printf 'quarterly numbers — served by the RUST node\n' > "$ROOT/srv/report.txt"
head -c 8388608 /dev/urandom >> "$ROOT/srv/report.txt"
printf '%s  read="%s"  write="%s"\n' "$CFP" "$ROOT/srv" "$ROOT/srv" > "$ROOT/scp.policy"
"$RUST" --serve-scp --mode pqc --no-relay --signing-privkey "$ROOT/keys/s/private_sign_pqc.key" \
  --signing-pubkey "$ROOT/keys/c/public_sign_pqc.key" --scp-policy "$ROOT/scp.policy" > "$ROOT/l1" 2>&1 &
SRV=$!; T=$(grab_ticket "$ROOT/l1")
echo "   rust scp server up"
sleep 0.5
( cd "$ROOT/cli" && NK_PASSPHRASE="" "$CPP" --connect "$T" --scp-get "$ROOT/srv/report.txt" --scp-local got.txt \
    --mode pqc --signing-privkey "$ROOT/keys/c/private_sign_pqc.key" --signing-pubkey "$ROOT/keys/s/public_sign_pqc.key" 2>&1 ) \
  | grep -aE 'authenticated|downloaded'
cmp -s "$ROOT/srv/report.txt" "$ROOT/cli/got.txt" && echo "   OK  8 MiB pulled, bytes identical"
kill $SRV 2>/dev/null; SRV=""; sleep 1.4; echo

# ===== shell: C++ client -> Rust server ===================================
echo "===  shell   C++ --shell-cmd   ->   Rust --serve-shell  ======================"
sleep 0.7
"$RUST" --serve-shell --mode pqc --no-relay --signing-privkey "$ROOT/keys/s/private_sign_pqc.key" \
  --signing-pubkey "$ROOT/keys/c/public_sign_pqc.key" > "$ROOT/l2" 2>&1 &
SRV=$!; T=$(grab_ticket "$ROOT/l2")
echo "   rust shell server up  —  C++ runs: uname -sr; id -un"
sleep 0.5
NK_PASSPHRASE="" "$CPP" --connect "$T" --shell-cmd 'echo "[remote:rust] $(uname -sr)  user=$(id -un)"' \
  --mode pqc --signing-privkey "$ROOT/keys/c/private_sign_pqc.key" --signing-pubkey "$ROOT/keys/s/public_sign_pqc.key" 2>/dev/null
kill $SRV 2>/dev/null; SRV=""; sleep 1.2; echo

# ===== shell: Rust client -> C++ server ===================================
echo "===  shell   Rust --shell-cmd  ->   C++  --serve-shell  ======================"
sleep 0.7
NK_PASSPHRASE="" "$CPP" --serve-shell --mode pqc --signing-privkey "$ROOT/keys/c/private_sign_pqc.key" \
  --signing-pubkey "$ROOT/keys/s/public_sign_pqc.key" > "$ROOT/l3" 2>&1 &
SRV=$!; T=$(grab_ticket "$ROOT/l3")
echo "   C++ PTY shell server up  —  Rust runs: uname -sr; id -un"
sleep 0.5
NK_PASSPHRASE="" "$RUST" --shell --shell-cmd 'echo "[remote:c++] $(uname -sr)  user=$(id -un)"' --connect "$T" \
  --no-relay --mode pqc --signing-privkey "$ROOT/keys/s/private_sign_pqc.key" \
  --signing-pubkey "$ROOT/keys/c/public_sign_pqc.key" < /dev/null 2>/dev/null
kill $SRV 2>/dev/null; SRV=""; sleep 1.2; echo

# ===== shell INTERACTIVE: a live session over the C++ PTY server ===========
echo "===  shell (interactive)   Rust --shell   ->   C++ --serve-shell (/bin/sh)  ==="
sleep 0.7
SHELL=/bin/sh NK_PASSPHRASE="" "$CPP" --serve-shell --mode pqc \
  --signing-privkey "$ROOT/keys/c/private_sign_pqc.key" \
  --signing-pubkey "$ROOT/keys/s/public_sign_pqc.key" > "$ROOT/l3b" 2>&1 &
SRV=$!; T=$(grab_ticket "$ROOT/l3b")
echo "   C++ PTY shell server up  —  a live sh session (type, run, exit):"
sleep 0.6
# Drive a real interactive shell: each line runs and its result comes back,
# then `exit` ends the session. The sh prompt/results render as a live terminal.
{ sleep 1.0; printf 'whoami\n';            sleep 0.9; \
  printf 'echo sum=$((7*6))\n';            sleep 0.9; \
  printf 'uname -sr\n';                    sleep 0.9; \
  printf 'exit\n';                         sleep 0.6; } | \
  timeout -s KILL 15 "$RUST" --shell --connect "$T" --no-relay --mode pqc \
    --signing-privkey "$ROOT/keys/s/private_sign_pqc.key" \
    --signing-pubkey "$ROOT/keys/c/public_sign_pqc.key" 2>/dev/null
kill $SRV 2>/dev/null; SRV=""; sleep 1.4; echo

# ===== pairing: C++ client -> Rust server =================================
echo "===  pairing  C++ --copy-bundle  ->  Rust --serve-pairing  ==================="
sleep 0.7
"$RUST" --serve-pairing --pairing-grant all --key-dir "$ROOT/keys/s" --keyring-db "$ROOT/rdb/keyring.db" \
  --mode pqc --no-relay --signing-privkey "$ROOT/keys/s/private_sign_pqc.key" > "$ROOT/l4" 2>&1 &
SRV=$!; T=$(grab_ticket "$ROOT/l4"); OTP=$(grab_otp "$ROOT/l4")
echo "   rust pairing server up, one-time token $OTP"
sleep 0.5
NK_PASSPHRASE="" "$CPP" --copy-bundle --connect "$T" --token "$OTP" --keybundle-handle cpp-laptop \
  --mode pqc --signing-privkey "$ROOT/keys/c/private_sign_pqc.key" --signing-pubkey "$ROOT/keys/s/public_sign_pqc.key" \
  --key-dir "$ROOT/keys/c" 2>/dev/null | grep -aE 'PASS'
kill $SRV 2>/dev/null; SRV=""
echo -n "   rust keyring now lists:  "; "$RUST" --keyring-cmd list --keyring-db "$ROOT/rdb/keyring.db" 2>/dev/null | awk '{print $2}' | paste -sd' '
sleep 1.4; echo

# ===== pairing: Rust client -> C++ server =================================
echo "===  pairing  Rust --copy-bundle ->  C++  --serve-pairing  ==================="
sleep 0.7
NK_PASSPHRASE="" "$CPP" --serve-pairing --pairing-grant all --keyring-db "$ROOT/cdb/keyring.db" \
  --mode pqc --signing-privkey "$ROOT/keys/c/private_sign_pqc.key" --key-dir "$ROOT/keys/c" > "$ROOT/l5" 2>&1 &
SRV=$!; T=$(grab_ticket "$ROOT/l5")
OTP=$(grep -aoE 'token \(valid 5 min\): [A-Z2-7]{8}' "$ROOT/l5" | grep -aoE '[A-Z2-7]{8}$' | head -1)
echo "   C++ pairing server up, one-time token $OTP"
sleep 0.5
printf '%s' "$OTP" | NK_PASSPHRASE="" "$RUST" --copy-bundle --connect "$T" --token - --keybundle-handle rust-laptop \
  --no-relay --mode pqc --signing-privkey "$ROOT/keys/s/private_sign_pqc.key" --key-dir "$ROOT/keys/s" 2>/dev/null | grep -aE 'registered'
kill $SRV 2>/dev/null; SRV=""
echo -n "   c++ keyring.db now lists: "; "$RUST" --keyring-cmd list --keyring-db "$ROOT/cdb/keyring.db" 2>/dev/null | awk '{print $2}' | paste -sd' '
sleep 1.6; echo

echo "===  C++ <-> Rust P2P interop  —  every role, both directions  [ OK ]  ======="
sleep 0.5
echo "     scp   pull        shell   both ways        pairing   both ways"
sleep 0.5
echo "     one iroh transport · P-256 + ML-KEM-768 · ML-DSA-65 mutual auth · no open port"
sleep 3
