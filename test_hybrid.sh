#!/bin/bash
set -e

EXE="./target/debug/nk-crypto-tool"

# Clean up
rm -rf hybrid_keys
mkdir hybrid_keys

echo "1. Generating Hybrid encryption keys..."
NK_PASSPHRASE="testpass" $EXE --mode hybrid --gen-enc-key --key-dir hybrid_keys

echo "2. Creating a test file..."
echo "Hello from Rust Hybrid nkCryptoTool!" > test_input_hybrid.txt

echo "3. Encrypting the test file..."
$EXE --mode hybrid --encrypt \
    --recipient-mlkem-pubkey hybrid_keys/public_enc_hybrid_mlkem.key \
    --recipient-ecdh-pubkey hybrid_keys/public_enc_hybrid_ecdh.key \
    --output-file test_encrypted_hybrid.bin test_input_hybrid.txt

echo "4. Decrypting the test file..."
NK_PASSPHRASE="testpass" $EXE --mode hybrid --decrypt \
    --user-mlkem-privkey hybrid_keys/private_enc_hybrid_mlkem.key \
    --user-ecdh-privkey hybrid_keys/private_enc_hybrid_ecdh.key \
    --output-file test_decrypted_hybrid.txt test_encrypted_hybrid.bin

echo "5. Verifying the result..."
diff test_input_hybrid.txt test_decrypted_hybrid.txt
echo "Verification successful!"

# Clean up
# rm test_input_hybrid.txt test_encrypted_hybrid.bin test_decrypted_hybrid.txt
