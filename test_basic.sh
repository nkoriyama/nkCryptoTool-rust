#!/bin/bash
set -e

EXE="./target/debug/nk-crypto-tool"

# Clean up
rm -rf test_keys
mkdir test_keys

echo "1. Generating ECC encryption keys..."
$EXE --mode ecc --gen-enc-key --key-dir test_keys --passphrase "testpass"

echo "2. Creating a test file..."
echo "Hello from Rust nkCryptoTool!" > test_input.txt

echo "3. Encrypting the test file..."
$EXE --mode ecc --encrypt --recipient-pubkey test_keys/public_enc_ecc.key --output test_encrypted.bin test_input.txt

echo "4. Decrypting the test file..."
$EXE --mode ecc --decrypt --user-privkey test_keys/private_enc_ecc.key --passphrase "testpass" --output test_decrypted.txt test_encrypted.bin

echo "5. Verifying the result..."
diff test_input.txt test_decrypted.txt
echo "Verification successful!"

# Clean up
# rm test_input.txt test_encrypted.bin test_decrypted.txt
