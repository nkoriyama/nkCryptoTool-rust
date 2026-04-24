#!/bin/bash
set -e

EXE="./target/debug/nk-crypto-tool"

# Clean up
rm -rf pqc_keys
mkdir pqc_keys

echo "1. Generating PQC encryption keys..."
$EXE --mode pqc --gen-enc-key --key-dir pqc_keys

echo "2. Creating a test file..."
echo "Hello from Rust PQC nkCryptoTool!" > test_input_pqc.txt

echo "3. Encrypting the test file..."
$EXE --mode pqc --encrypt --recipient-pubkey pqc_keys/public_enc_pqc.key --output test_encrypted_pqc.bin test_input_pqc.txt

echo "4. Decrypting the test file..."
$EXE --mode pqc --decrypt --user-privkey pqc_keys/private_enc_pqc.key --output test_decrypted_pqc.txt test_encrypted_pqc.bin

echo "5. Verifying the result..."
diff test_input_pqc.txt test_decrypted_pqc.txt
echo "Verification successful!"

# Clean up
# rm test_input_pqc.txt test_encrypted_pqc.bin test_decrypted_pqc.txt
