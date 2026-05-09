# Known Issues (v1.0.0)

Despite reaching v1.0.0, the following security and usability issues are known and scheduled for future resolution.

## Security Issues

### 1. Write-then-Verify window (37-1)
During file decryption, data is written to a temporary file before the final authentication tag is verified.
- **Mitigation**: Temporary files are created with `0600` permissions and random suffixes in the destination directory. They are deleted immediately if verification fails.
- **Root Fix**: Planned transition to full memory buffering or streaming AEAD verification.

### 2. HKDF Zeroization Feature (36-3)
The `hkdf` crate's `zeroize` feature is currently not enabled in `Cargo.toml`.
- **Risk**: Low (intermediate KDF states might remain in memory briefly).
- **Root Fix**: Enable `zeroize` feature in `Cargo.toml`.

### 4. ML-KEM Seed Internal Copy (37-2)
The underlying `fips203` library may perform internal copies of sensitive seeds that are outside the control of `nkCryptoTool`.
- **Status**: Blocked by upstream library updates.

## Usability Issues

### 1. Stdin/Stdout only File Transfer
Iroh file transfer currently only supports redirection via stdin/stdout. Direct file path arguments for network transfer are not yet implemented.
