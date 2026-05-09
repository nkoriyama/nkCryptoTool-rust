# Changelog

All notable changes to this project will be documented in this file.

## [1.1.0] - 2026-05-09

### Security
- **Two-pass decryption (closes 37-1)**: Decryption now verifies the
  AEAD tag in a dedicated read-only pass before any plaintext is
  written to disk. Eliminates the unverified-plaintext-on-disk window.
- **`aes-gcm` zeroize feature (partial 36-3 mitigation)**: Internal
  symmetric key material is now cleared from memory on drop. Note that
  `hkdf` itself remains Blocked — see KNOWN_ISSUES.md and
  THREAT_36-3_INVESTIGATION_REPORT.md.
- **`unwrap_pqc_priv_from_pkcs8` zeroize fix (closes 37-5)**: The
  `best_sk` candidate buffer in PKCS#8 scanning is now wrapped in
  `Zeroizing` and explicitly zeroized before each reassignment.

### Added
- **Slint GUI prototype (`--gui` flag, optional `gui` feature)**:
  Initial PoC with `GuiIOProvider` bridge to `chat_loop`. Fonts/system
  dependencies still required for full build (see PHASE2_GUI_PROTOTYPE_REPORT.md).

### Changed
- **`CryptoStrategy::restart_decryption()`**: New trait method to reset
  AEAD context for the Two-pass decryption flow.

### Documentation
- `KNOWN_ISSUES.md`: Removed 37-1 (closed). 36-3 marked as Blocked with
  ecosystem rationale. 37-2 remains Blocked (upstream `fips203`).
- `SECURITY_PROFILE.md`: Documented Two-pass decryption invariant.

## [1.0.0] - 2026-05-09

### Added
- **Iroh P2P Transport**: Migrated network mode from TCP to Iroh for automatic NAT traversal and relay fallback.
- **Connection Tickets (NKCT1)**: Introduced a shareable Base32 ticket format containing connection info and PQC fingerprints.
- **MITM Protection**: Implemented real-time verification of peer public keys against fingerprints in tickets.
- **V3 Handshake Protocol**: Enhanced handshake with public key transmission to support multi-client authentication and channel binding.
- **ALPN Separation**: Dedicated ALPNs for chat (`nkct/chat/1`) and file transfer (`nkct/file/1`).
- **QR Code Support**: Added terminal-based ASCII QR code display for connection tickets.
- **CLI Aliases**: Added `--my-sign-key` and `--my-enc-key` for improved usability.
- **Serial Testing**: Integrated `serial_test` for reliable sequential E2E transport verification.

### Changed
- **Default Transport**: Iroh is now the default transport mode.
- **Authentication**: Fingerprint verification and multi-client auth are now standard in Iroh mode.
- **CLI Robustness**: Fixed authentication logic regressions and enhanced endpoint closing reliability.

### Deprecated
- **TCP Transport**: Legacy TCP mode (`--transport tcp`) is now deprecated and scheduled for removal.
