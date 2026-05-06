# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

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

### Deprecated
- **TCP Transport**: Legacy TCP mode (`--transport tcp`) is now deprecated and scheduled for removal.
