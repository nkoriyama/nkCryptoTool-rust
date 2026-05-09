# Changelog

All notable changes to this project will be documented in this file.

## [2.0.1] - 2026-05-09

### Fixed
- **M5 test coverage completion**: v2.0.0 shipped with 3/5 of the M5 test suite. v2.0.1 adds the missing 2 tests: `test_privacy_mode_noop_on_linux` and `test_privacy_mode_unsupported_os_warning`.

### Documentation
- **SECURITY_PROFILE_GUI restoration**: Restored §1.5 (M2 QR threats) and §1.6 (M4 notification threats) sections that were inadvertently lost during v2.0.0 file rewrite.

## [2.0.0] - 2026-05-09

### Added
- **Phase 3 GUI Completion**: Final stabilization of the Slint-based graphical user interface.
- **Privacy Mode (M5)**: Integrated screen capture prevention for Windows and macOS. Prevents sensitive chat content from appearing in screenshots, screen recordings, and window sharing.
- **Unified GUI Binary**: The application now supports a full-featured graphical mode via the `--gui` flag, including secure passphrase entry (M1), QR ticket scanning (M2), clipboard protection (M3), and desktop notifications (M4).

### Changed
- **Major Version Upgrade**: Transitioned from v1.x to v2.0.0 to mark the official support of the Graphical User Interface as a primary feature.


## [1.4.1] - 2026-05-09

### Fixed
- **M4 test coverage completion**: v1.4.0 shipped with 2/5 of the M4 test suite (basic privacy + focus suppression). v1.4.1 adds the missing 3 tests: `test_notification_rate_limited_in_burst`, `test_notification_click_brings_window_to_front`, and `test_placeholder_check_notifications`.
- **KNOWN_ISSUES.md cleanup**: Removed the stale M4 (Desktop Notifications) entry that was inadvertently left in v1.4.0.

## [1.4.0] - 2026-05-09

### Added
- **Desktop Notifications (M4)**: Integrated OS-level notifications for new messages using `notify-rust`. Includes content-free privacy policy (generic bodies) and leading-edge rate limiting.

## [1.3.1] - 2026-05-09

### Fixed
- **M2 camera integration completion**: v1.3.0 shipped scaffolding only
  (CameraSource trait, NokhwaCameraSource impl, UI state transitions,
  but the button handler contained a placeholder comment in place of
  the actual camera thread launch). v1.3.1 wires up the full flow:
  button press → NokhwaCameraSource::start_scan → rqrr decode →
  Ticket::from_str → UI inject. Includes proper 30-second timeout,
  cancel handling, and error UX per PHASE3_M2_DESIGN_PROPOSAL.md v2 §3.2.

## [1.3.0] - 2026-05-09

### Added
- **QR Code Scan Input (M2 scaffolding)**: Initial integration of
  camera-based NKCT1 ticket reading using nokhwa and rqrr. Includes
  CameraSource trait abstraction, NokhwaCameraSource and MockCameraSource
  implementations, Slint UI for scanning state transitions, and Wayland
  Portal permission considerations.
  Note: v1.3.0 shipped scaffolding only; full functional integration
  arrived in v1.3.1.

## [1.2.0] - 2026-05-09

### Added
- **Secure Passphrase Dialog (M1)**: Implemented a password-type input field for encrypted private keys, preventing shoulder surfing and ensuring plaintext does not reside in UI properties after use.
- **Clipboard Protection (M3)**: Added automatic 30-second clear timer for sensitive information copied to the clipboard (e.g., connection tickets).
- **GUI CI Integration (M6)**: Configured GitHub Actions to verify `gui` feature builds and automated UI testing.

### Fixed
- **M3 stdout leak**: Removed sensitive `println!` logs from the clipboard handler to ensure no confidential data is recorded in process logs.

### Security
- **Passphrase copy prevention**: Explicitly documented and configured passphrase fields to prevent clipboard copy operations.

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
