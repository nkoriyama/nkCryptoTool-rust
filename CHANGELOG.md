# Changelog

All notable changes to this project will be documented in this file.

## [2.0.4] - 2026-05-10

### Fixed
- **GUI handshake callback actually invoked**: The `run_connect_with_handshake_callback` API added in v2.0.3 declared the `on_handshake_done` parameter but never invoked it. Now wraps the FnOnce in `Option` and calls it after handshake completes, before `chat_loop` begins. This restores the intended UI transition: `Connect` → chat panel immediately (not after disconnect).
- **GuiStdin buffer overflow panic**: `GuiStdin::poll_read` previously called `buf.put_slice(&data)` directly, which panics when the channel-received `Vec<u8>` is larger than `buf.remaining()` (e.g. typing "hello\n" into a 1-byte read buffer). Refactored to a pending-buffer model: drain into local `VecDeque` first, then write up to `buf.remaining()` per poll. This eliminates the immediate "Connection closed by peer" disconnect on first message send.

### Phase 3 Status
- v2.0.4 marks Phase 3 as **build-verified + E2E-verified**: GUI builds, runs, and successfully exchanges messages bidirectionally over Iroh PQC chat. Self-loopback test (CLI listener + GUI connector) confirms full round-trip messaging.

## [2.0.3] - 2026-05-10

### Added
- **`run_connect_with_handshake_callback` API**: Extended `NetworkProcessor` with a callback parameter intended to fire after handshake but before `chat_loop` blocks, to enable GUI state transition. (Note: the callback was not actually invoked in v2.0.3; this was fixed in v2.0.4.)

### Fixed
- **CHAT_ACTIVE flag reset on session end**: The session-active flag is now explicitly reset on chat_loop completion (both Ok and Err paths), preventing "Chat session already active" errors on reconnect attempts after abnormal disconnects.

## [2.0.2] - 2026-05-10

### Fixed
- **Slint Property Bugs**: Corrected property modifiers in \`chat.slint\` from \`in\` to \`in-out\` for properties modified by internal UI logic (buttons, accepted handlers).
- **Thread Safety**: Refactored GUI background tasks to avoid capturing \`!Send\` Slint handles across \`.await\` points.
- **Error Mapping**: Fixed boxed error mapping in \`main.rs\` to satisfy \`anyhow\` bounds.
- **M2 Implementation Fixes**: Resolved various compilation errors in camera and QR scanning logic (incorrect method names, missing casts, missing features).

### Added
- **Testing Feature**: Added \`testing\` feature to expose library mocks for integration tests.

## [2.0.1] - 2026-05-09

### Fixed
- **M5 test coverage completion**: Added missing tests for Linux no-op and unsupported OS warnings.

### Documentation
- **SECURITY_PROFILE_GUI restoration**: Restored §1.5 (M2 QR threats) and §1.6 (M4 notification threats).

## [2.0.0] - 2026-05-09

### Added
- **Phase 3 GUI Completion**: Final stabilization of the Slint-based graphical user interface.
- **Privacy Mode (M5)**: Integrated screen capture prevention for Windows and macOS.
- **Unified GUI Binary**: The application now supports a full-featured graphical mode via the \`--gui\` flag.

### Changed
- **Major Version Upgrade**: Transitioned to v2.x to mark official GUI support.

## [1.0.0] - [1.4.1]
(See git history for older entries)
