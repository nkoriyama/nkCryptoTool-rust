# Changelog

All notable changes to this project will be documented in this file.

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
