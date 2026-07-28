/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

//! Screen-capture exclusion ("Privacy Mode") for the desktop GUI.
//!
//! **No platform is implemented yet.** Every `set_protection` below reports
//! that honestly instead of returning `Ok(())`.
//!
//! It used to return `Ok(())` everywhere while calling no OS API at all, and
//! the Windows/macOS impls additionally claimed `is_supported() == true` and
//! offered no warning — so a user who enabled Privacy Mode before showing chat
//! plaintext, a ticket or key paths saw a switch that said "on" over a window
//! that was still fully capturable by any screen-share, screenshot tool or
//! recorder. A security control that silently does nothing is worse than an
//! absent one, because it is relied upon.
//!
//! Implementing it means acquiring the native window handle through slint's
//! raw-window-handle and calling `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)`
//! on Windows, or setting `NSWindow.sharingType = NSWindowSharingNone` on macOS.
//! On Linux there is no equivalent for an ordinary client — exclusion is the
//! compositor's decision, mediated by xdg-desktop-portal.

#[cfg(feature = "gui")]
use crate::error::Result;
#[cfg(all(feature = "gui", any(test, feature = "testing")))]
use std::sync::{Arc, Mutex};

#[cfg(feature = "gui")]
pub trait ScreenProtectionApi: Send + Sync {
    /// Apply or clear capture exclusion.
    ///
    /// Returns `Err` when the platform cannot honour the request. Callers MUST
    /// surface that rather than discarding it: the whole point of the control
    /// is that the user knows whether it took effect.
    fn set_protection(&self, window: &slint::Window, enabled: bool) -> Result<()>;
    /// Whether `set_protection` can actually exclude this window from capture.
    /// Must be `false` wherever the OS call is not implemented.
    fn is_supported(&self) -> bool;
    /// Why protection is unavailable, for display next to the control.
    fn get_warning_message(&self) -> Option<String>;
}

pub struct OsScreenProtectionApi;

/// The error every unimplemented platform returns, so the wording (and the
/// fact that it *is* an error) cannot drift between them.
#[cfg(feature = "gui")]
fn unsupported(detail: &str) -> crate::error::CryptoError {
    crate::error::CryptoError::Parameter(format!(
        "screen-capture protection is not implemented on this platform: {detail}"
    ))
}

#[cfg(all(feature = "gui-screen-protection", target_os = "windows"))]
impl ScreenProtectionApi for OsScreenProtectionApi {
    fn set_protection(&self, _window: &slint::Window, _enabled: bool) -> Result<()> {
        // Needs the HWND via slint's raw-window-handle, then
        // SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE | WDA_NONE).
        Err(unsupported(
            "SetWindowDisplayAffinity is not wired up (Windows)",
        ))
    }

    fn is_supported(&self) -> bool {
        false
    }

    fn get_warning_message(&self) -> Option<String> {
        Some(
            "Privacy mode is not implemented on Windows yet — this window is NOT excluded \
             from screenshots or screen sharing."
                .to_string(),
        )
    }
}

#[cfg(all(feature = "gui-screen-protection", target_os = "macos"))]
impl ScreenProtectionApi for OsScreenProtectionApi {
    fn set_protection(&self, _window: &slint::Window, _enabled: bool) -> Result<()> {
        // Needs the NSWindow via slint's raw-window-handle, then
        // sharingType = NSWindowSharingNone.
        Err(unsupported(
            "NSWindow.sharingType is not wired up (macOS)",
        ))
    }

    fn is_supported(&self) -> bool {
        false
    }

    fn get_warning_message(&self) -> Option<String> {
        Some(
            "Privacy mode is not implemented on macOS yet — this window is NOT excluded \
             from screenshots or screen sharing."
                .to_string(),
        )
    }
}

// The fallback impl requires ScreenProtectionApi trait + slint::Window type,
// both of which only exist under the `gui` feature. Gate accordingly so the
// lib still compiles without `gui` (CLI-only build via backend-rustcrypto etc.).
#[cfg(all(feature = "gui", any(not(feature = "gui-screen-protection"), target_os = "linux")))]
impl ScreenProtectionApi for OsScreenProtectionApi {
    fn set_protection(&self, _window: &slint::Window, _enabled: bool) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            Err(unsupported(
                "capture exclusion is the compositor's decision; there is no client-side \
                 equivalent on X11/Wayland (Linux)",
            ))
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(unsupported("build without the gui-screen-protection feature"))
        }
    }

    fn is_supported(&self) -> bool {
        false
    }

    fn get_warning_message(&self) -> Option<String> {
        #[cfg(target_os = "linux")]
        {
            Some(
                "Privacy mode is not available on Linux — capture exclusion would have to come \
                 from the compositor (xdg-desktop-portal / Wayland security protocols). This \
                 window is NOT excluded from screenshots or screen sharing."
                    .to_string(),
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            Some(
                "Privacy mode is unavailable: this build does not include the \
                 gui-screen-protection feature. This window is NOT excluded from screenshots \
                 or screen sharing."
                    .to_string(),
            )
        }
    }
}

#[cfg(all(feature = "gui", any(test, feature = "testing")))]
pub struct MockScreenProtectionApi {
    pub state: Arc<Mutex<bool>>,
}

#[cfg(feature = "gui")]
#[cfg(any(test, feature = "testing"))]
impl ScreenProtectionApi for MockScreenProtectionApi {
    fn set_protection(&self, _window: &slint::Window, enabled: bool) -> Result<()> {
        let mut lock = self.state.lock().unwrap();
        *lock = enabled;
        Ok(())
    }
    fn is_supported(&self) -> bool { true }
    fn get_warning_message(&self) -> Option<String> { None }
}
