/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

#[cfg(feature = "gui")]
use crate::error::Result;
#[cfg(feature = "gui")]
use std::sync::{Arc, Mutex};

#[cfg(feature = "gui")]
pub trait ScreenProtectionApi: Send + Sync {
    fn set_protection(&self, window: &slint::Window, enabled: bool) -> Result<()>;
    fn is_supported(&self) -> bool;
    fn get_warning_message(&self) -> Option<String>;
}

pub struct OsScreenProtectionApi;

#[cfg(all(feature = "gui-screen-protection", target_os = "windows"))]
impl ScreenProtectionApi for OsScreenProtectionApi {
    fn set_protection(&self, window: &slint::Window, enabled: bool) -> Result<()> {
        use windows::Win32::UI::WindowsAndMessaging::{SetWindowDisplayAffinity, WDA_EXCLUDEFROMCAPTURE, WDA_NONE};
        use windows::Win32::Foundation::HWND;
        
        // v1.16 Window::window_handle() exists?
        // Slint 1.16 window handle acquisition:
        // We might need to use the backend-specific handle.
        
        /* Note for Step 4.1: Implementation uses Slint internal handle if available */
        // For PoC/M5, we assume HWND acquisition is possible.
        
        let affinity = if enabled { WDA_EXCLUDEFROMCAPTURE } else { WDA_NONE };
        
        // This is a placeholder for actual handle acquisition in Slint 1.16
        // slint::Window::native_handle() or similar.
        // If Slint 1.16 doesn't expose HWND easily, this part requires backend access.
        Ok(())
    }

    fn is_supported(&self) -> bool {
        // Windows 10 2004+ check
        true 
    }

    fn get_warning_message(&self) -> Option<String> {
        None
    }
}

#[cfg(all(feature = "gui-screen-protection", target_os = "macos"))]
impl ScreenProtectionApi for OsScreenProtectionApi {
    fn set_protection(&self, window: &slint::Window, enabled: bool) -> Result<()> {
        // macOS NSWindow sharingType = NSWindowSharingNone
        Ok(())
    }

    fn is_supported(&self) -> bool {
        true
    }

    fn get_warning_message(&self) -> Option<String> {
        None
    }
}

#[cfg(any(not(feature = "gui-screen-protection"), target_os = "linux"))]
impl ScreenProtectionApi for OsScreenProtectionApi {
    fn set_protection(&self, _window: &slint::Window, _enabled: bool) -> Result<()> {
        Ok(())
    }

    fn is_supported(&self) -> bool {
        false
    }

    fn get_warning_message(&self) -> Option<String> {
        #[cfg(target_os = "linux")]
        {
            Some("Privacy mode relies on xdg-desktop-portal / Wayland security protocols.".to_string())
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }
}

#[cfg(test)]
pub struct MockScreenProtectionApi {
    pub state: Arc<Mutex<bool>>,
}

#[cfg(feature = "gui")]
#[cfg(test)]
impl ScreenProtectionApi for MockScreenProtectionApi {
    fn set_protection(&self, _window: &slint::Window, enabled: bool) -> Result<()> {
        let mut lock = self.state.lock().unwrap();
        *lock = enabled;
        Ok(())
    }
    fn is_supported(&self) -> bool { true }
    fn get_warning_message(&self) -> Option<String> { None }
}
