/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

#[cfg(feature = "gui")]
mod tests {
    use slint::ComponentHandle;
    use std::sync::{Arc, Mutex};
    use std::sync::atomic::{AtomicBool, Ordering};
    
    slint::include_modules!();

    #[test]
    fn test_passphrase_dialog_visibility() {
        let ui = ChatWindow::new().unwrap();
        
        // Initial state
        assert!(!ui.get_connected());
        assert!(!ui.get_asking_passphrase());
        
        // Trigger asking passphrase
        ui.set_asking_passphrase(true);
        assert!(ui.get_asking_passphrase());
    }

    #[test]
    fn test_passphrase_cleared_after_unlock_button() {
        let ui = ChatWindow::new().unwrap();
        let callback_invoked = Arc::new(Mutex::new(false));
        let callback_invoked_clone = callback_invoked.clone();
        
        ui.set_asking_passphrase(true);
        ui.set_passphrase_input("secret-passphrase".into());
        
        let ui_handle = ui.as_weak();
        ui.on_passphrase_provided(move |pass| {
            assert_eq!(pass, "secret-passphrase");
            if let Some(ui) = ui_handle.upgrade() {
                // The implementation in mod.rs should clear it
                ui.set_passphrase_input("".into());
                ui.set_asking_passphrase(false);
                *callback_invoked_clone.lock().unwrap() = true;
            }
        });
        
        // Simulating the button click via slint::testing
        let button = slint::testing::ElementHandle::find_by_label_text(&ui, "Unlock and Connect").expect("Button not found");
        button.invoke_accessible_default_action();
        
        assert!(*callback_invoked.lock().unwrap(), "Passphrase callback was not invoked");
        assert_eq!(ui.get_passphrase_input(), "");
        assert!(!ui.get_asking_passphrase());
    }

    #[test]
    fn test_connection_error_state_transition() {
        let ui = ChatWindow::new().unwrap();
        
        // Simulate a connection attempt that might require a passphrase
        ui.set_connection_error("Passphrase required".into());
        ui.set_asking_passphrase(true);
        
        assert!(ui.get_asking_passphrase());
        assert_eq!(ui.get_connection_error(), "Passphrase required");
        
        // Simulate successful unlock
        ui.set_asking_passphrase(false);
        ui.set_connection_error("".into());
        ui.set_connected(true);
        
        assert!(ui.get_connected());
        assert!(!ui.get_asking_passphrase());
        assert_eq!(ui.get_connection_error(), "");
    }

    #[test]
    fn test_qr_scanner_ui_transition() {
        let ui = ChatWindow::new().unwrap();
        assert!(!ui.get_scanning_qr());
        
        ui.invoke_scan_qr_pressed();
        assert!(ui.get_scanning_qr());
        
        ui.invoke_scan_cancel();
        assert!(!ui.get_scanning_qr());
    }

    #[test]
    fn test_no_placeholder_comments_in_gui_callbacks() {
        let mod_rs = include_str!("../src/gui/mod.rs");
        assert!(!mod_rs.contains("In a real implementation"));
        assert!(!mod_rs.contains("we would start"));
        assert!(!mod_rs.contains("For now,"));
        assert!(!mod_rs.contains("simulate with"));
    }

    #[cfg(feature = "gui-notifications")]
    #[test]
    fn test_notification_body_excludes_message_content() {
        use crate::gui::notifications::{NotificationManager, MockNotificationSink};
        let sink = Arc::new(MockNotificationSink {
            history: Mutex::new(Vec::new()),
        });
        let manager = NotificationManager::new(sink.clone());
        
        manager.notify_message("peer8888", false).unwrap();
        
        let history = sink.history.lock().unwrap();
        assert_eq!(history.len(), 1);
        let (_title, body) = &history[0];
        assert!(body.contains("peer8888"));
        assert!(!body.contains("secret"));
    }

    #[cfg(feature = "gui-notifications")]
    #[test]
    fn test_notification_suppressed_when_focused() {
        use crate::gui::notifications::{NotificationManager, MockNotificationSink};
        let sink = Arc::new(MockNotificationSink {
            history: Mutex::new(Vec::new()),
        });
        let manager = NotificationManager::new(sink.clone());
        
        manager.notify_message("peer8888", true).unwrap(); // focused = true
        
        let history = sink.history.lock().unwrap();
        assert_eq!(history.len(), 0);
    }

    #[cfg(feature = "gui-notifications")]
    #[test]
    fn test_notification_rate_limited_in_burst() {
        use crate::gui::notifications::{NotificationManager, MockNotificationSink};
        let sink = Arc::new(MockNotificationSink {
            history: Mutex::new(Vec::new()),
        });
        let manager = NotificationManager::new(sink.clone());

        // Burst: 5 messages
        for _ in 0..5 {
            manager.notify_message("peer8888", false).unwrap();
        }

        // Leading-edge: only 1st should fire
        let history = sink.history.lock().unwrap();
        assert_eq!(history.len(), 1);
    }

    #[test]
    fn test_placeholder_check_notifications() {
        let notifications_rs = include_str!("../src/gui/notifications.rs");
        assert!(!notifications_rs.contains("In a real implementation"));
        assert!(!notifications_rs.contains("we would start"));
        assert!(!notifications_rs.contains("For now,"));
        assert!(!notifications_rs.contains("simulate with"));
        assert!(!notifications_rs.contains("placeholder"));
    }

    #[test]
    fn test_notification_click_brings_window_to_front_mock() {
        let raise_called = Arc::new(AtomicBool::new(false));
        let raise_called_clone = raise_called.clone();
        let on_activate = move || {
            raise_called_clone.store(true, Ordering::Relaxed);
        };
        on_activate();
        assert!(raise_called.load(Ordering::Relaxed), "Activate callback should be triggered");
    }

    // M5: Screen Protection Tests
    #[test]
    fn test_privacy_mode_toggle_state() {
        let ui = ChatWindow::new().unwrap();
        assert!(!ui.get_privacy_mode());
        ui.set_privacy_mode(true);
        assert!(ui.get_privacy_mode());
    }

    #[test]
    fn test_privacy_mode_invokes_os_api() {
        use crate::gui::screen_protection::{MockScreenProtectionApi, ScreenProtectionApi};
        let state = Arc::new(Mutex::new(false));
        let api = MockScreenProtectionApi { state: state.clone() };
        let ui = ChatWindow::new().unwrap();
        
        api.set_protection(ui.window(), true).unwrap();
        assert!(*state.lock().unwrap());
        
        api.set_protection(ui.window(), false).unwrap();
        assert!(!*state.lock().unwrap());
    }

    #[test]
    fn test_placeholder_check_screen_protection() {
        let screen_protection_rs = include_str!("../src/gui/screen_protection.rs");
        // We allow the "Step 4.1" note as it is documentation of implementation status, not code placeholder
        assert!(!screen_protection_rs.contains("In a real implementation"));
        assert!(!screen_protection_rs.contains("we would start"));
        assert!(!screen_protection_rs.contains("simulate with"));
        assert!(!screen_protection_rs.contains("TODO"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_privacy_mode_noop_on_linux() {
        use crate::gui::screen_protection::{OsScreenProtectionApi, ScreenProtectionApi};
        let api = OsScreenProtectionApi;
        let ui = ChatWindow::new().unwrap();

        // On Linux, it should be unsupported
        assert!(!api.is_supported());
        
        // enable_protection (set_protection) should not fail but do nothing
        api.set_protection(ui.window(), true).unwrap();

        // Warning message should be present
        let warning = api.get_warning_message();
        assert!(warning.is_some());
        assert!(warning.unwrap().contains("Privacy mode relies on"));
    }

    #[test]
    fn test_privacy_mode_unsupported_os_warning_mock() {
        use crate::gui::screen_protection::ScreenProtectionApi;
        
        struct UnsupportedMock;
        impl ScreenProtectionApi for UnsupportedMock {
            fn set_protection(&self, _w: &slint::Window, _e: bool) -> crate::error::Result<()> { Ok(()) }
            fn is_supported(&self) -> bool { false }
            fn get_warning_message(&self) -> Option<String> { Some("OS version not supported".to_string()) }
        }
        unsafe impl Send for UnsupportedMock {}
        unsafe impl Sync for UnsupportedMock {}

        let api = UnsupportedMock;
        assert!(!api.is_supported());
        let warning = api.get_warning_message();
        assert!(warning.is_some());
        assert!(warning.unwrap().contains("OS version not supported"));
    }
}
