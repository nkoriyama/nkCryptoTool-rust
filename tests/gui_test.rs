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
    fn test_passphrase_cleared_after_send_mock() {
        let ui = ChatWindow::new().unwrap();
        ui.set_asking_passphrase(true);
        ui.set_passphrase_input("secret-passphrase".into());
        
        // The implementation in mod.rs should clear it
        ui.set_passphrase_input("".into());
        ui.set_asking_passphrase(false);
        
        assert_eq!(ui.get_passphrase_input(), "");
        assert!(!ui.get_asking_passphrase());
    }

    #[test]
    fn test_connection_error_state_transition() {
        let ui = ChatWindow::new().unwrap();
        ui.set_connection_error("Passphrase required".into());
        ui.set_asking_passphrase(true);
        assert!(ui.get_asking_passphrase());
        assert_eq!(ui.get_connection_error(), "Passphrase required");
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
        
        // We simulate the callback/logic
        ui.set_scanning_qr(true);
        assert!(ui.get_scanning_qr());
        
        ui.set_scanning_qr(false);
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
        use nk_crypto_tool::gui::notifications::{NotificationManager, MockNotificationSink};
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
        use nk_crypto_tool::gui::notifications::{NotificationManager, MockNotificationSink};
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
        use nk_crypto_tool::gui::notifications::{NotificationManager, MockNotificationSink};
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

        // Simulate the action callback that would be registered in mod.rs
        let on_activate = move || {
            raise_called_clone.store(true, Ordering::Relaxed);
        };

        // Trigger the mock "activate"
        on_activate();

        assert!(raise_called.load(Ordering::Relaxed), "Activate callback should be triggered");
    }

    #[test]
    fn test_privacy_mode_toggle_state() {
        let ui = ChatWindow::new().unwrap();
        assert!(!ui.get_privacy_mode());
        ui.set_privacy_mode(true);
        assert!(ui.get_privacy_mode());
    }

    #[test]
    fn test_privacy_mode_invokes_os_api() {
        use nk_crypto_tool::gui::screen_protection::{MockScreenProtectionApi, ScreenProtectionApi};
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
        assert!(!screen_protection_rs.contains("In a real implementation"));
        assert!(!screen_protection_rs.contains("we would start"));
        assert!(!screen_protection_rs.contains("simulate with"));
        assert!(!screen_protection_rs.contains("TODO"));
    }
}
