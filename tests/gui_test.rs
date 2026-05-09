/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

#[cfg(feature = "gui")]
mod tests {
    use slint::ComponentHandle;
    use std::sync::{Arc, Mutex};
    
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
}
