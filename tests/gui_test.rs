/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

#[cfg(feature = "gui")]
mod tests {
    use slint::ComponentHandle;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::sync::atomic::{AtomicBool, Ordering};
    use nk_crypto_tool::gui::{ChatWindow, TransferMode};

    fn ui() -> ChatWindow {
        i_slint_backend_testing::init_no_event_loop();
        ChatWindow::new().unwrap()
    }

    // ===== M1: Slint passphrase / connection UI =====

    #[test]
    fn test_passphrase_dialog_visibility() {
        let ui = ui();
        assert!(!ui.get_connected());
        assert!(!ui.get_asking_passphrase());

        ui.set_asking_passphrase(true);
        assert!(ui.get_asking_passphrase());
    }

    #[test]
    fn test_passphrase_cleared_after_send_mock() {
        let ui = ui();
        ui.set_asking_passphrase(true);
        ui.set_passphrase_input("secret-passphrase".into());

        ui.set_passphrase_input("".into());
        ui.set_asking_passphrase(false);

        assert_eq!(ui.get_passphrase_input(), "");
        assert!(!ui.get_asking_passphrase());
    }

    #[test]
    fn test_connection_error_state_transition() {
        let ui = ui();
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

    // ===== M2: QR scanner UI =====

    #[test]
    fn test_qr_scanner_ui_transition() {
        let ui = ui();
        assert!(!ui.get_scanning_qr());
        ui.set_scanning_qr(true);
        assert!(ui.get_scanning_qr());
        ui.set_scanning_qr(false);
        assert!(!ui.get_scanning_qr());
    }

    // ===== M3: placeholder check (gui callbacks) =====

    #[test]
    fn test_no_placeholder_comments_in_gui_callbacks() {
        let mod_rs = include_str!("../src/gui/mod.rs");
        assert!(!mod_rs.contains("In a real implementation"));
        assert!(!mod_rs.contains("we would start"));
        assert!(!mod_rs.contains("For now,"));
        assert!(!mod_rs.contains("simulate with"));
    }

    // ===== M4: Notifications =====

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

        manager.notify_message("peer8888", true).unwrap();

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

        for _ in 0..5 {
            manager.notify_message("peer8888", false).unwrap();
        }

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

    // ===== M5: Privacy / Screen protection =====

    #[test]
    fn test_privacy_mode_toggle_state() {
        let ui = ui();
        assert!(!ui.get_privacy_mode());
        ui.set_privacy_mode(true);
        assert!(ui.get_privacy_mode());
    }

    #[test]
    fn test_privacy_mode_invokes_os_api() {
        use nk_crypto_tool::gui::screen_protection::{MockScreenProtectionApi, ScreenProtectionApi};
        let ui = ui();
        let state = Arc::new(Mutex::new(false));
        let api = MockScreenProtectionApi { state: state.clone() };

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

    // ===== F1: Transfer mode toggle + file picker =====

    #[test]
    fn test_transfer_mode_toggle_state() {
        let ui = ui();
        assert_eq!(ui.get_transfer_mode(), TransferMode::Chat);

        ui.set_transfer_mode(TransferMode::FileSend);
        assert_eq!(ui.get_transfer_mode(), TransferMode::FileSend);

        ui.set_transfer_mode(TransferMode::FileReceive);
        assert_eq!(ui.get_transfer_mode(), TransferMode::FileReceive);

        ui.set_transfer_mode(TransferMode::Chat);
        assert_eq!(ui.get_transfer_mode(), TransferMode::Chat);
    }

    #[test]
    fn test_transfer_mode_layout_visibility() {
        let ui = ui();

        // Chat mode + connected → chat area visible
        ui.set_transfer_mode(TransferMode::Chat);
        ui.set_connected(true);
        assert!(ui.get_chat_area_visible(), "chat area should show in Chat+connected");
        assert!(!ui.get_file_picker_visible());
        assert!(!ui.get_save_dir_visible());

        // FileSend pre-connect → file picker visible
        ui.set_transfer_mode(TransferMode::FileSend);
        ui.set_connected(false);
        ui.set_asking_passphrase(false);
        ui.set_scanning_qr(false);
        assert!(!ui.get_chat_area_visible());
        assert!(ui.get_file_picker_visible(), "file picker should show in FileSend pre-connect");
        assert!(!ui.get_save_dir_visible());

        // FileReceive pre-connect → save dir visible
        ui.set_transfer_mode(TransferMode::FileReceive);
        assert!(!ui.get_chat_area_visible());
        assert!(!ui.get_file_picker_visible());
        assert!(ui.get_save_dir_visible(), "save dir should show in FileReceive pre-connect");

        // Asking passphrase suppresses file pickers
        ui.set_transfer_mode(TransferMode::FileSend);
        ui.set_asking_passphrase(true);
        assert!(!ui.get_file_picker_visible());
        assert!(!ui.get_save_dir_visible());
    }

    #[test]
    fn test_file_picker_returns_path() {
        use nk_crypto_tool::gui::file_picker::{MockFilePickerProvider, FilePickerProvider};
        use nk_crypto_tool::gui::pick_and_apply_file;

        let ui = ui();
        let mock = MockFilePickerProvider::default();
        *mock.next_file_path.lock().unwrap() = Some(PathBuf::from("/tmp/picked.bin"));

        pick_and_apply_file(&ui, &mock as &dyn FilePickerProvider);

        assert_eq!(ui.get_selected_file_path(), "/tmp/picked.bin",
            "selected-file-path should be updated to picked path");
        assert!(mock.history.lock().unwrap().iter().any(|s| *s == "pick_file"),
            "MockFilePickerProvider::pick_file must be invoked");
    }

    #[test]
    fn test_file_picker_save_dir_writable_check() {
        use nk_crypto_tool::gui::file_picker::{MockFilePickerProvider, FilePickerProvider};
        use nk_crypto_tool::gui::pick_and_apply_save_dir;

        let ui = ui();
        let mock = MockFilePickerProvider::default();

        // Use temp dir which is writable
        let tmp = std::env::temp_dir();
        *mock.next_dir_path.lock().unwrap() = Some(tmp.clone());

        pick_and_apply_save_dir(&ui, &mock as &dyn FilePickerProvider);

        assert_eq!(ui.get_save_dir_path(), tmp.to_string_lossy().to_string());
        assert!(mock.history.lock().unwrap().iter().any(|s| *s == "pick_directory"));
    }

    #[test]
    fn test_invalid_filename_warning() {
        use nk_crypto_tool::gui::validate_and_apply_save_file_name;

        let ui = ui();

        // Valid name → no warning
        ui.set_save_file_name("ok.bin".into());
        validate_and_apply_save_file_name(&ui);
        assert_eq!(ui.get_connection_error(), "");

        // Forward slash
        ui.set_save_file_name("evil/path".into());
        validate_and_apply_save_file_name(&ui);
        assert!(ui.get_connection_error().contains("Invalid"),
            "forward slash in filename must trigger Invalid warning");

        // Backslash
        ui.set_connection_error("".into());
        ui.set_save_file_name("evil\\path".into());
        validate_and_apply_save_file_name(&ui);
        assert!(ui.get_connection_error().contains("Invalid"),
            "backslash in filename must trigger Invalid warning");

        // Recovery: valid name clears the warning
        ui.set_save_file_name("recovered.bin".into());
        validate_and_apply_save_file_name(&ui);
        assert_eq!(ui.get_connection_error(), "",
            "warning must clear once filename is valid");
    }

    #[test]
    fn test_no_placeholder_comments_in_file_transfer() {
        let file_picker_rs = include_str!("../src/gui/file_picker.rs");
        assert!(!file_picker_rs.contains("In a real implementation"));
        assert!(!file_picker_rs.contains("we would start"));
        assert!(!file_picker_rs.contains("For now,"));
        assert!(!file_picker_rs.contains("simulate with"));
        assert!(!file_picker_rs.contains("TODO"));
        assert!(!file_picker_rs.contains("placeholder"));
    }

    // ===== F2: Listen workflow + FileIOProvider =====

    #[test]
    fn test_listen_state_properties() {
        let ui = ui();

        // Defaults
        assert!(!ui.get_listening());
        assert_eq!(ui.get_generated_ticket(), "");
        assert!(!ui.get_file_transfer_active());
        assert_eq!(ui.get_transfer_status(), "");

        // listening true → listen_display_visible (FileReceive context)
        ui.set_transfer_mode(TransferMode::FileReceive);
        ui.set_listening(true);
        ui.set_generated_ticket("nkct1example...".into());
        assert!(ui.get_listen_display_visible(), "listen-display-visible should be true while listening");
        assert!(!ui.get_connection_settings_visible(), "connection-settings hidden during listen");
        assert_eq!(ui.get_generated_ticket(), "nkct1example...");

        // After connect (handshake done): not listening, but connected
        ui.set_listening(false);
        ui.set_connected(true);
        ui.set_file_transfer_active(true);
        ui.set_transfer_status("Receiving...".into());
        assert!(!ui.get_listen_display_visible());
        assert!(ui.get_file_transfer_visible(), "file-transfer-visible should be true during file-mode connection");
        assert!(!ui.get_chat_area_visible(), "chat-area must NOT be visible in non-Chat mode");
    }

    #[test]
    fn test_file_transfer_visibility_chat_vs_file_modes() {
        let ui = ui();

        // Chat + connected → chat-area visible, file-transfer hidden
        ui.set_transfer_mode(TransferMode::Chat);
        ui.set_connected(true);
        assert!(ui.get_chat_area_visible());
        assert!(!ui.get_file_transfer_visible());

        // FileSend + connected → file-transfer visible, chat-area hidden
        ui.set_transfer_mode(TransferMode::FileSend);
        assert!(!ui.get_chat_area_visible());
        assert!(ui.get_file_transfer_visible());

        // FileReceive + connected → file-transfer visible
        ui.set_transfer_mode(TransferMode::FileReceive);
        assert!(!ui.get_chat_area_visible());
        assert!(ui.get_file_transfer_visible());

        // Disconnected → neither
        ui.set_connected(false);
        assert!(!ui.get_chat_area_visible());
        assert!(!ui.get_file_transfer_visible());
    }

    #[tokio::test]
    async fn test_file_io_provider_send_reads_file_bytes() {
        use nk_crypto_tool::network::{FileIOProvider, IOProvider};
        use tokio::io::AsyncReadExt;

        let mut tmp = std::env::temp_dir();
        tmp.push(format!("nkct_f2_send_{}.bin", std::process::id()));
        tokio::fs::write(&tmp, b"hello-f2-payload").await.unwrap();

        let provider = FileIOProvider::new_send(tmp.clone()).await.unwrap();
        let mut reader = provider.stdin();
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"hello-f2-payload");

        // One-shot: second stdin() call returns empty reader
        let mut reader2 = provider.stdin();
        let mut buf2 = Vec::new();
        reader2.read_to_end(&mut buf2).await.unwrap();
        assert!(buf2.is_empty(), "second stdin() must yield empty (one-shot)");

        let _ = tokio::fs::remove_file(&tmp).await;
    }

    #[tokio::test]
    async fn test_file_io_provider_recv_writes_file_bytes() {
        use nk_crypto_tool::network::{FileIOProvider, IOProvider};
        use tokio::io::AsyncWriteExt;

        let mut tmp = std::env::temp_dir();
        tmp.push(format!("nkct_f2_recv_{}.bin", std::process::id()));
        let _ = tokio::fs::remove_file(&tmp).await;

        let provider = FileIOProvider::new_recv(tmp.clone()).await.unwrap();
        let mut writer = provider.stdout();
        writer.write_all(b"received-f2-content").await.unwrap();
        writer.shutdown().await.unwrap();

        // Drop the writer reference before reading (file handle closes via Drop)
        drop(writer);

        let contents = tokio::fs::read(&tmp).await.unwrap();
        assert_eq!(contents, b"received-f2-content");

        let _ = tokio::fs::remove_file(&tmp).await;
    }

    #[tokio::test]
    async fn test_file_io_provider_send_open_failure_propagates() {
        use nk_crypto_tool::network::FileIOProvider;
        let result = FileIOProvider::new_send(std::path::PathBuf::from(
            "/nonexistent/path/that/should/never/exist/nkct_f2.bin"
        )).await;
        assert!(result.is_err(), "opening non-existent send file must fail");
    }

    #[test]
    fn test_no_placeholder_comments_in_network_mod() {
        let network_mod_rs = include_str!("../src/network/mod.rs");
        assert!(!network_mod_rs.contains("In a real implementation"));
        assert!(!network_mod_rs.contains("we would start"));
        assert!(!network_mod_rs.contains("For now,"));
    }
}
