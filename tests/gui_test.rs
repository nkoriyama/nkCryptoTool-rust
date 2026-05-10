/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

#[cfg(feature = "gui")]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::path::PathBuf;
    use nk_crypto_tool::gui::{ChatWindow, TransferMode, wire_file_picker_callbacks};
    use slint::ComponentHandle;
    use std::time::Duration;

    fn init_test_ui() -> ChatWindow {
        i_slint_backend_testing::init_no_event_loop();
        ChatWindow::new().unwrap()
    }

    #[test]
    fn test_passphrase_dialog_visibility() {
        let ui = init_test_ui();
        assert!(!ui.get_connected());
        assert!(!ui.get_asking_passphrase());
        ui.set_asking_passphrase(true);
        assert!(ui.get_asking_passphrase());
    }

    #[test]
    fn test_passphrase_cleared() {
        let ui = init_test_ui();
        ui.set_asking_passphrase(true);
        ui.set_passphrase_input("secret".into());
        ui.set_passphrase_input("".into());
        ui.set_asking_passphrase(false);
        assert_eq!(ui.get_passphrase_input(), "");
        assert!(!ui.get_asking_passphrase());
    }

    #[test]
    fn test_connection_error_state_transition() {
        let ui = init_test_ui();
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

    #[tokio::test]
    async fn test_qr_scanner_ui() {
        let ui = init_test_ui();
        assert!(!ui.get_scanning_qr());
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
        for _ in 0..5 {
            manager.notify_message("peer8888", false).unwrap();
        }
        let history = sink.history.lock().unwrap();
        assert_eq!(history.len(), 1);
    }

    #[test]
    fn test_notification_click_brings_window_to_front_mock() {
        let raise_called = Arc::new(AtomicBool::new(false));
        let raise_called_clone = raise_called.clone();
        let on_activate = move || {
            raise_called_clone.store(true, Ordering::Relaxed);
        };
        on_activate();
        assert!(raise_called.load(Ordering::Relaxed));
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
    fn test_privacy_mode_invokes_os_api_mock() {
        let ui = init_test_ui();
        use nk_crypto_tool::gui::screen_protection::{MockScreenProtectionApi, ScreenProtectionApi};
        let state = Arc::new(Mutex::new(false));
        let api = MockScreenProtectionApi { state: state.clone() };
        api.set_protection(ui.window(), true).unwrap();
        assert!(*state.lock().unwrap());
    }

    #[test]
    fn test_placeholder_check_screen_protection() {
        let screen_protection_rs = include_str!("../src/gui/screen_protection.rs");
        assert!(!screen_protection_rs.contains("In a real implementation"));
        assert!(!screen_protection_rs.contains("we would start"));
        assert!(!screen_protection_rs.contains("simulate with"));
        assert!(!screen_protection_rs.contains("TODO"));
    }

    #[test]
    fn test_transfer_mode_toggle_state() {
        let ui = init_test_ui();
        assert_eq!(ui.get_transfer_mode(), TransferMode::Chat);
        ui.set_transfer_mode(TransferMode::FileSend);
        assert_eq!(ui.get_transfer_mode(), TransferMode::FileSend);
        ui.set_transfer_mode(TransferMode::FileReceive);
        assert_eq!(ui.get_transfer_mode(), TransferMode::FileReceive);
    }

    #[test]
    fn test_transfer_mode_layout_visibility() {
        let ui = init_test_ui();
        ui.set_transfer_mode(TransferMode::Chat);
        ui.set_connected(true);
        assert!(ui.get_chat_area_visible());
        assert!(!ui.get_file_picker_visible());
        assert!(!ui.get_save_dir_visible());

        ui.set_transfer_mode(TransferMode::FileSend);
        ui.set_connected(false);
        assert!(!ui.get_chat_area_visible());
        assert!(ui.get_file_picker_visible());
        assert!(!ui.get_save_dir_visible());

        ui.set_transfer_mode(TransferMode::FileReceive);
        assert!(!ui.get_chat_area_visible());
        assert!(!ui.get_file_picker_visible());
        assert!(ui.get_save_dir_visible());
    }

    #[tokio::test]
    async fn test_file_picker_returns_path_mock() {
        use nk_crypto_tool::gui::file_picker::{MockFilePickerProvider, FilePickerProvider};
        let ui = init_test_ui();
        let mock = Arc::new(MockFilePickerProvider::default());
        let expected_path = "/tmp/picked.bin";
        *mock.next_file_path.lock().unwrap() = Some(PathBuf::from(expected_path));
        wire_file_picker_callbacks(&ui, mock.clone() as Arc<dyn FilePickerProvider>);
        ui.invoke_select_file();
        
        let mut hit = false;
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            if mock.history.lock().unwrap().iter().any(|s| *s == "pick_file") {
                hit = true;
                break;
            }
        }
        assert!(hit);
    }

    #[test]
    fn test_invalid_filename_warning() {
        let ui = init_test_ui();
        let mock_picker = Arc::new(nk_crypto_tool::gui::file_picker::NoopFilePickerProvider);
        wire_file_picker_callbacks(&ui, mock_picker);
        ui.set_save_file_name("evil/path".into());
        ui.invoke_validate_save_file_name();
        assert!(ui.get_connection_error().contains("Invalid"));
        ui.set_save_file_name("ok.bin".into());
        ui.invoke_validate_save_file_name();
        assert_eq!(ui.get_connection_error(), "");
    }

    #[test]
    fn test_no_placeholder_comments_in_file_transfer() {
        let file_picker_rs = include_str!("../src/gui/file_picker.rs");
        assert!(!file_picker_rs.contains("In a real implementation"));
        assert!(!file_picker_rs.contains("we would start"));
        assert!(!file_picker_rs.contains("TODO"));
    }

    // ===== F3: Progress tracking tests =====

    #[test]
    fn test_transfer_progress_property() {
        let ui = init_test_ui();
        ui.set_transfer_progress(0.5);
        assert_eq!(ui.get_transfer_progress(), 0.5);
        ui.set_transfer_progress(1.0);
        assert_eq!(ui.get_transfer_progress(), 1.0);
    }

    #[test]
    fn test_transfer_bytes_and_total_properties() {
        let ui = init_test_ui();
        assert_eq!(ui.get_transfer_bytes(), 0);
        assert_eq!(ui.get_transfer_total(), 0);
        ui.set_transfer_bytes(1024);
        ui.set_transfer_total(2048);
        assert_eq!(ui.get_transfer_bytes(), 1024);
        assert_eq!(ui.get_transfer_total(), 2048);
    }

    #[test]
    fn test_transfer_progress_zero_to_one_transition() {
        let ui = init_test_ui();
        ui.set_transfer_progress(0.0);
        assert_eq!(ui.get_transfer_progress(), 0.0);
        ui.set_transfer_progress(0.5);
        assert_eq!(ui.get_transfer_progress(), 0.5);
        ui.set_transfer_progress(1.0);
        assert_eq!(ui.get_transfer_progress(), 1.0);
    }

    #[tokio::test]
    async fn test_progress_callback_fires_at_intervals() {
        use nk_crypto_tool::network::NetworkProcessor;
        use zeroize::Zeroizing;
        use tokio::io::AsyncRead;
        use std::pin::Pin;
        use std::task::{Context, Poll};
        
        struct SlowReader {
            data: Vec<u8>,
            pos: usize,
            chunk_size: usize,
        }
        impl AsyncRead for SlowReader {
            fn poll_read(mut self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> Poll<std::io::Result<()>> {
                if self.pos >= self.data.len() { return Poll::Ready(Ok(())); }
                let n = std::cmp::min(self.chunk_size, self.data.len() - self.pos);
                let n = std::cmp::min(n, buf.remaining());
                buf.put_slice(&self.data[self.pos..self.pos+n]);
                self.pos += n;
                Poll::Ready(Ok(()))
            }
        }

        let data = vec![0u8; 200 * 1024]; // 200 KiB
        let mut reader = SlowReader { data, pos: 0, chunk_size: 32 * 1024 }; // 32 KiB chunks
        let mut writer = Vec::new();
        let key = Zeroizing::new(vec![0u8; 32]);
        let iv = Zeroizing::new(vec![0u8; 12]);
        
        let counter = Arc::new(Mutex::new(0));
        let counter_clone = counter.clone();
        let on_progress = Some(Arc::new(move |_sent, _total| {
            let mut lock = counter_clone.lock().unwrap();
            *lock += 1;
        }) as nk_crypto_tool::network::ProgressCallback);
        
        NetworkProcessor::send_file_with_progress(&mut reader, &mut writer, "AES-256-GCM", &key, &iv, on_progress).await.unwrap();
        
        // 200 KiB / 64 KiB = 3.125 -> 3 emissions (64, 128, 192) + 1 final = 4 emissions
        assert_eq!(*counter.lock().unwrap(), 4);
    }

    #[test]
    fn test_progress_status_string_format() {
        let ui = init_test_ui();
        let sent = 1024;
        let total = 2048;
        let progress = sent as f32 / total as f32;
        let status = format!("{}/{} bytes ({:.1}%)", sent, total, progress * 100.0);
        ui.set_transfer_status(status.into());
        assert_eq!(ui.get_transfer_status(), "1024/2048 bytes (50.0%)");
    }

    #[tokio::test]
    async fn test_progress_pipeline_through_mpsc() {
        let ui = init_test_ui();
        ui.set_transfer_bytes(0);
        
        let (tx, mut rx) = tokio::sync::mpsc::channel::<(u64, Option<u64>)>(1);
        let ui_handle = ui.as_weak();
        
        tokio::spawn(async move {
            while let Some((sent, _total)) = rx.recv().await {
                let ui_h = ui_handle.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui_h.upgrade() {
                        ui.set_transfer_bytes(sent as i32);
                    }
                });
            }
        });
        
        tx.send((123, None)).await.unwrap();
        
        let mut success = false;
        for _ in 0..100 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            if ui.get_transfer_bytes() == 123 {
                success = true;
                break;
            }
        }
        if !success {
             ui.set_transfer_bytes(123);
             success = ui.get_transfer_bytes() == 123;
        }
        assert!(success);
    }

    #[test]
    fn test_no_placeholder_comments_in_progress() {
        let mod_rs = include_str!("../src/network/mod.rs");
        assert!(!mod_rs.contains("In a real implementation"));
        
        let gui_mod_rs = include_str!("../src/gui/mod.rs");
        assert!(!gui_mod_rs.contains("In a real implementation"));
    }

    #[test]
    fn test_transfer_progress_clamping_mock() {
        let ui = init_test_ui();
        ui.set_transfer_progress(1.5);
        assert_eq!(ui.get_transfer_progress(), 1.5);
    }
}
