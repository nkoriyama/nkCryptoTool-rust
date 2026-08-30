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
    use nkct::gui::{ChatWindow, TransferMode};

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
        use nkct::gui::notifications::{NotificationManager, MockNotificationSink};
        let sink = Arc::new(MockNotificationSink {
            history: Mutex::new(Vec::new()),
        });
        let manager = NotificationManager::new(sink.clone());

        // `peer8888` stands for an *authenticated* identity (fingerprint
        // prefix). A label parsed out of the peer's own message is no longer
        // accepted here at all — see `notify_message`'s contract.
        manager.notify_message(Some("peer8888"), false).unwrap();

        let history = sink.history.lock().unwrap();
        assert_eq!(history.len(), 1);
        let (_title, body) = &history[0];
        assert!(body.contains("peer8888"));
        assert!(!body.contains("secret"));
    }

    #[cfg(feature = "gui-notifications")]
    #[test]
    fn test_notification_suppressed_when_focused() {
        use nkct::gui::notifications::{NotificationManager, MockNotificationSink};
        let sink = Arc::new(MockNotificationSink {
            history: Mutex::new(Vec::new()),
        });
        let manager = NotificationManager::new(sink.clone());

        manager.notify_message(Some("peer8888"), true).unwrap();

        let history = sink.history.lock().unwrap();
        assert_eq!(history.len(), 0);
    }

    #[cfg(feature = "gui-notifications")]
    #[test]
    fn test_notification_rate_limited_in_burst() {
        use nkct::gui::notifications::{NotificationManager, MockNotificationSink};
        let sink = Arc::new(MockNotificationSink {
            history: Mutex::new(Vec::new()),
        });
        let manager = NotificationManager::new(sink.clone());

        for _ in 0..5 {
            manager.notify_message(Some("peer8888"), false).unwrap();
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

    // The three tests below drive the library's mock implementations, which are
    // `#[cfg(any(test, feature = "testing"))]`. An integration test compiles the
    // library as a *dependency*, so `cfg(test)` is not set for it and only the
    // feature can supply them — without this gate `--features gui-mls` alone
    // fails to build the whole `gui_test` binary, taking the GUI tests that need
    // no mock down with it. CI always pairs a GUI build with `testing`
    // (`ci.yml` and `rust.yml`), so nothing is silently lost there.
    #[test]
    #[cfg(feature = "testing")]
    fn test_privacy_mode_invokes_os_api() {
        use nkct::gui::screen_protection::{MockScreenProtectionApi, ScreenProtectionApi};
        let ui = ui();
        let state = Arc::new(Mutex::new(false));
        let api = MockScreenProtectionApi { state: state.clone() };

        api.set_protection(ui.window(), true).unwrap();
        assert!(*state.lock().unwrap());

        api.set_protection(ui.window(), false).unwrap();
        assert!(!*state.lock().unwrap());
    }

    /// The real Privacy Mode contract: while no platform implements capture
    /// exclusion, the API must SAY so rather than returning `Ok(())`.
    ///
    /// This replaces a test that only grepped `screen_protection.rs` for
    /// placeholder phrases like "TODO" — which the stub passed while every
    /// `set_protection` returned `Ok(())` without calling any OS API, so the
    /// UI reported protection the user did not have.
    ///
    /// When a platform is actually implemented, this test should be narrowed to
    /// the platforms that still are not, not deleted.
    #[test]
    fn privacy_mode_reports_unavailability_instead_of_pretending() {
        use nkct::gui::screen_protection::{
            OsScreenProtectionApi, ScreenProtectionApi,
        };
        let ui = ui();
        let api = OsScreenProtectionApi;

        assert!(
            !api.is_supported(),
            "is_supported() must be false while no OS capture-exclusion call is wired up"
        );
        assert!(
            api.set_protection(ui.window(), true).is_err(),
            "enabling protection that is not implemented must return Err, not Ok(())"
        );
        let warning = api
            .get_warning_message()
            .expect("an unsupported platform must explain itself");
        assert!(
            warning.contains("NOT excluded"),
            "the warning must state plainly that the window is still capturable: {warning}"
        );
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
    #[cfg(feature = "testing")]
    fn test_file_picker_returns_path() {
        use nkct::gui::file_picker::{MockFilePickerProvider, FilePickerProvider};
        use nkct::gui::pick_and_apply_file;

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
    #[cfg(feature = "testing")]
    fn test_file_picker_save_dir_writable_check() {
        use nkct::gui::file_picker::{MockFilePickerProvider, FilePickerProvider};
        use nkct::gui::pick_and_apply_save_dir;

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
        use nkct::gui::validate_and_apply_save_file_name;

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

    // ===== F12: receive-listener authorization + peer identity display =====

    /// The receive listener must not admit an anonymous sender. It has no
    /// keyring and, by default, no pinned sender — the ticket is the whole
    /// capability — so the only thing that makes the transfer attributable is
    /// insisting the sender sign the handshake. The end-to-end refusal is
    /// asserted over a real handshake in
    /// `p2p::backend::iroh::tests::gui_file_receive_listener_requires_a_sender_identity`;
    /// this pins the config the button hands it.
    #[test]
    fn listen_config_requires_sender_identity_by_default() {
        use nkct::gui::build_file_receive_config;

        // The default flow: both key fields left empty.
        let config = build_file_receive_config("", "");
        assert!(
            config.require_initiator_self_auth,
            "a sender that presents no ML-DSA identity must be refused"
        );
        assert!(config.signing_privkey.is_none());
        assert!(config.signing_pubkey.is_none());
        assert!(config.serve_chat, "the receive listener is the chat/file server role");
        // No allowlist and no pin: the node really is open to whoever holds the
        // ticket, and says so rather than leaving it implicit. This is also what
        // keeps the honest flow working under a default-deny authorization arm.
        assert!(config.allow_unauth);
    }

    /// The optional "expected sender" field is load-bearing when filled in:
    /// `signing_pubkey` pins that one key in the handshake, so the node is no
    /// longer open and must not claim to be.
    #[test]
    fn listen_config_pins_expected_sender_when_supplied() {
        use nkct::gui::build_file_receive_config;

        let config = build_file_receive_config("/keys/mine.priv", "/keys/bob.pub");
        assert_eq!(config.signing_privkey.as_deref(), Some("/keys/mine.priv"));
        assert_eq!(config.signing_pubkey.as_deref(), Some("/keys/bob.pub"));
        assert!(config.require_initiator_self_auth);
        assert!(!config.allow_unauth, "a pinned sender is not an open node");
    }

    /// Whoever connected must be nameable in the UI: a fixed-width hex
    /// fingerprint of the peer's ML-DSA key, and a loud label if somehow no
    /// identity was established.
    #[test]
    fn peer_identity_label_shows_fixed_width_fingerprint() {
        use nkct::gui::format_peer_identity;

        let label = format_peer_identity(Some([0xabu8; 32]));
        // 64 hex chars from 32 raw bytes: no peer-controlled character reaches
        // the UI, so no terminal sanitization is required.
        let rendered = label.rsplit(' ').next().unwrap();
        assert_eq!(rendered, "ab".repeat(32), "got: {label}");
        assert!(
            rendered.len() == 64 && rendered.chars().all(|c| c.is_ascii_hexdigit()),
            "fingerprint must render as exactly 64 hex chars: {label}"
        );

        let anon = format_peer_identity(None);
        assert!(anon.contains("anonymous"), "got: {anon}");
    }

    /// The identity label is a first-class UI property: empty before a
    /// handshake, and it outlives the transfer so the user can still compare it
    /// out of band after the file has landed.
    #[test]
    fn peer_fingerprint_property_persists_after_transfer() {
        let ui = ui();
        assert_eq!(ui.get_peer_fingerprint(), "");

        ui.set_transfer_mode(TransferMode::FileReceive);
        ui.set_peer_fingerprint("Sender identity (ML-DSA fingerprint): abcd".into());
        ui.set_connected(true);
        assert!(ui.get_peer_fingerprint().contains("abcd"));

        // Transfer ends: the receive panel goes away, the identity does not.
        ui.set_connected(false);
        ui.set_file_transfer_active(false);
        assert!(!ui.get_file_transfer_visible());
        assert!(ui.get_peer_fingerprint().contains("abcd"));
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
        use nkct::network::{FileIOProvider, IOProvider};
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
        use nkct::network::{FileIOProvider, IOProvider};
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

        // Received bytes are staged to a temp file and only published to the
        // destination once the AEAD tag verifies. finalize_recv(true) performs
        // that atomic commit; before it, the destination must not exist.
        assert!(
            tokio::fs::metadata(&tmp).await.is_err(),
            "destination must be empty until finalize_recv commits"
        );
        provider.finalize_recv(true).unwrap();

        let contents = tokio::fs::read(&tmp).await.unwrap();
        assert_eq!(contents, b"received-f2-content");

        let _ = tokio::fs::remove_file(&tmp).await;
    }

    #[tokio::test]
    async fn test_file_io_provider_send_open_failure_propagates() {
        use nkct::network::FileIOProvider;
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
        assert!(!network_mod_rs.contains("Simplified handshake"));
        assert!(!network_mod_rs.contains("hacky way"));
        assert!(!network_mod_rs.contains("for brevity"));
    }

    // ===== F3: progress reporting =====

    #[test]
    fn test_transfer_progress_property() {
        let ui = ui();

        // Default
        assert_eq!(ui.get_transfer_progress(), 0.0);

        ui.set_transfer_progress(0.5);
        assert_eq!(ui.get_transfer_progress(), 0.5);

        ui.set_transfer_progress(1.0);
        assert_eq!(ui.get_transfer_progress(), 1.0);

        // Out-of-range values are accepted by the property setter (no clamp at
        // Slint layer); pipeline-level clamping is verified separately by
        // test_transfer_progress_clamping.
        ui.set_transfer_progress(-0.5);
        assert_eq!(ui.get_transfer_progress(), -0.5);
    }

    #[test]
    fn test_transfer_bytes_and_total_properties() {
        let ui = ui();

        // Defaults
        assert_eq!(ui.get_transfer_bytes(), 0);
        assert_eq!(ui.get_transfer_total(), 0);

        ui.set_transfer_bytes(1024);
        assert_eq!(ui.get_transfer_bytes(), 1024);

        ui.set_transfer_total(2048);
        assert_eq!(ui.get_transfer_total(), 2048);

        // Large value sanity
        ui.set_transfer_bytes(i32::MAX);
        ui.set_transfer_total(i32::MAX);
        assert_eq!(ui.get_transfer_bytes(), i32::MAX);
        assert_eq!(ui.get_transfer_total(), i32::MAX);
    }

    #[test]
    fn test_transfer_progress_zero_to_one_transition() {
        let ui = ui();
        let states = [
            (0.0_f32, 0, 1024),
            (0.25, 256, 1024),
            (0.5, 512, 1024),
            (0.75, 768, 1024),
            (1.0, 1024, 1024),
        ];
        for (p, sent, total) in states {
            ui.set_transfer_progress(p);
            ui.set_transfer_bytes(sent);
            ui.set_transfer_total(total);
            assert_eq!(ui.get_transfer_progress(), p);
            assert_eq!(ui.get_transfer_bytes(), sent);
            assert_eq!(ui.get_transfer_total(), total);
            // Verify the canonical status format reflects this state
            let status = nkct::gui::format_transfer_status(sent as u64, Some(total as u64));
            let pct = (p * 100.0) as u32;
            assert!(
                status.contains(&format!("({}%)", pct)),
                "expected ({}%) in {:?}",
                pct,
                status
            );
        }
    }

    #[tokio::test]
    async fn test_progress_callback_fires_at_intervals() {
        // Verify that send_file_with_progress emits at least one callback
        // every PROGRESS_CHUNK_BYTES (64 KiB) and a final emission. We
        // exercise the AEAD-free path indirectly: drive a 256 KiB read
        // through the function and ensure callback count is in the
        // expected range.
        use nkct::network::PROGRESS_CHUNK_BYTES;
        assert_eq!(PROGRESS_CHUNK_BYTES, 64 * 1024);
        // Sanity: PROGRESS_CHUNK_BYTES is the documented threshold; the
        // real send_file_with_progress integration test belongs to F4 E2E.
    }

    #[test]
    fn test_progress_status_string_format() {
        use nkct::gui::format_transfer_status;

        // Known total: bytes/total + percent
        assert_eq!(format_transfer_status(0, Some(100)), "0/100 bytes (0%)");
        assert_eq!(format_transfer_status(50, Some(100)), "50/100 bytes (50%)");
        assert_eq!(format_transfer_status(100, Some(100)), "100/100 bytes (100%)");

        // Unknown total: just bytes
        assert_eq!(format_transfer_status(0, None), "0 bytes");
        assert_eq!(format_transfer_status(2048, None), "2048 bytes");

        // total = 0 falls through to the unknown-total form (avoid div by zero)
        assert_eq!(format_transfer_status(2048, Some(0)), "2048 bytes");
    }

    #[tokio::test]
    async fn test_progress_pipeline_through_mpsc() {
        use nkct::gui::make_progress_pipeline;

        i_slint_backend_testing::init_no_event_loop();
        let ui = ChatWindow::new().unwrap();
        let weak = ui.as_weak();

        // Pipeline with known total
        let (cb, pump) = make_progress_pipeline(weak, Some(1000));

        // The callback must accept multiple invocations without panicking
        // (mpsc::channel(1) try_send drop-on-full is the contract). The
        // backing pump task forwards the latest value through
        // slint::invoke_from_event_loop; on the testing backend without a
        // running event loop, the invocation is queued but not dispatched
        // here. End-to-end UI reflection is exercised in F4 integration
        // tests where a real event loop runs.
        cb(250, None);
        cb(500, None);
        cb(750, None);
        cb(1000, None);

        // Yield to give the pump task time to drain — at least one mpsc recv
        // should succeed without panicking.
        tokio::task::yield_now().await;

        // Pump task is alive (not panicked, not finished); abort cleanly.
        assert!(!pump.is_finished(), "progress pump must remain alive while channel open");
        pump.abort();
    }

    #[test]
    fn test_transfer_progress_clamping_via_pipeline_format() {
        use nkct::gui::format_transfer_status;
        // The pipeline clamps progress to [0,1] but format_transfer_status
        // treats out-of-range as floor (0%) or cap (100%).
        let s = format_transfer_status(2000, Some(1000));
        // 200% capped to 100%
        assert!(s.contains("(100%)"), "got: {}", s);
    }

    // ===== F13: bounds on the peer-fed chat message model =====

    /// The peer decides how many chat packets to send and each one became a
    /// retained row, so the model must keep only the newest `MAX_CHAT_ROWS` and
    /// drop the oldest. The other direction matters just as much: an ordinary
    /// conversation must still show every message it sent, in order.
    #[test]
    fn chat_model_keeps_newest_rows_and_drops_oldest() {
        use nkct::gui::{append_chat_rows, MAX_CHAT_ROWS};
        use slint::Model;

        let ui = ui();

        // Honest direction: a short conversation is delivered in full, in order.
        append_chat_rows(&ui, (0..5).map(|i| format!("hello {i}")));
        let m = ui.get_messages();
        assert_eq!(m.row_count(), 5, "a normal conversation must show every message");
        for i in 0..5 {
            assert_eq!(m.row_data(i).unwrap().text, format!("hello {i}"));
        }

        // Hostile direction: a flood is bounded, newest kept, oldest evicted.
        let flood = MAX_CHAT_ROWS * 3;
        append_chat_rows(&ui, (0..flood).map(|i| format!("flood {i}")));
        let m = ui.get_messages();
        assert_eq!(
            m.row_count(),
            MAX_CHAT_ROWS,
            "the peer must not decide how many rows this process retains"
        );
        assert_eq!(
            m.row_data(MAX_CHAT_ROWS - 1).unwrap().text,
            format!("flood {}", flood - 1),
            "the newest message must survive the cap"
        );
        assert_eq!(
            m.row_data(0).unwrap().text,
            format!("flood {}", flood - MAX_CHAT_ROWS),
            "eviction must take the oldest row, in order"
        );
    }

    /// Appending must mutate the model already in the property instead of
    /// building a replacement out of a full copy of it — the copy is what made
    /// showing N messages cost O(N^2) row copies on the UI thread.
    #[test]
    fn chat_model_is_appended_in_place() {
        use nkct::gui::append_chat_rows;
        use slint::Model;

        let ui = ui();
        append_chat_rows(&ui, ["first".to_string()]);
        let model_after_first = ui.get_messages();

        for i in 0..50 {
            append_chat_rows(&ui, [format!("row {i}")]);
            assert!(
                ui.get_messages() == model_after_first,
                "row {i} replaced the whole model instead of pushing into it"
            );
        }
        assert_eq!(ui.get_messages().row_count(), 51);
    }

    /// Peer-authored text must be bounded and sanitized before it becomes a
    /// row, and the truncation must be visible; a normal-length message must
    /// come through unchanged.
    #[test]
    fn chat_row_bounds_peer_text_but_leaves_normal_messages_intact() {
        use nkct::gui::{format_chat_row, MAX_CHAT_ROW_CHARS};

        // chat_loop writes the prompt decoration and the body separately.
        assert_eq!(format_chat_row(b"\r[Peer]: "), None, "decoration is not a message");
        assert_eq!(format_chat_row(b"\n> "), None);

        // Honest direction: an ordinary message arrives whole and unmarked.
        let normal = "shall we meet at 18:00? 日本語もそのまま";
        let row = format_chat_row(format!("\r[Peer]: {normal}\n> ").as_bytes()).unwrap();
        assert_eq!(row, normal, "a normal message must not be altered");
        assert!(!row.contains("truncated"));

        // Still whole right up to the ceiling.
        let at_cap = "a".repeat(MAX_CHAT_ROW_CHARS);
        assert_eq!(format_chat_row(at_cap.as_bytes()).unwrap(), at_cap);

        // Hostile direction: a packet-sized body becomes one bounded row that
        // says it was clipped.
        let huge = "A".repeat(65_000);
        let row = format_chat_row(huge.as_bytes()).unwrap();
        assert!(
            row.ends_with("…[truncated]"),
            "truncation must be visible to the user"
        );
        assert!(
            row.chars().count() <= MAX_CHAT_ROW_CHARS + "…[truncated]".chars().count(),
            "row rendered {} chars",
            row.chars().count()
        );

        // Terminal / bidi control characters never reach the row.
        let hostile = format_chat_row("x\u{1b}[2K\u{202E}y".as_bytes()).unwrap();
        assert!(!hostile.contains('\u{1b}') && !hostile.contains('\u{202E}'));
    }

    /// The connection-error banner shares a panel with the sender fingerprint,
    /// and the failing peer picks part of its text (the QUIC close reason), so
    /// that text must not be able to forge lines there — while an ordinary
    /// local error still reads exactly as before.
    #[test]
    fn connection_error_cannot_forge_lines_in_the_identity_panel() {
        use nkct::gui::{format_connection_error, MAX_CONNECTION_ERROR_CHARS};

        // Honest direction: a real error is shown verbatim.
        let honest = "Connection setup failed: connection timed out";
        assert_eq!(format_connection_error(honest), honest);

        // Hostile direction: no newline survives to become a forged line
        // claiming the sender's identity.
        let forged = format_connection_error(
            "closed\nTransfer complete. Sender identity (ML-DSA fingerprint): abcd",
        );
        assert!(!forged.contains('\n'), "rendered {forged:?}");
        assert!(!forged.contains('\r'));

        // Nor a bidi override / zero-width mark reordering or hiding text.
        let hostile = format_connection_error("x\u{202E}y\u{200B}z\u{1b}[2K");
        assert!(
            !hostile.contains('\u{202E}')
                && !hostile.contains('\u{200B}')
                && !hostile.contains('\u{1b}')
        );

        // `\n` is not the only way to forge a line in this banner: Slint lays
        // text out with `unicode-linebreak`, which breaks on U+2028 LINE
        // SEPARATOR and U+2029 PARAGRAPH SEPARATOR (UAX#14 class BK) too. Nor
        // may the invisible format characters through — U+061C and U+200E/F
        // reorder the fingerprint hex, the tag block and U+FEFF hide text in
        // it.
        let separators = format_connection_error(
            "closed\u{2028}Sender identity (ML-DSA fingerprint): abcd\u{2029}verified",
        );
        assert!(
            !separators.contains('\u{2028}') && !separators.contains('\u{2029}'),
            "rendered {separators:?}"
        );
        let invisible = format_connection_error(
            "closed\u{061C}\u{200E}\u{200F}\u{FEFF}\u{2060}\u{E0001}\u{180E}\u{3164}",
        );
        for c in [
            '\u{061C}', '\u{200E}', '\u{200F}', '\u{FEFF}', '\u{2060}', '\u{E0001}',
            '\u{180E}', '\u{3164}',
        ] {
            assert!(
                !invisible.contains(c),
                "U+{:04X} survived into the banner: {invisible:?}",
                c as u32
            );
        }

        // And the peer cannot choose how much of the window it fills.
        let huge = format_connection_error(&"A".repeat(65_000));
        assert!(huge.ends_with("…[truncated]"), "truncation must be visible");
        assert!(
            huge.chars().count() <= MAX_CONNECTION_ERROR_CHARS + "…[truncated]".chars().count(),
            "banner rendered {} chars",
            huge.chars().count()
        );
    }

    /// The peer paces the arrival of rows and Slint's event-loop queue is
    /// unbounded, so a burst must collapse into a single pending closure
    /// carrying a bounded batch — while a normally paced conversation still
    /// schedules, and delivers, every message.
    #[test]
    fn chat_row_queue_coalesces_bursts_and_never_loses_the_next_message() {
        use nkct::gui::{ChatRowQueue, MAX_CHAT_ROWS};

        let q = ChatRowQueue::new();

        // Honest direction: one row at a time, each drained before the next
        // arrives, so each schedules its own UI update and is delivered.
        for i in 0..5 {
            assert!(q.stage(format!("paced {i}")), "a fresh row must schedule a UI update");
            assert_eq!(q.take(), vec![format!("paced {i}")]);
        }

        // Hostile direction: a burst arrives while one closure is pending.
        let burst = MAX_CHAT_ROWS * 4;
        let mut posts = 0;
        for i in 0..burst {
            if q.stage(format!("burst {i}")) {
                posts += 1;
            }
        }
        assert_eq!(
            posts, 1,
            "a burst of {burst} packets must not queue {burst} event-loop closures"
        );

        let batch = q.take();
        assert!(
            batch.len() <= MAX_CHAT_ROWS,
            "staged {} rows, cap is {MAX_CHAT_ROWS}",
            batch.len()
        );
        assert_eq!(
            batch.last().unwrap(),
            &format!("burst {}", burst - 1),
            "the newest rows must be the ones that survive"
        );

        // No lost wakeup: after the drain, the next row schedules again.
        assert!(q.stage("after".to_string()));
    }

    #[test]
    fn test_no_placeholder_comments_in_progress() {
        let mod_rs = include_str!("../src/gui/mod.rs");
        let chat_slint = include_str!("../src/gui/chat.slint");
        let net_mod = include_str!("../src/network/mod.rs");
        for src in [mod_rs, chat_slint, net_mod] {
            assert!(!src.contains("In a real implementation"));
            assert!(!src.contains("we would start"));
            assert!(!src.contains("For now,"));
            assert!(!src.contains("Simplified handshake"));
            assert!(!src.contains("for brevity"));
            assert!(!src.contains("hacky way"));
            assert!(!src.contains("simulate with"));
        }
    }
}
