#[cfg(feature = "gui")]
slint::include_modules!();

#[cfg(feature = "gui")]
use slint::ComponentHandle;
#[cfg(feature = "gui")]
use std::sync::Arc;
#[cfg(feature = "gui")]
use tokio::sync::mpsc;
#[cfg(feature = "gui")]
use slint::Model;
use std::str::FromStr;
use crate::network::GuiIOProvider;
#[cfg(feature = "gui")]
use slint::VecModel;
#[cfg(feature = "gui")]
use slint::StandardListViewItem;
#[cfg(feature = "gui")]
use zeroize::Zeroizing;
#[cfg(feature = "gui")]
use std::time::Duration;

#[cfg(feature = "gui-camera")]
pub mod camera;
#[cfg(feature = "gui-notifications")]
pub mod notifications;
pub mod screen_protection;
#[cfg(feature = "gui")]
pub mod file_picker;

#[cfg(feature = "gui")]
pub fn pick_and_apply_file(ui: &ChatWindow, picker: &dyn file_picker::FilePickerProvider) {
    if let Some(path) = picker.pick_file() {
        ui.set_selected_file_path(path.to_string_lossy().to_string().into());
        ui.set_connection_error("".into());
    }
}

#[cfg(feature = "gui")]
pub fn pick_and_apply_save_dir(ui: &ChatWindow, picker: &dyn file_picker::FilePickerProvider) {
    if let Some(path) = picker.pick_directory() {
        let writable = std::fs::metadata(&path)
            .map(|m| !m.permissions().readonly())
            .unwrap_or(false);
        if !writable {
            ui.set_connection_error("Selected directory is not writable".into());
        } else {
            ui.set_save_dir_path(path.to_string_lossy().to_string().into());
            ui.set_connection_error("".into());
        }
    }
}

/// Unix epoch seconds as a string, used when the user does not supply a
/// receive filename and we need a non-colliding default.
#[cfg(feature = "gui")]
fn chrono_like_timestamp() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

#[cfg(feature = "gui")]
pub fn validate_and_apply_save_file_name(ui: &ChatWindow) {
    let name = ui.get_save_file_name().to_string();
    if file_picker::has_invalid_filename_chars(&name) {
        ui.set_connection_error("Invalid characters in filename".into());
    } else if ui.get_connection_error().to_string().contains("Invalid characters") {
        ui.set_connection_error("".into());
    }
}

#[cfg(feature = "gui")]
pub fn wire_file_picker_callbacks(
    ui: &ChatWindow,
    picker: Arc<dyn file_picker::FilePickerProvider>,
) {
    let ui_handle_f = ui.as_weak();
    let picker_f = picker.clone();
    ui.on_select_file(move || {
        let ui_handle = ui_handle_f.clone();
        let picker = picker_f.clone();
        tokio::task::spawn_blocking(move || {
            let result = picker.pick_file();
            let _ = slint::invoke_from_event_loop(move || {
                if let (Some(ui), Some(path)) = (ui_handle.upgrade(), result) {
                    ui.set_selected_file_path(path.to_string_lossy().to_string().into());
                    ui.set_connection_error("".into());
                }
            });
        });
    });

    let ui_handle_d = ui.as_weak();
    let picker_d = picker.clone();
    ui.on_select_save_dir(move || {
        let ui_handle = ui_handle_d.clone();
        let picker = picker_d.clone();
        tokio::task::spawn_blocking(move || {
            let result = picker.pick_directory();
            let _ = slint::invoke_from_event_loop(move || {
                if let (Some(ui), Some(path)) = (ui_handle.upgrade(), result) {
                    let writable = std::fs::metadata(&path)
                        .map(|m| !m.permissions().readonly())
                        .unwrap_or(false);
                    if !writable {
                        ui.set_connection_error("Selected directory is not writable".into());
                    } else {
                        ui.set_save_dir_path(path.to_string_lossy().to_string().into());
                        ui.set_connection_error("".into());
                    }
                }
            });
        });
    });

    let ui_handle_v = ui.as_weak();
    ui.on_validate_save_file_name(move || {
        if let Some(ui) = ui_handle_v.upgrade() {
            validate_and_apply_save_file_name(&ui);
        }
    });
}

#[cfg(feature = "gui-camera")]
use crate::ticket::Ticket;
#[cfg(feature = "gui-camera")]
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(feature = "gui")]
pub async fn run_gui() -> Result<(), Box<dyn std::error::Error>> {
    let ui = ChatWindow::new()?;
    let ui_handle = ui.as_weak();

    let (stdin_tx, stdin_rx) = mpsc::channel(100);
    let (stdout_tx, stdout_rx) = mpsc::channel(100);
    
    // Channel for M1 passphrase response: (passphrase, ticket, privkey, pubkey)
    let (pass_tx, mut pass_rx) = mpsc::channel::<(Zeroizing<String>, String, String, String)>(1);

    let gui_provider = Arc::new(GuiIOProvider {
        stdin_rx: Arc::new(tokio::sync::Mutex::new(stdin_rx)),
        stdout_tx,
    });

    // M4: Notification Manager
    #[cfg(feature = "gui-notifications")]
    let notif_manager = {
        use crate::gui::notifications::{NotificationManager, DesktopNotificationSink};
        Arc::new(NotificationManager::new(Arc::new(DesktopNotificationSink)))
    };

    // M5: Screen Protection
    let protection_api: Arc<dyn screen_protection::ScreenProtectionApi> = Arc::new(screen_protection::OsScreenProtectionApi);
    if let Some(warn) = protection_api.get_warning_message() {
        ui.set_privacy_warning(warn.into());
    }

    // F1: File Picker
    {
        #[cfg(feature = "gui-file-transfer")]
        let picker: Arc<dyn file_picker::FilePickerProvider> = Arc::new(file_picker::RfdFilePickerProvider);
        #[cfg(not(feature = "gui-file-transfer"))]
        let picker: Arc<dyn file_picker::FilePickerProvider> = Arc::new(file_picker::NoopFilePickerProvider);
        wire_file_picker_callbacks(&ui, picker);
    }

    // Update UI when messages arrive from network
    let mut stdout_rx = stdout_rx;
    let ui_handle_out = ui_handle.clone();
    #[cfg(feature = "gui-notifications")]
    let nm = notif_manager.clone();
    
    tokio::spawn(async move {
        while let Some(data) = stdout_rx.recv().await {
            let msg = String::from_utf8_lossy(&data).to_string();
            let clean_msg = msg.trim_start_matches("\r[Peer]: ").trim_end_matches("\n> ").trim_start_matches("> ").to_string();
            if clean_msg.is_empty() || clean_msg == ">" { continue; }
            
            let mut peer_id = "Peer".to_string();
            if msg.contains("[") && msg.contains("]") {
                 if let Some(start) = msg.find('[') {
                     if let Some(end) = msg.find(']') {
                         peer_id = msg[start+1..end].to_string();
                     }
                 }
            }

            #[cfg(feature = "gui-notifications")]
            {
                 // M4: Trigger notification
                 let _ = nm.notify_message(&peer_id, false);
            }

            let ui_handle = ui_handle_out.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_handle.upgrade() {
                    let messages = ui.get_messages();
                    let new_messages = VecModel::default();
                    for i in 0..messages.row_count() {
                        new_messages.push(messages.row_data(i).unwrap());
                    }
                    new_messages.push(StandardListViewItem::from(slint::SharedString::from(clean_msg.as_str())));
                    ui.set_messages(slint::ModelRc::new(new_messages));
                }
            });
        }
    });

    let gp = gui_provider.clone();
    let ui_handle_conn = ui_handle.clone();
    let pass_tx_for_ui = pass_tx.clone();
    let ui_handle_pass_cb = ui_handle.clone();
    
    ui.on_passphrase_provided(move |pass| {
        let pass_tx = pass_tx_for_ui.clone();
        if let Some(ui) = ui_handle_pass_cb.upgrade() {
            let ticket = ui.get_ticket_text().to_string();
            let privkey = ui.get_privkey_path().to_string();
            let pubkey = ui.get_pubkey_path().to_string();
            let pass_val = Zeroizing::new(pass.to_string());
            tokio::spawn(async move {
                let _ = pass_tx.send((pass_val, ticket, privkey, pubkey)).await;
            });
        }
    });

    ui.on_copy_to_clipboard(move |text| {
        let text = text.to_string();
        tokio::spawn(async move {
            #[cfg(feature = "arboard")]
            {
                if let Ok(mut cb) = arboard::Clipboard::new() {
                    let _ = cb.set_text(text.clone());
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    if let Ok(current) = cb.get_text() {
                        if current == text {
                            let _ = cb.clear();
                            eprintln!("[nkct-gui] Clipboard auto-cleared.");
                        }
                    }
                }
            }
        });
    });

    // M5: Privacy Mode Toggle
    let ui_handle_privacy = ui_handle.clone();
    let pa = protection_api.clone();
    ui.on_privacy_mode_toggled(move |enabled| {
        if let Some(ui) = ui_handle_privacy.upgrade() {
            let _ = pa.set_protection(ui.window(), enabled);
        }
    });

    // M2: QR Scanner (Full Functional Integration)
    #[cfg(feature = "gui-camera")]
    {
        use crate::gui::camera::{CameraSource, NokhwaCameraSource, decode_qr_from_rgb, format_camera_error, format_ticket_parse_error};
        
        let ui_handle_qr = ui_handle.clone();
        let current_camera: Arc<tokio::sync::Mutex<Option<Arc<dyn CameraSource>>>> = Arc::new(tokio::sync::Mutex::new(None));
        let cancel_flag = Arc::new(AtomicBool::new(false));

        let camera_mutex = current_camera.clone();
        let cancel_flag_scan = cancel_flag.clone();
        ui.on_scan_qr_pressed(move || {
            let ui_handle = ui_handle_qr.clone();
            let camera_mutex = camera_mutex.clone();
            let cancel_flag = cancel_flag_scan.clone();
            cancel_flag.store(false, Ordering::Relaxed);
            
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_handle.upgrade() {
                    ui.set_scanning_qr(true);
                    ui.set_scanner_status("Initializing camera...".into());
                }
            });

            let ui_handle_cb = ui_handle_qr.clone();
            let cancel_flag_cb = cancel_flag_scan.clone();
            let camera_mutex_cb = camera_mutex.clone();
            
            tokio::spawn(async move {
                let camera: Arc<dyn CameraSource> = Arc::new(NokhwaCameraSource::new());
                {
                    let mut lock = camera_mutex_cb.lock().await;
                    *lock = Some(camera.clone());
                }

                let ui_handle_frame = ui_handle_cb.clone();
                let cancel_flag_frame = cancel_flag_cb.clone();
                let camera_mutex_frame = camera_mutex_cb.clone();

                let frame_callback = Arc::new(move |rgb: Vec<u8>, w: u32, h: u32| {
                    if cancel_flag_frame.load(Ordering::Relaxed) { return; }

                    if let Some(decoded) = decode_qr_from_rgb(&rgb, w, h) {
                        match Ticket::from_str(&decoded) {
                            Ok(ticket) => {
                                cancel_flag_frame.store(true, Ordering::Relaxed);
                                let ui_handle = ui_handle_frame.clone();
                                let camera_mutex = camera_mutex_frame.clone();
                                slint::invoke_from_event_loop(move || {
                                    if let Some(ui) = ui_handle.upgrade() {
                                        ui.set_ticket_text(ticket.to_string().into());
                                        ui.set_scanning_qr(false);
                                        ui.set_scanner_status("QR code recognized.".into());
                                    }
                                }).ok();
                                tokio::spawn(async move {
                                    let mut lock = camera_mutex.lock().await;
                                    if let Some(cam) = lock.take() {
                                        let _ = cam.stop_scan();
                                    }
                                });
                            }
                            Err(e) => {
                                let ui_handle = ui_handle_frame.clone();
                                let msg = format_ticket_parse_error(&crate::error::CryptoError::Parameter(e.to_string()));
                                slint::invoke_from_event_loop(move || {
                                    if let Some(ui) = ui_handle.upgrade() {
                                        ui.set_scanner_status(msg.into());
                                    }
                                }).ok();
                            }
                        }
                    }
                });

                if let Err(e) = camera.start_scan(frame_callback) {
                    let ui_handle = ui_handle_cb.clone();
                    let msg = format_camera_error(&e);
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_handle.upgrade() {
                            ui.set_scanning_qr(false);
                            ui.set_scanner_status(msg.into());
                        }
                    }).ok();
                } else {
                    let ui_handle_to = ui_handle_cb.clone();
                    let cancel_flag_to = cancel_flag_cb.clone();
                    let camera_mutex_to = camera_mutex_cb.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_secs(30)).await;
                        if !cancel_flag_to.load(Ordering::Relaxed) {
                            cancel_flag_to.store(true, Ordering::Relaxed);
                            let mut lock = camera_mutex_to.lock().await;
                            if let Some(cam) = lock.take() {
                                let _ = cam.stop_scan();
                            }
                            slint::invoke_from_event_loop(move || {
                                if let Some(ui) = ui_handle_to.upgrade() {
                                    ui.set_scanning_qr(false);
                                    ui.set_scanner_status("No QR code detected (Timeout).".into());
                                }
                            }).ok();
                        }
                    });
                }
            });
        });

        let ui_handle_qr_cancel = ui_handle.clone();
        let camera_mutex_cancel = current_camera.clone();
        let cancel_flag_cancel = cancel_flag.clone();
        ui.on_scan_cancel(move || {
            let ui_handle = ui_handle_qr_cancel.clone();
            let camera_mutex = camera_mutex_cancel.clone();
            let cancel_flag = cancel_flag_cancel.clone();
            cancel_flag.store(true, Ordering::Relaxed);
            tokio::spawn(async move {
                let mut lock = camera_mutex.lock().await;
                if let Some(cam) = lock.take() {
                    let _ = cam.stop_scan();
                }
            });
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_handle.upgrade() {
                    ui.set_scanning_qr(false);
                }
            });
        });
    }

    let ui_handle_for_connect = ui_handle.clone();
    ui.on_connect_pressed(move |ticket, privkey, pubkey| {
        let ui_handle = ui_handle_conn.clone();
        let gp = gp.clone();
        let ticket = ticket.to_string();
        let privkey = privkey.to_string();
        let pubkey = pubkey.to_string();

        // Read transfer mode and selected file path from UI (UI thread)
        let (mode, selected_file_path) = if let Some(ui) = ui_handle_for_connect.upgrade() {
            (ui.get_transfer_mode(), ui.get_selected_file_path().to_string())
        } else {
            return;
        };

        tokio::spawn(async move {
            let mut config = crate::config::CryptoConfig::default();
            config.connect_addr = Some(ticket.clone());
            config.signing_privkey = Some(privkey.clone());
            config.signing_pubkey = Some(pubkey.clone());
            config.transport = crate::config::TransportKind::Iroh;

            // Branch on transfer mode: Chat reuses GuiIOProvider, FileSend
            // builds a FileIOProvider with the selected file as input.
            let (io_provider, is_file_mode): (Arc<dyn crate::network::IOProvider>, bool) = match mode {
                TransferMode::Chat => {
                    config.chat_mode = true;
                    (gp.clone(), false)
                }
                TransferMode::FileSend => {
                    config.chat_mode = false;
                    if selected_file_path.is_empty() {
                        let ui_handle = ui_handle.clone();
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(ui) = ui_handle.upgrade() {
                                ui.set_connection_error("No file selected for send.".into());
                            }
                        });
                        return;
                    }
                    let path = std::path::PathBuf::from(&selected_file_path);
                    match crate::network::FileIOProvider::new_send(path).await {
                        Ok(p) => (Arc::new(p), true),
                        Err(e) => {
                            let ui_handle = ui_handle.clone();
                            let msg = format!("Cannot open file: {}", e);
                            let _ = slint::invoke_from_event_loop(move || {
                                if let Some(ui) = ui_handle.upgrade() {
                                    ui.set_connection_error(msg.into());
                                }
                            });
                            return;
                        }
                    }
                }
                TransferMode::FileReceive => {
                    let ui_handle = ui_handle.clone();
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_handle.upgrade() {
                            ui.set_connection_error("FileReceive mode uses Generate Ticket, not Connect.".into());
                        }
                    });
                    return;
                }
            };

            let processor = crate::network::iroh::NetworkProcessor::with_io(config.clone(), io_provider);
            let ui_handle_for_callback = ui_handle.clone();
            let on_handshake = move || {
                let ui_handle = ui_handle_for_callback.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui_handle.upgrade() {
                        ui.set_connected(true);
                        if is_file_mode {
                            ui.set_file_transfer_active(true);
                            ui.set_transfer_status("Transferring...".into());
                        }
                    }
                });
            };

            let res = processor.run_connect_with_handshake_callback(on_handshake).await;

            let ui_handle_end = ui_handle.clone();
            let res_msg = match &res {
                Ok(_) if is_file_mode => "File sent successfully.".to_string(),
                _ => "".to_string(),
            };
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_handle_end.upgrade() {
                    ui.set_connected(false);
                    ui.set_file_transfer_active(false);
                    if !res_msg.is_empty() {
                        ui.set_transfer_status(res_msg.into());
                    }
                }
            });

            if let Err(e) = res {
                let err_str = e.to_string();
                if err_str.contains("passphrase") || err_str.contains("encrypted") {
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_handle.upgrade() {
                            ui.set_asking_passphrase(true);
                        }
                    });
                } else {
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_handle.upgrade() {
                            ui.set_connection_error(err_str.into());
                        }
                    });
                }
            }
        });
    });

    // F2: Listen handler (FileReceive mode)
    let ui_handle_listen = ui_handle.clone();
    let listen_task: Arc<tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>> =
        Arc::new(tokio::sync::Mutex::new(None));
    let listen_task_for_press = listen_task.clone();
    ui.on_listen_pressed(move |privkey, pubkey| {
        let ui_handle = ui_handle_listen.clone();
        let privkey = privkey.to_string();
        let pubkey = pubkey.to_string();
        let listen_task = listen_task_for_press.clone();

        // Read save dir / file name from UI thread
        let (save_dir, save_name, mode) = if let Some(ui) = ui_handle_listen.upgrade() {
            (
                ui.get_save_dir_path().to_string(),
                ui.get_save_file_name().to_string(),
                ui.get_transfer_mode(),
            )
        } else {
            return;
        };

        if mode != TransferMode::FileReceive {
            let ui_handle = ui_handle.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_handle.upgrade() {
                    ui.set_connection_error("Generate Ticket only available in FileReceive mode.".into());
                }
            });
            return;
        }
        if save_dir.is_empty() {
            let ui_handle = ui_handle.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_handle.upgrade() {
                    ui.set_connection_error("Please choose a save directory first.".into());
                }
            });
            return;
        }
        let final_name = if save_name.is_empty() {
            format!("received_{}.bin", chrono_like_timestamp())
        } else {
            save_name.clone()
        };
        let recv_path = std::path::PathBuf::from(&save_dir).join(&final_name);

        let task = tokio::spawn(async move {
            let mut config = crate::config::CryptoConfig::default();
            config.signing_privkey = if privkey.is_empty() { None } else { Some(privkey.clone()) };
            config.signing_pubkey = if pubkey.is_empty() { None } else { Some(pubkey.clone()) };
            config.chat_mode = false;
            config.transport = crate::config::TransportKind::Iroh;
            config.allow_unauth = true;

            let file_io = match crate::network::FileIOProvider::new_recv(recv_path.clone()).await {
                Ok(p) => Arc::new(p),
                Err(e) => {
                    let ui_handle = ui_handle.clone();
                    let msg = format!("Cannot create receive file: {}", e);
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_handle.upgrade() {
                            ui.set_connection_error(msg.into());
                        }
                    });
                    return;
                }
            };

            let processor = crate::network::iroh::NetworkProcessor::with_io(
                config.clone(),
                file_io as Arc<dyn crate::network::IOProvider>,
            );

            let ui_handle_ticket = ui_handle.clone();
            let on_ticket = move |ticket: &crate::ticket::Ticket| {
                let ticket_str = ticket.to_string();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui_handle_ticket.upgrade() {
                        ui.set_generated_ticket(ticket_str.into());
                        ui.set_listening(true);
                    }
                });
            };

            let ui_handle_handshake = ui_handle.clone();
            let on_handshake = move || {
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui_handle_handshake.upgrade() {
                        ui.set_listening(false);
                        ui.set_connected(true);
                        ui.set_file_transfer_active(true);
                        ui.set_transfer_status("Receiving...".into());
                    }
                });
            };

            let res = processor.run_listen_once(on_ticket, on_handshake).await;

            let ui_handle_end = ui_handle.clone();
            let final_msg = match &res {
                Ok(_) => format!("File received: {}", recv_path.display()),
                Err(e) => format!("Receive failed: {}", e),
            };
            let is_ok = res.is_ok();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_handle_end.upgrade() {
                    ui.set_listening(false);
                    ui.set_connected(false);
                    ui.set_file_transfer_active(false);
                    ui.set_generated_ticket("".into());
                    if is_ok {
                        ui.set_transfer_status(final_msg.into());
                    } else {
                        ui.set_connection_error(final_msg.into());
                    }
                }
            });
        });

        let listen_task_clone = listen_task.clone();
        tokio::spawn(async move {
            let mut guard = listen_task_clone.lock().await;
            *guard = Some(task);
        });
    });

    let listen_task_for_cancel = listen_task.clone();
    let ui_handle_cancel = ui_handle.clone();
    ui.on_listen_cancel(move || {
        let listen_task = listen_task_for_cancel.clone();
        let ui_handle = ui_handle_cancel.clone();
        tokio::spawn(async move {
            let mut guard = listen_task.lock().await;
            if let Some(handle) = guard.take() {
                handle.abort();
            }
            drop(guard);
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_handle.upgrade() {
                    ui.set_listening(false);
                    ui.set_generated_ticket("".into());
                    ui.set_connection_error("Listen cancelled.".into());
                }
            });
        });
    });

    let gp_pass = gui_provider.clone();
    let ui_handle_pass_retry = ui_handle.clone();
    tokio::spawn(async move {
        while let Some((passphrase, ticket, privkey, pubkey)) = pass_rx.recv().await {
            let mut config = crate::config::CryptoConfig::default();
            config.connect_addr = Some(ticket);
            config.signing_privkey = Some(privkey);
            config.signing_pubkey = Some(pubkey);
            config.chat_mode = true;
            config.transport = crate::config::TransportKind::Iroh;
            config.passphrase = Some(passphrase);
            
            let processor = crate::network::iroh::NetworkProcessor::with_io(config, gp_pass.clone());
            let ui_handle_for_callback = ui_handle_pass_retry.clone();
            let on_handshake = move || {
                let ui_handle = ui_handle_for_callback.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui_handle.upgrade() {
                        ui.set_connected(true);
                        ui.set_asking_passphrase(false);
                        ui.set_connection_error("".into());
                    }
                });
            };

            let res = processor.run_connect_with_handshake_callback(on_handshake).await;

            let ui_handle_end = ui_handle_pass_retry.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_handle_end.upgrade() {
                    ui.set_connected(false);
                }
            });

            if let Err(e) = res {
                let err_str = e.to_string();
                let ui_handle = ui_handle_pass_retry.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui_handle.upgrade() {
                        ui.set_connection_error(err_str.into());
                    }
                });
            }
        }
    });

    ui.on_send_message(move |text| {
        let text = text.to_string() + "\n";
        let stdin_tx = stdin_tx.clone();
        tokio::spawn(async move {
            let _ = stdin_tx.send(text.into_bytes()).await;
        });
    });

    ui.run()?;
    Ok(())
}
