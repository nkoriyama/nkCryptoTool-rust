#[cfg(feature = "gui")]
slint::include_modules!();

#[cfg(feature = "gui")]
use slint::ComponentHandle;
#[cfg(feature = "gui")]
use std::sync::Arc;
#[cfg(feature = "gui")]
use tokio::sync::mpsc;
#[cfg(feature = "gui")]
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
    let (pass_tx, mut pass_rx) = mpsc::channel::<Zeroizing<String>>(1);

    let gui_provider = Arc::new(GuiIOProvider {
        stdin_rx: Arc::new(tokio::sync::Mutex::new(stdin_rx)),
        stdout_tx,
    });

    let mut stdout_rx = stdout_rx;
    let ui_handle_out = ui_handle.clone();
    tokio::spawn(async move {
        while let Some(data) = stdout_rx.recv().await {
            let msg = String::from_utf8_lossy(&data).to_string();
            let clean_msg = msg.trim_start_matches("\r[Peer]: ").trim_end_matches("\n> ").trim_start_matches("> ").to_string();
            if clean_msg.is_empty() || clean_msg == ">" { continue; }
            
            let ui_handle = ui_handle_out.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_handle.upgrade() {
                    let messages = ui.get_messages();
                    let new_messages = Arc::new(VecModel::default());
                    for i in 0..messages.row_count() {
                        new_messages.push(messages.row_data(i).unwrap());
                    }
                    new_messages.push(StandardListViewItem::from(clean_msg.as_str().into()));
                    ui.set_messages(new_messages.into());
                }
            });
        }
    });

    let gp = gui_provider.clone();
    let ui_handle_conn = ui_handle.clone();
    let pass_tx_for_ui = pass_tx.clone();
    
    ui.on_passphrase_provided(move |pass| {
        let pass_tx = pass_tx_for_ui.clone();
        tokio::spawn(async move {
            let _ = pass_tx.send(Zeroizing::new(pass.to_string())).await;
        });
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

    ui.on_connect_pressed(move |ticket, privkey, pubkey| {
        let ui_handle = ui_handle_conn.clone();
        let gp = gp.clone();
        let ticket = ticket.to_string();
        let privkey = privkey.to_string();
        let pubkey = pubkey.to_string();
        let pass_tx = pass_tx.clone();

        tokio::spawn(async move {
            let mut config = crate::config::CryptoConfig::default();
            config.connect_addr = Some(ticket.clone());
            config.signing_privkey = Some(privkey.clone());
            config.signing_pubkey = Some(pubkey.clone());
            config.chat_mode = true;
            config.transport = crate::config::TransportKind::Iroh;

            let processor = crate::network::iroh::NetworkProcessor::with_io(config.clone(), gp.clone());
            match processor.run_connect().await {
                Ok(_) => {
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_handle.upgrade() {
                            ui.set_connected(true);
                        }
                    });
                }
                Err(e) => {
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
            }
        });
    });

    let ui_handle_pass = ui_handle.clone();
    let gp_pass = gui_provider.clone();
    tokio::spawn(async move {
        while let Some(passphrase) = pass_rx.recv().await {
            let ui = match ui_handle_pass.upgrade() {
                Some(ui) => ui,
                None => break,
            };
            let ticket = ui.get_ticket_text().to_string();
            let privkey = ui.get_privkey_path().to_string();
            let pubkey = ui.get_pubkey_path().to_string();
            let mut config = crate::config::CryptoConfig::default();
            config.connect_addr = Some(ticket);
            config.signing_privkey = Some(privkey);
            config.signing_pubkey = Some(pubkey);
            config.chat_mode = true;
            config.transport = crate::config::TransportKind::Iroh;
            config.passphrase = Some(passphrase);
            let processor = crate::network::iroh::NetworkProcessor::with_io(config, gp_pass.clone());
            let ui_handle = ui_handle_pass.clone();
            match processor.run_connect().await {
                Ok(_) => {
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_handle.upgrade() {
                            ui.set_connected(true);
                            ui.set_asking_passphrase(false);
                            ui.set_connection_error("".into());
                        }
                    });
                }
                Err(e) => {
                    let err_str = e.to_string();
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_handle.upgrade() {
                            ui.set_connection_error(err_str.into());
                        }
                    });
                }
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
