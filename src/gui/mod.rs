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
pub async fn run_gui() -> Result<(), Box<dyn std::error::Error>> {
    let ui = ChatWindow::new()?;
    let ui_handle = ui.as_weak();

    let (stdin_tx, stdin_rx) = mpsc::channel(100);
    let (stdout_tx, stdout_rx) = mpsc::channel(100);

    let gui_provider = Arc::new(GuiIOProvider {
        stdin_rx: Arc::new(tokio::sync::Mutex::new(stdin_rx)),
        stdout_tx,
    });

    // Update UI when messages arrive from network
    let mut stdout_rx = stdout_rx;
    let ui_handle_out = ui_handle.clone();
    tokio::spawn(async move {
        while let Some(data) = stdout_rx.recv().await {
            let msg = String::from_utf8_lossy(&data).to_string();
            // Filter out the prompt and other CLI-specific prefixes if any
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
    ui.on_connect_pressed(move |ticket, privkey, pubkey| {
        let ui_handle = ui_handle_conn.clone();
        let gp = gp.clone();
        let ticket = ticket.to_string();
        let privkey = privkey.to_string();
        let pubkey = pubkey.to_string();

        tokio::spawn(async move {
            let mut config = crate::config::CryptoConfig::default();
            config.connect_addr = Some(ticket);
            config.signing_privkey = Some(privkey);
            config.signing_pubkey = Some(pubkey);
            config.chat_mode = true;
            config.transport = crate::config::TransportKind::Iroh;

            let processor = crate::network::iroh::NetworkProcessor::with_io(config, gp);
            match processor.run_connect().await {
                Ok(_) => {
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_handle.upgrade() {
                            ui.set_connected(true);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("Connection error: {}", e);
                }
            }
        });
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
