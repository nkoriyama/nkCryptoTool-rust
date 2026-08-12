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
// FromStr is used only by the gui-camera QR-scanning path
// (`Ticket::from_str(&decoded)`), so gate it to that feature.
#[cfg(feature = "gui-camera")]
use std::str::FromStr;
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
#[cfg(feature = "gui-notifications")]
pub mod notifications;
pub mod screen_protection;
#[cfg(feature = "gui")]
pub mod file_picker;
/// MLS group chat GUI driver (P8). Gated on `gui-mls` so the default
/// `gui` build (without MLS) skips the extra Slint module.
#[cfg(feature = "gui-mls")]
pub mod group_chat;

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

// `extract_peer_id` used to parse a sender label out of `[name] body` and hand
// it to the desktop-notification body. But `[name]` is part of the *peer's own
// message*, so the peer chose that label — it was never an identity, and a
// notification attributed to "nkCryptoTool" carrying peer-authored text is a
// phishing surface (markup-capable notification servers render `<a href=…>`).
// The parser is gone along with its only caller; the authenticated handshake
// fingerprint is the only thing that may ever label a notification, and until
// it is plumbed into the GUI the notification stays generic.

/// F3: format the transfer-status string from (sent, total). Public so the
/// test suite can verify the canonical format without driving a real
/// transfer.
pub fn format_transfer_status(sent: u64, total: Option<u64>) -> String {
    match total {
        Some(t) if t > 0 => {
            let pct = ((sent as f64 / t as f64) * 100.0).clamp(0.0, 100.0) as u32;
            format!("{}/{} bytes ({}%)", sent, t, pct)
        }
        _ => format!("{} bytes", sent),
    }
}

/// F13: hard ceiling on how many chat rows the GUI retains.
///
/// One accepted chat packet becomes one row, and the peer decides how many
/// packets to send, so without a ceiling the peer alone decides how much heap
/// this process keeps and how much the list view has to lay out. 1000 rows is
/// far more scrollback than a real session needs (an hour of brisk
/// back-and-forth is well under 100 rows) and costs at most ~1 MB even with
/// every row at `MAX_CHAT_ROW_CHARS`.
#[cfg(feature = "gui")]
pub const MAX_CHAT_ROWS: usize = 1000;

/// F13: hard ceiling on the rendered length of one chat row, in characters.
///
/// A chat packet carries up to ~65 KB of peer-authored body (`network`'s
/// `chunk_len` ceiling is 70000 bytes) and every byte of it used to land in a
/// `SharedString`. 256 is the same bound every other peer-string sink in the
/// tree uses (`scp`, `forward`), and `sanitize_for_terminal_bounded` appends a
/// visible `…[truncated]` marker so a clipped message never reads as complete.
#[cfg(feature = "gui")]
pub const MAX_CHAT_ROW_CHARS: usize = 256;

/// F13: render one `stdout` write from the chat loop as a display row, or
/// `None` when it carries nothing to show.
///
/// `chat_loop` writes a peer message as three separate writes — `"\r[Peer]: "`,
/// the body, `"\n> "` — so the prompt decoration arrives as its own write and
/// trims down to nothing. The trims and the empty / `">"` skip are unchanged
/// from the original inline code; what is new is the bound. The body reaching
/// here is filtered for control and bidi characters by `chat_loop`, but that
/// filter keeps `\n`/`\t`, misses U+200E/U+200F, and above all bounds nothing,
/// so one packet could put ~65 KB into a single list row.
/// `sanitize_for_terminal_bounded` is the only length bound applied to a chat
/// row — there is deliberately no second, different one downstream.
///
/// Public so the row bound can be tested without a peer.
#[cfg(feature = "gui")]
pub fn format_chat_row(data: &[u8]) -> Option<String> {
    let msg = String::from_utf8_lossy(data);
    let trimmed = msg
        .trim_start_matches("\r[Peer]: ")
        .trim_end_matches("\n> ")
        .trim_start_matches("> ");
    if trimmed.is_empty() || trimmed == ">" {
        return None;
    }
    Some(crate::utils::sanitize_for_terminal_bounded(
        trimmed,
        MAX_CHAT_ROW_CHARS,
    ))
}

/// F13: staging buffer between the network drain task and the Slint event loop.
///
/// The peer sets the rate at which chat packets arrive and
/// `slint::invoke_from_event_loop` queues without limit, so posting one closure
/// per packet lets the peer grow that queue — and the strings held in it —
/// without bound while the event loop falls further behind. Rows are staged
/// here instead, and staging hands out the obligation to post *one* closure:
/// every row staged while that closure is still pending is picked up by it when
/// it runs, so at most one closure is outstanding no matter how fast the peer
/// sends. The buffer is itself capped at `MAX_CHAT_ROWS`, since anything older
/// than that would be evicted by the model cap the moment it was applied.
#[cfg(feature = "gui")]
#[derive(Default)]
pub struct ChatRowQueue {
    inner: parking_lot::Mutex<ChatRowQueueInner>,
}

#[cfg(feature = "gui")]
#[derive(Default)]
struct ChatRowQueueInner {
    rows: std::collections::VecDeque<String>,
    /// True while a closure that will drain `rows` is queued on the event loop.
    posted: bool,
}

#[cfg(feature = "gui")]
impl ChatRowQueue {
    pub fn new() -> Self {
        Self::default()
    }

    /// Stage one row. Returns `true` if the caller must post exactly one
    /// event-loop closure that calls [`ChatRowQueue::take`]; `false` means such
    /// a closure is already pending and will carry this row too.
    pub fn stage(&self, row: String) -> bool {
        let mut inner = self.inner.lock();
        inner.rows.push_back(row);
        while inner.rows.len() > MAX_CHAT_ROWS {
            inner.rows.pop_front();
        }
        if inner.posted {
            false
        } else {
            inner.posted = true;
            true
        }
    }

    /// Take everything staged and clear the pending flag in one critical
    /// section, so a row staged after this point always schedules a fresh post
    /// (no lost wakeup).
    pub fn take(&self) -> Vec<String> {
        let mut inner = self.inner.lock();
        inner.posted = false;
        inner.rows.drain(..).collect()
    }

    /// Clear the pending flag without draining, for a caller whose post failed
    /// (the event loop is gone). The staged rows stay for the next attempt.
    pub fn release(&self) {
        self.inner.lock().posted = false;
    }
}

/// F13: append `rows` to the chat model in place, evicting the oldest rows so
/// the model never holds more than [`MAX_CHAT_ROWS`].
///
/// `messages` holds a `VecModel`, so appending is a push into the model that is
/// already there rather than a copy of every existing row into a freshly
/// allocated one — the latter made showing N messages cost O(N^2) row copies on
/// the UI thread. The first call swaps the `.slint` literal model for a
/// `VecModel`, carrying over whatever rows it held.
#[cfg(feature = "gui")]
pub fn append_chat_rows(ui: &ChatWindow, rows: impl IntoIterator<Item = String>) {
    if ui
        .get_messages()
        .as_any()
        .downcast_ref::<VecModel<StandardListViewItem>>()
        .is_none()
    {
        let existing = ui.get_messages();
        let carried: Vec<StandardListViewItem> = (0..existing.row_count())
            .filter_map(|i| existing.row_data(i))
            .collect();
        ui.set_messages(slint::ModelRc::new(VecModel::from(carried)));
    }
    let model = ui.get_messages();
    let Some(vec_model) = model.as_any().downcast_ref::<VecModel<StandardListViewItem>>() else {
        return;
    };
    for row in rows {
        while vec_model.row_count() >= MAX_CHAT_ROWS {
            vec_model.remove(0);
        }
        vec_model.push(StandardListViewItem::from(slint::SharedString::from(
            row.as_str(),
        )));
    }
}

/// F3: Build a progress callback + pump task that updates the UI
/// transfer-progress / transfer-bytes / transfer-total / transfer-status
/// properties from a tokio::sync::mpsc::channel(1) (latest-wins via
/// try_send drop-on-full).
///
/// `total_hint` is the GUI-side known total (e.g. file size from
/// FileIOProvider); it is forwarded to the UI so progress percentage can
/// be rendered. None when the total is not knowable upfront (receive side).
#[cfg(feature = "gui")]
pub fn make_progress_pipeline(
    ui_handle: slint::Weak<ChatWindow>,
    total_hint: Option<u64>,
) -> (crate::network::ProgressCallback, tokio::task::JoinHandle<()>) {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<(u64, Option<u64>)>(1);

    let cb: crate::network::ProgressCallback = {
        Arc::new(move |sent: u64, _total_hint_from_fn: Option<u64>| {
            let _ = tx.try_send((sent, total_hint));
        })
    };

    let pump = tokio::spawn(async move {
        while let Some((sent, total)) = rx.recv().await {
            let ui_handle = ui_handle.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_handle.upgrade() {
                    let progress = match total {
                        Some(t) if t > 0 => (sent as f32 / t as f32).clamp(0.0, 1.0),
                        _ => 0.0,
                    };
                    let status = format_transfer_status(sent, total);
                    ui.set_transfer_progress(progress);
                    ui.set_transfer_bytes(sent.min(i32::MAX as u64) as i32);
                    ui.set_transfer_total(total.unwrap_or(0).min(i32::MAX as u64) as i32);
                    ui.set_transfer_status(status.into());
                }
            });
        }
    });

    (cb, pump)
}

/// Build the `CryptoConfig` for the "Generate Ticket and Wait" (FileReceive)
/// listener. Public so the handshake-level regression test can drive the real
/// admission path with exactly the config the button builds, rather than a
/// hand-copied approximation that can drift from it.
///
/// `privkey` / `pubkey` are the raw UI fields; empty means "not supplied".
///
/// Authorization posture, in one place because all three parts interact:
///
/// * `signing_pubkey` (the optional "expected sender" field) pins one sender
///   when supplied: the handshake binds wire field #6 to it before verifying
///   `sig_I`, so only that key completes the handshake.
/// * When it is NOT supplied the node has no allowlist and no pin, so it is
///   open to whoever holds the ticket — `allow_unauth` says so honestly.
/// * `require_initiator_self_auth` is what keeps "open" from meaning
///   "anonymous". The ticket is the capability, so requiring a signature keeps
///   nobody out who has the ticket — an attacker can mint a key. What it buys
///   is that the session has an *identity*: a fingerprint the UI shows the
///   user, who can compare it out of band against the sender they meant.
///   Without it the peer is a `PeerId::Node` and the transfer is
///   unattributable.
#[cfg(feature = "gui")]
pub fn build_file_receive_config(privkey: &str, pubkey: &str) -> crate::config::CryptoConfig {
    let mut config = crate::config::CryptoConfig::default();
    config.signing_privkey = if privkey.is_empty() { None } else { Some(privkey.to_string()) };
    config.signing_pubkey = if pubkey.is_empty() { None } else { Some(pubkey.to_string()) };
    config.chat_mode = false;
    // This IS the chat/file server role — the GUI's receive button
    // listens on ALPN_FILE. `serve_chat` is what the ALPN dispatch
    // checks before serving that protocol, so a listener that does not
    // declare the role is refused (as a `--serve-shell` node now is).
    config.serve_chat = true;
    config.transport = crate::config::TransportKind::Iroh;
    config.allow_unauth = config.signing_pubkey.is_none();
    config.require_initiator_self_auth = true;
    config
}

/// Build the `CryptoConfig` for the "Connect" button — chat, or the file
/// *send* side of a transfer — and for the passphrase-retry that re-dials with
/// the same fields, so a retry cannot differ from the attempt it repeats.
///
/// `privkey` / `pubkey` are the raw UI fields; empty means "not supplied" and
/// must map to `None`, exactly as in [`build_file_receive_config`]. `Some("")`
/// is not an empty value here, it is a false claim, and both fields are read as
/// claims before they are read as paths:
///
/// * `signing_privkey.is_some()` *is* `has_signing_identity`, which sets
///   `INITIATOR_SELF_AUTH` in handshake field #5 — after which the initiator
///   must produce #6 and `sig_I`, so it loads the key and dies reading `""`.
/// * `signing_pubkey.is_some()` *is* "I hold a responder pin", which sets
///   `EXPECTS_RESPONDER_AUTH` and commits the pinned fingerprint in #7 — again
///   read from a path that is not there.
///
/// Left `None`, both claims are simply absent, which is the truth, and the
/// handshake then does the right thing on its own: it connects anonymously to a
/// responder that accepts that (`--allow-unauth`), and is refused by one that
/// does not — including this GUI's own receive listener, which sets
/// `require_initiator_self_auth` precisely so every transfer is attributable.
///
/// `chat_mode` and `passphrase` are left at their defaults: they differ per
/// call site, so the callers set them.
#[cfg(feature = "gui")]
fn build_connect_config(ticket: &str, privkey: &str, pubkey: &str) -> crate::config::CryptoConfig {
    let mut config = crate::config::CryptoConfig::default();
    config.connect_addr = Some(ticket.to_string());
    config.signing_privkey = if privkey.is_empty() { None } else { Some(privkey.to_string()) };
    config.signing_pubkey = if pubkey.is_empty() { None } else { Some(pubkey.to_string()) };
    config.transport = crate::config::TransportKind::Iroh;
    config
}

/// The UI label for the peer identity established by the handshake.
///
/// `crate::shell::fp_hex` is a fixed-width rendering of 32 raw bytes (64
/// lowercase hex chars, `{b:02x}` per byte), so the peer controls no character
/// of it and it needs no `sanitize_for_terminal_bounded` pass. The `None` arm
/// is a fixed literal for the same reason.
#[cfg(feature = "gui")]
pub fn format_peer_identity(peer_fp: Option<[u8; 32]>) -> String {
    match peer_fp {
        Some(fp) => format!("Sender identity (ML-DSA fingerprint): {}", crate::shell::fp_hex(&fp)),
        // Only reachable on a listener that does not set
        // `require_initiator_self_auth`; say so loudly rather than leaving the
        // label blank, which reads like "not connected yet".
        None => "⚠ Sender did not present an identity (anonymous)".to_string(),
    }
}

/// F6: hard ceiling on the peer-influenced part of the `connection-error`
/// banner, in characters. Same 256 as every other peer-string sink in the tree
/// (`format_chat_row`, `group_chat::render_event`, `scp`, `forward`).
#[cfg(feature = "gui")]
pub const MAX_CONNECTION_ERROR_CHARS: usize = 256;

/// F6: render a transport/backend error as `connection-error` banner text.
///
/// A failed transfer's error string is not ours: a peer that reaches the
/// listener with a valid ALPN and closes the QUIC connection with a chosen
/// reason phrase has that phrase stringified into `P2pError::Accept` and
/// wrapped into the `CryptoError` this banner shows. The banner is drawn in the
/// same panel as `peer-fingerprint` — the one thing the user is told to compare
/// out of band to decide whether the sender is who they meant — and a Slint
/// `Text` renders an embedded `\n` as a line break, so unfiltered peer text can
/// paint extra lines that read like our own identity or success lines. Nothing
/// bounds the length either.
///
/// So the peer's text goes through the same pass every other peer-derived
/// string in the tree already gets: controls (including `\n`), zero-width and
/// bidi marks become spaces, and the text is clipped with a visible
/// `…[truncated]` marker. Prefixes we author (`"Receive failed: "`) stay outside
/// the bound. Public so the bound can be tested without a peer.
#[cfg(feature = "gui")]
pub fn format_connection_error(err: &str) -> String {
    crate::utils::sanitize_for_terminal_bounded(err, MAX_CONNECTION_ERROR_CHARS)
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
    
    // F13: rows are staged here and applied in batches. The peer paces the
    // arrival of chat packets, so one event-loop closure per packet would let
    // it grow Slint's unbounded event queue at will.
    let chat_rows = Arc::new(ChatRowQueue::new());

    tokio::spawn(async move {
        while let Some(data) = stdout_rx.recv().await {
            // F13: peer text is bounded and sanitized before it becomes a row.
            let Some(clean_msg) = format_chat_row(&data) else {
                continue;
            };

            #[cfg(feature = "gui-notifications")]
            {
                 // M4: Trigger notification. `None` because no authenticated
                 // identity reaches this task — the only peer-derived string
                 // here is the message body itself, which the peer authored and
                 // which therefore must not label a notification. Pass the
                 // handshake fingerprint here once it is plumbed through.
                 let _ = nm.notify_message(None, false);
            }

            if !chat_rows.stage(clean_msg) {
                // A closure is already queued on the event loop and will carry
                // this row; queueing another one only grows the queue.
                continue;
            }
            let ui_handle = ui_handle_out.clone();
            let rows_for_ui = chat_rows.clone();
            let posted = slint::invoke_from_event_loop(move || {
                // Take first and unconditionally, so the pending flag is
                // cleared even if the window has gone away.
                let batch = rows_for_ui.take();
                if let Some(ui) = ui_handle.upgrade() {
                    append_chat_rows(&ui, batch);
                }
            });
            if posted.is_err() {
                chat_rows.release();
            }
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
        let Some(ui) = ui_handle_privacy.upgrade() else {
            return;
        };
        // The result is NOT discarded. `set_protection` returns Err on every
        // platform where the OS capture-exclusion call is not wired up, and
        // swallowing that left the switch reading "on" over a window that any
        // screen-share or screenshot tool still captured in full — a control
        // the user relies on precisely when secrets are on screen.
        match pa.set_protection(ui.window(), enabled) {
            Ok(()) => {
                if enabled {
                    ui.set_privacy_warning(slint::SharedString::from(""));
                }
            }
            Err(e) => {
                // Put the switch back where it actually is, and say why.
                ui.set_privacy_mode(false);
                let msg = pa
                    .get_warning_message()
                    .unwrap_or_else(|| format!("Privacy mode unavailable: {e}"));
                eprintln!("[nkct-gui] {msg}");
                ui.set_privacy_warning(slint::SharedString::from(msg));
            }
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
            let mut config = build_connect_config(&ticket, &privkey, &pubkey);

            // Branch on transfer mode: Chat reuses GuiIOProvider, FileSend
            // builds a FileIOProvider with the selected file as input.
            let mut total_send_bytes: Option<u64> = None;
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
                    total_send_bytes = tokio::fs::metadata(&path).await.ok().map(|m| m.len());
                    // F4 (Gemini Trigger 3 §3.1#2): pre-check file size against
                    // MAX_FILE_SIZE so the UI surfaces a clear error before the
                    // transfer starts, instead of letting the receiver reject
                    // mid-transfer (10 GB limit, see network::MAX_FILE_SIZE).
                    if let Some(sz) = total_send_bytes {
                        if sz > crate::network::MAX_FILE_SIZE {
                            let ui_handle = ui_handle.clone();
                            let msg = format!(
                                "File too large: {} bytes exceeds {} byte limit ({:.1} GB cap).",
                                sz,
                                crate::network::MAX_FILE_SIZE,
                                (crate::network::MAX_FILE_SIZE as f64) / 1024.0 / 1024.0 / 1024.0,
                            );
                            let _ = slint::invoke_from_event_loop(move || {
                                if let Some(ui) = ui_handle.upgrade() {
                                    ui.set_connection_error(msg.into());
                                }
                            });
                            return;
                        }
                    }
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

            // F3: build progress pipeline if in file mode
            let (on_progress_opt, progress_pump) = if is_file_mode {
                let (cb, pump) = make_progress_pipeline(ui_handle.clone(), total_send_bytes);
                (Some(cb), Some(pump))
            } else {
                (None, None)
            };

            let endpoint = match crate::p2p::backend::iroh::IrohEndpoint::new(&config, false).await {
                Ok(ep) => Arc::new(ep),
                Err(e) => {
                    ui_handle.upgrade_in_event_loop(move |ui| {
                        ui.set_connection_error(format!("Endpoint init: {}", e).into());
                    }).ok();
                    return;
                }
            };
            let processor = crate::p2p::NetworkProcessor::new(config.clone(), endpoint, io_provider);
            let ui_handle_for_callback = ui_handle.clone();
            let total_for_handshake = total_send_bytes;
            let on_handshake = move || {
                let ui_handle = ui_handle_for_callback.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui_handle.upgrade() {
                        ui.set_connected(true);
                        if is_file_mode {
                            ui.set_file_transfer_active(true);
                            ui.set_transfer_progress(0.0);
                            ui.set_transfer_bytes(0);
                            ui.set_transfer_total(total_for_handshake.unwrap_or(0).min(i32::MAX as u64) as i32);
                            ui.set_transfer_status("Transferring...".into());
                        }
                    }
                });
            };

            let res = processor
                .run_connect_with_handshake_callback_and_progress(on_handshake, on_progress_opt)
                .await;

            // Stop the progress pump after the transfer completes
            if let Some(pump) = progress_pump {
                pump.abort();
            }

            let ui_handle_end = ui_handle.clone();
            let res_msg = match &res {
                Ok(_) if is_file_mode => "File sent successfully.".to_string(),
                _ => "".to_string(),
            };
            let final_total = total_send_bytes;
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_handle_end.upgrade() {
                    ui.set_connected(false);
                    ui.set_file_transfer_active(false);
                    if !res_msg.is_empty() {
                        // On success, force progress to 100% for visual completeness
                        if let Some(t) = final_total {
                            ui.set_transfer_progress(1.0);
                            ui.set_transfer_bytes(t.min(i32::MAX as u64) as i32);
                        }
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
                    // F6: the responder chose part of this text (its QUIC close
                    // reason), so it is sanitized and bounded before it reaches
                    // the banner. The `passphrase` test above still runs on the
                    // raw string.
                    let shown = format_connection_error(&err_str);
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_handle.upgrade() {
                            ui.set_connection_error(shown.into());
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
            let config = build_file_receive_config(&privkey, &pubkey);

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
            // Kept so the completion path can ask whether a file was actually
            // published at `recv_path`, instead of inferring it from a listener
            // result that says only "the session ended cleanly".
            let recv_state = file_io.clone();

            let endpoint = match crate::p2p::backend::iroh::IrohEndpoint::new(&config, false).await {
                Ok(ep) => Arc::new(ep),
                Err(e) => {
                    ui_handle.upgrade_in_event_loop(move |ui| {
                        ui.set_connection_error(format!("Endpoint init: {}", e).into());
                    }).ok();
                    return;
                }
            };
            let mut processor = crate::p2p::NetworkProcessor::new(config.clone(), endpoint, file_io as Arc<dyn crate::network::IOProvider>);
            // Activate keyring authorization on the same terms as every other
            // listener (main.rs / network::run_server). With no `keyring_db`
            // configured — the GUI has no field for one — this is a no-op, so
            // the honest flow is unaffected; it is here so a keyring, once
            // configured, is actually consulted instead of silently ignored.
            if let Err(e) = processor.preload_allowlist().await {
                let ui_handle = ui_handle.clone();
                let msg = format!("Keyring allowlist: {}", e);
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui_handle.upgrade() {
                        ui.set_connection_error(msg.into());
                    }
                });
                return;
            }

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
            let on_handshake = move |peer_fp: Option<[u8; 32]>| {
                // Who actually connected. On a listener whose only admission
                // control is "holds the ticket", this is the one thing that
                // distinguishes the sender the user handed the ticket to from
                // anyone else who saw it, so it is shown before the bytes land.
                let identity = format_peer_identity(peer_fp);
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui_handle_handshake.upgrade() {
                        ui.set_peer_fingerprint(identity.into());
                        ui.set_listening(false);
                        ui.set_connected(true);
                        ui.set_file_transfer_active(true);
                        ui.set_transfer_progress(0.0);
                        ui.set_transfer_bytes(0);
                        ui.set_transfer_total(0); // unknown for receive side
                        ui.set_transfer_status("Receiving...".into());
                    }
                });
            };

            // F3: progress pipeline for receive side. Total bytes are unknown
            // until end-of-stream so total_hint is None; the pump will render
            // an indeterminate progress bar (transfer-total == 0).
            let (on_progress, progress_pump) = make_progress_pipeline(ui_handle.clone(), None);

            let res = processor
                .run_listen_once_with_progress(on_ticket, on_handshake, Some(on_progress))
                .await;
            progress_pump.abort();

            let ui_handle_end = ui_handle.clone();
            // A receipt is claimed only when `finalize_recv(true)` actually
            // published the transfer at `recv_path`. `res` being Ok means the
            // session ended cleanly, which is not the same thing — and naming a
            // path that already held a file would present stale content as the
            // file just received.
            let committed = recv_state.recv_committed();
            let final_msg = match &res {
                Ok(_) if committed => format!("File received: {}", recv_path.display()),
                Ok(_) => "Receive failed: the peer did not send a file".to_string(),
                // F6: whoever holds the ticket can reach this listener and pick
                // the QUIC close reason that ends up inside `e`, and this string
                // lands in the banner beside the sender fingerprint. The prefix
                // is ours; everything the peer touched is sanitized and bounded.
                Err(e) => format!("Receive failed: {}", format_connection_error(&e.to_string())),
            };
            let is_ok = res.is_ok() && committed;
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
            let mut config = build_connect_config(&ticket, &privkey, &pubkey);
            config.chat_mode = true;
            config.passphrase = Some(passphrase);
            
            let endpoint = match crate::p2p::backend::iroh::IrohEndpoint::new(&config, false).await {
                Ok(ep) => Arc::new(ep),
                Err(e) => {
                    ui_handle_pass_retry.upgrade_in_event_loop(move |ui| {
                        ui.set_connection_error(format!("Endpoint init: {}", e).into());
                    }).ok();
                    return;
                }
            };
            let processor = crate::p2p::NetworkProcessor::new(config, endpoint, gp_pass.clone());
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
                // F6: same peer-influenced text as the first connect attempt.
                let err_str = format_connection_error(&e.to_string());
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

#[cfg(all(test, feature = "gui"))]
mod connect_config_tests {
    use super::build_connect_config;

    /// An empty key field must reach the config as `None`, not `Some("")`.
    /// `Some("")` is read as a claim long before it is read as a path:
    /// `has_signing_identity` is `signing_privkey.is_some()`, so the initiator
    /// announces `INITIATOR_SELF_AUTH` in handshake field #5 and only then
    /// tries to load `""` as a key file — which is why a send from a GUI with
    /// no key configured died locally instead of reaching the handshake at all.
    /// `signing_pubkey` is the same shape: `Some("")` claims a responder pin
    /// and so skips the "no pinned identity to verify against" refusal in
    /// `p2p::processor` that exists to catch exactly this state.
    #[test]
    fn connect_config_leaves_empty_key_fields_unset() {
        let config = build_connect_config("nkct1example", "", "");
        assert!(
            config.signing_privkey.is_none(),
            "an empty key field is no signing identity, and must not claim to be one"
        );
        assert!(
            config.signing_pubkey.is_none(),
            "an empty expected-peer field is no responder pin, and must not claim to be one"
        );
        assert_eq!(config.connect_addr.as_deref(), Some("nkct1example"));
    }

    /// The honest flow is untouched: a filled-in field reaches the config
    /// verbatim, so a send with keys configured behaves exactly as before.
    #[test]
    fn connect_config_keeps_supplied_key_paths_verbatim() {
        let config = build_connect_config("nkct1example", "/keys/mine.priv", "/keys/bob.pub");
        assert_eq!(config.signing_privkey.as_deref(), Some("/keys/mine.priv"));
        assert_eq!(config.signing_pubkey.as_deref(), Some("/keys/bob.pub"));
        assert_eq!(config.connect_addr.as_deref(), Some("nkct1example"));
        assert!(matches!(config.transport, crate::config::TransportKind::Iroh));
    }
}

// The tests that lived here exercised `extract_peer_id`'s panic-safety on
// malformed remote input (`"] ["`, `"[unterminated"`, …). They went with the
// function: nothing parses a label out of a peer's message any more, so there
// is no longer a parser to keep panic-safe. The property that replaced them —
// that a notification body never carries peer-authored markup — is tested in
// `gui::notifications`.
