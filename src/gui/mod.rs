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

/// The one slot holding the running file-receive listener, if any.
///
/// A `std` mutex, not a `tokio` one, on purpose: both the "Generate Ticket and
/// Wait" press and the Cancel press arrive on the Slint event-loop thread, and
/// only a lock they can take *there and then* lets the handle be installed in
/// the same turn as the press. Storing it from a spawned task instead left a
/// multi-second window in which a live listener was in nobody's hands. It is
/// never held across an await.
#[cfg(feature = "gui")]
type ListenSlot = std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>;

/// Make `spawn`'s listener *the* listener: abort whatever is already in the
/// slot, then install the new handle, all under one lock. Returns whether a
/// previous listener was found and aborted.
///
/// The abort is the point. Overwriting the slot without it detached a listener
/// that was still accepting connections on a ticket already in circulation,
/// with no UI affordance left to stop it — Cancel can only reach the handle the
/// slot holds. A listener nobody holds is a listener nobody can revoke.
#[cfg(feature = "gui")]
fn install_listener(
    slot: &ListenSlot,
    spawn: impl FnOnce() -> tokio::task::JoinHandle<()>,
) -> bool {
    // A panic elsewhere must not make the listener unstoppable, so a poisoned
    // lock is recovered from rather than propagated.
    let mut guard = slot.lock().unwrap_or_else(|p| p.into_inner());
    let replaced = match guard.take() {
        Some(previous) => {
            previous.abort();
            true
        }
        None => false,
    };
    *guard = Some(spawn());
    replaced
}

/// Abort the listener in the slot, if one is there. Returns whether a handle
/// was taken and aborted; `false` means the listener had already finished on
/// its own (or never started).
#[cfg(feature = "gui")]
fn cancel_listener(slot: &ListenSlot) -> bool {
    let mut guard = slot.lock().unwrap_or_else(|p| p.into_inner());
    match guard.take() {
        Some(handle) => {
            handle.abort();
            true
        }
        None => false,
    }
}

/// One outbound connect, and the channel carrying this user's typed plaintext
/// into *that* session and no other.
///
/// `id` is what makes a late cleanup harmless: a task that finishes after the
/// slot has moved on names its own session when it closes, so it cannot take
/// down a successor's channel.
#[cfg(feature = "gui")]
struct ChatSession {
    id: u64,
    stdin_tx: mpsc::Sender<Vec<u8>>,
}

/// The one slot holding the connect in flight, if any.
///
/// A `std` mutex, not a `tokio` one, for the same reason as [`ListenSlot`]:
/// the press that claims it and the send that reads it both arrive on the
/// Slint event-loop thread, and the claim has to happen in the same turn as
/// the press. It is never held across an await.
#[cfg(feature = "gui")]
type ChatSessionSlot = std::sync::Mutex<Option<ChatSession>>;

/// Session ids are only ever compared for equality, never ordered or shown, so
/// a plain counter is enough. It is process-wide because the slot is.
#[cfg(feature = "gui")]
static NEXT_CHAT_SESSION_ID: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(1);

/// Claim the connect slot for a new session, handing back its id and the IO
/// provider that reads *its* stdin channel. `None` means a connect is already
/// in flight and this one must be refused.
///
/// The freshly created channel is the point. One process-wide channel, whose
/// single receiver every `GuiStdin` shared, bound a typed line to no session at
/// all: whichever session happened to poll first encrypted it, so a line meant
/// for the peer the user believed they were talking to could be sent to another
/// peer entirely. A channel created here, reachable only through the provider
/// returned here, cannot be read by any other session.
#[cfg(feature = "gui")]
fn open_connect_session(
    slot: &ChatSessionSlot,
    stdout_tx: &mpsc::Sender<Vec<u8>>,
) -> Option<(u64, Arc<GuiIOProvider>)> {
    // A panic elsewhere must not wedge the connect button forever, so a
    // poisoned lock is recovered from rather than propagated.
    let mut guard = slot.lock().unwrap_or_else(|p| p.into_inner());
    if guard.is_some() {
        return None;
    }
    let id = NEXT_CHAT_SESSION_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let (stdin_tx, stdin_rx) = mpsc::channel(100);
    *guard = Some(ChatSession { id, stdin_tx });
    // The transcript sender is shared on purpose: peer text from any session
    // lands in the one message list, exactly as before.
    let provider = Arc::new(GuiIOProvider {
        stdin_rx: Arc::new(tokio::sync::Mutex::new(stdin_rx)),
        stdout_tx: stdout_tx.clone(),
    });
    Some((id, provider))
}

/// Close session `id`: take it out of the slot and drop its sender, so the
/// session's reader sees EOF and nothing typed later can reach it. Returns
/// whether this call closed it; `false` means the slot was empty or had
/// already moved on to another session, which must not be disturbed.
#[cfg(feature = "gui")]
fn end_connect_session(slot: &ChatSessionSlot, id: u64) -> bool {
    let mut guard = slot.lock().unwrap_or_else(|p| p.into_inner());
    match guard.as_ref() {
        Some(session) if session.id == id => {
            *guard = None;
            true
        }
        _ => false,
    }
}

/// The sender of the session that is live *now*, or `None` when none is.
///
/// `None` means the line is dropped. Queueing it instead — the old behaviour of
/// the process-wide channel — is precisely the bug: text typed with no session
/// live would sit in the channel until some later session, with some other
/// peer, read and encrypted it.
#[cfg(feature = "gui")]
fn current_chat_sender(slot: &ChatSessionSlot) -> Option<mpsc::Sender<Vec<u8>>> {
    let guard = slot.lock().unwrap_or_else(|p| p.into_inner());
    guard.as_ref().map(|session| session.stdin_tx.clone())
}

/// Owns one outbound connect for the lifetime of the task that runs it.
///
/// Dropping it closes the session and clears `connecting`, on every exit path
/// the task has — early return, error, normal end, panic unwind — so no path
/// can leave a claimed slot (which would refuse every later connect) or a
/// permanently dead action button behind.
///
/// How long the dialled peer can keep it claimed is worth knowing: a peer that
/// accepts the connection and then stalls holds `connecting` true for the
/// bounded worst case of the dial ladder in `p2p::processor` (`CONNECT_TIMEOUTS`
/// 3+5+8+12+12 s plus 4×1 s backoff = 44 s) followed by `handshake_timeout`
/// (`config.rs`, 15 s by default) — about 59 s, after which this guard drops
/// and the button comes back. It is bounded, self-clearing and only ever
/// started by the user's own press, so a stalling peer can delay the next
/// connect but cannot block it.
#[cfg(feature = "gui")]
struct ConnectSessionGuard {
    slot: Arc<ChatSessionSlot>,
    id: u64,
    ui: slint::Weak<ChatWindow>,
}

#[cfg(feature = "gui")]
impl Drop for ConnectSessionGuard {
    fn drop(&mut self) {
        // Close first, report second: the sender is gone before the UI offers
        // the button that could start the next session.
        end_connect_session(&self.slot, self.id);
        let _ = self.ui.upgrade_in_event_loop(|ui| ui.set_connecting(false));
    }
}

#[cfg(feature = "gui")]
pub async fn run_gui() -> Result<(), Box<dyn std::error::Error>> {
    let ui = ChatWindow::new()?;
    let ui_handle = ui.as_weak();

    let (stdout_tx, stdout_rx) = mpsc::channel::<Vec<u8>>(100);
    
    // Channel for M1 passphrase response: (passphrase, ticket, privkey, pubkey)
    let (pass_tx, mut pass_rx) = mpsc::channel::<(Zeroizing<String>, String, String, String)>(1);

    // The stdin side is deliberately NOT built here. Each connect gets its own
    // channel and its own `GuiIOProvider` from `open_connect_session`, so there
    // is no shared receiver for a second session to read a typed line from.
    let chat_session: Arc<ChatSessionSlot> = Arc::new(std::sync::Mutex::new(None));

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
    let chat_session_for_connect = chat_session.clone();
    let stdout_tx_for_connect = stdout_tx.clone();
    ui.on_connect_pressed(move |ticket, privkey, pubkey| {
        let ui_handle = ui_handle_conn.clone();
        let ticket = ticket.to_string();
        let privkey = privkey.to_string();
        let pubkey = pubkey.to_string();

        // Read transfer mode and selected file path from UI (UI thread)
        let (mode, selected_file_path) = if let Some(ui) = ui_handle_for_connect.upgrade() {
            (ui.get_transfer_mode(), ui.get_selected_file_path().to_string())
        } else {
            return;
        };

        // Claim the connect slot now, synchronously, on the event-loop thread
        // where every press arrives. A refusal here is the second line of
        // defence behind `connecting` below: whatever the UI does, only one
        // session can hold the typed-plaintext channel, so a line can never be
        // handed to a session other than the one it was typed into.
        let Some((session_id, session_provider)) =
            open_connect_session(&chat_session_for_connect, &stdout_tx_for_connect)
        else {
            if let Some(ui) = ui_handle_for_connect.upgrade() {
                ui.set_connection_error("A connection is already in progress.".into());
            }
            return;
        };

        // Mark the UI busy in the same turn as the press, the way the listen
        // press sets `listening`. The action button is gated on `!connecting`
        // (chat.slint `start-action-enabled`), so this is what makes a second
        // press impossible during the seconds between the press and the
        // handshake that sets `connected`. Only that button goes dead: the
        // mode selector and the ticket/key fields around it stay usable.
        if let Some(ui) = ui_handle_for_connect.upgrade() {
            ui.set_connecting(true);
        }
        let session_guard = ConnectSessionGuard {
            slot: chat_session_for_connect.clone(),
            id: session_id,
            ui: ui_handle_for_connect.clone(),
        };

        tokio::spawn(async move {
            // Every exit below — including the early returns — releases the
            // slot and the button through this drop.
            let _session_guard = session_guard;
            let mut config = build_connect_config(&ticket, &privkey, &pubkey);

            // Branch on transfer mode: Chat uses this session's GuiIOProvider,
            // FileSend builds a FileIOProvider with the selected file as input.
            let mut total_send_bytes: Option<u64> = None;
            let (io_provider, is_file_mode): (Arc<dyn crate::network::IOProvider>, bool) = match mode {
                TransferMode::Chat => {
                    config.chat_mode = true;
                    (session_provider, false)
                }
                TransferMode::FileSend => {
                    config.chat_mode = false;
                    // A file send has no chat input. Drop the session's reader
                    // so its channel is closed: a line that somehow reached the
                    // sender is refused rather than buffered in a channel no
                    // one will ever read.
                    drop(session_provider);
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
    let listen_task: Arc<ListenSlot> = Arc::new(std::sync::Mutex::new(None));
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

        // Mark the UI busy now, synchronously, on the event-loop thread. The
        // button that reaches this handler sits in a panel gated on
        // `!listening` (chat.slint `connection-settings-visible`), so this is
        // what makes a second press impossible during the seconds it takes the
        // listener to come up and call `on_ticket`. It also puts Cancel on
        // screen (`listen-display-visible`) for that whole window instead of
        // only after the ticket appears. Any stale ticket text is cleared with
        // it: the panel is now visible before a ticket exists, and showing a
        // previous one there would present a dead ticket as the live one.
        if let Some(ui) = ui_handle_listen.upgrade() {
            ui.set_listening(true);
            ui.set_generated_ticket("".into());
        }

        install_listener(&listen_task, move || tokio::spawn(async move {
            let config = build_file_receive_config(&privkey, &pubkey);

            let file_io = match crate::network::FileIOProvider::new_recv(recv_path.clone()).await {
                Ok(p) => Arc::new(p),
                Err(e) => {
                    let ui_handle = ui_handle.clone();
                    let msg = format!("Cannot create receive file: {}", e);
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_handle.upgrade() {
                            // `listening` was set by the press; this listener
                            // never came up, so hand the controls back rather
                            // than leaving the user in a "waiting" panel with
                            // nothing behind it.
                            ui.set_listening(false);
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
                        // Same as above: no listener came up, so `listening`
                        // must not stay set.
                        ui.set_listening(false);
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
                        // Same as above: no listener came up, so `listening`
                        // must not stay set.
                        ui.set_listening(false);
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
        }));
    });

    let listen_task_for_cancel = listen_task.clone();
    let ui_handle_cancel = ui_handle.clone();
    ui.on_listen_cancel(move || {
        // Abort first, then report — and both on the event-loop thread, so the
        // listener is dead before the UI claims it is. `install_listener` put
        // the handle in the slot in the same event-loop turn as the press that
        // set `listening`, so there is no turn in which Cancel is reachable and
        // the slot is empty: `false` here means the listener had already
        // finished by itself, not that one is still running unheld.
        let _aborted = cancel_listener(&listen_task_for_cancel);
        if let Some(ui) = ui_handle_cancel.upgrade() {
            ui.set_listening(false);
            ui.set_generated_ticket("".into());
            ui.set_connection_error("Listen cancelled.".into());
        }
    });

    let ui_handle_pass_retry = ui_handle.clone();
    let chat_session_for_pass = chat_session.clone();
    let stdout_tx_for_pass = stdout_tx.clone();
    tokio::spawn(async move {
        while let Some((passphrase, ticket, privkey, pubkey)) = pass_rx.recv().await {
            // The unlocked retry is a chat session like any other, so it takes
            // the slot like any other: its own channel, and a refusal if a
            // session is already live rather than a second consumer of one.
            let Some((session_id, session_provider)) =
                open_connect_session(&chat_session_for_pass, &stdout_tx_for_pass)
            else {
                ui_handle_pass_retry.upgrade_in_event_loop(|ui| {
                    ui.set_connection_error("A connection is already in progress.".into());
                }).ok();
                continue;
            };
            ui_handle_pass_retry.upgrade_in_event_loop(|ui| {
                ui.set_connecting(true);
            }).ok();
            // Dropped at the end of this iteration, and on the early `return`
            // below, so the slot and the button are never left claimed.
            let _session_guard = ConnectSessionGuard {
                slot: chat_session_for_pass.clone(),
                id: session_id,
                ui: ui_handle_pass_retry.clone(),
            };

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
            let processor = crate::p2p::NetworkProcessor::new(config, endpoint, session_provider);
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

    let chat_session_for_send = chat_session.clone();
    let ui_handle_send = ui_handle.clone();
    ui.on_send_message(move |text| {
        // Take the sender of the session that is live in *this* event-loop
        // turn. There is no other sender to take: the channel belongs to that
        // one session, so the line cannot be read by a different peer's.
        let Some(stdin_tx) = current_chat_sender(&chat_session_for_send) else {
            // Nothing is live. The line is dropped, deliberately: holding it
            // for the next session is how it would reach a peer the user never
            // typed it for. Say so rather than swallowing it silently.
            if let Some(ui) = ui_handle_send.upgrade() {
                ui.set_connection_error("Not sent: no chat session is active.".into());
            }
            return;
        };
        let text = text.to_string() + "\n";
        let ui_handle = ui_handle_send.clone();
        tokio::spawn(async move {
            // The session can still end between the two, and then this send
            // fails against a dropped receiver — which is the outcome we want:
            // the line goes nowhere, and the user is told it did not go.
            if stdin_tx.send(text.into_bytes()).await.is_err() {
                ui_handle.upgrade_in_event_loop(|ui| {
                    ui.set_connection_error("Not sent: the chat session ended.".into());
                }).ok();
            }
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

/// Discipline of the single file-receive listener slot: a listener must never
/// outlive the handle that can stop it.
///
/// These drive `install_listener` / `cancel_listener` — the two functions the
/// "Generate Ticket and Wait" and "Cancel" handlers are made of — because the
/// handlers themselves need a Slint event loop. A never-ending task stands in
/// for a listener that is still accepting connections on a circulated ticket;
/// aborting it drops its future, which is what the witness records.
#[cfg(all(test, feature = "gui"))]
mod listen_slot_tests {
    use super::{ListenSlot, cancel_listener, install_listener};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    /// Set when the task it lives in is dropped — i.e. when the task was
    /// aborted (these tasks never finish on their own).
    struct AbortWitness(Arc<AtomicBool>);

    impl Drop for AbortWitness {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    fn listener_that_never_ends(aborted: Arc<AtomicBool>) -> tokio::task::JoinHandle<()> {
        // The witness is built here, not inside the body, so it is owned by the
        // future from the moment the future exists: a task aborted before its
        // first poll must count as aborted too.
        let witness = AbortWitness(aborted);
        tokio::spawn(async move {
            let _witness = witness;
            loop {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
    }

    async fn became_true(flag: &Arc<AtomicBool>) -> bool {
        for _ in 0..200 {
            if flag.load(Ordering::SeqCst) {
                return true;
            }
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        flag.load(Ordering::SeqCst)
    }

    /// The finding: pressing "Generate Ticket and Wait" a second time used to
    /// overwrite the slot, detaching the first listener — still live, still
    /// holding a valid ticket, and no longer reachable from Cancel.
    #[tokio::test]
    async fn a_second_press_aborts_the_listener_already_in_the_slot() {
        let slot: ListenSlot = std::sync::Mutex::new(None);
        let first_aborted = Arc::new(AtomicBool::new(false));

        let witness = first_aborted.clone();
        assert!(
            !install_listener(&slot, move || listener_that_never_ends(witness)),
            "the first press has no predecessor to abort"
        );
        tokio::task::yield_now().await;
        assert!(
            !first_aborted.load(Ordering::SeqCst),
            "the first listener must be running before the second press"
        );

        let second_aborted = Arc::new(AtomicBool::new(false));
        let witness = second_aborted.clone();
        assert!(
            install_listener(&slot, move || listener_that_never_ends(witness)),
            "the second press must find the first listener and report aborting it"
        );
        assert!(
            became_true(&first_aborted).await,
            "the first listener must be aborted, not orphaned: it would otherwise keep \
             accepting transfers on a ticket the user believes is dead"
        );
    }

    /// Cancel must be total: after the double press above, no listener at all
    /// survives it.
    #[tokio::test]
    async fn cancel_after_a_second_press_leaves_no_live_listener() {
        let slot: ListenSlot = std::sync::Mutex::new(None);
        let first_aborted = Arc::new(AtomicBool::new(false));
        let second_aborted = Arc::new(AtomicBool::new(false));

        let witness = first_aborted.clone();
        install_listener(&slot, move || listener_that_never_ends(witness));
        let witness = second_aborted.clone();
        install_listener(&slot, move || listener_that_never_ends(witness));
        // Let both actually get running, as a real listener would be.
        tokio::task::yield_now().await;

        assert!(
            cancel_listener(&slot),
            "Cancel must find a handle to abort"
        );
        assert!(became_true(&first_aborted).await, "first listener still live after Cancel");
        assert!(became_true(&second_aborted).await, "second listener still live after Cancel");
    }

    /// Cancel empties the slot, so a later Cancel has nothing to take — and
    /// says so, rather than claiming to have stopped something.
    #[tokio::test]
    async fn cancel_is_idempotent_and_reports_an_empty_slot() {
        let slot: ListenSlot = std::sync::Mutex::new(None);
        assert!(!cancel_listener(&slot), "nothing to cancel before any press");

        let aborted = Arc::new(AtomicBool::new(false));
        let witness = aborted.clone();
        install_listener(&slot, move || listener_that_never_ends(witness));

        assert!(cancel_listener(&slot));
        assert!(became_true(&aborted).await, "the listener must be aborted");
        assert!(!cancel_listener(&slot), "the slot must be empty after a cancel");
    }

    /// A poisoned lock must not turn into an unstoppable listener.
    #[tokio::test]
    async fn a_poisoned_slot_can_still_be_cancelled() {
        let slot: Arc<ListenSlot> = Arc::new(std::sync::Mutex::new(None));
        let aborted = Arc::new(AtomicBool::new(false));
        let witness = aborted.clone();
        install_listener(&slot, move || listener_that_never_ends(witness));

        let poisoner = slot.clone();
        let _ = std::thread::spawn(move || {
            let _guard = poisoner.lock().unwrap();
            panic!("poison the listener slot");
        })
        .join();
        assert!(slot.is_poisoned());

        assert!(cancel_listener(&slot), "a poisoned slot must still yield its handle");
        assert!(became_true(&aborted).await, "the listener must be aborted");
    }
}

/// Discipline of the chat session slot: a line the user typed reaches the
/// session it was typed into, or no session at all.
///
/// These drive `open_connect_session` / `end_connect_session` /
/// `current_chat_sender` — the three functions the connect press, the connect
/// task's cleanup and the send handler are made of — because the handlers
/// themselves need a Slint event loop. Reading from the provider each session
/// is given is the point: it is exactly what `chat_loop` does with the bytes
/// before encrypting them for that session's peer.
#[cfg(all(test, feature = "gui"))]
mod chat_session_tests {
    use super::{ChatSessionSlot, current_chat_sender, end_connect_session, open_connect_session};
    use crate::network::IOProvider;
    use tokio::io::AsyncReadExt;

    /// Long enough that a delivery would have landed; the clock is paused in
    /// the tests that wait on it, so it costs no wall time.
    const PROBE: std::time::Duration = std::time::Duration::from_secs(1);

    fn empty_slot() -> ChatSessionSlot {
        std::sync::Mutex::new(None)
    }

    /// The transcript channel every session shares — the display side, which
    /// this change deliberately leaves shared.
    fn transcript() -> (
        tokio::sync::mpsc::Sender<Vec<u8>>,
        tokio::sync::mpsc::Receiver<Vec<u8>>,
    ) {
        tokio::sync::mpsc::channel::<Vec<u8>>(8)
    }

    /// Two connects must not run at once: the second press is refused rather
    /// than given a second claim on the one typed-plaintext channel.
    #[tokio::test]
    async fn a_second_connect_is_refused_while_one_is_in_flight() {
        let (stdout_tx, _stdout_rx) = transcript();
        let slot = empty_slot();

        let (first_id, _first) = open_connect_session(&slot, &stdout_tx)
            .expect("the first connect must claim the free slot");
        assert!(
            open_connect_session(&slot, &stdout_tx).is_none(),
            "a second connect must be refused while the first is in flight"
        );

        assert!(end_connect_session(&slot, first_id), "the session must close");
        let (second_id, _second) = open_connect_session(&slot, &stdout_tx)
            .expect("the slot must be free once the session that held it ended");
        assert_ne!(
            first_id, second_id,
            "each session must be distinguishable from the one before it"
        );
    }

    /// The finding, directly: a line typed into the live session must be
    /// readable only by that session. Before the fix both sessions read one
    /// process-wide channel, so whichever polled first encrypted the line —
    /// possibly for a peer the user never typed it for.
    #[tokio::test(start_paused = true)]
    async fn a_typed_line_reaches_only_the_session_it_was_typed_into() {
        let (stdout_tx, _stdout_rx) = transcript();
        let slot = empty_slot();

        // A session with the first peer, which then ends.
        let (first_id, first) = open_connect_session(&slot, &stdout_tx).expect("first session");
        let mut first_stdin = first.stdin();
        assert!(end_connect_session(&slot, first_id));

        // The user connects to a second peer and types a line.
        let (_second_id, second) = open_connect_session(&slot, &stdout_tx).expect("second session");
        let mut second_stdin = second.stdin();
        let sender = current_chat_sender(&slot).expect("the live session must have a sender");
        sender
            .send(b"meet me at the safe house\n".to_vec())
            .await
            .expect("the live session's channel must accept the line");

        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(PROBE, second_stdin.read(&mut buf))
            .await
            .expect("the live session must receive what was typed into it")
            .expect("its reader must not error");
        assert_eq!(&buf[..n], b"meet me at the safe house\n");

        // The first peer's session must see end-of-input, never the line.
        let n = tokio::time::timeout(PROBE, first_stdin.read(&mut buf))
            .await
            .expect("an ended session's reader must be at EOF, not waiting for input")
            .expect("its reader must not error");
        assert_eq!(
            n, 0,
            "a line typed for the live session must never be readable by another peer's"
        );
    }

    /// A sender captured while a session was live must not be able to deliver
    /// once that session has ended — the "the session ended between `send` and
    /// the loop's next read" case. It fails; it does not spill into whatever
    /// session came next.
    #[tokio::test(start_paused = true)]
    async fn a_sender_from_an_ended_session_cannot_deliver_into_the_next_one() {
        let (stdout_tx, _stdout_rx) = transcript();
        let slot = empty_slot();

        let (first_id, first) = open_connect_session(&slot, &stdout_tx).expect("first session");
        let stale_sender = current_chat_sender(&slot).expect("a live session has a sender");
        assert!(end_connect_session(&slot, first_id));
        // The task that ran the session is gone, and its reader with it.
        drop(first);

        let (_second_id, second) = open_connect_session(&slot, &stdout_tx).expect("second session");
        let mut second_stdin = second.stdin();
        assert!(
            stale_sender.send(b"for the first peer only\n".to_vec()).await.is_err(),
            "a send on an ended session must fail rather than be re-routed"
        );

        let mut buf = [0u8; 64];
        assert!(
            tokio::time::timeout(PROBE, second_stdin.read(&mut buf)).await.is_err(),
            "the new session must receive nothing that was typed for the old one"
        );
    }

    /// With no session live there is nothing to send into. The line is dropped
    /// — the alternative, holding it until the next connect, is the bug.
    #[tokio::test(start_paused = true)]
    async fn a_line_typed_with_no_live_session_has_nowhere_to_go() {
        let (stdout_tx, _stdout_rx) = transcript();
        let slot = empty_slot();

        assert!(
            current_chat_sender(&slot).is_none(),
            "before any connect there is no session to type into"
        );

        let (id, session) = open_connect_session(&slot, &stdout_tx).expect("session");
        let mut stdin = session.stdin();
        assert!(end_connect_session(&slot, id));
        assert!(
            current_chat_sender(&slot).is_none(),
            "the sender must go with the session, so a later line cannot be queued for the \
             peer that connects next"
        );

        let mut buf = [0u8; 8];
        let n = tokio::time::timeout(PROBE, stdin.read(&mut buf))
            .await
            .expect("the ended session's reader must be at EOF")
            .expect("its reader must not error");
        assert_eq!(n, 0, "dropping the sender is what ends the session's input");
    }

    /// Cleanup names the session it is cleaning up. A task that finishes late
    /// must not close the session that replaced it — that would leave a live
    /// chat with no sender, and the user's next line silently dropped.
    #[tokio::test(start_paused = true)]
    async fn a_late_cleanup_cannot_close_the_session_that_replaced_it() {
        let (stdout_tx, _stdout_rx) = transcript();
        let slot = empty_slot();

        let (stale_id, _stale) = open_connect_session(&slot, &stdout_tx).expect("first session");
        assert!(end_connect_session(&slot, stale_id));

        let (live_id, live) = open_connect_session(&slot, &stdout_tx).expect("second session");
        let mut live_stdin = live.stdin();
        assert!(
            !end_connect_session(&slot, stale_id),
            "closing an already-closed session must not touch the slot"
        );

        let sender = current_chat_sender(&slot).expect("the live session must still be there");
        sender.send(b"still mine\n".to_vec()).await.expect("still deliverable");
        let mut buf = [0u8; 32];
        let n = tokio::time::timeout(PROBE, live_stdin.read(&mut buf))
            .await
            .expect("the live session must still receive")
            .expect("its reader must not error");
        assert_eq!(&buf[..n], b"still mine\n");

        assert!(end_connect_session(&slot, live_id), "its own id still closes it");
    }

    /// A panic elsewhere must not wedge the connect button: the slot is
    /// recovered from poisoning rather than propagating it.
    #[tokio::test]
    async fn a_poisoned_slot_can_still_be_claimed_and_closed() {
        let (stdout_tx, _stdout_rx) = transcript();
        let slot = std::sync::Arc::new(empty_slot());

        let poisoner = slot.clone();
        let _ = std::thread::spawn(move || {
            let _guard = poisoner.lock().unwrap();
            panic!("poison the chat session slot");
        })
        .join();
        assert!(slot.is_poisoned());

        let (id, _session) = open_connect_session(&slot, &stdout_tx)
            .expect("a poisoned slot must still admit a session");
        assert!(current_chat_sender(&slot).is_some());
        assert!(end_connect_session(&slot, id));
    }

    /// The UI side of the same rule, and its limit: `connecting` must kill the
    /// action button — set on the press, not on the handshake — and nothing
    /// else. The panel around that button holds the mode selector and the
    /// ticket and key fields, and taking those away would cost the user a
    /// capability this finding never asked to remove.
    #[test]
    fn connecting_disables_the_action_button_and_nothing_around_it() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = super::ChatWindow::new().expect("build the window against the test backend");

        assert!(ui.get_connection_settings_visible(), "idle: the panel is on screen");
        assert!(ui.get_start_action_enabled(), "idle: the action button is live");
        assert!(!ui.get_connecting_display_visible());

        ui.set_connecting(true);
        assert!(
            !ui.get_start_action_enabled(),
            "a connect in flight must kill the action button, rather than leaving it \
             pressable until the handshake sets `connected`"
        );
        assert!(
            ui.get_connection_settings_visible(),
            "but the panel must stay: the mode selector and the ticket/key fields around \
             the button are still the user's to see and change during a connect"
        );
        assert!(
            ui.get_connecting_display_visible(),
            "and the window must say a connect is in progress"
        );
        assert!(!ui.get_listening(), "the connect flow must not set the listen flag");

        ui.set_connecting(false);
        assert!(ui.get_start_action_enabled(), "the button comes back when the connect ends");

        // The listen flow keeps its own, wider gate from ae7d35b4 — the whole
        // panel goes while a listener is up — and the two flags stay separate.
        ui.set_listening(true);
        assert!(
            !ui.get_connection_settings_visible(),
            "a listener in flight still takes the panel down, as it did before"
        );
        assert!(!ui.get_connecting(), "the listen flow must not set the connect flag");
    }

    /// The mode selector stays reachable in every mode while a connect runs,
    /// which is what makes "switch to File Receive during a connect" still
    /// possible — up to the shared action button, which is disabled.
    #[test]
    fn the_mode_specific_rows_survive_a_connect_in_flight() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = super::ChatWindow::new().expect("build the window against the test backend");
        ui.set_connecting(true);

        ui.set_transfer_mode(super::TransferMode::FileSend);
        assert!(
            ui.get_file_picker_visible(),
            "the file chooser must not vanish because a connect is in flight"
        );

        ui.set_transfer_mode(super::TransferMode::FileReceive);
        assert!(
            ui.get_save_dir_visible(),
            "nor the save-directory row: a receive listener is a separate flow that never \
             touches the chat plaintext channel"
        );
    }
}

// The tests that lived here exercised `extract_peer_id`'s panic-safety on
// malformed remote input (`"] ["`, `"[unterminated"`, …). They went with the
// function: nothing parses a label out of a peer's message any more, so there
// is no longer a parser to keep panic-safe. The property that replaced them —
// that a notification body never carries peer-authored markup — is tested in
// `gui::notifications`.
