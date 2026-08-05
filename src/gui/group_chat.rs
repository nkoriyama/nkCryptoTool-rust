//! Slint driver for the MLS group chat window (P8).
//!
//! Builds the `GroupChatWindow` Slint component, wires its callbacks
//! into a long-lived [`GroupChatProcessor`], and runs an inbound task
//! that pushes `accept_next` events into the UI model.
//!
//! All UI mutations cross thread boundaries through
//! [`slint::invoke_from_event_loop`] — the Slint event loop is the
//! single owner of the model, while tokio tasks own the processor.
//! Errors surface in the status bar (red) rather than printing to
//! stderr; the user keeps a usable window even after a backend hiccup.
//! The exception is the inbound task, whose per-connection errors are
//! peer-paced: those become `[err]` rows in the message list, which is
//! bounded and coalesced, and only a closed endpoint stops the task.
//!
//! The processor here is built fresh against a sqlite path and an
//! `Arc<dyn P2pEndpoint>` passed in by `main.rs` so this module is
//! transport-agnostic — tests can drive it through `MockEndpoint`.
//!
//! Acceptance per `MLS_GROUP_CHAT_PLAN.md` §P8 is "groups list +
//! send/receive UI"; admin operations (add/remove) live in the same
//! window via a sub-form, matching plan §8.2.
//!
//! ## Threading sketch
//!
//! ```text
//!  ┌──────────────────────┐        ┌──────────────────────────┐
//!  │ Slint event loop     │        │ tokio inbound task       │
//!  │  ─ holds UI model    │  ◄──┐  │  loop {                  │
//!  │  ─ fires callbacks   │     │  │    accept_next().await   │
//!  │  ─ on_*(closure)     │     │  │      → render            │
//!  └──────────────────────┘     │  │      → invoke_from_      │
//!         │   tokio::spawn      │  │        event_loop(...)   │
//!         ▼                     │  │  }                       │
//!  ┌──────────────────────┐     │  └──────────────────────────┘
//!  │ per-callback worker  │ ────┘
//!  │  ─ create_group, etc │
//!  │  ─ refresh on done   │
//!  └──────────────────────┘
//! ```

#![cfg(feature = "gui-mls")]

use std::path::PathBuf;
use std::sync::Arc;

use slint::{ComponentHandle, Model, ModelRc, SharedString, StandardListViewItem, VecModel, Weak};

use crate::group::{
    cli, GroupChatProcessor, GroupId, IncomingGroupEvent,
};

// `slint::include_modules!()` at `crate::gui` exposes the generated
// `GroupChatWindow` type; we re-import it here for ergonomics.
use crate::gui::GroupChatWindow;

// The 1:1 chat window's bounds, reused rather than re-derived: both windows
// feed a `StandardListView` of `StandardListViewItem` from peer-paced text,
// so the ceilings and the reasoning behind them are the same. See
// `crate::gui` for why each number is what it is.
use crate::gui::{ChatRowQueue, MAX_CHAT_ROWS, MAX_CHAT_ROW_CHARS};

/// Run the MLS group chat GUI. Blocks the calling task until the user
/// closes the window or the Slint event loop exits.
///
/// `processor` is the long-lived MLS state owner. It is wrapped in
/// `Arc` so callback workers can share it; the inbound `accept_next`
/// task takes its own clone.
pub async fn run_group_gui(
    processor: Arc<GroupChatProcessor>,
) -> Result<(), Box<dyn std::error::Error>> {
    let ui = GroupChatWindow::new()?;
    let ui_handle = ui.as_weak();

    // Initial state: populate own ticket and the groups list.
    {
        let ticket_str = cli::print_local_address(&processor)
            .await
            .unwrap_or_else(|e| format!("(local_addr error: {e})"));
        ui.set_own_ticket(SharedString::from(ticket_str.as_str()));
    }
    refresh_groups_async(&ui, &processor).await;

    // -------- callback wiring ----------------------------------------
    // Most callbacks just kick off a tokio task that runs an
    // async handler, then refreshes the model on completion.

    // Create group.
    wire_create_group(&ui, ui_handle.clone(), Arc::clone(&processor));
    // Group row selected.
    wire_group_selected(&ui, ui_handle.clone(), Arc::clone(&processor));
    // Send application message.
    wire_send_message(&ui, ui_handle.clone(), Arc::clone(&processor));
    // Add member.
    wire_add_member(&ui, ui_handle.clone(), Arc::clone(&processor));
    // Export key package — opens an "out path" using a fixed location
    // for simplicity; a save-as dialog would require the
    // `gui-file-transfer` feature. Falls back to $HOME/keypackage.bin.
    wire_export_kp(&ui, ui_handle.clone(), Arc::clone(&processor));
    // Refresh / copy-ticket: pure local actions, no backend roundtrip.
    wire_refresh(&ui, ui_handle.clone(), Arc::clone(&processor));
    wire_copy_ticket(&ui);

    // -------- inbound task -------------------------------------------
    let inbound_proc = Arc::clone(&processor);
    let inbound_ui = ui_handle.clone();
    // A group member paces `accept_next` and Slint's event-loop queue is
    // unbounded, so rows are staged here instead of posting one closure per
    // event — see `push_event_into_ui`.
    let inbound_rows = Arc::new(ChatRowQueue::new());
    tokio::spawn(async move {
        loop {
            match inbound_proc.accept_next().await {
                Ok(evt) => {
                    push_event_into_ui(&inbound_ui, &inbound_rows, evt);
                }
                Err(e) => {
                    if inbound_error_is_fatal(&e) {
                        // The endpoint is gone (shutdown): nothing can ever
                        // arrive again, so report once and leave the loop. The
                        // only fatal variant's `Display` is fixed text with no
                        // peer input in it, so it needs no sanitizing.
                        set_status(&inbound_ui, format!("inbound: {e}"), true);
                        break;
                    }
                    // Every other error is scoped to the one incoming
                    // connection that produced it. Surface it and keep
                    // accepting, exactly as the CLI twin does — see
                    // `inbound_error_is_fatal`.
                    push_row_into_ui(&inbound_ui, &inbound_rows, render_inbound_error(&e));
                }
            }
        }
    });

    // Hand control to the Slint event loop. Blocks until the user
    // closes the window. `run()` is non-async and must run on the
    // main thread of the Slint event loop.
    ui.run()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Callback wiring helpers
// ---------------------------------------------------------------------------

fn wire_create_group(
    ui: &GroupChatWindow,
    ui_handle: Weak<GroupChatWindow>,
    processor: Arc<GroupChatProcessor>,
) {
    ui.on_create_group_pressed(move |name| {
        let proc_clone = Arc::clone(&processor);
        let ui_h = ui_handle.clone();
        // `on_*` closures run on the Slint event loop thread; we
        // hand the actual MLS work off to a tokio task to keep the UI
        // responsive while the cipher suite generates the group's
        // initial keys (a few ms even with the hybrid suite, but
        // architecturally we never block the event loop).
        tokio::spawn(async move {
            match cli::create_group(&proc_clone, name.as_str()).await {
                Ok(gid) => {
                    set_status(
                        &ui_h,
                        format!("Created group {gid}"),
                        false,
                    );
                    refresh_groups_invoke(&ui_h, &proc_clone);
                }
                Err(e) => set_status(&ui_h, format!("create_group: {e}"), true),
            }
        });
    });
}

fn wire_group_selected(
    ui: &GroupChatWindow,
    ui_handle: Weak<GroupChatWindow>,
    processor: Arc<GroupChatProcessor>,
) {
    ui.on_group_selected(move |row| {
        let proc_clone = Arc::clone(&processor);
        let ui_h = ui_handle.clone();
        // Resolve the click against the row the user actually saw, here on
        // the event-loop thread, and carry the *identity* into the worker.
        // Resolving the index later against a freshly-listed `list_groups`
        // was a TOCTOU: that list is storage-ordered and a remote peer grows
        // it unauthenticated — an unsolicited Welcome auto-joins a group
        // whose 32-byte id the sender chose, so an id sorting below ours
        // shifts every row and the click lands on the attacker's group,
        // which then becomes `selected_group_id`, the sole authorization
        // input to Add Member.
        let row = row as usize;
        let gid = match selected_row_group_id(&ui_h, row) {
            Ok(g) => g,
            Err(e) => {
                set_status(&ui_h, e, true);
                return;
            }
        };
        tokio::spawn(async move {
            let groups = match cli::list_groups(&proc_clone).await {
                Ok(g) => g,
                Err(e) => {
                    set_status(&ui_h, format!("list_groups: {e}"), true);
                    return;
                }
            };
            // The row is stale in the other direction too: the group it names
            // may have been left/removed since the model was populated. Reject
            // rather than fall through to a neighbouring group.
            if !groups.contains(&gid) {
                set_status(&ui_h, format!("group {gid} is no longer available"), true);
                return;
            }
            let members = match cli::list_members(&proc_clone, &gid).await {
                Ok(m) => m,
                Err(e) => {
                    set_status(&ui_h, format!("list_members: {e}"), true);
                    return;
                }
            };
            let gid_str = gid.to_string();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_h.upgrade() {
                    ui.set_selected_group_id(SharedString::from(gid_str.as_str()));
                    let m = VecModel::<StandardListViewItem>::default();
                    for info in &members {
                        m.push(StandardListViewItem::from(SharedString::from(
                            format!("leaf {}", info.index).as_str(),
                        )));
                    }
                    ui.set_members(ModelRc::new(m));
                    // Clear the message log on group switch — the
                    // history view is per-session (P9 may add
                    // persistent message log; mls-rs does not save
                    // application bodies, only key state).
                    ui.set_messages(ModelRc::new(VecModel::<StandardListViewItem>::default()));
                    ui.set_status(SharedString::from(""));
                    ui.set_status_is_error(false);
                }
            });
        });
    });
}

fn wire_send_message(
    ui: &GroupChatWindow,
    ui_handle: Weak<GroupChatWindow>,
    processor: Arc<GroupChatProcessor>,
) {
    ui.on_send_message_pressed(move |body| {
        let proc_clone = Arc::clone(&processor);
        let ui_h = ui_handle.clone();
        tokio::spawn(async move {
            let gid_str = match upgrade_get_selected_gid(&ui_h) {
                Some(s) if !s.is_empty() => s,
                _ => {
                    set_status(&ui_h, "no group selected".to_string(), true);
                    return;
                }
            };
            let gid = match parse_group_id(&gid_str) {
                Ok(g) => g,
                Err(e) => {
                    set_status(&ui_h, format!("parse gid: {e}"), true);
                    return;
                }
            };
            // P5 contract: caller must collect the recipients. The
            // GUI has no member→PeerAddr table yet (P9 work — needs
            // an address-book persistence layer), so for now we
            // surface an explicit error rather than silently no-op.
            // Once an address book lands, this branch becomes a
            // lookup against it.
            set_status(
                &ui_h,
                format!(
                    "send: GUI address book is not yet wired. Use \
                     the CLI `--mls-cmd send` with explicit \
                     --mls-recipient-ticket flags for group {gid}."
                ),
                true,
            );
            // Echo the local message to our own UI so the user
            // sees what they typed even though we did not transmit.
            let body_clone = body.to_string();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_h.upgrade() {
                    append_message(&ui, format!("[me, NOT SENT] {body_clone}"));
                }
            });
            // Suppress unused-Result silently — log only on error path.
            let _ = proc_clone;
        });
    });
}

fn wire_add_member(
    ui: &GroupChatWindow,
    ui_handle: Weak<GroupChatWindow>,
    processor: Arc<GroupChatProcessor>,
) {
    ui.on_add_member_pressed(move |ticket_str, kp_path_str| {
        let proc_clone = Arc::clone(&processor);
        let ui_h = ui_handle.clone();
        let ticket_str = ticket_str.to_string();
        let kp_path = PathBuf::from(kp_path_str.to_string());
        tokio::spawn(async move {
            let gid_str = match upgrade_get_selected_gid(&ui_h) {
                Some(s) if !s.is_empty() => s,
                _ => {
                    set_status(&ui_h, "no group selected".to_string(), true);
                    return;
                }
            };
            let gid = match parse_group_id(&gid_str) {
                Ok(g) => g,
                Err(e) => {
                    set_status(&ui_h, format!("parse gid: {e}"), true);
                    return;
                }
            };
            let ticket: crate::ticket::Ticket = match ticket_str.parse() {
                Ok(t) => t,
                Err(e) => {
                    set_status(&ui_h, format!("parse ticket: {e}"), true);
                    return;
                }
            };
            let recipient = ticket.peer_addr();
            match cli::add_member(&proc_clone, &gid, &kp_path, &recipient, &[]).await {
                Ok(()) => {
                    set_status(&ui_h, format!("Added member at {recipient:?}"), false);
                    refresh_groups_invoke(&ui_h, &proc_clone);
                }
                Err(e) => set_status(&ui_h, format!("add_member: {e}"), true),
            }
        });
    });
}

fn wire_export_kp(
    ui: &GroupChatWindow,
    ui_handle: Weak<GroupChatWindow>,
    processor: Arc<GroupChatProcessor>,
) {
    ui.on_export_key_package_pressed(move || {
        let proc_clone = Arc::clone(&processor);
        let ui_h = ui_handle.clone();
        tokio::spawn(async move {
            // No file dialog dependency in this build — pick a
            // predictable default path. The user can move it
            // afterwards. A future revision can pipe through the
            // gui-file-transfer rfd picker.
            let default_dir = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            let path = PathBuf::from(default_dir).join("nkct-keypackage.bin");
            match cli::export_key_package(&proc_clone, &path).await {
                Ok(()) => set_status(
                    &ui_h,
                    format!("KeyPackage written to {path:?}"),
                    false,
                ),
                Err(e) => set_status(&ui_h, format!("export_key_package: {e}"), true),
            }
        });
    });
}

fn wire_refresh(
    ui: &GroupChatWindow,
    ui_handle: Weak<GroupChatWindow>,
    processor: Arc<GroupChatProcessor>,
) {
    ui.on_refresh_pressed(move || {
        refresh_groups_invoke(&ui_handle, &processor);
    });
}

fn wire_copy_ticket(ui: &GroupChatWindow) {
    let ui_handle = ui.as_weak();
    ui.on_copy_ticket_pressed(move || {
        // arboard clipboard access. Slint already pulls in `arboard`
        // under the `gui` feature; reuse the same crate.
        if let Some(ui) = ui_handle.upgrade() {
            let ticket = ui.get_own_ticket().to_string();
            match arboard::Clipboard::new() {
                Ok(mut cb) => match cb.set_text(ticket) {
                    Ok(_) => {
                        ui.set_status(SharedString::from("Ticket copied to clipboard"));
                        ui.set_status_is_error(false);
                    }
                    Err(e) => {
                        ui.set_status(SharedString::from(
                            format!("clipboard set: {e}").as_str(),
                        ));
                        ui.set_status_is_error(true);
                    }
                },
                Err(e) => {
                    ui.set_status(SharedString::from(
                        format!("clipboard open: {e}").as_str(),
                    ));
                    ui.set_status_is_error(true);
                }
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Cross-thread UI helpers
// ---------------------------------------------------------------------------

fn set_status(ui_handle: &Weak<GroupChatWindow>, msg: String, is_error: bool) {
    let ui_h = ui_handle.clone();
    let _ = slint::invoke_from_event_loop(move || {
        if let Some(ui) = ui_h.upgrade() {
            ui.set_status(SharedString::from(msg.as_str()));
            ui.set_status_is_error(is_error);
        }
    });
}

/// Stage one inbound event as a display row and, if no drain is already
/// pending, post the single event-loop closure that will apply it.
///
/// `accept_next` returns as fast as the group's members send, and
/// `slint::invoke_from_event_loop` queues without limit, so one closure per
/// event let a member grow that queue — and the `String`s captured in it —
/// while the event loop fell further behind. Staging hands out the obligation
/// to post exactly *one* closure: rows staged while it is still pending are
/// picked up by it when it runs, so a burst of N events costs one closure
/// carrying at most `MAX_CHAT_ROWS` rows instead of N closures.
fn push_event_into_ui(
    ui_handle: &Weak<GroupChatWindow>,
    rows: &Arc<ChatRowQueue>,
    evt: IncomingGroupEvent,
) {
    push_row_into_ui(ui_handle, rows, render_event(&evt));
}

/// Stage one already-rendered row and post the drain closure if it is owed.
/// Split out of [`push_event_into_ui`] so the inbound task's error rows reach
/// the display through the same bounded, coalescing path as its event rows: a
/// peer paces both, and the queue is what keeps either from growing Slint's
/// unbounded event-loop queue.
fn push_row_into_ui(ui_handle: &Weak<GroupChatWindow>, rows: &Arc<ChatRowQueue>, line: String) {
    if !rows.stage(line) {
        // A closure is already queued and will carry this row too; posting
        // another one would only deepen the queue we are trying to bound.
        return;
    }
    let ui_h = ui_handle.clone();
    let rows_for_ui = Arc::clone(rows);
    let posted = slint::invoke_from_event_loop(move || {
        // Drain first and unconditionally, so the pending flag is cleared
        // even when the window has already gone away.
        let batch = rows_for_ui.take();
        if let Some(ui) = ui_h.upgrade() {
            for line in batch {
                append_message(&ui, line);
            }
        }
    });
    if posted.is_err() {
        // The event loop is gone; drop the obligation so a later row can try
        // again rather than staging forever behind a closure that never ran.
        rows.release();
    }
}

/// Append one rendered row to the message model, evicting the oldest rows so
/// the model never holds more than [`MAX_CHAT_ROWS`].
///
/// This is `gui::append_chat_rows` applied to this window: Slint generates a
/// distinct type per component and `ChatWindow`/`GroupChatWindow` share no
/// trait exposing `get_messages`, so the body is restated rather than called.
/// The append is a `push` into the model already in the property instead of a
/// copy of every existing row into a freshly allocated one — the copy made
/// showing N messages cost O(N^2) row copies on the event-loop thread, and a
/// group member chooses N. The first call swaps the `.slint` literal model for
/// a `VecModel`, carrying over whatever rows it held; `filter_map` rather than
/// `unwrap` because a model may shrink between `row_count` and `row_data`.
///
/// Both callers reach the cap through here — the inbound event path and the
/// local echo in `wire_send_message` — so no row source escapes it.
fn append_message(ui: &GroupChatWindow, line: String) {
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
        ui.set_messages(ModelRc::new(VecModel::from(carried)));
    }
    let model = ui.get_messages();
    let Some(vec_model) = model.as_any().downcast_ref::<VecModel<StandardListViewItem>>() else {
        return;
    };
    while vec_model.row_count() >= MAX_CHAT_ROWS {
        vec_model.remove(0);
    }
    vec_model.push(StandardListViewItem::from(SharedString::from(line.as_str())));
}

fn render_event(evt: &IncomingGroupEvent) -> String {
    match evt {
        IncomingGroupEvent::NewGroup { id } => format!("[joined] {id}"),
        IncomingGroupEvent::Message {
            group_id,
            sender_index,
            body,
        } => {
            // UTF-8 lossy so a member sending malformed bytes can't crash our
            // display; matches the CLI twin in `group::cli` and the 1:1 chat
            // policy. Then sanitize, for the same reason the CLI does: this
            // list is where the operator reads the `[joined]` / `[epoch]` /
            // `[removed]` lines that back their trust decisions, so a body
            // carrying line structure or a bidi override forges them.
            //
            // A `StandardListViewItem` is not a terminal, so the half of
            // `sanitize_for_terminal` that neutralizes cursor motion (ESC, \r)
            // is inert here — a Slint `Text` draws those, it does not obey
            // them. The half that matters is the one that survives the change
            // of medium: the bidi overrides and isolates reorder the glyphs
            // *within* the row, so a member can make their own line read as an
            // `[epoch]` or `[removed]` line, and the zero-width marks hide
            // text inside it. `\n` is a forged-line primitive either way — the
            // row is one fixed-height, non-wrapping, eliding line, so an
            // embedded newline either draws over the row's neighbours or
            // silently hides the rest of the body from the operator. Replacing
            // all of them with a space is therefore right here too, and
            // stripping the inert controls costs nothing.
            //
            // Bounded because the length of the body is the member's choice
            // and a row is retained until the `MAX_CHAT_ROWS` cap evicts it.
            // Same ceiling as the 1:1 window's `format_chat_row`, and the only
            // length bound on the body — deliberately no second, different one
            // downstream. The `[leaf .. @ ..]` prefix is ours, not the peer's,
            // so it is outside the bound.
            let text = crate::utils::sanitize_for_terminal_bounded(
                &String::from_utf8_lossy(body),
                MAX_CHAT_ROW_CHARS,
            );
            format!("[leaf {sender_index} @ {group_id}] {text}")
        }
        IncomingGroupEvent::EpochAdvanced {
            group_id,
            new_epoch,
        } => format!("[epoch] {group_id} → {new_epoch}"),
        IncomingGroupEvent::RemovedFromGroup {
            group_id,
            remover_index,
        } => format!("[removed] {group_id} by leaf {remover_index}"),
    }
}

/// Whether an `accept_next` error ends the inbound task.
///
/// Only a closed endpoint does — that is the shutdown signal, and after it no
/// further inbound connection can arrive. Every other error `accept_next`
/// returns is scoped to the single incoming connection that produced it and is
/// remote-controlled: an unexpected ALPN, a stalled handshake, a zero or
/// oversized MLS frame length, an undecodable `MlsMessage`, a SYNC from a
/// non-member. Treating those as fatal let any peer that can reach this
/// endpoint — including a member this window later removes — end MLS delivery
/// for the whole session with one malformed frame, after which the window keeps
/// looking alive while `[joined]` / `[epoch]` / `[removed]` and application
/// messages silently stop. Most of all, the user would never learn they had
/// been evicted, because `RemovedFromGroup` could no longer be delivered.
///
/// Same rule as the CLI twin in `group::cli`, deliberately: both drive the same
/// `accept_next` loop.
fn inbound_error_is_fatal(e: &crate::group::GroupError) -> bool {
    matches!(
        e,
        crate::group::GroupError::Transport(crate::p2p::P2pError::Closed)
    )
}

/// Render a non-fatal inbound error as one display row.
///
/// The text can carry peer-chosen bytes — a QUIC close reason arrives here
/// inside `Transport(Accept("accept_bi: …"))`, and an unexpected ALPN is echoed
/// back — and it lands in the very list the operator reads `[joined]` /
/// `[epoch]` / `[removed]` from, so it goes through exactly the sanitizing and
/// bounding `render_event` applies to a message body, for exactly the reasons
/// documented there. Bounding is safe: every `GroupError` prints its own
/// scaffolding (`transport: accept failed: …`) first and the peer's bytes last,
/// so the cut can only drop attacker-chosen tail. The `[err]` prefix is ours,
/// not the peer's, so it sits outside the bound.
fn render_inbound_error(e: &crate::group::GroupError) -> String {
    let text = crate::utils::sanitize_for_terminal_bounded(&e.to_string(), MAX_CHAT_ROW_CHARS);
    format!("[err] {text}")
}

fn upgrade_get_selected_gid(ui_handle: &Weak<GroupChatWindow>) -> Option<String> {
    ui_handle.upgrade().map(|ui| ui.get_selected_group_id().to_string())
}

/// Read the group id out of the `groups` row the user clicked.
///
/// Every row of that model is written as `gid.to_string()` (64 hex chars) by
/// `refresh_groups_*`, so the row carries the identity of the group it
/// displays. Reading it here binds the selection to what was on screen; the
/// row index alone is meaningless the moment the underlying list changes, and
/// a remote peer can change it by sending a Welcome.
///
/// Must be called on the Slint event-loop thread — it touches the model.
fn selected_row_group_id(
    ui_handle: &Weak<GroupChatWindow>,
    row: usize,
) -> Result<GroupId, String> {
    let ui = ui_handle.upgrade().ok_or("window is gone")?;
    let item = ui
        .get_groups()
        .row_data(row)
        .ok_or_else(|| format!("no group at row {row}"))?;
    parse_group_id(item.text.as_str()).map_err(|e| format!("parse gid: {e}"))
}

fn parse_group_id(hex: &str) -> Result<GroupId, String> {
    let bytes = hex::decode(hex).map_err(|e| format!("hex decode: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(GroupId::new(arr))
}

async fn refresh_groups_async(ui: &GroupChatWindow, processor: &GroupChatProcessor) {
    let groups = cli::list_groups(processor).await.unwrap_or_default();
    let m = VecModel::<StandardListViewItem>::default();
    for gid in &groups {
        m.push(StandardListViewItem::from(SharedString::from(
            gid.to_string().as_str(),
        )));
    }
    ui.set_groups(ModelRc::new(m));
}

fn refresh_groups_invoke(
    ui_handle: &Weak<GroupChatWindow>,
    processor: &Arc<GroupChatProcessor>,
) {
    let proc_clone = Arc::clone(processor);
    let ui_h = ui_handle.clone();
    tokio::spawn(async move {
        let groups = cli::list_groups(&proc_clone).await.unwrap_or_default();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(ui) = ui_h.upgrade() {
                let m = VecModel::<StandardListViewItem>::default();
                for gid in &groups {
                    m.push(StandardListViewItem::from(SharedString::from(
                        gid.to_string().as_str(),
                    )));
                }
                ui.set_groups(ModelRc::new(m));
            }
        });
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `render_event` produces a non-empty string for every
    /// `IncomingGroupEvent` variant. This is a static-data test so
    /// the UI keeps showing *something* even after a new variant is
    /// added (the project's enum is `non_exhaustive` candidates aside).
    #[test]
    fn render_event_covers_every_variant() {
        let gid = GroupId::new([1u8; 32]);
        for evt in [
            IncomingGroupEvent::NewGroup { id: gid },
            IncomingGroupEvent::Message {
                group_id: gid,
                sender_index: 0,
                body: b"hello".to_vec(),
            },
            IncomingGroupEvent::EpochAdvanced {
                group_id: gid,
                new_epoch: 7,
            },
            IncomingGroupEvent::RemovedFromGroup {
                group_id: gid,
                remover_index: 0,
            },
        ] {
            assert!(!render_event(&evt).is_empty());
        }
    }

    /// Build a real `GroupChatWindow` against the headless test backend, the
    /// same way `tests/gui_test.rs` builds a `ChatWindow`. The model bounds
    /// are only meaningful against the model Slint actually hands out, so
    /// these tests drive the generated component rather than a stand-in.
    fn group_ui() -> GroupChatWindow {
        i_slint_backend_testing::init_no_event_loop();
        GroupChatWindow::new().unwrap()
    }

    /// A member's message body is peer-authored text rendered into the list
    /// the operator reads `[joined]` / `[epoch]` / `[removed]` lines from, so
    /// it must not be able to carry line structure, bidi reordering or
    /// unbounded length into a row. The other direction matters just as much:
    /// an ordinary message must arrive exactly as it was sent.
    #[test]
    fn render_event_neutralizes_hostile_bodies_but_leaves_normal_text_intact() {
        let gid = GroupId::new([1u8; 32]);
        let render = |body: &[u8]| {
            render_event(&IncomingGroupEvent::Message {
                group_id: gid,
                sender_index: 3,
                body: body.to_vec(),
            })
        };

        // Honest direction: an ordinary message is passed through verbatim.
        let normal = "shall we meet at 18:00? 日本語もそのまま";
        let row = render(normal.as_bytes());
        assert!(
            row.ends_with(normal),
            "a normal message must not be altered, got: {row}"
        );
        assert!(!row.contains("truncated"));

        // Honest direction: still whole right up to the ceiling.
        let at_cap = "a".repeat(MAX_CHAT_ROW_CHARS);
        assert!(render(at_cap.as_bytes()).ends_with(&at_cap));

        // Hostile direction: newline padding cannot forge the event lines the
        // operator reads above this one.
        let forged = render(b"hi\n[epoch] 00 -> 99\n[removed] 00 by leaf 0");
        assert!(
            !forged.contains('\n') && !forged.contains('\r'),
            "a member must not be able to put line structure in a row: {forged}"
        );

        // Hostile direction: bidi overrides / isolates and the zero-width
        // marks reorder or hide glyphs inside the row even in a GUI.
        let bidi = render("x\u{202E}y\u{2066}z\u{200B}w\u{200F}v".as_bytes());
        for c in ['\u{202E}', '\u{2066}', '\u{200B}', '\u{200F}'] {
            assert!(!bidi.contains(c), "{c:?} survived into the row: {bidi}");
        }

        // Hostile direction: terminal control bytes never reach the row.
        let ctrl = render(b"x\x1b[2Ky\x07");
        assert!(!ctrl.contains('\u{1b}') && !ctrl.contains('\u{7}'));

        // Hostile direction: an oversized body becomes one bounded row that
        // visibly says it was clipped.
        let huge = render("A".repeat(65_000).as_bytes());
        assert!(
            huge.ends_with("…[truncated]"),
            "truncation must be visible to the operator"
        );
        assert!(
            huge.chars().count() <= MAX_CHAT_ROW_CHARS + "…[truncated]".chars().count() + 128,
            "row rendered {} chars",
            huge.chars().count()
        );

        // Malformed UTF-8 is replaced, not rejected: the row still renders.
        assert!(!render(&[0xff, 0xfe, b'h', b'i']).is_empty());
    }

    /// A member decides how many events to send and each one became a
    /// retained row, so the model must keep only the newest `MAX_CHAT_ROWS`
    /// and evict oldest-first — while an ordinary conversation still shows
    /// every message it sent, in order.
    #[test]
    fn append_message_bounds_a_flood_and_keeps_a_normal_conversation() {
        use slint::Model;

        let ui = group_ui();

        // Honest direction: a short conversation is delivered in full.
        for i in 0..5 {
            append_message(&ui, format!("hello {i}"));
        }
        let m = ui.get_messages();
        assert_eq!(m.row_count(), 5, "a normal conversation must show every message");
        for i in 0..5 {
            assert_eq!(m.row_data(i).unwrap().text, format!("hello {i}"));
        }

        // Hostile direction: a flood is bounded, newest kept, oldest evicted.
        let flood = MAX_CHAT_ROWS * 3;
        for i in 0..flood {
            append_message(&ui, format!("flood {i}"));
        }
        let m = ui.get_messages();
        assert_eq!(
            m.row_count(),
            MAX_CHAT_ROWS,
            "a member must not decide how many rows this process retains"
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
    /// showing N messages cost O(N^2) row copies on the event-loop thread.
    #[test]
    fn append_message_mutates_the_model_in_place() {
        use slint::Model;

        let ui = group_ui();
        append_message(&ui, "first".to_string());
        let model_after_first = ui.get_messages();

        for i in 0..50 {
            append_message(&ui, format!("row {i}"));
            assert!(
                ui.get_messages() == model_after_first,
                "row {i} replaced the whole model instead of pushing into it"
            );
        }
        assert_eq!(ui.get_messages().row_count(), 51);
    }

    /// Inbound events must be staged rather than each posting its own
    /// event-loop closure. With no loop running to drain it, a burst leaves
    /// every row in the queue — bounded to `MAX_CHAT_ROWS` — which is only
    /// true if `push_event_into_ui` routes through the queue at all.
    #[test]
    fn push_event_into_ui_coalesces_a_burst_through_the_queue() {
        let ui = group_ui();
        let handle = ui.as_weak();
        let rows = Arc::new(ChatRowQueue::new());
        let gid = GroupId::new([2u8; 32]);

        let burst = MAX_CHAT_ROWS * 3;
        for i in 0..burst {
            push_event_into_ui(
                &handle,
                &rows,
                IncomingGroupEvent::Message {
                    group_id: gid,
                    sender_index: 1,
                    body: format!("burst {i}").into_bytes(),
                },
            );
        }

        let batch = rows.take();
        assert_eq!(
            batch.len(),
            MAX_CHAT_ROWS,
            "a burst of {burst} events must stage a bounded batch, not one closure each"
        );
        assert!(
            batch.last().unwrap().ends_with(&format!("burst {}", burst - 1)),
            "the newest rows must be the ones that survive"
        );

        // No lost wakeup: after the drain, the next event schedules again.
        assert!(rows.stage("after".to_string()));
    }

    /// Only a closed endpoint may end the inbound task. Every other error
    /// `accept_next` returns is reachable by any peer that knows this node's
    /// id — a member about to be removed, or anyone handed the ticket — so
    /// treating one as fatal would let a single malformed frame silence
    /// `[epoch]` / `[removed]` for the rest of the session.
    #[test]
    fn inbound_error_is_fatal_only_for_a_closed_endpoint() {
        use crate::group::GroupError;
        use crate::p2p::P2pError;

        assert!(inbound_error_is_fatal(&GroupError::Transport(
            P2pError::Closed
        )));

        for e in [
            // Peer-triggerable, one connection each: bad ALPN, stalled
            // handshake, empty/oversized frame length, undecodable message,
            // SYNC for an unknown group or from a non-member.
            GroupError::Transport(P2pError::Accept(
                "accept_next: unexpected ALPN [\"bogus\"]".into(),
            )),
            GroupError::Transport(P2pError::Accept("read header: handshake timeout".into())),
            GroupError::Transport(P2pError::Recv("stream reset by peer".into())),
            GroupError::InvalidWelcome("Empty MLS frame length".into()),
            GroupError::NotFound,
            GroupError::NotMember,
        ] {
            assert!(
                !inbound_error_is_fatal(&e),
                "one connection's error must not end MLS delivery: {e}"
            );
        }
    }

    /// The error row carries peer-chosen text (a QUIC close reason, an echoed
    /// ALPN), and it lands in the same list as the `[joined]` / `[epoch]` /
    /// `[removed]` lines the operator trusts — so it must not be able to forge
    /// them, and must stay bounded.
    #[test]
    fn render_inbound_error_neutralizes_peer_text() {
        use crate::group::GroupError;
        use crate::p2p::P2pError;

        let render = |detail: &str| {
            render_inbound_error(&GroupError::Transport(P2pError::Accept(detail.to_string())))
        };

        // Honest direction: an ordinary diagnostic survives intact and labelled.
        let plain = render("read header: handshake timeout");
        assert!(plain.starts_with("[err] "));
        assert!(plain.ends_with("read header: handshake timeout"));
        assert!(!plain.contains("truncated"));

        // Hostile: no line structure, so no forged event lines.
        let forged = render("x\n[removed] 00 by leaf 0\n[epoch] 00 → 99");
        assert!(
            !forged.contains('\n') && !forged.contains('\r'),
            "a peer must not put line structure in a row: {forged}"
        );

        // Hostile: bidi overrides / isolates and zero-width marks reorder or
        // hide glyphs inside the row.
        let bidi = render("x\u{202E}y\u{2066}z\u{200B}w\u{200F}v");
        for c in ['\u{202E}', '\u{2066}', '\u{200B}', '\u{200F}'] {
            assert!(!bidi.contains(c), "{c:?} survived into the row: {bidi}");
        }

        // Hostile: an oversized close reason becomes one visibly clipped row.
        let huge = render(&"A".repeat(65_000));
        assert!(huge.ends_with("…[truncated]"));
        assert!(
            huge.chars().count() <= MAX_CHAT_ROW_CHARS + "…[truncated]".chars().count() + 128,
            "row rendered {} chars",
            huge.chars().count()
        );
    }

    /// Error rows must reach the display through the same staging queue as
    /// events: a peer paces them too, so one event-loop closure each would be
    /// the unbounded queue growth the staging exists to prevent.
    #[test]
    fn push_row_into_ui_coalesces_an_error_burst_through_the_queue() {
        let ui = group_ui();
        let handle = ui.as_weak();
        let rows = Arc::new(ChatRowQueue::new());

        let burst = MAX_CHAT_ROWS * 3;
        for i in 0..burst {
            push_row_into_ui(&handle, &rows, format!("[err] transport: accept failed: {i}"));
        }

        let batch = rows.take();
        assert_eq!(
            batch.len(),
            MAX_CHAT_ROWS,
            "a burst of {burst} errors must stage a bounded batch, not one closure each"
        );
        assert!(batch.last().unwrap().ends_with(&format!("{}", burst - 1)));
    }

    /// A click must resolve to the group the clicked row *displays*, not to
    /// whatever now sits at that index in the storage-ordered list.
    ///
    /// A remote peer grows that list unauthenticated: an unsolicited Welcome
    /// auto-joins a group whose 32-byte id its author chose, so an id sorting
    /// below ours is inserted ahead of every existing row while the `groups`
    /// model still shows the old order. Re-deriving the id from the index
    /// then hands the user's admin actions — Add Member is authorized by
    /// nothing but `selected-group-id` — to the attacker's group.
    #[test]
    fn selected_row_resolves_the_displayed_group_not_the_index() {
        let ui = group_ui();
        let handle = ui.as_weak();

        let mine = GroupId::new([0x11; 32]);
        let other = GroupId::new([0x22; 32]);
        let m = VecModel::<StandardListViewItem>::default();
        for gid in [mine, other] {
            m.push(StandardListViewItem::from(SharedString::from(
                gid.to_string().as_str(),
            )));
        }
        ui.set_groups(ModelRc::new(m));

        // Honest direction: every row resolves to the group it shows.
        assert_eq!(selected_row_group_id(&handle, 0).unwrap(), mine);
        assert_eq!(selected_row_group_id(&handle, 1).unwrap(), other);

        // Hostile direction: this is the list storage would hand back after
        // the injected group is joined. Resolution must not consult it — row 0
        // is still the group the user saw and clicked.
        let injected = GroupId::new([0x00; 32]);
        let storage_order = [injected, mine, other];
        assert_eq!(
            selected_row_group_id(&handle, 0).unwrap(),
            mine,
            "row 0 must stay the user's group even though storage row 0 is now {injected}"
        );
        assert_ne!(
            selected_row_group_id(&handle, 0).unwrap(),
            storage_order[0],
            "the selection must not be re-derived from the shifted list"
        );

        // A row past the end is rejected rather than coerced to a neighbour.
        assert!(selected_row_group_id(&handle, 2).is_err());
    }

    /// `parse_group_id` accepts 64-hex strings (32 bytes) and rejects
    /// non-hex / wrong-length inputs.
    #[test]
    fn parse_group_id_round_trip_and_negative_cases() {
        let original = GroupId::new([0xAB; 32]);
        let hex = original.to_string();
        let round_tripped = parse_group_id(&hex).expect("round-trip");
        assert_eq!(round_tripped, original);

        assert!(parse_group_id("not hex").is_err());
        assert!(parse_group_id("ab").is_err(), "too short");
        assert!(
            parse_group_id(&"a".repeat(63)).is_err(),
            "odd hex digit count"
        );
    }
}
