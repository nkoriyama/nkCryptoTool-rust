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
    tokio::spawn(async move {
        loop {
            match inbound_proc.accept_next().await {
                Ok(evt) => {
                    push_event_into_ui(&inbound_ui, evt);
                }
                Err(e) => {
                    // Transport errors usually mean the endpoint
                    // closed; report once and exit the loop.
                    let msg = format!("inbound: {e}");
                    set_status(&inbound_ui, msg, true);
                    break;
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
        tokio::spawn(async move {
            let groups = match cli::list_groups(&proc_clone).await {
                Ok(g) => g,
                Err(e) => {
                    set_status(&ui_h, format!("list_groups: {e}"), true);
                    return;
                }
            };
            let row = row as usize;
            let Some(gid) = groups.get(row).copied() else {
                set_status(&ui_h, format!("no group at row {row}"), true);
                return;
            };
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

fn push_event_into_ui(ui_handle: &Weak<GroupChatWindow>, evt: IncomingGroupEvent) {
    let line = render_event(&evt);
    let ui_h = ui_handle.clone();
    let _ = slint::invoke_from_event_loop(move || {
        if let Some(ui) = ui_h.upgrade() {
            append_message(&ui, line);
        }
    });
}

fn append_message(ui: &GroupChatWindow, line: String) {
    let cur = ui.get_messages();
    let m = VecModel::<StandardListViewItem>::default();
    for i in 0..cur.row_count() {
        m.push(cur.row_data(i).unwrap());
    }
    m.push(StandardListViewItem::from(SharedString::from(line.as_str())));
    ui.set_messages(ModelRc::new(m));
}

fn render_event(evt: &IncomingGroupEvent) -> String {
    match evt {
        IncomingGroupEvent::NewGroup { id } => format!("[joined] {id}"),
        IncomingGroupEvent::Message {
            group_id,
            sender_index,
            body,
        } => {
            let text = String::from_utf8_lossy(body);
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

fn upgrade_get_selected_gid(ui_handle: &Weak<GroupChatWindow>) -> Option<String> {
    ui_handle.upgrade().map(|ui| ui.get_selected_group_id().to_string())
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
