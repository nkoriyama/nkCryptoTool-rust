//! MLS group chat CLI dispatch (P7).
//!
//! `main.rs` parses `--mls-*` flags, builds a [`GroupChatProcessor`],
//! and calls [`run`]. The handlers here are deliberately small and
//! transport-agnostic — they take a pre-built processor and side-
//! effect via stdout/stderr only. Tests call the handlers directly,
//! bypassing argv parsing.
//!
//! ## Surface
//!
//! Each variant of [`MlsCommand`] is exposed as a `pub async fn`
//! handler so it can be called from tests or alternative front-ends
//! (e.g. the GUI in P8). [`run`] is the enum dispatcher used by the
//! CLI main.
//!
//! ## Storage
//!
//! `--mls-storage <path>` overrides the database path; otherwise
//! [`default_storage_path`] derives `$HOME/.local/share/nkct/groups.db`.
//! No automatic encryption — file mode 0o600 is set by
//! [`GroupStorage::open_at`].

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, Context};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::group::{GroupChatProcessor, GroupId, IncomingGroupEvent};
use crate::p2p::PeerAddr;
use crate::ticket::Ticket;

/// Subcommand selection for the MLS CLI.
///
/// Variants map 1:1 to the `--mls-<command>` flag the user passes.
/// Argument validation (paths exist, hex parses) happens during clap
/// parsing in `main.rs`; by the time a `MlsCommand` is constructed,
/// all fields are well-typed.
pub enum MlsCommand {
    /// Create a new group; print its GroupId to stdout.
    CreateGroup { name: String },
    /// List the GroupIds of every locally-stored group.
    ListGroups,
    /// List members (leaf indices) of a specific group.
    ListMembers { group_id: GroupId },
    /// Project a group's verified members onto a shell/forward policy: print one
    /// `<fingerprint-hex>  <template>` line per member to stdout, ready to redirect
    /// into a `--shell-policy` / `--forward-policy` file. `template` is the common
    /// per-member attribute string (e.g. `user=deploy cmd-allow="..."` or
    /// `allow="db:5432" bind="8080"`).
    ProjectPolicy { group_id: GroupId, template: String },
    /// Generate a fresh KeyPackage and write its raw MLS bytes to a file.
    ExportKeyPackage { output: PathBuf },
    /// Add the holder of `key_package_file` to `group_id` and ship
    /// the resulting Welcome to `recipient_ticket`.
    AddMember {
        group_id: GroupId,
        key_package_file: PathBuf,
        recipient_ticket: Ticket,
        /// Optional existing-member tickets to receive the Commit
        /// alongside the Welcome (needed for groups already ≥ 2
        /// before the Add).
        existing_member_tickets: Vec<Ticket>,
    },
    /// Remove a leaf and broadcast the resulting Commit to the given
    /// recipients (typically every member except ourselves, including
    /// the removed leaf so they learn cleanly).
    RemoveMember {
        group_id: GroupId,
        index: u32,
        recipient_tickets: Vec<Ticket>,
    },
    /// Block on the next inbound MLS frame on `nkct/mls/1` and print
    /// the resulting event. One-shot — exits after a single event.
    /// Use [`ChatGroup`](Self::ChatGroup) for an interactive loop.
    AcceptOne,
    /// Long-running interactive listener. Prints our own address
    /// (ticket) on startup so the inviter knows where to deliver a
    /// Welcome, then runs accept_next forever on one task while a
    /// stdin REPL on the other lets the user issue commands:
    ///
    ///   `/peer <ticket>`         — add a recipient address
    ///   `/gid <hex>`             — set/override the active group id (e.g.
    ///                              after creating one in a sibling process)
    ///   `/add <kp> <ticket>`     — add a new member to the active group,
    ///                              re-using this listener's iroh endpoint
    ///                              (no per-invocation process startup)
    ///   `/status`                — print active gid + peer count
    ///   `/quit`                  — exit the loop
    ///   (anything else)          — send the line as an application message
    ///                              to all `/peer` recipients in the active
    ///                              group (silently dropped if either is unset)
    ///
    /// An inbound `NewGroup` event sets the active group id when none is
    /// active yet, so a freshly-invited peer that has the inviter's ticket
    /// via `/peer` is ready to chat as soon as the Welcome arrives. It never
    /// *replaces* an active group: a Welcome from an unauthenticated peer
    /// would otherwise silently re-point everything typed next into a group
    /// of the sender's choosing. Such a group is still joined, and the
    /// printed `[joined] <gid> (not active …)` line carries the `/gid` to
    /// switch into it on purpose.
    Listen {
        /// Optional initial group_id. If unset, the listener waits for
        /// the first `NewGroup` event (from an inbound Welcome) and
        /// adopts that gid. If set, only `/gid` can change it.
        group_id: Option<GroupId>,
        /// Initial recipient tickets. More can be added later via
        /// the `/peer` stdin command.
        recipient_tickets: Vec<Ticket>,
        /// Directory received files are written to (file transfers framed
        /// over MLS application messages).
        recv_dir: PathBuf,
    },
    /// Send a single application message to the given recipients.
    Send {
        group_id: GroupId,
        body: String,
        recipient_tickets: Vec<Ticket>,
    },
    /// Send a file to the whole group, framed over MLS application
    /// messages (`START`/`DATA`/`END`). Recipients default to the
    /// group's remembered address book when no ticket is supplied.
    SendFile {
        group_id: GroupId,
        path: PathBuf,
        recipient_tickets: Vec<Ticket>,
    },
    /// Interactive chat loop: stdin lines are sent as application
    /// messages, inbound MLS events are printed to stdout.
    ChatGroup {
        group_id: GroupId,
        recipient_tickets: Vec<Ticket>,
    },
    /// Print our own reachable address as a ticket. Hand this to a
    /// peer so they can `AddMember --recipient-ticket` you in.
    PrintLocalAddress,
}

/// Resolve the default sqlite storage path: `$HOME/.local/share/nkct/groups.db`.
///
/// Creates the directory tree if missing. Returns an error if `$HOME`
/// is not set in the environment.
pub fn default_storage_path() -> anyhow::Result<PathBuf> {
    let home = std::env::var("HOME")
        .context("$HOME is not set; pass --mls-storage <path> explicitly")?;
    let dir = PathBuf::from(home).join(".local/share/nkct");
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create MLS storage directory {dir:?}"))?;
    Ok(dir.join("groups.db"))
}

/// Convert a list of ticket strings to typed [`PeerAddr`]s. Returns
/// the first parse error verbatim so the user sees which ticket
/// was malformed.
pub fn tickets_to_peer_addrs(tickets: &[Ticket]) -> Vec<PeerAddr> {
    tickets.iter().map(|t| t.peer_addr()).collect()
}

/// Resolve the recipient set for a group messaging command.
///
/// First **remember** any tickets the user supplied (keyed by node id, per
/// group) so a later invocation can omit `--mls-recipient-ticket`. Then use the
/// supplied set if non-empty; otherwise fall back to the group's **remembered**
/// delivery hints. MLS still authenticates/encrypts every message, so a stale
/// hint can at worst fail to deliver — never misdeliver plaintext.
fn resolve_recipients(
    processor: &GroupChatProcessor,
    gid: &GroupId,
    supplied: &[Ticket],
) -> Vec<PeerAddr> {
    processor.remember_member_tickets(gid, supplied);
    if !supplied.is_empty() {
        return tickets_to_peer_addrs(supplied);
    }
    match processor.known_member_addrs(gid) {
        Ok(addrs) => {
            if addrs.is_empty() {
                eprintln!(
                    "[mls] no --mls-recipient-ticket given and no remembered addresses \
                     for this group; nothing to deliver to"
                );
            }
            addrs
        }
        Err(e) => {
            eprintln!("[mls] failed to load remembered addresses: {e}");
            Vec::new()
        }
    }
}

// -----------------------------------------------------------------------------
// Per-command handlers. Each takes a borrow of the processor so tests
// can call them sequentially against the same processor instance.
// -----------------------------------------------------------------------------

pub async fn create_group(
    processor: &GroupChatProcessor,
    name: &str,
) -> anyhow::Result<GroupId> {
    let gid = processor
        .create_group()
        .await
        .with_context(|| format!("create_group {name:?}"))?;
    Ok(gid)
}

pub async fn list_groups(processor: &GroupChatProcessor) -> anyhow::Result<Vec<GroupId>> {
    processor
        .list_groups()
        .map_err(|e| anyhow!("list_groups: {e}"))
}

pub async fn list_members(
    processor: &GroupChatProcessor,
    group_id: &GroupId,
) -> anyhow::Result<Vec<crate::group::MemberInfo>> {
    processor
        .list_members(group_id)
        .await
        .map_err(|e| anyhow!("list_members {group_id}: {e}"))
}

pub async fn project_policy(
    processor: &GroupChatProcessor,
    group_id: &GroupId,
    template: &str,
) -> anyhow::Result<Vec<String>> {
    let fps = processor
        .projected_member_fingerprints(group_id)
        .await
        .map_err(|e| anyhow!("project_policy {group_id}: {e}"))?;
    Ok(fps
        .into_iter()
        .map(|fp| {
            let hex: String = fp.iter().map(|b| format!("{b:02x}")).collect();
            if template.is_empty() {
                hex
            } else {
                format!("{hex}  {template}")
            }
        })
        .collect())
}

pub async fn export_key_package(
    processor: &GroupChatProcessor,
    output: &Path,
) -> anyhow::Result<()> {
    let bytes = processor
        .export_key_package()
        .await
        .map_err(|e| anyhow!("export_key_package: {e}"))?;
    // tokio::fs::write is overkill for a single small file; use blocking
    // — KeyPackages are O(KiB) and this path is one-shot from main.
    std::fs::write(output, bytes.as_slice())
        .with_context(|| format!("write KeyPackage to {output:?}"))?;
    Ok(())
}

pub async fn add_member(
    processor: &GroupChatProcessor,
    group_id: &GroupId,
    key_package_file: &Path,
    recipient: &PeerAddr,
    existing_members: &[PeerAddr],
) -> anyhow::Result<()> {
    let kp_bytes = std::fs::read(key_package_file)
        .with_context(|| format!("read KeyPackage from {key_package_file:?}"))?;
    let added = processor
        .add_member(group_id, &kp_bytes)
        .await
        .map_err(|e| anyhow!("add_member: {e}"))?;

    // Attempt Welcome and Commit independently. Once `processor.add_member`
    // returns, the local group state has *already* advanced — failing
    // here without trying the Commit would leave existing members
    // stuck on the old epoch even though the new member may have
    // actually received the Welcome (our send_one's ACK read can
    // surface a spurious `connection lost` even when the body landed,
    // because iroh tears the QUIC connection after the receiver-side
    // listen has flushed the ACK).
    let welcome_res = processor.send_welcome_to(recipient, &added.welcome).await;
    let commit_res = processor
        .broadcast_commit(&added.commit, existing_members)
        .await;

    match (welcome_res, commit_res) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(we), Ok(())) => Err(anyhow!(
            "send Welcome reported {we} but Commit broadcast succeeded; \
             new member may have joined regardless — verify on their side"
        )),
        (Ok(()), Err(ce)) => Err(anyhow!(
            "broadcast Commit failed: {ce} (Welcome was delivered; existing \
             members are now out-of-sync with the new epoch)"
        )),
        (Err(we), Err(ce)) => {
            Err(anyhow!("send Welcome AND broadcast Commit failed: welcome={we}; commit={ce}"))
        }
    }
}

pub async fn remove_member(
    processor: &GroupChatProcessor,
    group_id: &GroupId,
    index: u32,
    recipients: &[PeerAddr],
) -> anyhow::Result<()> {
    let commit = processor
        .remove_member(group_id, index)
        .await
        .map_err(|e| anyhow!("remove_member leaf {index}: {e}"))?;
    processor
        .broadcast_commit(&commit, recipients)
        .await
        .map_err(|e| anyhow!("broadcast remove Commit: {e}"))?;
    Ok(())
}

pub async fn send_application_message(
    processor: &GroupChatProcessor,
    group_id: &GroupId,
    body: &[u8],
    recipients: &[PeerAddr],
) -> anyhow::Result<()> {
    processor
        .send_application_message(group_id, body, recipients)
        .await
        .map_err(|e| anyhow!("send_application_message: {e}"))?;
    Ok(())
}

pub async fn accept_one(
    processor: &GroupChatProcessor,
) -> anyhow::Result<IncomingGroupEvent> {
    processor
        .accept_next()
        .await
        .map_err(|e| anyhow!("accept_next: {e}"))
}

/// Print our own reachable address as a `Ticket` string.
pub async fn print_local_address(
    processor: &GroupChatProcessor,
) -> anyhow::Result<String> {
    let addr = processor
        .local_addr()
        .await
        .map_err(|e| anyhow!("local_addr: {e}"))?;
    Ok(Ticket::new(addr, None, None).to_string())
}

// -----------------------------------------------------------------------------
// Interactive chat loop. Reads stdin, sends each non-empty line as an
// application message; in parallel, runs accept_next and prints events.
//
// This mirrors `crate::network::NetworkProcessor::chat_loop`'s shape
// but with MLS framing. Cancel-safe — both halves close on stdin EOF
// or transport close.
// -----------------------------------------------------------------------------

pub async fn chat_group_loop<R, W>(
    processor: Arc<GroupChatProcessor>,
    group_id: GroupId,
    recipients: Vec<PeerAddr>,
    mut stdin: R,
    stdout: Arc<tokio::sync::Mutex<W>>,
) -> anyhow::Result<()>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // Shared with the inbound task rather than owned by the sending half: the
    // set is resolved once before the loop starts, but the group's membership
    // changes underneath it, and this process is the one that observes the
    // Commit doing so (see `prune_departed_recipients`).
    let recipients = Arc::new(tokio::sync::Mutex::new(recipients));

    // Membership baseline. This loop addresses exactly one group and its
    // inbound task is the only reader and writer, so the map is moved in
    // rather than shared. Seeded before the task can observe an event, so the
    // very first Commit is already a measurable delta.
    let rosters = tokio::sync::Mutex::new(RosterSnapshots::new());
    seed_roster(&processor, &rosters, &group_id).await;

    // Inbound task: run accept_next forever, push decoded events to
    // stdout via the shared writer.
    let inbound_processor = Arc::clone(&processor);
    let inbound_stdout = Arc::clone(&stdout);
    let inbound_recipients = Arc::clone(&recipients);
    let inbound = tokio::spawn(async move {
        loop {
            match inbound_processor.accept_next().await {
                Ok(evt) => {
                    let line = render_event(&evt);
                    // A Commit that evicted somebody *else* surfaces here as
                    // EpochAdvanced, and the event does not name who left, so
                    // the roster is re-read and diffed on any epoch change of
                    // our group.
                    let pruned = match &evt {
                        IncomingGroupEvent::EpochAdvanced { group_id: g, .. }
                            if *g == group_id =>
                        {
                            prune_departed_recipients(
                                &inbound_processor,
                                &group_id,
                                &inbound_recipients,
                                &rosters,
                            )
                            .await
                        }
                        _ => None,
                    };
                    let mut out = inbound_stdout.lock().await;
                    let _ = out.write_all(line.as_bytes()).await;
                    if let Some(note) = pruned {
                        let _ = out.write_all(b"\n").await;
                        let _ = out.write_all(note.as_bytes()).await;
                    }
                    let _ = out.write_all(b"\n> ").await;
                    let _ = out.flush().await;
                }
                // Endpoint gone (shutdown): stop the inbound task.
                Err(crate::group::GroupError::Transport(crate::p2p::P2pError::Closed)) => break,
                // Any other error is scoped to one incoming connection (bad
                // ALPN, handshake stall, undecodable message). Drop that
                // connection and keep accepting — otherwise a single malformed
                // inbound message would permanently stop MLS delivery for the
                // whole session.
                Err(e) => {
                    // The rendered error can carry peer-chosen text — a QUIC
                    // close reason arrives here inside
                    // `Transport(Accept("accept_bi: ..."))` — and this REPL is
                    // where the operator reads `[joined]` / `[epoch advanced]` /
                    // `[removed]` to judge who is in the group. Strip the
                    // control/bidi characters that would let a peer erase or
                    // forge those lines, exactly as `render_event` does for
                    // message bodies. Bounding is safe here: every `GroupError`
                    // variant `accept_next` can return prints its own
                    // scaffolding (`transport: accept failed: …`) first and the
                    // peer's bytes last, so the cut can only drop attacker-
                    // chosen tail, never a diagnostic the operator needs.
                    let msg = crate::utils::sanitize_for_terminal_bounded(&e.to_string(), 256);
                    let mut out = inbound_stdout.lock().await;
                    let _ = out
                        .write_all(format!("[err] {msg}\n> ").as_bytes())
                        .await;
                    let _ = out.flush().await;
                }
            }
        }
    });

    // Outbound: stdin → send_application_message.
    {
        let mut out = stdout.lock().await;
        let _ = out.write_all(b"> ").await;
        let _ = out.flush().await;
    }
    let mut reader = BufReader::new(&mut stdin);
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader
            .read_line(&mut line)
            .await
            .context("read stdin line")?;
        if n == 0 {
            // EOF — caller closed stdin.
            break;
        }
        let body = line.trim_end_matches(|c| c == '\n' || c == '\r');
        if body.is_empty() {
            let mut out = stdout.lock().await;
            let _ = out.write_all(b"> ").await;
            let _ = out.flush().await;
            continue;
        }
        // Snapshot under the lock, send without it: the fan-out awaits
        // peer-controlled endpoints and must not block the inbound task's
        // prune.
        let recips = recipients.lock().await.clone();
        // The prune can empty this list, and `fanout_send`'s empty-list early
        // return is an `Ok` — without this the operator would keep typing into
        // a session that silently delivers to nobody. Same guard `listen_loop`
        // already has for a set that started empty.
        if recips.is_empty() {
            let mut out = stdout.lock().await;
            let _ = out
                .write_all("[mls] no recipients — nothing to deliver to\n> ".as_bytes())
                .await;
            let _ = out.flush().await;
            continue;
        }
        match processor
            .send_application_message(&group_id, body.as_bytes(), &recips)
            .await
        {
            Ok(_) => {
                let mut out = stdout.lock().await;
                let _ = out.write_all(b"> ").await;
                let _ = out.flush().await;
            }
            Err(e) => {
                // Carries a hostile recipient's close reason via
                // `Connect`/`open_bi`, printed into the same prompt the inbound
                // task writes its `[err]` lines to — sanitize it identically.
                let msg = crate::utils::sanitize_for_terminal_bounded(&e.to_string(), 256);
                let mut out = stdout.lock().await;
                let _ = out
                    .write_all(format!("[send err] {msg}\n> ").as_bytes())
                    .await;
                let _ = out.flush().await;
            }
        }
    }

    inbound.abort();
    Ok(())
}

// -----------------------------------------------------------------------------
// Listen loop: long-running REPL combining accept_next + stdin commands.
//
// Two halves running on tokio tasks, communicating through `Arc<Mutex>`
// for the mutable session state (`group_id`, `recipients`).
//
// Inbound half:
//   accept_next() → render → push line to stdout
//   NewGroup → also adopt into `group_id`, but only when it is unset
//   RemovedFromGroup → also break the outer loop
//
// Outbound half (this fn):
//   read stdin line → parse slash-command → either mutate state or
//   send_application_message to the current recipients.
// -----------------------------------------------------------------------------
pub async fn listen_loop(
    processor: Arc<GroupChatProcessor>,
    initial_group_id: Option<GroupId>,
    initial_recipients: Vec<PeerAddr>,
    recv_dir: std::path::PathBuf,
) -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt;
    use tokio::sync::Mutex;

    // Shared file-transfer reassembler: inbound app messages that are file
    // frames are routed here (writing to `recv_dir`) by both the direct-accept
    // task and the inbox-poll task, so a file delivered through either channel
    // is reassembled into one staging file and committed on a verified END.
    let reasm = Arc::new(Mutex::new(crate::group::file_xfer::Reassembler::new(recv_dir)));

    // Single shared writer so the inbound task and the stdin REPL don't
    // interleave each other's lines. (println! across threads has no
    // atomicity guarantee; observed output: "[no-group, pee[listen]…".)
    let stdout = Arc::new(Mutex::new(tokio::io::stdout()));

    // Print our own ticket up front so the inviter (or another peer
    // running listen) can address us.
    {
        let mut out = stdout.lock().await;
        match print_local_address(&processor).await {
            Ok(t) => {
                let _ = out.write_all(format!("Listening at: {t}\n").as_bytes()).await;
            }
            Err(e) => {
                let _ = out.write_all(format!("(warning: local_addr unavailable: {e})\n").as_bytes()).await;
            }
        }
        let _ = out.flush().await;
    }

    let group_id = Arc::new(Mutex::new(initial_group_id));
    let recipients = Arc::new(Mutex::new(initial_recipients));
    // Membership baselines, one per group. Unlike `chat_group_loop` this loop
    // has one recipient list but many possible groups — `/gid` switches which
    // one it addresses — so a single baseline would end up measuring one
    // group's Commit against another group's roster. Seeded here for a group
    // named on the command line, and by `seed_roster` wherever a group first
    // becomes reachable later (`[joined]`, `/gid`).
    let rosters = Arc::new(Mutex::new(RosterSnapshots::new()));
    if let Some(gid) = initial_group_id {
        seed_roster(&processor, &rosters, &gid).await;
    }

    // Channel: inbound task signals "we were removed; please stop".
    let (kill_tx, mut kill_rx) = tokio::sync::mpsc::channel::<()>(1);

    // -------- inbox poll task --------------------------------------------
    // Only spawned when the processor has an inbox configured. Polls
    // every 2 s, dispatches each envelope through the shared MLS state
    // machine, and prints the resulting event with the same formatting
    // as the direct accept_next path so the user sees a uniform event
    // stream regardless of which channel delivered the message.
    //
    // Errors are surfaced to stdout but never break the loop — a
    // transient unreachable inbox should not stop us from accepting
    // future deliveries.
    let inbox_task: Option<tokio::task::JoinHandle<()>> = if processor.inbox().is_some() {
        let processor = Arc::clone(&processor);
        let group_id = Arc::clone(&group_id);
        let recipients = Arc::clone(&recipients);
        let rosters = Arc::clone(&rosters);
        let stdout = Arc::clone(&stdout);
        let kill_tx = kill_tx.clone();
        let reasm = Arc::clone(&reasm);
        Some(tokio::spawn(async move {
            let server = processor.inbox().expect("inbox checked above").clone();
            let mut cursor: u64 = 0;
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                let poll_res =
                    crate::network::inbox::poll(processor.endpoint_ref(), &server, cursor)
                        .await;
                let envelopes = match poll_res {
                    Ok((new_cursor, env)) => {
                        cursor = new_cursor;
                        env
                    }
                    Err(e) => {
                        // Remote-influenced the same way `[inbound err]` is: the
                        // inbox server's QUIC close reason is rendered verbatim
                        // into this string, and it lands in the same REPL the
                        // operator reads group events from.
                        let msg = crate::utils::sanitize_for_terminal_bounded(&e.to_string(), 256);
                        let mut out = stdout.lock().await;
                        let _ = out
                            .write_all(format!("[inbox poll err] {msg}\n").as_bytes())
                            .await;
                        let _ = out.flush().await;
                        continue;
                    }
                };
                for env in envelopes {
                    let evt = match processor.process_inbox_envelope(&env).await {
                        Ok(evt) => evt,
                        Err(e) => {
                            // The envelope being dispatched was posted by a
                            // remote peer, so its rejection reason can echo
                            // peer-chosen bytes into this REPL. Same gate.
                            let msg =
                                crate::utils::sanitize_for_terminal_bounded(&e.to_string(), 256);
                            let mut out = stdout.lock().await;
                            let _ = out
                                .write_all(format!("[inbox dispatch err] {msg}\n").as_bytes())
                                .await;
                            let _ = out.flush().await;
                            continue;
                        }
                    };
                    // Side-effect: NewGroup → adopt the gid only if that does
                    // not displace an already-active group, and announce which
                    // it was (see `adopt_new_group`), then take a membership
                    // baseline for it; EpochAdvanced → drop whoever left
                    // (see `prune_departed_recipients`), since a Commit reaches
                    // us through this channel too; Removed → signal the outer
                    // loop. Same logic as the inbound task; factor later if a
                    // third source appears.
                    if let IncomingGroupEvent::NewGroup { id } = &evt {
                        let line = adopt_new_group(&group_id, id).await;
                        seed_roster(&processor, &rosters, id).await;
                        let mut out = stdout.lock().await;
                        let _ = out.write_all(line.as_bytes()).await;
                        let _ = out.write_all(b"\n").await;
                        let _ = out.flush().await;
                        continue;
                    }
                    let mut pruned = None;
                    if let IncomingGroupEvent::EpochAdvanced { group_id: evt_gid, .. } = &evt {
                        let active = *group_id.lock().await;
                        if active == Some(*evt_gid) {
                            pruned = prune_departed_recipients(
                                &processor, evt_gid, &recipients, &rosters,
                            )
                            .await;
                        }
                    }
                    let is_removed = matches!(evt, IncomingGroupEvent::RemovedFromGroup { .. });
                    if let Some(line) = event_to_line(&evt, &reasm).await {
                        let mut out = stdout.lock().await;
                        let _ = out.write_all(line.as_bytes()).await;
                        let _ = out.write_all(b"\n").await;
                        let _ = out.flush().await;
                    }
                    if let Some(note) = pruned {
                        let mut out = stdout.lock().await;
                        let _ = out.write_all(note.as_bytes()).await;
                        let _ = out.write_all(b"\n").await;
                        let _ = out.flush().await;
                    }
                    if is_removed {
                        let _ = kill_tx.send(()).await;
                        return;
                    }
                }
            }
        }))
    } else {
        None
    };

    // -------- inbound task ------------------------------------------------
    let inbound = {
        let processor = Arc::clone(&processor);
        let group_id = Arc::clone(&group_id);
        let recipients = Arc::clone(&recipients);
        let rosters = Arc::clone(&rosters);
        let kill_tx = kill_tx.clone();
        let stdout = Arc::clone(&stdout);
        let reasm = Arc::clone(&reasm);
        tokio::spawn(async move {
            loop {
                let evt = match processor.accept_next().await {
                    Ok(evt) => evt,
                    Err(e) => {
                        // Don't break on transient errors.
                        //
                        // The rendered error carries peer-chosen text: an
                        // unauthenticated dialer's QUIC close reason arrives here
                        // inside `Transport(Accept("accept_bi: …"))`, and this
                        // REPL is where the operator reads `[joined]` /
                        // `[epoch advanced]` / `[removed]` to judge who is in the
                        // group. Strip the control/bidi characters that would let
                        // that peer erase or forge those lines, and bound the
                        // length so a repeated close can't flood the scrollback —
                        // the same gate `chat_group_loop`'s inbound task applies.
                        // Truncation only drops attacker-chosen tail: the error's
                        // own scaffolding is printed first, the peer's bytes last.
                        let msg = crate::utils::sanitize_for_terminal_bounded(&e.to_string(), 256);
                        let mut out = stdout.lock().await;
                        let _ = out
                            .write_all(format!("[inbound err] {msg}\n").as_bytes())
                            .await;
                        let _ = out.flush().await;
                        continue;
                    }
                };
                // Side effects: on join adopt the gid unless that would
                // displace an already-active group, print which it was (see
                // `adopt_new_group`) and take a membership baseline for it; on
                // an epoch change drop the recipients that Commit removed (see
                // `prune_departed_recipients`); on self-removal print, signal
                // the outer loop, and stop.
                let mut pruned = None;
                match &evt {
                    IncomingGroupEvent::NewGroup { id } => {
                        let line = adopt_new_group(&group_id, id).await;
                        seed_roster(&processor, &rosters, id).await;
                        let mut out = stdout.lock().await;
                        let _ = out.write_all(line.as_bytes()).await;
                        let _ = out.write_all(b"\n").await;
                        let _ = out.flush().await;
                        continue;
                    }
                    IncomingGroupEvent::RemovedFromGroup { .. } => {
                        if let Some(line) = event_to_line(&evt, &reasm).await {
                            let mut out = stdout.lock().await;
                            let _ = out.write_all(line.as_bytes()).await;
                            let _ = out.write_all(b"\n").await;
                            let _ = out.flush().await;
                        }
                        let _ = kill_tx.send(()).await;
                        break;
                    }
                    IncomingGroupEvent::EpochAdvanced { group_id: evt_gid, .. } => {
                        let active = *group_id.lock().await;
                        if active == Some(*evt_gid) {
                            pruned = prune_departed_recipients(
                                &processor, evt_gid, &recipients, &rosters,
                            )
                            .await;
                        }
                    }
                    _ => {}
                }
                if let Some(line) = event_to_line(&evt, &reasm).await {
                    let mut out = stdout.lock().await;
                    let _ = out.write_all(line.as_bytes()).await;
                    let _ = out.write_all(b"\n").await;
                    let _ = out.flush().await;
                }
                if let Some(note) = pruned {
                    let mut out = stdout.lock().await;
                    let _ = out.write_all(note.as_bytes()).await;
                    let _ = out.write_all(b"\n").await;
                    let _ = out.flush().await;
                }
            }
        })
    };

    // -------- outbound (stdin) half --------------------------------------
    use tokio::io::{AsyncBufReadExt, BufReader};
    let stdin = tokio::io::stdin();
    let mut lines = BufReader::new(stdin).lines();
    // Helper to atomically print a line via the shared writer.
    let say = |s: String| {
        let stdout = Arc::clone(&stdout);
        async move {
            let mut out = stdout.lock().await;
            let _ = out.write_all(s.as_bytes()).await;
            let _ = out.write_all(b"\n").await;
            let _ = out.flush().await;
        }
    };
    loop {
        tokio::select! {
            _ = kill_rx.recv() => {
                say("[listen] stopping (we were removed)".to_string()).await;
                break;
            }
            maybe_line = lines.next_line() => {
                match maybe_line {
                    Ok(Some(line)) => {
                        let trimmed = line.trim().to_string();
                        if trimmed.is_empty() {
                            continue;
                        }
                        if trimmed == "/quit" {
                            say("[listen] quit".to_string()).await;
                            break;
                        } else if let Some(rest) = trimmed.strip_prefix("/peer ") {
                            match rest.trim().parse::<Ticket>() {
                                Ok(t) => {
                                    let addr = t.peer_addr();
                                    let mut rs = recipients.lock().await;
                                    rs.push(addr);
                                    let n = rs.len();
                                    drop(rs);
                                    say(format!(
                                        "[listen] added recipient (total: {n})"
                                    ))
                                    .await;
                                }
                                Err(e) => say(format!("[listen] bad ticket: {e}")).await,
                            }
                        } else if let Some(rest) = trimmed.strip_prefix("/gid ") {
                            match parse_gid_hex(rest.trim()) {
                                Ok(g) => {
                                    let mut gid = group_id.lock().await;
                                    *gid = Some(g);
                                    drop(gid);
                                    // Epoch changes for `g` were ignored while
                                    // it was inactive, so give it a baseline
                                    // now if it has none.
                                    seed_roster(&processor, &rosters, &g).await;
                                    say(format!("[listen] active group set to {g}")).await;
                                }
                                Err(e) => say(format!("[listen] bad gid: {e}")).await,
                            }
                        } else if let Some(_rest) = trimmed.strip_prefix("/status") {
                            let gid = *group_id.lock().await;
                            let n = recipients.lock().await.len();
                            let gid_str = match gid {
                                Some(g) => format!("{g}"),
                                None => "<none>".to_string(),
                            };
                            say(format!("[listen] gid={gid_str} peers={n}")).await;
                        } else if let Some(rest) = trimmed.strip_prefix("/add ") {
                            // /add <kp_path> <new_member_ticket>
                            //
                            // In-REPL add-member: reuses this process's
                            // already-bound iroh endpoint instead of forking a
                            // separate `--mls-cmd add-member` invocation.
                            // For N-member group builds the per-invocation
                            // cost drops from ~270 ms (process start +
                            // endpoint bind + 200 ms linger) to ~20-50 ms
                            // (just the MLS state mutation + Welcome/Commit
                            // QUIC handshakes on the existing endpoint).
                            //
                            // The ticket is the LAST whitespace-separated
                            // token; everything before it is the KeyPackage
                            // file path. Splits at the LAST space so paths
                            // with spaces still work (tickets are BASE32
                            // and contain no whitespace).
                            let rest = rest.trim();
                            let (kp_path_str, ticket_str) =
                                match rest.rsplit_once(char::is_whitespace) {
                                    Some((p, t)) if !p.is_empty() && !t.is_empty() => (p, t),
                                    _ => {
                                        say("[listen] usage: /add <kp_file> <ticket>".to_string())
                                            .await;
                                        continue;
                                    }
                                };
                            let gid = match *group_id.lock().await {
                                Some(g) => g,
                                None => {
                                    say("[listen] /add needs an active group — use /gid first".to_string())
                                        .await;
                                    continue;
                                }
                            };
                            let new_ticket: Ticket = match ticket_str.parse() {
                                Ok(t) => t,
                                Err(e) => {
                                    say(format!("[listen] /add: bad ticket: {e}")).await;
                                    continue;
                                }
                            };
                            let recipient = new_ticket.peer_addr();
                            let existing = recipients.lock().await.clone();
                            match add_member(
                                &processor,
                                &gid,
                                std::path::Path::new(kp_path_str),
                                &recipient,
                                &existing,
                            )
                            .await
                            {
                                Ok(()) => {
                                    let mut rs = recipients.lock().await;
                                    rs.push(recipient);
                                    let n = rs.len();
                                    drop(rs);
                                    say(format!("[listen] /add ok — recipients now {n}")).await;
                                }
                                Err(e) => say(format!("[listen] /add failed: {e}")).await,
                            }
                        } else if trimmed.starts_with('/') {
                            say(format!(
                                "[listen] unknown command {trimmed:?}. Try /peer, /gid, /status, /add, /quit."
                            ))
                            .await;
                        } else {
                            // Plain text → send as application message.
                            let gid_opt = *group_id.lock().await;
                            let recips = recipients.lock().await.clone();
                            match (gid_opt, recips.is_empty()) {
                                (None, _) => {
                                    say("[listen] no active group yet — wait for [joined] or use /gid".to_string())
                                        .await;
                                }
                                (_, true) => {
                                    say("[listen] no recipients — use /peer <ticket>".to_string())
                                        .await;
                                }
                                (Some(gid), false) => {
                                    match processor
                                        .send_application_message(
                                            &gid,
                                            trimmed.as_bytes(),
                                            &recips,
                                        )
                                        .await
                                    {
                                        Ok(_) => {
                                            say(format!("[me] {trimmed}")).await;
                                        }
                                        Err(e) => {
                                            // A send failure carries the
                                            // *recipient's* text — its QUIC close
                                            // reason via `Connect`/`open_bi` —
                                            // so it needs the same terminal gate
                                            // as the inbound errors above.
                                            let msg =
                                                crate::utils::sanitize_for_terminal_bounded(
                                                    &e.to_string(),
                                                    256,
                                                );
                                            say(format!("[send err] {msg}")).await;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Ok(None) => {
                        say("[listen] stdin closed".to_string()).await;
                        break;
                    }
                    Err(e) => {
                        say(format!("[listen stdin err] {e}")).await;
                        break;
                    }
                }
            }
        }
    }

    inbound.abort();
    if let Some(t) = inbox_task {
        t.abort();
    }
    Ok(())
}

/// Decide whether an inbound `NewGroup` may become the listener's active
/// send target, and render the operator-facing line announcing it.
///
/// By the time we get here the Welcome has already been processed, so we are
/// a member of `id` either way — this governs only *which* group the lines the
/// operator subsequently types are encrypted to. Adopting unconditionally let
/// any peer holding one of our published KeyPackages silently re-point the
/// session: the operator kept typing, every line was encrypted to the
/// intruder's group instead of the intended one, the REPL still echoed
/// `[me] …`, and the intended recipients could not read it. So a new gid is
/// adopted only when no group is active yet, or when the Welcome is for the
/// group that is already active (a re-add must not read as a refusal).
/// Otherwise the group is joined but not activated and the operator is told
/// the `/gid` needed to switch into it deliberately.
///
/// `GroupId`'s `Display` is `hex::encode` of its 32 raw bytes, so the
/// rendered gid carries no peer-controlled text and needs no terminal
/// sanitising.
async fn adopt_new_group(
    group_id: &tokio::sync::Mutex<Option<GroupId>>,
    id: &GroupId,
) -> String {
    let mut active = group_id.lock().await;
    let adopted = match *active {
        None => {
            *active = Some(*id);
            true
        }
        Some(current) => current == *id,
    };
    drop(active);
    if adopted {
        format!("[joined] {id} (active)")
    } else {
        format!("[joined] {id} (not active — /gid {id} to switch)")
    }
}

/// The node ids a running loop last saw on a group's roster, per group.
///
/// A missing entry means "never looked", which is what makes the first look
/// able only to record and never to drop: a departure is only visible as the
/// difference between two observations.
type RosterSnapshots =
    std::collections::HashMap<GroupId, std::collections::HashSet<[u8; 32]>>;

/// Record `gid`'s roster as this session's baseline, unless one is held.
///
/// Without a baseline the first epoch change for a group can only record, so
/// the member that Commit evicted would stay addressed until the *next* one.
/// Seeding at every point a group first becomes reachable by the session
/// (loop start, `[joined]`, `/gid`) is what keeps that window shut.
///
/// An existing baseline is never overwritten: it may predate a `/gid` detour,
/// and a member who left during the detour is only detectable against the
/// older set — the epoch change that evicted them was skipped as not-active.
///
/// A roster that fails to load leaves no baseline and says nothing: the same
/// read has already been made and reported by `resolve_recipients` before
/// either loop starts, and the next epoch change retries it.
async fn seed_roster(
    processor: &GroupChatProcessor,
    rosters: &tokio::sync::Mutex<RosterSnapshots>,
    gid: &GroupId,
) {
    let mut snaps = rosters.lock().await;
    if snaps.contains_key(gid) {
        return;
    }
    if let Ok(members) = processor.current_member_node_ids(gid) {
        snaps.insert(*gid, members);
    }
}

/// Drop from a running loop's recipient set exactly the peers that have **left**
/// `gid` since this session last looked, then refresh the baseline. Returns the
/// operator-facing note, or `None` when nothing was dropped.
///
/// The address book is already filtered on read, so no *new* invocation can
/// resolve an evicted peer — but a chat/listen loop resolves its recipients
/// once, before the loop starts, and then holds that list for the whole
/// session. The node that processes the Remove Commit is exactly the node
/// still holding the removed peer in that list, so without this it keeps
/// dialling it and leaking ciphertext, timing and size metadata at it until
/// the operator restarts. Hooked to the inbound event rather than to a timer
/// or to each send: the epoch changing is the only moment membership can have
/// changed under a running session.
///
/// A departure is measured as a **delta**, never as a roster match. Retaining
/// only current members instead would delete every address that was never on
/// this roster: a `--mls-recipient-ticket` or `/peer` address, which
/// [`resolve_recipients`] deliberately passes through unfiltered, and — since
/// `listen_loop` shares one recipient list across every group it can address —
/// the members of all the *other* groups.
///
/// The map lock is released before the recipient lock is taken, so the two are
/// never held together and no ordering between them can arise.
///
/// The count is ours and the rest is a static literal, so nothing
/// peer-influenced reaches the terminal.
async fn prune_departed_recipients(
    processor: &GroupChatProcessor,
    gid: &GroupId,
    recipients: &tokio::sync::Mutex<Vec<PeerAddr>>,
    rosters: &tokio::sync::Mutex<RosterSnapshots>,
) -> Option<String> {
    let current = match processor.current_member_node_ids(gid) {
        Ok(c) => c,
        // Keep both the list and the baseline: a roster that cannot be loaded
        // fails every send from the same group state anyway, so guessing here
        // could only remove a still-valid recipient on top of that.
        Err(e) => {
            return Some(format!(
                "[mls] could not re-check recipients against the roster: {}",
                crate::utils::sanitize_for_terminal_bounded(&e.to_string(), 256)
            ))
        }
    };
    let departed: std::collections::HashSet<[u8; 32]> = {
        let mut snaps = rosters.lock().await;
        let seen = snaps.entry(*gid).or_default();
        let departed = seen.difference(&current).copied().collect();
        *seen = current;
        departed
    };
    if departed.is_empty() {
        return None;
    }
    let mut rs = recipients.lock().await;
    let before = rs.len();
    rs.retain(|a| !departed.contains(a.peer_id.as_bytes()));
    match before - rs.len() {
        // Somebody left, but we were not addressing them: say nothing rather
        // than report a drop that did not happen.
        0 => None,
        n => Some(format!(
            "[mls] dropped {n} recipient(s) removed from this group"
        )),
    }
}

fn parse_gid_hex(hex: &str) -> anyhow::Result<GroupId> {
    let bytes =
        hex::decode(hex).map_err(|e| anyhow!("invalid gid hex: {e}"))?;
    if bytes.len() != 32 {
        anyhow::bail!("gid must be 32 bytes (64 hex chars), got {}", bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(GroupId::new(arr))
}

/// Turn an inbound event into a display line, reassembling file-transfer frames
/// instead of printing them as chat. Returns `None` when there is nothing to
/// print (per-chunk `DATA` progress is suppressed to avoid flooding the log).
async fn event_to_line(
    evt: &IncomingGroupEvent,
    reasm: &tokio::sync::Mutex<crate::group::file_xfer::Reassembler>,
) -> Option<String> {
    use crate::group::file_xfer::{is_file_frame, FileStatus};
    if let IncomingGroupEvent::Message { group_id, sender_index, body } = evt {
        if is_file_frame(body) {
            // Attribute the frame to the MLS-authenticated (group, sender) so a
            // frame can only extend/finish a transfer opened by the same sender.
            let g: [u8; 32] = *group_id.as_bytes();
            return match reasm.lock().await.ingest(&g, *sender_index, body) {
                Some(FileStatus::Started { name, size }) => Some(format!(
                    "[file ⇩ {sender_index}@{group_id}] receiving {name:?} ({size} bytes)…"
                )),
                Some(FileStatus::Progress { .. }) => None,
                // The destination basename comes from the sender's START frame
                // (`safe_name` rejects only separators, NUL, `.` and `..`), so
                // ESC/CSI bytes reach the path. `{name:?}` is Debug-escaped
                // already; `path.display()` is not, hence the explicit filter.
                Some(FileStatus::Completed { name, path }) => Some(format!(
                    "[file ✓ {sender_index}@{group_id}] saved {name:?} → {}",
                    crate::utils::sanitize_for_terminal(&path.display().to_string())
                )),
                Some(FileStatus::Error(e)) => Some(format!(
                    "[file ✗ {sender_index}@{group_id}] {}",
                    crate::utils::sanitize_for_terminal(&e.to_string())
                )),
                None => None,
            };
        }
    }
    Some(render_event(evt))
}

fn render_event(evt: &IncomingGroupEvent) -> String {
    match evt {
        IncomingGroupEvent::NewGroup { id } => format!("[joined] {id}"),
        IncomingGroupEvent::Message {
            group_id,
            sender_index,
            body,
        } => {
            // UTF-8 lossy so a peer sending malformed bytes can't
            // crash our display; matches the 1:1 chat policy. Then strip the
            // control/bidi characters that would let a group member erase or
            // forge the event lines above their own — this REPL is where the
            // operator reads group and identity events to make trust
            // decisions, so spoofing it is not merely cosmetic. Applied here in
            // `render_event` so all of its call sites are covered.
            let text = crate::utils::sanitize_for_terminal(&String::from_utf8_lossy(body));
            format!("[{sender_index}@{group_id}] {text}")
        }
        IncomingGroupEvent::EpochAdvanced {
            group_id,
            new_epoch,
        } => format!("[epoch advanced] {group_id} → {new_epoch}"),
        IncomingGroupEvent::RemovedFromGroup {
            group_id,
            remover_index,
        } => format!("[removed] {group_id} (by leaf {remover_index})"),
    }
}

// -----------------------------------------------------------------------------
// Top-level dispatcher used by `main.rs`. Prints results to stdout/stderr.
// -----------------------------------------------------------------------------

pub async fn run(
    cmd: MlsCommand,
    processor: GroupChatProcessor,
) -> anyhow::Result<()> {
    match cmd {
        MlsCommand::CreateGroup { name } => {
            let gid = create_group(&processor, &name).await?;
            println!("Created group {name:?}: {gid}");
        }
        MlsCommand::ListGroups => {
            for gid in list_groups(&processor).await? {
                println!("{gid}");
            }
        }
        MlsCommand::ListMembers { group_id } => {
            for m in list_members(&processor, &group_id).await? {
                println!("index={}", m.index);
            }
        }
        MlsCommand::ProjectPolicy { group_id, template } => {
            let lines = project_policy(&processor, &group_id, &template).await?;
            eprintln!(
                "# projected {} verified member(s) of group {group_id}",
                lines.len()
            );
            for line in lines {
                println!("{line}");
            }
        }
        MlsCommand::ExportKeyPackage { output } => {
            export_key_package(&processor, &output).await?;
            eprintln!("KeyPackage written to {output:?}");
        }
        MlsCommand::AddMember {
            group_id,
            key_package_file,
            recipient_ticket,
            existing_member_tickets,
        } => {
            let recipient = recipient_ticket.peer_addr();
            // Existing members (who must receive the Commit): use the supplied
            // set if given, else the group's remembered hints — so you don't
            // re-list every current member on each add. Exclude the new member
            // (it gets a Welcome, not a Commit).
            processor.remember_member_tickets(&group_id, &existing_member_tickets);
            let mut existing = if !existing_member_tickets.is_empty() {
                tickets_to_peer_addrs(&existing_member_tickets)
            } else {
                processor.known_member_addrs(&group_id).unwrap_or_default()
            };
            existing.retain(|a| a.peer_id != recipient.peer_id);
            add_member(
                &processor,
                &group_id,
                &key_package_file,
                &recipient,
                &existing,
            )
            .await?;
            // Remember the freshly-added member for future sends/adds.
            processor.remember_member_tickets(&group_id, std::slice::from_ref(&recipient_ticket));
            eprintln!(
                "Added member; Welcome delivered to {recipient:?}; Commit to {} existing member(s)",
                existing.len()
            );
        }
        MlsCommand::RemoveMember {
            group_id,
            index,
            recipient_tickets,
        } => {
            // Refresh remembered hints for the remaining members from the
            // supplied tickets; if none supplied, fall back to the stored book.
            let addrs = resolve_recipients(&processor, &group_id, &recipient_tickets);
            remove_member(&processor, &group_id, index, &addrs).await?;
            eprintln!("Removed leaf {index} from {group_id}");
        }
        MlsCommand::AcceptOne => {
            // Print our own address first so the inviter knows where to
            // send the Welcome. The iroh NodeId is ephemeral per
            // process; printing it on every accept-one invocation is
            // the only practical way to surface it before we block.
            match print_local_address(&processor).await {
                Ok(ticket) => println!("Listening at: {ticket}"),
                Err(e) => eprintln!("(warning: local_addr unavailable: {e})"),
            }
            // Flush so the listener side sees the address even though
            // we're about to block on accept_next.
            use std::io::Write as _;
            let _ = std::io::stdout().flush();
            let evt = accept_one(&processor).await?;
            println!("{}", render_event(&evt));
            // Linger briefly so the sender's `send_mls_message` reads
            // back our ACK byte before we drop our iroh endpoint —
            // otherwise the sender surfaces a spurious "connection
            // lost" even though we successfully consumed the body.
            // 2.5 s mirrors the sender-side grace period in main.rs.
            tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
        }
        MlsCommand::Send {
            group_id,
            body,
            recipient_tickets,
        } => {
            let addrs = resolve_recipients(&processor, &group_id, &recipient_tickets);
            send_application_message(&processor, &group_id, body.as_bytes(), &addrs).await?;
            eprintln!("Sent to {} recipients", addrs.len());
        }
        MlsCommand::SendFile {
            group_id,
            path,
            recipient_tickets,
        } => {
            let addrs = resolve_recipients(&processor, &group_id, &recipient_tickets);
            // Stream the file frame-by-frame so a large file is never fully
            // resident in memory.
            let mut outgoing = crate::group::file_xfer::OutgoingFile::open(&path)
                .map_err(|e| anyhow!("open file {path:?}: {e}"))?;
            let name = outgoing.name().to_string();
            let mut frames = 0usize;
            while let Some(frame) = outgoing
                .next_frame()
                .map_err(|e| anyhow!("read file {path:?}: {e}"))?
            {
                send_application_message(&processor, &group_id, &frame, &addrs)
                    .await
                    .with_context(|| format!("send file frame {}", frames + 1))?;
                frames += 1;
            }
            eprintln!("Sent file {name:?} ({frames} frames) to {} recipients", addrs.len());
        }
        MlsCommand::ChatGroup {
            group_id,
            recipient_tickets,
        } => {
            let addrs = resolve_recipients(&processor, &group_id, &recipient_tickets);
            let stdin = tokio::io::stdin();
            let stdout = Arc::new(tokio::sync::Mutex::new(tokio::io::stdout()));
            chat_group_loop(Arc::new(processor), group_id, addrs, stdin, stdout).await?;
        }
        MlsCommand::Listen {
            group_id,
            recipient_tickets,
            recv_dir,
        } => {
            // Listen accepts a group_id only when one was supplied; the remembered
            // hints are looked up per group, so only resolve when we know which.
            let addrs = match group_id {
                Some(gid) => resolve_recipients(&processor, &gid, &recipient_tickets),
                None => tickets_to_peer_addrs(&recipient_tickets),
            };
            listen_loop(Arc::new(processor), group_id, addrs, recv_dir).await?;
        }
        MlsCommand::PrintLocalAddress => {
            let ticket = print_local_address(&processor).await?;
            println!("{ticket}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::storage::GroupStorage;
    use crate::p2p::backend::mock::MockNetwork;
    use crate::p2p::{P2pProtocol, PeerId};
    use tempfile::tempdir;

    /// `default_storage_path` derives `$HOME/.local/share/nkct/groups.db`
    /// and creates the parent directory. Override `$HOME` to a tempdir
    /// so the test doesn't touch the user's real home.
    #[test]
    fn default_storage_path_uses_home() {
        let dir = tempdir().expect("tempdir");
        // SAFETY: `set_var` in a single-threaded test is fine.
        // SAFETY: env::set_var is unsafe as of Rust 1.85; document the
        // single-threaded-test assumption explicitly.
        unsafe {
            std::env::set_var("HOME", dir.path());
        }
        let p = default_storage_path().expect("path");
        assert_eq!(
            p,
            dir.path().join(".local/share/nkct/groups.db"),
            "default path should be under $HOME/.local/share/nkct"
        );
        assert!(
            p.parent().unwrap().is_dir(),
            "parent dir should have been created"
        );
    }

    /// Build a `GroupChatProcessor` on a shared `MockNetwork` against
    /// a tempdir-backed sqlite. Returns the processor + tempdir guard.
    fn build_test_processor(
        net: &Arc<MockNetwork>,
        name: &str,
        peer_byte: u8,
    ) -> (GroupChatProcessor, tempfile::TempDir) {
        let dir = tempdir().expect("tempdir");
        let storage = GroupStorage::open_at(
            dir.path().join("groups.db"),
            crate::group::storage::test_passphrase(),
        )
        .expect("storage");
        let ep = net.register(
            PeerId::new([peer_byte; 32]),
            vec![P2pProtocol(crate::network::ALPN_MLS)],
        );
        let proc = GroupChatProcessor::new(name, Arc::new(ep), storage, None).expect("processor");
        (proc, dir)
    }

    /// End-to-end CLI dispatch: cover the bytes-on-disk handoff
    /// (`export_key_package` writes a file, `add_member` reads it),
    /// the Welcome-over-ALPN round-trip, and the read paths
    /// (`list_groups`, `list_members`). This is the P7 "CLI shape"
    /// acceptance check — every handler that wires the user-facing
    /// flow is exercised in one test.
    #[tokio::test]
    async fn cli_handlers_end_to_end() {
        let net = MockNetwork::new();
        let (alice, _dir_a) = build_test_processor(&net, "alice", 1);
        let (bob, _dir_b) = build_test_processor(&net, "bob", 2);
        let bob_addr = bob.local_addr().await.expect("bob addr");

        // 1) Bob exports a KeyPackage to a file.
        let kp_dir = tempdir().expect("kp dir");
        let kp_path = kp_dir.path().join("bob.kp");
        export_key_package(&bob, &kp_path)
            .await
            .expect("export kp");
        assert!(kp_path.exists());
        let kp_size = std::fs::metadata(&kp_path).unwrap().len();
        assert!(kp_size > 1_000, "hybrid KeyPackage should be > 1 KiB");

        // 2) Alice creates a group.
        let gid = create_group(&alice, "test-team").await.expect("create");
        let listed = list_groups(&alice).await.expect("list");
        assert_eq!(listed, vec![gid]);
        let members = list_members(&alice, &gid).await.expect("members");
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].index, 0);

        // 3) Alice adds Bob (file-mediated KeyPackage handoff). Bob's
        // accept_one is spawned first so it's pending when Alice sends.
        let bob_task = {
            let task_bob = bob;
            tokio::spawn(async move {
                let evt = accept_one(&task_bob).await.expect("bob accepts");
                (evt, task_bob)
            })
        };
        tokio::task::yield_now().await;
        add_member(&alice, &gid, &kp_path, &bob_addr, &[])
            .await
            .expect("add_member");
        let (bob_evt, bob) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            bob_task,
        )
        .await
        .expect("bob timeout")
        .expect("bob task");
        match bob_evt {
            IncomingGroupEvent::NewGroup { id } => assert_eq!(id, gid),
            other => panic!("bob expected NewGroup, got {other:?}"),
        }

        // 4) Both peers see the group; both see 2 members.
        let bob_listed = list_groups(&bob).await.expect("bob list");
        assert_eq!(bob_listed, vec![gid]);
        let alice_members = list_members(&alice, &gid).await.expect("alice members");
        let bob_members = list_members(&bob, &gid).await.expect("bob members");
        assert_eq!(alice_members.len(), 2);
        assert_eq!(bob_members.len(), 2);
    }

    /// An inbound Welcome must never silently re-point the listener's active
    /// group, and must still adopt when no group is active yet.
    ///
    /// Regression: `listen_loop`'s inbound task and its inbox-poll task both
    /// overwrote the shared active gid on every `NewGroup`, so any peer
    /// holding one of our published KeyPackages could deliver a Welcome and
    /// redirect every line the operator typed afterwards into a group it
    /// controls — overriding even an explicit `--mls-group-id`. Both sinks now
    /// route the decision through `adopt_new_group`.
    #[tokio::test]
    async fn inbound_welcome_never_replaces_the_active_group() {
        use tokio::sync::Mutex;

        let team = GroupId::new([0x11; 32]);
        let intruder = GroupId::new([0xaa; 32]);

        // An explicitly-set active group (`--mls-group-id`, or `/gid`)
        // survives a Welcome for a different group, and the operator is told
        // exactly what to type to switch.
        let active = Mutex::new(Some(team));
        let line = adopt_new_group(&active, &intruder).await;
        assert_eq!(
            *active.lock().await,
            Some(team),
            "an inbound Welcome must not replace the active group"
        );
        assert!(
            line.contains(&format!("/gid {intruder}")),
            "non-adoption must surface the /gid needed to switch, got {line:?}"
        );

        // The honest first-Welcome flow (listener started with no
        // --mls-group-id) still adopts, with no extra operator step.
        let active = Mutex::new(None);
        let line = adopt_new_group(&active, &team).await;
        assert_eq!(
            *active.lock().await,
            Some(team),
            "the first Welcome must still become the active group"
        );
        assert!(
            !line.contains("/gid "),
            "an adopted group needs no switch hint, got {line:?}"
        );

        // A second Welcome, from a different group, does not displace the
        // group adopted from the first one.
        let line = adopt_new_group(&active, &intruder).await;
        assert_eq!(*active.lock().await, Some(team));
        assert!(line.contains(&format!("/gid {intruder}")), "got {line:?}");

        // A re-add / re-invite for the group that is already active is not a
        // spurious refusal: it stays active and prints no switch hint.
        let line = adopt_new_group(&active, &team).await;
        assert_eq!(*active.lock().await, Some(team));
        assert!(
            !line.contains("/gid "),
            "a re-add of the active group must not read as a refusal, got {line:?}"
        );
    }

    /// Poll `buf` until it contains `needle`, or panic after 10 s. The loop
    /// writes the event line only after it has finished reacting to the event,
    /// so seeing the line means the reaction is complete — no sleep-and-hope.
    async fn wait_for_output(buf: &Arc<tokio::sync::Mutex<Vec<u8>>>, needle: &str) -> String {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let seen = String::from_utf8_lossy(&buf.lock().await.clone()).into_owned();
            if seen.contains(needle) {
                return seen;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for {needle:?}; saw: {seen:?}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    /// A member evicted while a chat session is *running* stops being addressed
    /// by that session, and the surviving member keeps being addressed.
    ///
    /// Regression: `chat_group_loop` resolved its recipients once, before the
    /// loop started, and held that `Vec` for the rest of the session. The
    /// address book's roster filter could not help — it is only consulted by a
    /// *new* invocation, and `accept_next` runs only inside these loops, so the
    /// node that processes the Remove Commit is exactly the node whose
    /// recipient list is already frozen. Every later message, Commit and file
    /// frame kept being dialled at the evicted peer: it cannot decrypt the new
    /// epoch, but it learns the group is live and reads per-message timing,
    /// size and sender-address metadata off a connection we keep opening.
    ///
    /// Alice evicts Bob and only Carol processes the Commit, so Carol's loop is
    /// the frozen-list node. Three directions are asserted, because the prune
    /// has to be exact in both senses:
    ///
    /// * Bob, who left, is not dialled at all — the leak itself;
    /// * Alice, who stayed, still receives — an over-firing prune that emptied
    ///   the list would show up here;
    /// * Dave, never a member of this group, still receives. He stands for
    ///   every address that was never on this roster: a `/peer` or
    ///   `--mls-recipient-ticket` peer, which `resolve_recipients` passes
    ///   through unfiltered by design, and (in `listen_loop`, whose one
    ///   recipient list is shared across groups) the members of every other
    ///   group. Retaining "current members only" would silently revoke all of
    ///   them at the first epoch change; only a *departure* may drop an
    ///   address.
    #[tokio::test]
    async fn chat_loop_stops_addressing_a_member_evicted_mid_session() {
        let net = MockNetwork::new();
        let (alice, _dir_a) = build_test_processor(&net, "alice", 1);
        let (bob, _dir_b) = build_test_processor(&net, "bob", 2);
        let (carol, _dir_c) = build_test_processor(&net, "carol", 3);
        let (dave, _dir_d) = build_test_processor(&net, "dave", 4);
        let bob = Arc::new(bob);
        let carol = Arc::new(carol);
        let alice_addr = alice.local_addr().await.expect("alice addr");
        let bob_addr = bob.local_addr().await.expect("bob addr");
        let carol_addr = carol.local_addr().await.expect("carol addr");
        let dave_addr = dave.local_addr().await.expect("dave addr");

        // ---- build the 3-member group (Alice, Bob, Carol) ------------------
        let gid = create_group(&alice, "evict-test").await.expect("create");
        let bob_kp = bob.export_key_package().await.expect("bob kp");
        let carol_kp = carol.export_key_package().await.expect("carol kp");

        let add_bob = alice.add_member(&gid, &bob_kp).await.expect("add bob");
        let task = {
            let bob = Arc::clone(&bob);
            tokio::spawn(async move { bob.accept_next().await })
        };
        alice
            .send_welcome_to(&bob_addr, &add_bob.welcome)
            .await
            .expect("welcome→bob");
        task.await.expect("bob task").expect("bob accepts welcome");

        let add_carol = alice.add_member(&gid, &carol_kp).await.expect("add carol");
        let bob_task = {
            let bob = Arc::clone(&bob);
            tokio::spawn(async move { bob.accept_next().await })
        };
        let carol_task = {
            let carol = Arc::clone(&carol);
            tokio::spawn(async move { carol.accept_next().await })
        };
        alice
            .send_welcome_to(&carol_addr, &add_carol.welcome)
            .await
            .expect("welcome→carol");
        alice
            .broadcast_commit(&add_carol.commit, &[bob_addr.clone()])
            .await
            .expect("commit→bob");
        bob_task.await.expect("bob task").expect("bob accepts commit");
        carol_task
            .await
            .expect("carol task")
            .expect("carol accepts welcome");

        // ---- Carol starts chatting, addressing all three peers -------------
        // Dave is in the list without ever being in the group — the state a
        // `/peer` or `--mls-recipient-ticket` address is in. `fanout_send`
        // spawns every recipient into one JoinSet and joins them all before
        // returning, so once any one of them has been delivered the others
        // have at least been attempted; no ordering assumption is needed.
        let (mut stdin_tx, stdin_rx) = tokio::io::duplex(4096);
        let out_buf: Arc<tokio::sync::Mutex<Vec<u8>>> =
            Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let chat = {
            let carol = Arc::clone(&carol);
            let out_buf = Arc::clone(&out_buf);
            let recipients = vec![bob_addr.clone(), dave_addr.clone(), alice_addr.clone()];
            tokio::spawn(async move {
                chat_group_loop(carol, gid, recipients, stdin_rx, out_buf).await
            })
        };

        // ---- Alice evicts Bob; only the running session learns of it -------
        // Bob is leaf 1 (added first); pinned by the P6 list_members test.
        let remove_commit = alice.remove_member(&gid, 1).await.expect("remove bob");
        alice
            .broadcast_commit(&remove_commit, &[carol_addr.clone()])
            .await
            .expect("remove commit→carol");
        wait_for_output(&out_buf, "[epoch advanced]").await;

        // ---- the running loop sends its next line --------------------------
        stdin_tx
            .write_all(b"after-eviction\n")
            .await
            .expect("write stdin");

        // Direction 1: the surviving member is still addressed.
        let alice_evt = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            alice.accept_next(),
        )
        .await
        .expect("alice timeout")
        .expect("alice accepts message");
        match alice_evt {
            IncomingGroupEvent::Message { body, .. } => assert_eq!(
                body, b"after-eviction",
                "the surviving member must still receive the session's messages"
            ),
            other => panic!("alice expected Message, got {other:?}"),
        }

        // Direction 2: the peer who was never a member is still addressed. He
        // cannot decrypt, so `accept_next` resolves to an error — but it does
        // resolve, and only bytes on a connection we opened can make it do so.
        // Timing out here is the regression: the prune reached past the one
        // node that left and revoked an address the operator chose by hand.
        let dave_res =
            tokio::time::timeout(std::time::Duration::from_secs(5), dave.accept_next()).await;
        assert!(
            dave_res.is_ok(),
            "an epoch change must not revoke an explicitly supplied non-member recipient"
        );

        // Direction 3: the evicted member is not dialled at all. The mock
        // transport queues an incoming connection the instant `connect`
        // returns, so by the time the fan-out has reached Alice and Dave, a
        // send to Bob would already be sitting in his queue and `accept_next`
        // would return at once instead of blocking.
        let bob_res =
            tokio::time::timeout(std::time::Duration::from_secs(2), bob.accept_next()).await;
        assert!(
            bob_res.is_err(),
            "a running session must stop delivering to an evicted member, got {:?}",
            bob_res.map(|r| r.map(|e| format!("{e:?}"))),
        );

        // The drop is announced, and the count is exactly the one node that
        // left — a prune that also took Dave would read "2".
        let seen = String::from_utf8_lossy(&out_buf.lock().await.clone()).into_owned();
        assert!(
            seen.contains("[mls] dropped 1 recipient(s) removed from this group"),
            "the operator must be told exactly which count of recipients went away, got {seen:?}"
        );

        drop(stdin_tx);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), chat).await;
    }

    /// `print_local_address` round-trips through the Ticket codec.
    /// Decoding it back must reproduce the same PeerAddr (peer_id at
    /// minimum — direct_addrs/relay are mock-empty).
    #[tokio::test]
    async fn print_local_address_roundtrips_via_ticket() {
        let net = MockNetwork::new();
        let (alice, _dir) = build_test_processor(&net, "alice", 1);
        let s = print_local_address(&alice).await.expect("local addr");
        assert!(
            s.starts_with('n'),
            "ticket strings start with the 'n' prefix marker, got: {s:?}"
        );
        let parsed: Ticket = s.parse().expect("parse ticket");
        let alice_addr = alice.local_addr().await.expect("alice addr");
        assert_eq!(parsed.peer_addr().peer_id, alice_addr.peer_id);
    }
}
