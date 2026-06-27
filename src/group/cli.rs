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
    /// Inbound `NewGroup` events auto-set the active group id, so a
    /// freshly-invited peer that has the inviter's ticket via
    /// `/peer` is ready to chat as soon as the Welcome arrives.
    Listen {
        /// Optional initial group_id. If unset, the listener waits for
        /// the first `NewGroup` event (from an inbound Welcome) and
        /// adopts that gid.
        group_id: Option<GroupId>,
        /// Initial recipient tickets. More can be added later via
        /// the `/peer` stdin command.
        recipient_tickets: Vec<Ticket>,
    },
    /// Send a single application message to the given recipients.
    Send {
        group_id: GroupId,
        body: String,
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
    // Inbound task: run accept_next forever, push decoded events to
    // stdout via the shared writer.
    let inbound_processor = Arc::clone(&processor);
    let inbound_stdout = Arc::clone(&stdout);
    let inbound = tokio::spawn(async move {
        loop {
            match inbound_processor.accept_next().await {
                Ok(evt) => {
                    let line = render_event(&evt);
                    let mut out = inbound_stdout.lock().await;
                    let _ = out.write_all(line.as_bytes()).await;
                    let _ = out.write_all(b"\n> ").await;
                    let _ = out.flush().await;
                }
                Err(e) => {
                    let mut out = inbound_stdout.lock().await;
                    let _ = out
                        .write_all(format!("[err] {e}\n").as_bytes())
                        .await;
                    let _ = out.flush().await;
                    break;
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
        match processor
            .send_application_message(&group_id, body.as_bytes(), &recipients)
            .await
        {
            Ok(_) => {
                let mut out = stdout.lock().await;
                let _ = out.write_all(b"> ").await;
                let _ = out.flush().await;
            }
            Err(e) => {
                let mut out = stdout.lock().await;
                let _ = out
                    .write_all(format!("[send err] {e}\n> ").as_bytes())
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
//   NewGroup → also update `group_id`
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
) -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt;
    use tokio::sync::Mutex;

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
        let stdout = Arc::clone(&stdout);
        let kill_tx = kill_tx.clone();
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
                        let mut out = stdout.lock().await;
                        let _ = out
                            .write_all(format!("[inbox poll err] {e}\n").as_bytes())
                            .await;
                        let _ = out.flush().await;
                        continue;
                    }
                };
                for env in envelopes {
                    let evt = match processor.process_inbox_envelope(&env).await {
                        Ok(evt) => evt,
                        Err(e) => {
                            let mut out = stdout.lock().await;
                            let _ = out
                                .write_all(format!("[inbox dispatch err] {e}\n").as_bytes())
                                .await;
                            let _ = out.flush().await;
                            continue;
                        }
                    };
                    // Side-effect: NewGroup → adopt the gid; Removed →
                    // signal the outer loop. Same logic as the inbound
                    // task; factor later if a third source appears.
                    if let IncomingGroupEvent::NewGroup { id } = &evt {
                        let mut g = group_id.lock().await;
                        *g = Some(*id);
                    }
                    let is_removed = matches!(evt, IncomingGroupEvent::RemovedFromGroup { .. });
                    let line = render_event(&evt);
                    let mut out = stdout.lock().await;
                    let _ = out.write_all(line.as_bytes()).await;
                    let _ = out.write_all(b"\n").await;
                    let _ = out.flush().await;
                    drop(out);
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
        let kill_tx = kill_tx.clone();
        let stdout = Arc::clone(&stdout);
        tokio::spawn(async move {
            loop {
                let line: String = match processor.accept_next().await {
                    Ok(IncomingGroupEvent::NewGroup { id }) => {
                        {
                            let mut g = group_id.lock().await;
                            *g = Some(id);
                        }
                        format!("[joined] {id}")
                    }
                    Ok(IncomingGroupEvent::Message {
                        group_id: gid,
                        sender_index,
                        body,
                    }) => {
                        let text = String::from_utf8_lossy(&body).into_owned();
                        format!("[leaf {sender_index} @ {gid}] {text}")
                    }
                    Ok(IncomingGroupEvent::EpochAdvanced {
                        group_id: gid,
                        new_epoch,
                    }) => {
                        format!("[epoch advanced] {gid} → {new_epoch}")
                    }
                    Ok(IncomingGroupEvent::RemovedFromGroup {
                        group_id: gid,
                        remover_index,
                    }) => {
                        let s = format!("[removed] {gid} (by leaf {remover_index})");
                        // Emit the line through the shared writer, then
                        // signal the kill channel.
                        let mut out = stdout.lock().await;
                        let _ = out.write_all(s.as_bytes()).await;
                        let _ = out.write_all(b"\n").await;
                        let _ = out.flush().await;
                        let _ = kill_tx.send(()).await;
                        break;
                    }
                    Err(e) => {
                        // Don't break on transient errors.
                        let mut out = stdout.lock().await;
                        let _ = out
                            .write_all(format!("[inbound err] {e}\n").as_bytes())
                            .await;
                        let _ = out.flush().await;
                        continue;
                    }
                };
                let mut out = stdout.lock().await;
                let _ = out.write_all(line.as_bytes()).await;
                let _ = out.write_all(b"\n").await;
                let _ = out.flush().await;
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
                                            say(format!("[send err] {e}")).await;
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

fn render_event(evt: &IncomingGroupEvent) -> String {
    match evt {
        IncomingGroupEvent::NewGroup { id } => format!("[joined] {id}"),
        IncomingGroupEvent::Message {
            group_id,
            sender_index,
            body,
        } => {
            // UTF-8 lossy so a peer sending malformed bytes can't
            // crash our display; matches the 1:1 chat policy.
            let text = String::from_utf8_lossy(body);
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
            let existing = tickets_to_peer_addrs(&existing_member_tickets);
            add_member(
                &processor,
                &group_id,
                &key_package_file,
                &recipient,
                &existing,
            )
            .await?;
            eprintln!("Added member; Welcome delivered to {recipient:?}");
        }
        MlsCommand::RemoveMember {
            group_id,
            index,
            recipient_tickets,
        } => {
            let addrs = tickets_to_peer_addrs(&recipient_tickets);
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
            let addrs = tickets_to_peer_addrs(&recipient_tickets);
            send_application_message(&processor, &group_id, body.as_bytes(), &addrs).await?;
            eprintln!("Sent to {} recipients", addrs.len());
        }
        MlsCommand::ChatGroup {
            group_id,
            recipient_tickets,
        } => {
            let addrs = tickets_to_peer_addrs(&recipient_tickets);
            let stdin = tokio::io::stdin();
            let stdout = Arc::new(tokio::sync::Mutex::new(tokio::io::stdout()));
            chat_group_loop(Arc::new(processor), group_id, addrs, stdin, stdout).await?;
        }
        MlsCommand::Listen {
            group_id,
            recipient_tickets,
        } => {
            let addrs = tickets_to_peer_addrs(&recipient_tickets);
            listen_loop(Arc::new(processor), group_id, addrs).await?;
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
