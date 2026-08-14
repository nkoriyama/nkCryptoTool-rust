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
    ///   `/resync [ticket]`       — ask that peer — or, with no ticket, this
    ///                              session's whole recipient list, which is
    ///                              not the active group's roster — for the
    ///                              Commits we missed while unreachable, and
    ///                              apply them; the recovery path for a member
    ///                              that was offline when the roster changed.
    ///                              Reports the epoch it reached, never that we
    ///                              are current — no responder can establish
    ///                              that
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
    /// Ask peers for the Commits we missed and apply them (delta resync).
    ///
    /// The recovery path for a member that fell behind on the roster: it
    /// missed a Commit while unreachable and no store-and-forward relay
    /// was configured to catch it, the deposit itself failed, or it stayed
    /// away past the relay's envelope TTL. The delta-resync protocol has
    /// existed on both sides since the commit-history table was added, but
    /// until this command nothing outside the test suite called it.
    ///
    /// We send our *own* current epoch, so this asks only for what we are
    /// missing; the responder additionally refuses history from before we
    /// joined.
    ///
    /// It reports the epoch it reached, what our own state did across each
    /// peer's exchange, and what each peer said — and never that we are up to
    /// date: a SYNC responder is authenticated by nothing, so no peer's answer
    /// can establish currency (see [`ResyncReport`]).
    Resync {
        group_id: GroupId,
        /// The peer to ask — **at most one**. `run` refuses a longer list
        /// before anything is dialled: a responder's Commits are applied as
        /// they arrive, so the first peer asked would otherwise decide which of
        /// the others the sweep still reaches (see `PeerSource::Operator`).
        /// Ask a second peer with a second invocation.
        ///
        /// Empty means the group's remembered member addresses instead
        /// (`known_member_addrs`), and that form **is** a multi-peer sweep:
        /// **all** of them are asked, in order — see [`resync_sweep`] on why
        /// there is no first-answer-wins — where "all" means all still on the
        /// list when their turn comes, since a queued node a Commit applied
        /// during the sweep took off this group's roster is dropped instead of
        /// dialled.
        peer_tickets: Vec<Ticket>,
    },
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

    // Both halves failed against a *peer*, so both error strings can carry text
    // that peer chose (its QUIC close reason arrives inside `Connect(..)`).
    // These messages are the ones the operator reads to decide whether the new
    // member actually joined, and this error is printed raw by `main`'s
    // top-level handler on the one-shot `--mls-cmd add-member` path as well as
    // by the REPL, so the peer's text is gated here — once, where it enters the
    // message — instead of at each of those printers.
    let show = |e: &dyn std::fmt::Display| {
        crate::utils::sanitize_for_terminal_bounded(&e.to_string(), 256)
    };
    match (welcome_res, commit_res) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(we), Ok(())) => Err(anyhow!(
            "send Welcome reported {} but Commit broadcast succeeded; \
             new member may have joined regardless — verify on their side",
            show(&we)
        )),
        (Ok(()), Err(ce)) => Err(anyhow!(
            "broadcast Commit failed: {} (Welcome was delivered; existing \
             members are now out-of-sync with the new epoch)",
            show(&ce)
        )),
        (Err(we), Err(ce)) => Err(anyhow!(
            "send Welcome AND broadcast Commit failed: welcome={}; commit={}",
            show(&we),
            show(&ce)
        )),
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

/// One peer that completed an exchange, described **only** by what our own
/// state did across it.
///
/// Neither flag is the peer's account of its own stream. That distinction is
/// the whole point: a responder is authenticated by nothing, so a report that
/// makes a peer-supplied node id the subject of a positive sentence has to
/// derive the predicate from something this node holds.
#[derive(Debug, Clone)]
pub struct PeerAnswer {
    /// The address we dialled.
    pub peer: PeerAddr,
    /// Our own epoch, read from our own group state, was higher after this
    /// peer's exchange than before it.
    ///
    /// A **window**, not causation. `listen_loop` applies inbound Commits on a
    /// separate task, so one of those can land inside a peer's window and be
    /// counted here; [`ResyncReport::render`] words the line accordingly rather
    /// than saying the Commits came from this peer.
    pub advanced_us: bool,
    /// This peer's stream carried a Commit that removed **us** from the group,
    /// which mls-rs verified against our own state before we persisted it
    /// ([`crate::group::processor::ResyncOutcome::removed_us`]).
    ///
    /// Independent of `advanced_us`, and reported separately because of it:
    /// mls-rs does not advance our persisted epoch for the Commit that evicts
    /// us, so the common case is this `true` and `advanced_us` `false`. (Both
    /// are `true` when the same stream carried an earlier Commit we could
    /// apply.)
    ///
    /// **"Verified" is weaker here than on any other Commit**, which is a reason
    /// to render this as evidence about the peer and never as a finding about
    /// the group. mls-rs 0.55.2 gates `update_key_schedule` on `!is_self_removed`
    /// (`group/message_processor.rs:836-846`) and recomputes the confirmation tag
    /// only inside it (`group/mod.rs:2492-2499`), so on a Commit that removes us
    /// the tag is required to be *present* and is never checked against the
    /// transcript we would have derived. What still holds is the authentication
    /// mls-rs runs before that point, against the sender's leaf in our own tree.
    pub served_our_removal: bool,
}

/// What a [`resync`] sweep did, for the caller to render.
///
/// **What this can and cannot say.** A SYNC responder is authenticated by
/// nothing — `request_resync` dials a [`PeerAddr`] and reads whatever comes
/// back, and the exchange proves neither the responder's membership nor its
/// epoch nor that it runs this software. So every field here is a record of
/// what *this node* did: the epoch pair read from our own state, the per-peer
/// flags of [`PeerAnswer`], the count of queued peers dropped because a Commit
/// applied mid-sweep took them off the roster, and the node ids that left this
/// group's roster while the sweep ran. What a peer *said* lives in `failures`
/// and is rendered
/// as that peer's claim. In particular there is no "we are up to date" here to
/// render, because no peer can establish that; see [`ResyncReport::render`].
#[derive(Debug, Clone)]
pub struct ResyncReport {
    /// Our epoch before the sweep, read from our own group state.
    pub from_epoch: u64,
    /// Our epoch after it, re-read from our own group state. Re-read
    /// unconditionally, including when every peer failed: a stream that broke
    /// mid-way can still have carried Commits we verified and applied, and
    /// reporting the epoch captured before the sweep told the operator that
    /// recovery made no progress when it partly did.
    pub to_epoch: u64,
    /// How many peers the sweep actually asked. Every peer still on the list
    /// when its turn came is asked; see [`resync`] on why there is no
    /// first-answer-wins short circuit, and `skipped` for the one way a peer
    /// leaves the list.
    pub asked: usize,
    /// How many queued peers were dropped from the sweep because a Commit
    /// applied while it ran removed them from the group (see [`PeerSource`]).
    /// Normally that Commit came from the sweep itself; in a listener the
    /// inbound task can apply one too, which is why neither this nor the
    /// rendered line says which. Reported so "asked N peer(s)" is never quietly
    /// smaller than the list the operator started from.
    pub skipped: usize,
    /// The node ids this group's roster listed when the sweep started and does
    /// not list now, in byte order.
    ///
    /// **An observation, and nothing acts on it.** It is written in
    /// [`resync_sweep`] after the queue has drained and read in
    /// [`ResyncReport::render`]; the queue belongs to [`PeerSource::recheck`],
    /// which does not see this value, [`PeerSource::Operator`] still re-derives
    /// nothing, and no peer is dropped or refused because of what is here. It
    /// is reported because the ids that
    /// leave the roster during a sweep are largely *not* the peers the sweep
    /// asked — an address the operator holds a ticket for need not be on the
    /// queue at all — so `skipped`, which counts queue drops and names nobody,
    /// leaves them unreported, and the operator's next invocation is where such
    /// an address gets dialled.
    ///
    /// Both sides are read from our own state with
    /// [`GroupChatProcessor::current_member_node_ids`], whose ids are
    /// self-asserted by whoever seated the leaf carrying them; an unreadable
    /// roster on either read leaves this empty rather than inferring a
    /// departure.
    pub departed: Vec<crate::p2p::PeerId>,
    /// The peers that completed an exchange, in ask order.
    pub answered: Vec<PeerAnswer>,
    /// One rendered line per peer that failed, already sanitized and
    /// length-bounded by [`describe_resync_failure`].
    pub failures: Vec<String>,
}

impl ResyncReport {
    /// Render the sweep as operator-facing lines — facts first, attribution
    /// second, and no claim the exchange cannot support.
    ///
    /// The epoch pair is a fact about *our* state. "You are up to date" would
    /// be an inference from unauthenticated sources and is deliberately absent:
    /// four attacker-chosen bytes (`OK\x00\x00`, then close) are all it took to
    /// produce it, which is exactly what a member that has just been evicted
    /// and does not know it would have been shown.
    ///
    /// Where a node id **is** the subject of a sentence here, the predicate is
    /// measured on our own state: our epoch moved across that peer's exchange
    /// (a window — see [`PeerAnswer::advanced_us`]), mls-rs verified a Commit
    /// from it that removed us, or this group's roster listed that id when the
    /// sweep started and does not list it now ([`ResyncReport::departed`], which
    /// is reported, not acted on). Crediting a peer with
    /// "Commits came from you" on the strength of its own return value is what
    /// this deliberately does not do; `request_resync` reports a Commit that
    /// removes us as applied, and our epoch does not move for it, so that
    /// credit was reachable with the epoch line directly contradicting it.
    ///
    /// **None of those three is a statement about the group**, and the removal
    /// line in particular is not. mls-rs verifying a Commit says the sender held
    /// this group's state at the epoch we are at — no more. A member the group
    /// evicted at an epoch we have not applied still holds exactly that, so it
    /// can sign a Commit removing us that verifies here while every honest
    /// member's roster still lists us (there is a test that does it). Nor is it
    /// a verdict on the responder: where no join epoch was recorded for us, an
    /// honest responder that removed us and re-admitted us later serves that old
    /// Remove out of its retained history (`member_join_epoch` `None` does not
    /// clamp). So the line reports what was served, tells the operator to ask
    /// another peer, offers no re-admission advice and names no
    /// command: advice to go and take a fresh invitation is the steer that was
    /// removed from the `ERR\x01` path, for the reason
    /// `describe_resync_failure` gives below, and it lands in the same place —
    /// `join_group_from_welcome` refuses a Welcome for a gid we already hold, so
    /// the only Welcome that could be accepted is one for a *different* group,
    /// from whoever connects first.
    pub fn render(&self) -> Vec<String> {
        let mut out = Vec::new();
        // Line 1 is about **our own** epoch, which is the only thing here we
        // hold ourselves.
        if self.to_epoch > self.from_epoch {
            out.push(format!(
                "epoch {} → {} after asking {} peer(s) ({} answered, {} failed)",
                self.from_epoch,
                self.to_epoch,
                self.asked,
                self.answered.len(),
                self.failures.len()
            ));
        } else {
            out.push(format!(
                "our epoch did not move; still at epoch {} after asking {} peer(s) \
                 ({} answered, {} failed)",
                self.to_epoch,
                self.asked,
                self.answered.len(),
                self.failures.len()
            ));
        }
        if self.skipped > 0 {
            // Says what was measured — they were on the list, and this group's
            // roster does not list them now — and neither who the Commit removed
            // nor who applied it. Not who it removed, because the sweep can also
            // apply a Commit that removes *us*, and reading a drop back as "it
            // removed them" would be this node's own eviction reported as
            // theirs. Not who applied it, because on the listener path the drop
            // is `prune_departed_recipients`' decision and its baseline moves on
            // the inbound task too, so this side cannot tell a Commit the sweep
            // pulled from one that arrived while it ran (`ResyncReport::skipped`
            // says the same).
            out.push(format!(
                "{} queued peer(s) were not asked: this group's roster no longer lists \
                 them. A Commit applied while this sweep ran took them off it — in a \
                 listener the inbound task applies Commits too, so this does not say \
                 which applied it — and a peer we have just watched drop off the roster \
                 is not one to go on dialling",
                self.skipped
            ));
        }
        if !self.departed.is_empty() {
            // Reported on every source, because the silence this closes is not
            // the `Operator` path's alone: `skipped` covers a departure only
            // when the departing node happened to be on this sweep's queue, and
            // the address an operator dials next is typically one held as a
            // ticket and never queued here at all.
            //
            // Hex via `PeerId`'s `Display`, which is `hex::encode` of 32 bytes,
            // so a roster id — a field its own member writes — reaches this
            // line as 64 hex characters and brings no other text with it.
            //
            // The predicate stays on our own two reads. It is not "the group
            // removed them": these ids are self-asserted
            // (`current_member_node_ids` reads `peer_id` out of the member's own
            // credential), and a member that seats a leaf claiming any node id
            // and then removes it produces this line. Nor is it advice — what to
            // do about an address that has left the roster is the operator's,
            // with the same caveat every other line here carries.
            out.push(format!(
                "{} node id(s) this group's roster listed when the sweep started are not \
                 on it now: {}. Both sides read from our own state: this roster moves when \
                 a Commit is applied, and in a listener the inbound task applies Commits \
                 too, so this does not say which exchange carried the one that moved it. \
                 It reports what our roster holds, not what the group did — a roster node \
                 id is written by the member it describes. Named because passing a ticket \
                 for one of them to a later invocation dials a node this roster no longer \
                 lists",
                self.departed.len(),
                self.departed
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        // Attribution, and only of what our own state did.
        let advanced: Vec<String> = self
            .answered
            .iter()
            .filter(|a| a.advanced_us)
            .map(|a| a.peer.peer_id.to_string())
            .collect();
        if !advanced.is_empty() {
            // Deliberately a time window rather than "Commits came from": the
            // listener applies inbound Commits on another task, so this node
            // cannot attribute its own epoch change to the peer it was talking
            // to at the time.
            out.push(format!("our epoch advanced while asking: {}", advanced.join(", ")));
        }
        // Evidence about the responder, not about our membership. Every clause
        // below is checkable in this repository: signing such a Commit takes
        // this group's state at our epoch, which a member evicted at a later
        // epoch still has; a responder whose *own current roster* reflected this
        // Commit — i.e. no longer lists us — would have answered `ERR\x01`
        // instead of streaming anything (`accept_next`'s membership check); and
        // mls-rs skips `update_key_schedule` for a self-removal and drops the
        // provisional state, so **that Commit** leaves our epoch, tree and
        // roster as it found them.
        //
        // The last clause is scoped to that Commit on purpose. This line is
        // rendered once per report, and `request_resync` applies and persists
        // every Commit ahead of the removal before it breaks out of the stream,
        // so a responder that streams `[Remove(someone), Remove(us)]` moves us
        // for the first one. Line 1 is where that shows.
        //
        // Note also that the ERR\x01 clause is about the responder's roster, not
        // about whether it applied the Commit: a responder that removed us and
        // later re-admitted us does list us again, and with no join epoch
        // recorded for us (`member_join_epoch` `None` does not clamp) it serves
        // that old Remove out of its retained history while behaving honestly.
        // Hence "ask another peer" rather than a verdict on this one.
        let removals: Vec<String> = self
            .answered
            .iter()
            .filter(|a| a.served_our_removal)
            .map(|a| a.peer.peer_id.to_string())
            .collect();
        if !removals.is_empty() {
            out.push(format!(
                "{} served a Commit that removes us, and mls-rs verified it against the \
                 state we hold — which says the signer held this group's state at our \
                 epoch, not that we are out of the group: a member the group evicted at \
                 an epoch we have not applied still holds that state, and a responder \
                 whose own roster reflected this Commit would have answered ERR\\x01 \
                 rather than streamed it to us. Applying that Commit alone left our \
                 epoch, tree and roster as they were — mls-rs discards a self-removal — \
                 which says nothing about anything else the same stream sent first; \
                 line 1 above is where that shows. Ask another peer",
                removals.join(", ")
            ));
        }
        // Said on both outcomes, because it bounds both of them.
        out.push(
            "a SYNC responder is authenticated by nothing, so this reports what the peers we \
             reached sent us — not that we are current with the group"
                .to_string(),
        );
        out.extend(self.failures.iter().cloned());
        out
    }
}

/// Render one peer's resync failure as a line, **attributed to that peer**.
///
/// Classification is on the error variant, never on the rendered text. That
/// much is a real property: a QUIC close reason the peer chose arrives inside
/// `Transport(Connect(..))`, so substring matching let any failure be dressed
/// as either protocol rejection, and the variants close that route.
///
/// What the variant establishes is **that the responder sent those four bytes,
/// and nothing more.** It does not establish that the claim is true: the SYNC
/// exchange authenticates no part of the responder — not its membership, not
/// its view of the roster, not even that it runs this software — so any node
/// this caller dials can send `ERR\x01`. These lines therefore say "it claims",
/// name the wire code, and mark the claim unverified.
///
/// They also stop short of recommending a re-join. Advice to go and take a
/// fresh invitation would be one unauthenticated peer's four bytes steering the
/// operator into `--mls-cmd accept-one`, which is `accept_next` and authorizes
/// no sender (`join_group_from_welcome`), so whoever arrives next is the
/// inviter. Naming the peer and marking the claim unverified is what the code
/// can support; deciding what to do about it is the operator's, with more than
/// one peer's word to go on.
///
/// Everything else — transport failures included — falls through to the
/// passthrough branch with the peer's own text sanitized and length-bounded,
/// exactly as the add/remove paths do.
fn describe_resync_failure(peer: &PeerAddr, err: &crate::group::GroupError) -> String {
    use crate::group::GroupError;
    let node = peer.peer_id;
    match err {
        GroupError::SyncRejectedByRoster => format!(
            "{node} answered ERR\\x01: it claims we are not on this group's roster. \
             Unverified — nothing authenticates this responder, so this is that peer's \
             claim and not a finding that we were removed; ask another member before \
             acting on it"
        ),
        GroupError::SyncEpochPruned => format!(
            "{node} answered ERR\\x02: it claims it no longer retains the Commits we \
             asked for, so it cannot serve a delta. Unverified — that is this peer's \
             claim about its own store; another member may still have the history"
        ),
        other => format!(
            "{node}: {}",
            crate::utils::sanitize_for_terminal_bounded(&other.to_string(), 256)
        ),
    }
}

/// Where a sweep's peer list came from, and therefore how the peers it has
/// **not yet asked** are re-derived once our own state moves under the loop.
///
/// A sweep applies Commits into our own MLS state as it runs, so the list it
/// was handed can be stale by the second iteration. The concrete case: Alice
/// streams the Commit that removed Carol, we verify and persist it, and the
/// loop then dials Carol — telling a member we have just watched being evicted
/// that we are online, at what network path, for which group, and at what
/// post-eviction epoch, and putting her reply in the operator's REPL. That is
/// the same connection-attempt/size/timing channel
/// [`prune_departed_recipients`] exists to close, reopened between two
/// iterations of one loop.
///
/// **Where there is a re-derivation, it is the source's own filter, never a
/// fresh one.** A blunt "keep only this group's current members" pass over a
/// listener's recipient list is exactly the cross-group revocation that finding
/// F7 was about and that `prune_departed_recipients` spent five rounds learning
/// to avoid: one group's Remove Commit must not silently stop delivery to a peer
/// another operator-selected group still vouches for. So the two variants that
/// re-derive re-run the decision that produced their list and nothing more —
/// and [`PeerSource::Operator`] re-derives nothing at all, for the reason on
/// that variant.
enum PeerSource<'a> {
    /// The address the operator named on this invocation
    /// (`--mls-recipient-ticket`). **Re-derives nothing**: the queue is asked as
    /// it was handed over, so no answer takes another address off it. From the
    /// CLI there is nothing to re-derive in any case — `run`'s
    /// `MlsCommand::Resync` arm refuses a second ticket before anything is
    /// dialled, so that queue holds one peer and is empty by the time `recheck`
    /// could run. (The test-only [`resync`] entry point still accepts a longer
    /// slice, for the tests that need a two-peer sweep.)
    ///
    /// That one-ticket rule is what stands in for a filter here, and it replaced
    /// one. The re-derivation this path used to run diffed the roster read
    /// before the sweep against the live one — and the only thing that moves
    /// between those two reads is our own roster, which is what the peer being
    /// asked moves: `request_resync` applies and persists whatever a responder
    /// streams once mls-rs verifies it against our own, possibly stale, state.
    /// So the first responder could serve a Remove of the second named peer, and
    /// that peer would be dropped from the queue instead of dialled — a
    /// responder excising the very peer whose answer would have contradicted it,
    /// rendered as a departure. Asking one peer per invocation leaves nothing to
    /// excise. A second peer is a second command, which starts from our state as
    /// the first left it, and whose failure to agree is visible to the operator.
    ///
    /// An explicit ticket also bypasses
    /// [`GroupChatProcessor::known_member_addrs`], and that bypass is why one is
    /// typed: the address is dialled because the operator named it, not because
    /// a roster vouches for it.
    Operator,
    /// The group's remembered member addresses, i.e. whatever
    /// [`GroupChatProcessor::known_member_addrs`] returned. That read filters
    /// the stored book against this group's **live** roster every time, so
    /// re-reading it is the same decision that built the list, made again
    /// against the roster the sweep has since advanced. It is per-group by
    /// construction and holds no operator-typed address, so nothing here can
    /// revoke another group's delivery path.
    Remembered,
    /// A running listener's shared recipient list. Re-derived by running
    /// [`prune_departed_recipients`] — S8's decision, cross-group vouching and
    /// all — and then keeping the peers that survived in `recipients`. The
    /// prune is the only thing that decides who departed; this variant just
    /// stops the sweep from dialling whoever it dropped.
    ///
    /// Used for both REPL forms. `/resync` with no argument is the only one
    /// with more than one peer, and its list *is* the recipient list — the
    /// addresses `listen` started with (`resolve_recipients`, or the tickets
    /// alone when no gid was given) plus every `/peer` typed since, held in one
    /// `Vec` across whatever groups `listen_loop` addresses. So it is **not**
    /// this group's roster, and it can hold addresses `known_member_addrs`
    /// would have filtered out, including ones no roster lists. A
    /// `/resync <ticket>` sweep has a single peer, so it is asked before there
    /// is any tail to re-derive, and this variant's only effect there is that
    /// the prune runs at all.
    Listener {
        recipients: &'a tokio::sync::Mutex<Vec<PeerAddr>>,
        rosters: &'a tokio::sync::Mutex<RosterSnapshots>,
    },
}

impl PeerSource<'_> {
    /// Re-derive `queue` — the peers not yet asked — and return how many were
    /// dropped, plus the prune's operator note when there is one.
    ///
    /// Called only after a peer whose exchange moved our own state, and once
    /// after the loop if none did (so the listener's prune still runs on both
    /// outcomes, as it did when it was a single call after the sweep).
    ///
    /// [`PeerSource::Remembered`] and [`PeerSource::Listener`] re-run the filter
    /// that produced their own list, against the state the sweep has since
    /// moved; [`PeerSource::Operator`] re-derives nothing. There is no separate
    /// roster baseline to diff against — the one that existed served only the
    /// `Operator` arm, and from the CLI that queue can no longer hold a second
    /// peer (see that variant).
    ///
    /// **Locks.** Nothing is held across the two acquisitions here:
    /// [`prune_departed_recipients`] takes `rosters` then `recipients` and has
    /// released both by the time it returns, and the read below is a third,
    /// separate acquisition. That function's critical section must stay free of
    /// await points (its own doc says why); this call site adds none to it.
    async fn recheck(
        &self,
        processor: &GroupChatProcessor,
        gid: &GroupId,
        queue: &mut std::collections::VecDeque<PeerAddr>,
    ) -> (usize, Option<String>) {
        let (keep, note) = match self {
            // Nothing to re-derive. Filtering here would mean deciding what the
            // operator's own list may still contain on evidence the peer we just
            // asked supplied, which is the trade the one-ticket rule at the
            // dispatch exists to avoid — and on the CLI path that admits one
            // ticket the queue is empty by the time this runs anyway.
            PeerSource::Operator => return (0, None),
            PeerSource::Remembered => match processor.known_member_addrs(gid) {
                Ok(addrs) => (addrs, None),
                // Our own group state is unreadable. Leave the queue alone
                // rather than guess: `request_resync` loads the same group
                // before it connects, so every remaining peer fails there and
                // no dial happens on the strength of this.
                Err(_) => return (0, None),
            },
            PeerSource::Listener {
                recipients,
                rosters,
            } => {
                let note = prune_departed_recipients(processor, gid, recipients, rosters).await;
                (recipients.lock().await.clone(), note)
            }
        };
        let keep: std::collections::HashSet<[u8; 32]> =
            keep.iter().map(|a| *a.peer_id.as_bytes()).collect();
        let before = queue.len();
        queue.retain(|a| keep.contains(a.peer_id.as_bytes()));
        (before - queue.len(), note)
    }
}

/// Ask **every** peer for the Commits we missed, and apply them.
///
/// The sweep does not stop at the first peer that answers, and that is a
/// security property rather than thoroughness. A responder proves nothing about
/// itself, so stopping early let a single peer decide the outcome by saying as
/// little as `OK\x00\x00` — a member evicted while unreachable would be told
/// nothing was missing by the very peer that had it, or the sweep would end
/// after a partial catch-up. Whose answer arrives first is steerable too: on
/// `--mls-cmd resync` with no ticket the list comes from `known_member_addrs`,
/// whose order is `list_member_addrs`' redb key order (= node-id byte order),
/// so grinding a low node key buys first place. Asking everyone makes being
/// first worth nothing.
///
/// **On the two sources that hold a derived list, "everyone" means everyone
/// still on the list when their turn comes.** The loop applies Commits into our
/// own state as it goes, so after any peer that moved us it re-derives its own
/// tail through [`PeerSource`] — the same filter that produced the list, run
/// again — and the peers that drops are counted in [`ResyncReport::skipped`] and
/// reported. Asking everyone is about not letting one peer end the sweep, and a
/// peer removed from the group by a Commit we just verified did not end
/// anything. [`PeerSource::Operator`] re-derives nothing; the restriction that
/// makes that safe lives at the dispatch, and is described on that variant.
///
/// Returns `Err` only for a **local** failure — no peer to ask, or our own group
/// state unreadable. Every remote outcome, including "every peer failed", comes
/// back inside the [`ResyncReport`] so the caller can render the epoch we
/// actually reached alongside each peer's reason. The `Vec<String>` is the
/// listener prune's operator notes, empty for every other source.
///
/// The request carries our *own* current epoch
/// ([`GroupChatProcessor::request_resync`]), so an honest catch-up asks for
/// exactly the delta we are missing and is a no-op when we are current. Each
/// Commit is verified by mls-rs before it touches our state, and a peer that
/// serves a stream we cannot apply moves us nowhere.
async fn resync_sweep(
    processor: &GroupChatProcessor,
    group_id: &GroupId,
    peers: &[PeerAddr],
    source: PeerSource<'_>,
) -> (anyhow::Result<ResyncReport>, Vec<String>) {
    let mut notes: Vec<String> = Vec::new();
    if peers.is_empty() {
        return (
            Err(anyhow!(
                "resync {group_id}: no peer to ask — pass --mls-recipient-ticket <ticket>, \
                 or /peer <ticket> in the listener, or add the group's members to its \
                 address book first"
            )),
            notes,
        );
    }
    let from_epoch = match processor.load_group_summary(group_id).await {
        Ok(s) => s.epoch,
        Err(e) => return (Err(anyhow!("resync {group_id}: {e}")), notes),
    };
    // Read once for the report and for nothing else. It is not a filter and not
    // a baseline anything is dropped against: the queue is re-derived only
    // through `PeerSource::recheck`, which never sees this value, so
    // `PeerSource::Operator` still asks the list exactly as it was given. An
    // unreadable roster leaves `None` and the sweep reports no departure rather
    // than inferring one.
    let roster_before = processor.current_member_node_ids(group_id).ok();
    let mut queue: std::collections::VecDeque<PeerAddr> = peers.iter().cloned().collect();
    let mut answered: Vec<PeerAnswer> = Vec::new();
    let mut failures: Vec<String> = Vec::new();
    let mut asked = 0usize;
    let mut skipped = 0usize;
    // Our own epoch as of the previous iteration, so each peer's exchange gets
    // measured against the state that existed when it started.
    let mut epoch = from_epoch;
    let mut rechecked = false;
    let mut aborted: Option<String> = None;

    while let Some(peer) = queue.pop_front() {
        asked += 1;
        let outcome = processor.request_resync(group_id, &peer).await;
        let served_our_removal = matches!(&outcome, Ok(o) if o.removed_us);
        // Re-read our own epoch after every peer, whatever the exchange
        // returned. This is what the per-peer flag is measured on, instead of
        // the peer's own report of its own stream: `request_resync` counts a
        // Commit that removes *us* as applied, and mls-rs does not advance our
        // persisted epoch for that one, so the peer's flag could say "I sent
        // you Commits" while the epoch line said nothing moved. A broken stream
        // matters here too — an `Err` after a genuine Commit still moved us.
        let (now, read_err) = match processor.load_group_summary(group_id).await {
            Ok(s) => (s.epoch, None),
            Err(e) => (epoch, Some(e.to_string())),
        };
        let advanced_us = now > epoch;
        epoch = now;
        match &outcome {
            Ok(_) => answered.push(PeerAnswer {
                peer,
                advanced_us,
                served_our_removal,
            }),
            Err(e) => failures.push(describe_resync_failure(&peer, e)),
        }
        if let Some(e) = read_err {
            // We can no longer tell who this group's Commits have removed, so
            // stop dialling rather than carry on blind. Recorded rather than
            // left to the reload below, so a short sweep is always explained
            // instead of silently reporting fewer peers than it was given.
            aborted = Some(e);
            break;
        }
        if advanced_us || served_our_removal {
            rechecked = true;
            let (dropped, note) = source.recheck(processor, group_id, &mut queue).await;
            skipped += dropped;
            if let Some(note) = note {
                notes.push(note);
            }
        }
    }
    if !rechecked {
        // The listener's prune runs on both outcomes — a sweep that ended in
        // error can still have applied a Commit, and a baseline can be stale
        // from an epoch change that happened while another group was active.
        // Nothing is left to re-derive at this point, so it is handed an empty
        // queue and only the prune's effect remains.
        let mut nothing_left = std::collections::VecDeque::new();
        let (_, note) = source.recheck(processor, group_id, &mut nothing_left).await;
        if let Some(note) = note {
            notes.push(note);
        }
    }
    if let Some(e) = aborted {
        return (
            Err(anyhow!(
                "resync {group_id}: our own group state became unreadable after {asked} \
                 peer(s), so the rest were not asked: {e}"
            )),
            notes,
        );
    }

    // Re-read on every path. On the failure path the old code reported the
    // epoch captured before the loop, so a responder that streamed one genuine
    // Commit and then aborted — a dropped link mid-resync, i.e. the exact
    // population this command serves — had the operator told that nothing had
    // moved when it had.
    let to_epoch = match processor.load_group_summary(group_id).await {
        Ok(s) => s.epoch,
        Err(e) => {
            return (
                Err(anyhow!("resync {group_id}: reload after the sweep: {e}")),
                notes,
            )
        }
    };

    // Which node ids this group's roster held when the sweep started and does
    // not hold now. Read after the sweep, alongside `to_epoch`, and reported —
    // the queue is already settled by here, so nothing downstream can act on
    // it. Empty when either read failed: a roster we could not read is not
    // evidence that anybody left, and it renders as the silence it is.
    let mut departed: Vec<crate::p2p::PeerId> = match (
        roster_before,
        processor.current_member_node_ids(group_id).ok(),
    ) {
        (Some(before), Some(now)) => before
            .into_iter()
            .filter(|id| !now.contains(id))
            .map(crate::p2p::PeerId::new)
            .collect(),
        _ => Vec::new(),
    };
    // `HashSet` iteration order is not stable, and the line is read by people
    // and diffed by tests.
    departed.sort_unstable_by_key(|p| *p.as_bytes());

    (
        Ok(ResyncReport {
            from_epoch,
            to_epoch,
            asked,
            skipped,
            departed,
            answered,
            failures,
        }),
        notes,
    )
}

/// Ask an operator-supplied list of peers — see [`resync_sweep`], whose
/// [`PeerSource::Operator`] mode this is.
///
/// The list is asked exactly as given: nothing is re-derived between peers, so
/// no peer's answer takes another address off it. (A sweep still stops early if
/// our own group state becomes unreadable part-way through, which comes back as
/// a local error naming how many peers were asked.) There is no recipient list
/// on this path, so it never produces a prune note.
///
/// From the command line the list is one address at most — `run`'s
/// `MlsCommand::Resync` arm refuses a second `--mls-recipient-ticket`. This
/// signature stays a slice for the tests that need a two-peer sweep to pin that
/// the loop does not stop at the first answer.
///
/// **Test-only, and compiled nowhere else.** The one-ticket rule is enforced at
/// the dispatch, so a wrapper that takes N peers and re-derives nothing between
/// them is sound only next to that check. Exported it would have been a library
/// entry point without it — `cli` and `group` are both `pub` (`src/lib.rs`,
/// `src/group/mod.rs`) — so the invariant would have lived in one caller rather
/// than in the callable surface. `run` reaches [`resync_sweep`] directly and
/// does not go through here. `#[cfg(test)]` rather than a plain private `fn`
/// because every call site is in this file's test module: private alone leaves
/// it uncalled in a non-test build, which is `dead_code`, and that is what the
/// `pub` was standing in for.
#[cfg(test)]
async fn resync(
    processor: &GroupChatProcessor,
    group_id: &GroupId,
    peers: &[PeerAddr],
) -> anyhow::Result<ResyncReport> {
    resync_sweep(processor, group_id, peers, PeerSource::Operator)
        .await
        .0
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
    // Operator-selected: this loop addresses the gid its caller was given on the
    // command line. It is also the only key here, so nothing ever vouches.
    seed_roster(&processor, &rosters, &group_id, true).await;

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
        // `--mls-group-id`: named by the operator, so it may vouch.
        seed_roster(&processor, &rosters, &gid, true).await;
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
                        // Welcome-derived: the sender chose this group and was
                        // never authorized, so it is seeded (it may become the
                        // active send target) but may not vouch for a recipient
                        // another group's Commit removed.
                        seed_roster(&processor, &rosters, id, false).await;
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
                        // Welcome-derived, exactly as in the inbox task above:
                        // seeded, but not allowed to vouch.
                        seed_roster(&processor, &rosters, id, false).await;
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
    // Every `say` is exactly one REPL line — the function appends the `\n`
    // itself — and this REPL is where the operator reads `[joined]` /
    // `[epoch advanced]` / `[removed]` to judge who is in the group. Several
    // arms interpolate text a peer chose (a QUIC close reason surfaces inside
    // `Transport(Accept(..))` / `Connect(..)`), so the gate belongs *here*,
    // where the line is rendered, rather than in each arm: `/add failed` was
    // the one arm that had forgotten it, and a future arm would be one more
    // chance to forget. Arms that also bound the length keep doing so — this
    // pass is deliberately unbounded, because operator-authored lines here can
    // legitimately be long (a ticket is longer than any peer-text bound).
    let say = |s: String| {
        let stdout = Arc::clone(&stdout);
        async move {
            let line = crate::utils::sanitize_for_terminal(&s);
            let mut out = stdout.lock().await;
            let _ = out.write_all(line.as_bytes()).await;
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
                                    // now if it has none. Typing the gid is the
                                    // operator act that lets `g` vouch, whether
                                    // it arrived by Welcome or not.
                                    seed_roster(&processor, &rosters, &g, true).await;
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
                                // Bounded like every sibling error arm: the
                                // peer's close reason lands at the tail of this
                                // string, so the cut can only drop attacker-
                                // chosen text, never the `[listen] /add failed:`
                                // scaffolding the operator needs.
                                Err(e) => {
                                    let msg = crate::utils::sanitize_for_terminal_bounded(
                                        &e.to_string(),
                                        256,
                                    );
                                    say(format!("[listen] /add failed: {msg}")).await
                                }
                            }
                        } else if trimmed == "/resync"
                            || trimmed.strip_prefix("/resync ").is_some()
                        {
                            // /resync [ticket]
                            //
                            // Catch up on Commits we missed while unreachable.
                            // This is where an operator lands after noticing
                            // the group has gone quiet — a Commit missed with
                            // no relay configured to catch it is not resent by
                            // anyone, so the lagging side has to ask.
                            //
                            // With a ticket, that peer alone. With no argument,
                            // this session's whole recipient list — the
                            // addresses `resolve_recipients` produced at startup
                            // plus every `/peer` since, shared across the groups
                            // this loop addresses — so it is not the active
                            // group's roster and can hold addresses
                            // `known_member_addrs` would have filtered out. That
                            // list is re-derived as the sweep runs: a recipient
                            // a Commit applied here removes stops being dialled
                            // before its turn comes (see `PeerSource`).
                            let arg = trimmed
                                .strip_prefix("/resync")
                                .unwrap_or_default()
                                .trim()
                                .to_string();
                            let gid = match *group_id.lock().await {
                                Some(g) => g,
                                None => {
                                    say("[listen] /resync needs an active group — use /gid first".to_string())
                                        .await;
                                    continue;
                                }
                            };
                            let peers: Vec<PeerAddr> = if arg.is_empty() {
                                recipients.lock().await.clone()
                            } else {
                                match arg.parse::<Ticket>() {
                                    Ok(t) => vec![t.peer_addr()],
                                    Err(e) => {
                                        say(format!("[listen] /resync: bad ticket: {e}")).await;
                                        continue;
                                    }
                                }
                            };
                            // Awaited *inside* a `select!` carrying the same
                            // `kill_rx` branch as the outer loop. An `.await`
                            // in a select! arm body is not polled alongside its
                            // siblings, so awaiting the sweep inline wedged the
                            // whole REPL — no `/quit`, no sends, and, worse, the
                            // inbound task's "we were removed, stop" signal
                            // unserviced — for as long as the peers took. That
                            // was `n` x the per-read deadline, recoverable only
                            // by killing the process. The sweep is cancel-safe:
                            // `request_resync` has no await between a Commit's
                            // `process_incoming_message` and its
                            // `write_to_storage`, so dropping the future at a
                            // read boundary cannot leave a half-applied commit,
                            // and `prune_departed_recipients`' critical section
                            // has no await either.
                            let (swept, pruned) = tokio::select! {
                                _ = kill_rx.recv() => {
                                    say("[listen] stopping (we were removed)".to_string()).await;
                                    break;
                                }
                                v = resync_and_prune(
                                    &processor, &gid, &peers, &recipients, &rosters,
                                ) => v,
                            };
                            match swept {
                                // One line per fact; `render` decides what may
                                // be claimed. Each peer's reason is already
                                // sanitized and bounded by
                                // `describe_resync_failure`, and each line is
                                // said separately so a long tail of peers
                                // cannot push the summary off the top.
                                Ok(report) => {
                                    for line in report.render() {
                                        say(format!("[listen] /resync — {line}")).await;
                                    }
                                }
                                // Local failure only (no peer to ask, or our own
                                // group state unreadable) — remote outcomes come
                                // back inside the report above.
                                Err(e) => {
                                    say(format!("[listen] /resync failed: {e}")).await
                                }
                            }
                            // One per prune that had something to report. The
                            // sweep prunes between peers, so a long sweep can
                            // produce more than one.
                            for note in pruned {
                                say(note).await;
                            }
                        } else if trimmed.starts_with('/') {
                            say(format!(
                                "[listen] unknown command {trimmed:?}. Try /peer, /gid, /status, /add, /resync, /quit."
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

/// What a running loop last saw of one group: the node ids on its roster, and
/// whether the **operator** named that group.
///
/// A missing entry — or one whose `members` is still `None` — means "never
/// looked", which is what makes the first look able only to record and never to
/// drop: a departure is only visible as the difference between two
/// observations. The two fields are deliberately independent: a group can be
/// selected before it can be read (see [`seed_roster`]).
#[derive(Default, Debug)]
struct RosterSnapshot {
    /// The node ids this session last saw on the group's roster, or `None` when
    /// no baseline has been taken yet — the group was named before it was
    /// joined, or its roster failed to load.
    members: Option<std::collections::HashSet<[u8; 32]>>,
    /// The operator named this group by its id: `--mls-group-id`, the
    /// `chat-group` positional gid, or a `/gid` typed into the REPL. **False**
    /// for a group this session knows only because a Welcome created it —
    /// `join_group_from_welcome` is reachable unauthenticated over
    /// `nkct/mls/1` and authorizes no sender, so any peer holding this node's
    /// ticket can put a group of its own choosing into this map. The flag is
    /// what keeps such a group out of `prune_departed_recipients`' vouching
    /// population; it never gates anything else, and a Welcome group that the
    /// operator later types a `/gid` for is upgraded to `true` at that point.
    operator_selected: bool,
}

/// Per-group snapshots for one running loop.
type RosterSnapshots = std::collections::HashMap<GroupId, RosterSnapshot>;

/// Record `gid`'s roster as this session's baseline, unless one is held, and
/// note whether the operator named it (see [`RosterSnapshot::operator_selected`]).
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
/// **The selection and the baseline are recorded independently**, and that
/// separation is load-bearing rather than tidiness. `--mls-group-id G` is an
/// operator act performed at a moment when G may not be joined yet, so its
/// roster read fails; recording the selection only alongside a successful read
/// dropped it, and the `[joined]` seeding that arrived with G's Welcome — which
/// passes `false` — then fixed G as non-vouching for the whole session, exactly
/// where an operator who typed the gid would expect the opposite. So the flag is
/// taken on every call and the baseline is taken on the first call that can read
/// one. The two rules compose without opening a path from an inbound event to a
/// `true`: the flag only ever moves up (`|=`), and it moves at all only for a
/// caller that passes `true`, which is only the three sites where the gid came
/// from the operator (`--mls-group-id`, `chat-group`'s positional gid, `/gid`).
/// Both `[joined]` sites pass `false` and can therefore create an entry, or fill
/// in a missing baseline, but never grant vouching rights.
///
/// **New call sites**: a group this session learns of from the network — a
/// Welcome, or one discovered through a resync — is inbound-derived and must be
/// seeded `false`. Passing `true` there would hand the vouching population back
/// to whoever authored that message, which is the whole of what
/// [`RosterSnapshot::operator_selected`] exists to prevent. `true` is for a gid
/// the operator named, and nothing else.
///
/// A roster that fails to load leaves the selection but no baseline, and says
/// nothing: the same read has already been made and reported by
/// `resolve_recipients` before either loop starts, and the next `seed_roster`
/// or epoch change retries it.
///
/// One consequence is worth knowing before it puzzles someone. A mistyped `/gid`
/// — a syntactically valid 32-byte id for a group we are not in — leaves a
/// selected entry whose roster can never be read, since nothing will ever join
/// that group. It is harmless in direction: an unreadable group vouches for
/// nobody, so it can only cost an address, never keep one. It is visible,
/// though, as one failing `load_group` per prune and a "could not be read"
/// clause appended to every drop notice for as long as the session runs. That
/// is operator-caused and self-inflicted; `/gid` with the right id replaces
/// nothing, so the cure is to restart the session.
async fn seed_roster(
    processor: &GroupChatProcessor,
    rosters: &tokio::sync::Mutex<RosterSnapshots>,
    gid: &GroupId,
    operator_selected: bool,
) {
    let mut snaps = rosters.lock().await;
    seed_roster_locked(processor, gid, operator_selected, &mut snaps);
}

/// The synchronous half of [`seed_roster`], split out for the same reason as
/// [`decide_departures`] and subject to the same rule: **do not make this
/// `async`.**
///
/// This is the second door into the lost update that `decide_departures` closes.
/// It reads the live roster through the same synchronous `&self` call while
/// holding the same guard, and it writes the same baseline field, so an `.await`
/// added between the read and the write here reintroduces the identical bug by a
/// different route — with the identical CI blind spot, since no test fails and
/// `clippy::await_holding_lock` does not flag a `tokio` guard.
fn seed_roster_locked(
    processor: &GroupChatProcessor,
    gid: &GroupId,
    operator_selected: bool,
    snaps: &mut RosterSnapshots,
) {
    let held = snaps.entry(*gid).or_default();
    // Monotonic, and independent of whether the read below succeeds.
    held.operator_selected |= operator_selected;
    if held.members.is_some() {
        return;
    }
    if let Ok(members) = processor.current_member_node_ids(gid) {
        held.members = Some(members);
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
/// A departure from `gid` also speaks **only for `gid`**. The delta alone does
/// not give that: `listen_loop`'s single recipient list is shared across every
/// group the session can address, so a peer who is a member of both this group
/// and another one appears in the list once and was, until this scope check,
/// dropped from it wholesale the moment *anyone* in this group removed them —
/// silently revoking delivery for the other group, which never asked for it and
/// whose members had no say in it. So an address whose node is still on the
/// **live** roster of another group **the operator selected** is kept: that
/// group still vouches for it as a delivery path, and one group's Commit must
/// not revoke another's. Those groups are re-read rather than taken from their
/// snapshots, which only advance when *their* epoch changes and would otherwise
/// vouch for a peer already gone from them; a group whose state cannot be read
/// vouches for nobody, so an unreadable group can only lose an address
/// (today's behaviour), never keep a departed one.
///
/// **A keep is provisional, and that is what makes "some group still lists it"
/// true.** The vouch is read at one instant, and the vouching group can drop the
/// peer straight afterwards — silently, since a group that is not the active one
/// is never pruned. So a kept id is written back into `gid`'s baseline
/// alongside the live roster: it stays a *departure candidate*, and every later
/// epoch change of `gid` re-reads the vouch and drops it the first time no
/// selected group answers for it. Without that, one keep was permanent — the
/// baseline moved past the id, `departed` could never contain it again, and the
/// session would have gone on dialling a peer that had since left both groups
/// for as long as it ran.
///
/// The re-check is **not prompt, and "not prompt" includes "never"**: it happens
/// on `gid`'s next epoch change, whatever that change is, because the vouching
/// group's own Remove reaches this session as an event it deliberately does not
/// act on. A session whose active group goes quiet therefore keeps a kept
/// address for the rest of the session. That window is not steerable by the
/// peer it benefits: once she is out of `gid` she can neither cause an epoch
/// change there nor suppress one, so she cannot lengthen it — she can only be
/// lucky in how quiet the group is. Restarting re-resolves the list, which is
/// the operator's lever if the wait matters.
///
/// **Why only operator-selected groups may vouch.** Keeping an address is a
/// decision *against* an authenticated Remove Commit, so the population that
/// can make it has to be one an attacker cannot seat. Every group in the map is
/// not that population: `seed_roster` also runs on `[joined]`, and
/// `join_group_from_welcome` authorizes no sender and is reachable
/// unauthenticated over `nkct/mls/1` — so any peer that knows this node's
/// ticket could otherwise send a Welcome for a group of its own containing a
/// leaf claiming any node id, and that id would be exempt from every later
/// prune, re-opening exactly the leak this function exists to close. Requiring
/// [`RosterSnapshot::operator_selected`] answers "who can add to the vouching
/// population, and what did they pass to do it": a current member of a group
/// whose id the operator typed — someone the operator already addresses and
/// already delivers that group's traffic to — and not any peer holding our
/// ticket. It does not make the vouch *unforgeable*: such a member can still
/// seat a leaf claiming an arbitrary node id (see below) and thereby hold an
/// address in the list; that is a keep, by a party the operator chose, and it
/// is the narrower of the two directions.
///
/// **What Route 1 therefore covers.** Cross-group revocation is closed for a
/// peer that another *operator-selected* group still lists. An address vouched
/// for only by a group this session merely joined — a Welcome we accepted and
/// never typed a `/gid` for — is prunable again by a different group's Commit,
/// deliberately: it is the same address an unauthenticated peer could otherwise
/// pin. Typing `/gid <that group>` promotes it and restores the protection.
///
/// **What this cannot decide.** Both sides of the comparison are transport node
/// ids, and the roster's copy is *self-asserted*: `current_member_node_ids`
/// reads `peer_id` out of the member's own credential — it does not check the
/// binding at all, and checking it would not help, because `verify_binding`
/// covers that field with the member's own two signatures rather than proving
/// control of the node key it names, so a self-consistent credential claiming
/// any node id verifies. A member of `gid` can therefore seat a leaf claiming
/// an arbitrary node id and remove it to synthesise a departure. Keying this on
/// the transport fingerprint instead — as `projected_member_fingerprints` does
/// for the shell/forward allowlist, where the binding does prove possession of
/// the key being fingerprinted — is not expressible here: a [`PeerAddr`]
/// carries only a node id, and every ticket on the MLS path is minted by
/// [`print_local_address`] as `Ticket::new(addr, None, None)`, with no
/// `pqc_sign_fp` for a roster fingerprint to be compared against. That residual
/// is accepted and recorded in `KNOWN_ISSUES.md` (Security Audit Residuals,
/// item 12); what the group scope bounds is only its reach, not its existence —
/// a synthesised departure still drops any address no operator-selected group
/// carries, including the `/peer` and `--mls-recipient-ticket` addresses that
/// have no group to vouch for them at all.
///
/// **Locks.** One acquisition covers the whole read-modify-write: this group's
/// live roster, the baseline it is diffed against, the other groups' vouches,
/// and the baseline write — with no await inside, because two tasks can run this
/// concurrently for the same gid and a lost update makes a departed member
/// permanently undroppable. Every roster read sits inside that section
/// deliberately: they reach MLS state through a synchronous call, not through
/// this map. The guard is then dropped *before* the recipient lock is taken, so
/// the two are never held together, and rosters-then-recipients is the only
/// order in which they ever appear anywhere in this file.
///
/// **The note repeats on purpose.** A kept address is reported again on each
/// later epoch change of `gid` for as long as it is kept, and the line reads
/// "left group {gid}" each time — the same departure still under review, not a
/// new one. Saying it repeatedly was judged better than saying it once and
/// leaving an address in the list the operator has no further sign of; the
/// repetition is exactly the re-check happening.
///
/// The counts are ours, `GroupId`'s `Display` is `hex::encode` of its 32 raw
/// bytes, and the rest is a static literal, so nothing peer-influenced reaches
/// the terminal.
async fn prune_departed_recipients(
    processor: &GroupChatProcessor,
    gid: &GroupId,
    recipients: &tokio::sync::Mutex<Vec<PeerAddr>>,
    rosters: &tokio::sync::Mutex<RosterSnapshots>,
) -> Option<String> {
    // ONE critical section on the map, covering all four steps of the
    // read-modify-write: the live roster read, the baseline read it is diffed
    // against, the vouch re-reads, and the baseline write.
    //
    // It has to be atomic in all four. `listen_loop` hands `rosters` to both the
    // inbound task and the inbox-poll task with nothing serialising their event
    // handling, so two prunes for the same gid can overlap, and the write is
    // last-writer-wins. If either roster read sits outside, the two tasks
    // capture different instants and the loser's older view is written back:
    // a member added by the commit one task is handling vanishes from the
    // baseline, and since `departed` is a difference *against* the baseline he
    // can never be pruned again however many times he is later removed. That
    // hole predates this patch — the base read the live roster outside the lock
    // too — but it was a narrow one; putting N synchronous `load_group` calls
    // between the read and the write would have widened it by orders of
    // magnitude, which is what made closing it properly the only option.
    //
    // Nothing inside the section awaits, and that is now enforced rather than
    // asserted: all four steps live in [`decide_departures`], which is not
    // `async`, so an `.await` added to them is a compile error. See its doc for
    // why a comment was not enough. Do not inline it back here.
    let (departed, vouched, unreadable) = {
        let mut snaps = rosters.lock().await;
        match decide_departures(processor, gid, &mut snaps) {
            Ok(decided) => decided,
            Err(note) => return Some(note),
        }
    };
    if departed.is_empty() {
        return None;
    }
    // The map guard is dropped above, before this is taken: the two locks are
    // never held together and only ever appear in this order.
    let mut rs = recipients.lock().await;
    let before = rs.len();
    rs.retain(|a| {
        let id = a.peer_id.as_bytes();
        !departed.contains(id) || vouched.contains(id)
    });
    let dropped = before - rs.len();
    // Every vouched id that is in the list was in `departed` and survived the
    // retain, so this counts exactly the addresses this group's Commit would
    // have dropped and the scope check kept.
    let kept = rs
        .iter()
        .filter(|a| vouched.contains(a.peer_id.as_bytes()))
        .count();
    drop(rs);
    let note = match (dropped, kept) {
        // Somebody left, but we were not addressing them: say nothing rather
        // than report a drop that did not happen.
        (0, 0) => return None,
        // Say it even though nothing changed: a cross-group address that is not
        // pruned must not look pruned, and the operator is the one who can
        // decide whether that peer should still be addressed here.
        (0, k) => format!(
            "[mls] {k} recipient(s) left group {gid} but are still members of another \
             group selected in this session — keeping their address(es)"
        ),
        (n, 0) => format!("[mls] dropped {n} recipient(s) removed from group {gid}"),
        (n, k) => format!(
            "[mls] dropped {n} recipient(s) removed from group {gid}; kept {k} that \
             are still members of another group selected in this session"
        ),
    };
    if dropped > 0 && unreadable > 0 {
        // A group we could not read vouched for nobody, so a drop above may
        // have been decided on an incomplete answer. Never silent.
        return Some(format!(
            "{note} ({unreadable} other group(s) could not be read, so their members \
             could not be vouched for)"
        ));
    }
    Some(note)
}

/// The synchronous half of [`prune_departed_recipients`]: everything decided
/// while the roster map is held.
///
/// **This function is deliberately not `async`, and that is the whole point of
/// it existing separately.** The prune's correctness rests on the four steps
/// below — the live roster read, the baseline read they are diffed against, the
/// vouch re-reads, and the baseline write — happening with no suspension point
/// between them, because `listen_loop` hands `rosters` to both the inbound task
/// and the inbox-poll task with nothing serialising them. An `.await` anywhere
/// in here lets the two interleave, the later writer clobbers the earlier, and a
/// member dropped from the baseline can never be pruned again however many times
/// he is later removed.
///
/// That guarantee used to be a convention held by a comment, and it was
/// invisible to CI: every test stays green when it breaks, and
/// `clippy::await_holding_lock` does not fire — it targets `std::sync` guards
/// and deliberately does not flag a `tokio::sync::MutexGuard` held across an
/// await, which is normally legal. Inside a non-`async fn` an `.await` is a
/// compile error instead, so breaking the invariant now takes a visible edit
/// that does not build.
///
/// Both roster reads reach MLS state through a synchronous `&self` call rather
/// than through the map, so nothing here needs to await in the first place.
///
/// `Err` carries the operator-facing note the caller renders. It is not a
/// failure of the prune so much as a decision not to prune against a roster we
/// could not read.
fn decide_departures(
    processor: &GroupChatProcessor,
    gid: &GroupId,
    snaps: &mut RosterSnapshots,
) -> Result<
    (
        std::collections::HashSet<[u8; 32]>,
        std::collections::HashSet<[u8; 32]>,
        usize,
    ),
    String,
> {
    let current = match processor.current_member_node_ids(gid) {
        Ok(c) => c,
        // Keep both the list and the baseline: a roster that cannot be
        // loaded fails every send from the same group state anyway, so
        // guessing here could only remove a still-valid recipient on top of
        // that. The caller renders this and drops the guard.
        Err(e) => {
            return Err(format!(
                "[mls] could not re-check recipients against the roster: {}",
                crate::utils::sanitize_for_terminal_bounded(&e.to_string(), 256)
            ))
        }
    };
    let vouching: Vec<GroupId> = snaps
        .iter()
        .filter(|(g, snap)| *g != gid && snap.operator_selected)
        .map(|(g, _)| *g)
        .collect();
    // No baseline yet — never looked, or the seeding read failed while the
    // group was still unjoined. Record only; a departure is measurable
    // against the next epoch change, not this one.
    let departed: std::collections::HashSet<[u8; 32]> =
        match snaps.get(gid).and_then(|snap| snap.members.as_ref()) {
            Some(prev) => prev.difference(&current).copied().collect(),
            None => std::collections::HashSet::new(),
        };
    // Which of the departures another operator-selected group still vouches
    // for. Skipped entirely when nothing departed, which is the common case
    // (every Add), so the usual epoch change still costs one roster read.
    let mut vouched: std::collections::HashSet<[u8; 32]> =
        std::collections::HashSet::new();
    let mut unreadable = 0usize;
    if !departed.is_empty() {
        for g in &vouching {
            match processor.current_member_node_ids(g) {
                Ok(members) => vouched.extend(departed.intersection(&members).copied()),
                Err(_) => unreadable += 1,
            }
        }
    }
    // The new baseline is the live roster **plus every id kept on another
    // group's word**. A kept id has not finished departing: writing only the
    // live roster would erase it from this group's snapshot, and since
    // `departed` is a difference against that snapshot it could never be a
    // candidate for this group again — the vouch, though re-read here, would
    // never be re-read *for it*. The vouching group's own Remove produces no
    // event this session acts on (both dispatch sites prune only for the
    // active gid), so `gid`'s next epoch change is the only trigger there
    // is, and this is what keeps it eligible for it. An id that is later
    // re-added to `gid` comes back inside `current` and simply stops being a
    // departure, which is why this is recorded as roster state rather than
    // as a pending-departure list that would have to be cleaned up.
    let mut next = current;
    next.extend(vouched.iter().copied());
    snaps.entry(*gid).or_default().members = Some(next);
    Ok((departed, vouched, unreadable))
}

/// Run a [`resync_sweep`] for a running listener, re-checking the recipient list
/// against the roster **as** the sweep moves it.
///
/// **The prune is the point of this pairing.** `/resync` is a second way to
/// process a Remove Commit, and on its own it unbundled the two halves the
/// inbound path always does together: the roster advanced, the evicted member
/// dropped off `current_member_node_ids`, and the session went on dialling her
/// — shipping a ciphertext frame, and the connection-attempt/size/timing
/// metadata around it, on every line the operator typed next.
/// [`prune_departed_recipients`] closes that; the only other trigger is an
/// *inbound* epoch change for the active gid, which for the quiet group this
/// command exists to rescue includes "never".
///
/// **Why it is interleaved rather than appended.** A single prune after the
/// sweep leaves one contact still open, and it is the sharpest one: the sweep
/// itself dials the peer whose eviction it has just applied, because the loop
/// walks the list it was handed while the roster moves underneath it. So
/// [`PeerSource::Listener`] runs the prune between peers, and the sweep drops
/// whatever the prune dropped before it can dial it. The prune still runs when
/// the sweep moved nothing, so a stale baseline is still caught.
///
/// Both halves are carried out rather than `?`-ed away: a stream that broke
/// mid-way can still have carried Commits we verified and applied, so an error
/// from the sweep is not evidence that the roster stood still. The `Vec` is one
/// entry per prune that had something to report — normally none or one.
///
/// **Locks.** [`prune_departed_recipients`] takes `rosters` and then
/// `recipients`, which is the one order this file ever uses; the sweep itself
/// takes neither, and the caller clones the recipient list and releases it
/// before calling. Cancelling this future (the listener drops it when the
/// inbound task signals "we were removed") cannot tear the prune: cancellation
/// happens only at await points, and that function's critical section contains
/// none — an invariant to keep in mind before touching it, since
/// `clippy::await_holding_lock` does not flag `tokio::sync` guards and CI
/// cannot see it.
async fn resync_and_prune(
    processor: &GroupChatProcessor,
    gid: &GroupId,
    peers: &[PeerAddr],
    recipients: &tokio::sync::Mutex<Vec<PeerAddr>>,
    rosters: &tokio::sync::Mutex<RosterSnapshots>,
) -> (anyhow::Result<ResyncReport>, Vec<String>) {
    resync_sweep(
        processor,
        gid,
        peers,
        PeerSource::Listener {
            recipients,
            rosters,
        },
    )
    .await
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
                Some(FileStatus::Started { name, size, cancelled }) => Some(match cancelled {
                    None => format!(
                        "[file ⇩ {sender_index}@{group_id}] receiving {name:?} ({size} bytes)…"
                    ),
                    // This sender hit its own concurrency cap, so its oldest
                    // receipt was cancelled to make room. Say so: the operator
                    // was told that file was arriving. Both names come from the
                    // sender's START frames.
                    Some(old) => format!(
                        "[file ⇩ {sender_index}@{group_id}] receiving {name:?} ({size} bytes)… \
                         (cancelled earlier receipt of {} from this sender: too many at once)",
                        crate::utils::sanitize_for_terminal(&format!("{old:?}"))
                    ),
                }),
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
        MlsCommand::Resync {
            group_id,
            peer_tickets,
        } => {
            // At most one ticket on this subcommand, refused here — before a
            // group is loaded or a peer is dialled.
            //
            // `--mls-recipient-ticket` stays a `Vec` (it is shared with the send
            // paths, which use it as one); the restriction belongs to `resync`
            // because of what a resync does with an answer. `request_resync`
            // applies and persists every Commit a responder streams, verified
            // only against our own — possibly stale — state, and one Commit can
            // remove several leaves. Given a list, the first responder therefore
            // decides which of the operator's other named peers this process
            // still reaches: it can serve a Remove of them and the sweep either
            // dials a peer it just watched being evicted or drops it, depending
            // on how the tail is re-derived. Neither is the operator's decision,
            // and both are the responder's. One peer per invocation removes the
            // choice: there is no queue for an answer to act on, and a second
            // peer is a second command whose disagreement the operator sees.
            //
            // A resync only *reads* history from a peer, so unlike the send
            // paths it does not write the address book: a supplied ticket wins,
            // otherwise ask the members this group already remembers. That
            // second form is still a multi-peer sweep, re-derived between peers
            // through `known_member_addrs` — the same live-roster filter that
            // produced its list. There is no listener recipient list on either
            // path to prune; the process exits when the sweep ends.
            if peer_tickets.len() > 1 {
                anyhow::bail!(
                    "resync {group_id}: --mls-cmd resync takes at most one \
                     --mls-recipient-ticket ({} given). A responder's Commits are \
                     applied as they arrive, so the first peer asked would decide \
                     which of the others this sweep still reaches — run the command \
                     once per peer instead, and compare the answers. (Omitting the \
                     ticket is a different thing, not a narrower one: it asks the \
                     group's remembered member addresses, all of them.)",
                    peer_tickets.len()
                );
            }
            let (peers, source) = if peer_tickets.is_empty() {
                (
                    processor.known_member_addrs(&group_id).unwrap_or_default(),
                    PeerSource::Remembered,
                )
            } else {
                (tickets_to_peer_addrs(&peer_tickets), PeerSource::Operator)
            };
            // Neither source produces prune notes; only a listener has a
            // recipient list to prune.
            let (swept, _notes) = resync_sweep(&processor, &group_id, &peers, source).await;
            let report = swept?;
            for line in report.render() {
                eprintln!("resync {group_id}: {line}");
            }
            // Non-zero exit when nobody could be reached at all, so a script
            // can tell "asked and learned nothing" from "could not ask". The
            // per-peer reasons are already on stderr above.
            if report.answered.is_empty() {
                anyhow::bail!(
                    "resync {group_id}: none of the {} peer(s) asked answered",
                    report.asked
                );
            }
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

        // The drop is announced, names the group whose roster changed, and the
        // count is exactly the one node that left — a prune that also took Dave
        // would read "2".
        let seen = String::from_utf8_lossy(&out_buf.lock().await.clone()).into_owned();
        assert!(
            seen.contains(&format!("[mls] dropped 1 recipient(s) removed from group {gid}")),
            "the operator must be told exactly which count of recipients went away, \
             and from which group, got {seen:?}"
        );

        drop(stdin_tx);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), chat).await;
    }

    /// A Remove Commit in one group must not revoke a delivery address that
    /// belongs to another group the same session addresses.
    ///
    /// Regression: `departed` is derived from a *single* group's roster delta —
    /// an event authored by a remote member of that group — but it was applied
    /// with `retain` to `listen_loop`'s one recipient list, which is
    /// deliberately shared across every group the session can address. A member
    /// of group A could therefore drop the victim's delivery address for a peer
    /// whose relationship is group B, and nobody in B had any say in it: the
    /// victim kept typing, the REPL still echoed `[me] …` (a fan-out to a
    /// shortened list returns `Ok`), and the only notice was a `[mls] dropped …`
    /// line stating the wrong reason.
    ///
    /// The scope does **not** bound a squatted node id to the attacker's own
    /// group: a leaf claiming any node id still synthesises a departure that
    /// drops every address no operator-selected group carries — `/peer` and
    /// `--mls-recipient-ticket` destinations included, which is `KNOWN_ISSUES.md`
    /// residual 12. What it bounds is which group's Commit may speak for an
    /// address another selected group still lists.
    ///
    /// Driven at `prune_departed_recipients` because `listen_loop` is the only
    /// loop with a multi-group recipient list and it reads the process's real
    /// stdin, so it cannot be driven from a test. The three cases below differ
    /// *only* in what the session holds for group B.
    #[tokio::test]
    async fn one_groups_removal_cannot_prune_another_groups_recipient() {
        let net = MockNetwork::new();
        let (alice, _dir_a) = build_test_processor(&net, "alice", 1);
        let (bob, _dir_b) = build_test_processor(&net, "bob", 2);
        let (carol, _dir_c) = build_test_processor(&net, "carol", 3);
        let carol = Arc::new(carol);
        let alice_addr = alice.local_addr().await.expect("alice addr");
        let bob_addr = bob.local_addr().await.expect("bob addr");
        let carol_addr = carol.local_addr().await.expect("carol addr");

        // ---- group A: alice, bob, carol ------------------------------------
        // Only carol's view matters (she is the session that holds the shared
        // recipient list and processes the Commit), so bob's Welcome is never
        // delivered — alice's Add still seats him on the roster carol joins on.
        let gid_a = create_group(&alice, "group-a").await.expect("create A");
        let bob_kp_a = bob.export_key_package().await.expect("bob kp A");
        alice
            .add_member(&gid_a, &bob_kp_a)
            .await
            .expect("add bob to A");
        let carol_kp = carol.export_key_package().await.expect("carol kp");
        let add_carol = alice
            .add_member(&gid_a, &carol_kp)
            .await
            .expect("add carol to A");
        let carol_task = {
            let carol = Arc::clone(&carol);
            tokio::spawn(async move { carol.accept_next().await })
        };
        alice
            .send_welcome_to(&carol_addr, &add_carol.welcome)
            .await
            .expect("welcome→carol");
        carol_task
            .await
            .expect("carol task")
            .expect("carol accepts welcome");

        // ---- group B: carol and bob, a relationship group A knows nothing of
        let gid_b = create_group(&carol, "group-b").await.expect("create B");
        let bob_kp_b = bob.export_key_package().await.expect("bob kp B");
        carol
            .add_member(&gid_b, &bob_kp_b)
            .await
            .expect("add bob to B");

        // Carol's session baselines, taken while bob is still on both rosters.
        let a_before = carol
            .current_member_node_ids(&gid_a)
            .expect("carol roster A");
        let b_before = carol
            .current_member_node_ids(&gid_b)
            .expect("carol roster B");
        assert!(
            a_before.contains(bob_addr.peer_id.as_bytes())
                && b_before.contains(bob_addr.peer_id.as_bytes()),
            "the test needs bob on both rosters before the removal"
        );

        // ---- alice evicts bob from A; carol's session processes the Commit --
        // Bob is leaf 1 (added first); pinned by the P6 list_members test.
        let remove = alice
            .remove_member(&gid_a, 1)
            .await
            .expect("remove bob from A");
        let carol_task = {
            let carol = Arc::clone(&carol);
            tokio::spawn(async move { carol.accept_next().await })
        };
        alice
            .broadcast_commit(&remove, std::slice::from_ref(&carol_addr))
            .await
            .expect("remove commit→carol");
        carol_task
            .await
            .expect("carol task")
            .expect("carol applies the remove Commit");
        assert!(
            !carol
                .current_member_node_ids(&gid_a)
                .expect("carol roster A after")
                .contains(bob_addr.peer_id.as_bytes()),
            "bob must be off group A's roster for the prune to see a departure"
        );

        let snapshot = |members: &std::collections::HashSet<[u8; 32]>, selected: bool| {
            RosterSnapshot {
                members: Some(members.clone()),
                operator_selected: selected,
            }
        };

        // ---- case 1: the operator selected group B — bob's address survives -
        let rosters = tokio::sync::Mutex::new(RosterSnapshots::from([
            (gid_a, snapshot(&a_before, true)),
            (gid_b, snapshot(&b_before, true)),
        ]));
        let recipients =
            tokio::sync::Mutex::new(vec![bob_addr.clone(), alice_addr.clone()]);
        let note = prune_departed_recipients(&carol, &gid_a, &recipients, &rosters).await;
        let held = recipients.lock().await.clone();
        assert!(
            held.iter().any(|a| a.peer_id == bob_addr.peer_id),
            "group A's Remove must not revoke a peer group B still vouches for"
        );
        assert!(
            held.iter().any(|a| a.peer_id == alice_addr.peer_id),
            "the scope check must not disturb the untouched recipients"
        );
        // Not silent, and not dressed up as a drop: the operator has to be able
        // to tell a kept cross-group address from a pruned one.
        let note = note.expect("a cross-group retention must be reported");
        assert!(
            !note.contains("dropped") && note.contains("another group"),
            "a retention must not read as a drop, got {note:?}"
        );

        // ---- case 2: group B arrived by Welcome and was never selected ------
        // The keep decision is a decision against an authenticated Remove
        // Commit, so a group any peer holding our ticket could have created —
        // `join_group_from_welcome` authorizes no sender — must not be able to
        // make it. Otherwise one unauthenticated Welcome seating a leaf that
        // claims bob's node id would pin his address in the list for good.
        let rosters = tokio::sync::Mutex::new(RosterSnapshots::from([
            (gid_a, snapshot(&a_before, true)),
            (gid_b, snapshot(&b_before, false)),
        ]));
        let recipients =
            tokio::sync::Mutex::new(vec![bob_addr.clone(), alice_addr.clone()]);
        let note = prune_departed_recipients(&carol, &gid_a, &recipients, &rosters).await;
        let held = recipients.lock().await.clone();
        assert!(
            !held.iter().any(|a| a.peer_id == bob_addr.peer_id),
            "a group the operator never selected must not exempt a departed peer"
        );
        assert_eq!(
            note,
            Some(format!(
                "[mls] dropped 1 recipient(s) removed from group {gid_a}"
            )),
            "an unselected group must not even be reported as vouching"
        );

        // ---- case 3: control — the session holds nothing for B at all -------
        // Bob is then vouched for by nothing, so the prune still fires: the fix
        // is a scope, not a blanket exemption.
        let rosters = tokio::sync::Mutex::new(RosterSnapshots::from([(
            gid_a,
            snapshot(&a_before, true),
        )]));
        let recipients =
            tokio::sync::Mutex::new(vec![bob_addr.clone(), alice_addr.clone()]);
        let note = prune_departed_recipients(&carol, &gid_a, &recipients, &rosters).await;
        let held = recipients.lock().await.clone();
        assert!(
            !held.iter().any(|a| a.peer_id == bob_addr.peer_id),
            "a departure no other group vouches for must still be pruned"
        );
        assert!(
            held.iter().any(|a| a.peer_id == alice_addr.peer_id),
            "the surviving member must keep being addressed"
        );
        assert_eq!(
            note,
            Some(format!(
                "[mls] dropped 1 recipient(s) removed from group {gid_a}"
            )),
            "the drop must name its count and the group whose roster changed"
        );
    }

    /// A group that arrived by Welcome may not vouch, and typing `/gid` for it
    /// is what promotes it — while nothing an inbound event does can demote a
    /// group the operator selected.
    ///
    /// This pins `seed_roster`'s half of the rule the case-2 assertion above
    /// depends on: the flag is set from the call site, an existing baseline is
    /// never overwritten, and the promotion moves in one direction only.
    #[tokio::test]
    async fn only_an_operator_typed_gid_promotes_a_welcome_group_to_vouching() {
        let net = MockNetwork::new();
        let (alice, _dir_a) = build_test_processor(&net, "alice", 1);
        let alice_addr = alice.local_addr().await.expect("alice addr");
        let gid = create_group(&alice, "seeded").await.expect("create");
        let rosters = tokio::sync::Mutex::new(RosterSnapshots::new());

        // The `[joined]` path: seeded so a later Commit is a measurable delta,
        // but not trusted to override one.
        seed_roster(&alice, &rosters, &gid, false).await;
        {
            let snaps = rosters.lock().await;
            let held = snaps.get(&gid).expect("a baseline was taken");
            assert!(
                !held.operator_selected,
                "a Welcome-derived group must not start out vouching"
            );
            assert!(
                held
                    .members
                    .as_ref()
                    .expect("a baseline was taken")
                    .contains(alice_addr.peer_id.as_bytes()),
                "the baseline must be the group's actual roster"
            );
        }

        // `/gid <hex>`: the operator names it, so it may vouch from now on.
        seed_roster(&alice, &rosters, &gid, true).await;
        assert!(
            rosters.lock().await[&gid].operator_selected,
            "typing /gid must promote a group the session only joined"
        );

        // A second Welcome for the same group cannot take that back.
        seed_roster(&alice, &rosters, &gid, false).await;
        assert!(
            rosters.lock().await[&gid].operator_selected,
            "an inbound event must not demote a group the operator selected"
        );
    }

    /// A member added while the session is running enters the baseline, so his
    /// later removal is still a measurable departure and still prunes.
    ///
    /// This pins the invariant a lost update on the baseline violated: the
    /// baseline write must record the live roster on **every** epoch change,
    /// including the ones where nothing departed, because `departed` is a
    /// difference against it and a member missing from it can never be pruned
    /// however many times he is removed afterwards. It does **not** reproduce
    /// the interleaving that caused that — two prunes for one gid racing between
    /// a separated read and write — which cannot be made deterministic here
    /// without a scheduling hook in the function itself; what rules that out now
    /// is structural, the read, the vouch re-reads and the write sharing one
    /// `rosters` acquisition with no await inside it.
    #[tokio::test]
    async fn an_added_member_enters_the_baseline_so_a_later_removal_prunes() {
        let net = MockNetwork::new();
        let (alice, _dir_a) = build_test_processor(&net, "alice", 1);
        let (carol, _dir_c) = build_test_processor(&net, "carol", 3);
        let (dave, _dir_d) = build_test_processor(&net, "dave", 4);
        let carol = Arc::new(carol);
        let alice_addr = alice.local_addr().await.expect("alice addr");
        let carol_addr = carol.local_addr().await.expect("carol addr");
        let dave_addr = dave.local_addr().await.expect("dave addr");

        let gid = create_group(&alice, "growing").await.expect("create");
        let carol_kp = carol.export_key_package().await.expect("carol kp");
        let add_carol = alice
            .add_member(&gid, &carol_kp)
            .await
            .expect("add carol");
        let task = {
            let carol = Arc::clone(&carol);
            tokio::spawn(async move { carol.accept_next().await })
        };
        alice
            .send_welcome_to(&carol_addr, &add_carol.welcome)
            .await
            .expect("welcome→carol");
        task.await.expect("task").expect("carol accepts welcome");

        let rosters = tokio::sync::Mutex::new(RosterSnapshots::from([(
            gid,
            RosterSnapshot {
                members: Some(carol.current_member_node_ids(&gid).expect("roster")),
                operator_selected: true,
            },
        )]));
        let recipients =
            tokio::sync::Mutex::new(vec![dave_addr.clone(), alice_addr.clone()]);

        // An epoch change that *adds*: nothing departs, and the baseline must
        // still take the new roster.
        let add_dave = alice
            .add_member(&gid, &dave.export_key_package().await.expect("dave kp"))
            .await
            .expect("add dave");
        let task = {
            let carol = Arc::clone(&carol);
            tokio::spawn(async move { carol.accept_next().await })
        };
        alice
            .broadcast_commit(&add_dave.commit, std::slice::from_ref(&carol_addr))
            .await
            .expect("add commit→carol");
        task.await.expect("task").expect("carol applies the add");
        let note = prune_departed_recipients(&carol, &gid, &recipients, &rosters).await;
        assert_eq!(note, None, "an Add drops nobody and says nothing");
        assert!(
            rosters.lock().await[&gid]
                .members
                .as_ref()
                .expect("baseline")
                .contains(dave_addr.peer_id.as_bytes()),
            "a member added mid-session must enter the baseline"
        );

        // Now remove him: this is only a departure if the baseline recorded him.
        let remove = alice
            .remove_member(&gid, 2)
            .await
            .expect("remove dave");
        let task = {
            let carol = Arc::clone(&carol);
            tokio::spawn(async move { carol.accept_next().await })
        };
        alice
            .broadcast_commit(&remove, std::slice::from_ref(&carol_addr))
            .await
            .expect("remove commit→carol");
        task.await.expect("task").expect("carol applies the remove");
        let note = prune_departed_recipients(&carol, &gid, &recipients, &rosters).await;
        let held = recipients.lock().await.clone();
        assert!(
            !held.iter().any(|a| a.peer_id == dave_addr.peer_id),
            "a member who joined and then left mid-session must still be pruned"
        );
        assert_eq!(
            note,
            Some(format!("[mls] dropped 1 recipient(s) removed from group {gid}")),
            "the drop must be reported exactly once"
        );
    }

    /// A recipient kept because another group vouched for it is re-checked when
    /// that vouch lapses, and dropped then.
    ///
    /// Regression: a keep was permanent. The baseline was rewritten to the
    /// post-removal roster, so the kept id left group A's snapshot and could
    /// never appear in `departed` for A again; the vouch was re-read on every
    /// later epoch change but never again *for that id*. Group B's own Remove
    /// produces no event the session acts on — both dispatch sites prune only
    /// for the active gid — so nothing else would have caught it either. The
    /// session went on dialling a peer that had since left both groups, feeding
    /// it the cleartext `group_id` and epoch in every `PrivateMessage` header
    /// plus size and timing, for as long as it ran. No forgery and no continued
    /// membership: the ordering alone decided it, since removing the peer from
    /// B *first* made the live re-read fail to vouch and dropped her correctly.
    ///
    /// The sequence below is that one: A evicts her (kept), then B evicts her
    /// with no prune running for B, then A advances again for an unrelated
    /// reason — an Add, so the second advance is not a removal and the re-check
    /// cannot be conditional on A's roster shrinking.
    #[tokio::test]
    async fn a_kept_recipient_is_dropped_once_its_vouching_group_lets_it_go() {
        let net = MockNetwork::new();
        let (alice, _dir_a) = build_test_processor(&net, "alice", 1);
        let (bob, _dir_b) = build_test_processor(&net, "bob", 2);
        let (carol, _dir_c) = build_test_processor(&net, "carol", 3);
        let (dave, _dir_d) = build_test_processor(&net, "dave", 4);
        let carol = Arc::new(carol);
        let alice_addr = alice.local_addr().await.expect("alice addr");
        let bob_addr = bob.local_addr().await.expect("bob addr");
        let carol_addr = carol.local_addr().await.expect("carol addr");

        // ---- group A: alice, bob, carol; group B: carol, bob ---------------
        let gid_a = create_group(&alice, "group-a").await.expect("create A");
        let bob_kp_a = bob.export_key_package().await.expect("bob kp A");
        alice
            .add_member(&gid_a, &bob_kp_a)
            .await
            .expect("add bob to A");
        let carol_kp = carol.export_key_package().await.expect("carol kp");
        let add_carol = alice
            .add_member(&gid_a, &carol_kp)
            .await
            .expect("add carol to A");
        let carol_task = {
            let carol = Arc::clone(&carol);
            tokio::spawn(async move { carol.accept_next().await })
        };
        alice
            .send_welcome_to(&carol_addr, &add_carol.welcome)
            .await
            .expect("welcome→carol");
        carol_task
            .await
            .expect("carol task")
            .expect("carol accepts welcome");
        let gid_b = create_group(&carol, "group-b").await.expect("create B");
        let bob_kp_b = bob.export_key_package().await.expect("bob kp B");
        carol
            .add_member(&gid_b, &bob_kp_b)
            .await
            .expect("add bob to B");

        // The session addresses both groups and holds both baselines.
        let rosters = tokio::sync::Mutex::new(RosterSnapshots::from([
            (
                gid_a,
                RosterSnapshot {
                    members: Some(carol.current_member_node_ids(&gid_a).expect("roster A")),
                    operator_selected: true,
                },
            ),
            (
                gid_b,
                RosterSnapshot {
                    members: Some(carol.current_member_node_ids(&gid_b).expect("roster B")),
                    operator_selected: true,
                },
            ),
        ]));
        let recipients =
            tokio::sync::Mutex::new(vec![bob_addr.clone(), alice_addr.clone()]);

        // ---- 1. A evicts bob. B vouches, so his address is kept ------------
        let remove = alice
            .remove_member(&gid_a, 1)
            .await
            .expect("remove bob from A");
        let carol_task = {
            let carol = Arc::clone(&carol);
            tokio::spawn(async move { carol.accept_next().await })
        };
        alice
            .broadcast_commit(&remove, std::slice::from_ref(&carol_addr))
            .await
            .expect("remove commit→carol");
        carol_task
            .await
            .expect("carol task")
            .expect("carol applies the remove Commit");
        prune_departed_recipients(&carol, &gid_a, &recipients, &rosters).await;
        assert!(
            recipients
                .lock()
                .await
                .iter()
                .any(|a| a.peer_id == bob_addr.peer_id),
            "the vouch must keep bob's address at the first eviction"
        );
        // The mechanism that makes the keep provisional: he is still in group
        // A's baseline, so he is still a departure candidate there. It is roster
        // state, not a pending-departure list, which is why a re-add to A would
        // simply stop being a departure instead of sticking.
        assert!(
            rosters.lock().await[&gid_a]
                .members
                .as_ref()
                .expect("baseline")
                .contains(bob_addr.peer_id.as_bytes()),
            "a kept id must stay a candidate for the group it left"
        );

        // ---- 2. B evicts bob too. B is not the active group, so no prune ---
        // runs for it and the session is told nothing.
        carol
            .remove_member(&gid_b, 1)
            .await
            .expect("remove bob from B");
        assert!(
            recipients
                .lock()
                .await
                .iter()
                .any(|a| a.peer_id == bob_addr.peer_id),
            "the test needs bob still addressed at this point"
        );

        // ---- 3. A advances again, for an unrelated reason (an Add) ---------
        let dave_kp = dave.export_key_package().await.expect("dave kp");
        let add_dave = alice
            .add_member(&gid_a, &dave_kp)
            .await
            .expect("add dave to A");
        let carol_task = {
            let carol = Arc::clone(&carol);
            tokio::spawn(async move { carol.accept_next().await })
        };
        alice
            .broadcast_commit(&add_dave.commit, std::slice::from_ref(&carol_addr))
            .await
            .expect("add commit→carol");
        carol_task
            .await
            .expect("carol task")
            .expect("carol applies the add Commit");
        let note = prune_departed_recipients(&carol, &gid_a, &recipients, &rosters).await;

        let held = recipients.lock().await.clone();
        assert!(
            !held.iter().any(|a| a.peer_id == bob_addr.peer_id),
            "a kept address must be dropped once no selected group vouches for it"
        );
        assert!(
            held.iter().any(|a| a.peer_id == alice_addr.peer_id),
            "re-checking a kept id must not prune anything else"
        );
        assert_eq!(
            note,
            Some(format!(
                "[mls] dropped 1 recipient(s) removed from group {gid_a}"
            )),
            "the delayed drop must be counted exactly once"
        );

        // A drop is final: bob is out of A's baseline too, so a further epoch
        // change reports nothing rather than re-announcing him.
        assert!(
            !rosters.lock().await[&gid_a]
                .members
                .as_ref()
                .expect("baseline")
                .contains(bob_addr.peer_id.as_bytes()),
            "a dropped id must not stay a candidate"
        );
    }

    /// `--mls-group-id G` selects G even when G has not been joined yet, and the
    /// `[joined]` seeding that arrives with G's Welcome fills in the baseline
    /// without taking the selection away.
    ///
    /// Regression: the selection was recorded only alongside a successful roster
    /// read, so naming a group before joining it recorded *nothing* — not even
    /// the flag. The `[joined]` path then seeded G with `false`, and G was
    /// non-vouching for the rest of the session: an address only G carried was
    /// prunable by another group's Commit, with Route 1's protection silently
    /// absent in precisely the configuration an operator who passes
    /// `--mls-group-id` is asking for.
    ///
    /// The only thing that distinguishes "not joined yet" from "joined" at
    /// `seed_roster` is whether `current_member_node_ids` succeeds, so the two
    /// states are modelled here by seeding from a processor that is not a member
    /// and then from one that is.
    #[tokio::test]
    async fn a_selection_made_before_the_group_arrives_is_not_lost() {
        let net = MockNetwork::new();
        let (alice, _dir_a) = build_test_processor(&net, "alice", 1);
        let (stranger, _dir_s) = build_test_processor(&net, "stranger", 9);
        let alice_addr = alice.local_addr().await.expect("alice addr");
        let gid = create_group(&alice, "named-early").await.expect("create");
        let rosters = tokio::sync::Mutex::new(RosterSnapshots::new());

        // `--mls-group-id G`, typed while G is still unknown to us: the roster
        // read fails, and the operator's selection must survive it.
        seed_roster(&stranger, &rosters, &gid, true).await;
        {
            let snaps = rosters.lock().await;
            let held = snaps.get(&gid).expect("the selection must be recorded");
            assert!(
                held.operator_selected,
                "a selection made before the group arrived must be kept"
            );
            assert!(
                held.members.is_none(),
                "a failed read must leave no baseline to diff against"
            );
        }

        // G's Welcome lands: the `[joined]` path seeds with `false`. It may fill
        // the baseline it could not take before, and may not undo the selection.
        seed_roster(&alice, &rosters, &gid, false).await;
        let snaps = rosters.lock().await;
        let held = snaps.get(&gid).expect("entry");
        assert!(
            held.operator_selected,
            "the [joined] seeding must not demote a group the operator named"
        );
        assert!(
            held.members
                .as_ref()
                .expect("the baseline is taken once the group can be read")
                .contains(alice_addr.peer_id.as_bytes()),
            "the later seeding must supply the baseline the failed read could not"
        );
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

    /// The operator-reachable recovery path works: a member that missed a
    /// Commit catches up with `resync`, and a member that was actually removed
    /// is told so.
    ///
    /// A Commit broadcast to an unreachable peer is retried by nobody: with a
    /// store-and-forward relay configured it is deposited for later pickup, but
    /// without one — or past the relay's envelope TTL — the lagging member is
    /// simply left behind, and until this command existed `request_resync` had
    /// no caller outside the test suite, so there was no way to ask.
    ///
    /// Phase 1 pins that the wired handler reaches `request_resync` and
    /// *applies* the delta; phase 2 that an honest request is not clamped out
    /// of its own history by the SYNC join-epoch floor; phase 3 that a removed
    /// member gets an answer it can act on rather than a silent no-op.
    #[tokio::test]
    async fn resync_catches_up_a_member_that_missed_a_commit() {
        let net = MockNetwork::new();
        let (alice, _dir_a) = build_test_processor(&net, "alice", 1);
        let (bob, _dir_b) = build_test_processor(&net, "bob", 2);
        let (carol, _dir_c) = build_test_processor(&net, "carol", 3);

        let alice_addr = alice.local_addr().await.expect("alice addr");
        let bob_addr = bob.local_addr().await.expect("bob addr");

        let bob_kp = bob.export_key_package().await.expect("bob kp");
        let carol_kp = carol.export_key_package().await.expect("carol kp");

        // Alice creates the group and admits Bob (epoch 1); Bob takes the
        // Welcome, so his own admission epoch is recorded on Alice's side.
        let gid = alice.create_group().await.expect("create");
        let add_bob = alice.add_member(&gid, &bob_kp).await.expect("add bob");
        let bob = {
            let task = tokio::spawn(async move {
                bob.accept_next().await.expect("bob accepts welcome");
                bob
            });
            alice
                .send_welcome_to(&bob_addr, &add_bob.welcome)
                .await
                .expect("welcome to bob");
            task.await.expect("bob task")
        };
        assert_eq!(
            bob.load_group_summary(&gid).await.expect("bob summary").epoch,
            1
        );

        // Carol is admitted (epoch 2) while Bob is unreachable — exactly the
        // case the inbox refusal leaves behind, since the Commit is never
        // relayed. Bob is not told.
        let _add_carol = alice.add_member(&gid, &carol_kp).await.expect("add carol");
        assert_eq!(
            alice.load_group_summary(&gid).await.expect("alice").epoch,
            2
        );
        assert_eq!(
            bob.load_group_summary(&gid).await.expect("bob").epoch,
            1,
            "Bob must still be behind before he asks"
        );

        // Phase 1+2: Bob runs the recovery command against Alice.
        let alice = {
            let task = tokio::spawn(async move {
                alice.accept_next().await.expect("alice serves the SYNC");
                alice
            });
            let report = resync(&bob, &gid, std::slice::from_ref(&alice_addr))
                .await
                .expect("resync must succeed against a peer that has the history");
            let alice = task.await.expect("alice task");

            assert_eq!(report.from_epoch, 1);
            assert_eq!(
                report.to_epoch, 2,
                "the delta Bob was entitled to must actually be applied"
            );
            assert_eq!(report.asked, 1);
            assert_eq!(report.skipped, 0);
            assert_eq!(report.answered.len(), 1);
            assert_eq!(report.answered[0].peer.peer_id, alice_addr.peer_id);
            assert!(
                report.answered[0].advanced_us,
                "our own epoch moved across Alice's exchange"
            );
            assert!(
                !report.answered[0].served_our_removal,
                "and it was a catch-up, not an eviction"
            );
            assert!(report.failures.is_empty(), "got: {:?}", report.failures);
            assert_eq!(
                bob.load_group_summary(&gid).await.expect("bob after").epoch,
                2,
                "catch-up must be persisted, not just reported"
            );
            alice
        };

        // With no peer to ask, the operator is told what to supply rather than
        // getting a silent success.
        let err = resync(&bob, &gid, &[])
            .await
            .expect_err("no peer must be an error");
        assert!(
            err.to_string().contains("no peer to ask"),
            "got: {err:#}"
        );

        // Phase 3: Alice evicts Bob, and Bob asks again. The responder refuses
        // on roster grounds and the operator gets a line naming that peer and
        // its wire code — attributed, not restated as fact.
        let bob_leaf = alice
            .list_members(&gid)
            .await
            .expect("members")
            .iter()
            .map(|m| m.index)
            .find(|i| *i == 1)
            .expect("bob's leaf");
        let _ = alice
            .remove_member(&gid, bob_leaf)
            .await
            .expect("remove bob");

        let task = tokio::spawn(async move {
            // The responder surfaces the refusal as an error of its own.
            let _ = alice.accept_next().await;
            alice
        });
        let report = resync(&bob, &gid, std::slice::from_ref(&alice_addr))
            .await
            .expect("a remote refusal is a report, not a local error");
        let _alice = task.await.expect("alice task");
        assert!(
            report.answered.is_empty(),
            "an evicted member must not be served"
        );
        assert_eq!(report.failures.len(), 1);
        assert!(
            report.failures[0].contains("claims we are not on this group's roster"),
            "the refusal must be attributed to that peer, got: {:?}",
            report.failures
        );
        let rendered = report.render().join(" | ");
        assert!(
            !rendered.contains("up to date"),
            "no wording may assert currency, got: {rendered:?}"
        );
        assert!(
            !rendered.to_lowercase().contains("invitation"),
            "one unauthenticated peer's four bytes must not recommend taking a Welcome, \
             got: {rendered:?}"
        );
    }

    /// A resync failure is classified on the error *variant* — and the line
    /// that variant produces attributes the claim to the peer instead of
    /// asserting it, and recommends nothing.
    ///
    /// Two separate properties, both load-bearing, both previously broken in a
    /// different direction:
    ///
    /// 1. **Provenance.** The QUIC close reason a peer chooses arrives inside
    ///    `Transport(Connect(..))`. While this classified by substring, a
    ///    responder that put `peer rejected roster` in it produced the roster
    ///    rejection's line with its own text dropped.
    /// 2. **Not overclaiming.** The variant proves only that the responder sent
    ///    four bytes — nothing authenticates the responder, so "you were
    ///    removed; rejoining needs a fresh invitation" was a conclusion the code
    ///    cannot reach, printed as advice. And it pointed at `--mls-cmd
    ///    accept-one`, which is `accept_next` with no sender check
    ///    (`join_group_from_welcome`), so any peer would do as the inviter: one
    ///    hostile responder's four bytes could talk an operator into taking a
    ///    Welcome from whoever answered next.
    #[test]
    fn resync_failure_is_attributed_to_the_peer_and_classified_by_variant() {
        use crate::group::GroupError;
        let peer = PeerAddr::new(PeerId::new([7; 32]));

        // (1) A peer-chosen close reason that mimics the protocol rejection.
        let forged = GroupError::Transport(crate::p2p::P2pError::Connect(
            "peer rejected roster or group".to_string(),
        ));
        let line = describe_resync_failure(&peer, &forged);
        assert!(
            !line.contains("claims we are not on this group's roster"),
            "a transport error must not be able to impersonate a roster rejection, got: {line:?}"
        );
        assert!(
            line.contains("peer rejected roster or group"),
            "the peer's own text belongs in the passthrough branch, got: {line:?}"
        );

        // (2) The genuine wire-level rejections are still explained, but as one
        // peer's claim, marked unverified, and with no course of action
        // attached to it.
        let roster = describe_resync_failure(&peer, &GroupError::SyncRejectedByRoster);
        let pruned = describe_resync_failure(&peer, &GroupError::SyncEpochPruned);
        for line in [&roster, &pruned] {
            assert!(
                line.contains("claims"),
                "the responder is unauthenticated, so its answer must read as a claim, \
                 got: {line:?}"
            );
            assert!(
                line.contains("Unverified"),
                "and must be marked as one, got: {line:?}"
            );
            assert!(
                !line.to_lowercase().contains("invitation")
                    && !line.to_lowercase().contains("welcome")
                    && !line.to_lowercase().contains("accept-one"),
                "four unauthenticated bytes must not recommend accepting a Welcome — \
                 `accept_next` authorizes no sender — got: {line:?}"
            );
        }
        assert!(
            roster.contains("ERR\\x01") && pruned.contains("ERR\\x02"),
            "each line names the wire code it is reporting, got: {roster:?} / {pruned:?}"
        );
    }

    /// The `--mls-cmd resync` dispatch arm resolves its ticket and reaches the
    /// same handler — the argv-facing half of the wiring.
    #[tokio::test]
    async fn resync_command_dispatches_through_run() {
        let net = MockNetwork::new();
        let (alice, _dir_a) = build_test_processor(&net, "alice", 1);
        let (bob, _dir_b) = build_test_processor(&net, "bob", 2);

        let bob_addr = bob.local_addr().await.expect("bob addr");
        let alice_ticket: Ticket = print_local_address(&alice)
            .await
            .expect("alice ticket")
            .parse()
            .expect("parse ticket");

        let bob_kp = bob.export_key_package().await.expect("bob kp");
        let gid = alice.create_group().await.expect("create");
        let add_bob = alice.add_member(&gid, &bob_kp).await.expect("add bob");
        let bob = {
            let task = tokio::spawn(async move {
                bob.accept_next().await.expect("bob accepts welcome");
                bob
            });
            alice
                .send_welcome_to(&bob_addr, &add_bob.welcome)
                .await
                .expect("welcome to bob");
            task.await.expect("bob task")
        };

        let task = tokio::spawn(async move {
            alice.accept_next().await.expect("alice serves the SYNC");
            alice
        });
        run(
            MlsCommand::Resync {
                group_id: gid,
                peer_tickets: vec![alice_ticket],
            },
            bob,
        )
        .await
        .expect("--mls-cmd resync must reach the peer");
        let _alice = task.await.expect("alice task");
    }

    /// Register an endpoint that speaks the SYNC wire format and nothing else:
    /// it reads the fixed 44-byte request and writes exactly `reply`, then
    /// closes. No group state, no roster, no membership — which is precisely
    /// the position every peer a resync dials is in as far as the caller can
    /// tell, since the exchange authenticates none of that.
    fn spawn_raw_sync_responder(
        net: &Arc<MockNetwork>,
        peer_byte: u8,
        reply: Vec<u8>,
    ) -> (PeerAddr, tokio::task::JoinHandle<()>) {
        use crate::p2p::P2pEndpoint;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let id = PeerId::new([peer_byte; 32]);
        let ep = net.register(id, vec![P2pProtocol(crate::network::ALPN_MLS)]);
        let handle = tokio::spawn(async move {
            let pending = match ep.accept().await {
                Ok(p) => p,
                Err(_) => return,
            };
            let inc = match pending.establish(std::time::Duration::from_secs(5)).await {
                Ok(i) => i,
                Err(_) => return,
            };
            let mut s = inc.stream;
            // b"SYNC" + group_id(32) + claimed_epoch(8)
            let mut req = [0u8; 44];
            if s.read_exact(&mut req).await.is_err() {
                return;
            }
            let _ = s.write_all(&reply).await;
            let _ = s.shutdown().await;
        });
        (PeerAddr::new(id), handle)
    }

    /// [`spawn_raw_sync_responder`] with a signal fired the moment the 44-byte
    /// SYNC request has been read.
    ///
    /// So a test can assert on **whether this address was dialled at all**,
    /// which is behaviour, rather than on the text of an error. The signal is
    /// sound to read the instant the call under test returns: the sweep awaits
    /// each `request_resync` to completion, so a dial that happened has already
    /// delivered the request by then.
    fn spawn_probed_sync_responder(
        net: &Arc<MockNetwork>,
        peer_byte: u8,
        reply: Vec<u8>,
    ) -> (
        PeerAddr,
        tokio::task::JoinHandle<()>,
        tokio::sync::mpsc::Receiver<()>,
    ) {
        use crate::p2p::P2pEndpoint;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let id = PeerId::new([peer_byte; 32]);
        let ep = net.register(id, vec![P2pProtocol(crate::network::ALPN_MLS)]);
        let (dialled_tx, dialled_rx) = tokio::sync::mpsc::channel::<()>(4);
        let handle = tokio::spawn(async move {
            let pending = match ep.accept().await {
                Ok(p) => p,
                Err(_) => return,
            };
            let inc = match pending.establish(std::time::Duration::from_secs(5)).await {
                Ok(i) => i,
                Err(_) => return,
            };
            let mut s = inc.stream;
            let mut req = [0u8; 44];
            if s.read_exact(&mut req).await.is_err() {
                return;
            }
            let _ = dialled_tx.send(()).await;
            let _ = s.write_all(&reply).await;
            let _ = s.shutdown().await;
        });
        (PeerAddr::new(id), handle, dialled_rx)
    }

    /// Four attacker-chosen bytes must not end the sweep, and must not become a
    /// claim that we are current.
    ///
    /// `OK\x00\x00` followed by a close is the entire cost of this: the stream
    /// EOFs at the first length prefix, `request_resync` breaks out of its loop
    /// and returns `Ok(false)`, and the caller used to take the first `Ok` and
    /// return, printing "Already up to date at epoch N". The scenario is not
    /// exotic — a member evicted while unreachable is exactly who runs this
    /// command, `known_member_addrs` filters remembered addresses against the
    /// caller's own *stale* roster so the evicted peer survives the filter, and
    /// redb key order is node-id byte order, so being asked first is grindable.
    ///
    /// Phase 1: that peer alone. Phase 2: that peer *ahead of* the honest one.
    #[tokio::test]
    async fn a_peer_that_only_says_ok_neither_ends_the_sweep_nor_claims_currency() {
        let net = MockNetwork::new();
        let (alice, _dir_a) = build_test_processor(&net, "alice", 1);
        let (bob, _dir_b) = build_test_processor(&net, "bob", 2);
        let (carol, _dir_c) = build_test_processor(&net, "carol", 3);

        let alice_addr = alice.local_addr().await.expect("alice addr");
        let bob_addr = bob.local_addr().await.expect("bob addr");
        let bob_kp = bob.export_key_package().await.expect("bob kp");
        let carol_kp = carol.export_key_package().await.expect("carol kp");

        let gid = alice.create_group().await.expect("create");
        let add_bob = alice.add_member(&gid, &bob_kp).await.expect("add bob");
        let bob = {
            let task = tokio::spawn(async move {
                bob.accept_next().await.expect("bob accepts welcome");
                bob
            });
            alice
                .send_welcome_to(&bob_addr, &add_bob.welcome)
                .await
                .expect("welcome to bob");
            task.await.expect("bob task")
        };
        // Bob misses this one.
        let _ = alice.add_member(&gid, &carol_kp).await.expect("add carol");
        assert_eq!(bob.load_group_summary(&gid).await.expect("bob").epoch, 1);

        // Phase 1: the mute peer is the only one that answers.
        let (mute_addr, mute) = spawn_raw_sync_responder(&net, 9, b"OK\x00\x00".to_vec());
        let report = resync(&bob, &gid, std::slice::from_ref(&mute_addr))
            .await
            .expect("a peer that answers is not a local failure");
        mute.await.expect("mute responder");
        assert_eq!(report.answered.len(), 1);
        assert!(
            !report.answered[0].advanced_us,
            "it moved our state nowhere, and the report must say so"
        );
        assert_eq!(report.from_epoch, 1);
        assert_eq!(report.to_epoch, 1);
        let rendered = report.render().join(" | ");
        assert!(
            !rendered.to_lowercase().contains("up to date"),
            "an unauthenticated peer's silence is not a proof of currency, got: {rendered:?}"
        );
        assert!(
            rendered.contains("our epoch did not move"),
            "the honest statement is about our own epoch, got: {rendered:?}"
        );
        assert!(
            rendered.contains("authenticated by nothing"),
            "and it must carry what bounds it, got: {rendered:?}"
        );

        // Phase 2: the mute peer answers *first*, the honest one second. The
        // sweep must reach Alice anyway — this is the assertion that fails
        // against a first-answer-wins loop, and it fails there by leaving Bob
        // at epoch 1.
        let (mute2_addr, mute2) = spawn_raw_sync_responder(&net, 10, b"OK\x00\x00".to_vec());
        let alice_task = tokio::spawn(async move {
            alice.accept_next().await.expect("alice serves the SYNC");
            alice
        });
        let report = resync(&bob, &gid, &[mute2_addr.clone(), alice_addr.clone()])
            .await
            .expect("sweep");
        // Asserted *before* joining the helper tasks on purpose: a
        // first-answer-wins loop never asks Alice at all, so joining her first
        // would hang here instead of failing the claim under test.
        assert_eq!(
            bob.load_group_summary(&gid).await.expect("bob after").epoch,
            2,
            "the sweep must not stop at the peer that said nothing"
        );
        mute2.await.expect("mute responder 2");
        let _alice = alice_task.await.expect("alice task");

        assert_eq!(report.asked, 2);
        assert_eq!(report.to_epoch, 2);
        let contributors: Vec<_> = report
            .answered
            .iter()
            .filter(|a| a.advanced_us)
            .map(|a| a.peer.peer_id)
            .collect();
        assert_eq!(
            contributors,
            vec![alice_addr.peer_id],
            "only the peer across whose exchange our own epoch moved is named"
        );
    }

    /// The failure report names the epoch we actually reached, not the one we
    /// started at.
    ///
    /// A responder that streams a **genuine** Commit and then breaks the stream
    /// leaves us further along than we were and the call in error. The old
    /// message captured `from_epoch` once, before the loop, and never re-read
    /// it, so it told the operator recovery had made no progress when it partly
    /// had — on a dropped link mid-resync, which is the exact population this
    /// command serves.
    ///
    /// The Commit replayed here is real: Carol is a member entitled to it, and
    /// the test fetches it from Alice over the wire rather than synthesising
    /// one, so what Bob applies is a Commit mls-rs verifies.
    #[tokio::test]
    async fn a_stream_that_breaks_after_applying_reports_the_epoch_it_reached() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let net = MockNetwork::new();
        let (alice, _dir_a) = build_test_processor(&net, "alice", 1);
        let (bob, _dir_b) = build_test_processor(&net, "bob", 2);
        let (carol, _dir_c) = build_test_processor(&net, "carol", 3);
        let (dave, _dir_d) = build_test_processor(&net, "dave", 4);

        let alice_addr = alice.local_addr().await.expect("alice addr");
        let bob_addr = bob.local_addr().await.expect("bob addr");
        let carol_addr = carol.local_addr().await.expect("carol addr");
        let bob_kp = bob.export_key_package().await.expect("bob kp");
        let carol_kp = carol.export_key_package().await.expect("carol kp");
        let dave_kp = dave.export_key_package().await.expect("dave kp");

        let gid = alice.create_group().await.expect("create");
        let add_bob = alice.add_member(&gid, &bob_kp).await.expect("add bob");
        let bob = {
            let task = tokio::spawn(async move {
                bob.accept_next().await.expect("bob accepts welcome");
                bob
            });
            alice
                .send_welcome_to(&bob_addr, &add_bob.welcome)
                .await
                .expect("welcome to bob");
            task.await.expect("bob task")
        };
        let add_carol = alice.add_member(&gid, &carol_kp).await.expect("add carol");
        let carol = {
            let task = tokio::spawn(async move {
                carol.accept_next().await.expect("carol accepts welcome");
                carol
            });
            alice
                .send_welcome_to(&carol_addr, &add_carol.welcome)
                .await
                .expect("welcome to carol");
            task.await.expect("carol task")
        };

        // Bob catches up honestly to epoch 2, so the epoch-3 Commit below is
        // the next one he can apply.
        let alice = {
            let task = tokio::spawn(async move {
                alice.accept_next().await.expect("alice serves the SYNC");
                alice
            });
            resync(&bob, &gid, std::slice::from_ref(&alice_addr))
                .await
                .expect("bob catches up");
            task.await.expect("alice task")
        };
        assert_eq!(bob.load_group_summary(&gid).await.expect("bob").epoch, 2);

        // Epoch 3, which Bob misses.
        let _ = alice.add_member(&gid, &dave_kp).await.expect("add dave");
        assert_eq!(alice.load_group_summary(&gid).await.expect("alice").epoch, 3);

        // Carol joined at epoch 2, so the SYNC join-epoch clamp entitles her to
        // the epoch-3 Commit. Take it off the wire verbatim.
        let commit_e3: Vec<u8> = {
            let task = tokio::spawn(async move {
                let _ = alice.accept_next().await;
                alice
            });
            let mut s = carol
                .endpoint_ref()
                .connect(&alice_addr, crate::group::transport::ALPN_MLS_PROTOCOL)
                .await
                .expect("carol dials alice");
            s.write_all(b"SYNC").await.expect("SYNC header");
            let mut req = [0u8; 40];
            req[0..32].copy_from_slice(gid.as_bytes());
            req[32..40].copy_from_slice(&2u64.to_le_bytes());
            s.write_all(&req).await.expect("SYNC request");
            let mut resp = [0u8; 4];
            s.read_exact(&mut resp).await.expect("SYNC response");
            assert_eq!(&resp, b"OK\x00\x00");
            let mut len = [0u8; 4];
            s.read_exact(&mut len).await.expect("commit length");
            let mut body = vec![0u8; u32::from_le_bytes(len) as usize];
            s.read_exact(&mut body).await.expect("commit bytes");
            let _alice = task.await.expect("alice task");
            body
        };

        // Replay it and then break the stream: `OK`, the genuine frame, then a
        // zero length, which `request_resync` rejects *after* it has applied.
        let mut reply = b"OK\x00\x00".to_vec();
        reply.extend_from_slice(&(commit_e3.len() as u32).to_le_bytes());
        reply.extend_from_slice(&commit_e3);
        reply.extend_from_slice(&0u32.to_le_bytes());
        let (broken_addr, broken) = spawn_raw_sync_responder(&net, 9, reply);

        let report = resync(&bob, &gid, std::slice::from_ref(&broken_addr))
            .await
            .expect("a broken remote stream is not a local failure");
        broken.await.expect("broken responder");

        assert_eq!(
            bob.load_group_summary(&gid).await.expect("bob after").epoch,
            3,
            "the genuine Commit really was applied before the break"
        );
        assert!(report.answered.is_empty(), "the exchange did end in error");
        assert_eq!(report.failures.len(), 1);
        assert_eq!(report.from_epoch, 2);
        assert_eq!(
            report.to_epoch, 3,
            "the epoch must be re-read after the sweep, not carried from before it"
        );
        let first = report.render().into_iter().next().expect("a summary line");
        assert!(
            first.contains("epoch 2 → 3"),
            "the operator must be told what progress was made, got: {first:?}"
        );
        assert!(
            !first.contains("still at epoch 2"),
            "and not told the node is where it no longer is, got: {first:?}"
        );
    }

    /// A Remove applied by `/resync` drops the removed member from the
    /// listener's recipient list, in the same breath.
    ///
    /// On the inbound path the Remove and the prune are bundled. `/resync` is a
    /// second way to process a Remove, and on its own it unbundled them: Carol
    /// left the roster, `current_member_node_ids` stopped listing her, and the
    /// session kept dialling her address on every line typed next — the
    /// connection-attempt and size/timing channel `prune_departed_recipients`
    /// exists to close. The only other trigger is an *inbound* epoch change for
    /// the active gid, which for the quiet group this command rescues can be
    /// never.
    ///
    /// This drives the pairing the REPL arm calls, with the listener's own
    /// state shapes: one shared recipient list and the per-group
    /// `RosterSnapshots` baseline seeded as an operator-named group.
    #[tokio::test]
    async fn resync_prunes_the_recipient_its_own_commit_removed() {
        let net = MockNetwork::new();
        let (alice, _dir_a) = build_test_processor(&net, "alice", 1);
        let (bob, _dir_b) = build_test_processor(&net, "bob", 2);
        let (carol, _dir_c) = build_test_processor(&net, "carol", 3);

        let alice_addr = alice.local_addr().await.expect("alice addr");
        let bob_addr = bob.local_addr().await.expect("bob addr");
        let carol_addr = carol.local_addr().await.expect("carol addr");
        let bob_kp = bob.export_key_package().await.expect("bob kp");
        let carol_kp = carol.export_key_package().await.expect("carol kp");

        let gid = alice.create_group().await.expect("create");
        let add_bob = alice.add_member(&gid, &bob_kp).await.expect("add bob");
        let bob = {
            let task = tokio::spawn(async move {
                bob.accept_next().await.expect("bob accepts welcome");
                bob
            });
            alice
                .send_welcome_to(&bob_addr, &add_bob.welcome)
                .await
                .expect("welcome to bob");
            task.await.expect("bob task")
        };
        let _ = alice.add_member(&gid, &carol_kp).await.expect("add carol");

        // Bob catches up to epoch 2, so his roster lists Carol and the listener
        // state below is the one a real session would hold.
        let alice = {
            let task = tokio::spawn(async move {
                alice.accept_next().await.expect("alice serves the SYNC");
                alice
            });
            resync(&bob, &gid, std::slice::from_ref(&alice_addr))
                .await
                .expect("bob catches up");
            task.await.expect("alice task")
        };
        assert_eq!(bob.load_group_summary(&gid).await.expect("bob").epoch, 2);

        let recipients = tokio::sync::Mutex::new(vec![alice_addr.clone(), carol_addr.clone()]);
        let rosters = tokio::sync::Mutex::new(RosterSnapshots::new());
        seed_roster(&bob, &rosters, &gid, true).await;

        // Alice evicts Carol while Bob is unreachable (epoch 3).
        let carol_leaf = alice
            .list_members(&gid)
            .await
            .expect("members")
            .iter()
            .map(|m| m.index)
            .find(|i| *i == 2)
            .expect("carol's leaf");
        let _ = alice
            .remove_member(&gid, carol_leaf)
            .await
            .expect("remove carol");

        // Bob asks, applies the Remove, and must stop addressing her.
        let task = tokio::spawn(async move {
            alice.accept_next().await.expect("alice serves the SYNC");
            alice
        });
        let (swept, notes) =
            resync_and_prune(&bob, &gid, std::slice::from_ref(&alice_addr), &recipients, &rosters)
                .await;
        let _alice = task.await.expect("alice task");
        let report = swept.expect("sweep");
        assert_eq!(report.to_epoch, 3, "the Remove really was applied");
        assert!(
            !bob.current_member_node_ids(&gid)
                .expect("bob roster")
                .contains(carol_addr.peer_id.as_bytes()),
            "Carol is off the roster"
        );

        let left: Vec<_> = recipients
            .lock()
            .await
            .iter()
            .map(|a| a.peer_id)
            .collect();
        assert!(
            !left.contains(&carol_addr.peer_id),
            "the member the applied Remove evicted must stop being dialled, got: {left:?}"
        );
        assert!(
            left.contains(&alice_addr.peer_id),
            "and nobody else may be dropped, got: {left:?}"
        );
        assert_eq!(notes.len(), 1, "one prune, one note, got: {notes:?}");
        assert!(
            notes[0].contains("dropped 1 recipient(s) removed from group"),
            "the drop must be reported, never silent, got: {notes:?}"
        );
    }

    /// The sweep stops dialling a peer once a Commit it applied **during that
    /// sweep** removed her.
    ///
    /// The list a sweep is handed is bound once, but `request_resync` applies
    /// Commits into our own MLS state inside the loop, so the roster moves
    /// underneath it. Ask Alice first and she streams the Remove of Carol; the
    /// next iteration then dials Carol — telling a member we have just watched
    /// being evicted that we are online, at what network path, for which group,
    /// and at what post-eviction epoch (the SYNC request carries it in clear,
    /// `processor.rs`'s `b"SYNC" + gid + epoch`), and putting whatever she
    /// answers into the operator's REPL. Pruning after the loop cannot close
    /// that: by then the dial has happened.
    ///
    /// The drop is [`prune_departed_recipients`]' decision and nothing else —
    /// the sweep only declines to dial what the prune removed — so a peer no
    /// longer on *this* roster but vouched for by another operator-selected
    /// group is still asked, exactly as it is still addressed.
    #[tokio::test]
    async fn resync_stops_dialling_a_peer_its_own_commit_just_removed() {
        let net = MockNetwork::new();
        let (alice, _dir_a) = build_test_processor(&net, "alice", 1);
        let (bob, _dir_b) = build_test_processor(&net, "bob", 2);
        let (carol, _dir_c) = build_test_processor(&net, "carol", 3);

        let alice_addr = alice.local_addr().await.expect("alice addr");
        let bob_addr = bob.local_addr().await.expect("bob addr");
        let carol_addr = carol.local_addr().await.expect("carol addr");
        let bob_kp = bob.export_key_package().await.expect("bob kp");
        let carol_kp = carol.export_key_package().await.expect("carol kp");

        let gid = alice.create_group().await.expect("create");
        let add_bob = alice.add_member(&gid, &bob_kp).await.expect("add bob");
        let bob = {
            let task = tokio::spawn(async move {
                bob.accept_next().await.expect("bob accepts welcome");
                bob
            });
            alice
                .send_welcome_to(&bob_addr, &add_bob.welcome)
                .await
                .expect("welcome to bob");
            task.await.expect("bob task")
        };
        let _ = alice.add_member(&gid, &carol_kp).await.expect("add carol");

        // Bob catches up to epoch 2, so his roster lists Carol and his
        // recipient list is the one a real session would hold.
        let alice = {
            let task = tokio::spawn(async move {
                alice.accept_next().await.expect("alice serves the SYNC");
                alice
            });
            resync(&bob, &gid, std::slice::from_ref(&alice_addr))
                .await
                .expect("bob catches up");
            task.await.expect("alice task")
        };
        assert_eq!(bob.load_group_summary(&gid).await.expect("bob").epoch, 2);

        let recipients = tokio::sync::Mutex::new(vec![alice_addr.clone(), carol_addr.clone()]);
        let rosters = tokio::sync::Mutex::new(RosterSnapshots::new());
        seed_roster(&bob, &rosters, &gid, true).await;

        // Alice evicts Carol at epoch 3 while Bob is unreachable.
        let carol_leaf = alice
            .list_members(&gid)
            .await
            .expect("members")
            .iter()
            .map(|m| m.index)
            .find(|i| *i == 2)
            .expect("carol's leaf");
        let _ = alice
            .remove_member(&gid, carol_leaf)
            .await
            .expect("remove carol");

        // Carol stops accepting connections. This is only so a dial that *does*
        // happen fails at once instead of sitting on the handshake deadline —
        // the property under test is `asked`, which counts every peer the loop
        // took off its queue whatever the dial then did.
        carol
            .endpoint_ref()
            .close()
            .await
            .expect("carol leaves the network");

        // Alice first, Carol second: the ordering that made the contact
        // unconditional once the sweep stopped returning on the first answer.
        let task = tokio::spawn(async move {
            alice.accept_next().await.expect("alice serves the SYNC");
            alice
        });
        let (swept, notes) = resync_and_prune(
            &bob,
            &gid,
            &[alice_addr.clone(), carol_addr.clone()],
            &recipients,
            &rosters,
        )
        .await;
        let _alice = task.await.expect("alice task");
        let report = swept.expect("sweep");

        assert_eq!(report.to_epoch, 3, "the Remove really was applied");
        assert_eq!(
            report.asked, 1,
            "the sweep must not dial the member it has just watched being removed"
        );
        assert_eq!(report.skipped, 1, "and must say that it did not");
        assert!(
            report.failures.is_empty(),
            "a peer that is never dialled cannot fail; a failure line here means it was \
             dialled after all, got: {:?}",
            report.failures
        );
        let rendered = report.render().join(" | ");
        assert!(
            rendered.contains("1 queued peer(s) were not asked"),
            "the operator must be told the sweep is smaller than the list, got: {rendered:?}"
        );

        // And the prune that decided it is the one the listener already uses.
        let left: Vec<_> = recipients.lock().await.iter().map(|a| a.peer_id).collect();
        assert!(
            !left.contains(&carol_addr.peer_id),
            "she must also stop being addressed, got: {left:?}"
        );
        assert!(
            left.contains(&alice_addr.peer_id),
            "and nobody else may be dropped, got: {left:?}"
        );
        assert_eq!(notes.len(), 1, "one prune, one note, got: {notes:?}");
        assert!(
            notes[0].contains("dropped 1 recipient(s) removed from group"),
            "got: {notes:?}"
        );
    }

    /// The one-shot `--mls-cmd resync` stops dialling too, through its own
    /// list's filter.
    ///
    /// There is no listener recipient list on that path — the process exits
    /// when the sweep ends — so the sibling test above does not cover it, and
    /// the same dial happens for the same reason: the list came from
    /// `known_member_addrs` before the loop, and the loop moved the roster it
    /// was filtered against. Re-reading it is that filter run again, not a new
    /// rule: the remembered book is per-group and holds no operator-typed
    /// address, so nothing here can revoke another group's delivery path.
    #[tokio::test]
    async fn the_one_shot_resync_stops_dialling_a_peer_its_own_commit_just_removed() {
        let net = MockNetwork::new();
        let (alice, _dir_a) = build_test_processor(&net, "alice", 1);
        let (bob, _dir_b) = build_test_processor(&net, "bob", 2);
        let (carol, _dir_c) = build_test_processor(&net, "carol", 3);

        let alice_addr = alice.local_addr().await.expect("alice addr");
        let bob_addr = bob.local_addr().await.expect("bob addr");
        let alice_ticket: Ticket = print_local_address(&alice)
            .await
            .expect("alice ticket")
            .parse()
            .expect("parse alice");
        let carol_ticket: Ticket = print_local_address(&carol)
            .await
            .expect("carol ticket")
            .parse()
            .expect("parse carol");
        let bob_kp = bob.export_key_package().await.expect("bob kp");
        let carol_kp = carol.export_key_package().await.expect("carol kp");

        let gid = alice.create_group().await.expect("create");
        let add_bob = alice.add_member(&gid, &bob_kp).await.expect("add bob");
        let bob = {
            let task = tokio::spawn(async move {
                bob.accept_next().await.expect("bob accepts welcome");
                bob
            });
            alice
                .send_welcome_to(&bob_addr, &add_bob.welcome)
                .await
                .expect("welcome to bob");
            task.await.expect("bob task")
        };
        let _ = alice.add_member(&gid, &carol_kp).await.expect("add carol");

        let alice = {
            let task = tokio::spawn(async move {
                alice.accept_next().await.expect("alice serves the SYNC");
                alice
            });
            resync(&bob, &gid, std::slice::from_ref(&alice_addr))
                .await
                .expect("bob catches up");
            task.await.expect("alice task")
        };
        assert_eq!(bob.load_group_summary(&gid).await.expect("bob").epoch, 2);

        // Bob's address book: both members, which is what `--mls-cmd resync`
        // with no ticket asks. redb key order is node-id byte order, so Alice
        // (0x01…) is asked before Carol (0x03…).
        bob.remember_member_tickets(&gid, &[alice_ticket, carol_ticket]);
        let peers = bob.known_member_addrs(&gid).expect("book");
        assert_eq!(peers.len(), 2, "both members are remembered");

        let carol_leaf = alice
            .list_members(&gid)
            .await
            .expect("members")
            .iter()
            .map(|m| m.index)
            .find(|i| *i == 2)
            .expect("carol's leaf");
        let _ = alice
            .remove_member(&gid, carol_leaf)
            .await
            .expect("remove carol");
        carol
            .endpoint_ref()
            .close()
            .await
            .expect("carol leaves the network");

        let task = tokio::spawn(async move {
            alice.accept_next().await.expect("alice serves the SYNC");
            alice
        });
        let (swept, notes) =
            resync_sweep(&bob, &gid, &peers, PeerSource::Remembered).await;
        let _alice = task.await.expect("alice task");
        let report = swept.expect("sweep");

        assert_eq!(report.to_epoch, 3, "the Remove really was applied");
        assert_eq!(
            report.asked, 1,
            "the one-shot sweep must not dial the member it just watched being removed"
        );
        assert_eq!(report.skipped, 1);
        assert!(
            report.failures.is_empty(),
            "a peer that is never dialled cannot fail, got: {:?}",
            report.failures
        );
        assert!(
            notes.is_empty(),
            "there is no recipient list on this path to report a prune for, got: {notes:?}"
        );
    }

    /// A departure the sweep watched happen is **named**, even where no queued
    /// peer was dropped for it.
    ///
    /// The gap this closes is the operator's next invocation. `--mls-cmd resync`
    /// takes one ticket, so the multi-peer forms' re-derivation has nothing to
    /// do here: the queue is one address long and `PeerSource::Operator`
    /// re-derives nothing anyway, which leaves `skipped` at 0 and, before this
    /// line existed, the whole report silent about anyone else. Bob, offline,
    /// holds tickets for Alice and Mallory. He asks Alice; her stream carries
    /// the Commit evicting Mallory, which mls-rs verifies and he persists. Then
    /// he reads the report and decides what to run next — and "epoch 2 → 3 after
    /// asking 1 peer(s)" is compatible with Mallory still being a member. The
    /// second invocation would hand a node this roster no longer lists his
    /// liveness, his network path, the group id and his post-eviction epoch,
    /// which `request_resync` puts in the SYNC request in clear.
    ///
    /// Nothing is *acted* on here, and the assertions below pin that too: the
    /// queue is untouched, the sweep still asks exactly what it was given, and
    /// there is no drop for a responder to steer. What changes is that the
    /// operator sees the id before choosing.
    ///
    /// The line's claim is checked as narrowly as it is made. It says these ids
    /// were on this group's roster as we held it at the start and are not on it
    /// now; it does not say the group removed them — `current_member_node_ids`
    /// reads a self-asserted `peer_id` out of each member's own credential — and
    /// it does not tell the operator what to do.
    #[tokio::test]
    async fn a_departure_the_sweep_watched_is_named_even_with_nothing_dropped() {
        let net = MockNetwork::new();
        let (alice, _dir_a) = build_test_processor(&net, "alice", 1);
        let (bob, _dir_b) = build_test_processor(&net, "bob", 2);
        let (mallory, _dir_m) = build_test_processor(&net, "mallory", 3);

        let alice_addr = alice.local_addr().await.expect("alice addr");
        let bob_addr = bob.local_addr().await.expect("bob addr");
        let mallory_addr = mallory.local_addr().await.expect("mallory addr");
        let bob_kp = bob.export_key_package().await.expect("bob kp");
        let mallory_kp = mallory.export_key_package().await.expect("mallory kp");

        let gid = alice.create_group().await.expect("create");
        let add_bob = alice.add_member(&gid, &bob_kp).await.expect("add bob");
        let bob = {
            let task = tokio::spawn(async move {
                bob.accept_next().await.expect("bob accepts welcome");
                bob
            });
            alice
                .send_welcome_to(&bob_addr, &add_bob.welcome)
                .await
                .expect("welcome to bob");
            task.await.expect("bob task")
        };
        let _ = alice
            .add_member(&gid, &mallory_kp)
            .await
            .expect("add mallory");

        // Bob catches up to the epoch that seats Mallory, so she is on the
        // roster he starts the next sweep from.
        let alice = {
            let task = tokio::spawn(async move {
                alice.accept_next().await.expect("alice serves the SYNC");
                alice
            });
            resync(&bob, &gid, std::slice::from_ref(&alice_addr))
                .await
                .expect("bob catches up");
            task.await.expect("alice task")
        };
        assert_eq!(bob.load_group_summary(&gid).await.expect("bob").epoch, 2);
        assert!(
            bob.current_member_node_ids(&gid)
                .expect("bob roster")
                .contains(mallory_addr.peer_id.as_bytes()),
            "the premise: Mallory is on Bob's roster before the sweep"
        );

        // Now she is evicted while Bob is not looking.
        let mallory_leaf = alice
            .list_members(&gid)
            .await
            .expect("members")
            .iter()
            .map(|m| m.index)
            .find(|i| *i == 2)
            .expect("mallory's leaf");
        let _ = alice
            .remove_member(&gid, mallory_leaf)
            .await
            .expect("remove mallory");

        // Invocation #1: the single ticket the CLI permits.
        let task = tokio::spawn(async move {
            alice.accept_next().await.expect("alice serves the SYNC");
            alice
        });
        let (swept, notes) = resync_sweep(
            &bob,
            &gid,
            std::slice::from_ref(&alice_addr),
            PeerSource::Operator,
        )
        .await;
        let _alice = task.await.expect("alice task");
        let report = swept.expect("sweep");

        assert_eq!(report.to_epoch, 3, "the Remove really was applied");
        assert_eq!(report.asked, 1);
        assert_eq!(
            report.skipped, 0,
            "nothing is dropped on this path — which is exactly why the report was silent"
        );
        assert!(notes.is_empty(), "no recipient list here, got: {notes:?}");
        assert_eq!(
            report.departed,
            vec![mallory_addr.peer_id],
            "the id that left the roster must be named, and only that one"
        );

        let lines = report.render();
        let mallory_hex = mallory_addr.peer_id.to_string();
        let line = lines
            .iter()
            .find(|l| l.contains(&mallory_hex))
            .unwrap_or_else(|| {
                panic!(
                    "the operator must see the node id before deciding what to run next, \
                     got: {lines:?}"
                )
            });
        // What reaches the line is a fixed-width hex id, not peer-chosen text:
        // `PeerId`'s `Display` is `hex::encode` of 32 bytes.
        assert_eq!(mallory_hex.len(), 64);
        assert!(mallory_hex.chars().all(|c| c.is_ascii_hexdigit()));
        // The claim stays where the code can support it.
        let lower = line.to_lowercase();
        assert!(
            !lower.contains("the group removed") && !lower.contains("was removed from"),
            "a roster node id is self-asserted, so the line reports our roster rather \
             than the group's verdict, got: {line:?}"
        );
        assert!(
            !lower.contains("do not ") && !lower.contains("stop dialling"),
            "the line reports; what to do about it is the operator's, got: {line:?}"
        );
        assert!(
            !lines.iter().any(|l| l.to_lowercase().contains("up to date")),
            "no wording may assert currency, got: {lines:?}"
        );
    }

    /// A peer that serves us the Commit removing **us** is reported as exactly
    /// that, and is never credited with moving our state.
    ///
    /// mls-rs verifies and persists that Commit like any other, but it does not
    /// advance our locally persisted epoch, so `request_resync` returns
    /// "applied" while `load_group_summary` still reads the epoch we came in
    /// at. Crediting the peer on that return produced a report whose first line
    /// said our epoch had not moved and whose second said Commits had come from
    /// the peer — a positive sentence about a peer-supplied node id that the
    /// code could not support. Any current member can drive it: the Commit
    /// removing us is plain handshake material every one of them holds.
    ///
    /// So the credit is measured on our own epoch (it does not move here), and
    /// the removal is reported from `CommitEffect::Removed`, which mls-rs sets
    /// only after authenticating the Commit against our own group state. That
    /// says the signer held this group's state at the epoch we are at — **not**
    /// that we are out of the group, and not that only a legitimate member could
    /// have produced it: the sibling test
    /// `a_removal_minted_by_an_evicted_member_is_reported_as_the_responder_not_as_our_exit`
    /// mints exactly this Commit from a member the group had already evicted, and
    /// asserts that no wording here claims otherwise.
    #[tokio::test]
    async fn a_commit_that_removes_us_is_reported_as_removal_not_as_progress() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let net = MockNetwork::new();
        let (alice, _dir_a) = build_test_processor(&net, "alice", 1);
        let (bob, _dir_b) = build_test_processor(&net, "bob", 2);
        let (carol, _dir_c) = build_test_processor(&net, "carol", 3);

        let alice_addr = alice.local_addr().await.expect("alice addr");
        let bob_addr = bob.local_addr().await.expect("bob addr");
        let carol_addr = carol.local_addr().await.expect("carol addr");
        let bob_kp = bob.export_key_package().await.expect("bob kp");
        let carol_kp = carol.export_key_package().await.expect("carol kp");

        let gid = alice.create_group().await.expect("create");
        let add_bob = alice.add_member(&gid, &bob_kp).await.expect("add bob");
        let bob = {
            let task = tokio::spawn(async move {
                bob.accept_next().await.expect("bob accepts welcome");
                bob
            });
            alice
                .send_welcome_to(&bob_addr, &add_bob.welcome)
                .await
                .expect("welcome to bob");
            task.await.expect("bob task")
        };
        let add_carol = alice.add_member(&gid, &carol_kp).await.expect("add carol");
        let carol = {
            let task = tokio::spawn(async move {
                carol.accept_next().await.expect("carol accepts welcome");
                carol
            });
            alice
                .send_welcome_to(&carol_addr, &add_carol.welcome)
                .await
                .expect("welcome to carol");
            task.await.expect("carol task")
        };

        // Bob catches up honestly to epoch 2.
        let alice = {
            let task = tokio::spawn(async move {
                alice.accept_next().await.expect("alice serves the SYNC");
                alice
            });
            resync(&bob, &gid, std::slice::from_ref(&alice_addr))
                .await
                .expect("bob catches up");
            task.await.expect("alice task")
        };
        assert_eq!(bob.load_group_summary(&gid).await.expect("bob").epoch, 2);

        // Alice removes Bob at epoch 3.
        let bob_leaf = alice
            .list_members(&gid)
            .await
            .expect("members")
            .iter()
            .map(|m| m.index)
            .find(|i| *i == 1)
            .expect("bob's leaf");
        let _ = alice.remove_member(&gid, bob_leaf).await.expect("remove bob");

        // Carol joined at epoch 2 and is entitled to the epoch-3 Commit, so take
        // it off the wire verbatim rather than synthesising one: what Bob
        // applies below is the genuine Remove, signed by Alice.
        let commit_e3: Vec<u8> = {
            let task = tokio::spawn(async move {
                let _ = alice.accept_next().await;
                alice
            });
            let mut s = carol
                .endpoint_ref()
                .connect(&alice_addr, crate::group::transport::ALPN_MLS_PROTOCOL)
                .await
                .expect("carol dials alice");
            s.write_all(b"SYNC").await.expect("SYNC header");
            let mut req = [0u8; 40];
            req[0..32].copy_from_slice(gid.as_bytes());
            req[32..40].copy_from_slice(&2u64.to_le_bytes());
            s.write_all(&req).await.expect("SYNC request");
            let mut resp = [0u8; 4];
            s.read_exact(&mut resp).await.expect("SYNC response");
            assert_eq!(&resp, b"OK\x00\x00");
            let mut len = [0u8; 4];
            s.read_exact(&mut len).await.expect("commit length");
            let mut body = vec![0u8; u32::from_le_bytes(len) as usize];
            s.read_exact(&mut body).await.expect("commit bytes");
            let _alice = task.await.expect("alice task");
            body
        };

        // Any member can replay it. This one answers with nothing else.
        let mut reply = b"OK\x00\x00".to_vec();
        reply.extend_from_slice(&(commit_e3.len() as u32).to_le_bytes());
        reply.extend_from_slice(&commit_e3);
        let (evictor_addr, evictor) = spawn_raw_sync_responder(&net, 11, reply);

        let report = resync(&bob, &gid, std::slice::from_ref(&evictor_addr))
            .await
            .expect("a removal is a report, not a local error");
        evictor.await.expect("evictor responder");

        assert_eq!(report.answered.len(), 1);
        assert!(
            report.answered[0].served_our_removal,
            "the Commit mls-rs verified removed us, and that is the one fact this \
             exchange establishes"
        );
        assert!(
            !report.answered[0].advanced_us,
            "our own epoch did not move for it, so nothing may say this peer moved us"
        );
        assert_eq!(report.from_epoch, 2);
        assert_eq!(
            report.to_epoch, 2,
            "mls-rs does not advance the persisted epoch for the Commit that evicts us"
        );

        let rendered = report.render().join(" | ");
        assert!(
            rendered.contains("our epoch did not move"),
            "line 1 is still about our own state, got: {rendered:?}"
        );
        assert!(
            !rendered.contains("our epoch advanced while asking"),
            "no peer may be credited with progress our own epoch did not make, \
             got: {rendered:?}"
        );
        assert!(
            !rendered.contains("Commits came from"),
            "and not under the old wording either, got: {rendered:?}"
        );
        assert!(
            rendered.contains("served a Commit that removes us"),
            "the operator must be told what this peer sent, got: {rendered:?}"
        );
        assert!(
            !rendered.to_lowercase().contains("up to date"),
            "being evicted is not currency, got: {rendered:?}"
        );
    }

    /// When the same stream moves us **and then** removes us, the removal line
    /// says what it changed and nothing more.
    ///
    /// `request_resync` applies and persists every Commit ahead of the removal
    /// before it breaks out of the stream, and the removal line is rendered once
    /// per report, gated only on "some peer served one". So a responder that
    /// streams `[Remove(someone else), Remove(us)]` — both signable from the
    /// evicted-member position the sibling test documents — produces a report
    /// whose first line records real movement. A sentence on the removal line
    /// claiming our epoch, tree and roster are unchanged contradicts it and is
    /// false: this responder just took a member off our roster.
    ///
    /// What is true, and all that is true, is the mls-rs behaviour for the
    /// self-removal Commit itself: `update_key_schedule` is skipped and the
    /// provisional state dropped, so **that** Commit changes nothing. The line
    /// is scoped to it and points at the epoch line for the rest.
    ///
    /// Both Commits are genuine and are taken off the wire from Alice rather
    /// than synthesised, so what Bob applies is what mls-rs verifies.
    #[tokio::test]
    async fn a_stream_that_moves_us_before_removing_us_scopes_the_unchanged_claim() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let net = MockNetwork::new();
        let (alice, _dir_a) = build_test_processor(&net, "alice", 1);
        let (bob, _dir_b) = build_test_processor(&net, "bob", 2);
        let (carol, _dir_c) = build_test_processor(&net, "carol", 3);
        // Dave is used only as an *entitled SYNC requester*: Alice's roster
        // lists him from the Add commit onward, which is all the responder's
        // membership check reads, so he needs no group state of his own.
        let (dave, _dir_d) = build_test_processor(&net, "dave", 4);

        let alice_addr = alice.local_addr().await.expect("alice addr");
        let bob_addr = bob.local_addr().await.expect("bob addr");
        let carol_addr = carol.local_addr().await.expect("carol addr");
        let bob_kp = bob.export_key_package().await.expect("bob kp");
        let carol_kp = carol.export_key_package().await.expect("carol kp");
        let dave_kp = dave.export_key_package().await.expect("dave kp");

        let gid = alice.create_group().await.expect("create");
        let add_bob = alice.add_member(&gid, &bob_kp).await.expect("add bob");
        let bob = {
            let task = tokio::spawn(async move {
                bob.accept_next().await.expect("bob accepts welcome");
                bob
            });
            alice
                .send_welcome_to(&bob_addr, &add_bob.welcome)
                .await
                .expect("welcome to bob");
            task.await.expect("bob task")
        };
        let _ = alice.add_member(&gid, &carol_kp).await.expect("add carol");
        let _ = alice.add_member(&gid, &dave_kp).await.expect("add dave");

        // Bob catches up honestly to epoch 3, so the epoch-4 and epoch-5
        // Commits below are the next two he can apply, in that order.
        let alice = {
            let task = tokio::spawn(async move {
                alice.accept_next().await.expect("alice serves the SYNC");
                alice
            });
            resync(&bob, &gid, std::slice::from_ref(&alice_addr))
                .await
                .expect("bob catches up");
            task.await.expect("alice task")
        };
        assert_eq!(bob.load_group_summary(&gid).await.expect("bob").epoch, 3);
        assert!(
            bob.current_member_node_ids(&gid)
                .expect("bob roster")
                .contains(carol_addr.peer_id.as_bytes()),
            "Carol is on Bob's roster before the sweep, so her departure is measurable"
        );

        // Epoch 4 removes Carol; epoch 5 removes Bob.
        let carol_leaf = alice
            .list_members(&gid)
            .await
            .expect("members")
            .iter()
            .map(|m| m.index)
            .find(|i| *i == 2)
            .expect("carol's leaf");
        let _ = alice
            .remove_member(&gid, carol_leaf)
            .await
            .expect("remove carol");
        let bob_leaf = alice
            .list_members(&gid)
            .await
            .expect("members")
            .iter()
            .map(|m| m.index)
            .find(|i| *i == 1)
            .expect("bob's leaf");
        let _ = alice.remove_member(&gid, bob_leaf).await.expect("remove bob");
        assert_eq!(alice.load_group_summary(&gid).await.expect("alice").epoch, 5);

        // Dave joined at epoch 3, so the join-epoch clamp entitles him to both.
        let frames: Vec<Vec<u8>> = {
            let task = tokio::spawn(async move {
                let _ = alice.accept_next().await;
                alice
            });
            let mut s = dave
                .endpoint_ref()
                .connect(&alice_addr, crate::group::transport::ALPN_MLS_PROTOCOL)
                .await
                .expect("dave dials alice");
            s.write_all(b"SYNC").await.expect("SYNC header");
            let mut req = [0u8; 40];
            req[0..32].copy_from_slice(gid.as_bytes());
            req[32..40].copy_from_slice(&3u64.to_le_bytes());
            s.write_all(&req).await.expect("SYNC request");
            let mut resp = [0u8; 4];
            s.read_exact(&mut resp).await.expect("SYNC response");
            assert_eq!(&resp, b"OK\x00\x00");
            let mut out = Vec::new();
            for _ in 0..2 {
                let mut len = [0u8; 4];
                s.read_exact(&mut len).await.expect("commit length");
                let mut body = vec![0u8; u32::from_le_bytes(len) as usize];
                s.read_exact(&mut body).await.expect("commit bytes");
                out.push(body);
            }
            let _alice = task.await.expect("alice task");
            out
        };

        let mut reply = b"OK\x00\x00".to_vec();
        for f in &frames {
            reply.extend_from_slice(&(f.len() as u32).to_le_bytes());
            reply.extend_from_slice(f);
        }
        let (responder_addr, responder) = spawn_raw_sync_responder(&net, 16, reply);

        let report = resync(&bob, &gid, std::slice::from_ref(&responder_addr))
            .await
            .expect("a removal is a report, not a local error");
        responder.await.expect("responder");

        // The sweep really did both things: it moved us, and it took a member
        // off our roster.
        assert_eq!(report.from_epoch, 3);
        assert_eq!(
            report.to_epoch, 4,
            "the Remove of Carol was applied and persisted; the Remove of us was not \
             counted as progress"
        );
        assert!(
            !bob.current_member_node_ids(&gid)
                .expect("bob roster")
                .contains(carol_addr.peer_id.as_bytes()),
            "this responder's stream took Carol off our roster"
        );
        assert_eq!(report.answered.len(), 1);
        assert!(report.answered[0].advanced_us);
        assert!(report.answered[0].served_our_removal);

        let rendered = report.render().join(" | ");
        assert!(
            rendered.contains("epoch 3 → 4"),
            "line 1 must record the movement, got: {rendered:?}"
        );
        assert!(
            rendered.contains("Applying that Commit alone left our epoch, tree and roster \
                               as they were"),
            "the unchanged claim must be scoped to the self-removal Commit, \
             got: {rendered:?}"
        );
        // The unscoped form, which this very report falsifies.
        assert!(
            !rendered.contains("Our own epoch, tree and roster are unchanged"),
            "a report that moved our epoch and shortened our roster may not also say \
             nothing changed, got: {rendered:?}"
        );
    }

    /// The one-shot `--mls-cmd resync` refuses a second
    /// `--mls-recipient-ticket`, and refuses it **before it dials anybody**.
    ///
    /// `--mls-recipient-ticket` is a shared `Vec` flag, and the other
    /// subcommands use it as one; the restriction is this subcommand's, because
    /// of what a resync does with an answer. `request_resync` applies and
    /// persists every Commit a responder streams, verified only against our own
    /// — possibly stale — state, and one Commit can remove several leaves. Given
    /// a list, the first peer asked therefore decides what happens to the rest:
    /// it can serve a Remove of the operator's other named peers, and the sweep
    /// then either dials a member it has just watched being evicted or drops it
    /// from the queue — a responder excising the answers that would have
    /// contradicted its own, reported as a departure. One peer per invocation
    /// leaves no queue for an answer to act on.
    ///
    /// The assertion is on behaviour, not on the message: each address is a
    /// responder that signals when it is dialled, and neither may be. If the
    /// check were dropped both would answer `OK\x00\x00`, `run` would return
    /// `Ok`, and both signals would arrive.
    #[tokio::test]
    async fn the_one_shot_resync_refuses_more_than_one_ticket() {
        let net = MockNetwork::new();
        let (alice, _dir_a) = build_test_processor(&net, "alice", 1);
        let (bob, _dir_b) = build_test_processor(&net, "bob", 2);

        let bob_addr = bob.local_addr().await.expect("bob addr");
        let bob_kp = bob.export_key_package().await.expect("bob kp");
        let gid = alice.create_group().await.expect("create");
        let add_bob = alice.add_member(&gid, &bob_kp).await.expect("add bob");
        let bob = {
            let task = tokio::spawn(async move {
                bob.accept_next().await.expect("bob accepts welcome");
                bob
            });
            alice
                .send_welcome_to(&bob_addr, &add_bob.welcome)
                .await
                .expect("welcome to bob");
            task.await.expect("bob task")
        };

        // Two peers that would both answer, so nothing but the refusal can keep
        // them un-dialled.
        let (first_addr, first, mut first_rx) =
            spawn_probed_sync_responder(&net, 14, b"OK\x00\x00".to_vec());
        let (second_addr, second, mut second_rx) =
            spawn_probed_sync_responder(&net, 15, b"OK\x00\x00".to_vec());

        let err = run(
            MlsCommand::Resync {
                group_id: gid,
                peer_tickets: vec![
                    Ticket::new(first_addr, None, None),
                    Ticket::new(second_addr, None, None),
                ],
            },
            bob,
        )
        .await
        .expect_err("two tickets must be refused");
        first.abort();
        second.abort();

        assert!(
            first_rx.try_recv().is_err(),
            "the refusal must land before the first peer is dialled"
        );
        assert!(
            second_rx.try_recv().is_err(),
            "and no peer on the list may be dialled either"
        );
        let msg = format!("{err:#}");
        assert!(
            msg.contains("at most one --mls-recipient-ticket"),
            "the operator must be told the limit, got: {msg:?}"
        );
        // The alternative offered must not misdescribe itself: dropping the
        // ticket selects the remembered-address sweep, which asks *every*
        // remembered member, not one.
        assert!(
            msg.contains("all of them"),
            "omitting the ticket is still a multi-peer sweep and the error must not \
             imply otherwise, got: {msg:?}"
        );
    }

    /// …and the one ticket it does take is asked even when no roster vouches for
    /// it.
    ///
    /// That bypass is why an explicit ticket exists: `resolve_recipients` and
    /// `known_member_addrs` filter the stored address book against this group's
    /// live roster, and a ticket the operator typed is deliberately not put
    /// through it — the address is dialled because the operator named it. Routing
    /// the ticket branch through the roster instead would revoke that for every
    /// address the roster cannot vouch for, including one that was never on it.
    ///
    /// Driven through `run` rather than through the sweep helper, because the
    /// dispatch arm is where the two branches are chosen and so where the bypass
    /// could be lost. Asserted on the dial itself: a filtered branch never
    /// connects to this address at all.
    #[tokio::test]
    async fn the_one_shot_resync_still_asks_a_single_ticket_no_roster_vouches_for() {
        let net = MockNetwork::new();
        let (alice, _dir_a) = build_test_processor(&net, "alice", 1);
        let (bob, _dir_b) = build_test_processor(&net, "bob", 2);
        let (carol, _dir_c) = build_test_processor(&net, "carol", 3);

        let bob_addr = bob.local_addr().await.expect("bob addr");
        let alice_ticket: Ticket = print_local_address(&alice)
            .await
            .expect("alice ticket")
            .parse()
            .expect("parse alice");
        let bob_kp = bob.export_key_package().await.expect("bob kp");
        let carol_kp = carol.export_key_package().await.expect("carol kp");

        let gid = alice.create_group().await.expect("create");
        let add_bob = alice.add_member(&gid, &bob_kp).await.expect("add bob");
        let bob = {
            let task = tokio::spawn(async move {
                bob.accept_next().await.expect("bob accepts welcome");
                bob
            });
            alice
                .send_welcome_to(&bob_addr, &add_bob.welcome)
                .await
                .expect("welcome to bob");
            task.await.expect("bob task")
        };
        let _ = alice.add_member(&gid, &carol_kp).await.expect("add carol");

        // Bob's address book holds a member of this group, so a branch that
        // consulted the roster would have somewhere else to go and would still
        // return `Ok` — which is what makes the dial signal, not the return
        // value, the thing under test.
        bob.remember_member_tickets(&gid, &[alice_ticket]);
        assert_eq!(
            bob.known_member_addrs(&gid).expect("book").len(),
            1,
            "the roster-filtered list is non-empty, so this test cannot pass by \
             accident of there being nothing else to ask"
        );

        // A node no group vouches for: never on this roster, never in the book.
        let (outsider_addr, outsider, mut outsider_rx) =
            spawn_probed_sync_responder(&net, 13, b"OK\x00\x00".to_vec());
        let outsider_id = outsider_addr.peer_id;
        assert!(
            !bob.current_member_node_ids(&gid)
                .expect("bob roster")
                .contains(outsider_id.as_bytes()),
            "the ticket under test must be for a node this group's roster does not list"
        );

        // Alice must not answer: if the ticket were filtered out and the sweep
        // fell back to the remembered book, this would be the peer it reached,
        // and the run would still succeed. Leaving her silent is what turns that
        // substitution into a visible failure.
        let alice_task = tokio::spawn(async move {
            let _ = alice;
            std::future::pending::<()>().await;
        });

        run(
            MlsCommand::Resync {
                group_id: gid,
                peer_tickets: vec![Ticket::new(outsider_addr, None, None)],
            },
            bob,
        )
        .await
        .expect("the outsider answered, so the sweep reached somebody");
        outsider.abort();
        alice_task.abort();

        assert!(
            outsider_rx.try_recv().is_ok(),
            "a ticket for a peer no roster vouches for must still be dialled — that \
             bypass is what an explicit ticket is for"
        );
    }

    /// A Commit removing us is **not** proof we are out of the group, and the
    /// report must not say it is.
    ///
    /// mls-rs verifying that Commit establishes one thing: its signer held this
    /// group's state at the epoch we are at. A member the group evicted at a
    /// *later* epoch — one we have not applied — still holds exactly that, and
    /// that is precisely the party a lagging caller ends up dialling
    /// (`known_member_addrs` filters the address book against our own stale
    /// roster, so an evicted member survives it). Here Carol, evicted at epoch 3,
    /// signs a Remove of Bob at Bob's epoch 2; Bob verifies it, while Alice — the
    /// honest, up-to-date group — still lists Bob as a member.
    ///
    /// So this pins what the line may say. It reports the responder; it does not
    /// call the Commit unmintable, does not tell the operator no delta can carry
    /// us past it (mls-rs discards a self-removal, so a later honest delta
    /// applies normally), and does not steer anyone to a fresh Welcome — which
    /// `join_group_from_welcome` refuses for a gid we already hold, leaving only
    /// a Welcome for a *different* group from whoever connects first. That is the
    /// chain already taken off the `ERR\x01` path.
    #[tokio::test]
    async fn a_removal_minted_by_an_evicted_member_is_reported_as_the_responder_not_as_our_exit() {
        let net = MockNetwork::new();
        let (alice, _dir_a) = build_test_processor(&net, "alice", 1);
        let (bob, _dir_b) = build_test_processor(&net, "bob", 2);
        let (carol, _dir_c) = build_test_processor(&net, "carol", 3);

        let alice_addr = alice.local_addr().await.expect("alice addr");
        let bob_addr = bob.local_addr().await.expect("bob addr");
        let carol_addr = carol.local_addr().await.expect("carol addr");
        let bob_kp = bob.export_key_package().await.expect("bob kp");
        let carol_kp = carol.export_key_package().await.expect("carol kp");

        let gid = alice.create_group().await.expect("create");
        let add_bob = alice.add_member(&gid, &bob_kp).await.expect("add bob");
        let bob = {
            let task = tokio::spawn(async move {
                bob.accept_next().await.expect("bob accepts welcome");
                bob
            });
            alice
                .send_welcome_to(&bob_addr, &add_bob.welcome)
                .await
                .expect("welcome to bob");
            task.await.expect("bob task")
        };
        let add_carol = alice.add_member(&gid, &carol_kp).await.expect("add carol");
        let carol = {
            let task = tokio::spawn(async move {
                carol.accept_next().await.expect("carol accepts welcome");
                carol
            });
            alice
                .send_welcome_to(&carol_addr, &add_carol.welcome)
                .await
                .expect("welcome to carol");
            task.await.expect("carol task")
        };

        // Bob catches up honestly to epoch 2.
        let alice = {
            let task = tokio::spawn(async move {
                alice.accept_next().await.expect("alice serves the SYNC");
                alice
            });
            resync(&bob, &gid, std::slice::from_ref(&alice_addr))
                .await
                .expect("bob catches up");
            task.await.expect("alice task")
        };
        assert_eq!(bob.load_group_summary(&gid).await.expect("bob").epoch, 2);

        // The group evicts Carol at epoch 3. Bob is unreachable and never sees
        // it, so his roster — and any address list derived from it — still has
        // her on it.
        let carol_leaf = alice
            .list_members(&gid)
            .await
            .expect("members")
            .iter()
            .map(|m| m.index)
            .find(|i| *i == 2)
            .expect("carol's leaf");
        let _ = alice
            .remove_member(&gid, carol_leaf)
            .await
            .expect("remove carol");

        // Carol, evicted but still holding epoch-2 state, signs a Remove of Bob.
        // It is built at Bob's current epoch, which is all it takes.
        let bob_leaf = carol
            .list_members(&gid)
            .await
            .expect("members")
            .iter()
            .map(|m| m.index)
            .find(|i| *i == 1)
            .expect("bob's leaf");
        let forged = carol
            .remove_member(&gid, bob_leaf)
            .await
            .expect("an evicted member can still sign at the epoch it was evicted from");

        let mut reply = b"OK\x00\x00".to_vec();
        reply.extend_from_slice(&(forged.len() as u32).to_le_bytes());
        reply.extend_from_slice(&forged);
        let (responder_addr, responder) = spawn_raw_sync_responder(&net, 12, reply);

        let report = resync(&bob, &gid, std::slice::from_ref(&responder_addr))
            .await
            .expect("a removal is a report, not a local error");
        responder.await.expect("responder");

        // mls-rs really did verify it — the detection is kept, not weakened.
        assert_eq!(report.answered.len(), 1);
        assert!(
            report.answered[0].served_our_removal,
            "mls-rs verified a Remove of us minted by a member the group had already \
             evicted; that is the case the wording has to survive"
        );

        // And it established nothing about our membership.
        assert!(
            alice
                .current_member_node_ids(&gid)
                .expect("alice roster")
                .contains(bob_addr.peer_id.as_bytes()),
            "the honest, up-to-date group still lists us, so we are not out of it"
        );
        assert_eq!(
            report.to_epoch, 2,
            "mls-rs discards a self-removal, so our own epoch is untouched"
        );
        assert!(
            bob.current_member_node_ids(&gid)
                .expect("bob roster")
                .contains(bob_addr.peer_id.as_bytes()),
            "and our own roster still lists us, so a later honest delta applies normally"
        );

        let rendered = report.render().join(" | ");
        assert!(
            rendered.contains("served a Commit that removes us"),
            "the operator must still be told what this peer sent, got: {rendered:?}"
        );
        assert!(
            rendered.contains("Ask another peer"),
            "and told what to do about it. Not that the responder is dishonest — an \
             honest one that removed us and re-admitted us later serves this same \
             Commit out of retained history where it recorded no join epoch for us — \
             but that one peer's word settles nothing here, got: {rendered:?}"
        );
        // The three claims round 3 made here, each false in this very test.
        assert!(
            !rendered.contains("mint"),
            "an evicted member just minted one, so nothing may say an outsider cannot, \
             got: {rendered:?}"
        );
        assert!(
            !rendered.to_lowercase().contains("welcome"),
            "no re-admission steer: `join_group_from_welcome` refuses a Welcome for a gid \
             we already hold, so the only one that could be accepted is for a different \
             group, from whoever connects first, got: {rendered:?}"
        );
        assert!(
            !rendered.contains("No delta can carry us past it"),
            "a later honest delta applies normally, got: {rendered:?}"
        );
        assert!(
            !rendered.to_lowercase().contains("accept-one")
                && !rendered.to_lowercase().contains("accept_one"),
            "and no command is named, got: {rendered:?}"
        );
    }
}
