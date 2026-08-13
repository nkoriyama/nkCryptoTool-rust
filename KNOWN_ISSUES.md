# Known Issues (v1.0.0)

Despite reaching v1.0.0, the following security and usability issues are known and scheduled for future resolution.

## Security Issues

### 1. HKDF Zeroization (36-3) — Blocked
The `hkdf` crate (v0.12 / v0.13) does **not** expose a `zeroize` feature, so internal HMAC context and PRK are not auto-zeroized on drop.
- **Status**: **Blocked** by upstream ecosystem. The `hmac` crate added `zeroize` in v0.13, but `hkdf` does not propagate it. Forcing `hkdf` v0.13 also pulls in `digest` v0.11, which conflicts with the `digest` v0.10-locked majority of our crypto stack (`p256`, `ecdsa`, `aes-gcm`, `sha3`).
- **Mitigation**: Output keys produced from HKDF are already wrapped in `Zeroizing` at call sites (`src/strategy/`, `src/backend/`). Only the crate-internal intermediate state remains potentially residual.
- **Risk**: Low (intermediate KDF states might remain in memory briefly).
- **Root Fix**: Wait for the RustCrypto ecosystem to migrate to `digest` v0.11 across `p256` / `aes-gcm` / `sha3`, then upgrade in lockstep with `hkdf` zeroize-aware revisions. Re-evaluate then.
- **Investigation reference**: `THREAT_36-3_INVESTIGATION_REPORT.md`.

### 2. ML-KEM Seed Internal Copy (37-2)
The underlying `fips203` library may perform internal copies of sensitive seeds that are outside the control of `nkCryptoTool`.
- **Status**: Blocked by upstream library updates.

## Usability Issues

### 1. Stdin/Stdout only File Transfer
Resolved: Direct file path arguments for network transfer are now implemented.


## GUI Features (deferred)

### 1. QR Code Scan (M2)
Automatic NKCT1 ticket reading via camera is not yet implemented.
- **Workaround**: Manual copy-paste of connection tickets.

## Security Audit Residuals (accepted, low/informational)

A 2026-06 audit surfaced the items below. Each was verified against the code
and is intentionally left as-is; the rationale is recorded here so the
trade-off is explicit rather than forgotten.

1. **TCP chat per-message random nonce** (`network/mod.rs`): AES-GCM with a
   random 96-bit nonce has a birthday bound around 2^32 messages per key. A
   single interactive chat session will not approach this, and the TCP
   transport is already deprecated (Iroh is preferred). Not changed.
2. **Chat replay window past the 100k nonce-history cap** (`network/mod.rs`):
   the per-session seen-nonce set is bounded (memory-safety/DoS trade-off); a
   replay of an *evicted* nonce within the same long-lived session would only
   re-display one already-seen line — no key compromise or integrity break.
3. **FETCH prekey rate-limit vs. fresh NodeIds** (`network/inbox.rs`): the
   per-NodeId token bucket is bypassable by minting new NodeIds (cheap), so a
   second, recipient-keyed bound was added in 2026-08: the lowest quarter of
   what a recipient is observed to stock is a reserve band, and a draw inside
   it also costs a token from a bucket keyed on the **recipient**, which no
   number of minted NodeIds divides. It bounds the drain rate and disengages
   the moment the recipient replenishes; it does **not** prevent the
   downgrade — a sustained attacker still drives a default-profile sender to a
   static-only seal, and the `Require Prekey (Strict PQ-FS)` profile remains
   the real backstop. Residuals: the stocking marks are process-local soft
   state (a server restart re-derives them from the live pools); an attacker
   holding 4096 *distinct* pools below their floors at once — each at the
   sustained below-floor cost — keeps the reserve table full, and a recipient
   first seen while it is full goes untracked, hence ungated until room
   appears; and the prune that keeps that table bounded can be forced, which
   drops stocking marks. That last one is the sharpest of the three. It was
   first written up here as costing the attacker a ~4 minute wait and buying a
   3x–7x advantage; a 2026-08 re-check against the code found both figures
   wrong and the framing misleading. The corrected account:
   - **No wait is required.** `TokenBucket::new` starts a bucket *full*, and
     `level > reserve_floor(r.stock) || r.bucket.try_take(now)` short-circuits,
     so a draw *above* the floor spends no token at all. An attacker who stops
     drawing exactly at the floor never charges the victim's bucket, so it
     stays full from creation and is prunable immediately. The ~4 minutes was
     the worst case for an attacker who had already spent all 8 tokens —
     spending one costs 30 s, spending none costs nothing.
   - **The real price is firing the prune.** `retain` runs only when a
     not-yet-tracked recipient draws while the table already holds
     `RESERVE_MAX_TRACKED` = 4096 entries. Because `level == 0` returns before
     the table is touched, only recipients with a genuinely stocked pool can
     create entries — but the attacker can supply those itself: PUBLISH writes
     to the slot of the handshake-authenticated NodeId and never parses the
     blob, so 4096 minted NodeIds each stocked with junk blobs will do. **No
     third party's prekeys are consumed**, only the victim's own. One prune
     costs roughly 4096 FETCH connections and 4096 pops from pools the attacker
     owns, and the same identities can be reused each round.
   - **What it buys is not extra keys but the removal of the refill race the
     reserve exists to win.** After a prune the mark re-derives from the
     drawn-down level `L` and the floor becomes `L/4`, so the pool can be
     walked down in ungated stages: 100 → 25 → 6 → 1 → 0 takes three prunes
     (~12,000 filler draws), 256 → 64 → 16 → 4 → 1 → 0 takes four (~16,000).
     No token is spent and no waiting occurs at any stage. Without the prune
     the same pool still empties, but at one key per 30 s once below the floor
     — ~8.5 minutes for 100 keys, ~28 minutes for 256 — and that window is
     exactly where a recipient's `maintain` run can replenish and win. Whether
     ~12,000 connections is in practice faster than 8.5 minutes depends on
     iroh handshake cost against `MAX_CONCURRENT_CONNECTIONS` = 256 and has
     **not** been measured.
   - Two further corrections to the old text. `retain` drops *every* entry
     whose bucket is full, not just the victim's, so one round's 4096 draws
     flush the marks of every recipient not currently being drawn below its
     floor — the cost is per round, not per victim. And "the price is holding
     that many slots below their floors for the whole window" described the
     *previous* residual, not this one: here the filler entries may stay full
     (they are pruned alongside the victim, which is fine for the attacker),
     one above-floor draw each is enough, and the table need only stand at
     4096 for the instant of the triggering draw.
4. **Non-constant-time fingerprint / pinned-key comparison**
   (`p2p/processor.rs`, `network/tcp.rs`): both operands are *public* values
   (a peer public key and its SHA3-256), compared once per connection, so a
   timing side-channel leaks nothing secret. Left as `!=` to avoid touching
   auth-critical paths for no security gain.
5. **Per-record at-rest rollback** (redb AAD binds slot but not a version):
   whole-DB anti-rollback (`rollback.rs`, default Off) and MLS epoch
   monotonicity cover this; see `docs/design/ATREST_ANTIROLLBACK_DESIGN.md`.
6. **redb create→chmod window** (`group/redb_storage.rs`): only AEAD ciphertext
   exists in the brief window before the file is tightened to 0600.
7. **Unauthenticated connection flood with rotating NodeIds** (`p2p/processor.rs`,
   2026-07): a peer that connects and stalls holds a pre-auth admission slot for
   up to `P2P_SETUP_TIMEOUT` + `handshake_timeout` (10 s + 15 s by default), and
   the accept throttle keys on the transport NodeId, which is free to mint — so
   rotating identities evades it. Availability only; nothing is disclosed or
   forged. **Confined, not prevented**: the pre-auth budget
   (`MAX_UNAUTHENTICATED`) is now a separate pool from the session budget
   (`MAX_SESSIONS`), so such a flood cannot take a slot from an authenticated
   session, and a stall after the transport proves the NodeId (the free
   Slowloris shape) is recorded against the throttle. Fully preventing it needs
   something the transport does not offer here — proof-of-work, or an
   address-level rate limit below the overlay. Accepted at this level.
8. **MLS group file receive is unverified on Windows** (`group/file_xfer.rs`,
   2026-07): every Windows CI job builds `--no-default-features --features
   backend-rustcrypto`, so the `mls` module — including the receive-side
   staging/publish path — is never compiled or run on a Windows host. That
   staging file comes from `create_owner_only`, which opens with a deny-all
   share mode there, so *every* path operation on it (the unlinks on a failed
   `END`, and the rename that publishes a completed file) has to follow the
   handle close; `Reassembler::on_end` / `abort` now order it that way, but the
   ordering is reasoned from the Win32 sharing rules, not observed. Until a
   Windows job enables `mls`, treat group file receive there as untested.

9. **A refused DEPOSIT still costs the sender a one-time prekey**
   (`network/inbox.rs`, `group/redb_storage.rs`, 2026-08): the per-recipient
   envelope cap now **refuses** a deposit into a full slot instead of evicting
   that recipient's oldest envelopes. Evicting was the bug — the recipient field
   of a DEPOSIT is unauthenticated, so any peer could flush a victim's
   undelivered queue by depositing into it, and POLL's `id > cursor` semantics
   meant the victim never learned those messages existed. The price of refusing
   is paid on the *send* path: a sender FETCHes a one-time prekey before it can
   know the deposit will be accepted, and the prekey is consumed at FETCH.
   Before this change a burned prekey always bought a delivery, because the
   deposit always succeeded; now an attacker holding a victim's 256-row slot
   turns each honest send into one destroyed prekey and zero deliveries. As many
   honest attempts as the pool holds keys — 100 at the `--prekey-count` default,
   at most 256 — exhaust it, after which the default profile seals
   `MODE_STATIC_ONLY` (no PQ-FS) until the recipient republishes. The
   per-recipient prekey reserve (item 3) does not help here: it bounds how fast
   an *attacker* drains a pool, and these draws are honest senders spending
   their own identities' budgets.
   - **What it costs the attacker**: nothing new. Holding a slot full is ~44 KB
     of upload per victim per week (256 minimum-size envelopes, and delivery
     does not delete — only the 7-day expiry sweep does), which is what flushing
     that victim's queue already cost before the fix. What changed is the
     effect: silent, undetectable destruction of a victim's mail became a loud
     `REPLY_FAIL` to the sender, with no stored envelope touched.
   - **What bounds it**: the slot frees itself when the backlog expires (7 days)
     — and it is the *next deposit addressed to that recipient* that frees it,
     because `deposit_in` sweeps the recipient's own key range
     (`sweep_recipient_expired`) before it counts the row cap. So the hold lasts
     exactly as long as the attacker keeps refilling the slot inside every
     7-day window, and no amount of unrelated junk stored elsewhere postpones
     the next honest delivery. That is deliberately **not** how the global byte
     budget recovers (item 10 below), so do not read the one bound off the
     other. One send's failure is also reported to that sender rather than
     swallowed.
     The byte budgets are partitioned per authenticated depositor, so no
     *single* identity can spend the store's whole budget — but iroh NodeIds are
     free to mint and a **fleet** of them can, which is item 10 below and not a
     bound this item may claim.
   - **Operator mitigation**: `--strict-pqfs` (`FsProfile::StrictPqFs`) refuses
     the downgrade rather than accepting it — the send fails instead of going out
     without forward secrecy. Keep pools stocked (`--prekey-cmd maintain`); a
     recipient also gets the stderr warning from
     `one_shot::warn_static_only_with_stocked_pool` when a static-only envelope
     arrives while its own pool is stocked, which this residual is now one of
     the listed explanations for.
10. **A fleet of minted NodeIds can spend the relay's whole byte budget and get
    DEPOSIT refused for everyone** (`group/redb_storage.rs`, 2026-08): the
    global check in `deposit_in` is applied *before* the per-depositor share, so
    once the ledger reaches `MAX_TOTAL_ENVELOPE_BYTES` (1 GiB) **every**
    depositor is refused — including a fresh, honest one holding nothing. This
    is a different and larger primitive than the trade item 9 accepts (one
    victim's slot held full), and it is stated here rather than fixed.
    - **What it costs the attacker**: about **268 minted identities and 1 GiB of
      upload** — 12 identities x 64 MiB (`MAX_ENVELOPE_BYTES_PER_SENDER`) to
      reach the 768 MiB soft limit, then 256 fresh identities x 1 MiB
      (`MAX_ENVELOPE_BYTES_PER_SENDER_CONGESTED`) to consume the congestion
      reserve; ~1,024 deposits at 1 MiB, or ~304 at the 16 MiB `MAX_PAYLOAD`,
      spread over at least two recipient ids because one slot holds 256 rows.
      Holding the store there costs re-sending it once per TTL window, about
      **1,775 B/s** sustained. No knowledge of any real PeerId is needed: those
      recipient ids can be random, since that field is unauthenticated — the
      same fact item 9's fix is about.
    - **Why the congestion reserve does not stop it**: the reserve makes each
      slice cost one *new* identity instead of one big one, and NodeIds are free
      to mint. Tightening either constant raises the identity count and nothing
      else, so this is documented rather than tuned — the same conclusion, for
      the same reason, as item 7's rotating-NodeId flood. Anything that actually
      prevents it needs admission control this transport does not offer:
      proof-of-work, an address-level limit below the overlay, or a depositor
      allowlist (there is no such knob today).
    - **What it does *not* do**: nothing stored is destroyed — refusal never
      deletes, which is the whole of the F2 fix — and POLL, FETCH, PUBLISH and
      CHECKPOINT are unaffected, so recipients keep draining mail already
      waiting. Availability of *new* deposits only. Read "unaffected" as *this
      budget does not gate them*, not as *they cost the relay nothing*: POLL
      used to have no bound of its own beyond a 64-**row** cap, which let one
      13-byte request make the relay decrypt and hold up to ~1 GiB — bytes an
      unauthenticated depositor uploaded once and could have re-served on every
      poll, per connection. A reply is now capped at `MAX_POLL_BYTES` (4 MiB)
      as well, leaving a per-connection floor of one `MAX_PAYLOAD` envelope
      (16 MiB, the same amount DEPOSIT already buffers) times
      `MAX_CONCURRENT_CONNECTIONS`. The visible consequence is that a slot is
      drained when a poll returns **nothing**, not when it returns fewer than
      64 rows; a large backlog takes more round trips, and none of it is lost,
      since the cursor only advances past rows actually delivered.
    - **How it lapses — later than one TTL window**: the flood's bytes are
      given back to the *global* ledger by the table-wide sweep
      (`sweep_expired`), which resumes from one shared wrapping cursor,
      examines at most `SWEEP_BUDGET_ROWS` (512) rows per step, runs at most
      once a second, and runs **only inside a DEPOSIT**. A full 1 GiB of
      minimum-size envelopes is ~6.3M rows (~171 B each), so returning all of
      it takes ~12,300 sweeps: at best ~3.4 hours *after* the rows expire, and
      only while deposits keep arriving — on a relay nobody is depositing to,
      nothing is reclaimed at all until someone does. A *slot* is not subject
      to this (item 9's hold really does end at the TTL) because a deposit
      sweeps its own recipient's range as well; the global budget is what walks.
    - **Operator note**: the 1 GiB budget is the disk bound, so the flood costs
      the relay disk it already agreed to. Run a relay for correspondents you
      are willing to serve; there is no way to tell a fleet from a crowd here.

    Three consequences of the same mechanism that are not attacks but **are**
    changes an honest deployment will notice:
    - **Undelivered mail is deleted after 7 days** (`ENVELOPE_TTL_SECS`), where
      the previous version kept it until something evicted it. Expiry is now the
      only thing that frees space, so a recipient offline longer than a week
      loses whatever was waiting for it. (*At or after* that point, precisely: a
      row goes when the first sweep walks it — the next deposit to that
      recipient, or the table-wide cursor arriving — so one may outlive its TTL
      on a quiet relay. Not something a recipient can count on.)
    - **256 envelopes per rolling week, per recipient.** POLL does not delete
      what it returns, so a delivered envelope still occupies its recipient's
      slot until it expires: `MAX_ENVELOPES_PER_RECIPIENT` now bounds what a
      recipient can be *sent* in a week — all its correspondents together, and
      an honest one gets no relief from the recipient draining promptly.
    - **Under congestion one 16 MiB deposit is refused even from a fresh
      identity**, because the congested share (1 MiB) is smaller than one
      `MAX_PAYLOAD` envelope. Large transfers fail while the store is above its
      soft limit, whoever sends them.

    Two growth vectors the budgets deliberately do not count, listed so a
    capacity plan does not miss them:
    - **~90 B per envelope on upgrade**: `EnvTs::cost` charges an
      upgrade-stamped row only for the envelope that was already there, not for
      the index row it adds (`ENV_TS_ROW_BYTES`). Charging it would push a store
      that was exactly healthy under the old cap over the new budget on first
      open and refuse every deposit until the sweep caught up. So a large legacy
      inbox exceeds the 1 GiB bound by about 90 B per stored envelope; it
      decays to zero one TTL window after the upgrade.
    - **~43 B per active depositor**: the per-depositor ledger rows in
      `TBL_META` (35 B key + 8 B value) are themselves uncharged. Bounded by the
      number of depositors holding a live backlog, and a row is dropped as soon
      as its balance reaches zero.

11. **MLS Commits and Proposals are sent in the clear — including to the
    store-and-forward relay** (`group/processor.rs`, `group/transport.rs`,
    2026-08): `Client::builder()`
    in `GroupChatProcessor::new` does not call `.mls_rules(..)`, so mls-rs
    applies `EncryptionOptions::default()` with `encrypt_control_messages =
    false`, and its `control_wire_format` returns `PrivateMessage` only when
    that flag is true (mls-rs 0.55.2, `group/mls_rules.rs`). **Every Commit and
    standalone Proposal this project emits is therefore a
    `WireFormat::PublicMessage` — signed, authenticated, and not encrypted.**
    Application messages are unaffected: those are `PrivateMessage`, AEAD-sealed
    under the epoch key schedule, as is a `Welcome`'s HPKE-wrapped GroupSecrets.
    - **What a control frame discloses**: the group id, the epoch, the
      committer's leaf index, and the membership change itself. An Add carries
      the joining member's entire KeyPackage inline — the NKCB credential with
      its iroh NodeId, ML-DSA-65 transport public key and display name, plus the
      hybrid signature key. A Remove carries the evicted leaf index. Those
      transport keys are exactly what `projected_member_fingerprints` turns into
      shell and port-forward authorization policy, so a party that collects
      these frames reads the team's access list and its complete
      membership-change timeline.
    - **Who receives one.** Two parties. The first is a peer we reach directly
      over authenticated QUIC, which is a *current group member* — already
      entitled to the current roster and every later epoch's membership data.
      That half is mild: what a member gains is the roster history back to its
      own admission in a form it can parse without any group secret, rather
      than only what the key schedule would grant.
      The second is **the inbox relay operator, who is not a member**. When a
      recipient is not reachable inside `DIRECT_CONNECT_TIMEOUT` (5 s),
      `send_one_with_inbox` deposits the frame at the operator-configured
      relay, cleartext Commits included. An operator that keeps what it stores
      reconstructs the group's whole membership graph, every member's iroh
      NodeId and ML-DSA-65 transport key, and the timeline of who joined and
      who was evicted. **This is the sharp end of this item and it is
      unmitigated.** Configuring `--inbox-url` is what enables it; running
      without a relay confines control frames to member-to-member QUIC.
    - **What *is* mitigated**: only the pull side. The SYNC commit-history
      responder clamps a requester's `claimed_epoch` to the epoch at which this
      node witnessed that member being added, so a member cannot ask a peer for
      retained history predating its own admission. That closes a member's
      *reach back*; it does nothing about the relay, which is handed the frames
      unasked.
    - **A refusal was tried here and withdrawn — do not re-propose it without
      reading this.** The obvious mitigation is for `send_one_with_inbox` to
      refuse to deposit a `PublicMessage`. It was implemented, then removed,
      because it converts a confidentiality leak into a **revocation that never
      lands**. The inbox deposit is the *only* automatic delivery path for a
      Commit that missed the 5 s direct window: `load_commits` has exactly one
      non-test reader (the SYNC responder), there is no re-broadcast and no
      retry queue, and the delta-resync protocol that could pull it is a pull —
      the removing node cannot push later at all — with, today, no
      operator-reachable caller (see the next bullet). So with
      the refusal in place: Alice removes Mallory; Bob happens to be
      unreachable for those five seconds; Bob stays at epoch N with Mallory on
      his roster, keeps dialling her, keeps encrypting application messages
      under a key schedule she can still open, still answers SYNC treating her
      as a member, and still emits her fingerprint from
      `projected_member_fingerprints` into shell/forward policy — indefinitely,
      where before the refusal it lasted until his next 2 s inbox poll. No
      special capability is needed to trigger that: "a peer was offline when
      the roster changed" is precisely the case the relay exists for, and
      anyone who can disturb one peer's path for five seconds can make an
      eviction permanently invisible to it. Silent revocation failure is worse
      than metadata disclosure to a relay the operator chose, and the flag day
      below fixes both at once — once control frames are `PrivateMessage`,
      relaying them is safe and the automatic path is safe with them.
    - **How a member that missed a Commit gets it, as of this change.** Almost
      always automatically, and only automatically: the relay holds the
      deposited frame and the recipient's inbox poll (2 s) applies it on its
      next run. That covers the ordinary "offline for a moment" case and is
      why the refusal above was withdrawn. What it does **not** cover is a
      deployment with no `--inbox-url` configured at all, a deposit that was
      itself refused (a full slot — item 9), or an absence longer than the
      relay's 7-day envelope TTL. In those cases the member is stuck at its old
      epoch and **there is no way to ask**: `GroupChatProcessor::request_resync`
      implements the pull and the responder side is live, but nothing outside
      the test suite calls it — no CLI subcommand, REPL command, GUI action or
      FFI method — so recovery is re-admission (a fresh Welcome). Wiring that
      pull to an operator-visible command is a separate follow-on change and is
      deliberately not part of this patch; until it lands, treat the relay as
      load-bearing for roster convergence.
    - **What the SYNC clamp does not cover.** A join epoch is recorded only when
      this node applies the Add commit itself (`record_witnessed_joins`, on the
      commit-build, direct-receive and resync-apply paths), stored per
      (group, member) in the existing application-data KV. `None` means
      "unknown" and deliberately does **not** clamp, because failing closed
      there would cut off legitimate resync. Unknown arises in two ways. For a
      member that was already on the roster when *we* joined, it is harmless: our
      own commit history starts at our own join, which is at or after theirs, so
      there is nothing older to leak. For a **database written before this
      release**, it is a real gap: members admitted before the upgrade have no
      record, so they keep being served from whatever epoch they claim, down to
      the oldest retained one, for as long as that history survives
      `DEFAULT_COMMIT_RETENTION` (100 epochs). No migration can fix that — the
      information was never recorded. It ages out as those epochs prune, and
      applies from admission onward for everyone added afterwards.
    - **What a real fix requires**: `encrypt_control_messages = true` via
      `.mls_rules(..)`, which changes the wire format of every Commit and
      Proposal. Every peer in a group must adopt it simultaneously — a peer on
      the old build cannot process a `PrivateMessage` Commit from a peer on the
      new one, and vice versa — so it is a flag day, scheduled separately and
      deliberately **not** taken here.

(Several other audit findings — the ECDSA verify bug, network-receive release
of unverified plaintext, the `Ticket::from_str` DoS, plaintext ECC keys, and
the weak PBKDF2 iteration count — were fixed; see the git history.)


