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
3. **FETCH prekey rate-limit vs. fresh NodeIds** (`network/inbox.rs`,
   `group/redb_storage.rs`): the per-NodeId token bucket is bypassable by
   minting new NodeIds (cheap), so a second, recipient-keyed bound was added in
   2026-08: the lowest quarter of what a recipient stocks is a reserve band, and
   a draw inside it also costs a token from a bucket keyed on the **recipient**,
   which no number of minted NodeIds divides. It bounds the drain rate and
   disengages the moment the recipient replenishes; it does **not** prevent the
   downgrade — a sustained attacker still drives a default-profile sender to a
   static-only seal, and the `Require Prekey (Strict PQ-FS)` profile remains
   the real backstop.

   **The stocking level the floor is computed from is now written by PUBLISH and
   persisted** (`b"pm:" ‖ blind_index(recipient)` in the inbox store's meta
   table, `prekey_mark_key`), replacing the process-local high-water mark the
   draw path used to derive. The first version of this defence kept that mark in
   the same bounded, prunable table as the token buckets, and **the prune was an
   attack**:
   - **No wait was required.** `TokenBucket::new` starts a bucket *full*, and
     `level > reserve_floor(..) || r.bucket.try_take(now)` short-circuits, so a
     draw *above* the floor spends no token at all. An attacker who stopped
     drawing exactly at the floor never charged the victim's bucket, so it
     stayed full from creation and was prunable immediately.
   - **The price was firing the prune.** `retain` runs only when a
     not-yet-tracked recipient draws while the table already holds
     `RESERVE_MAX_TRACKED` = 4096 entries. Because `level == 0` returns before
     the table is touched, only recipients with a genuinely stocked pool create
     entries — but the attacker can supply those itself: PUBLISH writes to the
     slot of the handshake-authenticated NodeId and never parses the blob, so
     4096 minted NodeIds each stocked with junk blobs will do. **No third
     party's prekeys are consumed**, only the victim's own.
   - **What it bought was the removal of the refill race the reserve exists to
     win.** After a prune the mark re-derived from the drawn-down level `L` and
     the floor became `L/4`, so the pool could be walked down in ungated stages:
     100 → 25 → 6 → 1 → 0 in three prunes, 256 → 64 → 16 → 4 → 1 → 0 in four.
     No token spent and no waiting at any stage. `retain` also drops *every*
     full-bucket entry, not just the victim's, so one round flushed the marks of
     every recipient not currently being drawn below its floor.

   With the mark in the store, a prune cannot reach it, and pruning a *bucket*
   buys an attacker nothing at all: the prune's test is `is_full_at`, and a full
   bucket holds exactly the eight tokens the fresh bucket replacing it would,
   while a bucket with tokens spent is not full and so cannot be pruned before
   the refill it is enforcing has already elapsed.

   **A pool that predates the record is anchored on its first draw**, at the
   level standing before that draw pops anything
   (`RedbInboxStore::prekey_level_and_mark`). This is not a nicety — without it
   the fix would have covered nothing on the day a relay upgrades: every
   existing pool would have carried no mark, fallen back to a level held in the
   prunable table, and the whole attack above would have stood untouched until
   each owner happened to republish, which is an operator-scheduled `maintain`
   run and so unbounded in practice. The anchored value is exactly the one the
   old code derived on a first draw, so no honest sender is turned away; what
   changed is that it is now durable, and only PUBLISH can move it afterwards.

   Regression tests: `a_forced_prune_cannot_collapse_a_victims_reserve_floor`
   runs the whole sequence (drain to the floor, flood the table with 4096
   attacker-stocked recipients, draw again) against a marked pool,
   `a_forced_prune_cannot_collapse_an_unmarked_pools_floor` runs it against the
   pre-record shape, and `a_restart_does_not_re_anchor_the_floor_to_a_drained_pool`
   plus `an_anchored_pool_keeps_its_floor_across_a_restart_and_a_republish`
   cover the process-local half.

   The update rule is **replace, not high-water**: the mark becomes whatever the
   PUBLISH left in the slot, counted inside the same write transaction. A mark
   that only rose would hold a floor against a pool the recipient no longer
   keeps — a peer dropping from 256 prekeys to 10 would sit permanently under a
   floor of 64, with every draw inside the band and honest senders throttled to
   one prekey per 30 s forever. Replacing keeps the invariant that matters: right
   after a PUBLISH the level equals the mark, so three quarters of the freshly
   stocked pool is always drawn ungated. It concedes nothing to the attacker,
   because a fetcher cannot *change* the mark — the slot is keyed on the
   handshake-authenticated NodeId, and the draw path's one write only ever
   creates a mark that is absent, never overwrites one that is there.

   Four residuals stand:
   - **An attacker holding 4096 *distinct* pools below their floors at once**
     — each at the sustained below-floor cost — keeps the reserve table full,
     and a recipient first drawn from while it is full goes untracked, hence
     ungated, until room appears. Unchanged by the persistence fix: the floor is
     known for such a recipient, but there is nowhere to put the bucket that
     would charge it, and the admission rule fails **open** deliberately
     (`REPLY_RATE_LIMITED` is a downgrade lever to `one_shot`, not a retry
     signal, so refusing untracked callers would be worse than serving them).
   - **A pool anchored on its first draw is anchored at whatever it then holds.**
     If it had already been drawn down before the relay upgraded, the anchor is
     the drained level rather than what its owner stocked — that information was
     process-local and did not survive. One-time and not repeatable (the mark is
     created once, and only PUBLISH moves it afterwards), no worse than what a
     restart did under the old code, and corrected by the owner's next PUBLISH.
   - **A drain that lands inside the window between a recipient's COUNT and its
     PUBLISH lowers the mark that PUBLISH records**, since the recipient tops up
     by the deficit COUNT reported. It buys little: the attacker must draw those
     keys at the ungated rate it already had, the effect is `mark = target - d`
     for `d` keys drawn in that window, it does not accumulate across rounds
     (the next clean replenishment restores the mark), and unlike the prune it
     cannot be fired on demand.
   - **~43 B of meta row per recipient that has ever published**, never removed.
     Uncounted by any budget, like the per-depositor ledger rows beside it, and
     dwarfed by the ~4.5 KB prekey blob a PUBLISH must store to create one.
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

    Three growth vectors the budgets deliberately do not count, listed so a
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
    - **~43 B per recipient that has ever published a prekey**: the stocking
      marks in the same table (item 3). Unlike the ledger rows these are never
      removed, so they are bounded by identities rather than by live state — but
      creating one requires storing at least one prekey blob (~4.5 KB), so they
      cannot be the cheapest way to grow this file.

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
      epoch until someone asks for the delta by hand:

          nk-crypto-tool --mls-cmd resync --mls-group-id <hex> \
              --mls-recipient-ticket <peer-ticket>

      or `/resync [ticket]` inside `--mls-cmd listen`, which is where an
      operator actually notices the group has gone quiet. **The two forms ask
      different sets, and neither set is "this group's members" as such:**
        - `--mls-cmd resync` takes **at most one** `--mls-recipient-ticket` and
          refuses a longer list before it dials anything (why, below). With no
          ticket it asks the group's remembered member addresses —
          `known_member_addrs`, i.e. the stored address book filtered against
          this group's live roster — and **all** of them.
        - `/resync <ticket>` asks that one peer. `/resync` with no argument asks
          the **listener's recipient list**, which is not this group's roster: it
          is whatever `resolve_recipients` produced at startup plus every address
          `/peer` has added since, shared across every group the session
          addresses. So it sends `SYNC` — the group id and our current epoch — to
          peers `known_member_addrs` would have filtered out, including addresses
          no roster lists at all.
      The request carries the caller's *own* current epoch, so it fetches
      exactly the delta it is missing and is a no-op when current — it is not
      clamped out of its own history by the change above. Recovery is **not
      automatic** on this path: nothing polls, so a member stays behind until
      someone runs it.
    - **What a resync can and cannot tell you.** `request_resync` dials a
      `PeerAddr` and reads whatever comes back. **Nothing in that exchange
      authenticates the responder** — not its membership, not its epoch, not its
      view of the roster, not even that it runs this software. So the command
      reports three different kinds of thing, and keeps them apart:
        - *Facts about our own state.* The epoch before and after, read from our
          own group state, re-read after the sweep (so a stream that applied a
          genuine Commit and then broke is reported as the progress it made),
          and per peer whether our epoch was higher after its exchange than
          before it. That per-peer flag is a **window, not causation** — a
          listener applies inbound Commits on another task — and the line says
          "our epoch advanced while asking" rather than crediting the peer with
          the Commits. It is measured on our own epoch precisely because
          `request_resync`'s own "I applied something" return is `true` for the
          Commit that removes us, which moves that epoch nowhere: crediting the
          peer on it printed "Commits came from X" directly under "our epoch did
          not move". Also here: the node ids this group's roster listed when the
          sweep started and does not list when it ended, named in hex. That is
          two reads of our own roster and no more — it does not say the group
          removed them (a roster node id is written by the member it describes),
          and nothing in the sweep acts on it; it is reported because the address
          an operator dials next is usually one held as a ticket rather than one
          this sweep had queued, so `skipped` alone left it unmentioned.
        - *One thing measured about the responder.* If a peer's stream carried a
          Commit removing **us**, mls-rs verified that Commit against our own
          group state — which establishes that its signer held this group's state
          at the epoch we are at, and **not** that we are out of the group. A
          member the group evicted at a later epoch, one we have not applied,
          still holds exactly that state and can sign a Remove of us that
          verifies here while every honest member's roster still lists us (there
          is a test that does it). "Verified" is also weaker on this Commit than
          on any other: mls-rs 0.55.2 gates `update_key_schedule` on
          `!is_self_removed` and recomputes the confirmation tag only inside it,
          so on a Commit that removes us the tag must be *present* and is never
          checked against the transcript we would have derived. Applying **that
          Commit** changes nothing here: mls-rs skips `update_key_schedule` for a
          self-removal and drops the provisional state, so it leaves our epoch,
          tree and roster as it found them and a later honest delta applies
          normally. The rendered line is scoped to that Commit, because the rest
          of the same stream was applied and persisted before it — a responder
          streaming `[Remove(someone else), Remove(us)]` really does advance our
          epoch and shorten our roster, and the epoch line is where that shows.
          What the event *is* good for is weighing the peer — a responder streams
          history only to a caller its **current** roster lists, and answers
          `ERR\x01` otherwise, so one whose roster reflected this Commit would
          have refused — and that is short of a verdict, so the line stops at
          "ask another peer". An honest responder produces the same event where
          it recorded no join epoch for us (`member_join_epoch` `None`
          deliberately does not clamp): having removed us and re-admitted us at
          an epoch we never applied, its roster lists us again and it serves the
          old Remove out of retained history. It carries
          **no re-admission advice and names no command**: `join_group_from_welcome`
          refuses a Welcome for a gid we already hold, so the only Welcome that
          could be accepted is one for a *different* group, from whoever connects
          first — the same steer that was taken off the `ERR\x01` path.
        - *One peer's claim.* Whatever each responder said, attributed to it by
          node id and marked unverified. The two protocol rejections are told
          apart by `GroupError` variant carried from the `ERR\x01`/`ERR\x02`
          wire codes, never by substring on the rendered error — a peer chooses
          the QUIC close reason that lands inside `Transport(Connect(..))`, so
          text matching let any failure be dressed as either rejection. What the
          variant establishes is that the responder sent those four bytes, and
          nothing more.
      There is deliberately **no "you are up to date"** anywhere in the output,
      and no recommendation to take a fresh invitation. Both were previously
      reachable from four attacker-chosen bytes: `OK\x00\x00` then close made
      the caller announce currency (to, of all people, a member that had just
      been evicted and was asking why the group went quiet), and `ERR\x01`
      pointed the operator at `--mls-cmd accept-one`, which is `accept_next`
      with no sender check, so whoever answered next would have been the
      inviter. For the same reason a multi-peer sweep asks **every** peer instead
      of stopping at the first that answers: one peer must not be able to end it
      by saying nothing, and `known_member_addrs` returns redb key order, which is
      node-id byte order and therefore grindable for first place. "Every" means
      every peer still on the list when its turn comes: the sweep applies
      Commits into our own state as it runs, so after any peer that moved us it
      re-derives its own tail — through `prune_departed_recipients` in the
      listener, through `known_member_addrs` on the one-shot path — and stops
      dialling whoever that dropped. Without it the sweep would ask Alice, apply
      her Remove of Carol, and then dial Carol, handing a member we have just
      watched being evicted our liveness, our network path, the group id and our
      post-eviction epoch (the SYNC request carries it in clear). The count of
      peers dropped this way is reported, so "asked N peer(s)" is never quietly
      smaller than the list it started from — and the line says only that this
      group's roster no longer lists them, not which Commit took them off it: on
      the listener path the drop is `prune_departed_recipients`' decision, and
      its baseline moves on the inbound task too.
    - **Why `--mls-cmd resync` takes at most one `--mls-recipient-ticket`.** A
      list on this subcommand hands the first peer asked a say over the rest.
      `request_resync` applies and persists every Commit a responder streams once
      mls-rs verifies it against our own — possibly stale — state, and one Commit
      can remove several leaves, so a responder can serve a Remove of the other
      named peers and either draw a dial to a member we have just watched being
      evicted or take them out of the queue, depending on how the tail is
      re-derived. Both are the responder's choice rather than the operator's, and
      the second is worse than it looks: the peer excised is exactly the one
      whose answer would have contradicted the first, and its absence is rendered
      as a departure. One peer per invocation leaves no queue for an answer to act
      on; a second peer is a second command, which starts from our state as the
      first left it and whose disagreement the operator can see. The flag itself
      stays a `Vec` — the send subcommands use it as one — so the restriction is
      `resync`'s alone, and the single ticket is still **not** put through the
      roster filter: an explicit ticket exists to reach a peer no group vouches
      for, and that bypass is kept (there is a test).
    - **What a resync still cannot defend against.** A peer that answers is
      trusted for the Commits it streams to the extent mls-rs verifies them, and
      it can stop early; a legitimate but partial catch-up and a deliberate one
      look the same. This is the same exposure the direct-receive path already
      has (`process_mls_bytes` applies any Commit any connecting peer pushes),
      so the pull adds no new way for a peer to move our own group state — what
      it does add is the sweep, which is the rest of this bullet — but it means
      "no peer sent us anything" is a statement about the peers reached, never
      about the group.
      **The one-ticket rule above is narrower than it may read: it removes a
      responder's say over the sweep only from the list an operator typed on one
      invocation, and the same lever is still there on both multi-peer forms.**
      `--mls-cmd resync` with no ticket walks `known_member_addrs` and `/resync`
      with no argument walks the listener's recipient list, and in both the tail
      is re-derived against *our own* roster as the responders being asked have
      just moved it — so a responder that streams a Remove of a queued peer still
      decides that peer is not asked. **That composition is introduced here, and
      an earlier draft of this entry was wrong to call it pre-existing.** Both
      halves of it are in the base: `known_member_addrs` filtering the stored
      address book against our own possibly-stale roster is base code, and so is
      `prune_departed_recipients`. What the base does not have is a caller — at
      `ba6f9f68` `request_resync` has none outside the test module, which is the
      gap this patch closes — so there was no sweep, no queue of peers waiting to
      be asked, and nothing for one responder's Commits to steer. The loop that
      walks such a queue while applying what the peer at its head streams is
      added here, and it is what turns a filter that was merely stale into one a
      responder can move on purpose.
      What bounds it is well short of a fix. The lever needs a Commit mls-rs
      verifies against our own state, so it is open to a node that holds this
      group's state at our epoch — a member, or one the group evicted at an epoch
      we have not applied — rather than to any node that answers a dial. It
      reaches one invocation: a resync reads history and writes no address-book
      row (`remember_member_tickets` is not called on this path), so the next
      sweep resolves `known_member_addrs` from the same stored book, and what
      carries over is the roster change, which is the Commit's doing rather than
      the sweep's. And the excision is no longer silent — the node ids this
      group's roster listed when a sweep started and does not list when it ended
      are named in the report, on every form — so a peer dropped this way is one
      the operator can go and ask on its own single-ticket invocation, which is
      the form the roster filter is deliberately not applied to. Seeing it is not
      the same as being protected from it, and this entry claims no more.
      The roster all of this is measured against does not
      authenticate the node ids it carries — `peer_id_from_credential` reads a
      self-asserted field, so a member can seat a leaf claiming an arbitrary node
      id and remove it to synthesise a departure. That is **item 12** below,
      recorded there against the session recipient list; a resync sweep is a
      second surface for it, and closing either needs the authenticated identity
      at the prune site that item 12's "why it is not fixed here" describes.
      Read "N queued peer(s) were not asked", and the node ids named alongside
      it, as something a responder may have caused.
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

12. **A group member can synthesise a departure and silently drop a recipient
    from a running session** (`group/cli.rs`, `group/processor.rs`, 2026-08): a
    chat/listen session prunes its in-memory recipient list when a group's epoch
    advances, by diffing the roster it last saw against the current one
    (`prune_departed_recipients`). Both sides of that diff are transport node
    ids read straight out of each member's own credential by
    `peer_id_from_credential`, and **nothing ties that field to the node key it
    names**: `verify_binding` covers `peer_id` with the member's own MLS and
    ML-DSA-65 signatures, which proves possession of those two keys and not of
    the iroh node key being claimed, so a self-consistent credential naming any
    32-byte id verifies. `current_member_node_ids` does not even check the
    binding, and checking it would not close this. A current member of a group
    the session tracks can therefore Add a leaf whose NKCB credential claims an
    arbitrary node id and then Remove it: the session watches that id join the
    roster and leave it, and drops the matching address from the list it is
    delivering to.
    - **What it costs the victim**: silent, targeted loss of delivery for the
      rest of the session, chosen by the attacker. The REPL keeps echoing
      `[me] …` because a fan-out to a shortened list returns `Ok`, and the only
      notice is a `[mls] dropped N recipient(s) …` line carrying a count, not an
      identity. It ends at the next restart, which re-resolves the list from the
      address book; nothing on disk is changed.
    - **What it still reaches, and who the realistic victims are**: every
      address that no operator-selected group carries. That is precisely the
      **operator-typed `/peer` and `--mls-recipient-ticket` addresses**, which
      `resolve_recipients` passes through unfiltered by design and which no
      roster lists at all — they can be dropped by a Commit in a group they have
      nothing to do with. A peer that shares exactly one group with the session
      is equally exposed, though there the attacker is a fellow member who could
      usually have removed that peer outright.
    - **What bounds it**: the prune is scoped to the group whose epoch advanced
      (2026-08), so an address that another group **the operator selected** —
      `--mls-group-id`, `chat-group`'s gid, or a `/gid` typed into the REPL —
      still lists on its live roster is kept instead of dropped. Groups the
      session merely joined may not vouch: `join_group_from_welcome` authorizes
      no sender and is reachable unauthenticated over `nkct/mls/1`, so allowing
      them would let any peer holding this node's ticket pin an address of its
      choosing against an authenticated Remove. The attacker must also be a
      member of the group that is the session's **active** send target, since
      the prune runs only for the active gid. One path does open that position
      to a stranger: `adopt_new_group` adopts an inbound Welcome's group when
      the session has no active group yet, which makes that Welcome's author a
      fellow member of the then-active group. A session started with
      `--mls-group-id`, or one that has already adopted, refuses the
      displacement and is not reachable that way.
    - **The mirror image, and inseparable from the bound above**: the same
      unauthenticated `peer_id` makes the *keep* direction forgeable too. A
      member of a group the operator selected can Add a leaf whose credential
      claims an arbitrary node id and simply leave it on the roster; that id is
      then exempt from every later prune, so its address stays in the session's
      recipient list against an authenticated Remove Commit in another group,
      for as long as the session runs. The party who can do that is narrower
      than the drop direction's — not any peer holding this node's ticket, since
      a group that merely arrived by Welcome may not vouch, but a current member
      of a group whose id the operator typed, someone the operator already
      addresses and already delivers that group's traffic to. It is not an
      oversight in the scope fix; it is the cost of having one. Keeping an
      address means *some* selected group still lists it — and that is checked
      afresh on every later epoch change of the group the peer left, because a
      kept id stays in that group's baseline as a departure candidate instead of
      being written out of it. So the keep lasts until the vouching group stops
      listing the leaf **and** the group the peer left next changes epoch; that
      second condition may not arrive at all in a session whose active group is
      quiet, though the peer can neither cause nor suppress it once she is out of
      that group. What no roster can do is prove the node id it lists, which is
      the whole of this item. It ends where the drop direction does: at restart,
      which re-resolves the list.
    - **Why it is not fixed here**: the prune site has no authenticated identity
      to key on. A `PeerAddr` — the only thing the recipient list holds — carries
      a node id and nothing else, and every ticket on the MLS path is minted as
      `Ticket::new(addr, None, None)` (`cli::print_local_address`, `ffi.rs`), so
      the `pqc_sign_fp` field is zero and there is nothing for a roster
      fingerprint to be compared against. Keying the prune on the transport
      fingerprint, the way `projected_member_fingerprints` keys the shell /
      port-forward allowlist — where the binding really does prove possession of
      the key being fingerprinted — therefore needs one of two larger changes:
      binding `peer_id` in the credential so it cannot be self-asserted (a
      credential-format change with the same flag-day migration as item 11's
      control-message encryption), or plumbing fingerprints through `PeerAddr`
      and every ticket producer and consumer. Both were judged larger than this
      finding and are deliberately not taken here.

(Several other audit findings — the ECDSA verify bug, network-receive release
of unverified plaintext, the `Ticket::from_str` DoS, plaintext ECC keys, and
the weak PBKDF2 iteration count — were fixed; see the git history.)


