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
     slot of the handshake-authenticated NodeId and does not parse the blob, so
     4096 minted NodeIds each stocked with junk blobs will do. **No third
     party's prekeys are consumed**, only the victim's own. Junk still works;
     what changed in 2026-08 is that it is no longer free — see the size floor
     under the first residual below.
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

   **This fix is itself the cause of an open MEDIUM finding**
   (`CLAUDE-SECURITY-20260821-233021`, F5 — unfixed, no patch attempted yet).
   `prekey_level_and_mark` is called from `draw_prekey` while the
   process-global `prekey_reserve` `std::sync::Mutex` is held, and it may open a
   redb *write* transaction and commit; `fetch_prekey`, also inside that
   section, always does. Two durable commits therefore run under a blocking
   mutex on a tokio worker, driven by an **unauthenticated** FETCH — so a flood
   stalls the whole relay: group delivery, Welcome delivery and prekey
   publication all stop for its duration. The suggested repair is to run the
   critical section off the async workers.

   It is worth being plain about the sequence, because it is the third time in
   this engagement that a repair became the next round's finding: this residual
   was written to record a defence added in 2026-08, and the audit of that same
   2026-08 range found the defence's own new call the cause of a relay stall.
   Adding a mechanism has a cost that is not visible from the finding it closes.

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
     and a recipient drawn from while it is full goes untracked, hence ungated,
     for as long as it stays that way (no entry is inserted on that path, so
     this is not limited to the recipient's first draw). Unchanged by the
     persistence fix and **still open**: the floor is known for such a
     recipient, but there is nowhere to put the bucket that would charge it,
     and the admission rule fails **open** deliberately
     (`REPLY_RATE_LIMITED` is a downgrade lever to `one_shot`, not a retry
     signal, so refusing untracked callers would be worse than serving them).

     What changed in 2026-08 is the **price**, not the escape. PUBLISH now
     admits a blob only from `MIN_PREKEY_BLOB` = 1 KiB up
     (`network/inbox.rs`), where it previously took any byte string of 1 byte
     and up. It still does not parse, verify or interpret a blob — it compares
     a length it has already read, and junk of an admissible size is stored and
     served exactly as before, so this establishes nothing about whether a
     stored blob is a real prekey. What it prices is the flood: an entry
     survives the prune only while its bucket is off full, only a draw at or
     below the floor charges one, and a pool of fewer than
     `PREKEY_RESERVE_DIVISOR` prekeys has a floor of 0 by integer division and
     is never charged at all — so a slot costs a pool of at least four prekeys,
     republished and drained about once per 30 s
     (`an_unprunable_reserve_entry_costs_a_pool_of_four` pins that boundary;
     the 30 s is `RESERVE_RL_REFILL_PER_SEC` arithmetic, not a test). Stocking
     more scales the hold and the price together at the same four-per-30 s
     rate, until the pool outgrows what the eight-token bucket can absorb.
     Across 4096 slots that cheapest rate is ~546 prekeys published per
     second: **~3.3 KiB/s of PUBLISH frames before the floor, ~549 KiB/s
     after**. The ~683 connections per second it also takes are unchanged, and
     an attacker willing to pay the bytes still opens the escape — a size
     floor buys bytes and nothing else. Those bytes are counted now
     (`META_PREKEY_BYTES`, item 10), but counting is all that happens to them:
     nothing refuses a PUBLISH, and at 4096 slots holding four 1 KiB prekeys
     each — ~17 MiB — this escape would not even reach the 256 MiB watermark
     that would tell the operator about it.

     The floor is deliberately *not* the 4537 B the current encoding produces.
     A relay that validated the wire format would become a version gate on an
     operation with no negotiation, and the failure mode of that gate is the
     downgrade this whole mechanism exists to prevent: a recipient whose
     PUBLISH is refused (`--prekey-cmd publish` / `maintain` exit non-zero)
     stops replenishing, its pool empties, and its senders fall back to
     `MODE_STATIC_ONLY`. 1 KiB sits below any encoding that carries a
     post-quantum KEM public key together with a post-quantum signature over
     it — the smallest FIPS 203 encapsulation key is 800 B (ML-KEM-512) and the
     most compact signature among NIST's selected PQ schemes is several hundred
     bytes more — and every plausible change to the format (larger KEM, larger
     signature) moves further above the floor.
     `a_real_signed_prekey_clears_the_size_floor` pins the current encoding
     against it.
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
     Uncounted by any budget, like the per-depositor ledger rows beside it. The
     PUBLISH that creates one has to store at least `MIN_PREKEY_BLOB` = 1 KiB
     (~4.5 KB for a real prekey) and is charged that against the prekey meter
     — but the publisher can then FETCH its own prekey away, which refunds the
     charge and leaves the row, so the blob is a deposit returned rather than a
     price paid. A `TBL_CHECKPOINT` row is cheaper still, at a 9-byte frame and
     no stored bytes, so this is not the cheapest way to leave an uncounted row
     per identity.
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
    - **Operator note**: the 1 GiB budget above bounds *envelope* bytes. It is
      not a bound on the size of this file: prekey rows are counted but **not**
      bounded (see the sub-item below), and the rows listed under "growth
      vectors" are neither. Provision for the envelope budget plus however much
      prekey storage you are willing to serve, plus redb's overhead. Nothing
      shrinks the file once it has grown: `Database::compact` is called on the
      node-local `RedbPrekeyStore` and not on `RedbInboxStore`, so what the
      envelope budget bounds is a high-water mark, and deleting rows does not
      give the space back to the filesystem. Run a relay for correspondents you
      are willing to serve; there is no way to tell a fleet from a crowd here.
    - **PUBLISH is metered and reported, not bounded** (`META_PREKEY_BYTES` +
      `PREKEY_BYTES_WARN_AT`, 2026-08). Prekey rows used to sit outside every
      storage defence the relay had *and* outside every count:
      `publish_prekeys` touched no ledger, neither sweep walks `TBL_PREKEY`, and
      the `created_at` it seals into every row is read by nothing, so there is
      no prekey TTL. A slot is capped at 256 rows, but the slot key is the
      handshake NodeId — free to mint — so **2 MiB of permanent relay disk per
      minted identity**, in two connections.
      What the 2026-08 change adds is accounting and a report, nothing else:
      those bytes are counted per row (refunded on the two paths that remove a
      row — a FETCH of it, and the row-cap eviction in `publish_prekeys`; no
      other code path removes one), and crossing a watermark prints one line per
      60 s on the operator's stderr carrying the total and the number of
      crossings it suppressed. **No PUBLISH is refused, and nothing about this
      slows an attacker down.**
      - **The residual, unchanged and open**: an unauthenticated flood can still
        fill the relay's disk, at 1:1 bandwidth cost (2 MiB per identity, ~8 KiB
        per row), and the bytes are permanent in practice — nothing expires
        them, and the two ways a prekey row leaves are a FETCH of that row and
        its owner republishing over it. An attacker has no reason to do either
        to its own pools, and nobody else can do it for them: FETCH needs the
        slot's NodeId, and what the relay stores is a blind index of it, so an
        operator holding the database cannot enumerate the minted slots to drain
        them. When the filesystem fills, every path that takes a write
        transaction fails (DEPOSIT, PUBLISH, FETCH, CHECKPOINT; POLL reads and
        would survive), and there is no recovery from inside the relay short of
        replacing the database.
      - **What the operator can actually do: notice, and intervene from
        outside.** There is no remedy inside the relay — no publisher
        allowlist, no prekey TTL, no sweep over `TBL_PREKEY`, and no compaction
        of this database. The available moves are to restrict who can reach the
        relay at a lower layer (do not hand out the node ticket; firewall it) or
        to stop the relay and replace `inbox.db`, which discards every stored
        envelope and every honest prekey pool with the flood's rows. The
        watermark line exists to make that decision possible before the disk
        decides it; it is not a defence.
      - **A byte cap was implemented here and then deliberately removed**
        (2026-08, same review). Refusing a PUBLISH past a 1 GiB prekey cap
        turned out to hand an attacker something worse than the disk: publish
        ~1 GiB across ~508 minted identities and **every** later PUBLISH on the
        relay is refused, honest recipients' included. Their pools then drain
        through FETCH — which any unauthenticated caller can drive — and can
        never be replenished, so every sender to every recipient on that relay
        seals `MODE_STATIC_ONLY`: a permanent, relay-wide post-quantum
        forward-secrecy downgrade, invisible to the senders it hits, for the
        price of the upload. It was also self-funding, since each prekey a
        victim served freed exactly the space the attacker needed to re-take,
        and self-sustaining, since the flood's own rows are never fetched. A
        full disk is the lesser harm: it is loud, and the operator can act on
        it.
      - **Why prekey bytes are not charged to the envelope budget**: that budget
        *is* enforced, so a PUBLISH flood spending it would make `deposit_in`'s
        global check refuse every depositor — the outcome this item is about,
        reached by a cheaper route. Prekey bytes also have no expiry to give
        them back, so a shared total would be pinned by them permanently.
        `inbox_prekey_flood_does_not_spend_the_envelope_budget` pins the
        separation. With the prekey cap gone, that budget is the one refusal a
        flood could still inflict on somebody else, which is what makes keeping
        the two counters apart worth a test.
      - **Why there is no prekey TTL**, though `created_at` is already stored
        for one: nothing in this tree republishes a pool on its own.
        `--prekey-cmd maintain` is a one-shot command the operator schedules,
        no timer or cron artifact ships here, and there is no low-water signal
        back to a pool's owner — the depleted FETCH is answered to the *sender*.
        A recipient that runs `init-identity` once and never returns would have
        its pool deleted on the clock, and every sender to it would then seal
        `MODE_STATIC_ONLY`: the relay would be destroying post-quantum forward
        secrecy on a timer, with no attacker involved, to bound bytes an
        attacker pays 1:1 in bandwidth for. Not taken.
      - **Where the watermark is set, and what it is worth**: 256 MiB, about
        58,000 real prekey rows — ~580 recipients stocked to the
        `--prekey-count` default of 100, or ~230 at the 256 maximum. Above the
        scale this relay is built for, so an honest deployment should not trip
        it, and well below the 1 GiB the operator already provisions for
        envelopes, so the line arrives with room left to act. It cannot tell a
        flood from a relay that simply grew, and the line says so; an operator
        whose relay legitimately holds this much has also outgrown the
        documented provisioning and is the right person to hear about it. The
        line itself is rate-gated exactly as the accept-failure line is
        (`ACCEPT_ERROR_LOG_INTERVAL`), because PUBLISH is remotely triggerable
        and a line per crossing would be an unbounded write to the operator's
        log.
      - **Residual: the watermark line can be buried in operator-log noise an
        attacker chooses** — **CLOSED 2026-08-19.** Both lines now have gates of
        their own (`PEER_LOG_INTERVAL`, one `LogGate` instance each), and the
        relay's own failures are routed around them. The analysis below is kept
        because the fix came out of it — **with one correction, which is the
        useful part**: it says to route `Storage` *and `Io`* around the gate.
        `Io` belongs on the gated side. Nothing on the production path constructs
        one — the module's only explicit construction is in the test that pins
        this classification; it arrives via `#[from] std::io::Error`, and on
        the server path the only sources are the 31 `read_timed`/`write_timed`
        calls against the peer's own stream — so a peer produces one by
        resetting a connection, as cheaply as a `Protocol`. Ungating it would
        have reopened the hole through a different variant. Pinned by
        `io_errors_are_peer_caused_and_therefore_gated`.

        Two further departures from the plan below. Sanitizing was called "a
        separate question, and the answer today is no"; the answer is now yes,
        because that argument has to be re-made for every variant that reaches
        the line and `Io` carries an OS-formatted string this module did not
        write. And both arms moved out of `run()` into
        `report_setup_failure_at` / `report_handle_error_at`, so a test can
        drive the server's real gates — a test over two locally-constructed
        `LogGate`s would pass even if `run()` shared one, which is the bug.

        The ungated branch has a residual of its own, stated rather than
        implied: on a persistent fault (a full disk) the relay writes one line
        per affected connection, unbounded. That is the deliberate side of the
        trade — a rate on it would be a rate on the relay's own alarm — and a
        peer can only arrive while the condition holds, not cause it.

        The original analysis follows.
        The gate above bounds what the *watermark* writes — one line per 60 s,
        whatever else is happening — but two other lines on the same stderr are
        ungated and remotely triggerable, so a peer can push the watermark line
        off an operator's screen or out of a log tail at a volume of its own
        choosing. The noise does not stop the line being *written*: the
        watermark's gate is state of its own, and nothing on those two paths
        touches it (`prekey_warn` has exactly one non-test reader,
        `note_prekey_bytes`), so however many of those two lines are written the
        watermark's own gate is unmoved, it still carries its own
        suppressed-count, and a `grep` for it still finds it. What the noise
        costs is the chance an operator *reads* it.

        Two things do stop the line, and neither is the noise itself. The disk
        actually filling: `note_prekey_bytes` runs after
        `publish_prekeys(..)?`, so a failing PUBLISH returns before the report.
        And connection starvation: the permit at `InboxServer::run` is taken
        before the spawn and held for the connection's life, so peers that hold
        all `MAX_CONCURRENT_CONNECTIONS` of them stalled in `establish` park the
        accept loop and no PUBLISH is dispatched to fire the watermark at all.
        That is pre-existing and documented at the semaphore, but it is the same
        flood: an attacker generating the noise can also starve the line it
        would bury. Read "the gate is unmoved" as a statement about the gate,
        not a promise that the line arrives.
        The two paths, in `network/inbox.rs`'s accept loop:
        - `eprintln!("[inbox] connection setup failed or timed out")`, on any
          `P2pPending::establish` failure. **The cheaper of the two**: in the
          iroh backend an ALPN outside the endpoint's set fails before the QUIC
          handshake even completes, and a peer that completes the handshake and
          never opens a bi-stream fails at `accept_bi`. Neither needs a byte of
          protocol.
        - `eprintln!("[inbox] handle error: {e}")`, on any `Err` from `handle`.
          Dearer: it needs a completed handshake *plus* `accept_bi` *plus* one
          byte the dispatcher rejects. Pre-existing and prekey-independent —
          this line predates prekeys entirely.

        A gate over the second line was written during the 2026-08 change and
        **removed on review, because a single shared gate is the wrong shape**.
        `handle` returns `Protocol` / `Timeout` / `TooLarge`, which are cheap
        and attacker-chosen, *and* `Storage`, which is the relay reporting its
        own failure — `No space left on device` among them. One content-blind
        gate mixes the two, so an attacker that claims each 60 s window with a
        malformed frame suppresses the text of every storage error behind it.
        That would be a capability an unauthenticated peer does not have today,
        bought for one byte per minute, and it compounds with the parenthesis
        above: on a full disk the watermark has already stopped firing, so the
        handler-error line is the relay's last self-report at exactly the moment
        the shared gate would hand it to the attacker. A probe of the rejected
        version measured it — one 0x7f per window, 501 `No space left on device`
        errors behind it, zero of them printed. Whoever picks this up should
        gate both lines and route `Storage` (and `Io`) around the gate, or give
        it a gate of its own, the way `run()` already routes `P2pError::Closed`
        around the accept-error gate rather than counting it as noise.
        Sanitizing is a separate question and the
        answer today is no: the `establish` line interpolates nothing, and every
        `Protocol` message `handle` can produce is integers the server itself
        read.
      - **A pool at its row cap does not creep**: the eviction the row cap
        performs refunds in the same transaction as the charge, so a publisher
        already at 256 rows replacing them moves the meter by the difference in
        blob sizes and a steady-state `maintain` moves it by nothing. That
        matters for the report rather than for admission: a meter that drifted
        upward on rotation would eventually fire the watermark on a relay
        storing a constant number of rows, and a warning that cries wolf is one
        nobody reads.
      - **The meter under-reports on an upgraded relay**: prekey rows written
        before it existed are not counted, and nothing sweeps them, so the
        number in the warning line is a lower bound on what `TBL_PREKEY`
        actually occupies until those rows are fetched or republished over. It
        does not decay on a clock the way `EnvTs::cost`'s upgrade allowance
        does.

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

    Growth vectors the envelope budget does not count, listed so a capacity plan
    does not miss them. The largest by far is the prekey blobs themselves — 2 MiB
    of permanent storage per minted identity — which are now *counted* and
    reported past a watermark but, as the sub-item above says, still bounded by
    nothing. The rest are small, but they are small per *identity*, and
    identities are free:
    - **~90 B per envelope on upgrade**: `EnvTs::cost` charges an
      upgrade-stamped row only for the envelope that was already there, not for
      the index row it adds (`ENV_TS_ROW_BYTES`). Charging it would push a store
      that was exactly healthy under the old cap over the new budget on first
      open and refuse every deposit until the sweep caught up. So a large legacy
      inbox exceeds the 1 GiB bound by about 90 B per stored envelope; it
      decays to zero one TTL window after the upgrade.
    - **Every prekey row written before the prekey meter existed**: uncounted
      for the same reason, and never decaying, because nothing sweeps
      `TBL_PREKEY` — a row leaves only when someone fetches it or its owner
      republishes over it. Nothing is refused on the meter, so this costs no
      admission; what it costs is accuracy, and the warning line under-reports
      the table by exactly those rows.
    - **~43 B per active depositor**: the per-depositor ledger rows in
      `TBL_META` (35 B key + 8 B value) are themselves uncharged. Bounded by the
      number of depositors holding a live backlog, and a row is dropped as soon
      as its balance reaches zero.
    - **~43 B per recipient that has ever published a prekey**: the stocking
      marks in the same table (item 3). Unlike the ledger rows these are never
      removed, so they are bounded by identities rather than by live state. The
      blob that creates one is floored at `MIN_PREKEY_BLOB` and charged to the
      prekey meter, but the publisher can FETCH its own prekey straight back —
      which refunds the meter and leaves this row — so treat the blob as a
      deposit returned rather than a price paid. A `TBL_CHECKPOINT` row is
      cheaper still, at a 9-byte frame and no stored bytes, so this is not the
      cheapest way to leave an uncounted row per identity.
    - **The prekey rows' own keys** (40 B each: blind index + id) and redb's
      per-page overhead. The prekey meter counts sealed *values*, the way the
      envelope ledger counts `sealed_len`, so the file runs above both figures
      by a per-row constant.

11. **Control-frame confidentiality is a property of the sender, so a group's
    Commits are only as private as its least-upgraded committer**
    (`group/processor.rs`, `group/transport.rs`, 2026-08):
    `GroupChatProcessor::new` calls `.mls_rules(mls_rules())` with
    `encrypt_control_messages = true`, so mls-rs's `control_wire_format`
    returns `PrivateMessage` for a member-sent Commit or standalone Proposal
    (mls-rs 0.55.2, `group/mls_rules.rs`). **Every Commit and standalone
    Proposal this build emits is therefore AEAD-sealed under the epoch key
    schedule** — where before it was a `WireFormat::PublicMessage`, signed and
    authenticated but readable by anyone holding the frame. "Every" is exact
    because `control_wire_format` keys on `Sender::Member(_)` and this crate
    builds control messages nowhere except `Group::commit_builder()` on a
    loaded group; there is no external-commit or `ExternalClient` path, and a
    future one would not inherit the setting. Application messages are
    unchanged: those were and remain `PrivateMessage`, as is a `Welcome`'s
    HPKE-wrapped GroupSecrets.

    **This does not close the leak for a group, and the entry stays open for
    that reason.** The wire format is decided where a Commit is *built*, by the
    node building it, so an admin still on an older build deposits its own Adds
    at the relay in the clear — same group, same day, nothing this node can do
    about it. A group's control traffic becomes confidential exactly when every
    member *that commits in it* has upgraded. That is monotone improvement with
    **no coordination point and no flag day** (below), but it is also not a
    deployment event: do not read this as "closed on release" or "closed by
    upgrading the relay."
    - **Why there is no flag day.** `EncryptionOptions` is read from three
      places in all of mls-rs 0.55.2 — `group/commit.rs:679`,
      `group/mod.rs:942`, `group/mod.rs:1525` — every one of them send-side,
      all via `Group::encryption_options()`. Nothing in `message_processor.rs`
      or `message_verifier.rs` reads it, `control_wire_format` or
      `encrypt_control_messages`, and `message_processor.rs` contains no
      `WireFormat` comparison at all: receive dispatch branches on the payload
      that arrived, gated only on the compile-time `private_message` feature,
      which both builds have (mls-rs's default `rfc_compliant` implies it). The
      one wire-format rejection on the receive path runs the other way — a
      *cleartext Application* message is refused. Probed in both directions
      with one side upgraded and the other not: an un-upgraded receiver applies
      our encrypted Add and Remove and lands on the same epoch and roster, and
      an un-upgraded sender's `PublicMessage` Commits are still applied by us.
    - **What a control frame still discloses.** The group id, the epoch and the
      content type are unencrypted fields of a `PrivateMessage` header (RFC 9420
      §6.3), as are the frame's size and its timing. What is now *inside* the
      seal is the committer's leaf index and the membership change itself: for
      an Add, the joining member's entire KeyPackage — the NKCB credential with
      its iroh NodeId, ML-DSA-65 transport public key and display name, plus the
      hybrid signature key; for a Remove, the evicted leaf index. Those
      transport keys are what `projected_member_fingerprints` turns into shell
      and port-forward authorization policy, which is what made this the sharp
      edge of the item. A party collecting frames from an upgraded sender now
      reads an activity timeline against a known group id, not the team's
      access list. Size is **not** part of that improvement, and one measurement
      should not be read as saying otherwise: `PaddingMode::StepFunction` —
      mls-rs's default, and already in force for application messages — pads the
      frame's *sealed content*, not the frame, rounding that content up to one of
      four buckets per octave (mls-rs's own comment: it "hides all but 2 most
      significant bits"; 4096 bytes wide around 24 KB). In one 3-member group an
      Add and a Remove happened to land in the same bucket, both arriving as
      24 672-byte frames — 24 576 bytes of padded content plus header and tag,
      which is why the figure is not itself a multiple of the bucket width. That
      does not generalise and
      was not designed to: a Commit carrying only Adds needs no UpdatePath
      (`CommitOptions::path_required` is `false`), a Commit containing a Remove
      must carry one (`path_update_required`), so the two are structurally
      different sizes, and the bucket widens with the frame. Treat a control
      frame's size as disclosed.
    - **Who receives one.** Two parties, and the second is why this mattered.
      The first is a peer we reach directly over authenticated QUIC, which is a
      *current group member* — already entitled to the current roster and every
      later epoch's membership data. The second is **the inbox relay operator,
      who is not a member**. When a recipient is not reachable inside
      `DIRECT_CONNECT_TIMEOUT` (5 s), `send_one_with_inbox` deposits the frame
      at the operator-configured relay, and that is the ordinary
      offline-delivery case the feature exists for rather than an edge. From an
      upgraded sender the operator now holds a ciphertext plus the header fields
      above. From a peer that has not upgraded it still reconstructs the group's
      membership graph, every member's iroh NodeId and ML-DSA-65 transport key,
      and the timeline of who joined and who was evicted. Configuring
      `--inbox-url` is what puts any of it in front of a non-member; running
      without a relay confines control frames to member-to-member QUIC.
    - **What encrypting cost.** These are figures from a one-off investigation
      run taken to 12 members, not numbers the suite pins — nothing re-measures
      them. The largest Commit observed there was 41 056 bytes against
      `MAX_MLS_FRAME_BYTES` of 16 MiB (~400x margin), an overhead of roughly
      +5.5 % on an Add and +16 % on a Remove. Add commits do not grow with group
      size (`CommitOptions::path_required` is `false`); path-bearing Removes grow
      with tree depth. What the suite does pin is deliberately weaker:
      `commits_are_emitted_as_private_message` builds a 3-member group, *prints*
      each Commit's size and asserts only that it stays under a sixteenth of the
      frame cap — a guard against a Commit that stops fitting, not a check on
      those percentages. Storage needed nothing —
      `store_commit`/`load_commits` treat the frame as an opaque blob,
      and a `groups.db` holding a mixed `PublicMessage`/`PrivateMessage` history
      replays in sequence correctly, probed by upgrading a node in place
      mid-history and resyncing a never-upgraded peer across the seam.
    - **The SYNC clamp is a separate protection and is *not* subsumed by this.**
      The commit-history responder clamps a requester's `claimed_epoch` to the
      epoch at which this node witnessed that member being added, so a member
      cannot ask a peer for retained history predating its own admission. That
      is an **authorization** decision and the wire format does not touch it: a
      SYNC requester is a current member; retained history includes frames
      committed as `PublicMessage`, from before this change or from a peer
      without it; and a member removed and re-admitted holds the epoch secrets
      from its first stay while being recorded at its latest admission. Whether
      we serve a frame is this responder's decision, whether the requester could
      open it is not, and only the first is ours. It closes a member's *reach
      back*; it does nothing about the relay, which is handed frames unasked.
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
      than metadata disclosure to a relay the operator chose.
      **That reasoning never depended on the wire format, and encrypting
      control frames does not revive the refusal — it only makes it pointless
      as well as harmful.** Once control frames are `PrivateMessage`, relaying
      them is safe and the automatic path is safe with them. The refusal was
      withdrawn on *availability* grounds, so "the leak is smaller now" is not
      an argument for bringing it back, and neither is "some peers still send
      cleartext" — refusing those is the same stranded revocation with a
      narrower trigger.
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
      exactly the delta it is missing and is a no-op when current — the clamp
      above withholds history *predating* the caller's admission, which its own
      epoch is never below. The one case where a well-formed request still comes
      back empty is a responder that can vouch for no span of its own history
      (the history floor, below); there the answer is a fresh Welcome. Recovery
      is **not automatic** on this path: nothing polls, so a member stays behind
      until someone runs it.
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
          it does not clamp what it serves to our own admission — a peer older
          than the history floor below, where an unrecorded join epoch was
          served unclamped: having removed us and re-admitted us at
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
    - **What the SYNC clamp rests on when it does not know the requester.** A
      join epoch is recorded only when this node applies the Add commit itself
      (`record_witnessed_joins`, on the commit-build, direct-receive,
      resync-apply and remove paths), stored per (group, member) in the existing
      application-data KV. `None` means "unknown", and unknown is **not** an
      entitlement: it can mean a member already on the roster when we joined
      (harmless — our own history starts at our own join, at or after theirs), a
      database written before this record existed, or a record we failed to
      write. Nothing in a `None` tells those apart, so the responder falls back
      to a group-wide **history floor** (`GroupStorage::history_floor`): the
      exclusive bound of the epoch span in which our join records are complete.
      It is pinned at `epoch - 1` by the first commit this node applies once
      the record exists — *any* commit, an Add, a Remove or anything else, since
      what pins it is the fact that we now know who joined at that epoch, which
      a Remove settles as surely as an Add — and it is raised above
      any epoch whose join records we failed to write, so the span it claims is
      never stale. Above the floor "no record" demonstrably means "did not join
      here", so that span is served; a database that can vouch for no span at
      all serves an **empty delta** rather than the requester's own guess, and a
      storage error on either lookup is refused with `ERR\x02` rather than
      served unclamped. The decision is one pure function,
      `group::processor::sync_history_floor`.
    - **What that leaves: one availability residual, no disclosure.** A database
      written before this release, holding retained commits and having applied
      no commit since, has no floor — so a member it never witnessed joining
      gets an empty delta and has to take a fresh Welcome for that group. It
      self-heals at that node's very next applied commit, of any kind. It does
      not arise on a database created after this release: there the floor is
      pinned by the same commit that first retains history, so it sits below
      every epoch retained and the clamp does not bite an unrecorded member at
      all (barring a storage failure on the floor write, which is logged).
      Before this floor existed the same `None` was served unclamped, down to
      the oldest retained epoch — up to `DEFAULT_COMMIT_RETENTION` (100 epochs)
      of pre-admission Adds, each carrying a KeyPackage.
    - **What is left, and what would close it.** `encrypt_control_messages =
      true` is taken (`group::processor::mls_rules`), so what remains is not a
      code change in this repository: it is the population of peers. A group is
      clear of this item once every member that ever *commits* in it runs a
      build with that setting, and there is no way for one node to verify or
      enforce that — a `PublicMessage` Commit arriving from a peer is
      indistinguishable from one arriving from an old *release*, and refusing
      it is the withdrawn refusal above wearing a different hat. What an
      operator can do is upgrade the members who add and remove people (an Add
      is the frame that carries a KeyPackage), and treat `--inbox-url` as
      naming a party that sees the group's traffic pattern regardless. An
      earlier draft of this entry called the change a flag day requiring
      simultaneous adoption; that was **wrong and is withdrawn** — the two
      builds interoperate in both directions, as the first bullet records.

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
    - **What a keep can no longer do** (2026-08): the address it holds is not a
      delivery target of the group that removed the peer. Every read
      `listen_loop` makes of its one shared recipient list that becomes traffic
      **for a particular group** — the application message a typed line is
      encrypted into, the Commit `/add` broadcasts, the peers an argument-less
      `/resync` asks, and the tail the sweep re-derives between peers — goes
      through `cli::recipients_for_group`, which withholds the ids that group's
      own live roster no longer lists but this session's baseline for it still
      does. So a keep, forged or genuine, buys an address the **vouching**
      group's fan-out — the delivery that group was already making to it, and
      that another group's Commit had no standing to revoke — and buys the
      evicting group's fan-out nothing: no ciphertext, no dial, no timing, no
      size. That decision reads one group's baseline and that same group's live
      roster and nothing else, so no second group's membership can put an id
      into it or take one out of it, and nothing on it is a current member of
      the group being addressed. What a keep still buys is delivery from a group
      whose roster never listed the id at all — the position an operator-typed
      `/peer` or `--mls-recipient-ticket` address occupies, which is the drop
      direction's subject above rather than this one's.
    - **What the send scope does not announce.** The epoch-change notice reports
      a keep and says the kept address is no longer sent that group's messages,
      but the prune that emits it runs only for the group that is **active** at
      the time its epoch advances. A peer removed from a group that was not
      active is therefore withheld from that group's fan-out with no notice at
      all, the next time the operator makes it active and sends — provided this
      session had already taken a baseline for that group before the removal,
      since a first look can only record. That is the same authenticated Remove
      being honoured late rather than a new drop, and the address stays in the
      list for the other groups. Two more edges, both
      deliberate: because the scope is a difference against a baseline, an
      address this session watched leave a group stays withheld from that
      group's sends even if the operator re-types it with `/peer`, and
      `/status`'s `peers=` still counts the whole shared list rather than the
      active group's fan-out. A restart re-resolves the list from the address
      book and clears every baseline with it.
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
      credential-format change, which really would need a coordinated migration
      — both sides parse a credential, so a receiver that cannot validate the
      new binding rejects the member outright; item 11's control-message
      encryption was once described here as the same kind of problem and is
      not, because the wire format is read on the send path only), or plumbing
      fingerprints through `PeerAddr`
      and every ticket producer and consumer. Both were judged larger than this
      finding and are deliberately not taken here.

(Several other audit findings — the ECDSA verify bug, network-receive release
of unverified plaintext, the `Ticket::from_str` DoS, plaintext ECC keys, and
the weak PBKDF2 iteration count — were fixed; see the git history.)



## Open, MEDIUM, patch attempted and declined (2026-08)

These are **not** accepted residuals and must not be read as the section above.
Each is an unfixed MEDIUM finding that a fix was written for — verified, run,
and then rejected because the fix introduced a capability worse than the one it
closed. The rejected implementations, their diffstats and the exact objection
that killed each are kept in the scan directories named below; those directories
are outside git, so the summary here is the durable record.

The pattern the three share, which is the reason to record them together: the
repair added a **mechanism**, and the mechanism itself came under the
attacker's influence. Fixes in this codebase that landed did the opposite —
they removed attacker-controlled input from a decision using values the tree
already had.

13. **At-rest anti-rollback binds only the KEK** (`group/at_rest.rs`,
    `group/rollback.rs`; scan `CLAUDE-SECURITY-20260820-195218`, F3). An
    attacker who can substitute an older `groups.db` is accepted under every
    `NK_ROLLBACK_POLICY` value, because freshness is bound to the key wrapper
    and not to the database that holds the state.

    **Four implementations, all declined.** Every one bound freshness with a
    counter, and a counter cannot tell an attack from an accident: the
    substituted database and the operator's own restored backup produce the
    same mismatch. So each attempt closed the rollback and opened a
    denial-of-recovery. The second locked an uncompromised database
    permanently unopenable after a single run with `NK_ROLLBACK_POLICY` unset
    — the default, which a cron job, a systemd unit or `sudo` reaches — with
    an error accusing the operator of tampering. The fourth closed every
    earlier objection, was independently reproduced by the verifier against
    the production path, and still granted a new capability: an attacker with
    the finding's own privilege deletes `groups.db`, one ordinary open
    renumbers the empty database at anchor+1, and **the operator's newest
    genuine backup is then refused as stale**. At the patch base, restoring
    any copy opened.

    A fifth attempt along the same design will meet the same wall. What is
    needed is evidence that distinguishes attack from accident, from somewhere
    an attacker cannot forge; the KEK is already bound and is what the finding
    starts from.

14. **A single group member can permanently starve inbound file transfers**
    (`group/file_xfer.rs`; scans `CLAUDE-SECURITY-20260820-195218` F4 and
    `CLAUDE-SECURITY-20260821-233021` F4 — found twice, from different
    scopes). The reassembly pool holds 16 slots shared across all senders and
    groups, and the aggregate cap refuses at the limit rather than reclaiming,
    so one authenticated member holding all 16 stops every other transfer for
    good.

    **Two implementations, both declined**, and both failed the same way: they
    reclaimed slots on an idleness measure the attacker drives. The first used
    wall-clock idleness — an attacker who stalls the receiver's serialized
    accept loop makes another sender's live transfer look abandoned. The
    second used a service clock advancing only while the receiver ingests, but
    every ingested frame advances it including junk, so one attacker frame per
    60 seconds drives it at wall-clock rate; the verifier reproduced the
    destruction of all 16 other-principal transfers and the unlinking of their
    `.part` files. That is the cross-principal destruction commit `d689865a`
    exists to prevent.

    **A third fix was attempted on 2026-08-26 and also declined**, and what it
    established is worth more than the fix would have been.

    Partitioning is *partly* done already and this entry said otherwise when it
    was first written: `MAX_TRANSFERS_PER_SENDER = 4` exists (`d689865a`), but
    it is keyed on `(group, sender)`, so it bounds one sender within one group
    and bounds neither a single group nor a single attacker identity spread
    across groups. The finding's recommendation said "no single principal **and
    ideally no single group**"; the group half is what remains untried. One
    group with four members already fills all sixteen slots, which the file's
    own `fill_to_cap` test helper demonstrates by holding the group fixed.

    The third attempt tried to attack *permanence* instead of breadth: free a
    group's slots when an MLS Remove Commit ejects us from it, since a Remove is
    an authenticated fact the code already carries rather than an idleness
    measure an attacker drives. Two premises collapsed.

    First, `handle_removal` fires only when the LOCAL node is removed and
    carries only `remover_index`, never the removed member's leaf — and
    `--mls-cmd remove-member` runs in a different process from the `listen_loop`
    that owns the reassembler, with no REPL or GUI path between them. **An
    operator who ejects an abuser cannot get the slots back today, and no change
    confined to `handle_removal` can make that work.**

    Second, and this is the fact to carry forward: **the slots held by a group
    we were removed from are not dead.** mls-rs skips `update_key_schedule`
    entirely when the Commit removes self, so our epoch freezes at N and
    epoch-N frames keep decrypting indefinitely — the three-epoch retention
    limit never applies, and the remover can withhold the Commit from a sender
    to keep that sender on epoch N for as long as it likes. A probe completed a
    bystander's transfer *after* the removal. So freeing those slots is not
    reclaiming dead state; it is destroying live state, and since any member may
    Remove any leaf (there is no application-level admin check), it would let
    any member of a group make our node unlink every other sender's staging
    files at a moment of their choosing — the cross-principal reach the comment
    on `MAX_CONCURRENT_TRANSFERS` explicitly forbids.

    The verdict is the useful summary: the change would have closed the case an
    attacker has no motive to enter — after it, removing us would hand the slots
    back — while arming the case they do. An attacker who simply never removes
    us keeps their slots regardless.

15. **A ticket's `direct_addrs` are bounded in number but not in kind**
    (`p2p/backend/iroh.rs`; scan `CLAUDE-SECURITY-20260821-233021` F2, same
    defect as the other scan's F9). `Ticket::from_str` now keeps at most 32
    addresses (`aab8f007`), so the 65535-target fan-out is closed. What is
    **not** closed is that an unspecified, multicast or IPv4-broadcast address
    among those 32 still becomes a hole-punch target — a reflection primitive,
    since one datagram reaches every listener on the victim's link.

    **The filter for it was written, passed verification twice, and was
    declined by the adversarial review**, which found it hands an attacker a
    way to make a victim unreachable. Nothing validates the addresses a node
    advertises about *itself*: `portmapper`'s UPnP path checks only that the
    address is v4, iroh's `update_direct_addresses` does not check at all, and
    `peer_addr_from_iroh` copies whatever results into the node's own tickets.
    A LAN-adjacent host that wins the SSDP race and answers as a fake IGD — or
    the operator of the relay in use, via the QAD observed address — can
    therefore put a refused kind into the victim's own address set. A peer that
    refuses the whole ticket then **drops the relay address with it**, because
    the error returns before the address list is assembled, so the victim
    becomes unreachable even by relay; before the patch that entry was one dead
    dial target and the connection succeeded.
    `group::processor::put_member_addr` re-serialises and persists the parsed
    ticket, so the poisoning outlives the attacker.

    Two directions were not tried and are the place to start: filter on the
    **emitting** side in `peer_addr_from_iroh`, so a poisoned address never
    reaches our own ticket; and/or drop the offending entry instead of the
    ticket, so the relay survives. The declined diff and the full reasoning are
    in that scan directory's `rejected-diffs/`, and the doc comment on
    `validate_peer_relay_url` carries a short form of it so the next reader who
    notices the missing filter finds out why it is missing.
