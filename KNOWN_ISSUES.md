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
   appears; and forcing a prune while a victim's own reserve bucket has
   refilled (so ~4 minutes with no below-floor draw on it) drops that victim's
   mark, which the next draw then re-derives from the drawn-down level. That
   last one is the sharpest of the three: the re-derived floor is a quarter of
   the *drawn-down* level `L`, so the attacker immediately regains `L - L/4`
   ungated draws plus a fresh 8-token burst, against the 8 draws that simply
   waiting out the same ~4 minutes would have bought — about **3x** at the
   default `--prekey-count 100` pool (`L` = 25: 19 + 8 draws) and about **7x**
   at a 256-key pool (`L` = 64: 48 + 8), growing with the pool size. The price
   is holding that many slots below their floors for the whole window.
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

(Several other audit findings — the ECDSA verify bug, network-receive release
of unverified plaintext, the `Ticket::from_str` DoS, plaintext ECC keys, and
the weak PBKDF2 iteration count — were fixed; see the git history.)


