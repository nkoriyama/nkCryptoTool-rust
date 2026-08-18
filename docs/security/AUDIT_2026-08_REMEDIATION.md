# Claude Security audit (2026-08) — remediation record

Three scans of `src/`, run as a split so that no candidate went unvoted:

| run | scope | findings |
|---|---|---|
| `CLAUDE-SECURITY-20260806-001323` | `src/` part 1 (28 files) | 2 (`C-F1`, `C-F2`) |
| `CLAUDE-SECURITY-20260806-173039` | `src/group` | 10 (`A-F1`..`A-F10`) |
| `CLAUDE-SECURITY-20260811-090443` | `src/p2p` + `src/network` + `src/gui` | 13 (`B-F1`..`B-F13`) |

この3スキャンより前の4ターンと、7ターンを跨いだ推移は
[`AUDIT_CROSS_ANALYSIS.md`](./AUDIT_CROSS_ANALYSIS.md) にある。

**25 findings. No HIGH, no CRITICAL.** All were derived from reading; the scans
executed none of the repository's code. Every fix below is backed by tests that
do run.

The split existed because earlier runs had hit a verification cap and left
candidates unvoted. All three of these completed every round at full voter
count.

**24 are closed in code. One (`A-F8`) is addressed by documentation, with the
implementation deliberately deferred.** One further item — the inbox relay's
prekey storage — was found while patching, and is metered and reported rather
than closed, for a reason given below that is worth reading before anyone
"finishes" it.

---

## 1. Where each finding was fixed

| commit | closes |
|---|---|
| `27cf3462` | `C-F1` `C-F2` `A-F4` `B-F2` `B-F10` `B-F11` `B-F13` — terminal sanitization, seven findings by one root fix |
| `ec8c9ac6` | `A-F1` `A-F9` `B-F5` — inbox POLL bounded by bytes, not row count |
| `056cdfde` | `B-F1` `B-F3` — FETCH throttle table prunable; an `accept()` error no longer kills the relay |
| `d689865a` | `A-F3` — group file-transfer eviction scoped to the authenticated sender |
| `cd3f162c` | `B-F9` `B-F12` — dispatch on the service a listener was opened for; one guard owns the chat slot |
| `ae7d35b4` | `B-F4` `B-F7` — receive-listener handle held synchronously; a ticket's relay URL validated before dialing |
| `2b96646d` | `A-F10` — SYNC history clamped to the requester's own join epoch |
| `ded989e6` | `B-F8` — each GUI chat connect gets its own input channel and session slot |
| `fdb80a23` | `B-F6` — the prekey reserve floor anchored in the store, so a forced prune cannot reset it |
| `ba6f9f68` | `A-F7` (route 1) — recipient prune scoped to the group whose epoch advanced |
| `6a95fbca` | (no numbered finding) — `request_resync` wired to an operator command; split out of the `A-F10` patch on scope grounds |
| `058835e8` | `A-F2` `A-F5` — MLS Commits and Proposals sealed as `PrivateMessage` |
| `fe3a0121` | `A-F6` — the listen session's death scoped to the operator's active group |
| `af4dd501` | `A-F8` — **documentation only**; see §4 |

Supporting commits from the same cycle: `ca0c666a` (RUSTSEC-2026-0257),
`94ad10bb` (residual correction), `ac79d3e9` (test hygiene), `24b7a217`
(no-await invariant made a compile error), `5a18565b` (CI lints `mls`),
`ed8aa43b` (inbox prekey floor and meter).

---

## 2. The three roots

Twenty-five findings collapsed into three.

**Terminal and GUI display forgery.** The most-repeated class across every
audit this project has run: a peer-chosen string — a QUIC close reason, a
path, a filename — reaching an operator's terminal, an audit log, or a GUI
banner without passing the sanitizer. Seven of the twenty-five were instances.
`27cf3462` closed them with one predicate rather than seven patches, and
narrowed the sanitizer's own range in the process: it had swallowed the 240
Mn variation selectors along with the Cf tag block, so `葛\u{E0100}飾区` did
not survive a round trip. A regression test now pins that byte-identity.

**Unbounded allocation on the inbox relay.** One 13-byte POLL drove roughly a
GiB of relay heap; the FETCH throttle table could never be pruned because its
guard tested `is_full()` rather than `is_full_at(now)`, so `retain` freed
nothing; and a single `accept()` error ended the relay. The first revision of
the throttle fix was itself rejected — its shared overflow bucket denied 103
of 119 honest FETCHes at 1000 fresh NodeIds/sec, which is a PQ-FS downgrade
lever, not a rate limit.

**Group boundaries not acting as trust boundaries.** A Remove Commit in one
group could destroy another group's in-flight transfers (`A-F3`), silently
revoke delivery to a peer whose relationship was a different group (`A-F7`),
or end the whole listen session (`A-F6`). The SYNC responder served history
from before the requester joined (`A-F10`). Each is now scoped per group and
per join epoch.

---

## 3. What the deepest finding turned out to cost

`A-F2`/`A-F5`: `GroupChatProcessor::new` built its client without calling
`.mls_rules(..)`, so mls-rs's default left `encrypt_control_messages` false and
every Commit went out as `WireFormat::PublicMessage` — signed, and readable by
anyone who saw the frame. An Add Commit carries the joiner's whole KeyPackage:
iroh NodeId, ML-DSA-65 transport public key, display name. Those frames reach a
third-party inbox relay whenever a direct send fails, so a relay operator could
reconstruct a group's membership history and the team's identity map without
ever holding a group key — and those ML-DSA keys are what
`projected_member_fingerprints` turns into shell and port-forward policy.

The finding said the fix required every peer to upgrade at once. **That was
measured and is false**, which is why it shipped in a day rather than a
release. `EncryptionOptions` is read in exactly three places in all of
mls-rs 0.55.2, every one on the send side; no receive path reads it. Probed in
both directions: an unmodified peer applies an encrypted Add and Remove and
lands on a byte-identical roster, and an upgraded peer applies a cleartext one.
A lagging member replays encrypted history over SYNC across a mixed store,
because `check_metadata` already required `epoch == context.epoch` for a
Commit — identical for either wire format.

What replaces the flag day is a smaller, real residual: **confidentiality is a
property of the sender**, so a group's control traffic is only as private as
its least-upgraded committer. Monotone improvement, no coordination point — and
not a deployment event either.

---

## 4. Deliberately not fixed

**`A-F8` — the anti-rollback counter binds only the KEK.** Swapping in an old
`groups.db` while keeping the current KEK is never detected under any policy,
and a pair-restore is detected only across a rekey boundary.
`SECURITY_PROFILE.md` §7.5 now says exactly that; the binding is unchanged by
owner decision.

**`A-F7` route 2 — credential squatting.** The chosen remedy could not be
expressed at the site: `PeerAddr` has no fingerprint field, every MLS-path
ticket is minted `Ticket::new(addr, None, None)`, and keying the prune on a
fingerprint would degrade to "never prune", reopening the leak the prune
exists to close. Recorded as `KNOWN_ISSUES.md` item 12 with its realistic
victims.

**The inbox relay's prekey storage.** `publish_prekeys` sat outside every
storage defence: no byte ledger, no TTL (the sealed `created_at` is read by
nothing), and `compact` never runs on that database. An unauthenticated peer
minting NodeIds pins ~2 MiB per identity, at 1:1 bandwidth cost, permanently.

A hard cap was built and then removed. **The reason is the most useful thing
in this section.** A held cap is a permanent, relay-wide, self-funding PQ-FS
downgrade lever the uncapped version did not have: publish ~1 GiB across ~508
identities and every PUBLISH is refused thereafter, including every honest
recipient's; honest pools drain via FETCH, which anyone can drive, and can
never be restocked. It is absorbing — the only thing that frees budget is an
honest pool serving a sender, which the flood re-takes. The trade was a loud,
operator-recoverable failure for a silent, permanent one.

What ships is a 1 KiB floor under a published blob (parsing was rejected: it
buys no cost and creates a version gate), a byte ledger charged and refunded
in the same transaction, and a watermark that reports without refusing.
`ed8aa43b` and `KNOWN_ISSUES.md` item 10 carry the detail.

---

## 5. What this cycle left behind that outlives it

Two mechanisms, and they are the only part of this work that keeps paying:

**`scripts/check_roster_sync_sections.sh`** (`24b7a217`). The roster
read-modify-write must complete with no suspension point, or two tasks
interleave and a member dropped from the baseline can never be pruned again.
That was a convention held by a comment and **invisible to CI**: every test
stays green when it breaks, and `clippy::await_holding_lock` does not fire —
it targets `std::sync` guards and deliberately does not flag a
`tokio::sync::MutexGuard` held across an await. The section now lives in
non-`async` functions, so an `.await` is a compile error, and the script
guards the one hole that leaves — a future editor making them `async` again.
It **fails closed**: a missing file or a renamed anchor is an error, because a
guard that silently retires itself is worse than no guard.

**CI lints `mls`** (`5a18565b`). Every clippy invocation in CI omitted the
feature, so all of `src/group/` was compiled and tested but never
lint-checked. The gap had been widening — the three security patches before it
all touched `src/group/`.

---

## 6. How the fixes were checked, and what that caught

Each patch went through a generator, an independent verifier that ran the
suites, and an adversarial reviewer that saw only the diff. **The rejections
are the substance of this record.**

Two patches took five and six rounds. In `A-F7`'s, three of four rejections
were defects introduced by the fix to the round before: an unauthenticated
Welcome could seat the vouching population; the operator's `--mls-group-id`
selection was lost for a not-yet-joined group; a keep decision was never
re-evaluated; and splitting a read from its write widened a pre-existing lost
update by orders of magnitude.

The findings that mattered were found by probing, not by argument:

- A verifier ran a finding's own attack against the *patched* code and drew 25
  of 25 reserve keys below the floor the patch said it had raised.
- A probe reverted one of two call sites and left all 429 tests green, showing
  the suite bound the decision function and neither wiring.
- A probe held one 60-second window with a single byte and showed 501
  subsequent `No space left on device` errors printing zero lines.

**One defect class recurred in nearly every patch and was never eliminated,
only caught: text asserting a protection the code does not implement.** One
withdrawn claim survived five sweeps at six sites, including a file that
asserted it in a doc comment and forbade it in an assertion 490 lines below.
The countermeasure that worked is cheap and manual: **before shipping, grep
the diff for `never`, `cannot`, `only`, `all`, and for each name the code that
makes it true or scope it down.**

Two bookkeeping failures are worth recording so they are not repeated.
`A-F6` was counted as closed for most of the engagement because six rounds of
work on the `EpochAdvanced` path of the same function absorbed it in the
tally; it was open the whole time. And raw test counts were compared across
runs with different feature strings, producing figures that could not be
reproduced — **the check that works is comparing sorted test-name sets against
base**, which answers "was anything silently skipped" and the count does not.

---

## 7. Not scanned

`tests/`, `docs/`, the CI workflows, and the android tree. Each scan report
names its own boundary.

Also untested, structurally: both call sites of the `A-F6` fix. `listen_loop`
reads the process's real stdin and cannot be driven from a test, so the two
sites agreeing rests on review, and the test doc says so rather than implying
coverage.
