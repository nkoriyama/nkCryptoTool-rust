# Claude Security audit (2026-07-28) — remediation record

Scan of the whole repository at revision `0061f0e0dc80c9c4a3f34dab500a34f7b4b306ba`,
run at **medium** effort with no scope narrowing. Fifty-nine raw candidates
deduplicated to fifty-two; forty-five reached a three-lens adversarial panel
(135 votes, every round complete at three voters) and **21 survived** the
two-of-three bar. No HIGH or CRITICAL.

All 21 are now addressed. Nothing in the scan executed the repository's code —
every finding was derived from reading, and every fix below is backed by tests
that do run.

---

## 1. Findings and where they were fixed

Severity/confidence are as the panel left them (confidence is clamped by the
vote: only a unanimous panel earns `high`).

### Authorization boundary

| ID | Sev | Votes | Summary | Fixed in | Tests |
|----|-----|-------|---------|----------|-------|
| F1 | MED | 3/3 | Keyring allowlist snapshotted at startup, so `keyring revoke` never took effect on a running server | `p2p/processor.rs` — new `AllowlistSource`, replaces the frozen `HashMap` | (behavioural; covered indirectly by the iroh handshake suite) |
| F2 | MED | 2/3 | `ALPN_CHAT` / `ALPN_FILE` served by every listener with no serve-mode gate and no per-service grant | `config.rs` (`serve_chat`, `file_mode`), `main.rs`, `p2p/processor.rs` (**both** dispatches) | `iroh::tests::chat_and_file_alpns_are_refused_without_serve_chat`, `processor::tests::single_shot_listener_refuses_chat_file_without_serve_chat` |

**F1.** The map is now a live view: `(mtime, len)` of the keyring file
invalidates it, with a 5-second ceiling so a revoke landing in the same mtime
tick as the previous read cannot hide behind timestamp granularity. Reload
failure **fails closed** (one retry absorbs contention with a concurrent
`keyring` command) — falling back to the superseded map is exactly the
revoked-but-still-admitted behaviour being fixed.

**F2.** Chat and file-receive are gated like the other four services. Two
further problems surfaced while fixing it:

- The grant check read `granted & mask == 0`, which for a multi-bit mask
  accepts a peer holding *any one* bit. It now requires `granted & mask == mask`.
  Chat/file require `GRANT_ALL` rather than getting new bits, because a new bit
  could not be told apart from a deliberate narrow grant in rows already stored
  under the current `GRANT_ALL`.
- **The ALPN dispatch is duplicated.** `run_listen_loop` (the long-running
  server) and `run_listen_once` (single-shot, used by `--serve-pairing` and the
  GUI) each carry their own copy, and the first fix only covered the loop. A
  `--serve-pairing` node therefore still served an ungated chat session against
  its own stdin to any peer that dialled `nkct/chat/2`. Both copies now carry
  the gate, and both are tested. If a third listener path is ever added, it
  needs the same gate — the duplication is the hazard here.

Callers that legitimately serve chat/file must now declare the role. The GUI's
receive button (`gui/mod.rs`) and the file-transfer e2e helper set
`serve_chat = true`; they are file servers, so the declaration is the correct
outcome rather than a workaround.

### Untrusted header integers

| ID | Sev | Votes | Summary | Fixed in | Tests |
|----|-----|-------|---------|----------|-------|
| F4 | MED | 3/3 | `chunk_size` drives an unbounded `Zeroizing<Vec>` capacity that is volatile-zeroed on drop | `strategy/streaming_aead.rs`, `pqc.rs`, `ecc.rs`, `hybrid.rs`, `processor.rs` | `streaming_aead::tests::chunk_size_bounds_reject_zero_and_the_amplifying_range` |
| F5 | MED | 3/3 | Same root cause at the sibling wire-buffer allocation | same | same |
| F15 | LOW | 3/3 | Same root cause; abort-on-constrained-target facet | same | same |

One cause, three findings. `V3_MAX_CHUNK_SIZE` (64 MiB) is enforced in all three
`deserialize_header` implementations — before anything sizes a buffer — and
`run_chunked_decrypt` additionally clamps by `min(chunk_size + tag, body_size)`,
so the field is non-amplifying regardless of what the parser let through. The
encrypt side takes the same bound, so this build cannot write a file it would
then refuse to read.

### MLS state management

| ID | Sev | Votes | Summary | Fixed in | Tests |
|----|-----|-------|---------|----------|-------|
| F8 | MED | 3/3 | Unsynchronised read-modify-write lets a concurrent task silently revert a member removal | `group/processor.rs` (per-group async lock), `group/redb_storage.rs` (epoch CAS) | `same_group_waiters_are_serialized`, `different_groups_stay_parallel`, `concurrent_first_acquisition_shares_one_mutex`, `released_locks_are_reclaimed`, `stale_snapshot_write_is_refused`, `same_and_advancing_epoch_writes_are_accepted` |
| F9 | MED | 3/3 | Remote-chosen group id persisted before its length is validated, permanently poisoning `list_groups()` | `group/processor.rs`, `group/storage.rs` | (covered by the group suite) |
| F10 | MED | 3/3 | Welcome with an attacker-chosen group id overwrites an existing local group's MLS state | `group/processor.rs` | (covered by the group suite) |

**F8 is two layers.** A per-group async lock (`Mutex<HashMap<Vec<u8>,
Weak<Mutex<()>>>>`) serialises the whole load → mutate → persist cycle in
`process_mls_bytes`, `send_application_message`, `add_member`, `remove_member`
and `request_resync`; unrelated groups stay parallel, and the table holds only
`Weak`s so released locks are reclaimed. Underneath, `write_inner` performs an
epoch compare-and-swap **inside the same redb write transaction**, refusing a
snapshot older than what is stored. The lock prevents the race on the normal
paths; the CAS keeps a future path that bypasses the lock from rolling state
back silently. `request_resync` takes the lock per applied commit rather than
for the whole stream, so a slow peer cannot hold the group lock for the length of
a stream. That is a statement about the lock only: an operator-initiated
`/resync` is awaited in `listen_loop`'s stdin arm, which polls just the removal
signal while the sweep runs, so typed lines — `/quit` included — do wait it out.

**F9/F10.** Validation and the clobber check now run *before*
`write_to_storage`, and `list_group_ids` skips a malformed row with a warning
instead of failing the whole scan — a single planted row used to deny access to
every real group with no CLI or FFI way to remove it.

### Signature domain separation

| ID | Sev | Votes | Summary | Fixed in | Tests |
|----|-----|-------|---------|----------|-------|
| F11 | MED | 2/3 | File signing uses an empty FIPS 204 context, colliding with the MLS transport-binding signature that shares the same ML-DSA key | `strategy/pqc.rs`, `group/binding.rs` | `binding::tests::file_signature_is_not_usable_as_a_transport_binding_signature` |

Only two producers in the tree used `ctx = ""`: file signing and MLS transport
binding. Both now carry a context — `FILE_SIGN_CTX` and `BINDING_SIG_CTX` — so
no two protocols share one. See §3 for the compatibility consequences.

### Operator-display integrity

| ID | Sev | Votes | Summary | Fixed in |
|----|-----|-------|---------|----------|
| F3 | MED | 3/3 | MLS group chat bodies written to the terminal unsanitized | `group/cli.rs` (`render_event`) |
| F12 | LOW | 3/3 | scp `Fail` message printed unsanitized | `scp.rs` (`ScpFrame::decode`) |
| F13 | LOW | 3/3 | Port-forward rejection reason printed unsanitized | `forward.rs` (`FwdFrame::decode`) |
| F14 | LOW | 2/3 | Received-file path printed with `Path::display()` | `group/cli.rs`, `group/file_xfer.rs` |
| F17 | LOW | 3/3 | Pairing response text printed unsanitized | `pairing.rs` (`PairingResponse::decode`) |
| F18 | LOW | 3/3 | Peer-authored KeyBundle handle stored unvalidated and rendered raw | `keyring.rs`, `main.rs` |
| F19 | LOW | 3/3 | `aead_algo` interpolated into a printed error | `strategy/streaming_aead.rs` + the three parsers |
| F20 | LOW | 3/3 | `kem_algo` echoed unescaped | `keyring.rs` (`peek_v3_header`) |

The shared filter lives in `utils::sanitize_for_terminal` /
`sanitize_for_terminal_bounded` (tested in `utils::terminal_sanitizer_tests`).
It is applied at the **decode boundary** rather than at each print site, so a
single gate covers all nine consumers of `ScpFrame::Err`, both forward reason
fields, and both pairing paths. Two cases are fixed at the root instead:
`Reassembler::safe_name` now *rejects* control and bidi characters (the name
becomes a real filename, not just display text), and `KeyringStore::add` itself
applies `validate_handle` so every ingest path is covered. Algorithm names are
charset-restricted at parse time, which closes F19 and F20 at the source.

### Transfer completion

| ID | Sev | Votes | Summary | Fixed in | Tests |
|----|-----|-------|---------|----------|-------|
| F16 | LOW | 3/3 | scp `get -r` treats an unauthenticated stream truncation as a completed transfer | `shell.rs` (`recv_packet`), `scp.rs` (new `recv_tree`) | see below |

`recv_packet` now distinguishes a clean FIN at a packet boundary from a
transport error or a close part-way through a packet. `recv_tree` was extracted
from `run_scp_client` so the contract is directly testable: **only
`ScpFrame::Done` is a success exit.** The single-file path deliberately keeps
tolerating a close after its own terminator, because the declared size plus the
protocol `Eof` already establish completeness — that difference is documented in
both places and pinned by tests.

Tests: `recursive_get_accepts_explicit_done_for_empty_transfer`,
`recursive_get_accepts_explicit_done_after_entries`,
`recursive_get_rejects_stream_end_before_done`,
`recursive_get_rejects_stream_end_mid_file_body`,
`recursive_get_rejects_file_shorter_than_declared_size`,
`single_file_accepts_stream_end_after_size_and_eof`,
`single_file_rejects_stream_end_without_protocol_eof`,
`single_file_rejects_stream_end_before_transfer_is_complete`, plus
`shell::tests::{clean_close_on_a_packet_boundary_is_end_of_stream,
close_part_way_through_the_length_prefix_is_an_error,
close_part_way_through_a_packet_body_is_an_error}`.

### Operator deception / secret handling

| ID | Sev | Votes | Summary | Fixed in | Tests |
|----|-----|-------|---------|----------|-------|
| F6 | MED | 2/3 | "Privacy Mode" is a silent no-op on every platform while the UI reports it as enabled | `gui/screen_protection.rs`, `gui/mod.rs` | `gui_test::privacy_mode_reports_unavailability_instead_of_pretending` |
| F7 | MED | 3/3 | Pairing one-time token passed on argv, exposed via `/proc/<pid>/cmdline` | `main.rs` | (manual; `--token -` path) |
| F21 | LOW | 3/3 | Remote chat peer fully controls the desktop-notification body | `gui/notifications.rs`, `gui/mod.rs` | `notifications::tests::*` (4 tests) |

**F6 — read §2. The capture-exclusion feature is still not implemented.**

**F7.** `--token -` reads the OTP from a terminal without echo, or from stdin so
it can be piped. A token on the command line still works but warns, and the
server's suggested client command now uses `--token -`. An environment variable
was deliberately *not* added: `/proc/<pid>/environ` is owner-readable rather than
world-readable, so it is better than argv but still inherited by every child and
visible to anything running as the same user.

**F21.** The notification label is no longer parsed out of the peer's own
message — `extract_peer_id` is gone along with its only caller. `notify_message`
now takes `Option<&str>` documented as *authenticated identity only*, and the
call site passes `None` because no authenticated identity reaches that task yet.
Any label that is supplied is control-filtered, markup-escaped and truncated.

---

## 2. Privacy Mode: what was and was not done

**Not implemented:** screen-capture exclusion. `SetWindowDisplayAffinity`
(Windows) and `NSWindow.sharingType` (macOS) are still not wired up, and on
Linux there is no client-side equivalent — exclusion is the compositor's
decision.

**What changed:** the fail-open pretence was removed.

- `is_supported()` returns `false` on every platform (it previously returned
  `true` on Windows and macOS while calling no OS API).
- `set_protection()` returns `Err` describing what is missing, instead of
  `Ok(())`.
- `get_warning_message()` returns a warning on every platform, and it states
  plainly that the window is **NOT excluded** from screenshots or screen
  sharing. It was previously `None` off Linux, so the failure was silent.
- The caller no longer discards the result: it resets the toggle to `false` and
  shows the warning.

The correct wording for release notes is *"the unimplemented state is now
surfaced and the fail-open pretence removed"*, **not** *"Privacy Mode was
implemented"*. A user reading the UI now learns the truth; they still have no
capture protection.

The test that used to guard this only grepped the source for placeholder
phrases like `TODO`, which the stub passed. It has been replaced with one that
asserts the actual contract, and should be narrowed rather than deleted when a
platform is implemented.

---

## 3. Compatibility breaks — require a release decision

### 3.1 NKCS v1 → v2 (file signatures)

- This build **produces** NKCS v2, signed under `FILE_SIGN_CTX`.
- It **verifies** both v2 and v1 (v1 under the empty context), so existing
  signature files keep validating.
- Unknown versions are rejected rather than guessed.

**Resolved for this release.** The C++ implementation (`../nkCryptoTool`,
`PQCStrategy`) carries the matching change: it signs under the same
`FILE_SIGN_CTX`, emits NKCS v2, verifies both v2 and v1, and rejects unknown
versions. It reuses the existing `mldsaSignCtx` / `mldsaVerifyCtx` backend
entry points (already used by KeyBundle), so no backend interface changed.

Verified on real binaries, both directions:

| Check | Result |
|---|---|
| Rust signs → header `4e4b4353 0200` | v2 emitted |
| Rust signs → **C++ verifies** | passes |
| C++ signs → header `4e4b4353 0200` | v2 emitted |
| C++ signs → **Rust verifies** | passes |
| version field flipped to 1 | both reject (context mismatch) |
| unknown version 3 → Rust | rejected: `unsupported NKCS signature version 3` |
| unknown version 3 → C++ | rejected, but by a later OpenSSL parameter error rather than the version check — **fail-closed, but the intended path is unconfirmed** (open item) |

Ship the two repositories as one release unit. A `.sig` from this Rust build
still fails against a C++ build older than this change.

Note: `tests/unit/unit_tests.cpp` in the C++ repository fails to compile (three
`MockStrategy` override mismatches). Confirmed pre-existing by stashing the
change and rebuilding — unrelated to this work.

### 3.2 MLS transport-binding context

`BINDING_SIG_CTX` replaces the empty ML-DSA context in `create_binding` /
`verify_binding`. This is a **protocol compatibility break**: bindings made by an
older build will not verify here, and vice versa. There is no negotiation and no
version field on the binding, so a rolling upgrade is not possible — mixed-version
peers will see verification failures with no indication of the cause. Either add
a version/negotiation step before shipping, or document an all-at-once upgrade
and say explicitly that mid-upgrade binding failures are expected.

This was applied on the maintainer's explicit instruction after the narrower
alternative (separating only the file-signing path, which already removes the
collision) was raised and declined.

### 3.3 `--serve-chat` now required

A node started as a shell/scp/forward/pairing server no longer serves chat or
file-receive. This is the intended authorization fix and safety outweighs
backward compatibility here. Anyone relying on the old behaviour must add
`--serve-chat` explicitly.

Migration note: the server logs `Rejecting nkct/chat/2: this node is not a chat
server` on its own stderr, but the client only sees the connection close. This
matches how the other four ALPNs already behave, and is deliberate — telling an
unauthenticated peer which services a node runs is itself a disclosure.

---

## 4. Verification

```
cargo test                                             206 passed, 1 ignored
cargo test --features mls                              363 passed, 1 ignored
cargo test --features "testing gui gui-notifications
                       gui-screen-protection"          243 passed, 1 ignored
cargo clippy --features "testing mls gui …"
             --all-targets                             0 errors
```

**Known clippy warnings, pre-existing and untouched:** three
`very_complex_type` warnings in `group/redb_storage.rs` (lines 146, 591, 2045).
No warning is attributable to the new code.

**`cargo fmt --check` was deliberately not satisfied.** It reports ~949 diffs
across the working tree, CI does not run it, and the repository is not
rustfmt-formatted as a matter of policy. Reformatting would mix whitespace with
security changes, obscure the diff, and pollute `git blame`. This is a
repository-wide question to settle separately.

---

## 5. Coverage limits carried forward

These are **not** clean results — they were never examined, and the re-scan
should treat them as first-time evaluations rather than confirmations.

- **7 candidate sites never reached a panel** (`unverifiedByCap: 7`). Neither
  confirmed nor refuted.
- **`android-app:memory-and-unsafe` was pruned before dispatch.** Memory safety
  and unsafe code in the Android app was never researched.
- **Deliberately skipped components:** `build-ci-tooling`
  (`.cargo`, `.github`, `ci`, `scripts`, `packaging` — a real supply-chain
  surface), `demos-scratch`, `docs`, and generated Android build output.

## 6. What a re-scan should look at

Beyond confirming the 21 do not reappear:

- New contention or DoS paths between the group lock table and the epoch CAS.
- Resource retention in the receive loops now that only `Done` exits
  successfully (staged files on the error path in particular).
- Whether the Privacy Mode warning can be suppressed through another path.
- The three coverage gaps in §5.

**Re-scan status: run.** See §7.

---

## 7. Re-scan of the remediation commit (2026-07-28)

A second scan was run in `changes` mode over the remediation commit itself
(`4de865a52306c1bf9e80014f7208aaf5239dcddd`, 29 files / 2686 lines) at **medium**
effort. Sixteen raw candidates deduplicated to fifteen; all fifteen reached a
three-lens adversarial panel (45 votes, every round complete at three voters)
and **6 survived**. No HIGH. Nine were refuted — F8/F9/F10/F11/F12/F14 at 0/3
and F7/F13/F15 at 1/3.

Report: `CLAUDE-SECURITY-20260728-023318/CLAUDE-SECURITY-RESULTS.md`
(`verification.status: verified`).

Four of the six were gaps in the §1 remediation rather than new defects: two
sinks the new sanitizer and the new algorithm-name validator do not reach, one
denial-of-service introduced by the new per-group lock, and one exposure the
first pass mitigated but did not close.

### Findings and where they were fixed

`R6` is the same sink as `R2`, found independently through a second lens; the
`R2` fix closes both, so five changes cover six findings.

| ID | Sev | Votes | Summary | Fixed in | Tests |
|----|-----|-------|---------|----------|-------|
| R4 | MED | 3/3 | Per-group MLS lock held across `fanout_send`, so one silent member freezes all inbound processing for the group | `group/processor.rs`, `group/transport.rs` | `send_releases_group_lock_before_fanout`, `send_still_waits_for_the_group_lock` |
| R2/R6 | MED | 3/3 | `MkDir` chmods pre-existing client directories, and an empty path reaches the destination root itself | `scp.rs` — `safe_join`, `recv_tree`, new `clamp_dir_mode` | `mkdir_rejects_empty_path`, `mkdir_leaves_pre_existing_directory_mode_alone`, `mkdir_does_not_mode_implied_parents`, `mkdir_applies_mode_to_newly_created_directory`, `mkdir_clamps_group_and_other_write` |
| R3 | MED | 2/3 | Pairing OTP still accepted on argv (warned only), leaving the `/proc/<pid>/cmdline` hijack path documented | `main.rs`, `USAGE.md` | `pairing_token_cli.rs` (2 tests) |
| R1 | MED | 3/3 | Peer-supplied path bypasses the decode-time terminal sanitizer via `dest.display()` | `scp.rs` — new `show_path` at three sinks | `peer_path_is_sanitized_in_operator_errors` |
| R5 | LOW | 3/3 | NKCS signature-header algorithm names skip `validate_algo_name` | `strategy/pqc.rs`, `strategy/ecc.rs` | 5 tests across both parsers |

**R4.** The group guard now covers `load → encrypt → persist → encode` and
stops there; `fanout_send` runs with it released. The ordering is deliberate:
the key schedule is persisted before any bytes leave the host (a recipient must
never hold a message our state does not know we sent), which also fixes the
failure semantics — past the critical section the epoch has advanced durably, so
a fan-out error is a *delivery* failure and never rolls MLS state back. Delivery
ordering is not serialized by this lock and never was: `broadcast_commit` has
always fanned out unlocked, and MLS application messages carry their own
generation, so recipients tolerate reordering. Separately, the sender's trailing
ACK read and stream shutdown moved from `IDLE_TIMEOUT` (300 s each) to a new
`ACK_LINGER` of 10 s — both outcomes are discarded, so the longer wait bought
nothing and cost a 10-minute stall per message that any recipient could trigger.

The regression test was confirmed to have teeth: restoring the old lock scope
makes `send_releases_group_lock_before_fanout` fail with
`held the group lock across the fan-out`.

**R2/R6.** Three changes. `safe_join` rejects a relative path with no
components, so a peer can no longer name the destination root. `MkDir` uses
`create_dir` instead of `create_dir_all` for the directory the peer named, so
`AlreadyExists` is distinguishable from "we made it" and the mode is applied
only to directories this transfer created; missing ancestors are still created,
but with default permissions. Finally `clamp_dir_mode` masks off group and other
write even on directories we did create, so a peer cannot leave a
world-writable directory behind. OpenSSH scp makes the same trade the other way
round — it ignores the remote mode entirely without `-p`.

**R3.** A warning was not enough: the in-tree help and `USAGE.md` still showed
the argv form, so the exposure survived in practice. `--token` now accepts only
`-`; a literal value is an error naming the `/proc` exposure and the piping
alternative. This is a **breaking CLI change** — see §8.

**R1.** `show_path` routes peer-derived paths through the same
`sanitize_for_terminal_bounded` gate the frame decoder uses, at the `mkdir`,
`stage` and `commit` sinks in `recv_tree`. The decoder's comment claiming
`Fail`/`Err` were "the peer's only channel to the display" was wrong and has
been corrected in place.

**R5.** `validate_algo_name` is now called immediately after each `read_string`
in both `deserialize_signature_header` implementations, matching what the
encryption header already did. Rejection is at the parse boundary, not at the
point of use. The real algorithm names (`ML-KEM-768`, `ML-DSA-65`, `SHA3-512`,
`prime256v1`) all pass the charset, so no existing signature stops verifying;
there is an explicit test for that.

### Verification

```
cargo test                                    219 passed, 1 ignored
cargo test --features mls --lib group::       126 passed
cargo clippy --all-targets                    no issues
scripts/mandate_check.sh                      PASS=21 FAIL=0 WARN=1
```

The `WARN` is the pre-existing `clippy has continue-on-error: true` check.
`.security-baseline.sha256` needed no rebaseline: none of the nine baselined
files changed in this round.

### Coverage limits of the re-scan

**The "6 findings" figure is not a complete re-evaluation of the remediation
commit.** The componentizer inferred the commit's scope from the preceding
`docs(scp)` / `chore` commits and concluded it was scp-scoped, so it excluded
`src/group`, `src/utils.rs`, `src/processor.rs`, `src/pairing.rs`,
`src/keyring.rs`, `src/forward.rs` and `src/gui` from the researcher matrix —
all of which the commit in fact modifies. R4 was found in
`src/group/processor.rs` only because a researcher followed a lead across that
boundary, which is evidence that the excluded areas were not empty. The nine
refutations bound nothing outside the scanned components.

The correct next step is a scan that explicitly covers the changed components,
or a whole-repository run — not another `changes` pass.

### Observed but not changed

`scp.rs` interpolates peer-supplied paths into **server-side audit records**
without sanitizing: `scp mkdir ok path={}` (`dir.display()`),
`scp deny: mkdir {path}` (the raw frame string), `scp put ok path={}`, and the
`put {path}: …` reasons. This is the same class as R1 with a different sink — an
audit file rather than a terminal — and the panel did not raise it. Left for a
scan pass that covers the server side deliberately, rather than folded into this
round.

---

## 8. Breaking changes in this round

- **`--token <OTP>` is rejected.** Only `--token -` is accepted; the OTP is read
  from the terminal without echo, or from stdin so it can be piped. Any script
  passing the OTP literally must change to
  `printf '%s' "$OTP" | nk-crypto-tool … --token -`.
- **`MkDir` modes are no longer honoured on pre-existing directories**, and are
  masked to drop group/other write on new ones. A `get -r` that previously
  reproduced a `0o775` or `0o777` directory now yields `0o755`.
