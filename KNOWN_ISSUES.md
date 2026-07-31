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
   per-NodeId token bucket is bypassable by minting new NodeIds (cheap). This
   is the documented residual; the `Require Prekey (Strict PQ-FS)` profile is
   the real backstop against depletion downgrade.
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

(Several other audit findings — the ECDSA verify bug, network-receive release
of unverified plaintext, the `Ticket::from_str` DoS, plaintext ECC keys, and
the weak PBKDF2 iteration count — were fixed; see the git history.)


