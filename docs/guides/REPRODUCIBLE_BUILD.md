# Reproducible builds

## Why

nkCryptoTool's threat model includes regulation that pressures software vendors
to scan users' messages on-device before encryption (client-side scanning, e.g.
EU "Chat Control"). End-to-end encryption does not defend against a scanner
compiled into the client you run. The structural defense is a **reproducible
build**: anyone can rebuild the released binary from public source and byte-for-
byte compare it, so an injected scanner in a distributed binary shows up as a
hash mismatch. This only works if the build is deterministic and the toolchain
is pinned — which is what this directory provides.

## What is pinned

| Input | Pinned by |
|---|---|
| rustc / cargo | `rust-toolchain.toml` (1.96.1) **and** the base image digest below |
| Base image | `packaging/Containerfile.repro` — `rust@sha256:a41f7740…` (rustc 1.96.1, host target `x86_64-unknown-linux-musl`) |
| Dependency versions | `Cargo.lock`, enforced with `cargo build --locked` |
| Features | default only (`backend-rustcrypto` — pure Rust; **no** openssl-src / sqlcipher C builds, no gui/mls) |
| Codegen target | `target-cpu=x86-64-v2` (portable floor, not the build host's CPU) — `.cargo/config.toml` |
| Build paths | fixed `WORKDIR /build` + `CARGO_HOME /usr/local/cargo`, then `--remap-path-prefix` scrubs both from the binary |

The artifact is a **static-PIE musl** executable: no glibc, no host shared
libraries, so the run host contributes nothing to the bytes.

## Build and self-verify

```bash
packaging/reproducible-build.sh
```

This runs two independent `--no-cache` container builds and asserts their
binaries are byte-identical, then writes `packaging/out/nk-crypto-tool` and
`packaging/out/SHA256SUMS`. Set `SOURCE_DATE_EPOCH` to override the timestamp
(defaults to the HEAD commit time).

## Verify a published release (third party)

```bash
git checkout <release-tag>
packaging/reproducible-build.sh
sha256sum -c <(curl -s <published SHA256SUMS URL>)   # or compare by eye
```

A matching hash means the binary you can download corresponds exactly to this
source tree — no extra code, no scanner.

## Residual variables (honest limits)

- **apk build deps.** The image installs `build-base` from the Alpine repo
  snapshot that the pinned base-image digest carries. Alpine package versions
  can drift if the base tag is later re-cut, so reproduction is guaranteed
  against *this digest*, not against `rust:1.96.1-alpine` as a moving tag. Bump
  the digest and `rust-toolchain.toml` together.
- **crates.io availability.** `--locked` fixes versions; crates.io tarballs are
  immutable, but a yanked/removed crate would break a future rebuild. Vendoring
  (`cargo vendor`) removes this dependency if long-term reproducibility is
  needed.
- **Scope.** Reproducibility is claimed for the container build only. A host
  cross-build uses different absolute paths and is not path-scrubbed.
- **This is not attestation of the source.** It proves binary == source; review
  the source itself for what it does.
