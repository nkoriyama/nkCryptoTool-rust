#!/usr/bin/env bash
# Build the distributable static-musl nkct reproducibly, twice, from
# independent (--no-cache) container builds, and assert the two binaries are
# byte-identical. Emits the artifact + SHA256SUMS under packaging/out/.
#
# Usage:  packaging/reproducible-build.sh            # SOURCE_DATE_EPOCH = HEAD commit time
#         SOURCE_DATE_EPOCH=1700000000 packaging/reproducible-build.sh
#
# A third party verifies a release by running this on the tagged source and
# comparing the printed sha256 against the published SHA256SUMS.
set -euo pipefail

cd "$(dirname "$0")/.."
CF=packaging/Containerfile.repro
OUT=packaging/out
mkdir -p "$OUT"

# Reproducible timestamp: the commit being built, not "now".
: "${SOURCE_DATE_EPOCH:=$(git log -1 --format=%ct 2>/dev/null || echo 0)}"
export SOURCE_DATE_EPOCH
echo "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"

# The VAES variant restates the FULL musl rustflags (EXTRA_RUSTFLAGS replaces
# the config.toml section — see Containerfile.repro), swapping the portable
# x86-64-v2 floor for x86-64-v3 + the AVX-512/VAES features the aes crate's
# `aes_backend="avx512"` backend requires. main() carries a startup CPUID
# guard so a VAES-less machine gets a clear error instead of a SIGILL.
VAES_RUSTFLAGS='-C target-cpu=x86-64-v3 -C target-feature=+aes,+pclmulqdq,+vaes,+vpclmulqdq,+avx512f --cfg aes_backend="avx512" --remap-path-prefix=/build=nkct --remap-path-prefix=/usr/local/cargo=cargo'

build_once() {
  local tag="$1" dest="$2" extra="${3:-}"
  echo "== building $tag (--no-cache) =="
  podman build --no-cache \
    --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" \
    --build-arg "EXTRA_RUSTFLAGS=$extra" \
    -f "$CF" -t "$tag" .
  # Extract the artifact from the image (no run, no mounts → no host variance).
  local cid; cid=$(podman create "$tag")
  podman cp "$cid:/nkct" "$dest"
  podman rm "$cid" >/dev/null
}

# Build each variant twice from independent images and require byte-identity.
# name:extra-rustflags pairs; the portable variant keeps config.toml in charge.
build_variant() {
  local name="$1" extra="${2:-}"
  build_once "nkct-repro-$name-a" "$OUT/$name.a" "$extra"
  build_once "nkct-repro-$name-b" "$OUT/$name.b" "$extra"
  local ha hb
  ha=$(sha256sum "$OUT/$name.a" | cut -d' ' -f1)
  hb=$(sha256sum "$OUT/$name.b" | cut -d' ' -f1)
  echo "$name build A: $ha"
  echo "$name build B: $hb"
  if [ "$ha" != "$hb" ]; then
    echo "MISMATCH ($name): the two builds differ — not reproducible." >&2
    ls -l "$OUT/$name.a" "$OUT/$name.b" >&2
    exit 1
  fi
  mv "$OUT/$name.a" "$OUT/$name"
  rm -f "$OUT/$name.b"
}

# VARIANTS=nkct packaging/reproducible-build.sh  → portable only
: "${VARIANTS:=nkct nkct-vaes}"
for v in $VARIANTS; do
  case "$v" in
    nkct)      build_variant "$v" "" ;;
    nkct-vaes) build_variant "$v" "$VAES_RUSTFLAGS" ;;
    *) echo "unknown variant $v" >&2; exit 1 ;;
  esac
done

( cd "$OUT" && sha256sum $VARIANTS > SHA256SUMS )
echo "OK: reproducible. artifacts + hashes in $OUT/"
cat "$OUT/SHA256SUMS"
