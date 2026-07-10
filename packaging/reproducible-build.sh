#!/usr/bin/env bash
# Build the distributable static-musl nk-crypto-tool reproducibly, twice, from
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

build_once() {
  local tag="$1" dest="$2"
  echo "== building $tag (--no-cache) =="
  podman build --no-cache \
    --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" \
    -f "$CF" -t "$tag" .
  # Extract the artifact from the image (no run, no mounts → no host variance).
  local cid; cid=$(podman create "$tag")
  podman cp "$cid:/nk-crypto-tool" "$dest"
  podman rm "$cid" >/dev/null
}

build_once nkct-repro-a "$OUT/nk-crypto-tool.a"
build_once nkct-repro-b "$OUT/nk-crypto-tool.b"

HA=$(sha256sum "$OUT/nk-crypto-tool.a" | cut -d' ' -f1)
HB=$(sha256sum "$OUT/nk-crypto-tool.b" | cut -d' ' -f1)
echo "build A: $HA"
echo "build B: $HB"

if [ "$HA" != "$HB" ]; then
  echo "MISMATCH: the two builds differ — not reproducible. Diffing sizes:" >&2
  ls -l "$OUT/nk-crypto-tool.a" "$OUT/nk-crypto-tool.b" >&2
  exit 1
fi

cp "$OUT/nk-crypto-tool.a" "$OUT/nk-crypto-tool"
rm -f "$OUT/nk-crypto-tool.a" "$OUT/nk-crypto-tool.b"
( cd "$OUT" && sha256sum nk-crypto-tool > SHA256SUMS )
echo "OK: reproducible. artifact + hash in $OUT/"
cat "$OUT/SHA256SUMS"
