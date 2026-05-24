#!/usr/bin/env bash
# Enforces the P2P abstraction boundary:
#
# Only `src/p2p/backend/iroh.rs` is allowed to import iroh-crate types
# (`use iroh::...`, `use iroh_base::...`, `use iroh_relay::...`). Any
# other source file that imports them indicates an abstraction leak and
# should funnel through `crate::p2p::P2pEndpoint` / `P2pStream` instead.
#
# Doc-comment mentions and references to our own module path
# (`crate::p2p::backend::iroh::...`) are intentionally not matched.
#
# Run: bash scripts/check_p2p_abstraction.sh
set -euo pipefail

ALLOWED_FILE='src/p2p/backend/iroh.rs'

# Use-import detector: `use iroh::`, `use iroh_base::`, `use iroh_relay::`
# at the start of a logical line (after any leading whitespace).
PATTERN='^[[:space:]]*use[[:space:]]+iroh(_base|_relay)?(::|;|[[:space:]])'

FORBIDDEN=$(grep -rEn "$PATTERN" src/ --include='*.rs' \
    | grep -v "^${ALLOWED_FILE}:" \
    || true)

if [ -n "$FORBIDDEN" ]; then
    echo "Forbidden iroh-crate imports outside ${ALLOWED_FILE}:" >&2
    echo "$FORBIDDEN" >&2
    echo >&2
    echo "Use the abstraction in 'crate::p2p' (P2pEndpoint / P2pStream) instead." >&2
    exit 1
fi

echo "OK: no iroh-crate imports outside ${ALLOWED_FILE}."
