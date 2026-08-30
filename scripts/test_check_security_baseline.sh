#!/usr/bin/env bash
# Unit test for scripts/check_security_baseline.sh.
#
# That script is what makes mandate_check.sh §19 verify a set of files rather
# than a set of lines, and it runs against a miniature repo here instead of the
# real one so the interesting cases -- a deleted entry, a decoy entry, a mangled
# hash -- can actually be constructed.
#
# The two cases that must stay CLEAN come first, and they are the reason the
# check has the shape it has. In particular: a security-critical file that is
# genuinely deleted, dropped from the list and rebaselined must PASS. That has
# happened in this repository (src/network/tcp.rs, when the deprecated TCP
# transport went away), and any rule about how much coverage may shrink would
# redden a release-blocking gate for a maintainer doing the right thing.
#
# Run: bash scripts/test_check_security_baseline.sh
set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECKER="$REPO_ROOT/scripts/check_security_baseline.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0

# A miniature repo the checker is happy with: two covered files, a list naming
# both (with a comment and a blank line, which must be ignored), and a baseline
# generated the way scripts/rebaseline_security.sh generates the real one.
fixture() {
    rm -rf "${WORK:?}"/* "${WORK:?}"/.security-baseline.sha256
    mkdir -p "$WORK/scripts" "$WORK/src"
    printf 'fn alpha() {}\n' > "$WORK/src/alpha.rs"
    printf 'fn beta() {}\n' > "$WORK/src/beta.rs"
    cat > "$WORK/scripts/security_critical_files.txt" <<'LIST'
# a comment, and the blank line below, both ignored

src/alpha.rs
src/beta.rs
LIST
    ( cd "$WORK" && sha256sum src/alpha.rs src/beta.rs > .security-baseline.sha256 )
}

# run_case <expected-exit> <description>   (the caller has already mutated $WORK)
run_case() {
    local want="$1" desc="$2" got out
    out="$(cd "$WORK" && bash "$CHECKER" 2>&1)"
    got=$?
    if [ "$got" = "$want" ]; then
        PASS=$((PASS + 1))
        printf '  ok    (exit %s) %s\n' "$got" "$desc"
    else
        FAIL=$((FAIL + 1))
        printf '  FAIL  want exit %s, got %s: %s\n' "$want" "$got" "$desc"
        printf '        %s\n' "$out"
    fi
}

echo "must stay CLEAN -- trees a maintainer is allowed to produce"

fixture
run_case 0 "the baseline covers exactly the listed files"

fixture
rm "$WORK/src/beta.rs"
sed -i '/^src\/beta\.rs$/d' "$WORK/scripts/security_critical_files.txt"
( cd "$WORK" && sha256sum src/alpha.rs > .security-baseline.sha256 )
run_case 0 "a genuinely deleted file, removed from the list and rebaselined (tcp.rs)"

echo
echo "must be DETECTED -- coverage removed while every remaining hash still matches"

fixture
sed -i '/src\/beta\.rs$/d' "$WORK/.security-baseline.sha256"
run_case 1 "THE FINDING: an entry deleted from the baseline, the file still listed"

fixture
printf 'fn gamma() {}\n' > "$WORK/src/gamma.rs"
( cd "$WORK" && sha256sum src/gamma.rs >> .security-baseline.sha256 )
run_case 1 "an entry the list never named (padding to keep a total looking healthy)"

fixture
printf 'fn gamma() {}\n' > "$WORK/src/gamma.rs"
sed -i '/src\/beta\.rs$/d' "$WORK/.security-baseline.sha256"
( cd "$WORK" && sha256sum src/gamma.rs >> .security-baseline.sha256 )
run_case 1 "a covered path swapped for another in the baseline alone"

# sha256sum warns about this line on stderr, skips it, and exits 0 (measured on
# GNU coreutils 9.10) -- so the file leaves coverage exactly as if the line had
# been deleted. The checker parses the lines itself for this reason.
fixture
sed -i '1s/^.//' "$WORK/.security-baseline.sha256"
run_case 1 "a 63-character hash, the malformed line sha256sum silently skips"

echo
echo "must be DETECTED -- the checks that already worked, still working"

fixture
printf 'fn alpha() { backdoor() }\n' > "$WORK/src/alpha.rs"
run_case 1 "a baselined file's contents changed"

echo
echo "must FAIL CLOSED -- an input missing must not report a pass"

fixture
rm "$WORK/src/beta.rs"
run_case 1 "a listed file no longer on disk"

fixture
rm "$WORK/.security-baseline.sha256"
run_case 1 "no baseline at all"

fixture
rm "$WORK/scripts/security_critical_files.txt"
run_case 1 "no list to compare against"

fixture
printf '# every entry commented out\n' > "$WORK/scripts/security_critical_files.txt"
run_case 1 "an empty list, which would otherwise accept any baseline"

echo
echo "summary: pass=$PASS fail=$FAIL"
[ "$FAIL" -eq 0 ]
