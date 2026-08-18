#!/usr/bin/env bash
# Unit test for scripts/check_workflow_triggers.py.
#
# The checker replaced a regex that an independent verifier rejected twice, both
# times for false positives on legitimate workflows. Those exact cases are the
# first three below (probe L, probe D, probe G) and they are the reason this
# file exists: the failure mode being guarded against is not "misses an attack",
# it is "reddens a release-blocking gate for someone who wrote the safe thing".
#
# The detection cases include every form the old regex missed, and the .yaml
# extension, which is the finding itself.
#
# Run: bash scripts/test_check_workflow_triggers.sh
set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECKER="$REPO_ROOT/scripts/check_workflow_triggers.py"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0

# run_case <expected-exit> <filename> <description> ; body on stdin
run_case() {
    local want="$1" fname="$2" desc="$3"
    rm -rf "$WORK/.github/workflows"
    mkdir -p "$WORK/.github/workflows"
    cat > "$WORK/.github/workflows/$fname"
    local got out
    out="$(cd "$WORK" && python3 "$CHECKER" 2>&1)"
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

echo "must stay CLEAN -- legitimate workflows that name the token (the two rejected rounds)"

run_case 0 w.yml "probe L: the defensive \`if:\` idiom" <<'YAML'
name: x
on:
  pull_request:
jobs:
  build:
    if: github.event_name != 'pull_request_target'
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
YAML

run_case 0 w.yml "probe D: policy declaration as a block-sequence item" <<'YAML'
name: x
on: [push]
jobs:
  policy:
    runs-on: ubuntu-latest
    steps:
      - uses: some/policy-action@v1
        with:
          deny-triggers:
            - pull_request_target
            - workflow_run
YAML

run_case 0 w.yml "probe G: the token inside an env block scalar" <<'YAML'
name: x
on:
  push:
    branches: [main]
env:
  BANNED_TRIGGERS: |
    pull_request_target
    workflow_run
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
YAML

run_case 0 w.yml "a comment mentioning the token (ci.yml:3 is exactly this)" <<'YAML'
# Triggers: push to main + pull_request (NOT pull_request_target -- F4-X10).
name: x
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
YAML

run_case 0 w.yml "a job whose id contains the token" <<'YAML'
name: x
on: [push]
jobs:
  guard_against_pull_request_target:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
YAML

echo
echo "must be DETECTED -- every form, including the ones the old regex missed"

run_case 1 w.yml "mapping form (the only one the old regex caught)" <<'YAML'
name: x
on:
  pull_request_target:
    types: [opened]
jobs: {}
YAML

run_case 1 w.yml "flow sequence" <<'YAML'
name: x
on: [push, pull_request_target]
jobs: {}
YAML

run_case 1 w.yml "flow sequence, quoted items" <<'YAML'
name: x
on: ["push", "pull_request_target"]
jobs: {}
YAML

run_case 1 w.yml "inline mapping" <<'YAML'
name: x
on: {pull_request_target: {types: [opened]}}
jobs: {}
YAML

run_case 1 w.yml "flow sequence split across lines" <<'YAML'
name: x
on: [
  push,
  pull_request_target
]
jobs: {}
YAML

run_case 1 w.yml "block sequence under on:" <<'YAML'
name: x
on:
  - push
  - pull_request_target
jobs: {}
YAML

run_case 1 w.yml "scalar form" <<'YAML'
name: x
on: pull_request_target
jobs: {}
YAML

run_case 1 w.yml "quoted key, dodging the YAML 1.1 boolean coercion" <<'YAML'
name: x
"on":
  pull_request_target:
jobs: {}
YAML

run_case 1 w.yml "capitalised key (YAML 1.1 coerces On/ON to true as well)" <<'YAML'
name: x
On:
  pull_request_target:
jobs: {}
YAML

run_case 1 w.yaml "THE FINDING: same declaration in a .yaml file" <<'YAML'
name: x
on:
  pull_request_target:
    types: [opened]
jobs: {}
YAML

echo
echo "must FAIL CLOSED -- a gate that cannot run must not report a pass"

run_case 2 w.yml "unparseable YAML" <<'YAML'
name: x
on: [push
  this is not: valid: yaml: at all
	- and a tab
YAML

echo
echo "summary: pass=$PASS fail=$FAIL"
[ "$FAIL" -eq 0 ]
