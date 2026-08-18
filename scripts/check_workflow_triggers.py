#!/usr/bin/env python3
"""Fail if any GitHub Actions workflow declares a forbidden trigger.

Forbidden today: `pull_request_target`. It runs with the base repository's
secrets and a write-capable token while checking out a fork's proposed code,
so a workflow that combines it with a checkout of `github.event.pull_request`
hands an attacker the repository.

WHY THIS IS A PARSER AND NOT A REGEX
------------------------------------
The check it replaces was `grep -lE '^\\s*-?\\s*pull_request_target\\s*:'` over
`.github/workflows/*.yml`. Two rounds of trying to widen that regex were
rejected by an independent verifier, both times for the same reason: a text
match cannot tell a *trigger declaration* from the token merely appearing.
The concrete workflows that broke, all of which declare no such trigger:

  * `if: github.event_name != 'pull_request_target'` -- the *defensive* idiom.
    The author asserting the job does not run under it. A release-blocking
    gate that reddens CI for writing the safe thing is worse than the hole.
  * `with: {deny-triggers: [pull_request_target]}` -- a policy declaration
    passed to some other tool, as a block-sequence item.
  * `env: {BANNED_TRIGGERS: "...pull_request_target..."}` -- the token inside
    a block scalar.

And the forms the old regex missed, because it required a trailing colon:

  * `on: [push, pull_request_target]`          (flow sequence)
  * `on: ["push", "pull_request_target"]`      (quoted items)
  * `on: {pull_request_target: {types: [opened]}}`  (inline mapping)
  * a flow sequence split across lines

Parsing the document decides all seven correctly at once, because it asks the
only question that matters -- what are the keys of the top-level trigger
block -- instead of guessing from surrounding characters.

THE TRAP, WHICH IS WHY THIS IS TESTED
-------------------------------------
GitHub's `on:` is a YAML 1.1 boolean. PyYAML is a YAML 1.1 parser, so

    yaml.safe_load("on:\\n  push:\\n")  ->  {True: {'push': None}}

The key is `True`, not `'on'`. An implementation that reaches for
`doc.get('on')` finds nothing and reports every workflow clean -- a silent
fail-open, strictly worse than the regex it replaced, and invisible because
the check still prints a pass. `_trigger_block` handles it and
`tests/test_check_workflow_triggers.sh` pins it.

FAIL-CLOSED
-----------
Unparseable file, unreadable file, and missing PyYAML are all errors, not
passes. A gate that cannot run must say so; the alternative is a green tick
that means nothing. Exit codes: 0 clean, 1 forbidden trigger found, 2 cannot
check.
"""
from __future__ import annotations

import sys
from pathlib import Path

FORBIDDEN = {"pull_request_target"}
WORKFLOW_DIR = Path(".github/workflows")
# GitHub accepts either extension. Reading only one of them was the finding.
SUFFIXES = (".yml", ".yaml")


def _trigger_block(doc):
    """Return the value of the workflow's trigger key, or None.

    Accepts `True` (bare `on:`, which YAML 1.1 renders as a boolean), and the
    quoted spellings `'on'` / `"On"` / `"ON"` that authors use precisely to
    dodge that coercion.
    """
    if not isinstance(doc, dict):
        return None
    for key, value in doc.items():
        if key is True:
            return value
        if isinstance(key, str) and key.lower() == "on":
            return value
    return None


def _declared_triggers(block) -> set[str]:
    """Normalise every form a trigger block can take into a set of names."""
    if isinstance(block, str):
        return {block}
    if isinstance(block, list):
        # `on: [push, pull_request_target]`, quoted or not, one line or many.
        return {item for item in block if isinstance(item, str)}
    if isinstance(block, dict):
        # `on: {push: ..., pull_request_target: {types: [...]}}`, block or flow.
        return {key for key in block if isinstance(key, str)}
    return set()


def main() -> int:
    try:
        import yaml
    except ImportError:
        print(
            "check_workflow_triggers: cannot check -- PyYAML is not installed.\n"
            "  This gate parses workflows rather than grepping them; without a\n"
            "  parser it has nothing to say, and reporting a pass would be a\n"
            "  lie. Install it (pip install PyYAML / apt install python3-yaml).",
            file=sys.stderr,
        )
        return 2

    if not WORKFLOW_DIR.is_dir():
        print("check_workflow_triggers: no .github/workflows directory; nothing to check")
        return 0

    files = sorted(
        p for p in WORKFLOW_DIR.iterdir()
        if p.is_file() and p.suffix in SUFFIXES
    )
    if not files:
        print("check_workflow_triggers: no workflow files; nothing to check")
        return 0

    offenders: list[str] = []
    unreadable: list[str] = []

    for path in files:
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception as exc:  # parse error, encoding error, I/O error
            unreadable.append(f"{path}: {type(exc).__name__}: {exc}")
            continue
        declared = _declared_triggers(_trigger_block(doc))
        for name in sorted(declared & FORBIDDEN):
            offenders.append(f"{path}: declares trigger `{name}`")

    if unreadable:
        print("check_workflow_triggers: cannot check the following:", file=sys.stderr)
        for line in unreadable:
            print(f"  {line}", file=sys.stderr)
        return 2

    if offenders:
        print("check_workflow_triggers: forbidden trigger declared:", file=sys.stderr)
        for line in offenders:
            print(f"  {line}", file=sys.stderr)
        return 1

    names = ", ".join(sorted(FORBIDDEN))
    print(f"check_workflow_triggers: {len(files)} workflow(s), none declare: {names}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
