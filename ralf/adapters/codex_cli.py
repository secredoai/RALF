"""Codex CLI rules adapter — read-only sync from ``~/.codex/rules/*.rules``.

The Codex CLI's rule file uses a Python-ish DSL whose only relevant
form (as of Apr 2026) is::

    prefix_rule(pattern=["curl", "--proto", "=https", ...], decision="allow")

We do NOT execute or ``eval`` the file — that would be a remote-code-
execution risk if Codex's rules ever start sourcing from a public URL.
Instead we extract the ``pattern=[...]`` and ``decision="..."`` parts
with regex and parse the list with :func:`ast.literal_eval`.

Direction: read-only. We translate Codex rules into RALF audit events
and ``app_control.yaml`` entries, but we never write back to Codex's
rule file. The plan explicitly defers the write direction because
``decision="deny"`` is unverified in Codex's DSL.

Public API:

    - :func:`parse_rules_file` — pure parser, returns ``list[CodexRule]``.
    - :func:`import_codex_rules` — full pipeline: parse → audit log →
      app_control. Idempotent: re-importing the same file is a no-op
      (the app_control is a set; the audit log gets new entries each
      time but with consistent reasons).
    - :func:`watch_codex_rules` — mtime poll loop. Foreground or thread.
"""
from __future__ import annotations

import ast
import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from ralf.core.audit import record
from ralf.core.event import CommonEvent

# ----------------------------------------------------------------------
# parser
# ----------------------------------------------------------------------


@dataclass
class CodexRule:
    pattern: list[str]
    decision: str  # "allow" | "deny" | "ask" — Codex's vocabulary
    line_no: int


# Match ``prefix_rule(pattern=[...], decision="...")``. Tolerates extra
# whitespace and either single or double quotes around ``decision``.
_RULE_RE = re.compile(
    r"""
    prefix_rule\s*\(
        \s*pattern\s*=\s*(?P<pattern>\[[^\]]*\])
        \s*,\s*
        decision\s*=\s*(?P<dq>['"])(?P<decision>[^'"]*)(?P=dq)
        \s*\)
    """,
    re.VERBOSE,
)


def _default_rules_path() -> Path:
    return Path(os.path.expanduser("~/.codex/rules/default.rules"))


def parse_rules_file(path: Path) -> list[CodexRule]:
    """Parse a Codex rules file. Returns one :class:`CodexRule` per match.

    Lines that don't match the ``prefix_rule(...)`` form are skipped
    silently — Codex may add other rule types in the future and we
    don't want a parser failure to break the sync. Lines that match
    the regex but whose ``pattern=[...]`` fails ``ast.literal_eval``
    are also skipped (logged on stderr).
    """
    if not path.exists():
        return []

    out: list[CodexRule] = []
    text = path.read_text(encoding="utf-8", errors="replace")
    for line_no, line in enumerate(text.splitlines(), start=1):
        match = _RULE_RE.search(line)
        if not match:
            continue
        pattern_src = match.group("pattern")
        decision = match.group("decision")
        try:
            pattern = ast.literal_eval(pattern_src)
        except (ValueError, SyntaxError) as exc:
            print(
                f"codex_cli: skipping line {line_no}: cannot parse "
                f"pattern={pattern_src!r}: {exc}",
                file=sys.stderr,
            )
            continue
        if not isinstance(pattern, list) or not all(isinstance(p, str) for p in pattern):
            continue
        if not pattern:
            continue
        out.append(CodexRule(pattern=pattern, decision=decision, line_no=line_no))
    return out


# ----------------------------------------------------------------------
# Codex → RALF translation
# ----------------------------------------------------------------------


def _codex_to_ralf_decision(codex_decision: str) -> str:
    """Translate Codex's decision vocabulary to RALF's."""
    return {
        "allow": "allow",
        "deny": "block",
        "ask": "review",
    }.get(codex_decision, "review")


def _first_token_basename(rule: CodexRule) -> str:
    """The first argv token, lowered, basename only.

    For ``["bash", "-lc", "..."]`` this returns ``bash``. The
    app_control list is keyed on basenames so ``/usr/bin/curl`` and
    ``curl`` map to the same entry.
    """
    if not rule.pattern:
        return ""
    head = rule.pattern[0]
    return head.rsplit("/", 1)[-1]


def import_codex_rules(
    path: Path | None = None,
    *,
    audit_path: Path | None = None,
    app_control_path: Path | None = None,
    record_audit: bool = True,
) -> tuple[int, int]:
    """Read ``path``, write audit events + app_control entries.

    Returns ``(rules_imported, binaries_added_to_app_control)``. Both
    numbers are useful for the CLI's status print.

    Idempotent: app_control is a set, so re-running this function on
    an unchanged file does not add duplicate entries. Audit-log
    entries DO accumulate per run (one per rule, per sync) — that's
    intentional, so the dashboard's history view shows when each
    sync happened.
    """
    rules_path = path or _default_rules_path()
    rules = parse_rules_file(rules_path)
    if not rules:
        return 0, 0

    # Lazy import so the codex adapter doesn't pull in the YAML loader
    # for callers that only want to parse.
    from ralf.shared.app_control import AppControl, AppDecision

    ac = AppControl(app_control_path) if app_control_path else AppControl()
    decision_map = {
        "allow": AppDecision.ALLOW,
        "block": AppDecision.BLOCK,
        "review": AppDecision.REVIEW,
    }

    added = 0
    for rule in rules:
        ralf_decision = _codex_to_ralf_decision(rule.decision)
        token = _first_token_basename(rule)

        # Add to app_control if we have a recognizable first token.
        if token:
            existing = ac.check(token)
            target = decision_map.get(ralf_decision, AppDecision.UNKNOWN)
            # Only mutate if the entry is missing or differs from target.
            if existing != target and target != AppDecision.UNKNOWN:
                ac.add(token, target)
                added += 1

        if record_audit:
            command = " ".join(rule.pattern)
            record(
                CommonEvent(
                    agent="codex_cli",
                    session_id="codex-rules-sync",
                    tool="Bash",  # Codex prefix_rules gate Bash invocations
                    command=command,
                    file_path="",
                    decision=ralf_decision,
                    score=0,
                    reason=(
                        f"imported from {rules_path} "
                        f"(line {rule.line_no}, codex_decision={rule.decision})"
                    ),
                    rule_hits=[],
                ),
                path=audit_path,
            )

    return len(rules), added


# ----------------------------------------------------------------------
# mtime watcher
# ----------------------------------------------------------------------


def _mtime_or_zero(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def watch_codex_rules(
    path: Path | None = None,
    *,
    interval: float = 1.0,
    iterations: int | None = None,
    audit_path: Path | None = None,
    app_control_path: Path | None = None,
    on_change=None,
) -> Iterator[tuple[int, int]]:
    """mtime-poll loop. Yields ``(rules, added)`` after each re-import.

    The first iteration always imports (mtime != last_mtime). After
    that, only changes trigger a re-import.

    Pass ``iterations=N`` to bound the loop for tests; ``None`` runs
    forever. ``on_change`` is an optional callback receiving the
    same tuple yielded.

    ``audit_path`` and ``app_control_path`` are forwarded to
    :func:`import_codex_rules` so tests can isolate state without
    reloading the ``ralf.shared.app_control`` module (which breaks
    enum identity for any test importing ``AppDecision`` directly).
    """
    rules_path = path or _default_rules_path()
    last_mtime = -1.0
    count = 0
    while iterations is None or count < iterations:
        current = _mtime_or_zero(rules_path)
        if current != last_mtime:
            result = import_codex_rules(
                rules_path,
                audit_path=audit_path,
                app_control_path=app_control_path,
            )
            last_mtime = current
            if on_change is not None:
                on_change(result)
            yield result
        count += 1
        if iterations is None or count < iterations:
            time.sleep(interval)
