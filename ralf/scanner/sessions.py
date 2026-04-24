"""Rogue session detection + Runtime Shield (watch mode).

Batch-scans past agent sessions for attack patterns using the existing
score_command() engine. Optionally runs continuously, alerting on
PASS->FAIL transitions.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

from ralf.scanner import CheckResult, ScanReport
from ralf.scanner.checks import register

log = logging.getLogger(__name__)

_PLAT = ("linux", "darwin")
_CAT = "session"
_HOME = Path.home()

# Threshold for flagging a command as rogue (same as verdict_engine.BLOCK_THRESHOLD).
_BLOCK_THRESHOLD = 10


def _score_command_safe(command: str) -> int:
    """Score a command, returning 0 on any error."""
    try:
        from ralf.shared.verdict_engine import score_command
        verdict = score_command(command)
        return verdict.score
    except Exception:
        return 0


# ── Session file discovery ─────────────────────────────────────────────


def _claude_session_files(days: int) -> list[Path]:
    """Find Claude Code session JSONL files modified within `days`."""
    projects = _HOME / ".claude" / "projects"
    if not projects.exists():
        return []
    cutoff = time.time() - (days * 86400)
    files: list[Path] = []
    try:
        for d in projects.iterdir():
            if not d.is_dir():
                continue
            for f in d.iterdir():
                if f.suffix == ".jsonl":
                    try:
                        if f.stat().st_mtime >= cutoff:
                            files.append(f)
                    except OSError:
                        pass
    except (OSError, PermissionError):
        pass
    return files


def _codex_session_files(days: int) -> list[Path]:
    """Find Codex session files modified within `days`."""
    codex_dirs = [
        _HOME / ".codex" / "sessions",
        _HOME / ".codex",
    ]
    cutoff = time.time() - (days * 86400)
    files: list[Path] = []
    for base in codex_dirs:
        if not base.exists():
            continue
        try:
            for root, _dirs, filenames in os.walk(str(base)):
                for name in filenames:
                    if name.endswith((".jsonl", ".json")):
                        p = Path(root) / name
                        try:
                            if p.stat().st_mtime >= cutoff:
                                files.append(p)
                        except OSError:
                            pass
        except (OSError, PermissionError):
            pass
    return files


def _gemini_session_files(days: int) -> list[Path]:
    """Find Gemini session files modified within `days`."""
    sessions = _HOME / ".gemini" / "sessions"
    if not sessions.exists():
        return []
    cutoff = time.time() - (days * 86400)
    files: list[Path] = []
    try:
        for f in sessions.rglob("*.json*"):
            try:
                if f.stat().st_mtime >= cutoff:
                    files.append(f)
            except OSError:
                pass
    except (OSError, PermissionError):
        pass
    return files


# ── Command extraction from session files ──────────────────────────────


_BASH_CMD_RE = re.compile(r'"command"\s*:\s*"([^"]+)"')


def _extract_commands_from_jsonl(path: Path, limit: int = 2000) -> list[str]:
    """Extract Bash commands from a JSONL session transcript."""
    commands: list[str] = []
    try:
        lines = path.read_text(errors="replace").splitlines()[-limit:]
    except (OSError, PermissionError):
        return commands
    for line in lines:
        if "Bash" not in line and "command" not in line:
            continue
        try:
            data = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            # Try regex fallback for partial lines
            match = _BASH_CMD_RE.search(line)
            if match:
                commands.append(match.group(1))
            continue

        # Claude Code format: tool_name="Bash", tool_input.command
        cmd = _extract_cmd_from_obj(data)
        if cmd:
            commands.append(cmd)
    return commands


def _extract_cmd_from_obj(obj: dict | list) -> str:
    """Recursively extract a command string from a session object."""
    if isinstance(obj, dict):
        # Direct command field
        if obj.get("tool_name") == "Bash" or obj.get("type") == "tool_use":
            inp = obj.get("tool_input") or obj.get("input") or {}
            if isinstance(inp, dict) and "command" in inp:
                return inp["command"]
        # Recurse into nested dicts
        for v in obj.values():
            if isinstance(v, (dict, list)):
                result = _extract_cmd_from_obj(v)
                if result:
                    return result
    elif isinstance(obj, list):
        for item in obj[:50]:  # cap recursion
            if isinstance(item, (dict, list)):
                result = _extract_cmd_from_obj(item)
                if result:
                    return result
    return ""


# ── Session audit ──────────────────────────────────────────────────────


def audit_sessions(
    agent: str = "all",
    days: int = 7,
) -> list[CheckResult]:
    """Scan past agent sessions for rogue command patterns.

    Uses score_command() to batch-score every Bash command in recent
    session transcripts. Any command scoring >= BLOCK_THRESHOLD is flagged.

    Args:
        agent: "all", "claude", "codex", or "gemini".
        days: Look back window in days.

    Returns:
        List of CheckResult (one per agent scanned).
    """
    results: list[CheckResult] = []
    agents = (
        ["claude", "codex", "gemini"] if agent == "all"
        else [agent]
    )

    finders = {
        "claude": _claude_session_files,
        "codex": _codex_session_files,
        "gemini": _gemini_session_files,
    }

    for a in agents:
        finder = finders.get(a)
        if finder is None:
            continue
        files = finder(days)
        if not files:
            results.append(CheckResult(
                check_id=f"session_{a}",
                name=f"{a.title()} Session Audit",
                category="session",
                status="pass",
                detail=f"No {a} session files found in last {days} days",
                remediation="",
                severity="high",
                score_delta=0,
            ))
            continue

        rogue_commands: list[str] = []
        total_commands = 0
        for f in files[:50]:  # cap file count
            commands = _extract_commands_from_jsonl(f)
            total_commands += len(commands)
            for cmd in commands:
                score = _score_command_safe(cmd)
                if score >= _BLOCK_THRESHOLD:
                    rogue_commands.append(
                        f"[score={score}] {cmd[:120]}"
                    )
                    if len(rogue_commands) >= 20:
                        break
            if len(rogue_commands) >= 20:
                break

        ok = len(rogue_commands) == 0
        detail = (
            f"Scanned {total_commands} commands in {len(files)} {a} session(s): no rogue commands"
            if ok else
            f"{len(rogue_commands)} rogue command(s) in {total_commands} total across {len(files)} file(s)"
        )
        if rogue_commands:
            detail += "\n" + "\n".join(f"  - {r}" for r in rogue_commands[:10])

        results.append(CheckResult(
            check_id=f"session_{a}",
            name=f"{a.title()} Session Audit",
            category="session",
            status="pass" if ok else "fail",
            detail=detail,
            remediation="" if ok else f"Review flagged commands; consider rotating exposed credentials",
            severity="high",
            score_delta=0 if ok else -10,
        ))

    return results


# ── Runtime Shield (watch mode) ────────────────────────────────────────


def _cache_dir() -> Path:
    xdg = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    return Path(xdg) / "ralf-free"


def _load_last_scan() -> dict[str, str] | None:
    """Load last scan results from cache."""
    cache = _cache_dir() / "last_scan.json"
    if not cache.exists():
        return None
    try:
        return json.loads(cache.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def _save_scan(report: ScanReport) -> None:
    """Save scan results to cache."""
    cache_dir = _cache_dir()
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache = cache_dir / "last_scan.json"
    # Store as {check_id: status}
    data = {r.check_id: r.status for r in report.results}
    data["_score"] = str(report.score)
    data["_grade"] = report.grade
    data["_ts"] = report.ts
    cache.write_text(json.dumps(data, indent=2))


def _diff_results(
    old: dict[str, str],
    new_report: ScanReport,
) -> list[str]:
    """Detect PASS->FAIL and FAIL->PASS transitions."""
    transitions: list[str] = []
    for r in new_report.results:
        old_status = old.get(r.check_id)
        if old_status is None:
            continue
        if old_status != r.status:
            direction = "REGRESSION" if r.status in ("fail", "warn") else "IMPROVEMENT"
            transitions.append(
                f"[{direction}] {r.name}: {old_status.upper()} -> {r.status.upper()}"
            )
    return transitions


def _write_audit_transitions(transitions: list[str]) -> None:
    """Append transitions to audit JSONL for dashboard display."""
    if not transitions:
        return
    audit_path = _cache_dir() / "posture_audit.jsonl"
    _cache_dir().mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).isoformat()
    with open(audit_path, "a") as f:
        for t in transitions:
            f.write(json.dumps({"ts": ts, "event": t}) + "\n")


def watch(interval: int = 300) -> Iterator[tuple[ScanReport, list[str]]]:
    """Re-run scan every `interval` seconds. Yield (report, transitions).

    Usage::

        for report, transitions in watch(interval=300):
            if transitions:
                for t in transitions:
                    print(t)
    """
    from ralf.scanner.runner import run_all_checks

    while True:
        report = run_all_checks()
        old = _load_last_scan()
        transitions: list[str] = []
        if old is not None:
            transitions = _diff_results(old, report)
            _write_audit_transitions(transitions)
        _save_scan(report)
        yield report, transitions
        time.sleep(interval)


# ── Registered checks (for `ralf-free scan` integration) ──────────────
# These run a quick session audit (7-day window) as part of the posture scan.


@register(
    id="session_claude_quick",
    name="Claude Session Quick Audit",
    category="session",
    platforms=_PLAT,
    severity="high",
)
def check_session_claude_quick() -> CheckResult:
    results = audit_sessions(agent="claude", days=7)
    return results[0] if results else CheckResult(
        check_id="session_claude_quick",
        name="Claude Session Quick Audit",
        category="session",
        status="skip",
        detail="No audit results",
        remediation="",
        severity="high",
        score_delta=0,
    )


@register(
    id="session_codex_quick",
    name="Codex Session Quick Audit",
    category="session",
    platforms=_PLAT,
    severity="high",
)
def check_session_codex_quick() -> CheckResult:
    results = audit_sessions(agent="codex", days=7)
    return results[0] if results else CheckResult(
        check_id="session_codex_quick",
        name="Codex Session Quick Audit",
        category="session",
        status="skip",
        detail="No audit results",
        remediation="",
        severity="high",
        score_delta=0,
    )
