"""JSONL audit log for every verdict — append-only with size rotation.

Persisted to ``$XDG_STATE_HOME/ralf-free/audit.jsonl`` (defaults to
``~/.local/state/ralf-free/audit.jsonl``). Rotates to ``audit.jsonl.1``
when the active file exceeds :data:`MAX_BYTES` (10 MB).

Entry schema (free-form dict, but the hook and CLI expect these keys)::

    {
      "ts": "2026-04-08T09:30:00.000000+00:00",  # ISO8601 UTC
      "tool": "Bash" | "Write" | "Edit" | "NotebookEdit",
      "decision": "allow" | "review" | "block",
      "score": int,
      "reason": str,
      "command": str | null,     # for Bash
      "file_path": str | null,   # for Write/Edit/NotebookEdit
      "rule_hits": [rule_id, ...]
    }
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import tempfile
from pathlib import Path
from typing import Any

MAX_BYTES = 10 * 1024 * 1024  # 10 MB — rotate when active log exceeds this


def _state_dir() -> Path:
    xdg = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    return Path(xdg) / "ralf-free"


DEFAULT_LOG_PATH = _state_dir() / "audit.jsonl"


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="microseconds")


def append(
    entry: dict[str, Any],
    *,
    path: Path | None = None,
    max_bytes: int = MAX_BYTES,
) -> None:
    """Append one JSONL line to the audit log. Rotates if the active
    file already exceeds ``max_bytes``.

    Rotation scheme: ``audit.jsonl`` → ``audit.jsonl.1``, replacing any
    existing ``.1`` file. One generation of history is kept.

    The ``ts`` key is injected if missing so callers don't have to
    format timestamps themselves.
    """
    log_path = Path(path) if path else DEFAULT_LOG_PATH
    log_path.parent.mkdir(parents=True, exist_ok=True)

    # Inject timestamp
    if "ts" not in entry:
        entry = {"ts": _now_iso(), **entry}

    # Rotate if over size cap BEFORE writing this line.
    try:
        if log_path.exists() and log_path.stat().st_size >= max_bytes:
            _rotate(log_path)
    except OSError:
        pass

    line = json.dumps(entry, ensure_ascii=False) + "\n"
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(line)


def _rotate(log_path: Path) -> None:
    """Move the active log to ``.1``, overwriting any previous rotation."""
    rotated = log_path.with_suffix(log_path.suffix + ".1")
    try:
        if rotated.exists():
            rotated.unlink()
    except OSError:
        pass
    os.replace(log_path, rotated)


def tail(n: int, *, path: Path | None = None) -> list[dict[str, Any]]:
    """Return the last ``n`` entries from the active log.

    Returns an empty list if the file doesn't exist. Malformed lines
    are skipped silently (the hook may get killed mid-write under the
    systemd timeout).
    """
    log_path = Path(path) if path else DEFAULT_LOG_PATH
    if not log_path.exists() or n <= 0:
        return []
    out: list[dict[str, Any]] = []
    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()
    for line in lines[-n:]:
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
            if isinstance(entry, dict):
                out.append(entry)
        except json.JSONDecodeError:
            continue
    return out
