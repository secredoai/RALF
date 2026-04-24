"""Tests for :mod:`ralf.adapters.claude_code` — adapter-level coverage.

The legacy ``test_shared_hook.py`` covers the verdict / decision side
via the shim (including write-blocking on SQLi/CWE-78/CWE-502). This
file specifically covers the audit-log wiring and the pause sentinel
— both of which are NEW in the adapter refactor.
"""
from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from ralf.adapters import claude_code
from ralf.shared.audit_log import tail
from ralf.shared.verdict_engine import reset_cache


@pytest.fixture(autouse=True)
def _isolated_state(tmp_path: Path, monkeypatch):
    """Redirect XDG dirs to tmp_path so tests don't pollute the user's home."""
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    # Reload audit_log so DEFAULT_LOG_PATH picks up the new XDG_STATE_HOME.
    import importlib
    from ralf.shared import audit_log
    importlib.reload(audit_log)
    reset_cache()
    yield
    reset_cache()


def _drive(monkeypatch, payload: dict) -> tuple[int, str]:
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))
    out = io.StringIO()
    monkeypatch.setattr("sys.stdout", out)
    rc = claude_code.run()
    return rc, out.getvalue()


def _audit_log_path(tmp_path: Path) -> Path:
    return tmp_path / "state" / "ralf-free" / "audit.jsonl"


# ---------------------------------------------------------------------
# audit log wiring
# ---------------------------------------------------------------------


def test_bash_allow_writes_audit_entry(monkeypatch, tmp_path: Path) -> None:
    rc, _ = _drive(monkeypatch, {
        "tool_name": "Bash", "tool_input": {"command": "ls /tmp"},
    })
    assert rc == 0
    entries = tail(10, path=_audit_log_path(tmp_path))
    assert len(entries) == 1
    assert entries[0]["agent"] == "claude_code"
    assert entries[0]["tool"] == "Bash"
    assert entries[0]["command"] == "ls /tmp"
    assert entries[0]["decision"] == "allow"
    assert "session_id" in entries[0]


def test_bash_block_writes_audit_entry(monkeypatch, tmp_path: Path) -> None:
    cmd = "".join(["cat /etc/shad", "ow"])
    rc, _ = _drive(monkeypatch, {
        "tool_name": "Bash", "tool_input": {"command": cmd},
    })
    assert rc == 0
    entries = tail(10, path=_audit_log_path(tmp_path))
    assert len(entries) == 1
    assert entries[0]["decision"] == "block"
    assert entries[0]["score"] >= 10


def test_write_allow_writes_audit_entry(monkeypatch, tmp_path: Path) -> None:
    """Benign Write content should produce an allow audit entry.

    (Block-path coverage for Write lives in test_shared_hook.py.)
    """
    rc, out = _drive(monkeypatch, {
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/tmp/x.py",
            "content": "def add(a, b):\n    return a + b\n",
        },
    })
    assert rc == 0
    assert out == ""
    entries = tail(10, path=_audit_log_path(tmp_path))
    assert len(entries) == 1
    assert entries[0]["agent"] == "claude_code"
    assert entries[0]["tool"] == "Write"
    assert entries[0]["file_path"] == "/tmp/x.py"
    assert entries[0]["decision"] == "allow"
    assert entries[0]["command"] == ""  # file-write events have empty command


def test_empty_command_writes_no_audit_entry(monkeypatch, tmp_path: Path) -> None:
    """Empty/whitespace command early-returns BEFORE the audit write."""
    _drive(monkeypatch, {"tool_name": "Bash", "tool_input": {"command": "  "}})
    entries = tail(10, path=_audit_log_path(tmp_path))
    assert entries == []


# ---------------------------------------------------------------------
# pause sentinel
# ---------------------------------------------------------------------


def test_pause_sentinel_short_circuits_bash(monkeypatch, tmp_path: Path) -> None:
    sentinel = tmp_path / "cache" / "ralf-free" / "paused"
    sentinel.parent.mkdir(parents=True, exist_ok=True)
    sentinel.touch()

    rc, out = _drive(monkeypatch, {
        "tool_name": "Bash",
        "tool_input": {"command": "".join(["cat /etc/shad", "ow"])},
    })
    assert rc == 0
    # No deny JSON should be emitted while paused
    assert out == ""

    entries = tail(10, path=_audit_log_path(tmp_path))
    assert len(entries) == 1
    assert entries[0]["decision"] == "paused"
    assert entries[0]["score"] == -1


def test_pause_sentinel_short_circuits_write(monkeypatch, tmp_path: Path) -> None:
    """Pause short-circuits BEFORE scoring, so any non-empty content works."""
    sentinel = tmp_path / "cache" / "ralf-free" / "paused"
    sentinel.parent.mkdir(parents=True, exist_ok=True)
    sentinel.touch()

    rc, out = _drive(monkeypatch, {
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/tmp/x.py",
            "content": "def add(a, b):\n    return a + b\n",
        },
    })
    assert rc == 0
    assert out == ""
    entries = tail(10, path=_audit_log_path(tmp_path))
    assert len(entries) == 1
    assert entries[0]["decision"] == "paused"
    assert entries[0]["tool"] == "Write"
    assert entries[0]["file_path"] == "/tmp/x.py"
