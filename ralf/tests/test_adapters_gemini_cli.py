"""Tests for :mod:`ralf.adapters.gemini_cli`."""
from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from ralf.adapters import gemini_cli
from ralf.shared.audit_log import tail
from ralf.shared.verdict_engine import reset_cache


@pytest.fixture(autouse=True)
def _isolated_state(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
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
    rc = gemini_cli.run()
    return rc, out.getvalue()


def _audit_path(tmp_path: Path) -> Path:
    return tmp_path / "state" / "ralf-free" / "audit.jsonl"


# ---------------------------------------------------------------------
# tool name normalization
# ---------------------------------------------------------------------


def test_normalize_known_tools() -> None:
    assert gemini_cli._normalize_tool("run_shell") == "Bash"
    assert gemini_cli._normalize_tool("RUN_SHELL") == "Bash"
    assert gemini_cli._normalize_tool("write_file") == "Write"
    assert gemini_cli._normalize_tool("replace") == "Edit"
    assert gemini_cli._normalize_tool("edit") == "Edit"


def test_normalize_unknown_returns_empty() -> None:
    assert gemini_cli._normalize_tool("magic") == ""
    assert gemini_cli._normalize_tool("") == ""


# ---------------------------------------------------------------------
# payload shape extraction
# ---------------------------------------------------------------------


def test_extract_claude_compatible_shape() -> None:
    name, args = gemini_cli._extract_tool_call({
        "tool_name": "run_shell", "tool_input": {"command": "ls"},
    })
    assert name == "run_shell"
    assert args == {"command": "ls"}


def test_extract_gemini_native_shape() -> None:
    name, args = gemini_cli._extract_tool_call({
        "toolCall": {"name": "run_shell", "args": {"command": "ls"}},
    })
    assert name == "run_shell"
    assert args == {"command": "ls"}


def test_extract_handles_snake_case_tool_call() -> None:
    name, args = gemini_cli._extract_tool_call({
        "tool_call": {"name": "write_file", "input": {"file_path": "/tmp/x"}},
    })
    assert name == "write_file"
    assert args == {"file_path": "/tmp/x"}


def test_extract_returns_empty_when_no_tool() -> None:
    assert gemini_cli._extract_tool_call({}) == ("", {})
    assert gemini_cli._extract_tool_call({"random": "noise"}) == ("", {})


# ---------------------------------------------------------------------
# end-to-end dispatch via run()
# ---------------------------------------------------------------------


def test_run_bash_allow_writes_audit(monkeypatch, tmp_path: Path) -> None:
    rc, out = _drive(monkeypatch, {
        "toolCall": {"name": "run_shell", "args": {"command": "ls /tmp"}},
    })
    assert rc == 0
    assert out == ""
    entries = tail(10, path=_audit_path(tmp_path))
    assert len(entries) == 1
    assert entries[0]["agent"] == "gemini_cli"
    assert entries[0]["tool"] == "Bash"
    assert entries[0]["command"] == "ls /tmp"
    assert entries[0]["decision"] == "allow"


def test_run_bash_block_emits_gemini_deny_shape(monkeypatch, tmp_path: Path) -> None:
    cmd = "".join(["cat /etc/shad", "ow"])
    rc, out = _drive(monkeypatch, {
        "toolCall": {"name": "run_shell", "args": {"command": cmd}},
    })
    assert rc == 0
    decision = json.loads(out)
    assert decision["decision"] == "deny"
    assert "RALF-free BLOCK (bash)" in decision["reason"]
    entries = tail(10, path=_audit_path(tmp_path))
    assert entries[0]["agent"] == "gemini_cli"
    assert entries[0]["decision"] == "block"


def test_run_write_allow(monkeypatch, tmp_path: Path) -> None:
    rc, out = _drive(monkeypatch, {
        "toolCall": {
            "name": "write_file",
            "args": {
                "file_path": "/tmp/x.py",
                "content": "def add(a, b):\n    return a + b\n",
            },
        },
    })
    assert rc == 0
    assert out == ""
    entries = tail(10, path=_audit_path(tmp_path))
    assert len(entries) == 1
    assert entries[0]["agent"] == "gemini_cli"
    assert entries[0]["tool"] == "Write"
    assert entries[0]["file_path"] == "/tmp/x.py"


def test_run_replace_maps_to_edit(monkeypatch, tmp_path: Path) -> None:
    rc, _ = _drive(monkeypatch, {
        "toolCall": {
            "name": "replace",
            "args": {
                "file_path": "/tmp/x.py",
                "new_string": "print('hi')\n",
            },
        },
    })
    assert rc == 0
    entries = tail(10, path=_audit_path(tmp_path))
    assert len(entries) == 1
    assert entries[0]["tool"] == "Edit"


def test_run_unknown_tool_no_audit(monkeypatch, tmp_path: Path) -> None:
    rc, out = _drive(monkeypatch, {
        "toolCall": {"name": "search_web", "args": {"q": "x"}},
    })
    assert rc == 0
    assert out == ""
    assert tail(10, path=_audit_path(tmp_path)) == []


def test_run_claude_compatible_shape_works(monkeypatch, tmp_path: Path) -> None:
    """Both shapes go through the same dispatcher."""
    rc, _ = _drive(monkeypatch, {
        "tool_name": "run_shell",
        "tool_input": {"command": "ls /tmp"},
    })
    assert rc == 0
    entries = tail(10, path=_audit_path(tmp_path))
    assert len(entries) == 1
    assert entries[0]["agent"] == "gemini_cli"


def test_run_pause_sentinel_short_circuits(monkeypatch, tmp_path: Path) -> None:
    sentinel = tmp_path / "cache" / "ralf-free" / "paused"
    sentinel.parent.mkdir(parents=True, exist_ok=True)
    sentinel.touch()

    rc, out = _drive(monkeypatch, {
        "toolCall": {
            "name": "run_shell",
            "args": {"command": "".join(["cat /etc/shad", "ow"])},
        },
    })
    assert rc == 0
    assert out == ""
    entries = tail(10, path=_audit_path(tmp_path))
    assert entries[0]["decision"] == "paused"
    assert entries[0]["agent"] == "gemini_cli"
