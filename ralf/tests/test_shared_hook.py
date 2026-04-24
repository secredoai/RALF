"""Tests for the Claude Code PreToolUse adapter.

Tests drive the hook via pytest's ``capsys`` and ``monkeypatch`` to
inject JSON on stdin and capture the permissionDecision on stdout.
"""
from __future__ import annotations

import io
import json

import pytest

from ralf.adapters import claude_code as hook
from ralf.shared.verdict_engine import reset_cache


def _join(*parts: str) -> str:
    return "".join(parts)


@pytest.fixture(autouse=True)
def _clean_state():
    """Reset verdict engine cache between tests."""
    reset_cache()
    yield
    reset_cache()


def _run_with_payload(monkeypatch, payload: dict) -> tuple[int, str]:
    """Inject a JSON payload on stdin, run hook.run(), return (rc, stdout)."""
    buf = io.StringIO(json.dumps(payload))
    monkeypatch.setattr("sys.stdin", buf)
    stdout = io.StringIO()
    monkeypatch.setattr("sys.stdout", stdout)
    rc = hook.run()
    return rc, stdout.getvalue()


def _parse_decision(stdout: str) -> dict | None:
    """Parse the JSON permissionDecision, or return None if stdout empty."""
    if not stdout.strip():
        return None
    return json.loads(stdout)


# ---------------------------------------------------------------------
# empty / malformed payloads
# ---------------------------------------------------------------------


def test_empty_payload_allow(monkeypatch) -> None:
    rc, out = _run_with_payload(monkeypatch, {})
    assert rc == 0
    assert out == ""  # No permissionDecision → default allow


def test_unknown_tool_allow(monkeypatch) -> None:
    rc, out = _run_with_payload(
        monkeypatch, {"tool_name": "LS", "tool_input": {}}
    )
    assert rc == 0
    assert out == ""


def test_malformed_json_allow(monkeypatch) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("not json"))
    stdout = io.StringIO()
    monkeypatch.setattr("sys.stdout", stdout)
    rc = hook.run()
    assert rc == 0
    assert stdout.getvalue() == ""


# ---------------------------------------------------------------------
# Bash tool — command scoring
# ---------------------------------------------------------------------


def test_bash_benign_ls_allow(monkeypatch) -> None:
    rc, out = _run_with_payload(
        monkeypatch,
        {"tool_name": "Bash", "tool_input": {"command": "ls /tmp"}},
    )
    assert rc == 0
    assert out == ""  # No deny JSON → allow


def test_bash_shadow_read_blocks(monkeypatch) -> None:
    cmd = _join("cat /etc/shad", "ow")
    rc, out = _run_with_payload(
        monkeypatch,
        {"tool_name": "Bash", "tool_input": {"command": cmd}},
    )
    assert rc == 0
    decision = _parse_decision(out)
    assert decision is not None
    assert decision["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "RALF-free BLOCK (bash)" in decision["hookSpecificOutput"]["permissionDecisionReason"]


def test_bash_empty_command_allow(monkeypatch) -> None:
    rc, out = _run_with_payload(
        monkeypatch,
        {"tool_name": "Bash", "tool_input": {"command": ""}},
    )
    assert rc == 0
    assert out == ""


def test_bash_git_status_not_blocked_after_phase2b(monkeypatch) -> None:
    """Regression: ``git status`` was a Phase 2a FPR.

    Phase 2b intent classifier should suppress the GTFOBins binary-only
    hit for git when the subcommand is ``status`` (READ intent).
    """
    rc, out = _run_with_payload(
        monkeypatch,
        {"tool_name": "Bash", "tool_input": {"command": "git status"}},
    )
    assert rc == 0
    # Allowed — no JSON deny emitted
    assert out == ""


# ---------------------------------------------------------------------
# Write tool — file content scoring
# ---------------------------------------------------------------------


def test_write_benign_python_allow(monkeypatch) -> None:
    rc, out = _run_with_payload(
        monkeypatch,
        {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/tmp/x.py",
                "content": "def add(a, b):\n    return a + b\n",
            },
        },
    )
    assert rc == 0
    assert out == ""


def test_write_sql_injection_blocks(monkeypatch) -> None:
    rc, out = _run_with_payload(
        monkeypatch,
        {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/tmp/sql.py",
                "content": 'cursor.execute(f"SELECT * FROM u WHERE id={uid}")',
            },
        },
    )
    assert rc == 0
    decision = _parse_decision(out)
    assert decision is not None
    reason = decision["hookSpecificOutput"]["permissionDecisionReason"]
    assert "RALF-free BLOCK (write)" in reason
    assert "CWE-89" in reason


def test_write_unsafe_yaml_blocks(monkeypatch) -> None:
    rc, out = _run_with_payload(
        monkeypatch,
        {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/tmp/x.py",
                "content": "import yaml; yaml.load(fh)",
            },
        },
    )
    assert rc == 0
    decision = _parse_decision(out)
    assert decision is not None
    assert "CWE-502" in decision["hookSpecificOutput"]["permissionDecisionReason"]


def test_write_yaml_with_loader_allowed(monkeypatch) -> None:
    rc, out = _run_with_payload(
        monkeypatch,
        {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/tmp/x.py",
                "content": "import yaml; yaml.load(fh, Loader=yaml.SafeLoader)",
            },
        },
    )
    assert rc == 0
    assert out == ""


def test_write_empty_content_allow(monkeypatch) -> None:
    rc, out = _run_with_payload(
        monkeypatch,
        {
            "tool_name": "Write",
            "tool_input": {"file_path": "/tmp/x.py", "content": ""},
        },
    )
    assert rc == 0
    assert out == ""


# ---------------------------------------------------------------------
# Edit tool — same path, reads new_string fallback
# ---------------------------------------------------------------------


def test_edit_with_new_string(monkeypatch) -> None:
    rc, out = _run_with_payload(
        monkeypatch,
        {
            "tool_name": "Edit",
            "tool_input": {
                "file_path": "/tmp/x.py",
                "new_string": 'os.system("rm " + filename)',
            },
        },
    )
    assert rc == 0
    decision = _parse_decision(out)
    assert decision is not None
    assert "CWE-78" in decision["hookSpecificOutput"]["permissionDecisionReason"]


# ---------------------------------------------------------------------
# NotebookEdit tool — reads new_source
# ---------------------------------------------------------------------


def test_notebook_edit_blocks_injection(monkeypatch) -> None:
    rc, out = _run_with_payload(
        monkeypatch,
        {
            "tool_name": "NotebookEdit",
            "tool_input": {
                "notebook_path": "/tmp/nb.ipynb",
                "cell_id": "abc",
                "new_source": 'cursor.execute(f"SELECT * FROM u WHERE id={uid}")',
            },
        },
    )
    assert rc == 0
    decision = _parse_decision(out)
    assert decision is not None
    assert "RALF-free BLOCK (notebookedit)" in decision["hookSpecificOutput"]["permissionDecisionReason"]


def test_notebook_edit_benign_allow(monkeypatch) -> None:
    rc, out = _run_with_payload(
        monkeypatch,
        {
            "tool_name": "NotebookEdit",
            "tool_input": {
                "notebook_path": "/tmp/nb.ipynb",
                "new_source": "print('hello')",
            },
        },
    )
    assert rc == 0
    assert out == ""


# ---------------------------------------------------------------------
# Fail-open posture: if scoring raises, the hook should still allow
# ---------------------------------------------------------------------


def test_bash_scorer_exception_fails_open(monkeypatch) -> None:
    """Injecting a broken scorer should not block."""
    def explode(command: str):
        raise RuntimeError("boom")

    monkeypatch.setattr("ralf.shared.verdict_engine.score_command", explode)
    rc, out = _run_with_payload(
        monkeypatch,
        {"tool_name": "Bash", "tool_input": {"command": "ls"}},
    )
    assert rc == 0
    assert out == ""
