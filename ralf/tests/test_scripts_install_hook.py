"""Tests for :mod:`ralf.scripts.install_hook`."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from ralf.scripts import install_hook


@pytest.fixture(autouse=True)
def _auto_yes(monkeypatch):
    """Skip the input() prompt in install_for_agent."""
    monkeypatch.setenv("RALF_AUTO_YES", "1")


# ---------------------------------------------------------------------
# pure-function merge / remove
# ---------------------------------------------------------------------


def test_get_profile_known() -> None:
    p = install_hook.get_profile("claude")
    assert p.name == "claude"
    assert "claude_code" in p.hook_command


def test_get_profile_unknown_raises() -> None:
    with pytest.raises(ValueError):
        install_hook.get_profile("nonexistent")


def test_install_into_empty_settings() -> None:
    p = install_hook.get_profile("claude")
    new = install_hook._install_into({}, p)
    assert "hooks" in new
    assert "PreToolUse" in new["hooks"]
    assert len(new["hooks"]["PreToolUse"]) == 1
    entry = new["hooks"]["PreToolUse"][0]
    assert entry["matcher"] == p.hook_matcher
    assert entry["hooks"][0]["command"] == p.hook_command


def test_hook_present_detects_exact_match() -> None:
    p = install_hook.get_profile("gemini")
    settings = install_hook._install_into({}, p)
    assert install_hook._hook_present(settings, p) is True


def test_hook_present_false_on_empty() -> None:
    p = install_hook.get_profile("claude")
    assert install_hook._hook_present({}, p) is False


def test_remove_from_purges_hook() -> None:
    p = install_hook.get_profile("claude")
    seeded = install_hook._install_into({}, p)
    new, removed = install_hook._remove_from(seeded, p)
    # Claude has multiple hooks (PreToolUse + PostToolUse); remove all.
    assert removed == len(p.hooks)
    assert "hooks" not in new  # tree pruned to empty


def test_remove_from_preserves_unrelated_hooks() -> None:
    p = install_hook.get_profile("claude")
    settings = {
        "hooks": {
            "PreToolUse": [
                {"matcher": "OtherTool", "hooks": [
                    {"type": "command", "command": "/some/other/command"},
                ]},
            ],
        }
    }
    new, removed = install_hook._remove_from(settings, p)
    assert removed == 0
    assert new["hooks"]["PreToolUse"][0]["matcher"] == "OtherTool"


# ---------------------------------------------------------------------
# install_for_agent / uninstall_for_agent — file IO
# ---------------------------------------------------------------------


def test_install_creates_settings_file(tmp_path: Path) -> None:
    target = tmp_path / "settings.json"
    rc = install_hook.install_for_agent(
        "claude", settings_path=target, yes=True,
    )
    assert rc == 0
    assert target.exists()
    data = json.loads(target.read_text())
    assert "hooks" in data
    assert "PreToolUse" in data["hooks"]


def test_install_idempotent_second_run_is_noop(tmp_path: Path, capsys) -> None:
    target = tmp_path / "settings.json"
    install_hook.install_for_agent("claude", settings_path=target, yes=True)
    rc = install_hook.install_for_agent(
        "claude", settings_path=target, yes=True,
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "already present" in out


def test_install_makes_backup(tmp_path: Path) -> None:
    target = tmp_path / "settings.json"
    target.write_text('{"existing": "config"}')
    rc = install_hook.install_for_agent(
        "claude", settings_path=target, yes=True,
    )
    assert rc == 0
    # Look for the backup file
    backups = list(target.parent.glob("settings.json.bak.*"))
    assert len(backups) == 1
    assert json.loads(backups[0].read_text()) == {"existing": "config"}


def test_install_invalid_json_returns_error(tmp_path: Path) -> None:
    target = tmp_path / "settings.json"
    target.write_text("not json at all")
    rc = install_hook.install_for_agent(
        "claude", settings_path=target, yes=True,
    )
    assert rc == 2


def test_uninstall_removes_hook(tmp_path: Path) -> None:
    target = tmp_path / "settings.json"
    install_hook.install_for_agent("claude", settings_path=target, yes=True)
    rc = install_hook.uninstall_for_agent("claude", settings_path=target)
    assert rc == 0
    data = json.loads(target.read_text())
    assert "hooks" not in data or "PreToolUse" not in data.get("hooks", {})


def test_uninstall_missing_file_is_noop(tmp_path: Path, capsys) -> None:
    target = tmp_path / "absent.json"
    rc = install_hook.uninstall_for_agent("claude", settings_path=target)
    assert rc == 0
    out = capsys.readouterr().out
    assert "nothing to remove" in out


def test_install_gemini_uses_before_tool_event(tmp_path: Path) -> None:
    target = tmp_path / "gemini-settings.json"
    install_hook.install_for_agent("gemini", settings_path=target, yes=True)
    data = json.loads(target.read_text())
    assert "BeforeTool" in data["hooks"]
    assert "gemini_cli" in data["hooks"]["BeforeTool"][0]["hooks"][0]["command"]
