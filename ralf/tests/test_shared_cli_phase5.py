"""Phase 5 CLI tests — pause / resume / install-agent / codex / dashboard.

Kept in a separate file from test_shared_cli.py so the new subcommands
don't bloat the existing test module.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from ralf.shared import cli


def _isolate(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))


# ---------------------------------------------------------------------
# pause / resume
# ---------------------------------------------------------------------


def test_pause_creates_sentinel(monkeypatch, tmp_path: Path, capsys) -> None:
    _isolate(monkeypatch, tmp_path)
    rc = cli.main(["pause"])
    assert rc == 0
    sentinel = tmp_path / "cache" / "ralf-free" / "paused"
    assert sentinel.exists()
    out = capsys.readouterr().out
    assert "paused" in out


def test_resume_removes_sentinel(monkeypatch, tmp_path: Path, capsys) -> None:
    _isolate(monkeypatch, tmp_path)
    cli.main(["pause"])
    capsys.readouterr()
    rc = cli.main(["resume"])
    assert rc == 0
    sentinel = tmp_path / "cache" / "ralf-free" / "paused"
    assert not sentinel.exists()
    out = capsys.readouterr().out
    assert "resumed" in out


def test_resume_when_not_paused_is_noop(monkeypatch, tmp_path: Path, capsys) -> None:
    _isolate(monkeypatch, tmp_path)
    rc = cli.main(["resume"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "already running" in out


# ---------------------------------------------------------------------
# install-agent
# ---------------------------------------------------------------------


def test_install_agent_claude(monkeypatch, tmp_path: Path) -> None:
    """install-agent wires the hook into the chosen settings file."""
    monkeypatch.setenv("RALF_AUTO_YES", "1")
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    # Force fresh install_hook profile lookup with new HOME
    import importlib
    from ralf.scripts import install_hook
    importlib.reload(install_hook)

    rc = cli.main(["install-agent", "--agent", "claude"])
    assert rc == 0
    settings = fake_home / ".claude" / "settings.json"
    assert settings.exists()
    data = json.loads(settings.read_text())
    assert "PreToolUse" in data["hooks"]


def test_install_agent_unknown_argparse_rejects(capsys) -> None:
    with pytest.raises(SystemExit):
        cli.main(["install-agent", "--agent", "magic"])


# ---------------------------------------------------------------------
# codex sync
# ---------------------------------------------------------------------


def test_codex_sync_with_explicit_path(monkeypatch, tmp_path: Path, capsys) -> None:
    _isolate(monkeypatch, tmp_path)
    rules = tmp_path / "rules.txt"
    rules.write_text(
        'prefix_rule(pattern=["ls", "/tmp"], decision="allow")\n'
        'prefix_rule(pattern=["git", "status"], decision="allow")\n'
    )
    rc = cli.main(["codex", "sync", "--path", str(rules)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Imported 2 rules" in out


def test_codex_sync_missing_path_returns_error(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    _isolate(monkeypatch, tmp_path)
    rc = cli.main(["codex", "sync", "--path", str(tmp_path / "absent.txt")])
    assert rc == 1
    err = capsys.readouterr().err
    assert "not found" in err


def test_codex_no_subcommand(capsys) -> None:
    rc = cli.main(["codex"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "sync" in err


# ---------------------------------------------------------------------
# doctor extension
# ---------------------------------------------------------------------


def test_doctor_reports_pause_state(monkeypatch, tmp_path: Path, capsys) -> None:
    _isolate(monkeypatch, tmp_path)
    cli.main(["pause"])
    capsys.readouterr()
    cli.main(["doctor"])
    out = capsys.readouterr().out
    assert "PAUSED" in out


def test_doctor_reports_adapters_section(monkeypatch, tmp_path: Path, capsys) -> None:
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    import importlib
    from ralf.scripts import install_hook
    importlib.reload(install_hook)
    cli.main(["doctor"])
    out = capsys.readouterr().out
    # Both agents should be listed (either OK or "no settings file")
    assert "claude" in out
    assert "gemini" in out
