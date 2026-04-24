"""Tests for :mod:`ralf.shared.cli`.

Invokes ``cli.main()`` directly with argv and captures stdout/stderr.
Uses ``monkeypatch`` + tmp paths to isolate config/log files per test.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from ralf.shared import cli


def _capture(monkeypatch, tmp_path: Path) -> None:
    """Point XDG_CONFIG_HOME and XDG_STATE_HOME at ``tmp_path``.

    MUST be called before any cli command that touches the on-disk
    config/log files — otherwise the test would scribble on the real
    user's home.
    """
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    # Force app_control and audit_log to recompute their default paths.
    import importlib
    from ralf.shared import app_control, audit_log
    importlib.reload(app_control)
    importlib.reload(audit_log)


# ---------------------------------------------------------------------
# basic argparse behavior
# ---------------------------------------------------------------------


def test_no_args_prints_help(capsys) -> None:
    rc = cli.main([])
    out = capsys.readouterr().out
    assert rc == 0
    assert "ralf-free" in out
    assert "install" in out
    assert "status" in out
    assert "test" in out


def test_version(capsys) -> None:
    rc = cli.main(["version"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "ralf-free" in out


def test_install_points_to_installer(capsys) -> None:
    rc = cli.main(["install"])
    err = capsys.readouterr().err
    assert rc == 2
    assert "setup.sh" in err or "install-agent" in err


# ---------------------------------------------------------------------
# test subcommand — scores a command
# ---------------------------------------------------------------------


def test_test_benign_command(capsys) -> None:
    rc = cli.main(["test", "ls /tmp"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Decision:" in out
    assert "ALLOW" in out


def test_test_blocking_command(capsys) -> None:
    """A shadow read should return non-zero exit and print BLOCK."""
    cmd = "".join(["cat /etc/shad", "ow"])
    rc = cli.main(["test", cmd])
    out = capsys.readouterr().out
    assert rc == 1  # non-zero when blocked
    assert "BLOCK" in out


# ---------------------------------------------------------------------
# app_control subcommands (isolated via tmp XDG_CONFIG_HOME)
# ---------------------------------------------------------------------


def test_allow_add_list_remove(monkeypatch, tmp_path: Path, capsys) -> None:
    _capture(monkeypatch, tmp_path)

    rc = cli.main(["allow", "ls"])
    assert rc == 0
    capsys.readouterr()  # clear

    rc = cli.main(["list"])
    out = capsys.readouterr().out
    assert rc == 0
    assert '"ls"' in out

    rc = cli.main(["remove", "ls"])
    assert rc == 0
    capsys.readouterr()

    rc = cli.main(["list"])
    out = capsys.readouterr().out
    assert '"ls"' not in out


def test_block_and_review(monkeypatch, tmp_path: Path, capsys) -> None:
    _capture(monkeypatch, tmp_path)

    cli.main(["block", "nsenter"])
    cli.main(["review", "docker"])
    capsys.readouterr()

    rc = cli.main(["list"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "nsenter" in out
    assert "docker" in out


def test_remove_missing_is_error(monkeypatch, tmp_path: Path, capsys) -> None:
    _capture(monkeypatch, tmp_path)
    rc = cli.main(["remove", "nonexistent"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "not found" in err


# ---------------------------------------------------------------------
# logs subcommand
# ---------------------------------------------------------------------


def test_logs_empty(monkeypatch, tmp_path: Path, capsys) -> None:
    _capture(monkeypatch, tmp_path)
    rc = cli.main(["logs"])
    err = capsys.readouterr().err
    assert rc == 0
    assert "empty" in err


def test_logs_with_entries(monkeypatch, tmp_path: Path, capsys) -> None:
    _capture(monkeypatch, tmp_path)
    # Directly seed the audit log
    from ralf.shared.audit_log import DEFAULT_LOG_PATH, append
    append({"tool": "Bash", "decision": "allow", "command": "ls"},
           path=DEFAULT_LOG_PATH)
    append({"tool": "Bash", "decision": "block", "command": "evil"},
           path=DEFAULT_LOG_PATH)

    rc = cli.main(["logs", "-n", "5"])
    out = capsys.readouterr().out
    assert rc == 0
    assert '"decision": "allow"' in out
    assert '"decision": "block"' in out


# ---------------------------------------------------------------------
# doctor + status + compile-rules — smoke tests that exercise the
# real rule engine, so they don't need XDG isolation.
# ---------------------------------------------------------------------


def test_doctor(capsys) -> None:
    rc = cli.main(["doctor"])
    out = capsys.readouterr().out
    # Doctor should at least report OK on YAML + platform
    assert rc in (0, 1)  # 0 if all green, 1 if any failure
    assert "ralf-free doctor" in out


def test_status(capsys) -> None:
    rc = cli.main(["status"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "ralf-free" in out
    assert "Rules:" in out
    assert "Loaded" in out


def test_compile_rules(tmp_path: Path, monkeypatch, capsys) -> None:
    """Redirect the cache dir to tmp so we don't clobber the real one."""
    monkeypatch.setenv("HOME", str(tmp_path))
    import importlib
    from ralf.shared import rules
    importlib.reload(rules)
    # Now DEFAULT_CACHE_FILE points under tmp_path
    rc = cli.main(["compile-rules"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Compiled" in out
    assert "Pickle save" in out
