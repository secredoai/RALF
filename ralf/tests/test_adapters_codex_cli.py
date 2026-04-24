"""Tests for :mod:`ralf.adapters.codex_cli`."""
from __future__ import annotations

from pathlib import Path

import pytest

from ralf.adapters.codex_cli import (
    CodexRule,
    _codex_to_ralf_decision,
    _first_token_basename,
    import_codex_rules,
    parse_rules_file,
    watch_codex_rules,
)
from ralf.shared.audit_log import tail


SAMPLE_RULES = '''\
prefix_rule(pattern=["curl", "--proto", "=https", "--tlsv1.2", "-sSf", "https://sh.rustup.rs"], decision="allow")
prefix_rule(pattern=["bash", "-lc", "source \\"$HOME/.cargo/env\\" && cargo build --workspace"], decision="allow")
prefix_rule(pattern=["git", "clone", "https://github.com/PrismML-Eng/llama.cpp"], decision="allow")
prefix_rule(pattern=["mkdir", "-p", "/tmp/models/example-model"], decision="allow")
'''


@pytest.fixture
def rules_file(tmp_path: Path) -> Path:
    f = tmp_path / "default.rules"
    f.write_text(SAMPLE_RULES)
    return f


# ---------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------


def test_parse_rules_file_returns_four_rules(rules_file: Path) -> None:
    rules = parse_rules_file(rules_file)
    assert len(rules) == 4
    assert rules[0].pattern[0] == "curl"
    assert rules[1].pattern[0] == "bash"
    assert rules[2].pattern[0] == "git"
    assert rules[3].pattern[0] == "mkdir"
    for r in rules:
        assert r.decision == "allow"
    assert [r.line_no for r in rules] == [1, 2, 3, 4]


def test_parse_rules_file_missing(tmp_path: Path) -> None:
    assert parse_rules_file(tmp_path / "nope.rules") == []


def test_parse_rules_file_skips_unknown_lines(tmp_path: Path) -> None:
    f = tmp_path / "mixed.rules"
    f.write_text(
        '# a comment\n'
        'some_other_rule(pattern=["x"])\n'
        'prefix_rule(pattern=["ls"], decision="allow")\n'
    )
    rules = parse_rules_file(f)
    assert len(rules) == 1
    assert rules[0].pattern == ["ls"]


def test_parse_rules_file_skips_malformed_pattern(tmp_path: Path, capsys) -> None:
    """A regex hit with a non-list pattern should warn + skip, not crash."""
    f = tmp_path / "bad.rules"
    f.write_text('prefix_rule(pattern=[not_python], decision="allow")\n')
    rules = parse_rules_file(f)
    assert rules == []
    err = capsys.readouterr().err
    assert "cannot parse" in err


def test_parse_rules_file_handles_single_quoted_decision(tmp_path: Path) -> None:
    f = tmp_path / "sq.rules"
    f.write_text("prefix_rule(pattern=[\"ls\"], decision='allow')\n")
    rules = parse_rules_file(f)
    assert len(rules) == 1
    assert rules[0].decision == "allow"


# ---------------------------------------------------------------------
# translation
# ---------------------------------------------------------------------


def test_codex_to_ralf_decision() -> None:
    assert _codex_to_ralf_decision("allow") == "allow"
    assert _codex_to_ralf_decision("deny") == "block"
    assert _codex_to_ralf_decision("ask") == "review"
    # Unknown vocabulary defaults to review (safer than allow)
    assert _codex_to_ralf_decision("strange") == "review"


def test_first_token_basename_basename_only() -> None:
    rule = CodexRule(pattern=["/usr/bin/curl", "-sSf", "https://x"], decision="allow", line_no=1)
    assert _first_token_basename(rule) == "curl"


def test_first_token_basename_empty() -> None:
    assert _first_token_basename(CodexRule(pattern=[], decision="allow", line_no=1)) == ""


# ---------------------------------------------------------------------
# import pipeline
# ---------------------------------------------------------------------


def test_import_codex_rules_writes_audit_and_app_control(
    rules_file: Path, tmp_path: Path
) -> None:
    audit_log = tmp_path / "audit.jsonl"
    app_control = tmp_path / "app_control.yaml"

    imported, added = import_codex_rules(
        rules_file, audit_path=audit_log, app_control_path=app_control,
    )
    assert imported == 4
    assert added == 4

    entries = tail(20, path=audit_log)
    assert len(entries) == 4
    assert all(e["agent"] == "codex_cli" for e in entries)
    assert all(e["decision"] == "allow" for e in entries)
    assert all(e["session_id"] == "codex-rules-sync" for e in entries)

    # app_control file is YAML; load it to check contents
    import yaml
    state = yaml.safe_load(app_control.read_text())
    assert sorted(state["allow"]) == ["bash", "curl", "git", "mkdir"]
    assert state["block"] == []
    assert state["review"] == []


def test_import_is_idempotent(rules_file: Path, tmp_path: Path) -> None:
    """Running sync twice on the same file does not duplicate app_control."""
    app_control = tmp_path / "app_control.yaml"
    audit_log = tmp_path / "audit.jsonl"

    import_codex_rules(rules_file, audit_path=audit_log, app_control_path=app_control)
    imported2, added2 = import_codex_rules(
        rules_file, audit_path=audit_log, app_control_path=app_control,
    )
    assert imported2 == 4   # rules were re-parsed
    assert added2 == 0      # but no new app_control changes


def test_import_skips_audit_when_disabled(rules_file: Path, tmp_path: Path) -> None:
    audit_log = tmp_path / "audit.jsonl"
    app_control = tmp_path / "app_control.yaml"
    import_codex_rules(
        rules_file,
        audit_path=audit_log,
        app_control_path=app_control,
        record_audit=False,
    )
    assert not audit_log.exists() or tail(10, path=audit_log) == []


def test_import_empty_file(tmp_path: Path) -> None:
    f = tmp_path / "empty.rules"
    f.write_text("")
    imported, added = import_codex_rules(
        f, audit_path=tmp_path / "audit.jsonl",
        app_control_path=tmp_path / "ac.yaml",
    )
    assert imported == 0
    assert added == 0


# ---------------------------------------------------------------------
# watcher
# ---------------------------------------------------------------------


def test_watch_one_iteration_triggers_initial_import(
    rules_file: Path, tmp_path: Path
) -> None:
    """Bound the loop with iterations=1 so the test exits.

    Use explicit path overrides instead of XDG env + module reload —
    reloading ``ralf.shared.app_control`` breaks the AppDecision
    enum identity for any test that imported it at module load time.
    """
    audit_log = tmp_path / "audit.jsonl"
    app_control = tmp_path / "app_control.yaml"

    results = list(watch_codex_rules(
        rules_file,
        interval=0.0,
        iterations=1,
        audit_path=audit_log,
        app_control_path=app_control,
    ))
    assert len(results) == 1
    assert results[0] == (4, 4)
    assert audit_log.exists()
    assert app_control.exists()
