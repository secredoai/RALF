"""Tests for :mod:`ralf.core.event` and :mod:`ralf.core.audit`."""
from __future__ import annotations

from pathlib import Path

from ralf.core.audit import record
from ralf.core.event import CommonEvent
from ralf.shared.audit_log import tail


def _sample_event(**overrides) -> CommonEvent:
    base = dict(
        agent="claude_code",
        session_id="abc123",
        tool="Bash",
        command="ls /tmp",
        file_path="",
        decision="allow",
        score=0,
        reason="no signals",
        rule_hits=[],
    )
    base.update(overrides)
    return CommonEvent(**base)


def test_common_event_as_dict_round_trip() -> None:
    e = _sample_event()
    d = e.as_dict()
    assert d["agent"] == "claude_code"
    assert d["session_id"] == "abc123"
    assert d["tool"] == "Bash"
    assert d["decision"] == "allow"
    assert d["score"] == 0
    assert d["rule_hits"] == []


def test_common_event_default_rule_hits_is_empty_list() -> None:
    """Default factory must produce a fresh list per instance."""
    a = _sample_event()
    b = _sample_event()
    a.rule_hits.append("rule-x")
    assert b.rule_hits == []


def test_record_writes_to_audit_log(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    record(_sample_event(score=4), path=log)
    entries = tail(10, path=log)
    assert len(entries) == 1
    assert entries[0]["agent"] == "claude_code"
    assert entries[0]["score"] == 4
    assert "ts" in entries[0]


def test_record_silently_ignores_io_errors(tmp_path: Path, monkeypatch) -> None:
    """A failing audit-log write must NEVER raise out of record()."""
    def explode(*args, **kwargs):
        raise OSError("disk full")
    monkeypatch.setattr("ralf.core.audit._append", explode)
    # Must not raise.
    record(_sample_event())


def test_record_for_codex_sync_event(tmp_path: Path) -> None:
    """A Codex-sync event has agent='codex_cli' and empty rule_hits."""
    log = tmp_path / "audit.jsonl"
    e = _sample_event(
        agent="codex_cli",
        session_id="codex-rules-import",
        tool="Bash",
        command="curl --proto =https --tlsv1.2 -sSf https://sh.rustup.rs",
        decision="allow",
        score=0,
        reason="imported from ~/.codex/rules/default.rules",
    )
    record(e, path=log)
    entries = tail(1, path=log)
    assert entries[0]["agent"] == "codex_cli"
    assert entries[0]["reason"].startswith("imported from")
