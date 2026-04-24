"""Tests for :mod:`ralf.shared.audit_log`."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from ralf.shared.audit_log import append, tail


@pytest.fixture
def tmp_log(tmp_path: Path) -> Path:
    return tmp_path / "audit.jsonl"


def test_append_creates_file(tmp_log: Path) -> None:
    assert not tmp_log.exists()
    append({"tool": "Bash", "command": "ls", "decision": "allow"}, path=tmp_log)
    assert tmp_log.exists()


def test_append_injects_timestamp(tmp_log: Path) -> None:
    append({"tool": "Bash", "command": "ls"}, path=tmp_log)
    entries = tail(10, path=tmp_log)
    assert len(entries) == 1
    assert "ts" in entries[0]
    # ISO8601 shape check: 20xx-xx-xx
    assert entries[0]["ts"].startswith("20")


def test_append_preserves_explicit_timestamp(tmp_log: Path) -> None:
    append({"ts": "1970-01-01T00:00:00+00:00", "tool": "Bash"}, path=tmp_log)
    entries = tail(1, path=tmp_log)
    assert entries[0]["ts"] == "1970-01-01T00:00:00+00:00"


def test_append_multiple(tmp_log: Path) -> None:
    for i in range(5):
        append({"tool": "Bash", "i": i}, path=tmp_log)
    entries = tail(10, path=tmp_log)
    assert len(entries) == 5
    assert [e["i"] for e in entries] == [0, 1, 2, 3, 4]


def test_tail_last_n(tmp_log: Path) -> None:
    for i in range(20):
        append({"tool": "Bash", "i": i}, path=tmp_log)
    entries = tail(5, path=tmp_log)
    assert len(entries) == 5
    assert [e["i"] for e in entries] == [15, 16, 17, 18, 19]


def test_tail_zero(tmp_log: Path) -> None:
    append({"tool": "Bash"}, path=tmp_log)
    assert tail(0, path=tmp_log) == []


def test_tail_missing_file(tmp_log: Path) -> None:
    assert tail(10, path=tmp_log) == []


def test_tail_skips_malformed_lines(tmp_log: Path) -> None:
    """A partial / corrupt line should not kill the tail."""
    append({"tool": "Bash", "i": 1}, path=tmp_log)
    with open(tmp_log, "a") as f:
        f.write("not json\n")
    append({"tool": "Bash", "i": 2}, path=tmp_log)
    entries = tail(10, path=tmp_log)
    assert [e.get("i") for e in entries] == [1, 2]


def test_rotation_on_size_overflow(tmp_log: Path) -> None:
    """When the log exceeds max_bytes, it should rotate to .1.

    Note: single-generation rotation means intermediate rotations get
    overwritten. With 20 small entries and rotation roughly every 8
    writes, we lose the first batch on the second rotation. This is
    intentional.
    """
    # 1 KB cap for the test
    for i in range(20):
        append({"tool": "Bash", "payload": "x" * 100, "i": i},
               path=tmp_log, max_bytes=1000)

    rotated = tmp_log.with_suffix(tmp_log.suffix + ".1")
    assert rotated.exists(), "expected rotation to have happened"
    assert tmp_log.exists()

    # Active file has ONLY the entries written since the most recent
    # rotation — strictly fewer than 20.
    new_entries = tail(100, path=tmp_log)
    rotated_content = rotated.read_text().splitlines()
    assert 0 < len(new_entries) < 20
    assert 0 < len(rotated_content) < 20

    # The most recent write should still be in the active log.
    assert new_entries[-1]["i"] == 19


def test_rotation_overwrites_previous_rotation(tmp_log: Path) -> None:
    rotated = tmp_log.with_suffix(tmp_log.suffix + ".1")
    # Seed a fake old rotated file
    rotated.parent.mkdir(parents=True, exist_ok=True)
    rotated.write_text("old rotation content\n")

    # Fill the active log past the cap
    for i in range(30):
        append({"tool": "Bash", "payload": "x" * 100, "i": i},
               path=tmp_log, max_bytes=1000)

    # The old rotation must have been overwritten
    assert "old rotation content" not in rotated.read_text()


def test_entry_schema_roundtrip(tmp_log: Path) -> None:
    entry = {
        "tool": "Bash",
        "command": "ls /tmp",
        "decision": "allow",
        "score": 0,
        "reason": "no signals",
        "rule_hits": ["rule-1", "rule-2"],
    }
    append(entry, path=tmp_log)
    result = tail(1, path=tmp_log)[0]
    for k, v in entry.items():
        assert result[k] == v
