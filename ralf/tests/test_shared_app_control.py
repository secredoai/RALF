"""Tests for :mod:`ralf.shared.app_control`."""
from __future__ import annotations

from pathlib import Path

import pytest

from ralf.shared.app_control import AppControl, AppDecision


@pytest.fixture
def tmp_config(tmp_path: Path) -> Path:
    return tmp_path / "app_control.yaml"


def test_empty_file_all_unknown(tmp_config: Path) -> None:
    ac = AppControl(tmp_config)
    assert ac.check("ls") == AppDecision.UNKNOWN
    assert ac.check("") == AppDecision.UNKNOWN


def test_add_and_check_allow(tmp_config: Path) -> None:
    ac = AppControl(tmp_config)
    ac.add("ls", AppDecision.ALLOW)
    assert ac.check("ls") == AppDecision.ALLOW
    assert tmp_config.exists()


def test_add_and_check_block(tmp_config: Path) -> None:
    ac = AppControl(tmp_config)
    ac.add("nsenter", AppDecision.BLOCK)
    assert ac.check("nsenter") == AppDecision.BLOCK


def test_add_and_check_review(tmp_config: Path) -> None:
    ac = AppControl(tmp_config)
    ac.add("docker", AppDecision.REVIEW)
    assert ac.check("docker") == AppDecision.REVIEW


def test_basename_stripping(tmp_config: Path) -> None:
    """``/usr/bin/ls`` should resolve to ``ls``."""
    ac = AppControl(tmp_config)
    ac.add("ls", AppDecision.ALLOW)
    assert ac.check("/usr/bin/ls") == AppDecision.ALLOW
    assert ac.check("/opt/homebrew/bin/ls") == AppDecision.ALLOW


def test_move_between_lists(tmp_config: Path) -> None:
    ac = AppControl(tmp_config)
    ac.add("tool", AppDecision.ALLOW)
    assert ac.check("tool") == AppDecision.ALLOW
    ac.add("tool", AppDecision.BLOCK)
    assert ac.check("tool") == AppDecision.BLOCK
    # Should be ONLY on block list
    state = ac.as_dict()
    assert "tool" not in state["allow"]
    assert "tool" in state["block"]


def test_remove(tmp_config: Path) -> None:
    ac = AppControl(tmp_config)
    ac.add("tool", AppDecision.BLOCK)
    assert ac.remove("tool") is True
    assert ac.check("tool") == AppDecision.UNKNOWN
    assert ac.remove("tool") is False  # already gone


def test_persist_and_reload(tmp_config: Path) -> None:
    ac1 = AppControl(tmp_config)
    ac1.add("ls", AppDecision.ALLOW)
    ac1.add("nsenter", AppDecision.BLOCK)
    ac1.add("docker", AppDecision.REVIEW)

    # Fresh instance re-reads the file
    ac2 = AppControl(tmp_config)
    assert ac2.check("ls") == AppDecision.ALLOW
    assert ac2.check("nsenter") == AppDecision.BLOCK
    assert ac2.check("docker") == AppDecision.REVIEW


def test_as_dict_sorted(tmp_config: Path) -> None:
    ac = AppControl(tmp_config)
    for t in ("c", "a", "b"):
        ac.add(t, AppDecision.ALLOW)
    state = ac.as_dict()
    assert state["allow"] == ["a", "b", "c"]


def test_priority_block_over_allow(tmp_config: Path) -> None:
    """Since ``add`` moves the token, you can't have same token on both
    lists; but the check order (block first) protects against manual
    file edits that put the same token on two lists."""
    ac = AppControl(tmp_config)
    ac._block.add("dangerous")
    ac._allow.add("dangerous")
    assert ac.check("dangerous") == AppDecision.BLOCK
