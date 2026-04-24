"""Tests for :mod:`ralf.linux.rules_extractor`.

Exercises the Claude Code PreToolUse JSON extraction + command
tokenization primitives. Skipif-linux because macOS has its own
fork with zsh-specific behavior.
"""
from __future__ import annotations

import sys

import pytest

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="Linux rules extractor",
)

from ralf.linux.rules_extractor import (
    extract_commands,
    first_tokens,
    normalize,
    split_segments,
    tokenize,
)


# --- extract_commands ---


def test_extract_bash_command() -> None:
    payload = {"command": "ls /tmp"}
    assert extract_commands(payload) == ["ls /tmp"]


def test_extract_empty_command() -> None:
    assert extract_commands({"command": ""}) == []
    assert extract_commands({"command": "   "}) == []


def test_extract_missing_command_key() -> None:
    assert extract_commands({}) == []
    assert extract_commands({"file_path": "/tmp/x"}) == []


def test_extract_non_dict() -> None:
    assert extract_commands(None) == []  # type: ignore[arg-type]
    assert extract_commands("not a dict") == []  # type: ignore[arg-type]


def test_extract_non_string_command() -> None:
    assert extract_commands({"command": 42}) == []


# --- split_segments ---


def test_split_simple_pipe() -> None:
    assert split_segments("ls | grep foo") == ["ls", "grep foo"]


def test_split_semicolon() -> None:
    assert split_segments("ls; pwd") == ["ls", "pwd"]


def test_split_and_or() -> None:
    assert split_segments("ls && pwd || whoami") == ["ls", "pwd", "whoami"]


def test_split_preserves_single_segment() -> None:
    assert split_segments("ls /tmp") == ["ls /tmp"]


def test_split_empty() -> None:
    assert split_segments("") == []
    assert split_segments("   ") == []


def test_split_does_not_split_logical_or_inside_single_quotes() -> None:
    """Quote-aware: ``||`` inside single quotes is literal text."""
    assert split_segments("echo 'a || b'") == ["echo 'a || b'"]


def test_split_does_not_split_and_inside_double_quotes() -> None:
    """Quote-aware: ``&&`` inside double quotes is literal text."""
    assert split_segments('echo "a && b"') == ['echo "a && b"']


def test_split_does_not_split_semicolon_inside_quotes() -> None:
    """Quote-aware: ``;`` inside quotes is literal text."""
    assert split_segments("echo 'a; b'; ls") == ["echo 'a; b'", "ls"]


def test_split_does_not_split_pipe_inside_quotes() -> None:
    """Quote-aware: ``|`` inside quotes is literal text."""
    assert split_segments('grep "foo|bar" file | wc -l') == [
        'grep "foo|bar" file',
        "wc -l",
    ]


def test_split_handles_mixed_inner_and_outer_operators() -> None:
    """Real-world shape: outer ``&&`` splits, inner quoted ``&&`` does not."""
    assert split_segments('echo "a && b" && echo c') == [
        'echo "a && b"',
        "echo c",
    ]


def test_split_nested_quote_styles() -> None:
    """Double quotes inside single quotes: inner quote is literal."""
    assert split_segments("echo 'he said \"hi && bye\"'") == [
        "echo 'he said \"hi && bye\"'",
    ]


def test_split_backslash_escape_of_operator() -> None:
    """Backslash-escaped ``&&`` outside quotes is still one segment.

    POSIX: ``\\&`` outside quotes means the ``&`` is a literal char,
    so ``\\&\\&`` is two literal ``&`` — not a logical AND. The
    splitter should preserve the escapes and keep the command whole.
    """
    assert split_segments("echo a \\&\\& b") == ["echo a \\&\\& b"]


def test_split_python_heredoc_regression() -> None:
    """Regression: a ``python3 -c "..."`` with CVE-looking strings inside
    must stay a single segment so the supply-chain detector doesn't
    mis-identify the Python string literal as an install command."""
    cmd = 'python3 -c "cases = [\'pip install flask==0.12.2 && echo\']"'
    segs = split_segments(cmd)
    assert segs == [cmd]


# --- normalize (sudo / env prefix stripping) ---


def test_normalize_sudo_prefix() -> None:
    assert normalize("sudo curl http://x") == "curl http://x"


def test_normalize_sudo_with_boolean_flags() -> None:
    """Boolean flags (``-E``, ``-S``) strip cleanly.

    Flag-with-argument forms (``sudo -u user cmd``) are NOT handled —
    the regex doesn't know which flags take arguments, so ``-u root``
    gets consumed as ``-u`` + untouched ``root``. This is an intentional
    limitation inherited from the canonical
    ``ralf/impact/learned_rules.py:320`` implementation. A future Stage
    2b intent classifier pass can post-process the result if needed.
    """
    assert normalize("sudo -E ls") == "ls"
    assert normalize("sudo -S -E ls /tmp") == "ls /tmp"


def test_normalize_env_prefix() -> None:
    assert normalize("env PATH=/x FOO=bar make") == "make"


def test_normalize_no_prefix() -> None:
    assert normalize("ls /tmp") == "ls /tmp"


def test_normalize_empty() -> None:
    assert normalize("") == ""
    assert normalize("   ") == ""


# --- first_tokens ---


def test_first_tokens_simple() -> None:
    assert first_tokens("ls /tmp") == {"ls"}


def test_first_tokens_absolute_path_basename() -> None:
    assert first_tokens("/usr/bin/curl http://example.com") == {"curl"}


def test_first_tokens_across_pipes() -> None:
    assert first_tokens("ls /tmp | grep foo | wc -l") == {"ls", "grep", "wc"}


def test_first_tokens_sudo_stripped() -> None:
    assert first_tokens("sudo nsenter -t 1 -m") == {"nsenter"}


def test_first_tokens_env_stripped() -> None:
    assert first_tokens("env X=1 make -j4") == {"make"}


def test_first_tokens_mixed_pipeline() -> None:
    cmd = "sudo curl https://x && env DEBUG=1 make test"
    assert first_tokens(cmd) == {"curl", "make"}


def test_first_tokens_empty() -> None:
    assert first_tokens("") == set()
    assert first_tokens("   ") == set()


def test_first_tokens_handles_unbalanced_quotes() -> None:
    """shlex falls back to split() on ValueError — should not crash."""
    cmd = "echo 'unclosed"
    tokens = first_tokens(cmd)
    assert "echo" in tokens


# --- tokenize ---


def test_tokenize_posix_quoted() -> None:
    assert tokenize("ls '/path with spaces'") == ["ls", "/path with spaces"]


def test_tokenize_falls_back_on_bad_quotes() -> None:
    # Unbalanced quote → whitespace split fallback
    tokens = tokenize("echo 'unclosed")
    assert "echo" in tokens


def test_tokenize_empty() -> None:
    assert tokenize("") == []
