"""Tests for :mod:`ralf.macos.rules_extractor`.

Module is pure Python and platform-independent — the tests run on
Linux too. Verify that the macOS fork behaves identically to the
Linux twin for the POSIX-subset operations that matter at this stage.
"""
from __future__ import annotations

from ralf.macos.rules_extractor import (
    extract_commands,
    first_tokens,
    normalize,
    split_segments,
    tokenize,
)


def test_extract_bash_command() -> None:
    assert extract_commands({"command": "ls /tmp"}) == ["ls /tmp"]


def test_extract_empty() -> None:
    assert extract_commands({}) == []
    assert extract_commands({"command": ""}) == []


def test_split_pipe() -> None:
    assert split_segments("ls | grep foo") == ["ls", "grep foo"]


def test_split_and_or_semi() -> None:
    assert split_segments("ls && pwd || whoami; date") == [
        "ls", "pwd", "whoami", "date",
    ]


# --- Quote-aware split_segments regression corpus ---
#
# These tests run on any platform (the module is pure Python), so they
# exercise the shared :mod:`ralf.shared.bash_split` implementation that
# both linux and macos ``rules_extractor.split_segments`` delegate to.
# Linux has parallel tests in test_linux_rules_extractor.py that are
# platform-gated off on darwin.


def test_split_preserves_logical_or_in_single_quotes() -> None:
    assert split_segments("echo 'a || b'") == ["echo 'a || b'"]


def test_split_preserves_logical_and_in_double_quotes() -> None:
    assert split_segments('echo "a && b"') == ['echo "a && b"']


def test_split_preserves_semicolon_in_quotes() -> None:
    assert split_segments("echo 'a; b'; ls") == ["echo 'a; b'", "ls"]


def test_split_preserves_pipe_in_quotes() -> None:
    assert split_segments('grep "foo|bar" file | wc -l') == [
        'grep "foo|bar" file',
        "wc -l",
    ]


def test_split_mixed_inner_and_outer_operators() -> None:
    assert split_segments('echo "a && b" && echo c') == [
        'echo "a && b"',
        "echo c",
    ]


def test_split_nested_quote_styles() -> None:
    """Double quotes inside single quotes are literal text."""
    assert split_segments("echo 'he said \"hi && bye\"'") == [
        "echo 'he said \"hi && bye\"'",
    ]


def test_split_backslash_escapes_operator() -> None:
    """Escaped ``\\&\\&`` outside quotes keeps the command whole."""
    assert split_segments("echo a \\&\\& b") == ["echo a \\&\\& b"]


def test_split_python_heredoc_regression() -> None:
    """Regression for the 2026-04-14 hook-self-block incident: a
    ``python3 -c "..."`` heredoc containing ``pip install flask==0.12.2``
    inside a Python string literal must stay a single segment so the
    supply-chain detector does not treat the quoted content as an
    install command."""
    cmd = 'python3 -c "cases = [\'pip install flask==0.12.2 && echo\']"'
    assert split_segments(cmd) == [cmd]


def test_normalize_sudo() -> None:
    assert normalize("sudo -E ls /tmp") == "ls /tmp"


def test_normalize_env() -> None:
    assert normalize("env FOO=bar make") == "make"


def test_first_tokens_homebrew_path() -> None:
    """Homebrew path is stripped via basename."""
    assert first_tokens("/opt/homebrew/bin/git status") == {"git"}


def test_first_tokens_pipeline() -> None:
    cmd = "sudo curl https://example.com | /usr/local/bin/grep foo"
    assert first_tokens(cmd) == {"curl", "grep"}


def test_first_tokens_empty() -> None:
    assert first_tokens("") == set()


def test_tokenize_quoted() -> None:
    assert tokenize("ls '/Applications/My App.app'") == [
        "ls", "/Applications/My App.app",
    ]


def test_tokenize_bad_quote_fallback() -> None:
    """Unbalanced quote falls back to whitespace split."""
    tokens = tokenize("echo 'unclosed")
    assert "echo" in tokens
