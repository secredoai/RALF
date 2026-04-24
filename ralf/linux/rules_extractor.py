"""Linux command extraction from Claude Code PreToolUse JSON.

Extracts and normalizes the command string(s) from a Claude Code
``PreToolUse`` payload. Shell behavior is bash/sh / POSIX — see the
macOS twin for zsh-specific quoting notes.

Public API:
    - :func:`extract_commands(tool_input)` — list[str] of command segments
    - :func:`first_tokens(command)` — set[str] of first-token binaries
    - :func:`normalize(command)` — strip sudo/env prefixes, collapse whitespace

The Claude Code hook JSON shape (PreToolUse for Bash tool)::

    {
      "tool_name": "Bash",
      "tool_input": {"command": "ls -la /tmp"},
      ...
    }

For Write/Edit, ``tool_input`` contains ``file_path`` and ``content`` /
``new_string``; the file-write path is handled separately by the
code_scanner, not this module.
"""
from __future__ import annotations

import re
import shlex

from ralf.shared.bash_split import split_segments as _shared_split_segments

_SUDO_PREFIX = re.compile(r'^(?:sudo\s+(?:-\S+\s+)*)')
_ENV_PREFIX = re.compile(r'^(?:env\s+(?:\S+=\S+\s+)*)')
_NOHUP_PREFIX = re.compile(r'^(?:nohup\s+)')
_TIME_PREFIX = re.compile(r'^(?:(?:\\?time|/usr/bin/time)(?:\s+-\S+)*\s+)')
_EXEC_PREFIX = re.compile(r'^(?:exec\s+(?:-\S+\s+)*)')

# Shell wrapper: bash/sh/dash/zsh -c "..."  (whole-command form only).
# Does not handle escaped same-quote inside the argument — that's a
# documented known gap; sufficient for the common evasion shapes
# encountered by package-install and intent detection.
_SHELL_WRAP_RE = re.compile(
    r'''^\s*(?:/(?:usr/)?bin/)?(?:bash|sh|dash|zsh)\s+-c\s+(['"])(.*)\1\s*$''',
    re.DOTALL,
)
# Subshell and backtick wrappers (anchored to entire command, not mid-pipeline).
_SUBSHELL_WRAP_RE = re.compile(r"^\s*\$\((.*)\)\s*$", re.DOTALL)
_BACKTICK_WRAP_RE = re.compile(r"^\s*`(.*)`\s*$", re.DOTALL)
_SHELL_UNWRAP_MAX_DEPTH = 3


def extract_commands(tool_input: dict) -> list[str]:
    """Return the raw command string(s) from a PreToolUse ``tool_input``.

    For Bash, returns ``[tool_input["command"]]`` (a single-element list
    so callers always iterate). Returns an empty list for non-command
    tool inputs. Write/Edit go through the file-content path instead.
    """
    if not isinstance(tool_input, dict):
        return []
    cmd = tool_input.get("command")
    if isinstance(cmd, str) and cmd.strip():
        return [cmd]
    return []


def split_segments(command: str) -> list[str]:
    """Split a shell command on top-level ``|`` / ``;`` / ``&&`` / ``||``.

    Quote-aware (single, double, and backslash-escape contexts respected).
    Does not recurse into ``$(...)`` / ``(...)`` / backticks — subshells
    are a separate layer handled by ``unwrap_shell_wrappers`` and the
    deobfuscation pipeline. Thin wrapper around the shared implementation
    in :mod:`ralf.shared.bash_split`.
    """
    return _shared_split_segments(command)


def normalize(segment: str) -> str:
    """Strip leading transparent-launcher prefixes from a segment.

    Handles: ``sudo``, ``env KEY=val``, ``nohup``, ``time``/``/usr/bin/time``,
    ``exec``. These are all prefixes that hand off to the next token as the
    real binary — stripping them lets downstream detectors see the actual
    command being launched. Applied repeatedly to catch stacked prefixes
    like ``sudo nohup env X=1 pip install ...``.
    """
    if not segment:
        return segment
    s = segment.strip()
    for _ in range(4):  # cap: prevents pathological input from looping
        prev = s
        s = _SUDO_PREFIX.sub("", s).strip()
        s = _ENV_PREFIX.sub("", s).strip()
        s = _NOHUP_PREFIX.sub("", s).strip()
        s = _TIME_PREFIX.sub("", s).strip()
        s = _EXEC_PREFIX.sub("", s).strip()
        if s == prev:
            break
    return s


def unwrap_shell_wrappers(command: str) -> str:
    """Recursively unwrap shell wrappers that envelope the entire command.

    Handles ``bash -c "..."``, ``sh -c '...'``, ``$(...)`` subshells, and
    `` `...` `` backticks. Capped at ``_SHELL_UNWRAP_MAX_DEPTH`` levels.
    Mid-pipeline wrappers (``foo | bash -c "..."``, ``echo $(date) hi``)
    are NOT unwrapped here — segment-level detection handles those.
    """
    if not command:
        return command
    result = command
    for _ in range(_SHELL_UNWRAP_MAX_DEPTH):
        m = _SHELL_WRAP_RE.match(result)
        if m:
            result = m.group(2)
            continue
        m = _SUBSHELL_WRAP_RE.match(result)
        if m:
            result = m.group(1)
            continue
        m = _BACKTICK_WRAP_RE.match(result)
        if m:
            result = m.group(1)
            continue
        break
    return result


def first_tokens(command: str) -> set[str]:
    """Return the set of first-token binaries across all segments.

    ``sudo nsenter ... | curl foo`` → ``{"nsenter", "curl"}``.
    Basename-only: ``/usr/bin/curl`` becomes ``curl``.
    """
    out: set[str] = set()
    for seg in split_segments(command):
        norm = normalize(seg)
        if not norm:
            continue
        try:
            toks = shlex.split(norm, posix=True)
        except ValueError:
            toks = norm.split()
        if not toks:
            continue
        first = toks[0].rsplit("/", 1)[-1]
        if first:
            out.add(first)
    return out


def tokenize(segment: str) -> list[str]:
    """POSIX-mode shlex tokenization of a single segment.

    Falls back to whitespace split if shlex fails on unbalanced quotes.
    """
    if not segment:
        return []
    try:
        return shlex.split(segment, posix=True)
    except ValueError:
        return segment.split()
