"""macOS command extraction from Claude Code PreToolUse JSON.

Mirrors :mod:`ralf.linux.rules_extractor` with three macOS-focused
divergences documented here:

    1. **Default shell is zsh** — zsh accepts the same ``|``, ``;``,
       ``&&``, ``||`` compound operators as bash, so the segment
       splitter is unchanged. Zsh-specific ``=(...)`` process
       substitution and ``${=var}`` word-splitting are NOT recursed
       into.

    2. **Homebrew paths** — first-token basename stripping is
       unchanged (``/opt/homebrew/bin/git`` → ``git``), but note that
       some Homebrew packages install symlinks named differently
       from the underlying binary. We rely on the first-token
       basename, not a path-to-binary resolver.

    3. **BSD userland ``sudo``** — macOS ``sudo`` accepts the same
       flag syntax as Linux ``sudo``, so the prefix regex is
       unchanged. The same flag-with-argument limitation applies
       (``sudo -u user cmd`` leaves ``user`` as the first token);
       the intent classifier can re-classify after tokenization.

Everything else is a straight fork of the Linux module. Divergence
here is deliberate and must come with a comment explaining why.
"""
from __future__ import annotations

import re
import shlex

from ralf.shared.bash_split import split_segments as _shared_split_segments

_SUDO_PREFIX = re.compile(r'^(?:sudo\s+(?:-\S+\s+)*)')
_ENV_PREFIX = re.compile(r'^(?:env\s+(?:\S+=\S+\s+)*)')


def extract_commands(tool_input: dict) -> list[str]:
    """Return raw command string(s) from a PreToolUse ``tool_input``.

    Returns a single-element list containing the ``command`` key.
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
    zsh accepts the same compound operators as bash; process substitution
    ``=(...)`` / ``<(...)`` is not recursed into. Thin wrapper around the
    shared implementation in :mod:`ralf.shared.bash_split`.
    """
    return _shared_split_segments(command)


def normalize(segment: str) -> str:
    """Strip leading ``sudo`` and ``env KEY=val`` prefixes."""
    if not segment:
        return segment
    s = segment.strip()
    s = _SUDO_PREFIX.sub("", s).strip()
    s = _ENV_PREFIX.sub("", s).strip()
    return s


def first_tokens(command: str) -> set[str]:
    """Return the set of first-token binaries across all segments.

    Basename-only (``/opt/homebrew/bin/git`` → ``git``). Mirrors the
    Linux implementation.
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

    zsh supports the same POSIX subset ``shlex`` understands, so POSIX
    mode is correct here. Zsh-specific expansions (``$'...'``,
    ``${=var}``) are preserved literally rather than expanded.
    """
    if not segment:
        return []
    try:
        return shlex.split(segment, posix=True)
    except ValueError:
        return segment.split()
