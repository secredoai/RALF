"""Shell normalization: resolve metachar evasion to canonical form.

Runs BEFORE deobfuscation and ActionParser in the check() pipeline.
Handles: empty quote insertion, backslash escapes, brace expansion,
variable expansion (including IFS), glob normalization, concatenation.

Pure string manipulation — no subprocess, no disk access.
Latency target: <0.5ms for typical commands.
"""

from __future__ import annotations

import re

_MAX_INPUT_LEN = 8192  # 8KB cap (matches code_scanner)
_MAX_EXPANSION_PASSES = 5
_MAX_VARIABLES = 20
_MAX_BRACE_EXPANSIONS = 10
_MAX_BRACE_DEPTH = 3


# ---------------------------------------------------------------------------
# 1. Quote removal — strip empty quotes that break token matching
# ---------------------------------------------------------------------------

# Empty quote pairs NOT inside a larger quoted string
_EMPTY_DOUBLE = re.compile(r'""')
_EMPTY_SINGLE = re.compile(r"''")


def _remove_quotes(cmd: str) -> str:
    """Remove empty quote pairs used to break binary/path tokens.

    c""at → cat, c''at → cat
    Preserves: echo "hello world", echo 'foo bar'
    """
    # Strategy: walk the string, track quoting state.
    # Remove "" or '' only when they appear mid-token (no whitespace on either side)
    # or at token boundaries that produce an empty insertion.
    result: list[str] = []
    i = 0
    n = len(cmd)

    while i < n:
        # Check for empty double-quote pair mid-token
        if cmd[i] == '"' and i + 1 < n and cmd[i + 1] == '"':
            # Empty quotes "" — check if mid-token (not standalone echo "")
            # Mid-token: preceded and/or followed by non-whitespace
            prev_is_word = i > 0 and cmd[i - 1] not in (' ', '\t', '\n', ';', '|', '&')
            next_is_word = i + 2 < n and cmd[i + 2] not in (' ', '\t', '\n', ';', '|', '&', '\0')
            if prev_is_word or next_is_word:
                # Mid-token empty quotes — remove them
                i += 2
                continue
            # Standalone "" (like echo "") — keep
            result.append(cmd[i])
            i += 1
            continue

        # Check for empty single-quote pair mid-token
        if cmd[i] == "'" and i + 1 < n and cmd[i + 1] == "'":
            prev_is_word = i > 0 and cmd[i - 1] not in (' ', '\t', '\n', ';', '|', '&')
            next_is_word = i + 2 < n and cmd[i + 2] not in (' ', '\t', '\n', ';', '|', '&', '\0')
            if prev_is_word or next_is_word:
                i += 2
                continue
            result.append(cmd[i])
            i += 1
            continue

        result.append(cmd[i])
        i += 1

    return "".join(result)


# ---------------------------------------------------------------------------
# 2. Escape resolution — remove unquoted backslash-escapes
# ---------------------------------------------------------------------------

def _resolve_escapes(cmd: str) -> str:
    r"""Remove backslash-escapes outside of quotes.

    c\at → cat, /e\tc/sha\dow → /etc/shadow
    Preserves: backslashes inside single quotes, \\ (literal backslash)
    """
    result: list[str] = []
    i = 0
    n = len(cmd)
    in_single = False
    in_double = False

    while i < n:
        c = cmd[i]

        # Track quoting state
        if c == "'" and not in_double:
            in_single = not in_single
            result.append(c)
            i += 1
            continue
        if c == '"' and not in_single:
            in_double = not in_double
            result.append(c)
            i += 1
            continue

        # Backslash handling
        if c == '\\' and not in_single and i + 1 < n:
            next_c = cmd[i + 1]
            if next_c == '\\':
                # Literal backslash \\  → keep one backslash
                result.append('\\')
                i += 2
                continue
            if next_c == '\n':
                # Line continuation — skip both
                i += 2
                continue
            # Unquoted backslash before regular char — remove the backslash
            result.append(next_c)
            i += 2
            continue

        result.append(c)
        i += 1

    return "".join(result)


# ---------------------------------------------------------------------------
# 3. Brace expansion — {cat,/etc/shadow} → cat /etc/shadow
# ---------------------------------------------------------------------------

_BRACE_RE = re.compile(r'\{([^{}]+)\}')


def _expand_braces(cmd: str) -> str:
    """Expand comma-separated brace groups.

    {cat,/etc/shadow} → cat /etc/shadow
    {cat,head} /etc/shadow → cat head /etc/shadow (space-separated)
    Skips range syntax {1..10}, ${VAR} (variable refs).
    Bounded: max 10 expansions, max depth 3.
    """
    result = cmd
    for _depth in range(_MAX_BRACE_DEPTH):
        m = _BRACE_RE.search(result)
        if not m:
            break

        inner = m.group(1)

        # Skip: ${VAR} — this is a variable reference, not brace expansion
        if m.start() > 0 and result[m.start() - 1] == '$':
            # Replace temporarily to avoid infinite loop, then restore
            break

        # Skip: range syntax {1..10}
        if '..' in inner:
            break

        # Must have comma to be brace expansion
        if ',' not in inner:
            break

        parts = inner.split(',')
        if len(parts) > _MAX_BRACE_EXPANSIONS:
            parts = parts[:_MAX_BRACE_EXPANSIONS]

        expanded = ' '.join(parts)
        result = result[:m.start()] + expanded + result[m.end():]

    return result


# ---------------------------------------------------------------------------
# 4. Variable expansion — resolve assignments within the command
# ---------------------------------------------------------------------------

# Assignment pattern: VAR=value (with optional export)
_ASSIGN_RE = re.compile(
    r'^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)='
    r'(?:"([^"]*)"|\'([^\']*)\'|(\S*))\s*$'
)

# Variable reference patterns
_VAR_REF_RE = re.compile(r'\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)')

# Sprint 2k: FD redirect tracking
_FD_ASSIGN_RE = re.compile(r'^exec\s+(\d+)\s*<\s*(/\S+)\s*$')
_FD_REF_RE = re.compile(r'<&(\d+)|/dev/fd/(\d+)')


def _expand_variables(cmd: str) -> tuple[str, dict[str, str]]:
    """Resolve variable assignments and references within a command.

    a=cat;b=/etc/shadow;$a $b → cat /etc/shadow
    IFS=/;cmd=cat${IFS}etc${IFS}shadow;$cmd → cat/etc/shadow (then rejoin handles it)
    export X=cat;$X /etc/shadow → cat /etc/shadow

    Returns (expanded_command, variables_dict).
    Bounded: max 20 variables, max 5 resolution passes.
    """
    # Split on unquoted semicolons to find assignment vs execution segments
    segments = _split_semicolons(cmd)
    if len(segments) <= 1 and '=' not in cmd.split(None, 1)[0] if cmd.strip() else True:
        # No semicolons and first token isn't assignment — nothing to expand
        return cmd, {}

    variables: dict[str, str] = {}
    exec_segments: list[str] = []

    for seg in segments:
        seg = seg.strip()
        if not seg:
            continue

        # Sprint 2k: FD redirect tracking (exec N< /path)
        fd_m = _FD_ASSIGN_RE.match(seg)
        if fd_m:
            fd_num = fd_m.group(1)
            fd_path = fd_m.group(2)
            variables[f"__fd_{fd_num}"] = fd_path
            continue

        # Try to parse as assignment
        m = _ASSIGN_RE.match(seg)
        if m and len(variables) < _MAX_VARIABLES:
            name = m.group(1)
            value = m.group(2) if m.group(2) is not None else (
                m.group(3) if m.group(3) is not None else (m.group(4) or ""))
            # Resolve any existing variables in the value
            value = _substitute_vars(value, variables)
            variables[name] = value
        else:
            exec_segments.append(seg)

    if not variables:
        return cmd, {}

    # Resolve variables and FD references in execution segments
    resolved_parts: list[str] = []
    for seg in exec_segments:
        resolved = _substitute_vars(seg, variables)
        resolved = _substitute_fds(resolved, variables)
        resolved_parts.append(resolved)

    # If no execution segments, the whole command was assignments — return original
    if not resolved_parts:
        return cmd, variables

    result = "; ".join(resolved_parts) if len(resolved_parts) > 1 else resolved_parts[0]

    # Multi-pass resolution for chained references (A=$B; $A)
    for _pass in range(_MAX_EXPANSION_PASSES):
        prev = result
        result = _substitute_vars(result, variables)
        if result == prev:
            break

    return result, variables


def _substitute_vars(text: str, variables: dict[str, str]) -> str:
    """Replace $VAR and ${VAR} references with values from dict."""
    def _replacer(m: re.Match) -> str:
        name = m.group(1) or m.group(2)
        return variables.get(name, m.group(0))

    return _VAR_REF_RE.sub(_replacer, text)


def _substitute_fds(text: str, variables: dict[str, str]) -> str:
    """Replace <&N and /dev/fd/N references with tracked FD paths."""
    def _fd_replacer(m: re.Match) -> str:
        fd_num = m.group(1) or m.group(2)
        fd_key = f"__fd_{fd_num}"
        path = variables.get(fd_key)
        if path:
            return path
        return m.group(0)

    return _FD_REF_RE.sub(_fd_replacer, text)


def _split_semicolons(cmd: str) -> list[str]:
    """Split on unquoted semicolons, respecting quotes."""
    parts: list[str] = []
    current: list[str] = []
    in_single = False
    in_double = False
    i = 0
    n = len(cmd)

    while i < n:
        c = cmd[i]

        if c == '\\' and not in_single and i + 1 < n:
            current.append(c)
            current.append(cmd[i + 1])
            i += 2
            continue

        if c == "'" and not in_double:
            in_single = not in_single
            current.append(c)
            i += 1
            continue

        if c == '"' and not in_single:
            in_double = not in_double
            current.append(c)
            i += 1
            continue

        if c == ';' and not in_single and not in_double:
            parts.append("".join(current))
            current = []
            i += 1
            continue

        current.append(c)
        i += 1

    if current:
        parts.append("".join(current))

    return parts


# ---------------------------------------------------------------------------
# 5. Glob normalization — flag and best-guess resolve
# ---------------------------------------------------------------------------

# Single-char wildcard in path/binary positions
_GLOB_SINGLE_RE = re.compile(r'(/[\w./]*)\?+([\w./]*)')
# Character class in path/binary positions
_GLOB_CLASS_RE = re.compile(r'(/[\w./]*)\[([^\]]+)\]([\w./]*)')


def _expand_globs(cmd: str) -> str:
    """Normalize single-char glob patterns to best-guess literals.

    /bin/c?t → /bin/cat (replace ? with most likely char)
    /etc/sha?ow → /etc/shadow
    Does NOT handle * wildcards (too ambiguous).
    Does NOT access the filesystem.
    """
    result = cmd

    # Handle ? in paths: try common letters that make real words
    # Strategy: for each ?, try 'a'-'z' and see if the result looks like
    # a known path or binary. Fallback: use the surrounding chars as hint.
    def _guess_qmark(m: re.Match) -> str:
        prefix = m.group(1)
        suffix = m.group(2)
        path = prefix + suffix
        # For common patterns, hardcode the likely resolution
        # /bin/c?t → /bin/cat, /etc/sha?ow → /etc/shadow
        # General heuristic: try each letter, prefer ones that form words
        full = prefix + '?' + suffix
        for letter in 'abcdefghijklmnopqrstuvwxyz':
            candidate = prefix + letter + suffix
            # Check if this looks like a real common path
            if candidate in _COMMON_PATHS:
                return candidate
        # Fallback: keep the glob char (will be flagged as indicator)
        return full

    # Apply single-char glob resolution
    prev = result
    result = _GLOB_SINGLE_RE.sub(_guess_qmark, result)
    if result != prev:
        return result

    # Character class resolution: [a-z] → take first char
    def _resolve_class(m: re.Match) -> str:
        prefix = m.group(1)
        chars = m.group(2)
        suffix = m.group(3)
        # Take the first character from the class
        first = chars[0] if chars and chars[0] != '-' else 'a'
        return prefix + first + suffix

    result = _GLOB_CLASS_RE.sub(_resolve_class, result)
    return result


# Common paths for glob guessing — binary names and sensitive files
_COMMON_PATHS = frozenset({
    # Binaries
    "/bin/cat", "/bin/bat", "/bin/cut", "/bin/sh", "/bin/bash", "/bin/dash",
    "/usr/bin/cat", "/usr/bin/cut", "/usr/bin/bat",
    "/usr/bin/head", "/usr/bin/tail", "/usr/bin/find",
    # Sensitive files
    "/etc/shadow", "/etc/passwd", "/etc/sudoers", "/etc/hosts",
    "/etc/crontab", "/etc/fstab",
})


# ---------------------------------------------------------------------------
# 6. /proc/N/root traversal stripping
# ---------------------------------------------------------------------------

_PROC_ROOT_RE = re.compile(r'/proc/\d+/root(/\S+)')


def _strip_proc_root(cmd: str) -> str:
    """Strip /proc/N/root prefix from paths — it aliases the real filesystem.

    /proc/1/root/etc/shadow → /etc/shadow
    """
    return _PROC_ROOT_RE.sub(lambda m: m.group(1), cmd)


# ---------------------------------------------------------------------------
# 7. Concatenation rejoining — join adjacent resolved tokens
# ---------------------------------------------------------------------------

def _rejoin_concatenation(cmd: str) -> str:
    """Post-pass: clean up artifacts from variable expansion.

    After variable expansion, adjacent resolved tokens may need joining.
    Also normalizes multiple spaces to single space.
    """
    # Normalize whitespace (collapse multiple spaces)
    result = re.sub(r'  +', ' ', cmd).strip()
    return result


# ---------------------------------------------------------------------------
# Top-level entry point
# ---------------------------------------------------------------------------

def normalize_shell(command: str) -> tuple[str, list[str]]:
    """Normalize shell metachar evasion to canonical form.

    Returns (normalized_command, indicators).
    Indicators are strings describing what was normalized.
    Safe: returns original command unchanged if no metachar detected.
    Latency target: <0.5ms for typical commands.
    """
    if not command or len(command) > _MAX_INPUT_LEN:
        return command, []

    indicators: list[str] = []
    result = command

    # Order matters: quotes first, then escapes, then variables, then braces, then globs

    prev = result
    result = _remove_quotes(result)
    if result != prev:
        indicators.append("quote_removal")

    prev = result
    result = _resolve_escapes(result)
    if result != prev:
        indicators.append("escape_resolution")

    prev = result
    result, _vars = _expand_variables(result)
    if result != prev:
        indicators.append("variable_expansion")
    if "IFS" in _vars:
        indicators.append("ifs_manipulation")

    prev = result
    result = _expand_braces(result)
    if result != prev:
        indicators.append("brace_expansion")

    prev = result
    result = _expand_globs(result)
    if result != prev:
        indicators.append("glob_normalization")

    prev = result
    result = _strip_proc_root(result)
    if result != prev:
        indicators.append("proc_root_traversal")

    result = _rejoin_concatenation(result)

    return result, indicators
