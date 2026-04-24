"""Quote-aware shell command segment splitter + the chokepoint layer.

Single source of truth used by:
    - :func:`ralf.linux.rules_extractor.split_segments`
    - :func:`ralf.macos.rules_extractor.split_segments`
    - :func:`ralf.shared.rules._extract_first_tokens`

Plus the Phase I (2026-04-14) chokepoint — :class:`NormalizedSegment`
and :func:`normalize_command` — which produce a single authoritative
list of normalized segments per ``score_command()`` call. Detectors that
opt in receive the list; detectors that operate on the full command
keep their old ``command: str`` signature. This prevents the
supply-chain-evasion class of bug from recurring: the normalizer runs
exactly once and cannot be bypassed by construction.

Splits a command on top-level pipeline / sequencing operators
(``|``, ``;``, ``&&``, ``||``) while respecting single-quote,
double-quote, and backslash-escape contexts.

What this module does NOT do:
    - Recurse into ``$(...)``, backticks, or process substitutions.
      Subshells are a separate layer handled upstream by
      ``unwrap_shell_wrappers`` and the deobfuscation pipeline.
    - Parse redirections (``>``, ``2>&1``, ``<<``). Those stay attached
      to their segment; detectors that care tokenize further.
    - Honor here-docs. A ``<<EOF ... EOF`` body is walked like regular
      input; in practice detectors care about the command launching
      the here-doc, not its body.

Latency target: <0.5ms for 8KB inputs.
"""
from __future__ import annotations

from dataclasses import dataclass

_MAX_INPUT_LEN = 8192


def split_segments(command: str) -> list[str]:
    """Split ``command`` on unquoted ``|`` / ``;`` / ``&&`` / ``||``.

    Returns a list of non-empty, whitespace-stripped segments. Returns
    an empty list for blank or ``None``-ish input. Quote and escape
    state is tracked so operators appearing inside ``'...'`` or
    ``"..."`` are preserved as literal characters in the same segment.

    Examples:
        >>> split_segments("ls | grep foo")
        ['ls', 'grep foo']
        >>> split_segments("echo 'a || b'")
        ["echo 'a || b'"]
        >>> split_segments('python3 -c "print(1 && 2)"')
        ['python3 -c "print(1 && 2)"']
        >>> split_segments("echo hi && pip install flask==0.12.2")
        ['echo hi', 'pip install flask==0.12.2']
    """
    if not command or not command.strip():
        return []
    if len(command) > _MAX_INPUT_LEN:
        # Pathological input — upstream code_scanner caps at 8KB too.
        # Returning the whole thing as one segment is safer than
        # spending unbounded time walking it char-by-char.
        return [command.strip()]

    parts: list[str] = []
    buf: list[str] = []
    in_single = False
    in_double = False
    i = 0
    n = len(command)

    def _flush() -> None:
        seg = "".join(buf).strip()
        if seg:
            parts.append(seg)
        buf.clear()

    while i < n:
        c = command[i]

        # Backslash escape — outside single quotes, consumes the next
        # char as a literal. Inside single quotes, backslashes are
        # themselves literal (POSIX).
        if c == "\\" and not in_single and i + 1 < n:
            buf.append(c)
            buf.append(command[i + 1])
            i += 2
            continue

        # Quote state toggles. Quotes inside the *other* kind of quote
        # are literal text, not quote toggles.
        if c == "'" and not in_double:
            in_single = not in_single
            buf.append(c)
            i += 1
            continue
        if c == '"' and not in_single:
            in_double = not in_double
            buf.append(c)
            i += 1
            continue

        # Inside any quoted context — operators are literal.
        if in_single or in_double:
            buf.append(c)
            i += 1
            continue

        # Two-char operators take precedence over single-char ones.
        if c == "&" and i + 1 < n and command[i + 1] == "&":
            _flush()
            i += 2
            continue
        if c == "|" and i + 1 < n and command[i + 1] == "|":
            _flush()
            i += 2
            continue

        # Single-char separators.
        if c == ";" or c == "|":
            _flush()
            i += 1
            continue

        buf.append(c)
        i += 1

    _flush()
    return parts


# ── Chokepoint layer (Phase I, 2026-04-14) ──────────────────────────────────


@dataclass(frozen=True)
class NormalizedSegment:
    """A single command segment with all normalization layers applied.

    Produced exactly once per ``score_command()`` call via
    :func:`normalize_command`. Detectors that want per-segment view get
    the list; detectors that operate on the full command keep their
    existing signature.

    Attributes:
        raw: original segment text after quote-aware splitting (pre-normalize)
        normalized: after unwrap_shell_wrappers + strip transparent prefixes
        first_token: basename of the first shell token in ``normalized``
        is_wrapper: whether unwrap_shell_wrappers changed the content
    """
    raw: str
    normalized: str
    first_token: str
    is_wrapper: bool


def normalize_command(command: str) -> list[NormalizedSegment]:
    """Single chokepoint: produce normalized segments for the whole command.

    Pipeline:
        1. ``unwrap_shell_wrappers`` (bash -c, sh -c, $(...), backticks)
        2. ``split_segments`` (quote-aware split on && || ; |)
        3. Per-segment: ``strip_prefixes`` (sudo / env / nohup / time / exec)
        4. Token extraction (first word, basename, POSIX shlex)

    Fails open — if any helper is missing or
    raises, we fall back to a single-element list containing the raw
    command. Detectors should always get at least one segment.
    """
    if not command:
        return []
    try:
        # Defer imports so bash_split stays importable on degraded installs.
        from ralf.detection.supply_chain import _ECOSYSTEM_MAP  # probe
        from ralf.linux.rules_extractor import (
            normalize as _strip_prefixes,
            unwrap_shell_wrappers as _unwrap,
        )
    except Exception:
        # No helpers available — return a naive single segment.
        return [NormalizedSegment(
            raw=command, normalized=command.strip(),
            first_token="", is_wrapper=False,
        )]

    import shlex

    unwrapped = _unwrap(command)
    is_wrapper = unwrapped != command
    raw_segments = split_segments(unwrapped) or [unwrapped.strip()]

    out: list[NormalizedSegment] = []
    for raw in raw_segments:
        norm = _strip_prefixes(raw)
        # One more unwrap pass — a segment might itself be a wrapper
        # (e.g., ``nohup bash -c "..."`` → after strip: ``bash -c "..."``).
        post_unwrap = _unwrap(norm)
        seg_is_wrapper = is_wrapper or (post_unwrap != norm)
        first = ""
        try:
            toks = shlex.split(post_unwrap, posix=True)
            if toks:
                first = toks[0].rsplit("/", 1)[-1]
        except ValueError:
            parts = post_unwrap.split()
            if parts:
                first = parts[0].rsplit("/", 1)[-1]
        out.append(NormalizedSegment(
            raw=raw,
            normalized=post_unwrap,
            first_token=first,
            is_wrapper=seg_is_wrapper,
        ))
    return out


# ── Detector opt-in helpers ─────────────────────────────────────────────────


def first_tokens_from_segments(segments: list[NormalizedSegment]) -> set[str]:
    """Set of first-token basenames across normalized segments."""
    return {s.first_token for s in segments if s.first_token}


def normalized_chain(segments: list[NormalizedSegment]) -> str:
    """Rejoin normalized segments into a single semicolon-separated chain.

    Useful for detectors that want a single string to scan but with
    wrapper envelopes already stripped. Not a faithful reconstruction of
    the original command — operators between segments are lost.
    """
    return "; ".join(s.normalized for s in segments if s.normalized)
