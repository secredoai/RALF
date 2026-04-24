"""macOS command deobfuscator — BSD userland fork of linux/deobfuscate.py.

Differences from the Linux twin:
    - BSD ``base64 -D`` flag added to decode regex alternation (Linux
      uses ``-d`` / ``--decode``; macOS system base64 uses ``-D``).
      Homebrew coreutils users on macOS can still type ``-d``, so the
      regex accepts both.
    - ``md5`` vs ``md5sum`` would matter if a decoder used the hash
      name, but no current decoder does. If a future decoder adds hash-based
      obfuscation pattern, this file diverges.
    - Shell list in rev / ROT13 / octal pipes includes ``zsh`` first
      (default macOS shell) rather than ``bash``. The behavior is
      identical because both shells accept piped input the same way;
      the ordering is just documentary.

Everything else is a straight fork of ``ralf/linux/deobfuscate.py``
and should track it closely — divergence here is intentional, not
incidental, and must come with a code comment explaining why.
"""
from __future__ import annotations

import base64
import binascii
import re

_B64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
_HEX_CHARS = set("0123456789abcdefABCDEF")

_MIN_TOKEN_LEN = 20


def _detect_encoding_type(token: str) -> str | None:
    if len(token) < _MIN_TOKEN_LEN:
        return None
    chars = set(token)
    if chars <= _B64_CHARS:
        if chars <= _HEX_CHARS and len(token) % 2 == 0:
            return "hex"
        return "base64"
    if chars <= _HEX_CHARS and len(token) % 2 == 0:
        return "hex"
    return None


# BSD flag support: (?:-d|--decode|-D) — note the uppercase -D
_BSD_B64_FLAGS = r"(?:-d|--decode|-D)"

_B64_SUBSHELL = re.compile(
    r"""\$\(\s*echo\s+["']?([A-Za-z0-9+/=]{20,})["']?\s*\|\s*base64\s+"""
    + _BSD_B64_FLAGS
    + r"""\s*\)"""
)
_B64_PIPE = re.compile(
    r"""echo\s+["']?([A-Za-z0-9+/=]{20,})["']?\s*\|\s*base64\s+"""
    + _BSD_B64_FLAGS
)
_B64_HERESTRING = re.compile(
    r"""base64\s+"""
    + _BSD_B64_FLAGS
    + r"""\s*<<<\s*["']?([A-Za-z0-9+/=]{20,})["']?"""
)

_HEX_XXD = re.compile(
    r"""echo\s+["']?([0-9a-fA-F]{20,})["']?\s*\|\s*xxd\s+-r\s+-p"""
)

_PRINTF_HEX = re.compile(
    r"""\$?\(\s*printf\s+["']((?:\\x[0-9a-fA-F]{2})+)["']\s*\)"""
)
_PRINTF_HEX_BARE = re.compile(
    r"""printf\s+["']((?:\\x[0-9a-fA-F]{2})+)["']"""
)
_ANSI_C_HEX = re.compile(
    r"""\$'((?:\\x[0-9a-fA-F]{2})+)'"""
)


def _safe_b64_decode(encoded: str) -> str | None:
    try:
        raw = base64.b64decode(encoded, validate=True)
        return raw.decode("utf-8")
    except Exception:
        return None


def _safe_hex_decode(hex_str: str) -> str | None:
    try:
        raw = binascii.unhexlify(hex_str)
        return raw.decode("utf-8")
    except Exception:
        return None


def _decode_printf_hex(escaped: str) -> str | None:
    hex_str = escaped.replace("\\x", "")
    return _safe_hex_decode(hex_str)


def _decode_subshell_patterns(command: str) -> tuple[str, list[str]]:
    indicators: list[str] = []
    result = command

    for m in _B64_SUBSHELL.finditer(result):
        decoded = _safe_b64_decode(m.group(1))
        if decoded:
            result = result.replace(m.group(0), decoded)
            indicators.append(f"base64 subshell decoded: {decoded[:60]}")

    for m in _B64_PIPE.finditer(result):
        decoded = _safe_b64_decode(m.group(1))
        if decoded:
            result = result.replace(m.group(0), decoded)
            indicators.append(f"base64 pipe decoded: {decoded[:60]}")

    for m in _B64_HERESTRING.finditer(result):
        decoded = _safe_b64_decode(m.group(1))
        if decoded:
            result = result.replace(m.group(0), decoded)
            indicators.append(f"base64 herestring decoded: {decoded[:60]}")

    for m in _HEX_XXD.finditer(result):
        decoded = _safe_hex_decode(m.group(1))
        if decoded:
            result = result.replace(m.group(0), decoded)
            indicators.append(f"hex xxd decoded: {decoded[:60]}")

    for m in _PRINTF_HEX.finditer(result):
        decoded = _decode_printf_hex(m.group(1))
        if decoded:
            result = result.replace(m.group(0), decoded)
            indicators.append(f"printf hex decoded: {decoded[:60]}")

    for m in _PRINTF_HEX_BARE.finditer(result):
        decoded = _decode_printf_hex(m.group(1))
        if decoded:
            result = result.replace(m.group(0), decoded)
            indicators.append(f"printf hex decoded: {decoded[:60]}")

    for m in _ANSI_C_HEX.finditer(result):
        decoded = _decode_printf_hex(m.group(1))
        if decoded:
            result = result.replace(m.group(0), decoded)
            indicators.append(f"ANSI-C hex decoded: {decoded[:60]}")

    return result, indicators


def _decode_inline_blobs(command: str) -> tuple[str, list[str]]:
    indicators: list[str] = []
    import shlex
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        tokens = command.split()

    for token in tokens:
        if token.startswith("-") or "$(" in token or "`" in token:
            continue
        if "/" in token and not token.startswith("/tmp/"):
            continue
        enc_type = _detect_encoding_type(token)
        if enc_type == "base64":
            decoded = _safe_b64_decode(token)
            if decoded:
                command = command.replace(token, decoded, 1)
                indicators.append(f"inline base64 decoded: {decoded[:60]}")
        elif enc_type == "hex":
            decoded = _safe_hex_decode(token)
            if decoded:
                command = command.replace(token, decoded, 1)
                indicators.append(f"inline hex decoded: {decoded[:60]}")

    return command, indicators


def _decode_interpreter_patterns(command: str) -> tuple[str, list[str]]:
    indicators: list[str] = []
    result = command

    for m in re.finditer(
        r"""exec\s*\(\s*__import__\s*\(\s*['"]base64['"]\s*\)\s*\.b64decode\s*\(\s*['"]([A-Za-z0-9+/=]+)['"]\s*\)""",
        result,
    ):
        decoded = _safe_b64_decode(m.group(1))
        if decoded:
            result = result.replace(m.group(0), f"exec({decoded!r}")
            indicators.append(f"python base64 exec decoded: {decoded[:60]}")

    for m in re.finditer(
        r"""exec\s*\(\s*bytes\.fromhex\s*\(\s*['"]([0-9a-fA-F]+)['"]\s*\)\s*\.decode\s*\(\s*\)""",
        result,
    ):
        decoded = _safe_hex_decode(m.group(1))
        if decoded:
            result = result.replace(m.group(0), f"exec({decoded!r}")
            indicators.append(f"python hex exec decoded: {decoded[:60]}")

    for m in re.finditer(
        r"""eval\s*\(\s*codecs\.decode\s*\(\s*['"]([0-9a-fA-F]+)['"]\s*,\s*['"]hex['"]\s*\)""",
        result,
    ):
        decoded = _safe_hex_decode(m.group(1))
        if decoded:
            result = result.replace(m.group(0), f"eval({decoded!r}")
            indicators.append(f"python codecs hex decoded: {decoded[:60]}")

    for m in re.finditer(
        r"""eval\s*\(\s*Buffer\.from\s*\(\s*['"]([A-Za-z0-9+/=]+)['"]\s*,\s*['"]base64['"]\s*\)\s*\.toString\s*\(\s*\)""",
        result,
    ):
        decoded = _safe_b64_decode(m.group(1))
        if decoded:
            result = result.replace(m.group(0), f"eval({decoded!r}")
            indicators.append(f"node base64 eval decoded: {decoded[:60]}")

    for m in re.finditer(
        r"""eval\s*\(\s*Base64\.decode64\s*\(\s*['"]([A-Za-z0-9+/=]+)['"]\s*\)""",
        result,
    ):
        decoded = _safe_b64_decode(m.group(1))
        if decoded:
            result = result.replace(m.group(0), f"eval({decoded!r}")
            indicators.append(f"ruby base64 eval decoded: {decoded[:60]}")

    return result, indicators


# rev / ROT13 / octal — zsh listed first as the macOS default shell.
_REV_PIPE = re.compile(
    r"""echo\s+(?:["']([^"']+)["']|(\S+))\s*\|\s*rev\s*\|\s*(?:zsh|bash|sh|dash)"""
)
_ROT13_PIPE = re.compile(
    r"""echo\s+(?:["']([^"']+)["']|(\S+))\s*\|\s*tr\s+['"]a-zA-Z['"]\s+['"]n-za-mN-ZA-M['"]\s*\|\s*(?:zsh|bash|sh|dash)"""
)
_OCTAL_ECHO = re.compile(
    r"""echo\s+-e\s+["']((?:\\[0-3]?[0-7]{1,2}[\s]*)+)["']\s*(?:\|\s*(?:zsh|bash|sh|dash))?"""
)


def _decode_rev_pipe(command: str) -> tuple[str, list[str]]:
    indicators: list[str] = []
    result = command
    for m in _REV_PIPE.finditer(result):
        encoded = m.group(1) or m.group(2) or ""
        decoded = encoded[::-1]
        if decoded:
            result = result.replace(m.group(0), decoded)
            indicators.append(f"rev pipe decoded: {decoded[:60]}")
    return result, indicators


def _decode_rot13_pipe(command: str) -> tuple[str, list[str]]:
    import codecs
    indicators: list[str] = []
    result = command
    for m in _ROT13_PIPE.finditer(result):
        encoded = m.group(1) or m.group(2) or ""
        decoded = codecs.decode(encoded, 'rot_13')
        if decoded:
            result = result.replace(m.group(0), decoded)
            indicators.append(f"ROT13 pipe decoded: {decoded[:60]}")
    return result, indicators


def _decode_octal_echo(command: str) -> tuple[str, list[str]]:
    indicators: list[str] = []
    result = command
    for m in _OCTAL_ECHO.finditer(result):
        encoded = m.group(1)
        try:
            decoded = re.sub(
                r'\\([0-3]?[0-7]{1,2})',
                lambda x: chr(int(x.group(1), 8)),
                encoded,
            ).strip()
            if decoded and len(decoded) >= 2:
                result = result.replace(m.group(0), decoded)
                indicators.append(f"octal echo decoded: {decoded[:60]}")
        except (ValueError, OverflowError):
            pass
    return result, indicators


def _detect_manual_decoder(command: str) -> list[str]:
    indicators: list[str] = []

    has_b64_alphabet = bool(re.search(
        r'["\']ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\+/',
        command,
    ))
    has_b64_data = bool(re.search(r'["\'][A-Za-z0-9+/=]{20,}["\']', command))
    if has_b64_alphabet and has_b64_data:
        indicators.append("manual base64 decoder: alphabet + encoded data in same script")

    has_hex_table = bool(re.search(r'["\']0123456789abcdef', command, re.IGNORECASE))
    has_hex_data = bool(re.search(r'["\'][0-9a-fA-F]{20,}["\']', command))
    if has_hex_table and has_hex_data:
        indicators.append("manual hex decoder: lookup table + encoded data in same script")

    return indicators


def _flatten_string_concat(command: str) -> tuple[str, list[str]]:
    indicators: list[str] = []
    result = command

    concat_pattern = re.compile(
        r"""(['"])([^'"]*)\1\s*\+\s*(['"])([^'"]*)\3"""
    )

    for _ in range(10):
        m = concat_pattern.search(result)
        if not m:
            break
        merged = m.group(2) + m.group(4)
        quote = m.group(1)
        result = result[:m.start()] + f"{quote}{merged}{quote}" + result[m.end():]
        if not indicators:
            indicators.append(f"string concatenation flattened: {quote}{merged}{quote}")

    return result, indicators


def deobfuscate(command: str) -> tuple[str, list[str]]:
    """Main entry point — see ``linux/deobfuscate.deobfuscate`` for semantics.

    BSD userland: accepts ``base64 -D`` in addition to ``-d`` and ``--decode``.
    """
    result, concat_indicators = _flatten_string_concat(command)
    indicators: list[str] = list(concat_indicators)

    result, subshell_indicators = _decode_subshell_patterns(result)
    indicators.extend(subshell_indicators)
    result, rev_indicators = _decode_rev_pipe(result)
    indicators.extend(rev_indicators)
    result, rot13_indicators = _decode_rot13_pipe(result)
    indicators.extend(rot13_indicators)
    result, octal_indicators = _decode_octal_echo(result)
    indicators.extend(octal_indicators)
    result, interp_indicators = _decode_interpreter_patterns(result)
    indicators.extend(interp_indicators)
    result, inline_indicators = _decode_inline_blobs(result)
    indicators.extend(inline_indicators)

    indicators.extend(_detect_manual_decoder(result))

    return result, indicators
