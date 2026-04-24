"""Deobfuscation pipeline: decode base64, hex, printf, rev, ROT13, and octal-encoded commands."""

from __future__ import annotations

import base64
import binascii
import re

# --- Encoding type detection (charset-ratio, not entropy) ---

_B64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
_HEX_CHARS = set("0123456789abcdefABCDEF")

_MIN_TOKEN_LEN = 20


def _detect_encoding_type(token: str) -> str | None:
    """Classify a token by charset ratio.

    100% [A-Za-z0-9+/=] + len>=20 → 'base64'
    100% [0-9a-fA-F] + even length + len>=20 → 'hex'
    """
    if len(token) < _MIN_TOKEN_LEN:
        return None
    chars = set(token)
    if chars <= _B64_CHARS:
        # Disambiguate: if also all hex, prefer hex when even length
        if chars <= _HEX_CHARS and len(token) % 2 == 0:
            return "hex"
        return "base64"
    if chars <= _HEX_CHARS and len(token) % 2 == 0:
        return "hex"
    return None


# --- Subshell pattern decoding ---

# echo ENCODED | base64 -d  (with or without $(...) wrapper)
_B64_SUBSHELL = re.compile(
    r"""\$\(\s*echo\s+["']?([A-Za-z0-9+/=]{20,})["']?\s*\|\s*base64\s+(?:-d|--decode)\s*\)"""
)
_B64_PIPE = re.compile(
    r"""echo\s+["']?([A-Za-z0-9+/=]{20,})["']?\s*\|\s*base64\s+(?:-d|--decode)"""
)
# base64 -d <<< "ENCODED"
_B64_HERESTRING = re.compile(
    r"""base64\s+(?:-d|--decode)\s*<<<\s*["']?([A-Za-z0-9+/=]{20,})["']?"""
)

# echo HEX | xxd -r -p
_HEX_XXD = re.compile(
    r"""echo\s+["']?([0-9a-fA-F]{20,})["']?\s*\|\s*xxd\s+-r\s+-p"""
)

# printf '\x63\x61\x74'  (with or without $(...) wrapper)
_PRINTF_HEX = re.compile(
    r"""\$?\(\s*printf\s+["']((?:\\x[0-9a-fA-F]{2})+)["']\s*\)"""
)
_PRINTF_HEX_BARE = re.compile(
    r"""printf\s+["']((?:\\x[0-9a-fA-F]{2})+)["']"""
)

# $'\x62\x61\x73\x68'  (ANSI-C quoting)
_ANSI_C_HEX = re.compile(
    r"""\$'((?:\\x[0-9a-fA-F]{2})+)'"""
)


def _safe_b64_decode(encoded: str) -> str | None:
    """Attempt base64 decode; return None on failure or non-UTF8."""
    try:
        raw = base64.b64decode(encoded, validate=True)
        return raw.decode("utf-8")
    except Exception:
        return None


def _safe_hex_decode(hex_str: str) -> str | None:
    """Attempt hex decode; return None on failure or non-UTF8."""
    try:
        raw = binascii.unhexlify(hex_str)
        return raw.decode("utf-8")
    except Exception:
        return None


def _decode_printf_hex(escaped: str) -> str | None:
    """Decode \\x63\\x61\\x74 → 'cat'."""
    hex_str = escaped.replace("\\x", "")
    return _safe_hex_decode(hex_str)


def _decode_subshell_patterns(command: str) -> tuple[str, list[str]]:
    """Regex-match and replace subshell decode patterns with decoded plaintext."""
    indicators: list[str] = []
    result = command

    # Base64 subshell: $(echo ... | base64 -d)
    for m in _B64_SUBSHELL.finditer(result):
        decoded = _safe_b64_decode(m.group(1))
        if decoded:
            result = result.replace(m.group(0), decoded)
            indicators.append(f"base64 subshell decoded: {decoded[:60]}")

    # Base64 pipe: echo ... | base64 -d
    for m in _B64_PIPE.finditer(result):
        decoded = _safe_b64_decode(m.group(1))
        if decoded:
            result = result.replace(m.group(0), decoded)
            indicators.append(f"base64 pipe decoded: {decoded[:60]}")

    # Base64 herestring: base64 -d <<< "..."
    for m in _B64_HERESTRING.finditer(result):
        decoded = _safe_b64_decode(m.group(1))
        if decoded:
            result = result.replace(m.group(0), decoded)
            indicators.append(f"base64 herestring decoded: {decoded[:60]}")

    # Hex xxd: echo ... | xxd -r -p
    for m in _HEX_XXD.finditer(result):
        decoded = _safe_hex_decode(m.group(1))
        if decoded:
            result = result.replace(m.group(0), decoded)
            indicators.append(f"hex xxd decoded: {decoded[:60]}")

    # printf hex: $(printf '\x...')
    for m in _PRINTF_HEX.finditer(result):
        decoded = _decode_printf_hex(m.group(1))
        if decoded:
            result = result.replace(m.group(0), decoded)
            indicators.append(f"printf hex decoded: {decoded[:60]}")

    # printf hex bare: printf '\x...'
    for m in _PRINTF_HEX_BARE.finditer(result):
        decoded = _decode_printf_hex(m.group(1))
        if decoded:
            result = result.replace(m.group(0), decoded)
            indicators.append(f"printf hex decoded: {decoded[:60]}")

    # ANSI-C hex: $'\x62\x61\x73\x68'
    for m in _ANSI_C_HEX.finditer(result):
        decoded = _decode_printf_hex(m.group(1))
        if decoded:
            result = result.replace(m.group(0), decoded)
            indicators.append(f"ANSI-C hex decoded: {decoded[:60]}")

    return result, indicators


def _decode_inline_blobs(command: str) -> tuple[str, list[str]]:
    """Find standalone tokens matching charset-ratio, attempt decode.

    Only tokens NOT inside $(...). Returns (command, indicators).
    """
    indicators: list[str] = []
    # Skip tokens inside subshells — those are handled by _decode_subshell_patterns
    # Simple heuristic: split on whitespace, skip if token contains $( or is a flag
    import shlex
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        tokens = command.split()

    for token in tokens:
        if token.startswith("-") or "$(" in token or "`" in token:
            continue
        # Skip common false positives: paths, URLs
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
    """Decode base64/hex payloads embedded in interpreter -c/-e arguments.

    Patterns:
      Python: exec(__import__('base64').b64decode('...'))
      Python: exec(bytes.fromhex('...').decode())
      Python: eval(codecs.decode('...', 'hex'))
      Node:   eval(Buffer.from('...', 'base64').toString())
      Ruby:   eval(Base64.decode64('...'))
    """
    indicators: list[str] = []
    result = command

    # Python: exec(__import__('base64').b64decode('ENCODED'))
    for m in re.finditer(
        r"""exec\s*\(\s*__import__\s*\(\s*['"]base64['"]\s*\)\s*\.b64decode\s*\(\s*['"]([A-Za-z0-9+/=]+)['"]\s*\)""",
        result,
    ):
        decoded = _safe_b64_decode(m.group(1))
        if decoded:
            result = result.replace(m.group(0), f"exec({decoded!r}")
            indicators.append(f"python base64 exec decoded: {decoded[:60]}")

    # Python: exec(bytes.fromhex('ENCODED').decode())
    for m in re.finditer(
        r"""exec\s*\(\s*bytes\.fromhex\s*\(\s*['"]([0-9a-fA-F]+)['"]\s*\)\s*\.decode\s*\(\s*\)""",
        result,
    ):
        decoded = _safe_hex_decode(m.group(1))
        if decoded:
            result = result.replace(m.group(0), f"exec({decoded!r}")
            indicators.append(f"python hex exec decoded: {decoded[:60]}")

    # Python: eval(codecs.decode('ENCODED', 'hex'))
    for m in re.finditer(
        r"""eval\s*\(\s*codecs\.decode\s*\(\s*['"]([0-9a-fA-F]+)['"]\s*,\s*['"]hex['"]\s*\)""",
        result,
    ):
        decoded = _safe_hex_decode(m.group(1))
        if decoded:
            result = result.replace(m.group(0), f"eval({decoded!r}")
            indicators.append(f"python codecs hex decoded: {decoded[:60]}")

    # Node: eval(Buffer.from('ENCODED', 'base64').toString())
    for m in re.finditer(
        r"""eval\s*\(\s*Buffer\.from\s*\(\s*['"]([A-Za-z0-9+/=]+)['"]\s*,\s*['"]base64['"]\s*\)\s*\.toString\s*\(\s*\)""",
        result,
    ):
        decoded = _safe_b64_decode(m.group(1))
        if decoded:
            result = result.replace(m.group(0), f"eval({decoded!r}")
            indicators.append(f"node base64 eval decoded: {decoded[:60]}")

    # Ruby: eval(Base64.decode64('ENCODED'))
    for m in re.finditer(
        r"""eval\s*\(\s*Base64\.decode64\s*\(\s*['"]([A-Za-z0-9+/=]+)['"]\s*\)""",
        result,
    ):
        decoded = _safe_b64_decode(m.group(1))
        if decoded:
            result = result.replace(m.group(0), f"eval({decoded!r}")
            indicators.append(f"ruby base64 eval decoded: {decoded[:60]}")

    return result, indicators


# ---------------------------------------------------------------------------
# Sprint 2k: Additional decode patterns (rev, ROT13, octal)
# ---------------------------------------------------------------------------

# echo 'REVERSED' | rev | bash/sh
_REV_PIPE = re.compile(
    r"""echo\s+(?:["']([^"']+)["']|(\S+))\s*\|\s*rev\s*\|\s*(?:bash|sh|dash|zsh)"""
)

# echo 'ROT13' | tr 'a-zA-Z' 'n-za-mN-ZA-M' | bash/sh
_ROT13_PIPE = re.compile(
    r"""echo\s+(?:["']([^"']+)["']|(\S+))\s*\|\s*tr\s+['"]a-zA-Z['"]\s+['"]n-za-mN-ZA-M['"]\s*\|\s*(?:bash|sh|dash|zsh)"""
)

# echo -e '\143\141\164...' | bash (octal escapes)
_OCTAL_ECHO = re.compile(
    r"""echo\s+-e\s+["']((?:\\[0-3]?[0-7]{1,2}[\s]*)+)["']\s*(?:\|\s*(?:bash|sh|dash|zsh))?"""
)


def _decode_rev_pipe(command: str) -> tuple[str, list[str]]:
    """Decode echo 'REVERSED' | rev | bash patterns."""
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
    """Decode echo 'ROT13' | tr 'a-zA-Z' 'n-za-mN-ZA-M' | bash patterns."""
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
    """Decode echo -e '\\143\\141\\164...' octal escape patterns."""
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
    """Detect manual base64/hex decoder implementations in script content.

    Catches scripts that avoid importing base64 by implementing their own
    decoder using the base64 alphabet string + encoded data.
    """
    indicators: list[str] = []

    # Base64 alphabet string (full or partial) alongside encoded-looking data
    has_b64_alphabet = bool(re.search(
        r'["\']ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\+/',
        command,
    ))
    has_b64_data = bool(re.search(r'["\'][A-Za-z0-9+/=]{20,}["\']', command))

    if has_b64_alphabet and has_b64_data:
        indicators.append("manual base64 decoder: alphabet + encoded data in same script")

    # Hex lookup table + encoded data
    has_hex_table = bool(re.search(r'["\']0123456789abcdef', command, re.IGNORECASE))
    has_hex_data = bool(re.search(r'["\'][0-9a-fA-F]{20,}["\']', command))

    if has_hex_table and has_hex_data:
        indicators.append("manual hex decoder: lookup table + encoded data in same script")

    return indicators


def _flatten_string_concat(command: str) -> tuple[str, list[str]]:
    """Flatten Python string concatenation used to evade pattern matching.

    Catches:
      __import__('so' + 'cket')        → __import__('socket')
      __import__("so" + "ck" + "et")   → __import__("socket")
      'ba' + 'se' + '64'              → 'base64'
    """
    indicators: list[str] = []
    result = command

    # Match chains of 'str' + 'str' (single or double quoted)
    concat_pattern = re.compile(
        r"""(['"])([^'"]*)\1\s*\+\s*(['"])([^'"]*)\3"""
    )

    # Iteratively flatten until no more concatenations
    for _ in range(10):  # Max 10 passes to prevent infinite loops
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
    """Main entry point. Runs string concat flatten, subshell, interpreter,
    then inline blob decoding.

    Safe: decode failures return original command unchanged.
    Returns (deobfuscated_command, list_of_indicator_strings).
    """
    # Flatten string concatenation FIRST — before any pattern matching
    result, concat_indicators = _flatten_string_concat(command)
    indicators = concat_indicators

    result, subshell_indicators = _decode_subshell_patterns(result)
    indicators.extend(subshell_indicators)
    # Sprint 2k: rev, ROT13, octal decode
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

    # Detect manual decoder implementations (no decoding needed — just flag)
    manual_indicators = _detect_manual_decoder(result)
    indicators.extend(manual_indicators)

    return result, indicators
