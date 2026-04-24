"""Tests for :mod:`ralf.detection.deobfuscate` (Linux base).

Skipif-linux because the macOS twin lives in a separate module; the
decoder logic is portable Python but the test payloads reference
GNU-flavor ``base64 -d``.
"""
from __future__ import annotations

import base64
import binascii
import sys

import pytest

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="Linux deobfuscator",
)

from ralf.detection.deobfuscate import deobfuscate, _detect_encoding_type


# --- encoding-type detection ---


def test_detect_base64() -> None:
    # Must contain chars that are in B64 but NOT in hex (so the hex
    # disambiguator doesn't prefer "hex"). "G" is in B64, not in hex.
    assert _detect_encoding_type("G" * 20) == "base64"
    assert _detect_encoding_type("SGVsbG8gV29ybGQgdGhpcw==") == "base64"


def test_detect_hex() -> None:
    # 20+ chars, even length, all hex
    assert _detect_encoding_type("0123456789abcdef0123") == "hex"


def test_detect_too_short() -> None:
    assert _detect_encoding_type("short") is None


def test_detect_random_text() -> None:
    assert _detect_encoding_type("this is not encoded!") is None


# --- base64 subshell / pipe / herestring ---


def _b64(text: str) -> str:
    # Pad payload so encoded form is >= 20 chars
    padded = text + " " * max(0, 16 - len(text))
    return base64.b64encode(padded.encode()).decode()


def test_base64_subshell_decode() -> None:
    enc = _b64("bash -i interactive")
    cmd = f"$(echo {enc} | base64 -d)"
    decoded, indicators = deobfuscate(cmd)
    assert "bash -i" in decoded
    assert any("base64 subshell" in i for i in indicators)


def test_base64_pipe_decode() -> None:
    enc = _b64("whoami system command")
    cmd = f"echo {enc} | base64 -d"
    decoded, indicators = deobfuscate(cmd)
    assert "whoami" in decoded
    assert any("base64 pipe" in i or "base64 subshell" in i for i in indicators)


def test_base64_herestring_decode() -> None:
    enc = _b64("cat passwd filler")
    cmd = f'base64 -d <<< "{enc}"'
    decoded, indicators = deobfuscate(cmd)
    assert "cat passwd" in decoded
    assert any("herestring" in i for i in indicators)


# --- hex xxd ---


def test_hex_xxd_decode() -> None:
    raw = b"echo hello xxd decode"
    hex_str = binascii.hexlify(raw).decode()
    cmd = f"echo {hex_str} | xxd -r -p"
    decoded, indicators = deobfuscate(cmd)
    assert "echo hello" in decoded
    assert any("xxd" in i for i in indicators)


# --- printf hex ---


def test_printf_hex_decode() -> None:
    # \x63 \x61 \x74 = "cat"
    cmd = r"$(printf '\x63\x61\x74')"
    decoded, indicators = deobfuscate(cmd)
    assert "cat" in decoded
    assert any("printf hex" in i for i in indicators)


def test_ansi_c_hex_decode() -> None:
    cmd = r"$'\x62\x61\x73\x68'"
    decoded, indicators = deobfuscate(cmd)
    assert "bash" in decoded
    assert any("ANSI-C hex" in i for i in indicators)


# --- rev / rot13 / octal ---


def test_rev_pipe_decode() -> None:
    cmd = "echo 'imaohw' | rev | bash"
    decoded, indicators = deobfuscate(cmd)
    assert "whoami" in decoded
    assert any("rev pipe" in i for i in indicators)


def test_rot13_pipe_decode() -> None:
    cmd = "echo 'jubnzv' | tr 'a-zA-Z' 'n-za-mN-ZA-M' | bash"
    decoded, indicators = deobfuscate(cmd)
    assert "whoami" in decoded
    assert any("ROT13" in i for i in indicators)


def test_octal_echo_decode() -> None:
    # \143\141\164 = "cat"
    cmd = r"echo -e '\143\141\164' | bash"
    decoded, indicators = deobfuscate(cmd)
    assert "cat" in decoded
    assert any("octal" in i for i in indicators)


# --- string concat flatten ---


def test_flatten_two_part_concat() -> None:
    cmd = "__import__('so' + 'cket')"
    decoded, indicators = deobfuscate(cmd)
    assert "socket" in decoded
    assert any("concat" in i for i in indicators)


def test_flatten_three_part_concat() -> None:
    cmd = "__import__('ba' + 'se' + '64')"
    decoded, _ = deobfuscate(cmd)
    assert "base64" in decoded


def test_flatten_no_change_when_no_concat() -> None:
    cmd = "ls /tmp"
    decoded, indicators = deobfuscate(cmd)
    assert decoded == cmd
    assert indicators == []


# --- interpreter inline decoders ---


def test_python_base64_exec_decode() -> None:
    enc = _b64("os.system(rm)")
    cmd = f"python3 -c \"exec(__import__('base64').b64decode('{enc}'))\""
    decoded, indicators = deobfuscate(cmd)
    assert "os.system" in decoded
    assert any("python base64" in i for i in indicators)


def test_python_hex_exec_decode() -> None:
    raw = b"os.system"
    hex_str = binascii.hexlify(raw).decode()
    cmd = f"python3 -c \"exec(bytes.fromhex('{hex_str}').decode())\""
    decoded, indicators = deobfuscate(cmd)
    assert "os.system" in decoded
    assert any("python hex" in i for i in indicators)


# --- idempotency / safety ---


def test_benign_command_unchanged() -> None:
    decoded, indicators = deobfuscate("git status")
    assert decoded == "git status"
    assert indicators == []


def test_empty_command() -> None:
    decoded, indicators = deobfuscate("")
    assert decoded == ""
    assert indicators == []


def test_malformed_base64_safe() -> None:
    """Invalid base64 should not crash, just pass through."""
    cmd = "echo not_base_64_at_all_but_20_chars!!! | base64 -d"
    decoded, _ = deobfuscate(cmd)
    # Contents should be unchanged since the payload isn't valid b64
    assert "base64 -d" in decoded


def test_manual_decoder_flagged() -> None:
    """Scripts that embed the base64 alphabet + encoded data should flag."""
    code = (
        'alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"\n'
        'data = "SGVsbG8gV29ybGQgdGhpcyBpcyBsb25n"\n'
    )
    _, indicators = deobfuscate(code)
    assert any("manual base64" in i for i in indicators)
