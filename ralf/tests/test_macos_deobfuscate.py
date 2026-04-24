"""Tests for :mod:`ralf.macos.deobfuscate`.

Module is importable on any OS (it's pure Python), so these tests run
on Linux too — they exercise the BSD ``base64 -D`` flag support and the
shared decoder logic. A macOS-native integration test would live
separately.
"""
from __future__ import annotations

import base64

from ralf.macos.deobfuscate import deobfuscate


def _b64(text: str) -> str:
    padded = text + " " * max(0, 16 - len(text))
    return base64.b64encode(padded.encode()).decode()


# --- BSD -D flag: the whole point of the macOS fork ---


def test_base64_subshell_bsd_flag() -> None:
    enc = _b64("bash -i macos bsd")
    cmd = f"$(echo {enc} | base64 -D)"
    decoded, indicators = deobfuscate(cmd)
    assert "bash -i" in decoded
    assert any("base64 subshell" in i for i in indicators)


def test_base64_pipe_bsd_flag() -> None:
    enc = _b64("whoami bsd flag test")
    cmd = f"echo {enc} | base64 -D"
    decoded, indicators = deobfuscate(cmd)
    assert "whoami" in decoded


def test_base64_herestring_bsd_flag() -> None:
    enc = _b64("cat passwd bsd test")
    cmd = f'base64 -D <<< "{enc}"'
    decoded, indicators = deobfuscate(cmd)
    assert "cat passwd" in decoded


# --- GNU -d flag still works (macOS with Homebrew coreutils) ---


def test_base64_subshell_gnu_flag_still_works() -> None:
    enc = _b64("bash -i still works")
    cmd = f"$(echo {enc} | base64 -d)"
    decoded, _ = deobfuscate(cmd)
    assert "bash -i" in decoded


def test_base64_long_decode_flag() -> None:
    enc = _b64("bash -i long decode test")
    cmd = f"$(echo {enc} | base64 --decode)"
    decoded, _ = deobfuscate(cmd)
    assert "bash -i" in decoded


# --- shared decoder logic (identical across Linux/macOS) ---


def test_rev_pipe_decode_zsh() -> None:
    """zsh is macOS default; our regex lists zsh first."""
    cmd = "echo 'imaohw' | rev | zsh"
    decoded, _ = deobfuscate(cmd)
    assert "whoami" in decoded


def test_string_concat_flatten() -> None:
    cmd = "__import__('so' + 'cket')"
    decoded, _ = deobfuscate(cmd)
    assert "socket" in decoded


def test_printf_hex_ansi_c() -> None:
    cmd = r"$'\x62\x61\x73\x68'"
    decoded, _ = deobfuscate(cmd)
    assert "bash" in decoded


def test_benign_unchanged() -> None:
    decoded, indicators = deobfuscate("git status")
    assert decoded == "git status"
    assert indicators == []
