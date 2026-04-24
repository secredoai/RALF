"""Platform detection and per-OS module dispatcher.

:func:`get_platform_name` returns ``"linux"`` or ``"macos"``. The
``get_rules_extractor`` / ``get_intent_classifier`` /
``get_deobfuscator`` helpers return the OS-appropriate implementation
so callers don't scatter ``if sys.platform`` checks through the code.
"""
from __future__ import annotations

import sys
from types import ModuleType


class UnsupportedPlatformError(RuntimeError):
    """Raised when running on an unsupported OS."""


def get_platform_name() -> str:
    """Return ``"linux"`` or ``"macos"``; raise if neither."""
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform == "darwin":
        return "macos"
    raise UnsupportedPlatformError(
        f"RALF supports Linux and macOS only; got sys.platform={sys.platform!r}"
    )


def get_rules_extractor() -> ModuleType:
    """Return the OS-appropriate ``rules_extractor`` module."""
    name = get_platform_name()
    if name == "linux":
        from ralf.linux import rules_extractor
        return rules_extractor
    from ralf.macos import rules_extractor
    return rules_extractor


def get_intent_classifier() -> ModuleType:
    """Return the OS-appropriate ``intent_classifier`` module.

    Linux uses the shared base classifier from
    :mod:`ralf.detection.command_intent`. macOS keeps its own fork
    because it carries BSD flag overrides + macOS-only binaries.
    """
    name = get_platform_name()
    if name == "linux":
        from ralf.detection import command_intent
        return command_intent
    from ralf.macos import intent_classifier
    return intent_classifier


def get_deobfuscator() -> ModuleType:
    """Return the OS-appropriate ``deobfuscate`` module.

    Linux uses the shared deobfuscator from
    :mod:`ralf.detection.deobfuscate`. macOS keeps its own fork because
    it extends the regex set to also match BSD userland flags.
    """
    name = get_platform_name()
    if name == "linux":
        from ralf.detection import deobfuscate
        return deobfuscate
    from ralf.macos import deobfuscate
    return deobfuscate
