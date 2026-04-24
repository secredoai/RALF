"""RALF detection primitives — pure Python, no I/O.

Modules:
- ``sensitive_paths`` — sensitive path / device regex
- ``deobfuscate`` — shell deobfuscation pipeline
- ``shell_normalize`` — shell normalization
- ``command_intent`` — per-binary intent classification
- ``intent_flow`` — multi-segment intent flow analysis
- ``code_scanner`` — file-content threat scanning
"""
from __future__ import annotations

__version__ = "0.1.0"

from ralf.detection.command_intent import (
    CommandIntent,
    IntentClassification,
    IntentClassifier,
    classify,
)
from ralf.detection.deobfuscate import deobfuscate
from ralf.detection.intent_flow import IntentFlowEngine
from ralf.detection.sensitive_paths import get_matches, has_sensitive
from ralf.detection.shell_normalize import normalize_shell

__all__ = [
    "__version__",
    "has_sensitive",
    "get_matches",
    "deobfuscate",
    "normalize_shell",
    "IntentFlowEngine",
    "IntentClassifier",
    "IntentClassification",
    "CommandIntent",
    "classify",
]
