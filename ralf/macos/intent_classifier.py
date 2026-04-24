"""macOS intent-aware command classifier.

Imports the base rule table from ``ralf.detection.command_intent`` and
adds the macOS-specific overrides:

    - ``_SENSITIVE_PATHS`` with macOS additions (``Library/Keychains``,
      Chrome ``Login Data``)
    - ``base64`` rule overridden to also match the BSD ``-D`` flag
    - macOS-only binaries: launchctl, plutil, defaults, codesign,
      xattr, csrutil, spctl, xcrun, brew

The classifier algorithm itself is duplicated locally (~50 LOC) so the
macOS-extended sensitive-path regex is used for the EXFIL/STAGE
escalation decisions. The base ``IntentClassifier`` from
``ralf.detection.command_intent`` uses its own (Linux/canonical)
sensitive-path regex which doesn't know about Keychains.
"""
from __future__ import annotations

import re

from ralf.detection.command_intent import (
    CommandIntent,
    IntentClassification,
    _INTENT_RULES as _BASE_RULES,
    _SUPPRESS_INTENTS,
    _rules,
)


# macOS-extended sensitive paths: Linux/canonical set PLUS Keychains and
# the Chrome Login Data plist (the macOS analog of Linux ~/.config).
_SENSITIVE_PATHS = re.compile(
    r'(?:/etc/(?:shadow|passwd|sudoers|ssh)|'
    r'\.ssh/(?:id_rsa|id_ed25519|authorized_keys)|'
    r'\.gnupg|\.aws/credentials|\.kube/config|'
    r'\.docker/config\.json|'
    r'Library/Keychains|'
    r'Library/Application Support/Google/Chrome/Default/Login Data)',
    re.I,
)


# Build the macOS rule table by copying the shared base, overriding the
# entries that need BSD-flavored tweaks, and appending macOS-only binaries.
_INTENT_RULES: dict = dict(_BASE_RULES)

# base64 — BSD userland uses uppercase `-D` for decode in addition to `-d`.
_INTENT_RULES["base64"] = _rules(
    (r'(?:-d\b|-D\b|--decode\b)', CommandIntent.READ, 0.80, "base64 decode"),
    (None, CommandIntent.OPERATE, 0.70, "base64 encode"),
)

# ---------- macOS-only binaries ----------

# launchctl — macOS init/service manager
_INTENT_RULES["launchctl"] = _rules(
    (r'\b(?:list|print|print-cache|managername|managerpid|managerid)\b',
     CommandIntent.READ, 0.95, "launchctl read-only query"),
    (r'\b(?:load|bootstrap|enable)\b',
     CommandIntent.PERSIST, 0.90, "launchctl persistence via launchd"),
    (r'\b(?:unload|bootout|disable|remove)\b',
     CommandIntent.DISRUPT, 0.85, "launchctl service disruption"),
    (r'\b(?:start|stop|kickstart|kill)\b',
     CommandIntent.OPERATE, 0.80, "launchctl service operation"),
    (None, CommandIntent.UNKNOWN, 0.5, "launchctl unclassified"),
)

# plutil — property-list inspector/editor.
# Note: no leading \b before dash-flags; \b requires a word-char
# transition and `-` is not a word char.
_INTENT_RULES["plutil"] = _rules(
    (r'(?:\s|^)(?:-p|-convert\s+xml1|-lint)\b',
     CommandIntent.READ, 0.90, "plutil inspect plist"),
    (r'(?:\s|^)(?:-replace|-insert|-remove)\b',
     CommandIntent.EDIT, 0.85, "plutil modify plist"),
    (None, CommandIntent.UNKNOWN, 0.5, "plutil unclassified"),
)

# defaults — user preference editor (plist for apps)
_INTENT_RULES["defaults"] = _rules(
    (r'\b(?:read|find|help|domains)\b',
     CommandIntent.READ, 0.95, "defaults read preference"),
    (r'\b(?:write|delete|import|rename)\b',
     CommandIntent.EDIT, 0.85, "defaults write preference"),
    (None, CommandIntent.UNKNOWN, 0.5, "defaults unclassified"),
)

# codesign — can strip signatures (trust weakening)
_INTENT_RULES["codesign"] = _rules(
    (r'\s--remove-signature\b',
     CommandIntent.ESCALATE, 0.85, "codesign --remove-signature (trust weakening)"),
    (r'\s(?:-v|--verify|-d|--display|-h)\b',
     CommandIntent.READ, 0.95, "codesign verification / inspection"),
    (None, CommandIntent.OPERATE, 0.70, "codesign operation"),
)

# xattr — can strip quarantine flag (Gatekeeper bypass)
_INTENT_RULES["xattr"] = _rules(
    (r'\s-d\s+com\.apple\.quarantine\b',
     CommandIntent.ESCALATE, 0.95, "xattr remove quarantine (Gatekeeper bypass)"),
    (r'\s(?:-cr?\b|-d\b)',
     CommandIntent.EDIT, 0.80, "xattr strip attributes"),
    (None, CommandIntent.READ, 0.85, "xattr query"),
)

# csrutil — System Integrity Protection
_INTENT_RULES["csrutil"] = _rules(
    (r'\bstatus\b', CommandIntent.READ, 0.95, "csrutil status"),
    (r'\b(?:disable|enable)\b',
     CommandIntent.ESCALATE, 0.90, "csrutil toggles SIP (Recovery only)"),
    (None, CommandIntent.UNKNOWN, 0.5, "csrutil unclassified"),
)

# spctl — Gatekeeper assessment. Same leading-\b caveat as plutil.
_INTENT_RULES["spctl"] = _rules(
    (r'(?:\s|^)(?:--status|--assess|--list)\b',
     CommandIntent.READ, 0.95, "spctl assessment query"),
    (r'(?:\s|^)(?:--master-disable|--add|--remove)\b',
     CommandIntent.ESCALATE, 0.85, "spctl Gatekeeper modification"),
    (None, CommandIntent.OPERATE, 0.70, "spctl operation"),
)

# xcrun — Xcode command-line launcher
_INTENT_RULES["xcrun"] = _rules(
    (None, CommandIntent.OPERATE, 0.70, "xcrun tool launcher"),
)

# brew — Homebrew package manager. --version omitted because it'd
# need the dash-flag prefix trick; subcommands are word tokens so
# plain \b works for them.
_INTENT_RULES["brew"] = _rules(
    (r'\b(?:list|info|search|doctor|help|home|uses|deps)\b',
     CommandIntent.READ, 0.95, "brew read-only subcommand"),
    (r'\b(?:install|uninstall|upgrade|update|reinstall|pin|unpin|link|unlink)\b',
     CommandIntent.OPERATE, 0.80, "brew package operation"),
    (None, CommandIntent.UNKNOWN, 0.5, "brew unclassified"),
)


class IntentClassifier:
    """macOS classifier — same algorithm as the shared base, but using
    the macOS-extended ``_INTENT_RULES`` and ``_SENSITIVE_PATHS``.
    """

    @staticmethod
    def classify(binary: str, command: str) -> IntentClassification:
        binary = binary.rsplit("/", 1)[-1] if "/" in binary else binary

        if binary in ("cat", "head", "tail", "base64") and "|" in command:
            if _SENSITIVE_PATHS.search(command) and re.search(
                r'\|\s*(?:nc|ncat|curl|wget|socat|ssh|scp|netcat)\b', command
            ):
                return IntentClassification(
                    binary=binary, intent=CommandIntent.EXFIL,
                    confidence=0.90,
                    evidence="sensitive file piped to network tool",
                    suppress_identity=False,
                )

        if binary in ("echo", "cat", "printf", "yes") and "|" in command:
            pipe_parts = command.split("|")
            if len(pipe_parts) >= 2:
                last = pipe_parts[-1].strip().split()
                if last:
                    pipe_target = last[0].rsplit("/", 1)[-1]
                    if pipe_target in _INTENT_RULES:
                        return IntentClassifier.classify(pipe_target, command)

        rules = _INTENT_RULES.get(binary)
        if not rules:
            return IntentClassification(
                binary=binary,
                intent=CommandIntent.UNKNOWN,
                confidence=0.0,
                evidence="binary not in intent classifier",
                suppress_identity=False,
            )

        for rule in rules:
            if rule.pattern is None:
                return IntentClassification(
                    binary=binary,
                    intent=rule.intent,
                    confidence=rule.confidence,
                    evidence=rule.evidence,
                    suppress_identity=rule.intent in _SUPPRESS_INTENTS,
                )
            if rule.pattern.search(command):
                intent = rule.intent
                if intent == CommandIntent.OPERATE and _SENSITIVE_PATHS.search(command):
                    intent = CommandIntent.STAGE
                return IntentClassification(
                    binary=binary,
                    intent=intent,
                    confidence=rule.confidence,
                    evidence=rule.evidence,
                    suppress_identity=intent in _SUPPRESS_INTENTS,
                )

        return IntentClassification(
            binary=binary,
            intent=CommandIntent.UNKNOWN,
            confidence=0.0,
            evidence="no matching rule",
            suppress_identity=False,
        )


Intent = CommandIntent  # simple-name alias


def classify(first_token: str, command: str | None = None) -> CommandIntent:
    return IntentClassifier.classify(first_token, command or first_token).intent
