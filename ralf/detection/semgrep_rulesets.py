"""Semgrep ruleset selection — content language → registry ruleset list.

RALF Free runs Semgrep with a curated set of public community rulesets.
Always-on core rulesets target general security, OWASP Top 10, CWE Top 25,
and secret detection. Language-specific rulesets are added per-scan based on
file extension or content-shape sniffing.

No external dependency — this module just returns config flags; the Semgrep
binary itself is optional. See :mod:`ralf.detection.semgrep_adapter` for the
runner.
"""
from __future__ import annotations

import os
from pathlib import Path

# ── Always-on core (public, CC-licensed Semgrep Registry rulesets) ────────

ALWAYS_ON_RULESETS: tuple[str, ...] = (
    "p/ci",
    "p/security-audit",
    "p/owasp-top-ten",
    "p/cwe-top-25",
    "p/secrets",
    "p/gitleaks",
)

# ── Language-specific rulesets (keyed on normalized language id) ──────────

LANGUAGE_RULESETS: dict[str, tuple[str, ...]] = {
    "python": ("p/python", "p/flask", "p/django", "p/bandit"),
    "javascript": ("p/javascript", "p/nodejs", "p/react", "p/eslint-plugin-security"),
    "typescript": ("p/typescript", "p/javascript", "p/nodejs", "p/react"),
    "ruby": ("p/ruby", "p/rails", "p/brakeman"),
    "golang": ("p/golang", "p/gosec"),
    "php": ("p/php", "p/php-laravel", "p/phpcs-security-audit"),
    "java": ("p/java", "p/spring", "p/findsecbugs"),
    "kotlin": ("p/java", "p/kotlin"),
    "shell": ("p/bash", "p/shell"),
    "bash": ("p/bash", "p/shell"),
    "dockerfile": ("p/dockerfile",),
    "yaml_k8s": ("p/kubernetes", "p/dockerfile"),
    "terraform": ("p/terraform",),
}

# ── File-extension → language id ──────────────────────────────────────────

_EXT_TO_LANGUAGE: dict[str, str] = {
    ".py": "python",
    ".pyw": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".rb": "ruby",
    ".erb": "ruby",
    ".go": "golang",
    ".php": "php",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".sh": "shell",
    ".bash": "bash",
    ".zsh": "bash",
    ".tf": "terraform",
    ".tfvars": "terraform",
}

# Files whose NAME (not extension) identifies a language
_NAME_TO_LANGUAGE: dict[str, str] = {
    "Dockerfile": "dockerfile",
    "dockerfile": "dockerfile",
    "Containerfile": "dockerfile",
}


def language_for_path(file_path: str | os.PathLike | None) -> str | None:
    """Infer a language id from a file path. Returns None if unknown.

    Matches by filename first (for ``Dockerfile``-style names), then by
    lowercase suffix.
    """
    if not file_path:
        return None
    p = Path(file_path)
    if p.name in _NAME_TO_LANGUAGE:
        return _NAME_TO_LANGUAGE[p.name]
    suffix = p.suffix.lower()
    return _EXT_TO_LANGUAGE.get(suffix)


def language_for_yaml_content(content: str) -> str | None:
    """For ``.yml``/``.yaml`` — sniff whether this is a k8s/helm manifest."""
    if not content:
        return None
    markers = ("apiVersion:", "kind:", "metadata:", "spec:")
    hits = sum(1 for m in markers if m in content)
    if hits >= 2:
        return "yaml_k8s"
    return None


def rulesets_for_path(
    file_path: str | os.PathLike | None = None,
    *,
    content: str | None = None,
    include_always_on: bool = True,
) -> tuple[str, ...]:
    """Return the ruleset list to pass to Semgrep for a given file.

    Combines always-on core rulesets with language-specific ones.
    """
    rulesets: list[str] = list(ALWAYS_ON_RULESETS) if include_always_on else []
    lang = language_for_path(file_path)
    if lang is None and content and file_path:
        p = Path(file_path)
        if p.suffix.lower() in (".yml", ".yaml"):
            lang = language_for_yaml_content(content)
    if lang and lang in LANGUAGE_RULESETS:
        rulesets.extend(LANGUAGE_RULESETS[lang])
    # Deduplicate while preserving order
    seen: set[str] = set()
    out: list[str] = []
    for r in rulesets:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return tuple(out)


def all_known_rulesets() -> tuple[str, ...]:
    """Return every ruleset this module can select, for pre-caching by setup.sh."""
    seen: set[str] = set()
    out: list[str] = []
    for r in ALWAYS_ON_RULESETS:
        if r not in seen:
            seen.add(r)
            out.append(r)
    for langrules in LANGUAGE_RULESETS.values():
        for r in langrules:
            if r not in seen:
                seen.add(r)
                out.append(r)
    return tuple(out)


__all__ = [
    "ALWAYS_ON_RULESETS",
    "LANGUAGE_RULESETS",
    "language_for_path",
    "language_for_yaml_content",
    "rulesets_for_path",
    "all_known_rulesets",
]
