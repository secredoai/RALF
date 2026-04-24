"""CWE Top 25 registry — maps RALF native + Semgrep detectors to canonical CWE IDs.

Source of truth: ``ralf/data/cwe_top25.json``. Every finding produced by the
code scanner, supply-chain scanner, or injection scanner should cite a CWE ID
from this registry so the audit log is machine-queryable.

Usage::

    from ralf.detection.cwe_registry import (
        get_cwe, list_covered_cwes, cwes_for_language, owasp_for_cwe,
    )

    entry = get_cwe("CWE-78")
    if entry:
        print(entry.name, entry.owasp)

    for cwe in list_covered_cwes():
        print(cwe.id, cwe.applicable)
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

_DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "cwe_top25.json"


@dataclass(frozen=True)
class CWEEntry:
    """One CWE registry entry."""

    id: str
    name: str
    owasp: str
    applicable: tuple[str, ...]
    detectors: tuple[str, ...]
    note: str = ""
    rank_2024: int | None = None

    @classmethod
    def from_dict(cls, d: dict) -> "CWEEntry":
        return cls(
            id=d["id"],
            name=d.get("name", ""),
            owasp=d.get("owasp", ""),
            applicable=tuple(d.get("applicable", [])),
            detectors=tuple(d.get("detectors", [])),
            note=d.get("note", ""),
            rank_2024=d.get("rank_2024"),
        )

    @property
    def is_covered(self) -> bool:
        """True if at least one detector is registered for this CWE."""
        return bool(self.detectors) and bool(self.applicable)


@lru_cache(maxsize=1)
def _load_registry(data_path: Path | None = None) -> tuple[CWEEntry, ...]:
    path = Path(data_path) if data_path else _DATA_FILE
    with path.open("r", encoding="utf-8") as f:
        raw = json.load(f)
    return tuple(CWEEntry.from_dict(e) for e in raw.get("cwes", []))


def get_cwe(cwe_id: str) -> CWEEntry | None:
    """Look up a CWE by ID (e.g. 'CWE-78'). Case-sensitive."""
    for entry in _load_registry():
        if entry.id == cwe_id:
            return entry
    return None


def list_covered_cwes() -> tuple[CWEEntry, ...]:
    """Return CWEs with at least one detector registered."""
    return tuple(e for e in _load_registry() if e.is_covered)


def list_all_cwes() -> tuple[CWEEntry, ...]:
    """Return every CWE in the registry (covered or not)."""
    return _load_registry()


def cwes_for_language(language: str) -> tuple[CWEEntry, ...]:
    """Return covered CWEs applicable to the given language (python/js/ruby/node/shell/web/config)."""
    return tuple(e for e in list_covered_cwes() if language in e.applicable)


def owasp_for_cwe(cwe_id: str) -> str | None:
    """Return the OWASP Top 10 category ID ('A01'..'A10') for a CWE, if mapped."""
    entry = get_cwe(cwe_id)
    return entry.owasp if entry else None


def coverage_summary() -> dict:
    """Summary for CLI display."""
    registry = _load_registry()
    covered = [e for e in registry if e.is_covered]
    by_language: dict[str, int] = {}
    for e in covered:
        for lang in e.applicable:
            by_language[lang] = by_language.get(lang, 0) + 1
    by_owasp: dict[str, int] = {}
    for e in covered:
        if e.owasp:
            by_owasp[e.owasp] = by_owasp.get(e.owasp, 0) + 1
    return {
        "total_cwes_in_registry": len(registry),
        "covered": len(covered),
        "uncovered": len(registry) - len(covered),
        "by_language": dict(sorted(by_language.items(), key=lambda kv: -kv[1])),
        "by_owasp_category": dict(sorted(by_owasp.items())),
    }


__all__ = [
    "CWEEntry",
    "get_cwe",
    "list_covered_cwes",
    "list_all_cwes",
    "cwes_for_language",
    "owasp_for_cwe",
    "coverage_summary",
]
