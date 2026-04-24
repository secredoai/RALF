"""OWASP Top 10 (2021) mapping — CWE-ID to OWASP category with Cheat Sheet refs.

Source of truth: ``ralf/data/owasp_top10_2021.json``. Exposes a lookup API for
enriching findings with their OWASP category, related CWEs, RALF detector
coverage, and Cheat Sheet URLs for the ``remediation`` field.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

_DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "owasp_top10_2021.json"


@dataclass(frozen=True)
class OwaspCategory:
    id: str
    name: str
    description: str
    related_cwes: tuple[str, ...]
    ralf_coverage: tuple[str, ...]
    cheat_sheet_urls: tuple[str, ...]

    @classmethod
    def from_dict(cls, d: dict) -> "OwaspCategory":
        return cls(
            id=d["id"],
            name=d.get("name", ""),
            description=d.get("description", ""),
            related_cwes=tuple(d.get("related_cwes", [])),
            ralf_coverage=tuple(d.get("ralf_coverage", [])),
            cheat_sheet_urls=tuple(d.get("cheat_sheet_urls", [])),
        )


@lru_cache(maxsize=1)
def _load() -> tuple[OwaspCategory, ...]:
    with _DATA_FILE.open("r", encoding="utf-8") as f:
        raw = json.load(f)
    return tuple(OwaspCategory.from_dict(c) for c in raw.get("categories", []))


def get_category(category_id: str) -> OwaspCategory | None:
    """Look up by ID like 'A01' or 'A10'."""
    for c in _load():
        if c.id == category_id:
            return c
    return None


def list_categories() -> tuple[OwaspCategory, ...]:
    return _load()


def category_for_cwe(cwe_id: str) -> OwaspCategory | None:
    """First OWASP category that lists this CWE as related."""
    for c in _load():
        if cwe_id in c.related_cwes:
            return c
    return None


def cheat_sheet_urls_for_cwe(cwe_id: str) -> tuple[str, ...]:
    """Cheat Sheet URLs associated with the OWASP category of a CWE."""
    cat = category_for_cwe(cwe_id)
    return cat.cheat_sheet_urls if cat else ()


def coverage_summary() -> dict:
    cats = _load()
    return {
        "total_categories": len(cats),
        "covered": sum(1 for c in cats if c.ralf_coverage),
        "category_detector_counts": {c.id: len(c.ralf_coverage) for c in cats},
    }


__all__ = [
    "OwaspCategory",
    "get_category",
    "list_categories",
    "category_for_cwe",
    "cheat_sheet_urls_for_cwe",
    "coverage_summary",
]
