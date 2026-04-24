"""OWASP ASVS v5 mapping — CWE-ID → ASVS requirement ID.

Source of truth: ``ralf/data/owasp_asvs_v5.json`` — curated subset of the
OWASP Application Security Verification Standard v5 bundling the ~70
requirements that RALF's code-scanner + supply-chain + Semgrep layers
can verify automatically. Use ``requirements_for_cwe(cwe_id)`` to enrich
a FileScanHit with ASVS requirement tags.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

_DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "owasp_asvs_v5.json"


@dataclass(frozen=True)
class AsvsRequirement:
    id: str
    chapter: str
    text: str
    level: int
    related_cwes: tuple[str, ...]
    detectors: tuple[str, ...]

    @classmethod
    def from_dict(cls, d: dict) -> "AsvsRequirement":
        return cls(
            id=d["id"],
            chapter=d.get("chapter", ""),
            text=d.get("text", ""),
            level=int(d.get("level", 1)),
            related_cwes=tuple(d.get("related_cwes", [])),
            detectors=tuple(d.get("detectors", [])),
        )


@lru_cache(maxsize=1)
def _load() -> tuple[AsvsRequirement, ...]:
    with _DATA_FILE.open("r", encoding="utf-8") as f:
        raw = json.load(f)
    return tuple(
        AsvsRequirement.from_dict(r) for r in raw.get("requirements", [])
    )


def list_requirements() -> tuple[AsvsRequirement, ...]:
    return _load()


def get_requirement(req_id: str) -> AsvsRequirement | None:
    for r in _load():
        if r.id == req_id:
            return r
    return None


def requirements_for_cwe(cwe_id: str) -> tuple[AsvsRequirement, ...]:
    """Return every ASVS requirement that lists ``cwe_id`` among its related CWEs."""
    return tuple(r for r in _load() if cwe_id in r.related_cwes)


def requirements_for_chapter(chapter_prefix: str) -> tuple[AsvsRequirement, ...]:
    """All requirements whose chapter begins with ``chapter_prefix`` (e.g. ``"V5"``)."""
    return tuple(
        r for r in _load()
        if r.id.startswith(chapter_prefix) or r.chapter.startswith(chapter_prefix)
    )


def coverage_summary() -> dict:
    reqs = _load()
    with_detectors = [r for r in reqs if r.detectors]
    chapters: dict[str, int] = {}
    for r in reqs:
        # First token of chapter (before the " - " separator) is the chapter key
        root = r.chapter.split(" - ", 1)[0] if r.chapter else "Uncategorized"
        chapters[root] = chapters.get(root, 0) + 1
    return {
        "total_requirements": len(reqs),
        "with_detectors": len(with_detectors),
        "level_1_count": sum(1 for r in reqs if r.level == 1),
        "level_2_count": sum(1 for r in reqs if r.level == 2),
        "by_chapter": dict(sorted(chapters.items(), key=lambda kv: -kv[1])),
    }


__all__ = [
    "AsvsRequirement",
    "list_requirements",
    "get_requirement",
    "requirements_for_cwe",
    "requirements_for_chapter",
    "coverage_summary",
]
