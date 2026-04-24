"""MITRE ATT&CK Linux technique catalog loader.

Source of truth: ``ralf/data/mitre_attack_linux.json``. Provides typed loader,
tactic-filtered queries, and a coverage helper for CLI.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

_DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "mitre_attack_linux.json"


@dataclass(frozen=True)
class Technique:
    """One MITRE ATT&CK technique entry."""

    id: str
    name: str
    tactic: str
    description: str

    @classmethod
    def from_dict(cls, d: dict) -> "Technique":
        return cls(
            id=d["id"],
            name=d.get("name", ""),
            tactic=d.get("tactic", ""),
            description=d.get("description", ""),
        )


@dataclass
class Matrix:
    """Full technique matrix for a platform."""

    platform: str
    version: int
    source: str
    url: str
    last_updated: str
    techniques: tuple[Technique, ...]

    def by_id(self) -> dict[str, Technique]:
        return {t.id: t for t in self.techniques}

    def by_tactic(self) -> dict[str, tuple[Technique, ...]]:
        out: dict[str, list[Technique]] = {}
        for t in self.techniques:
            out.setdefault(t.tactic, []).append(t)
        return {k: tuple(v) for k, v in out.items()}

    def tactics(self) -> tuple[str, ...]:
        return tuple(sorted({t.tactic for t in self.techniques}))


@lru_cache(maxsize=1)
def load_matrix(data_path: Path | None = None) -> Matrix:
    """Load the Linux ATT&CK matrix. Cached."""
    path = Path(data_path) if data_path else _DATA_FILE
    with path.open("r", encoding="utf-8") as f:
        raw = json.load(f)
    techniques = tuple(Technique.from_dict(t) for t in raw.get("techniques", []))
    return Matrix(
        platform="linux",
        version=raw.get("version", 1),
        source=raw.get("source", ""),
        url=raw.get("url", ""),
        last_updated=raw.get("last_updated", ""),
        techniques=techniques,
    )


def list_techniques(tactic: str | None = None) -> tuple[Technique, ...]:
    """Return all techniques, optionally filtered by tactic."""
    matrix = load_matrix()
    if tactic is None:
        return matrix.techniques
    return tuple(t for t in matrix.techniques if t.tactic == tactic)


def get_technique(technique_id: str) -> Technique | None:
    """Look up a technique by ID. Returns None if absent."""
    return load_matrix().by_id().get(technique_id)


def tactics() -> tuple[str, ...]:
    """Return the set of tactics present in the matrix."""
    return load_matrix().tactics()


def coverage_summary() -> dict:
    matrix = load_matrix()
    return {
        "platform": matrix.platform,
        "source": matrix.source,
        "url": matrix.url,
        "last_updated": matrix.last_updated,
        "total_techniques": len(matrix.techniques),
        "tactics": list(matrix.tactics()),
        "techniques_per_tactic": {
            tac: len(techs) for tac, techs in matrix.by_tactic().items()
        },
    }


__all__ = [
    "Technique",
    "Matrix",
    "load_matrix",
    "list_techniques",
    "get_technique",
    "tactics",
    "coverage_summary",
]
