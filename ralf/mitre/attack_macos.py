"""MITRE ATT&CK macOS technique catalog loader.

Mirrors :mod:`ralf.mitre.attack_linux` — same dataclasses, different data file.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from ralf.mitre.attack_linux import Matrix, Technique

_DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "mitre_attack_macos.json"


@lru_cache(maxsize=1)
def load_matrix(data_path: Path | None = None) -> Matrix:
    """Load the macOS ATT&CK matrix. Cached."""
    path = Path(data_path) if data_path else _DATA_FILE
    with path.open("r", encoding="utf-8") as f:
        raw = json.load(f)
    techniques = tuple(Technique.from_dict(t) for t in raw.get("techniques", []))
    return Matrix(
        platform="macos",
        version=raw.get("version", 1),
        source=raw.get("source", ""),
        url=raw.get("url", ""),
        last_updated=raw.get("last_updated", ""),
        techniques=techniques,
    )


def list_techniques(tactic: str | None = None) -> tuple[Technique, ...]:
    matrix = load_matrix()
    if tactic is None:
        return matrix.techniques
    return tuple(t for t in matrix.techniques if t.tactic == tactic)


def get_technique(technique_id: str) -> Technique | None:
    return load_matrix().by_id().get(technique_id)


def tactics() -> tuple[str, ...]:
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
    "load_matrix",
    "list_techniques",
    "get_technique",
    "tactics",
    "coverage_summary",
]
