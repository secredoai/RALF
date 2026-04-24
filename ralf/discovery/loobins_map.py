"""LOOBins catalog loader for macOS native-binary offensive-capability data.

Source of truth: ``ralf/data/loobins_capabilities.json`` — a curated snapshot
of the public LOOBins catalog (loobins.io, MIT-licensed). This module provides
a typed loader, query helpers, and a coverage summary for CLI consumption.

Example::

    from ralf.discovery import list_binaries, get_binary

    for b in list_binaries():
        print(b.name, b.capability_tags)

    launchctl = get_binary("launchctl")
    if launchctl:
        print(launchctl.example_use)
        print(launchctl.mitre_techniques)
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Iterable

_DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "loobins_capabilities.json"


@dataclass(frozen=True)
class LoobinsBinary:
    """One entry in the LOOBins catalog."""

    name: str
    path: str
    short_description: str
    capability_tags: tuple[str, ...]
    mitre_techniques: tuple[str, ...]
    example_use: str
    intent: str

    @classmethod
    def from_dict(cls, d: dict) -> "LoobinsBinary":
        return cls(
            name=d["name"],
            path=d.get("path", ""),
            short_description=d.get("short_description", ""),
            capability_tags=tuple(d.get("capability_tags", [])),
            mitre_techniques=tuple(d.get("mitre_techniques", [])),
            example_use=d.get("example_use", ""),
            intent=d.get("intent", "unknown"),
        )

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "path": self.path,
            "short_description": self.short_description,
            "capability_tags": list(self.capability_tags),
            "mitre_techniques": list(self.mitre_techniques),
            "example_use": self.example_use,
            "intent": self.intent,
        }


@dataclass
class LoobinsCatalog:
    """Full LOOBins catalog."""

    version: int
    source: str
    last_updated: str
    binaries: tuple[LoobinsBinary, ...] = field(default_factory=tuple)

    def by_name(self) -> dict[str, LoobinsBinary]:
        """Index by binary name. If a name appears twice, last one wins."""
        return {b.name: b for b in self.binaries}

    def by_capability(self, tag: str) -> tuple[LoobinsBinary, ...]:
        return tuple(b for b in self.binaries if tag in b.capability_tags)

    def by_mitre(self, technique_id: str) -> tuple[LoobinsBinary, ...]:
        return tuple(b for b in self.binaries if technique_id in b.mitre_techniques)

    def capability_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for b in self.binaries:
            for tag in b.capability_tags:
                counts[tag] = counts.get(tag, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: -kv[1]))


@lru_cache(maxsize=1)
def load_catalog(data_path: Path | None = None) -> LoobinsCatalog:
    """Load the LOOBins catalog from JSON. Result is cached."""
    path = Path(data_path) if data_path else _DATA_FILE
    with path.open("r", encoding="utf-8") as f:
        raw = json.load(f)
    binaries = tuple(LoobinsBinary.from_dict(b) for b in raw.get("binaries", []))
    return LoobinsCatalog(
        version=raw.get("version", 1),
        source=raw.get("source", "loobins.io"),
        last_updated=raw.get("last_updated", ""),
        binaries=binaries,
    )


def list_binaries() -> tuple[LoobinsBinary, ...]:
    """Return all catalogued binaries."""
    return load_catalog().binaries


def get_binary(name: str) -> LoobinsBinary | None:
    """Look up a binary by name. Case-sensitive. Returns None if not found."""
    return load_catalog().by_name().get(name)


def binaries_with_capability(tag: str) -> tuple[LoobinsBinary, ...]:
    """Return binaries tagged with the given capability."""
    return load_catalog().by_capability(tag)


def binaries_with_mitre(technique_id: str) -> tuple[LoobinsBinary, ...]:
    """Return binaries mapped to the given MITRE technique ID."""
    return load_catalog().by_mitre(technique_id)


def coverage_summary() -> dict:
    """Return a summary suitable for CLI display."""
    catalog = load_catalog()
    return {
        "source": catalog.source,
        "last_updated": catalog.last_updated,
        "version": catalog.version,
        "total_binaries": len(catalog.binaries),
        "by_capability": catalog.capability_counts(),
        "unique_mitre_techniques": len(
            {t for b in catalog.binaries for t in b.mitre_techniques}
        ),
        "unique_intents": len({b.intent for b in catalog.binaries}),
    }


__all__ = [
    "LoobinsBinary",
    "LoobinsCatalog",
    "load_catalog",
    "list_binaries",
    "get_binary",
    "binaries_with_capability",
    "binaries_with_mitre",
    "coverage_summary",
]
