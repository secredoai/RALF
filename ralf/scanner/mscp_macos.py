"""NIST macOS Security Compliance Project (mSCP) loader + query API.

Source of truth: ``ralf/data/mscp_rules.json`` — curated subset of the NIST
mSCP baseline rules (github.com/usnistgov/macos_security, public domain).
Each rule carries NIST SP 800-53 control references, DISA STIG IDs where
applicable, and CIS Apple macOS Benchmark cross-refs.

Runtime: this module is a *catalog browser* — it surfaces the rules and
their framework mappings. Actual "apply / check" automation (which would
run arbitrary shell commands on the host) is out of scope for the read-only
RALF posture layer.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

_DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "mscp_rules.json"


@dataclass(frozen=True)
class MscpRule:
    id: str
    title: str
    category: str
    severity: str
    nist_800_53: tuple[str, ...]
    disa_stig: tuple[str, ...]
    cis: tuple[str, ...]

    @classmethod
    def from_dict(cls, d: dict) -> "MscpRule":
        return cls(
            id=d["id"],
            title=d.get("title", ""),
            category=d.get("category", ""),
            severity=d.get("severity", ""),
            nist_800_53=tuple(d.get("nist_800_53", [])),
            disa_stig=tuple(d.get("disa_stig", [])),
            cis=tuple(d.get("cis", [])),
        )


@lru_cache(maxsize=1)
def _load() -> tuple[MscpRule, ...]:
    with _DATA_FILE.open("r", encoding="utf-8") as f:
        raw = json.load(f)
    return tuple(MscpRule.from_dict(r) for r in raw.get("rules", []))


def list_rules(category: str | None = None) -> tuple[MscpRule, ...]:
    rules = _load()
    if category is None:
        return rules
    return tuple(r for r in rules if r.category == category)


def get_rule(rule_id: str) -> MscpRule | None:
    for r in _load():
        if r.id == rule_id:
            return r
    return None


def categories() -> tuple[str, ...]:
    return tuple(sorted({r.category for r in _load()}))


def rules_by_nist(control_id: str) -> tuple[MscpRule, ...]:
    """All mSCP rules that reference the given NIST SP 800-53 control.

    Matches both bare and family notation (e.g. ``IA-2`` matches ``IA-2(1)``).
    """
    prefix = control_id.strip()
    return tuple(
        r for r in _load()
        if any(ctrl == prefix or ctrl.startswith(prefix + "(")
               for ctrl in r.nist_800_53)
    )


def rules_by_stig(stig_id: str) -> tuple[MscpRule, ...]:
    return tuple(r for r in _load() if stig_id in r.disa_stig)


def rules_by_cis(cis_id: str) -> tuple[MscpRule, ...]:
    return tuple(r for r in _load() if cis_id in r.cis)


def coverage_summary() -> dict:
    rules = _load()
    by_cat: dict[str, int] = {}
    by_sev: dict[str, int] = {}
    for r in rules:
        by_cat[r.category] = by_cat.get(r.category, 0) + 1
        by_sev[r.severity] = by_sev.get(r.severity, 0) + 1

    with_nist = sum(1 for r in rules if r.nist_800_53)
    with_stig = sum(1 for r in rules if r.disa_stig)
    with_cis  = sum(1 for r in rules if r.cis)

    unique_nist_controls = len({c for r in rules for c in r.nist_800_53})
    return {
        "total_rules": len(rules),
        "with_nist_refs": with_nist,
        "with_stig_refs": with_stig,
        "with_cis_refs":  with_cis,
        "unique_nist_controls": unique_nist_controls,
        "by_category": dict(sorted(by_cat.items(), key=lambda kv: -kv[1])),
        "by_severity": dict(sorted(by_sev.items(), key=lambda kv: -kv[1])),
    }


__all__ = [
    "MscpRule",
    "list_rules",
    "get_rule",
    "categories",
    "rules_by_nist",
    "rules_by_stig",
    "rules_by_cis",
    "coverage_summary",
]
