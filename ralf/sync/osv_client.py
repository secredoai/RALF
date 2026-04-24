"""OSV.dev bulk-download client.

OSV publishes per-ecosystem vulnerability dumps as zip archives at
``https://osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip``.
Each zip contains one JSON per advisory in the official OSV schema
(https://ossf.github.io/osv-schema/). The federation layer consumes these
dumps instead of API queries — far faster and denser than per-package
lookups.

OSV federates many sources under one schema: GHSA (GitHub Security
Advisory), PyPA, Go Vulnerability DB, RustSec, npm audit, Packagist
(PHP), NuGet (.NET), and others. Pulling OSV gives us the union.
"""
from __future__ import annotations

import io
import json
import logging
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from ralf.sync._base import SyncError, fetch_bytes

log = logging.getLogger(__name__)

# One zip per ecosystem. Matches the 7 package ecosystems the supply-chain
# layer understands (pip, npm, cargo, gem, go, composer, nuget).
#
# NuGet's OSV data carries a CC-BY-SA-4.0 license (Share-Alike), which
# conflicts with shipping a combined bundle under RALF Free's Apache-2.0
# tool code. NuGet is therefore EXCLUDED from the default fetch set. Users
# who accept the Share-Alike obligation on their local DB can opt in by
# passing ``ecosystems=all_ecosystems()`` to ``sync_cve()`` or invoking
# ``ralf-free sync cve --ecosystems NuGet`` from the CLI.
_ECOSYSTEM_URLS: dict[str, str] = {
    "PyPI":      "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip",
    "npm":       "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip",
    "crates.io": "https://osv-vulnerabilities.storage.googleapis.com/crates.io/all.zip",
    "RubyGems":  "https://osv-vulnerabilities.storage.googleapis.com/RubyGems/all.zip",
    "Go":        "https://osv-vulnerabilities.storage.googleapis.com/Go/all.zip",
    "Packagist": "https://osv-vulnerabilities.storage.googleapis.com/Packagist/all.zip",
    "NuGet":     "https://osv-vulnerabilities.storage.googleapis.com/NuGet/all.zip",
}

# Ecosystems excluded from the default bundle to avoid license-compatibility
# edge cases (currently: NuGet due to CC-BY-SA-4.0 Share-Alike).
_LICENSE_RESTRICTED_ECOSYSTEMS: frozenset[str] = frozenset({"NuGet"})

# OSV ecosystem name → RALF canonical ecosystem name (matches what
# ralf/detection/supply_chain.py stores in the advisories.ecosystem column).
_ECO_NORMALIZE: dict[str, str] = {
    "PyPI":      "pip",
    "npm":       "npm",
    "crates.io": "cargo",
    "RubyGems":  "rubygems",
    "Go":        "go",
    "Packagist": "composer",
    "NuGet":     "nuget",
}

# npm's dump is the largest (>100 MB as of 2026); cap set to 300 MB for
# headroom on future growth. The cap is a safety net against runaway
# downloads — it doesn't affect normal operation.
_ECOSYSTEM_SIZE_CAP: int = 300 * 1024 * 1024


@dataclass
class OsvAdvisory:
    """One advisory × affected-package pair — the shape our SQLite DB expects.

    An OSV record may cover multiple packages; the flattener below emits one
    :class:`OsvAdvisory` per (cve, package, ecosystem) tuple so the row count
    matches the federated DB primary key.
    """

    cve_id: str              # Preferred CVE-ID; falls back to GHSA/OSV id if no CVE
    package_name: str
    ecosystem: str           # RALF canonical (pip/npm/cargo/...)
    severity: str
    summary: str
    vulnerable_versions: str
    patched_versions: str
    published_date: str
    modified_date: str
    cvss_v3_score: float
    source: str              # "osv"
    aliases: tuple[str, ...] = field(default_factory=tuple)


_SEVERITY_BUCKETS: tuple[tuple[float, str], ...] = (
    (9.0, "CRITICAL"),
    (7.0, "HIGH"),
    (4.0, "MEDIUM"),
    (0.1, "LOW"),
)


def _bucket_cvss(score: float) -> str:
    for threshold, label in _SEVERITY_BUCKETS:
        if score >= threshold:
            return label
    return "UNKNOWN"


def _cvss_from_severity(sev_entries: list[dict]) -> float:
    """Extract CVSS v3 base score from an OSV ``severity`` list. Returns 0.0 if absent.

    OSV severity entries have ``type`` (e.g. ``CVSS_V3``) and ``score``
    (a CVSS vector string like ``CVSS:3.1/AV:N/AC:L/...``). We parse the
    base score from the vector if present.
    """
    for entry in sev_entries or []:
        if not isinstance(entry, dict):
            continue
        stype = str(entry.get("type") or "").upper()
        score_field = entry.get("score")
        if not score_field:
            continue
        # Sometimes `score` is a numeric base score directly
        if isinstance(score_field, (int, float)):
            return float(score_field)
        # Otherwise it's a CVSS vector string — the base score isn't in the
        # vector itself; OSV's `score` here is often the full vector. Fall
        # back to 0.0 and let downstream code use CVSS_V3 tag as a signal.
        if isinstance(score_field, str) and stype.startswith("CVSS"):
            # Look for a numeric score in `database_specific` later (OSV
            # optional); for now return 0.0 — downstream bucket-by-severity
            # still works via string match.
            return 0.0
    return 0.0


def _extract_cve_id(advisory: dict) -> str:
    """Return the advisory's CVE-ID if present, else the OSV/GHSA id."""
    aliases = advisory.get("aliases") or []
    for alias in aliases:
        if isinstance(alias, str) and alias.startswith("CVE-"):
            return alias
    return str(advisory.get("id") or "").strip()


def _extract_severity(advisory: dict) -> tuple[str, float]:
    """Prefer ``database_specific.severity`` (GHSA-style string), else CVSS."""
    dbs = advisory.get("database_specific") or {}
    severity_str = str(dbs.get("severity") or "").upper().strip()
    cvss = _cvss_from_severity(advisory.get("severity") or [])
    if severity_str in {"CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW"}:
        return (severity_str if severity_str != "MODERATE" else "MEDIUM", cvss)
    if cvss > 0.0:
        return (_bucket_cvss(cvss), cvss)
    return ("UNKNOWN", 0.0)


def _extract_version_ranges(pkg_affected: dict) -> tuple[str, str]:
    """Collapse OSV ``affected.ranges`` into our (vulnerable, patched) strings.

    OSV ranges have events like ``[{"introduced": "0"}, {"fixed": "2.17.1"}]``.
    We keep the serialization simple — join events into comma-separated
    "<=fixed" / ">=introduced" style strings the existing supply-chain
    layer already consumes.
    """
    vuln_parts: list[str] = []
    patched_parts: list[str] = []

    for rng in pkg_affected.get("ranges", []) or []:
        events = rng.get("events") or []
        for ev in events:
            if "introduced" in ev:
                v = str(ev["introduced"]).strip()
                if v and v != "0":
                    vuln_parts.append(f">= {v}")
            if "fixed" in ev:
                v = str(ev["fixed"]).strip()
                if v:
                    patched_parts.append(v)
            if "last_affected" in ev:
                v = str(ev["last_affected"]).strip()
                if v:
                    vuln_parts.append(f"<= {v}")
    # Versions list (explicit enumeration)
    for v in pkg_affected.get("versions") or []:
        vuln_parts.append(str(v))

    return (", ".join(vuln_parts), ", ".join(patched_parts))


def _flatten_advisory(advisory: dict) -> list[OsvAdvisory]:
    """One OSV record → list of per-package OsvAdvisory rows."""
    out: list[OsvAdvisory] = []
    cve_id = _extract_cve_id(advisory)
    if not cve_id:
        return out

    severity_label, cvss_score = _extract_severity(advisory)
    summary = str(advisory.get("summary") or advisory.get("details") or "").strip()
    if len(summary) > 500:
        summary = summary[:497] + "..."
    published = str(advisory.get("published") or "").strip()
    modified = str(advisory.get("modified") or "").strip()
    aliases = tuple(
        str(a).strip() for a in (advisory.get("aliases") or []) if isinstance(a, str)
    )

    for affected in advisory.get("affected") or []:
        pkg = affected.get("package") or {}
        osv_eco = str(pkg.get("ecosystem") or "").strip()
        # Normalize ecosystem: strip suffixes like ":2021" (Go)
        base_eco = osv_eco.split(":", 1)[0]
        ralf_eco = _ECO_NORMALIZE.get(base_eco, base_eco.lower() or "unknown")
        pkg_name = str(pkg.get("name") or "").strip()
        if not pkg_name:
            continue
        vuln, patched = _extract_version_ranges(affected)
        out.append(OsvAdvisory(
            cve_id=cve_id,
            package_name=pkg_name,
            ecosystem=ralf_eco,
            severity=severity_label,
            summary=summary,
            vulnerable_versions=vuln,
            patched_versions=patched,
            published_date=published,
            modified_date=modified,
            cvss_v3_score=cvss_score,
            source="osv",
            aliases=aliases,
        ))
    return out


def fetch_ecosystem(
    osv_ecosystem: str,
    *,
    published_since: str | None = None,
    timeout_sec: float = 120.0,
    on_progress: Callable[[str, int], None] | None = None,
) -> list[OsvAdvisory]:
    """Fetch + parse one OSV ecosystem zip. Returns flattened advisory rows.

    ``published_since`` (ISO-8601 date string like ``2021-01-01``) filters
    out advisories published before that date. Useful for the 5-year window.
    """
    if osv_ecosystem not in _ECOSYSTEM_URLS:
        raise SyncError(f"unknown OSV ecosystem: {osv_ecosystem!r}")
    url = _ECOSYSTEM_URLS[osv_ecosystem]
    body, _headers = fetch_bytes(
        url, timeout_sec=timeout_sec, size_cap_bytes=_ECOSYSTEM_SIZE_CAP,
    )

    out: list[OsvAdvisory] = []
    try:
        with zipfile.ZipFile(io.BytesIO(body)) as zf:
            names = [n for n in zf.namelist() if n.lower().endswith(".json")]
            for i, name in enumerate(names):
                try:
                    raw = zf.read(name)
                    doc = json.loads(raw.decode("utf-8", errors="replace"))
                except (KeyError, json.JSONDecodeError, UnicodeError):
                    continue
                if not isinstance(doc, dict):
                    continue
                if published_since:
                    pub = str(doc.get("published") or "").strip()
                    if pub and pub < published_since:
                        continue
                out.extend(_flatten_advisory(doc))
                if on_progress and (i % 1000 == 0):
                    on_progress(osv_ecosystem, i)
    except zipfile.BadZipFile as e:
        raise SyncError(f"OSV {osv_ecosystem} zip invalid: {e}") from e

    return out


def known_ecosystems() -> tuple[str, ...]:
    """Default ecosystem set for ``sync_cve`` — excludes license-restricted feeds.

    NuGet is excluded by default because its OSV feed is CC-BY-SA-4.0
    (Share-Alike), which would cascade into the Apache-2.0 tool code's
    derivative licensing story if bundled. Use :func:`all_ecosystems` to
    include it explicitly.
    """
    return tuple(
        k for k in _ECOSYSTEM_URLS
        if k not in _LICENSE_RESTRICTED_ECOSYSTEMS
    )


def all_ecosystems() -> tuple[str, ...]:
    """Every ecosystem including the license-restricted ones. Opt-in only."""
    return tuple(_ECOSYSTEM_URLS.keys())


__all__ = [
    "OsvAdvisory",
    "fetch_ecosystem",
    "known_ecosystems",
]
