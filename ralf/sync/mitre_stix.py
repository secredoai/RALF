"""MITRE ATT&CK STIX fetcher.

Pulls the full MITRE ATT&CK Enterprise matrix in STIX 2.0 format from the
official ``mitre/cti`` GitHub repository and filters to a single platform
(``linux`` or ``macOS``). Emits the JSON schema that
:mod:`ralf.mitre.attack_linux` / :mod:`ralf.mitre.attack_macos` expect.

Source: https://github.com/mitre/cti — the canonical MITRE STIX export.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from ralf.sync._base import (
    SyncError,
    SyncResult,
    fetch_bytes,
    timer,
    write_json_atomic,
)

log = logging.getLogger(__name__)

_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

_STIX_SIZE_CAP = 100 * 1024 * 1024  # 100 MB — the STIX bundle is ~30 MB today

# Platform string as it appears in STIX x_mitre_platforms
_PLATFORM_LABELS = {
    "linux": "Linux",
    "macos": "macOS",
}

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_OUTPUT_FILES = {
    "linux": _DATA_DIR / "mitre_attack_linux.json",
    "macos": _DATA_DIR / "mitre_attack_macos.json",
}


def _extract_tid(obj: dict) -> str | None:
    """Extract the MITRE technique ID (e.g. ``T1059.004``) from STIX external refs."""
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack":
            tid = ref.get("external_id")
            if tid and tid.startswith("T"):
                return tid
    return None


def _extract_tactic(obj: dict) -> str:
    """First kill-chain phase name (STIX tactic) — normalized to underscore-case.

    MITRE STIX uses hyphen-case (e.g. ``defense-evasion``) for phase names.
    Our JSON schema and downstream consumers (CLI filters, audit-log
    fields) use underscore-case (``defense_evasion``). Normalize at
    the ingest boundary so the rest of the system sees one form.
    """
    raw = ""
    for kcp in obj.get("kill_chain_phases", []) or []:
        if kcp.get("kill_chain_name") == "mitre-attack":
            raw = str(kcp.get("phase_name") or "")
            break
    if not raw:
        phases = obj.get("kill_chain_phases") or []
        if phases:
            raw = str(phases[0].get("phase_name") or "")
    return raw.replace("-", "_")


def _truncate_description(desc: str, limit: int = 500) -> str:
    """STIX descriptions are long and include Markdown. Keep the first paragraph
    up to ``limit`` chars, strip citations like ``(Citation: Foo)``."""
    import re
    # Drop (Citation: ...) fragments MITRE inlines
    clean = re.sub(r"\(Citation:[^)]*\)", "", desc or "").strip()
    # First paragraph
    first = clean.split("\n\n", 1)[0]
    if len(first) > limit:
        first = first[:limit].rstrip() + "…"
    return first


def _parse_stix_for_platform(stix_bundle: dict, platform_key: str) -> list[dict]:
    """Filter STIX bundle to attack-patterns on a single platform, emit RALF schema.

    Excludes revoked and deprecated objects (MITRE's way of sunsetting techniques).
    """
    platform_label = _PLATFORM_LABELS[platform_key]
    results: list[dict] = []

    for obj in stix_bundle.get("objects", []) or []:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") is True:
            continue
        if obj.get("x_mitre_deprecated") is True:
            continue

        platforms = obj.get("x_mitre_platforms") or []
        if platform_label not in platforms:
            continue

        tid = _extract_tid(obj)
        if not tid:
            continue

        tactic = _extract_tactic(obj)
        name = str(obj.get("name") or "").strip()
        desc = _truncate_description(str(obj.get("description") or ""))

        if not name or not tactic:
            continue

        results.append({
            "id": tid,
            "name": name,
            "tactic": tactic,
            "description": desc,
        })

    # Deterministic order for stable diffs
    results.sort(key=lambda r: (r["tactic"], r["id"]))
    return results


def _sync_platform(
    platform_key: str,
    *,
    output_path: Path | None = None,
    timeout_sec: float = 60.0,
) -> SyncResult:
    url = _STIX_URL
    label = f"mitre-{platform_key}"
    outpath = output_path or _OUTPUT_FILES[platform_key]

    with timer() as t:
        try:
            body, _headers = fetch_bytes(
                url, timeout_sec=timeout_sec, size_cap_bytes=_STIX_SIZE_CAP,
            )
            bytes_fetched = len(body)
            try:
                bundle = json.loads(body.decode("utf-8", errors="replace"))
            except json.JSONDecodeError as e:
                raise SyncError(f"STIX bundle not valid JSON: {e}") from e
            if not isinstance(bundle, dict) or "objects" not in bundle:
                raise SyncError("STIX bundle missing 'objects' array")

            techniques = _parse_stix_for_platform(bundle, platform_key)
            if not techniques:
                raise SyncError(
                    f"STIX parse produced 0 {platform_key} techniques — filter problem?"
                )

            payload = {
                "version": 2,
                "source": f"MITRE ATT&CK Enterprise Matrix — {_PLATFORM_LABELS[platform_key]} platform",
                "url": f"https://attack.mitre.org/matrices/enterprise/{platform_key}/",
                "upstream_bundle_url": url,
                "last_updated": _today_iso(),
                "description": (
                    f"Complete {_PLATFORM_LABELS[platform_key]} technique set extracted "
                    "from the official MITRE ATT&CK STIX feed (enterprise-attack.json). "
                    "Excludes revoked and deprecated techniques."
                ),
                "techniques": techniques,
            }
            write_json_atomic(outpath, payload)
        except SyncError as e:
            return SyncResult(
                source=label, url=url, success=False, record_count=0,
                output_path=None, bytes_fetched=0, elapsed_sec=t.elapsed,
                error=str(e),
            )

    return SyncResult(
        source=label, url=url, success=True, record_count=len(techniques),
        output_path=outpath, bytes_fetched=bytes_fetched, elapsed_sec=t.elapsed,
    )


def _today_iso() -> str:
    import datetime as _dt
    return _dt.date.today().isoformat()


def sync_mitre_linux(*, output_path: Path | None = None, timeout_sec: float = 60.0) -> SyncResult:
    """Fetch + parse MITRE ATT&CK, filter to Linux, write JSON."""
    return _sync_platform("linux", output_path=output_path, timeout_sec=timeout_sec)


def sync_mitre_macos(*, output_path: Path | None = None, timeout_sec: float = 60.0) -> SyncResult:
    """Fetch + parse MITRE ATT&CK, filter to macOS, write JSON."""
    return _sync_platform("macos", output_path=output_path, timeout_sec=timeout_sec)


__all__ = ["sync_mitre_linux", "sync_mitre_macos"]
