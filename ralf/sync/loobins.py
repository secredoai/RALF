"""LOOBins fetcher — macOS offensive-binary catalog from the community repo.

Pulls the LOOBins GitHub archive (``infosecB/LOOBins``), parses every YAML
entry, and emits the JSON schema that :mod:`ralf.discovery.loobins_map` loads.

Each LOOBin upstream has fields: name, short_description, path, author, created,
example_use_cases (with code + mitre_tactics + mitre_techniques), detections,
resources, acknowledgements. We map those onto our simpler schema (one entry
per binary, capability tags + MITRE list + single intent tag).
"""
from __future__ import annotations

import io
import logging
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# Regex to pull MITRE T-IDs out of LOOBins "resources" URLs. Upstream LOOBins
# links to attack.mitre.org/techniques/T####/### rather than carrying the ID
# as a structured field.
_TID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

from ralf.sync._base import (
    SyncError,
    SyncResult,
    fetch_bytes,
    timer,
    write_json_atomic,
)

log = logging.getLogger(__name__)

_LOOBINS_URL = "https://codeload.github.com/infosecB/LOOBins/zip/refs/heads/main"
_LOOBINS_SIZE_CAP = 50 * 1024 * 1024  # 50 MB (repo is ~1-2 MB today)

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_OUTPUT_PATH = _DATA_DIR / "loobins_capabilities.json"

# MITRE tactic → our capability tag
_TACTIC_TO_CAPABILITY: dict[str, str] = {
    "execution": "execution",
    "persistence": "persistence",
    "privilege-escalation": "privilege_escalation",
    "defense-evasion": "defense_evasion",
    "credential-access": "credential_access",
    "discovery": "discovery",
    "lateral-movement": "lateral_movement",
    "collection": "collection",
    "command-and-control": "command_and_control",
    "exfiltration": "exfiltration",
    "impact": "impact",
    "resource-development": "resource_hijack",
    "initial-access": "execution",
    "reconnaissance": "discovery",
}

# Our intent vocabulary — picked from the dominant tactic
_TACTIC_TO_INTENT: dict[str, str] = {
    "execution": "spawn_shell",
    "persistence": "persist",
    "privilege-escalation": "escalate",
    "defense-evasion": "modify",
    "credential-access": "credential_access",
    "discovery": "recon",
    "lateral-movement": "exfiltrate",
    "collection": "read",
    "command-and-control": "exfiltrate",
    "exfiltration": "exfiltrate",
    "impact": "disrupt",
    "reconnaissance": "recon",
}

_CAPABILITY_TAGS_GLOSSARY = {
    "execution": "Arbitrary code execution",
    "persistence": "Install / register long-lived footholds",
    "privilege_escalation": "Gain higher integrity",
    "defense_evasion": "Bypass or disable security controls",
    "credential_access": "Read / dump / exfiltrate secrets",
    "discovery": "Enumerate system state",
    "lateral_movement": "Move between hosts / sessions",
    "collection": "Gather target data",
    "exfiltration": "Send data outbound",
    "command_and_control": "Remote control channels",
    "impact": "Destroy / modify / deny access",
    "resource_hijack": "Appropriate system resources",
}


@dataclass
class _ParsedLoobin:
    name: str
    path: str = ""
    short_description: str = ""
    capability_tags: set[str] = field(default_factory=set)
    mitre_techniques: set[str] = field(default_factory=set)
    example_use: str = ""
    primary_tactic: str = ""


def _load_yaml_safe(raw: bytes) -> dict | None:
    """Load a YAML document; return None on malformed/empty."""
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError:
        return None
    if not isinstance(data, dict):
        return None
    return data


def _is_loobin_schema(doc: dict) -> bool:
    """Return True if the YAML doc looks like a LOOBins entry.

    Real LOOBins entries have ``short_description``, ``example_use_cases``, or
    ``full_path``. GitHub Actions workflow YAMLs have ``on`` and ``jobs`` keys
    — reject those. Docs missing BOTH sets are ambiguous; we reject to stay
    conservative.
    """
    # Positive markers — any one of these is sufficient
    positive = {"short_description", "example_use_cases", "full_path",
                "detections", "resources", "author"}
    if any(k in doc for k in positive):
        # Negative markers — if either is present, it's a workflow
        if "jobs" in doc and ("on" in doc or "runs-on" in doc):
            return False
        return True
    return False


def _parse_one_yaml(raw: bytes) -> _ParsedLoobin | None:
    """Parse one LOOBin YAML into the RALF shape. Tolerant of schema drift."""
    doc = _load_yaml_safe(raw)
    if doc is None:
        return None

    if not _is_loobin_schema(doc):
        return None

    name = str(doc.get("name") or "").strip()
    if not name:
        return None

    # LOOBins uses `paths:` (plural list). Fall back to `full_path` / `path`
    # if upstream schema changes.
    paths_val = doc.get("paths") or doc.get("full_path") or doc.get("path") or ""
    if isinstance(paths_val, list):
        path_str = str(paths_val[0]).strip() if paths_val else ""
    else:
        path_str = str(paths_val).strip()

    entry = _ParsedLoobin(
        name=name,
        path=path_str,
        short_description=str(doc.get("short_description") or doc.get("description") or "").strip(),
    )

    # MITRE technique IDs live in the "resources" section URLs, not as a
    # structured field. Extract every T-ID we can find.
    for res in doc.get("resources") or []:
        if not isinstance(res, dict):
            continue
        for value in (res.get("url"), res.get("name")):
            if not value:
                continue
            for match in _TID_RE.findall(str(value)):
                entry.mitre_techniques.add(match)

    use_cases = doc.get("example_use_cases") or []
    first_tactic_seen: str | None = None
    first_example: str | None = None

    if isinstance(use_cases, list):
        for uc in use_cases:
            if not isinstance(uc, dict):
                continue
            # Tactics + techniques
            tactics = uc.get("tactics") or uc.get("mitre_tactics") or []
            techniques = uc.get("tactics") and [] or uc.get("mitre_techniques") or []
            if isinstance(tactics, list):
                for t in tactics:
                    t_norm = str(t or "").strip().lower()
                    if not t_norm:
                        continue
                    cap = _TACTIC_TO_CAPABILITY.get(t_norm)
                    if cap:
                        entry.capability_tags.add(cap)
                    if first_tactic_seen is None:
                        first_tactic_seen = t_norm
            if isinstance(techniques, list):
                for tid in techniques:
                    tid_s = str(tid or "").strip()
                    if tid_s.startswith("T"):
                        entry.mitre_techniques.add(tid_s)
            # Example phrase
            if first_example is None:
                desc = uc.get("description") or uc.get("name")
                if desc:
                    first_example = str(desc).strip()

    if first_tactic_seen:
        entry.primary_tactic = first_tactic_seen
    if first_example:
        entry.example_use = first_example[:200]

    return entry


def _to_output_dict(entry: _ParsedLoobin) -> dict:
    # Cap capabilities at a reasonable number for display
    caps = sorted(entry.capability_tags)
    intent = _TACTIC_TO_INTENT.get(entry.primary_tactic, "unknown")
    return {
        "name": entry.name,
        "path": entry.path,
        "short_description": entry.short_description,
        "capability_tags": caps,
        "mitre_techniques": sorted(entry.mitre_techniques),
        "example_use": entry.example_use,
        "intent": intent,
    }


def _parse_loobins_archive(archive_bytes: bytes) -> list[dict]:
    """Unpack zip, parse every .yml / .yaml entry under LOOBins subtree."""
    out: list[_ParsedLoobin] = []
    seen: set[str] = set()

    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as zf:
        for info in zf.infolist():
            name = info.filename
            if info.is_dir():
                continue
            lower = name.lower()
            if not (lower.endswith(".yml") or lower.endswith(".yaml")):
                continue
            parts = name.split("/")
            # Must live under the top-level LOOBins/ content directory, NOT
            # .github/workflows/ or similar. Require exactly
            # <repo-root>/LOOBins/<name>.yml — path depth matters.
            if "LOOBins" not in parts:
                continue
            try:
                loobins_idx = parts.index("LOOBins")
            except ValueError:
                continue
            # Skip the repo-root "LOOBins-main" wrapper entry and require the
            # file to be an immediate child of the LOOBins/ content directory
            if loobins_idx == 0 or loobins_idx + 1 != len(parts) - 1:
                continue
            # Exclude anything still sitting under .github/ (defensive —
            # shouldn't happen with the path-component check above)
            if ".github" in parts:
                continue

            try:
                raw = zf.read(info)
            except (KeyError, RuntimeError):
                continue
            parsed = _parse_one_yaml(raw)
            if parsed is None or parsed.name in seen:
                continue
            seen.add(parsed.name)
            out.append(parsed)

    out.sort(key=lambda e: e.name.lower())
    return [_to_output_dict(e) for e in out]


def sync_loobins(*, output_path: Path | None = None, timeout_sec: float = 60.0) -> SyncResult:
    """Fetch LOOBins GitHub archive, parse, write JSON."""
    url = _LOOBINS_URL
    outpath = output_path or _OUTPUT_PATH

    with timer() as t:
        try:
            body, _headers = fetch_bytes(
                url, timeout_sec=timeout_sec, size_cap_bytes=_LOOBINS_SIZE_CAP,
            )
            bytes_fetched = len(body)
            try:
                binaries = _parse_loobins_archive(body)
            except zipfile.BadZipFile as e:
                raise SyncError(f"LOOBins archive not a valid zip: {e}") from e

            if len(binaries) < 50:
                raise SyncError(
                    f"LOOBins parse produced only {len(binaries)} binaries — schema drift?"
                )

            import datetime as _dt
            payload = {
                "version": 2,
                "source": "loobins.io",
                "license_note": (
                    "LOOBins catalog is MIT-licensed public security knowledge, "
                    "sourced from github.com/infosecB/LOOBins and refreshed via "
                    "ralf-free sync loobins."
                ),
                "upstream_url": url,
                "last_updated": _dt.date.today().isoformat(),
                "description": (
                    "Complete macOS offensive-binary catalog synced from the "
                    "LOOBins community repository. Each entry carries "
                    "capability tags derived from MITRE ATT&CK tactics plus the "
                    "MITRE technique IDs the community has mapped to the binary."
                ),
                "capability_tags_glossary": _CAPABILITY_TAGS_GLOSSARY,
                "binaries": binaries,
            }
            write_json_atomic(outpath, payload)
        except SyncError as e:
            return SyncResult(
                source="loobins", url=url, success=False, record_count=0,
                output_path=None, bytes_fetched=0, elapsed_sec=t.elapsed,
                error=str(e),
            )

    return SyncResult(
        source="loobins", url=url, success=True, record_count=len(binaries),
        output_path=outpath, bytes_fetched=bytes_fetched, elapsed_sec=t.elapsed,
    )


__all__ = ["sync_loobins"]
