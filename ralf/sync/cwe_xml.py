"""MITRE CWE XML dictionary fetcher.

Pulls the canonical CWE research-view XML (``cwec_latest.xml.zip``) from
cwe.mitre.org, filters to weaknesses applicable to RALF's target languages
(Python / JavaScript / Ruby / PHP / Go / shell / framework-agnostic), and
emits the JSON schema that :mod:`ralf.detection.cwe_registry` loads.

Source: https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
"""
from __future__ import annotations

import io
import logging
import zipfile
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

from ralf.sync._base import (
    SyncError,
    SyncResult,
    fetch_bytes,
    timer,
    write_json_atomic,
)

log = logging.getLogger(__name__)

_CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
_CWE_SIZE_CAP = 25 * 1024 * 1024  # 25 MB (latest ~6 MB compressed, ~20 MB uncompressed)

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_OUTPUT_PATH = _DATA_DIR / "cwe_top25.json"

# Languages in CWE's Applicable_Platforms that map to RALF's "applicable" tags.
# CWE uses "Name" for specific languages and "Class" for umbrella groupings
# (e.g. "Not Language-Specific", "Interpreted").
_LANGUAGE_MAP: dict[str, str] = {
    # Exact names
    "Python": "python",
    "JavaScript": "js",
    "TypeScript": "js",
    "Ruby": "ruby",
    "PHP": "web",
    "Java": "web",
    "Go": "web",
    "Shell": "shell",
    "Unix Shell": "shell",
    "Bash": "shell",
}
_LANGUAGE_CLASSES: set[str] = {
    "Interpreted",
    "Not Language-Specific",
}

# Map CWE IDs to OWASP Top 10 2021 category. Based on OWASP's official CWE
# mapping table (https://owasp.org/Top10/A00_2021-Introduction/). Only the
# subset where the primary-category mapping is unambiguous is listed here.
_CWE_TO_OWASP: dict[str, str] = {
    # A01 — Broken Access Control
    "CWE-22": "A01", "CWE-23": "A01", "CWE-35": "A01", "CWE-59": "A01",
    "CWE-201": "A01", "CWE-219": "A01", "CWE-264": "A01", "CWE-275": "A01",
    "CWE-276": "A01", "CWE-284": "A01", "CWE-285": "A01", "CWE-352": "A01",
    "CWE-359": "A01", "CWE-377": "A01", "CWE-402": "A01", "CWE-425": "A01",
    "CWE-441": "A01", "CWE-497": "A01", "CWE-538": "A01", "CWE-540": "A01",
    "CWE-548": "A01", "CWE-552": "A01", "CWE-566": "A01", "CWE-601": "A01",
    "CWE-639": "A01", "CWE-651": "A01", "CWE-668": "A01", "CWE-706": "A01",
    "CWE-862": "A01", "CWE-863": "A01", "CWE-913": "A01", "CWE-922": "A01",
    "CWE-1275": "A01",
    # A02 — Cryptographic Failures
    "CWE-261": "A02", "CWE-296": "A02", "CWE-310": "A02", "CWE-319": "A02",
    "CWE-321": "A02", "CWE-322": "A02", "CWE-323": "A02", "CWE-324": "A02",
    "CWE-325": "A02", "CWE-326": "A02", "CWE-327": "A02", "CWE-328": "A02",
    "CWE-329": "A02", "CWE-330": "A02", "CWE-331": "A02", "CWE-335": "A02",
    "CWE-336": "A02", "CWE-337": "A02", "CWE-338": "A02", "CWE-340": "A02",
    "CWE-347": "A02", "CWE-523": "A02", "CWE-720": "A02", "CWE-757": "A02",
    "CWE-759": "A02", "CWE-760": "A02", "CWE-780": "A02", "CWE-798": "A02",
    "CWE-818": "A02", "CWE-916": "A02", "CWE-295": "A02", "CWE-311": "A02",
    "CWE-312": "A02", "CWE-522": "A02",
    # A03 — Injection
    "CWE-20": "A03", "CWE-74": "A03", "CWE-75": "A03", "CWE-77": "A03",
    "CWE-78": "A03", "CWE-79": "A03", "CWE-80": "A03", "CWE-83": "A03",
    "CWE-87": "A03", "CWE-88": "A03", "CWE-89": "A03", "CWE-90": "A03",
    "CWE-91": "A03", "CWE-93": "A03", "CWE-94": "A03", "CWE-95": "A03",
    "CWE-96": "A03", "CWE-97": "A03", "CWE-98": "A03", "CWE-99": "A03",
    "CWE-113": "A03", "CWE-116": "A03", "CWE-138": "A03", "CWE-184": "A03",
    "CWE-470": "A03", "CWE-471": "A03", "CWE-564": "A03", "CWE-610": "A03",
    "CWE-643": "A03", "CWE-644": "A03", "CWE-652": "A03", "CWE-917": "A03",
    # A04 — Insecure Design
    "CWE-73": "A04", "CWE-183": "A04", "CWE-209": "A04", "CWE-213": "A04",
    "CWE-235": "A04", "CWE-256": "A04", "CWE-257": "A04", "CWE-266": "A04",
    "CWE-269": "A04", "CWE-280": "A04", "CWE-316": "A04", "CWE-419": "A04",
    "CWE-430": "A04", "CWE-434": "A04", "CWE-444": "A04", "CWE-451": "A04",
    "CWE-472": "A04", "CWE-501": "A04", "CWE-525": "A04", "CWE-539": "A04",
    "CWE-579": "A04", "CWE-598": "A04", "CWE-602": "A04", "CWE-642": "A04",
    "CWE-646": "A04", "CWE-650": "A04", "CWE-653": "A04", "CWE-656": "A04",
    "CWE-657": "A04", "CWE-799": "A04", "CWE-807": "A04", "CWE-840": "A04",
    "CWE-841": "A04", "CWE-927": "A04", "CWE-1021": "A04", "CWE-1173": "A04",
    "CWE-400": "A04", "CWE-1333": "A04",
    # A05 — Security Misconfiguration
    "CWE-2": "A05", "CWE-11": "A05", "CWE-13": "A05", "CWE-15": "A05",
    "CWE-16": "A05", "CWE-260": "A05", "CWE-315": "A05", "CWE-520": "A05",
    "CWE-526": "A05", "CWE-537": "A05", "CWE-541": "A05", "CWE-547": "A05",
    "CWE-611": "A05", "CWE-614": "A05", "CWE-756": "A05", "CWE-776": "A05",
    "CWE-942": "A05", "CWE-1004": "A05", "CWE-1032": "A05", "CWE-1174": "A05",
    "CWE-732": "A05",
    # A06 — Vulnerable Components
    "CWE-1104": "A06", "CWE-937": "A06", "CWE-1035": "A06", "CWE-1026": "A06",
    # A07 — Auth Failures
    "CWE-255": "A07", "CWE-259": "A07", "CWE-287": "A07", "CWE-288": "A07",
    "CWE-290": "A07", "CWE-294": "A07", "CWE-297": "A07", "CWE-300": "A07",
    "CWE-302": "A07", "CWE-304": "A07", "CWE-306": "A07", "CWE-307": "A07",
    "CWE-346": "A07", "CWE-384": "A07", "CWE-521": "A07", "CWE-613": "A07",
    "CWE-620": "A07", "CWE-640": "A07", "CWE-940": "A07", "CWE-1216": "A07",
    # A08 — Software/Data Integrity
    "CWE-345": "A08", "CWE-353": "A08", "CWE-426": "A08", "CWE-494": "A08",
    "CWE-502": "A08", "CWE-565": "A08", "CWE-784": "A08", "CWE-829": "A08",
    "CWE-830": "A08", "CWE-915": "A08",
    # A09 — Logging/Monitoring
    "CWE-117": "A09", "CWE-223": "A09", "CWE-532": "A09", "CWE-778": "A09",
    # A10 — SSRF
    "CWE-918": "A10",
}

# CWE Top 25 2024 ranks. Source: https://cwe.mitre.org/top25/
_TOP_25_2024: dict[str, int] = {
    "CWE-79": 1, "CWE-787": 2, "CWE-89": 3, "CWE-352": 4, "CWE-22": 5,
    "CWE-125": 6, "CWE-78": 7, "CWE-416": 8, "CWE-862": 9, "CWE-434": 10,
    "CWE-94": 11, "CWE-20": 12, "CWE-77": 13, "CWE-287": 14, "CWE-269": 15,
    "CWE-502": 16, "CWE-200": 17, "CWE-863": 18, "CWE-918": 19, "CWE-119": 20,
    "CWE-476": 21, "CWE-798": 22, "CWE-190": 23, "CWE-400": 24, "CWE-306": 25,
}

# CWEs that are memory-safety and NOT applicable to Py/JS/Ruby/Node/Shell —
# we keep them in the registry with applicable=[] + a note.
_MEMORY_SAFETY_CWES: set[str] = {
    "CWE-119", "CWE-120", "CWE-121", "CWE-125", "CWE-190", "CWE-191",
    "CWE-401", "CWE-415", "CWE-416", "CWE-476", "CWE-665", "CWE-787",
}

# Detectors we have registered for each CWE. Source: native code scanner
# (ralf/detection/code_scanner.py) + Semgrep Registry rulesets that ship
# always-on. Adding entries here does NOT create detectors — it describes
# what ones the code scanner already covers.
_DETECTOR_MAP: dict[str, list[str]] = {
    "CWE-22": ["native:path-traversal", "semgrep:p/path-traversal"],
    "CWE-77": ["native:os-command-injection", "semgrep:p/command-injection"],
    "CWE-78": ["native:os-command-injection", "native:shell-mode-invocation",
               "native:reverse-shell-shaped", "semgrep:p/command-injection"],
    "CWE-79": ["semgrep:p/xss"],
    "CWE-89": ["native:sql-interpolation", "native:sql-raw-grammar", "semgrep:p/sqli"],
    "CWE-94": ["native:dynamic-eval-on-input", "native:dynamic-exec-on-input",
               "semgrep:p/cwe-94"],
    "CWE-200": ["native:log-secret-exposure", "semgrep:p/secrets"],
    "CWE-287": ["semgrep:p/auth"],
    "CWE-295": ["native:cert-validation-disabled", "semgrep:p/cert-validation"],
    "CWE-306": ["semgrep:p/auth"],
    "CWE-327": ["native:weak-crypto", "semgrep:p/cryptography"],
    "CWE-352": ["native:framework-csrf-missing", "semgrep:p/csrf"],
    "CWE-400": ["native:redos-user-regex", "semgrep:p/redos"],
    "CWE-434": ["native:unrestricted-upload", "semgrep:p/file-upload"],
    "CWE-502": ["native:unsafe-deserialization", "semgrep:p/cwe-502"],
    "CWE-522": ["native:credential-path-read", "semgrep:p/secrets"],
    "CWE-601": ["native:open-redirect", "semgrep:p/open-redirect"],
    "CWE-611": ["native:xxe-parser-config", "semgrep:p/xxe"],
    "CWE-732": ["native:world-writable-perms", "semgrep:p/permissions"],
    "CWE-798": ["native:hardcoded-credentials", "semgrep:p/secrets",
                "semgrep:p/gitleaks"],
    "CWE-862": ["semgrep:p/auth"],
    "CWE-863": ["semgrep:p/authz"],
    "CWE-916": ["native:weak-password-hash", "semgrep:p/crypto"],
    "CWE-918": ["native:ssrf-user-url", "semgrep:p/ssrf"],
    "CWE-1275": ["semgrep:p/cookie-security"],
    "CWE-1333": ["native:redos-user-regex", "semgrep:p/redos"],
    # Catch-all language-specific coverage via Semgrep's CWE Top 25 ruleset
    "CWE-20": ["semgrep:p/input-validation"],
    "CWE-74": ["semgrep:p/owasp-top-ten"],
    "CWE-117": ["semgrep:p/logging"],
    "CWE-269": ["semgrep:p/privilege"],
}


# ── Namespace-agnostic XPath helpers ──────────────────────────────────────


def _localname(tag: str) -> str:
    """Strip XML namespace, return bare tag name."""
    if "}" in tag:
        return tag.rsplit("}", 1)[1]
    return tag


def _find_child(el: ET.Element, local_name: str) -> ET.Element | None:
    for child in el:
        if _localname(child.tag) == local_name:
            return child
    return None


def _find_all_children(el: ET.Element, local_name: str) -> list[ET.Element]:
    return [c for c in el if _localname(c.tag) == local_name]


def _text_of_descendants(el: ET.Element) -> str:
    """Flatten mixed-content XML into plain text."""
    parts: list[str] = []
    if el.text:
        parts.append(el.text.strip())
    for child in el:
        parts.append(_text_of_descendants(child))
        if child.tail:
            parts.append(child.tail.strip())
    return " ".join(p for p in parts if p)


# ── Per-weakness parse ────────────────────────────────────────────────────


def _applicable_languages(weakness: ET.Element) -> tuple[list[str], bool]:
    """Returns (languages, any_language_flag).

    ``any_language_flag=True`` when the weakness is tagged
    'Not Language-Specific' or 'Interpreted' with no exclusions — we treat
    these as applicable to all our target languages.
    """
    ap = _find_child(weakness, "Applicable_Platforms")
    if ap is None:
        # No applicability declared — conservative default: include as "web"
        # so the entry stays queryable.
        return (["web"], False)

    applicable: set[str] = set()
    any_language = False

    for lang in _find_all_children(ap, "Language"):
        name = lang.get("Name") or ""
        class_ = lang.get("Class") or ""
        if name in _LANGUAGE_MAP:
            applicable.add(_LANGUAGE_MAP[name])
        if class_ in _LANGUAGE_CLASSES:
            any_language = True

    if any_language:
        applicable.update({"python", "js", "ruby", "node", "shell", "web"})

    return (sorted(applicable), any_language)


def _description(weakness: ET.Element) -> str:
    desc_el = _find_child(weakness, "Description")
    if desc_el is None:
        return ""
    text = _text_of_descendants(desc_el)
    # Keep the first sentence up to ~300 chars
    if len(text) > 300:
        text = text[:300].rstrip() + "…"
    return text


def _parse_weaknesses(xml_bytes: bytes) -> list[dict]:
    """Parse the CWE Weakness_Catalog XML. Returns applicable-language CWE entries."""
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as e:
        raise SyncError(f"CWE XML parse error: {e}") from e

    weaknesses_container = _find_child(root, "Weaknesses")
    if weaknesses_container is None:
        raise SyncError("CWE XML missing <Weaknesses> container")

    results: list[dict] = []
    for w in _find_all_children(weaknesses_container, "Weakness"):
        wid = w.get("ID")
        name = w.get("Name") or ""
        status = (w.get("Status") or "").lower()
        if not wid or not name:
            continue
        # Skip deprecated or obsolete weaknesses
        if status in ("deprecated", "obsolete"):
            continue

        cwe_id = f"CWE-{wid}"
        applicable, any_language = _applicable_languages(w)
        is_memory_safety = cwe_id in _MEMORY_SAFETY_CWES
        if is_memory_safety:
            applicable = []  # Override — not applicable to our language set

        owasp = _CWE_TO_OWASP.get(cwe_id, "")
        detectors = _DETECTOR_MAP.get(cwe_id, [])
        rank = _TOP_25_2024.get(cwe_id)

        entry = {
            "id": cwe_id,
            "name": name,
            "owasp": owasp,
            "applicable": applicable,
            "detectors": detectors,
            "rank_2024": rank,
            "description": _description(w),
        }
        if is_memory_safety:
            entry["note"] = "Memory-safety; not applicable to Py/JS/Ruby/Node/Shell"
        results.append(entry)

    # Keep only entries with SOME relevance: applicable to one of our languages,
    # OR explicitly in the 2024 Top 25 (memory-safety items retained with note),
    # OR have a detector registered, OR have an OWASP mapping.
    filtered: list[dict] = []
    for e in results:
        if e["applicable"] or e["rank_2024"] or e["detectors"] or e["owasp"]:
            filtered.append(e)

    # Deterministic order for stable diffs: by CWE ID numerically
    def _key(e: dict) -> int:
        try:
            return int(e["id"].split("-", 1)[1])
        except (IndexError, ValueError):
            return 99999

    filtered.sort(key=_key)
    return filtered


# ── Public API ────────────────────────────────────────────────────────────


def sync_cwe(*, output_path: Path | None = None, timeout_sec: float = 60.0) -> SyncResult:
    """Fetch CWE XML, parse, filter, write JSON."""
    url = _CWE_URL
    outpath = output_path or _OUTPUT_PATH

    with timer() as t:
        try:
            body, _headers = fetch_bytes(
                url, timeout_sec=timeout_sec, size_cap_bytes=_CWE_SIZE_CAP,
            )
            bytes_fetched = len(body)
            try:
                with zipfile.ZipFile(io.BytesIO(body)) as zf:
                    xml_names = [n for n in zf.namelist() if n.lower().endswith(".xml")]
                    if not xml_names:
                        raise SyncError("CWE zip archive contains no XML")
                    xml_bytes = zf.read(xml_names[0])
            except zipfile.BadZipFile as e:
                raise SyncError(f"CWE archive not a valid zip: {e}") from e

            entries = _parse_weaknesses(xml_bytes)
            if len(entries) < 50:
                raise SyncError(
                    f"CWE parse produced only {len(entries)} entries — schema drift?"
                )

            import datetime as _dt
            payload = {
                "version": 2,
                "source": "MITRE CWE — https://cwe.mitre.org/",
                "edition": "Complete weakness catalog (filtered to applicable CWEs)",
                "upstream_url": url,
                "last_updated": _dt.date.today().isoformat(),
                "description": (
                    "CWE dictionary bundle for RALF Free. Parsed from the canonical "
                    "MITRE CWE XML feed (cwec_latest.xml.zip), filtered to entries "
                    "that are either applicable to one of RALF's target languages "
                    "(Python/JavaScript/Ruby/Node/Shell/web), in the CWE Top 25, "
                    "or mapped to a RALF detector. Deprecated and obsolete weaknesses "
                    "are excluded."
                ),
                "applicability_legend": {
                    "python": "Python / CPython",
                    "js": "JavaScript / Node.js / TypeScript",
                    "ruby": "Ruby / Rails",
                    "node": "Node.js runtime",
                    "shell": "Bash / sh / zsh",
                    "config": "YAML / JSON / TOML / Dockerfile",
                    "web": "Any framework-agnostic web code",
                },
                "cwes": entries,
            }
            write_json_atomic(outpath, payload)
        except SyncError as e:
            return SyncResult(
                source="cwe", url=url, success=False, record_count=0,
                output_path=None, bytes_fetched=0, elapsed_sec=t.elapsed,
                error=str(e),
            )

    return SyncResult(
        source="cwe", url=url, success=True, record_count=len(entries),
        output_path=outpath, bytes_fetched=bytes_fetched, elapsed_sec=t.elapsed,
    )


__all__ = ["sync_cwe"]
