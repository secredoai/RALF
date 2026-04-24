"""Data-sync fetchers — pull public security-knowledge catalogs from their
sources of truth and emit the bundled JSON files loaded at runtime.

RALF Free ships baseline bundled data in ``ralf/data/*.json`` so the tool works
offline out of the box. The fetchers here let users run ``ralf-free sync`` to
refresh that data from the upstream public sources:

- MITRE ATT&CK STIX feed → ``mitre_attack_linux.json`` + ``mitre_attack_macos.json``
- MITRE CWE XML dictionary → ``cwe_top25.json`` (extended to all applicable CWEs)
- LOOBins GitHub archive → ``loobins_capabilities.json``
- GTFOBins GitHub archive → learned-rule generation for Linux LOLBins

Every fetcher is:

- **Opt-in** (the user runs ``ralf-free sync`` explicitly; no background downloads)
- **Deterministic** (same input → same output, safe to re-run)
- **Offline-safe** (network failure falls back to the bundled baseline)
- **Bounded** (size caps + timeouts on every HTTPS fetch; no new deps)
- **Safe** (HTTPS-only URLs, ``json.loads`` / ``yaml.safe_load`` / stdlib XML only)

See :mod:`ralf.sync._base` for the shared fetch machinery and error model.
"""
from ralf.sync._base import (
    SyncError,
    SyncResult,
    NetworkUnavailableError,
    ResponseTooLargeError,
    HttpError,
    default_user_agent,
)
from ralf.sync.mitre_stix import sync_mitre_linux, sync_mitre_macos
from ralf.sync.cwe_xml import sync_cwe
from ralf.sync.loobins import sync_loobins
from ralf.sync.gtfobins import sync_gtfobins
from ralf.sync.cve_federator import sync_cve

__all__ = [
    "SyncError",
    "SyncResult",
    "NetworkUnavailableError",
    "ResponseTooLargeError",
    "HttpError",
    "default_user_agent",
    "sync_mitre_linux",
    "sync_mitre_macos",
    "sync_cwe",
    "sync_loobins",
    "sync_gtfobins",
    "sync_cve",
]
