"""Objective-See macOS malware IOC feed sync.

Fetches the Objective-See community malware catalog from GitHub, parses
into IocRecord tuples, and writes to the SQLite IOC store.

Signature mirrors sync_gtfobins: ``sync_objective_see(*, timeout_sec=60.0,
db_path=None)`` returns a :class:`SyncResult`.
"""
from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path

from ralf.sync._base import (
    SyncResult,
    fetch_bytes,
    NetworkUnavailableError,
    HttpError,
    ResponseTooLargeError,
    SyncError,
)
from ralf.threats.ioc_store import IocRecord, IocStore

log = logging.getLogger(__name__)

_FEED_URL = (
    "https://raw.githubusercontent.com/objective-see/Malware/master/malware.json"
)

_SOURCE = "objective-see"
_SEVERITY = "malicious"


def _parse_feed(raw: bytes) -> list[IocRecord]:
    """Parse the Objective-See malware JSON into IocRecord list.

    The feed schema is an object mapping malware-family names to metadata
    dicts. Each entry may contain ``hashes`` (list of SHA-256), ``bundleID``
    (string), and ``path`` (glob pattern).
    """
    data = json.loads(raw)
    now_iso = datetime.now(timezone.utc).isoformat()
    records: list[IocRecord] = []

    if isinstance(data, dict):
        for family_name, meta in data.items():
            if not isinstance(meta, dict):
                continue
            hashes = meta.get("hashes", [])
            if isinstance(hashes, str):
                hashes = [hashes]
            bundle_id = str(meta.get("bundleID", "") or "")
            path_glob = str(meta.get("path", "") or "")

            for h in hashes:
                if not isinstance(h, str) or len(h) != 64:
                    continue
                records.append(IocRecord(
                    sha256=h.lower(),
                    bundle_id=bundle_id,
                    path_glob=path_glob,
                    malware_family=str(family_name),
                    source=_SOURCE,
                    severity=_SEVERITY,
                    added_at=now_iso,
                ))

            if not hashes and bundle_id:
                records.append(IocRecord(
                    sha256="",
                    bundle_id=bundle_id,
                    path_glob=path_glob,
                    malware_family=str(family_name),
                    source=_SOURCE,
                    severity=_SEVERITY,
                    added_at=now_iso,
                ))

    elif isinstance(data, list):
        for entry in data:
            if not isinstance(entry, dict):
                continue
            family_name = str(entry.get("name", entry.get("family", "unknown")))
            hashes = entry.get("hashes", entry.get("sha256", []))
            if isinstance(hashes, str):
                hashes = [hashes]
            bundle_id = str(entry.get("bundleID", entry.get("bundle_id", "")) or "")
            path_glob = str(entry.get("path", "") or "")

            for h in hashes:
                if not isinstance(h, str) or len(h) != 64:
                    continue
                records.append(IocRecord(
                    sha256=h.lower(),
                    bundle_id=bundle_id,
                    path_glob=path_glob,
                    malware_family=family_name,
                    source=_SOURCE,
                    severity=_SEVERITY,
                    added_at=now_iso,
                ))

    return records


def sync_objective_see(
    *,
    timeout_sec: float = 60.0,
    db_path: Path | None = None,
) -> SyncResult:
    """Fetch the Objective-See feed and populate the IOC store."""
    t0 = time.monotonic()
    try:
        body, _headers = fetch_bytes(_FEED_URL, timeout_sec=timeout_sec)
    except (NetworkUnavailableError, HttpError, ResponseTooLargeError, SyncError) as exc:
        return SyncResult(
            source=_SOURCE,
            url=_FEED_URL,
            success=False,
            record_count=0,
            output_path=None,
            bytes_fetched=0,
            elapsed_sec=time.monotonic() - t0,
            error=str(exc),
        )

    try:
        records = _parse_feed(body)
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        return SyncResult(
            source=_SOURCE,
            url=_FEED_URL,
            success=False,
            record_count=0,
            output_path=None,
            bytes_fetched=len(body),
            elapsed_sec=time.monotonic() - t0,
            error=f"feed parse error: {exc}",
        )

    store = IocStore(db_path=db_path)
    try:
        added = store.add_many(records)
    finally:
        store.close()

    return SyncResult(
        source=_SOURCE,
        url=_FEED_URL,
        success=True,
        record_count=added,
        output_path=db_path or Path("~/.config/ralf-free/iocs.db"),
        bytes_fetched=len(body),
        elapsed_sec=time.monotonic() - t0,
    )
