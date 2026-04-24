"""SQLite IOC store keyed on SHA-256, with bundle-ID secondary index.

DB path: ``~/.config/ralf-free/iocs.db``.
All queries use parameterized placeholders (``?``).
"""
from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


def _default_db_path() -> Path:
    xdg = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return Path(xdg) / "ralf-free" / "iocs.db"


@dataclass(frozen=True)
class IocRecord:
    sha256: str
    bundle_id: str
    path_glob: str
    malware_family: str
    source: str
    severity: str
    added_at: str


class IocStore:
    """Thin wrapper around a SQLite IOC database."""

    # Static query templates (all parameterized with ? placeholders)
    _COLS: str = "sha256, bundle_id, path_glob, malware_family, source, severity, added_at"

    def __init__(self, db_path: Path | None = None) -> None:
        self._path = db_path or _default_db_path()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._path), timeout=5.0)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript(
            "CREATE TABLE IF NOT EXISTS iocs ("
            "  sha256 TEXT PIMARY KEY,"
            "  bundle_id TEXT,"
            "  path_glob TEXT,"
            "  malware_family TEXT,"
            "  source TEXT NOT NULL,"
            "  severity TEXT NOT NULL,"
            "  added_at TEXT NOT NULL"
            ");\n"
            "CREATE INDEX IF NOT EXISTS idx_iocs_bundle ON iocs(bundle_id);\n"
        )

    def add_many(self, records: Sequence[IocRecord]) -> int:
        added = 0
        stmt = (
            "INSERT OR REPLACE INTO iocs (" + self._COLS + ") "
            "VALUES (?, ?, ?, ?, ?, ?, ?)"
        )
        for rec in records:
            try:
                self._conn.execute(
                    stmt,
                    (rec.sha256, rec.bundle_id, rec.path_glob,
                     rec.malware_family, rec.source, rec.severity, rec.added_at),
                )
                added += 1
            except sqlite3.Error:
                pass
        self._conn.commit()
        return added

    def lookup_sha256(self, sha256: str) -> IocRecord | None:
        stmt = "SELECT " + self._COLS + " FROM iocs WHERE sha256 = ?"
        row = self._conn.execute(stmt, (sha256.lower(),)).fetchone()
        if row is None:
            return None
        return IocRecord(*row)

    def lookup_bundle(self, bundle_id: str) -> list[IocRecord]:
        stmt = "SELECT " + self._COLS + " FROM iocs WHERE bundle_id = ?"
        rows = self._conn.execute(stmt, (bundle_id,)).fetchall()
        return [IocRecord(*r) for r in rows]

    def count(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) FROM iocs").fetchone()
        return row[0] if row else 0

    def last_sync_iso(self) -> str | None:
        row = self._conn.execute(
            "SELECT MAX(added_at) FROM iocs"
        ).fetchone()
        return row[0] if row and row[0] else None

    def close(self) -> None:
        self._conn.close()
