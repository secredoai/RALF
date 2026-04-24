"""File-backed per-session ring buffer for content provenance.

The ledger is a JSONL file per session stored under
``$XDG_CACHE_HOME/ralf-free/provenance/<session_id>.jsonl``. Reads and
writes are atomic (tempfile + os.replace). The writer caps the buffer at
:data:`MAX_EVENTS_PER_SESSION` entries; older entries are evicted FIFO.
Queries filter by :data:`HISTORY_WINDOW_SECONDS` (30 min default).

Concurrency: multiple hook processes may write the same session file in
parallel. The read-modify-write cycle is serialized by an exclusive
advisory lock (``fcntl.LOCK_EX`` on POSIX) acquired on a per-session
lock file. On lock failure (non-POSIX host, NFS, etc.) we fail open —
the ledger is advisory, it must never break the hook.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

try:
    import fcntl  # POSIX: Linux + macOS (classifiers enforce)
except ImportError:  # pragma: no cover — non-POSIX
    fcntl = None  # type: ignore[assignment]

from ralf.provenance import (
    EXCERPT_LIMIT, FULL_REDACTED_LIMIT, ContentEvent, TrustLevel,
    compute_hash, is_untrusted, make_excerpt, make_full_redacted,
)
from ralf.provenance.redaction import redact_and_clip

log = logging.getLogger(__name__)

# Configuration
MAX_EVENTS_PER_SESSION = 20
HISTORY_WINDOW_SECONDS = 1800  # 30 minutes

# Hard cap on total ledger file size (safety against runaway growth).
MAX_FILE_BYTES = 5 * 1024 * 1024


def _ledger_dir() -> Path:
    """Return the directory for provenance files."""
    xdg = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    return Path(xdg) / "ralf-free" / "provenance"


def _sanitize_session_id(session_id: str) -> str:
    """Strip characters that could escape the ledger dir."""
    keep = "".join(
        c if c.isalnum() or c in ("-", "_") else "_"
        for c in session_id
    )
    return keep[:128] or "default"


@contextmanager
def _acquire_lock(lock_path: Path):
    """Exclusive advisory lock for ledger read-modify-write.

    Uses ``fcntl.LOCK_EX`` on POSIX. Fail-open on any error (non-POSIX
    host, NFS, permission denied) — the ledger is advisory; locking is
    a correctness aid, not a safety requirement. Callers are expected
    to tolerate lost events on lock failure (which is still better than
    the pre-2026-04-15 state of NO locking at all).

    The lock file is separate from the data file so we can ``os.replace``
    the data without invalidating the lock fd.
    """
    if fcntl is None:
        yield
        return
    lockfile = None
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        lockfile = open(lock_path, "w", encoding="utf-8")
        try:
            fcntl.flock(lockfile.fileno(), fcntl.LOCK_EX)
        except OSError:
            pass  # fail-open if flock unsupported (e.g., NFS without locking)
        yield
    except OSError:
        yield  # fail-open on lockfile open error
    finally:
        if lockfile is not None:
            try:
                lockfile.close()  # implicitly releases the lock
            except OSError:
                pass


class ProvenanceLedger:
    """Per-session ring buffer of content events.

    All methods fail open — if the file is unreadable, locked, or corrupt,
    we degrade gracefully. The ledger is an advisory signal feeding the
    verdict engine; it must never break the hook.
    """

    def __init__(self, session_id: str):
        self.session_id = _sanitize_session_id(session_id)
        self._dir = _ledger_dir()
        try:
            self._dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            log.debug("Failed to create ledger dir: %s", exc)
        self._path = self._dir / f"{self.session_id}.jsonl"

    # ── Write path ──────────────────────────────────────────────────────

    def record(
        self,
        trust: TrustLevel,
        source: str,
        content: str,
        *,
        injection_score: int = 0,
        injection_hits: tuple[str, ...] = (),
    ) -> ContentEvent | None:
        """Record a content event. Returns the stored event, or None on error.

        The content is REDACTED (credentials stripped) before storage.
        Excerpts and hashes are computed over the redacted content.
        Size metadata records the original pre-redaction byte count.
        """
        if not content:
            return None
        try:
            size_bytes = len(content.encode("utf-8", errors="replace"))
            redacted, _red_counts = redact_and_clip(content, FULL_REDACTED_LIMIT)
            event = ContentEvent(
                trust=trust,
                source=source[:500],  # cap source string length
                timestamp=time.time(),
                content_hash=compute_hash(redacted),
                excerpt=make_excerpt(redacted),
                full_redacted=make_full_redacted(redacted),
                size_bytes=size_bytes,
                injection_score=injection_score,
                injection_hits=tuple(injection_hits),
                session_id=self.session_id,
            )
            self._append(event)
            return event
        except Exception as exc:
            log.debug("ledger.record failed: %s", exc)
            return None

    def _append(self, event: ContentEvent) -> None:
        """Append + trim atomically under an exclusive file lock.

        Reads existing events, appends the new one, trims to capacity,
        writes back via tempfile + os.replace. Lock serializes concurrent
        hook processes so events aren't lost.
        """
        lock_path = self._path.with_suffix(".jsonl.lock")
        with _acquire_lock(lock_path):
            existing = self._read_all()
            existing.append(event)

            # Trim by time (drop events older than window)
            cutoff = time.time() - HISTORY_WINDOW_SECONDS
            existing = [e for e in existing if e.timestamp >= cutoff]

            # Trim by count
            if len(existing) > MAX_EVENTS_PER_SESSION:
                existing = existing[-MAX_EVENTS_PER_SESSION:]

            self._write_all(existing)

    # ── Read path ───────────────────────────────────────────────────────

    def recent(self, n: int = MAX_EVENTS_PER_SESSION) -> list[ContentEvent]:
        """Return the most recent ``n`` events within the TTL window."""
        events = self._read_all()
        cutoff = time.time() - HISTORY_WINDOW_SECONDS
        events = [e for e in events if e.timestamp >= cutoff]
        return events[-n:]

    def recent_untrusted(self, n: int = MAX_EVENTS_PER_SESSION) -> list[ContentEvent]:
        """Return recent events from untrusted sources only."""
        return [e for e in self.recent(n) if is_untrusted(e.trust)]

    def _read_all(self) -> list[ContentEvent]:
        """Read all events from disk. Silent-fail on corruption."""
        if not self._path.exists():
            return []
        try:
            if self._path.stat().st_size > MAX_FILE_BYTES:
                log.warning(
                    "ledger file %s exceeds %d bytes — rotating",
                    self._path, MAX_FILE_BYTES,
                )
                self._rotate()
                return []
            events: list[ContentEvent] = []
            with open(self._path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        events.append(ContentEvent.from_dict(data))
                    except (json.JSONDecodeError, ValueError):
                        continue
            return events
        except OSError as exc:
            log.debug("ledger._read_all failed: %s", exc)
            return []

    def _write_all(self, events: list[ContentEvent]) -> None:
        """Write events atomically via tempfile + os.replace."""
        try:
            fd, tmp_path = tempfile.mkstemp(
                prefix=f".{self.session_id}.",
                suffix=".jsonl.tmp",
                dir=str(self._dir),
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    for event in events:
                        f.write(json.dumps(event.to_dict(include_full=True)))
                        f.write("\n")
                os.replace(tmp_path, self._path)
            except Exception:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise
        except OSError as exc:
            log.debug("ledger._write_all failed: %s", exc)

    def _rotate(self) -> None:
        """Rotate an oversized ledger file to .1, start fresh."""
        try:
            rotated = self._path.with_suffix(".jsonl.1")
            if rotated.exists():
                rotated.unlink()
            self._path.rename(rotated)
        except OSError as exc:
            log.debug("ledger._rotate failed: %s", exc)

    # ── Maintenance ─────────────────────────────────────────────────────

    def clear(self) -> None:
        """Remove this session's ledger file."""
        try:
            if self._path.exists():
                self._path.unlink()
        except OSError as exc:
            log.debug("ledger.clear failed: %s", exc)

    @property
    def path(self) -> Path:
        """The file path for this session's ledger (for testing)."""
        return self._path
