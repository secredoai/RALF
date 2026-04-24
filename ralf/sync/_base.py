"""Shared HTTP-fetch infrastructure for the sync fetchers.

Design:

- Stdlib only (``urllib.request`` + ``http.client``) so Free gets no new deps.
- HTTPS-only URL enforcement.
- Response size cap (default 100 MB; per-call override).
- Wall-clock timeout (default 30 s; per-call override).
- Descriptive user-agent so upstreams can identify us and rate-limit politely.
- Structured error types — fetchers catch ``SyncError`` subclasses and surface
  them in :class:`SyncResult`; never raise into the CLI dispatcher.

Error model:

- :class:`NetworkUnavailableError` — DNS/connection/read failures
- :class:`HttpError` — non-2xx response
- :class:`ResponseTooLargeError` — exceeded size cap
- :class:`SyncError` — base class for all of the above, also raised on
  malformed response payloads

The :class:`SyncResult` dataclass is what every fetcher returns. It carries
success state, the source URL actually used, the count of records ingested,
the output path on disk, and diagnostic info for the CLI.
"""
from __future__ import annotations

import logging
import platform
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# ── Defaults ──────────────────────────────────────────────────────────────

DEFAULT_TIMEOUT_SEC: float = 30.0
DEFAULT_SIZE_CAP_BYTES: int = 100 * 1024 * 1024  # 100 MB
CHUNK_BYTES: int = 64 * 1024


# ── User agent ────────────────────────────────────────────────────────────


def default_user_agent(version: str = "0.1.0") -> str:
    """Polite, identifiable user-agent string.

    Upstreams (GitHub, MITRE) can use this to rate-limit us separately from
    generic unidentified traffic and contact us if our fetches misbehave.
    """
    py = platform.python_version()
    return (
        f"ralf-free/{version} (+https://github.com/ralf-free) "
        f"python/{py}"
    )


# ── Error types ───────────────────────────────────────────────────────────


class SyncError(Exception):
    """Base class for sync errors surfaced back to the caller.

    Fetchers catch this and stuff the message into SyncResult.error.
    """


class NetworkUnavailableError(SyncError):
    """DNS / TCP / TLS / read failure — the network couldn't be reached."""


class HttpError(SyncError):
    """Non-2xx HTTP response. Carries the status code."""

    def __init__(self, message: str, status_code: int):
        super().__init__(message)
        self.status_code = status_code


class ResponseTooLargeError(SyncError):
    """Response body exceeded the configured size cap."""


# ── SyncResult ────────────────────────────────────────────────────────────


@dataclass
class SyncResult:
    """Outcome of one fetcher invocation."""

    source: str                      # human-readable source label (e.g. "mitre-linux")
    url: str                         # URL actually fetched from
    success: bool
    record_count: int                # e.g. number of techniques / CWEs / binaries
    output_path: Path | None         # where JSON was written (None on failure)
    bytes_fetched: int               # size of upstream payload
    elapsed_sec: float               # wall-clock duration
    error: str | None = None         # error message on failure
    warnings: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        if self.success:
            return (
                f"[OK]   {self.source:20} {self.record_count:5} records, "
                f"{self.bytes_fetched // 1024:5} KB in {self.elapsed_sec:5.2f}s "
                f"→ {self.output_path}"
            )
        return (
            f"[FAIL] {self.source:20} {self.error or 'unknown error'}"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "url": self.url,
            "success": self.success,
            "record_count": self.record_count,
            "output_path": str(self.output_path) if self.output_path else None,
            "bytes_fetched": self.bytes_fetched,
            "elapsed_sec": round(self.elapsed_sec, 3),
            "error": self.error,
            "warnings": list(self.warnings),
        }


# ── HTTPS-only fetch ──────────────────────────────────────────────────────


def _require_https(url: str) -> None:
    """Enforce HTTPS. Mitigates TLS-stripping / man-in-the-middle."""
    if not url.startswith("https://"):
        raise SyncError(f"URL must use HTTPS: {url!r}")


def fetch_bytes(
    url: str,
    *,
    timeout_sec: float = DEFAULT_TIMEOUT_SEC,
    size_cap_bytes: int = DEFAULT_SIZE_CAP_BYTES,
    extra_headers: dict[str, str] | None = None,
    user_agent: str | None = None,
) -> tuple[bytes, dict[str, str]]:
    """HTTPS GET with timeout + size cap. Returns (body, headers).

    Raises :class:`NetworkUnavailableError` on connection problems,
    :class:`HttpError` on non-2xx responses, or
    :class:`ResponseTooLargeError` if the body exceeds ``size_cap_bytes``.
    """
    _require_https(url)

    headers = {
        "User-Agent": user_agent or default_user_agent(),
        "Accept-Encoding": "gzip, identity",
    }
    if extra_headers:
        headers.update(extra_headers)

    req = urllib.request.Request(url, headers=headers, method="GET")

    # Default ssl context — standard CA bundle, cert validation required.
    context = ssl.create_default_context()

    try:
        with urllib.request.urlopen(req, timeout=timeout_sec, context=context) as resp:
            status = resp.status
            if status < 200 or status >= 300:
                raise HttpError(f"{url}: HTTP {status}", status_code=status)

            body = bytearray()
            while True:
                chunk = resp.read(CHUNK_BYTES)
                if not chunk:
                    break
                body.extend(chunk)
                if len(body) > size_cap_bytes:
                    raise ResponseTooLargeError(
                        f"{url}: exceeded size cap {size_cap_bytes} bytes"
                    )

            resp_headers = {k.lower(): v for k, v in resp.headers.items()}

            # Decompress if gzipped. urlopen does NOT transparently gunzip.
            if resp_headers.get("content-encoding", "").lower() == "gzip":
                import gzip
                try:
                    body = bytearray(gzip.decompress(bytes(body)))
                except OSError as e:
                    raise SyncError(f"{url}: gzip decompress failed: {e}") from e

            return bytes(body), resp_headers

    except urllib.error.HTTPError as e:
        raise HttpError(f"{url}: HTTP {e.code} {e.reason}", status_code=e.code) from e
    except urllib.error.URLError as e:
        raise NetworkUnavailableError(f"{url}: {e.reason}") from e
    except (OSError, TimeoutError) as e:
        raise NetworkUnavailableError(f"{url}: {e}") from e


# ── Convenience: atomic JSON write ────────────────────────────────────────


def write_json_atomic(path: Path, data: dict | list, *, sort_keys: bool = False) -> None:
    """Write JSON atomically (tmp file + rename). Safe against crashes mid-write.

    Uses indent=2 + UTF-8, with a trailing newline for clean diffs.
    """
    import json
    import os
    tmp = path.with_suffix(path.suffix + ".tmp")
    path.parent.mkdir(parents=True, exist_ok=True)
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, sort_keys=sort_keys)
        f.write("\n")
    os.replace(tmp, path)


# ── Convenience: timer ────────────────────────────────────────────────────


def timer() -> "_Timer":
    return _Timer()


class _Timer:
    def __enter__(self) -> "_Timer":
        self._start = time.monotonic()
        self.elapsed = 0.0
        return self

    def __exit__(self, *args) -> None:
        self.elapsed = time.monotonic() - self._start


__all__ = [
    "SyncError",
    "SyncResult",
    "NetworkUnavailableError",
    "HttpError",
    "ResponseTooLargeError",
    "DEFAULT_TIMEOUT_SEC",
    "DEFAULT_SIZE_CAP_BYTES",
    "default_user_agent",
    "fetch_bytes",
    "write_json_atomic",
    "timer",
]
