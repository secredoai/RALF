"""Cross-adapter audit recorder — thin wrapper over ``ralf.shared.audit_log``.

Why a wrapper instead of just calling ``audit_log.append`` directly?
Three reasons:

    1. Type safety — adapters pass a :class:`CommonEvent`, not an
       ad-hoc dict, so the schema can't drift between adapters.
    2. Failure isolation — audit-log writes must NEVER cause a hook
       to fail open or block. The wrapper catches every exception
       and silently drops the event rather than letting an OSError
       bubble out of the adapter and prevent a verdict from being
       emitted.
    3. Future-proofing — if we later add SQLite mirroring or
       remote shipping, the change lands here, not in every adapter.
"""
from __future__ import annotations

from pathlib import Path

from ralf.core.event import CommonEvent
from ralf.provenance.redaction import redact
from ralf.shared.audit_log import append as _append


def record(event: CommonEvent, *, path: Path | None = None) -> None:
    """Append ``event`` to the audit log. Never raises.

    Pass ``path`` for tests that want to redirect the log to a tmp
    file; production callers should leave it ``None`` and rely on the
    XDG-derived default in :mod:`ralf.shared.audit_log`.

    Credentials (API keys, bearer tokens, KEY=VALUE secrets, private
    keys, URL-embedded creds) are stripped from ``command`` and
    ``reason`` before the row is written — the audit log must never
    be a secret-leak surface.
    """
    try:
        row = event.as_dict()
        if row.get("command"):
            row["command"], _ = redact(row["command"])
        if row.get("reason"):
            row["reason"], _ = redact(row["reason"])
        _append(row, path=path)
    except Exception:
        # The audit log is best-effort. A failed write must NOT
        # prevent the adapter from emitting its verdict.
        pass
