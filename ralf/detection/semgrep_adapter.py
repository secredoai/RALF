"""Semgrep adapter — invoke the Semgrep CLI from within RALF hooks.

Design goals:

- **Graceful fallback**: if ``semgrep`` is not on PATH, this module reports
  "unavailable" and the hook layer continues with native detectors only.
- **Hard performance budget**: 3 s wall-clock timeout per scan, 100 KB content
  cap per scan, max 2 concurrent scans (enforced by a semaphore in the caller).
- **Safe invocation**: subprocess is launched with an argument list (no shell
  interpolation). Content is written to a temp file and cleaned up. No command
  string is ever constructed via concatenation.
- **Pure public knowledge**: ships only Semgrep Registry community rulesets
  (``p/ci``, ``p/security-audit``, ``p/owasp-top-ten``, ``p/cwe-top-25``,
  ``p/secrets``, ``p/gitleaks`` and language-specific ones). No proprietary
  rules.

The ``run_semgrep`` function is synchronous. The hook layer should call it
only when content is code-shaped (see ``semgrep_rulesets.language_for_path``)
to avoid scanning binary blobs or large JSON payloads.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from ralf.detection.semgrep_rulesets import rulesets_for_path

log = logging.getLogger(__name__)

# ── Budgets ────────────────────────────────────────────────────────────────

DEFAULT_TIMEOUT_SEC: float = 3.0
MAX_CONTENT_BYTES: int = 100 * 1024  # 100 KB
SEMGREP_BIN_ENV = "RALF_SEMGREP_BIN"


# ── Dataclasses ────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class SemgrepFinding:
    """Normalized finding from a Semgrep run."""

    rule_id: str
    message: str
    severity: str              # "ERROR" | "WARNING" | "INFO"
    cwe_ids: tuple[str, ...]
    owasp_categories: tuple[str, ...]
    start_line: int
    end_line: int
    path: str
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "message": self.message,
            "severity": self.severity,
            "cwe_ids": list(self.cwe_ids),
            "owasp_categories": list(self.owasp_categories),
            "start_line": self.start_line,
            "end_line": self.end_line,
            "path": self.path,
        }


@dataclass
class SemgrepRunResult:
    """Outcome of one Semgrep invocation."""

    available: bool
    invoked: bool
    findings: tuple[SemgrepFinding, ...]
    elapsed_sec: float
    timed_out: bool
    error: str | None = None

    @property
    def clean(self) -> bool:
        return self.invoked and not self.findings and not self.timed_out

    def to_dict(self) -> dict:
        return {
            "available": self.available,
            "invoked": self.invoked,
            "findings": [f.to_dict() for f in self.findings],
            "elapsed_sec": round(self.elapsed_sec, 4),
            "timed_out": self.timed_out,
            "error": self.error,
        }


# ── Availability ───────────────────────────────────────────────────────────


@lru_cache(maxsize=1)
def semgrep_binary() -> str | None:
    """Locate the Semgrep binary. Respects ``RALF_SEMGREP_BIN`` override.

    Returns the absolute path or None if unavailable.
    """
    override = os.environ.get(SEMGREP_BIN_ENV, "").strip()
    if override:
        p = Path(override)
        if p.is_file() and os.access(p, os.X_OK):
            return str(p)
        log.debug("RALF_SEMGREP_BIN points at %s which is not executable", override)
    found = shutil.which("semgrep")
    return found


def is_available() -> bool:
    return semgrep_binary() is not None


# ── Output parser ──────────────────────────────────────────────────────────


def _parse_cwes(metadata: dict) -> tuple[str, ...]:
    """Extract CWE IDs from Semgrep rule metadata. Tolerates many formats."""
    raw = metadata.get("cwe") or metadata.get("cwe2022-top25") or []
    if isinstance(raw, str):
        raw = [raw]
    out: list[str] = []
    for item in raw:
        # Formats seen: "CWE-78: OS Command Injection", "CWE-78", 78
        if isinstance(item, int):
            out.append(f"CWE-{item}")
            continue
        s = str(item).strip()
        if s.startswith("CWE-"):
            out.append(s.split(":", 1)[0].strip())
        elif s.isdigit():
            out.append(f"CWE-{s}")
    return tuple(dict.fromkeys(out))  # dedup preserving order


def _parse_owasp(metadata: dict) -> tuple[str, ...]:
    """Extract OWASP category IDs ('A01'..'A10') from rule metadata."""
    raw = metadata.get("owasp") or []
    if isinstance(raw, str):
        raw = [raw]
    out: list[str] = []
    for item in raw:
        s = str(item).strip().upper()
        if s.startswith("A") and len(s) >= 3 and s[1:3].isdigit():
            out.append(s[:3])
    return tuple(dict.fromkeys(out))


def _parse_findings(stdout: str, path: str) -> tuple[SemgrepFinding, ...]:
    """Parse Semgrep JSON output into normalized findings."""
    try:
        data = json.loads(stdout) if stdout.strip() else {}
    except json.JSONDecodeError as e:
        log.debug("Semgrep stdout not valid JSON: %s", e)
        return ()
    findings: list[SemgrepFinding] = []
    for raw in data.get("results", []) or []:
        extra = raw.get("extra", {}) or {}
        metadata = extra.get("metadata", {}) or {}
        findings.append(SemgrepFinding(
            rule_id=raw.get("check_id", ""),
            message=extra.get("message", "") or metadata.get("message", ""),
            severity=(extra.get("severity") or "INFO").upper(),
            cwe_ids=_parse_cwes(metadata),
            owasp_categories=_parse_owasp(metadata),
            start_line=int(raw.get("start", {}).get("line", 0)),
            end_line=int(raw.get("end", {}).get("line", 0)),
            path=path,
            raw=raw,
        ))
    return tuple(findings)


# ── Runner ─────────────────────────────────────────────────────────────────


def _build_argv(
    binary: str,
    scan_path: str,
    rulesets: tuple[str, ...],
) -> list[str]:
    """Build the Semgrep argv. Each ruleset becomes its own ``--config`` flag."""
    argv = [binary, "--json", "--quiet", "--no-git-ignore", "--metrics=off"]
    for r in rulesets:
        argv.extend(("--config", r))
    argv.append(scan_path)
    return argv


def run_semgrep(
    content: str,
    *,
    file_path: str | None = None,
    timeout_sec: float = DEFAULT_TIMEOUT_SEC,
    content_cap_bytes: int = MAX_CONTENT_BYTES,
) -> SemgrepRunResult:
    """Run Semgrep on content. Returns a SemgrepRunResult.

    - Does not raise on Semgrep errors (returns ``available=False`` or an
      ``error`` string).
    - Uses a temp file so the caller never has to hand Semgrep a real path.
    - Always cleans up the temp file, even on timeout.
    """
    import time

    binary = semgrep_binary()
    if binary is None:
        return SemgrepRunResult(
            available=False,
            invoked=False,
            findings=(),
            elapsed_sec=0.0,
            timed_out=False,
            error=None,
        )

    if not content:
        return SemgrepRunResult(
            available=True, invoked=False, findings=(), elapsed_sec=0.0, timed_out=False,
        )

    if len(content.encode("utf-8", errors="replace")) > content_cap_bytes:
        return SemgrepRunResult(
            available=True, invoked=False, findings=(), elapsed_sec=0.0, timed_out=False,
            error=f"content_exceeds_cap:{content_cap_bytes}",
        )

    rulesets = rulesets_for_path(file_path, content=content)
    if not rulesets:
        return SemgrepRunResult(
            available=True, invoked=False, findings=(), elapsed_sec=0.0, timed_out=False,
            error="no_applicable_rulesets",
        )

    suffix = Path(file_path).suffix if file_path else ".txt"
    tmp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=suffix, delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        argv = _build_argv(binary, tmp_path, rulesets)
        start = time.monotonic()
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=timeout_sec,
                check=False,
            )
            elapsed = time.monotonic() - start
        except subprocess.TimeoutExpired:
            elapsed = time.monotonic() - start
            return SemgrepRunResult(
                available=True, invoked=True, findings=(),
                elapsed_sec=elapsed, timed_out=True,
                error="timeout",
            )

        findings = _parse_findings(proc.stdout, tmp_path)
        return SemgrepRunResult(
            available=True,
            invoked=True,
            findings=findings,
            elapsed_sec=elapsed,
            timed_out=False,
            error=None if proc.returncode in (0, 1) else f"exit_{proc.returncode}",
        )
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def version() -> str | None:
    """Return Semgrep version string, or None if unavailable."""
    binary = semgrep_binary()
    if binary is None:
        return None
    try:
        proc = subprocess.run(
            [binary, "--version"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        return (proc.stdout or proc.stderr).strip() or None
    except (subprocess.TimeoutExpired, OSError):
        return None


__all__ = [
    "SemgrepFinding",
    "SemgrepRunResult",
    "DEFAULT_TIMEOUT_SEC",
    "MAX_CONTENT_BYTES",
    "semgrep_binary",
    "is_available",
    "run_semgrep",
    "version",
]
