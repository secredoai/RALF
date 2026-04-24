"""Bandit adapter — Python-only SAST fallback.

Bandit is the canonical Python security linter. ~200-500 ms cold, ships
~60 test plugins. Included here as a fallback for Python files when ruff
is absent (many environments have bandit already).

Design parallels :mod:`ralf.detection.ruff_adapter` — graceful fallback,
hard timeout, content cap, safe subprocess invocation.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

log = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SEC: float = 3.0
MAX_CONTENT_BYTES: int = 100 * 1024
BANDIT_BIN_ENV = "RALF_BANDIT_BIN"


@dataclass(frozen=True)
class BanditFinding:
    rule_id: str               # e.g. "B303"
    severity: str              # "HIGH" | "MEDIUM" | "LOW"
    confidence: str            # "HIGH" | "MEDIUM" | "LOW"
    message: str
    start_line: int
    path: str
    cwe_ids: tuple[str, ...]

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "confidence": self.confidence,
            "message": self.message,
            "start_line": self.start_line,
            "path": self.path,
            "cwe_ids": list(self.cwe_ids),
        }


@dataclass
class BanditRunResult:
    available: bool
    invoked: bool
    findings: tuple[BanditFinding, ...]
    elapsed_sec: float
    timed_out: bool
    error: str | None = None


@lru_cache(maxsize=1)
def bandit_binary() -> str | None:
    override = os.environ.get(BANDIT_BIN_ENV, "").strip()
    if override:
        p = Path(override)
        if p.is_file() and os.access(p, os.X_OK):
            return str(p)
    return shutil.which("bandit")


def is_available() -> bool:
    return bandit_binary() is not None


def version() -> str | None:
    binary = bandit_binary()
    if binary is None:
        return None
    try:
        proc = subprocess.run(
            [binary, "--version"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        # Bandit prints the version line like "bandit 1.9.4\n  python..."
        return (proc.stdout or proc.stderr).splitlines()[0].strip() or None
    except (subprocess.TimeoutExpired, OSError):
        return None


def _parse_findings(stdout: str, path: str) -> tuple[BanditFinding, ...]:
    """Bandit JSON: {'results': [{'test_id', 'issue_severity', 'issue_confidence',
    'test_name', 'filename', 'line_number', 'issue_text', 'cwe', 'issue_cwe'}, ...]}
    """
    try:
        data = json.loads(stdout) if stdout.strip() else {}
    except json.JSONDecodeError:
        return ()
    if not isinstance(data, dict):
        return ()
    findings: list[BanditFinding] = []
    for row in data.get("results", []) or []:
        if not isinstance(row, dict):
            continue
        rule_id = str(row.get("test_id") or "")
        if not rule_id:
            continue
        msg = str(row.get("issue_text") or row.get("test_name") or "")

        # Bandit exposes CWE as either a string, int, or nested dict
        cwe_raw = row.get("issue_cwe") or row.get("cwe") or {}
        cwe_ids: list[str] = []
        if isinstance(cwe_raw, dict):
            cid = cwe_raw.get("id")
            if cid:
                cwe_ids.append(f"CWE-{cid}")
        elif isinstance(cwe_raw, int):
            cwe_ids.append(f"CWE-{cwe_raw}")
        elif isinstance(cwe_raw, str):
            s = cwe_raw.strip()
            if s.startswith("CWE-"):
                cwe_ids.append(s)
            elif s.isdigit():
                cwe_ids.append(f"CWE-{s}")

        findings.append(BanditFinding(
            rule_id=rule_id,
            severity=str(row.get("issue_severity") or "MEDIUM").upper(),
            confidence=str(row.get("issue_confidence") or "MEDIUM").upper(),
            message=msg[:200],
            start_line=int(row.get("line_number") or 0),
            path=path,
            cwe_ids=tuple(cwe_ids),
        ))
    return tuple(findings)


def run_bandit(
    content: str,
    *,
    file_path: str | None = None,
    timeout_sec: float = DEFAULT_TIMEOUT_SEC,
    content_cap_bytes: int = MAX_CONTENT_BYTES,
) -> BanditRunResult:
    binary = bandit_binary()
    if binary is None:
        return BanditRunResult(
            available=False, invoked=False, findings=(),
            elapsed_sec=0.0, timed_out=False,
        )
    if not content:
        return BanditRunResult(
            available=True, invoked=False, findings=(),
            elapsed_sec=0.0, timed_out=False,
        )
    if len(content.encode("utf-8", errors="replace")) > content_cap_bytes:
        return BanditRunResult(
            available=True, invoked=False, findings=(),
            elapsed_sec=0.0, timed_out=False,
            error="content_cap_exceeded",
        )

    import time
    tmp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        argv = [binary, "-f", "json", "-q", tmp_path]
        start = time.monotonic()
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True,
                timeout=timeout_sec, check=False,
            )
            elapsed = time.monotonic() - start
        except subprocess.TimeoutExpired:
            return BanditRunResult(
                available=True, invoked=True, findings=(),
                elapsed_sec=time.monotonic() - start, timed_out=True,
                error="timeout",
            )

        findings = _parse_findings(proc.stdout, tmp_path)
        # Bandit exits 1 when it finds issues — that's normal, not an error
        err = None
        if proc.returncode not in (0, 1):
            err = f"exit_{proc.returncode}"
        return BanditRunResult(
            available=True, invoked=True, findings=findings,
            elapsed_sec=elapsed, timed_out=False, error=err,
        )
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


__all__ = [
    "BanditFinding", "BanditRunResult",
    "DEFAULT_TIMEOUT_SEC", "MAX_CONTENT_BYTES",
    "bandit_binary", "is_available", "version", "run_bandit",
]
