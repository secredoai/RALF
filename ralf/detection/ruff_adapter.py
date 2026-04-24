"""Ruff adapter — fast Python-only SAST for the hook path.

Ruff (Rust, single binary, ~10-50 ms cold-start) ships ~40 security lints
under the ``S`` rule prefix (bandit-equivalent). We invoke it on Python
content via a temp file and parse JSON findings.

Design mirrors :mod:`ralf.detection.semgrep_adapter`:

- Graceful fallback: no binary on PATH -> ``available=False``, never raises.
- Hard timeout: 2 s (ruff finishes in under 100 ms on small files, 2 s is
  safety margin).
- Content cap: 100 KB.
- Safe invocation: argv list, no shell, temp file, cleanup in ``finally``.
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

log = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SEC: float = 2.0
MAX_CONTENT_BYTES: int = 100 * 1024
RUFF_BIN_ENV = "RALF_RUFF_BIN"


@dataclass(frozen=True)
class RuffFinding:
    """Normalized finding from a ruff run."""

    rule_id: str               # e.g. "S102"
    severity: str              # "ERROR" | "WARNING" (ruff uses severity-ish)
    message: str
    start_line: int
    end_line: int
    path: str
    cwe_ids: tuple[str, ...]   # derived from rule → CWE mapping below

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "path": self.path,
            "cwe_ids": list(self.cwe_ids),
        }


@dataclass
class RuffRunResult:
    available: bool
    invoked: bool
    findings: tuple[RuffFinding, ...]
    elapsed_sec: float
    timed_out: bool
    error: str | None = None


# Ruff "S" rule -> approximate CWE mapping. Not every rule has a
# canonical CWE; these are the high-confidence entries. For rules not in
# this table, we emit an empty CWE list and leave the rule_id intact.
_RULE_CWE: dict[str, tuple[str, ...]] = {
    "S101": ("CWE-703",),                    # assert-used
    "S102": ("CWE-94",),                     # exec-builtin
    "S103": ("CWE-732",),                    # bad-file-permissions
    "S104": ("CWE-668",),                    # possible-binding-to-all-interfaces
    "S105": ("CWE-798",),                    # hardcoded-password-string
    "S106": ("CWE-798",),                    # hardcoded-password-func-arg
    "S107": ("CWE-798",),                    # hardcoded-password-default
    "S108": ("CWE-377",),                    # hardcoded-temp-file
    "S110": ("CWE-703",),                    # try-except-pass
    "S112": ("CWE-703",),                    # try-except-continue
    "S113": ("CWE-400",),                    # request-without-timeout
    "S201": ("CWE-489",),                    # flask-debug-true
    "S202": ("CWE-22",),                     # tarfile-unsafe-members
    "S301": ("CWE-502",),                    # suspicious-pickle-usage
    "S302": ("CWE-502",),                    # suspicious-marshal-usage
    "S303": ("CWE-327", "CWE-916"),          # suspicious-insecure-hash-usage
    "S304": ("CWE-327",),                    # suspicious-insecure-cipher-usage
    "S305": ("CWE-327",),                    # suspicious-insecure-cipher-mode-usage
    "S306": ("CWE-377",),                    # suspicious-mktemp-usage
    "S307": ("CWE-94",),                     # suspicious-eval-usage
    "S308": ("CWE-79",),                     # suspicious-mark-safe-usage
    "S310": ("CWE-918",),                    # suspicious-url-open-usage
    "S311": ("CWE-330",),                    # suspicious-non-cryptographic-random-usage
    "S312": ("CWE-319",),                    # suspicious-telnet-usage
    "S313": ("CWE-611",),                    # suspicious-xmlc-element-tree-usage
    "S314": ("CWE-611",),                    # suspicious-xml-element-tree-usage
    "S315": ("CWE-611",),                    # suspicious-xml-expat-reader-usage
    "S316": ("CWE-611",),                    # suspicious-xml-expat-builder-usage
    "S317": ("CWE-611",),                    # suspicious-xml-sax-usage
    "S318": ("CWE-611",),                    # suspicious-xml-mini-dom-usage
    "S319": ("CWE-611",),                    # suspicious-xml-pull-dom-usage
    "S320": ("CWE-611",),                    # suspicious-xmle-tree-usage
    "S321": ("CWE-319",),                    # suspicious-ftp-lib-usage
    "S323": ("CWE-295",),                    # suspicious-unverified-context-usage
    "S324": ("CWE-327", "CWE-916"),          # hashlib-insecure-hash-function
    "S501": ("CWE-295",),                    # request-with-no-cert-validation
    "S502": ("CWE-327",),                    # ssl-insecure-version
    "S503": ("CWE-327",),                    # ssl-with-bad-defaults
    "S504": ("CWE-327",),                    # ssl-with-no-version
    "S505": ("CWE-327",),                    # weak-cryptographic-key
    "S506": ("CWE-502",),                    # unsafe-yaml-load
    "S507": ("CWE-295",),                    # ssh-no-host-key-verification
    "S508": ("CWE-327",),                    # snmp-insecure-version
    "S509": ("CWE-327",),                    # snmp-weak-cryptography
    "S601": ("CWE-78",),                     # paramiko-call
    "S602": ("CWE-78",),                     # subprocess-popen-with-shell-equals-true
    "S603": ("CWE-78",),                     # subprocess-without-shell-equals-true
    "S604": ("CWE-78",),                     # call-with-shell-equals-true
    "S605": ("CWE-78",),                     # start-process-with-a-shell
    "S606": ("CWE-78",),                     # start-process-with-no-shell
    "S607": ("CWE-78",),                     # start-process-with-partial-path
    "S608": ("CWE-89",),                     # hardcoded-sql-expression
    "S609": ("CWE-78",),                     # unix-command-wildcard-injection
    "S610": ("CWE-89",),                     # django-extra
    "S611": ("CWE-89",),                     # django-raw-sql
    "S612": ("CWE-532",),                    # logging-config-insecure-listen
    "S701": ("CWE-94",),                     # jinja2-autoescape-false
    "S702": ("CWE-94",),                     # mako-templates
}


@lru_cache(maxsize=1)
def ruff_binary() -> str | None:
    override = os.environ.get(RUFF_BIN_ENV, "").strip()
    if override:
        p = Path(override)
        if p.is_file() and os.access(p, os.X_OK):
            return str(p)
    return shutil.which("ruff")


def is_available() -> bool:
    return ruff_binary() is not None


def version() -> str | None:
    binary = ruff_binary()
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


def _parse_findings(stdout: str, path: str) -> tuple[RuffFinding, ...]:
    try:
        rows = json.loads(stdout) if stdout.strip() else []
    except json.JSONDecodeError:
        return ()
    if not isinstance(rows, list):
        return ()
    findings: list[RuffFinding] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        code = str(row.get("code") or "")
        if not code:
            continue
        msg = str(row.get("message") or "")
        loc = row.get("location") or {}
        end_loc = row.get("end_location") or {}
        start_line = int(loc.get("row", 0))
        end_line = int(end_loc.get("row", start_line))
        cwes = _RULE_CWE.get(code, ())
        # Ruff doesn't carry severity in findings; all `S` rules are
        # security-relevant so we map them to ERROR to trigger RALF's
        # escalation bump. Non-S rules (if caller enabled more) become
        # WARNING by default.
        sev = "ERROR" if code.startswith("S") else "WARNING"
        findings.append(RuffFinding(
            rule_id=code, severity=sev, message=msg[:200],
            start_line=start_line, end_line=end_line, path=path,
            cwe_ids=cwes,
        ))
    return tuple(findings)


def run_ruff(
    content: str,
    *,
    file_path: str | None = None,
    timeout_sec: float = DEFAULT_TIMEOUT_SEC,
    content_cap_bytes: int = MAX_CONTENT_BYTES,
) -> RuffRunResult:
    """Run ruff on the given Python content. Never raises."""
    binary = ruff_binary()
    if binary is None:
        return RuffRunResult(
            available=False, invoked=False, findings=(),
            elapsed_sec=0.0, timed_out=False,
        )
    if not content:
        return RuffRunResult(
            available=True, invoked=False, findings=(),
            elapsed_sec=0.0, timed_out=False,
        )
    if len(content.encode("utf-8", errors="replace")) > content_cap_bytes:
        return RuffRunResult(
            available=True, invoked=False, findings=(),
            elapsed_sec=0.0, timed_out=False,
            error="content_cap_exceeded",
        )

    import time
    suffix = ".py"
    if file_path:
        p = Path(file_path)
        if p.suffix in (".py", ".pyw", ".pyi"):
            suffix = p.suffix
    tmp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=suffix, delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        argv = [
            binary, "check",
            "--select=S",
            "--no-fix",
            "--output-format=json",
            "--exit-zero",              # never non-zero on findings
            "--quiet",
            tmp_path,
        ]
        start = time.monotonic()
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True,
                timeout=timeout_sec, check=False,
            )
            elapsed = time.monotonic() - start
        except subprocess.TimeoutExpired:
            return RuffRunResult(
                available=True, invoked=True, findings=(),
                elapsed_sec=time.monotonic() - start, timed_out=True,
                error="timeout",
            )

        findings = _parse_findings(proc.stdout, tmp_path)
        return RuffRunResult(
            available=True, invoked=True, findings=findings,
            elapsed_sec=elapsed, timed_out=False,
            error=None if proc.returncode == 0 else f"exit_{proc.returncode}",
        )
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


__all__ = [
    "RuffFinding", "RuffRunResult",
    "DEFAULT_TIMEOUT_SEC", "MAX_CONTENT_BYTES",
    "ruff_binary", "is_available", "version", "run_ruff",
]
