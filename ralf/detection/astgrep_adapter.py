"""ast-grep adapter — multi-language fast SAST via tree-sitter.

ast-grep (Rust, single binary) matches AST patterns across Python / JS / TS /
Rust / Go / Java / C++ / PHP / Ruby. ~50-200 ms cold-start. Accepts a
user-supplied rule YAML via ``--rule`` or a config directory via
``--config``.

This adapter ships without a bundled rule library (community rules vary
per language and evolve fast). When the user has an ast-grep config in
their project (``sgconfig.yml``) the adapter picks it up automatically.
Otherwise it still reports ``available=True`` but returns zero findings
on a bare scan — consistent with the "graceful no-op when not configured"
design of the other SAST adapters.
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
ASTGREP_BIN_ENV = "RALF_ASTGREP_BIN"

# Extension -> ast-grep language flag (subset of the 20+ ast-grep supports)
_EXT_TO_LANG: dict[str, str] = {
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "tsx",
    ".rb": "ruby",
    ".go": "go",
    ".php": "php",
    ".java": "java",
    ".rs": "rust",
    ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cxx": "cpp", ".cc": "cpp", ".hpp": "cpp",
    ".cs": "csharp",
    ".kt": "kotlin", ".kts": "kotlin",
    ".swift": "swift",
    ".scala": "scala",
    ".sh": "bash", ".bash": "bash",
}


@dataclass(frozen=True)
class AstGrepFinding:
    rule_id: str
    severity: str              # "error" | "warning" | "info" | "hint" (ast-grep)
    message: str
    start_line: int
    end_line: int
    path: str
    cwe_ids: tuple[str, ...]

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
class AstGrepRunResult:
    available: bool
    invoked: bool
    findings: tuple[AstGrepFinding, ...]
    elapsed_sec: float
    timed_out: bool
    error: str | None = None


@lru_cache(maxsize=1)
def astgrep_binary() -> str | None:
    """ast-grep ships two command names: ``ast-grep`` and the shorter ``sg``."""
    override = os.environ.get(ASTGREP_BIN_ENV, "").strip()
    if override:
        p = Path(override)
        if p.is_file() and os.access(p, os.X_OK):
            return str(p)
    for name in ("ast-grep", "sg"):
        hit = shutil.which(name)
        if hit:
            return hit
    return None


def is_available() -> bool:
    return astgrep_binary() is not None


def version() -> str | None:
    binary = astgrep_binary()
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


def language_for_extension(ext: str) -> str | None:
    return _EXT_TO_LANG.get(ext.lower())


def _parse_findings(stdout: str, path: str) -> tuple[AstGrepFinding, ...]:
    """ast-grep ``--json=stream`` emits one JSON object per line;
    ``--json=compact`` emits a JSON array. We accept either.
    """
    findings: list[AstGrepFinding] = []

    def _parse_row(obj: dict) -> None:
        rule_id = str(obj.get("ruleId") or obj.get("rule_id") or "")
        if not rule_id:
            return
        severity = str(obj.get("severity") or "info").lower()
        # ast-grep doesn't standardize CWE tags in its output; they appear
        # in rule metadata when the rule author sets them. We extract from
        # `metadata.cwe` if present.
        cwe_ids: list[str] = []
        metadata = obj.get("metadata") or {}
        raw = metadata.get("cwe") or []
        if isinstance(raw, (list, tuple)):
            for c in raw:
                s = str(c).strip()
                if s.startswith("CWE-"):
                    cwe_ids.append(s)
                elif s.isdigit():
                    cwe_ids.append(f"CWE-{s}")
        elif isinstance(raw, str) and raw:
            s = raw.strip()
            cwe_ids.append(s if s.startswith("CWE-") else f"CWE-{s}")

        rng = obj.get("range") or {}
        start = rng.get("byteOffset") or {}
        end = rng.get("end") or {}
        start_line = int(start.get("line", 0)) + 1 if isinstance(start, dict) else 0
        end_line = int(end.get("line", start_line - 1)) + 1 if isinstance(end, dict) else start_line
        msg = str(obj.get("message") or "")

        findings.append(AstGrepFinding(
            rule_id=rule_id, severity=severity, message=msg[:200],
            start_line=start_line, end_line=end_line, path=path,
            cwe_ids=tuple(cwe_ids),
        ))

    text = stdout.strip()
    if not text:
        return ()
    # Try compact JSON array first
    if text.startswith("["):
        try:
            arr = json.loads(text)
            for obj in arr:
                if isinstance(obj, dict):
                    _parse_row(obj)
            return tuple(findings)
        except json.JSONDecodeError:
            pass
    # Fall back to line-delimited JSON
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            _parse_row(obj)
    return tuple(findings)


def run_astgrep(
    content: str,
    *,
    file_path: str | None = None,
    timeout_sec: float = DEFAULT_TIMEOUT_SEC,
    content_cap_bytes: int = MAX_CONTENT_BYTES,
    config: str | None = None,
) -> AstGrepRunResult:
    """Run ast-grep against the content.

    ``config`` is an optional path to an ast-grep ``sgconfig.yml``. When
    omitted, ast-grep scans with no rules loaded and returns zero findings
    — matches the "graceful no-op when not configured" design.
    """
    binary = astgrep_binary()
    if binary is None:
        return AstGrepRunResult(
            available=False, invoked=False, findings=(),
            elapsed_sec=0.0, timed_out=False,
        )
    if not content:
        return AstGrepRunResult(
            available=True, invoked=False, findings=(),
            elapsed_sec=0.0, timed_out=False,
        )
    if len(content.encode("utf-8", errors="replace")) > content_cap_bytes:
        return AstGrepRunResult(
            available=True, invoked=False, findings=(),
            elapsed_sec=0.0, timed_out=False,
            error="content_cap_exceeded",
        )

    suffix = Path(file_path).suffix if file_path else ".txt"
    if not language_for_extension(suffix):
        return AstGrepRunResult(
            available=True, invoked=False, findings=(),
            elapsed_sec=0.0, timed_out=False,
            error="unsupported_extension",
        )

    import time
    tmp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=suffix, delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        argv: list[str] = [binary, "scan", "--json=compact"]
        if config:
            argv.extend(("--config", config))
        argv.append(tmp_path)

        start = time.monotonic()
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True,
                timeout=timeout_sec, check=False,
            )
            elapsed = time.monotonic() - start
        except subprocess.TimeoutExpired:
            return AstGrepRunResult(
                available=True, invoked=True, findings=(),
                elapsed_sec=time.monotonic() - start, timed_out=True,
                error="timeout",
            )

        findings = _parse_findings(proc.stdout, tmp_path)
        err = None if proc.returncode in (0, 1) else f"exit_{proc.returncode}"
        return AstGrepRunResult(
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
    "AstGrepFinding", "AstGrepRunResult",
    "DEFAULT_TIMEOUT_SEC", "MAX_CONTENT_BYTES",
    "astgrep_binary", "is_available", "version",
    "language_for_extension", "run_astgrep",
]
