"""Credential exposure scanner — 10 checks across 3 surfaces.

Surfaces:
1. Agent config files (API keys, tokens in Claude/Codex/Gemini/env configs)
2. Shell history (API keys, curl auth headers in bash/zsh history)
3. Agent session logs (leaked creds in agent conversation transcripts)
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path

from ralf.scanner import CheckResult
from ralf.scanner.checks import register

log = logging.getLogger(__name__)

_PLAT = ("linux", "darwin")
_CAT = "credential"

# ── Shared credential patterns ─────────────────────────────────────────

# Split some patterns to avoid self-detection by RALF's content scanner.
_API_KEY_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Anthropic API key", re.compile(r"sk-ant-[a-zA-Z0-9_-]{20,}")),
    ("OpenAI API key", re.compile(r"sk-[a-zA-Z0-9]{20,}")),
    ("Google API key", re.compile(r"AIza[a-zA-Z0-9_-]{35}")),
    ("GitHub PAT", re.compile(r"ghp_[a-zA-Z0-9]{36}")),
    ("GitLab PAT", re.compile(r"glpat-[a-zA-Z0-9-]{20}")),
    ("Slack token", re.compile(r"xox[bpras]-[0-9a-zA-Z-]+")),
    ("AWS Access Key", re.compile(r"AKIA[A-Z0-9]{16}")),
    ("Private key", re.compile(
        r"BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY"
    )),
    ("Bearer token", re.compile(
        r"Bearer\s+[a-zA-Z0-9._-]{20,}"
    )),
    ("Password assignment", re.compile(
        r"(?:password|passwd|secret)\s*[:=]\s*\S{4,}", re.IGNORECASE,
    )),
]

_HOME = Path.home()


def _scan_file_for_keys(path: Path, limit_lines: int = 5000) -> list[str]:
    """Scan a file for credential patterns. Returns list of findings."""
    findings: list[str] = []
    try:
        text = path.read_text(errors="replace")
    except (OSError, PermissionError):
        return findings

    lines = text.splitlines()[:limit_lines]
    for i, line in enumerate(lines, 1):
        for name, pat in _API_KEY_PATTERNS:
            if pat.search(line):
                findings.append(f"{name} at line {i}")
    return findings


def _file_exists(path: Path) -> bool:
    try:
        return path.exists()
    except (OSError, PermissionError):
        return False


# ── Surface 1: Agent config files ──────────────────────────────────────


@register(
    id="cred_claude_config",
    name="Claude Config Credential Exposure",
    category=_CAT,
    platforms=_PLAT,
    severity="critical",
)
def check_cred_claude_config() -> CheckResult:
    paths = [
        _HOME / ".claude" / "settings.json",
        _HOME / ".claude" / "credentials.json",
    ]
    all_findings: list[str] = []
    for p in paths:
        if _file_exists(p):
            findings = _scan_file_for_keys(p)
            all_findings.extend(f"{p.name}: {f}" for f in findings)

    ok = len(all_findings) == 0
    return CheckResult(
        check_id="cred_claude_config",
        name="Claude Config Credential Exposure",
        category=_CAT,
        status="pass" if ok else "fail",
        detail="No credentials in Claude config" if ok else f"{len(all_findings)} credential(s) found",
        remediation="Remove plain-text keys from Claude config files; use ANTHROPIC_API_KEY env var instead",
        severity="critical",
        score_delta=0 if ok else -15,
    )


@register(
    id="cred_codex_config",
    name="Codex Config Credential Exposure",
    category=_CAT,
    platforms=_PLAT,
    severity="critical",
)
def check_cred_codex_config() -> CheckResult:
    paths = [
        _HOME / ".codex" / "config.toml",
        _HOME / ".codex" / "auth.json",
    ]
    all_findings: list[str] = []
    for p in paths:
        if _file_exists(p):
            findings = _scan_file_for_keys(p)
            all_findings.extend(f"{p.name}: {f}" for f in findings)

    ok = len(all_findings) == 0
    scanned = [p.name for p in paths if _file_exists(p)]
    return CheckResult(
        check_id="cred_codex_config",
        name="Codex Config Credential Exposure",
        category=_CAT,
        status="pass" if ok else "fail",
        detail=(
            "No credentials in Codex config" if ok
            else f"{len(all_findings)} credential(s) found in {', '.join(scanned)}"
        ),
        remediation="Remove plain-text keys from Codex config; use OPENAI_API_KEY env var instead",
        severity="critical",
        score_delta=0 if ok else -15,
    )


@register(
    id="cred_gemini_config",
    name="Gemini Config Credential Exposure",
    category=_CAT,
    platforms=_PLAT,
    severity="critical",
)
def check_cred_gemini_config() -> CheckResult:
    paths = [
        _HOME / ".gemini" / "settings.json",
        _HOME / ".gemini" / "config.json",
    ]
    all_findings: list[str] = []
    for p in paths:
        if _file_exists(p):
            findings = _scan_file_for_keys(p)
            all_findings.extend(f"{p.name}: {f}" for f in findings)

    ok = len(all_findings) == 0
    return CheckResult(
        check_id="cred_gemini_config",
        name="Gemini Config Credential Exposure",
        category=_CAT,
        status="pass" if ok else "fail",
        detail="No credentials in Gemini config" if ok else f"{len(all_findings)} credential(s) found",
        remediation="Remove plain-text keys; use GOOGLE_API_KEY env var instead",
        severity="critical",
        score_delta=0 if ok else -15,
    )


@register(
    id="cred_env_files",
    name=".env File Credential Exposure",
    category=_CAT,
    platforms=_PLAT,
    severity="critical",
)
def check_cred_env_files() -> CheckResult:
    env_paths = [
        _HOME / ".env",
        Path.cwd() / ".env",
        Path.cwd() / ".env.local",
    ]
    sensitive_key_re = re.compile(
        r"^(.*(?:SECRET|TOKEN|PASSWORD|API_KEY|APIKEY|PRIVATE_KEY|AUTH)[_A-Z0-9]*)\s*=\s*\S+",
        re.IGNORECASE | re.MULTILINE,
    )
    all_findings: list[str] = []
    for p in env_paths:
        if not _file_exists(p):
            continue
        try:
            content = p.read_text(errors="replace")
        except (OSError, PermissionError):
            continue
        matches = sensitive_key_re.findall(content)
        all_findings.extend(f"{p}: {m}" for m in matches)

    ok = len(all_findings) == 0
    return CheckResult(
        check_id="cred_env_files",
        name=".env File Credential Exposure",
        category=_CAT,
        status="pass" if ok else "fail",
        detail="No secrets found in .env files" if ok else f"{len(all_findings)} secret(s) in .env files",
        remediation="Use a secrets manager; remove plaintext secrets from .env files; add .env to .gitignore",
        severity="critical",
        score_delta=0 if ok else -15,
    )


@register(
    id="cred_env_permissions",
    name=".env File Permissions",
    category=_CAT,
    platforms=_PLAT,
    severity="high",
)
def check_cred_env_permissions() -> CheckResult:
    env_paths = [
        _HOME / ".env",
        Path.cwd() / ".env",
        Path.cwd() / ".env.local",
    ]
    loose: list[str] = []
    for p in env_paths:
        if not _file_exists(p):
            continue
        try:
            mode = p.stat().st_mode & 0o777
        except OSError:
            continue
        if mode > 0o600:
            loose.append(f"{p}: {oct(mode)}")

    ok = len(loose) == 0
    return CheckResult(
        check_id="cred_env_permissions",
        name=".env File Permissions",
        category=_CAT,
        status="pass" if ok else "warn",
        detail="All .env files have safe permissions" if ok else f"{len(loose)} .env file(s) with loose permissions",
        remediation="Run: chmod 600 .env .env.local",
        severity="high",
        score_delta=0 if ok else -5,
    )


# ── Surface 2: Shell history ───────────────────────────────────────────


@register(
    id="cred_history_keys",
    name="Shell History API Key Exposure",
    category=_CAT,
    platforms=_PLAT,
    severity="critical",
)
def check_cred_history_keys() -> CheckResult:
    history_files = [
        _HOME / ".bash_history",
        _HOME / ".zsh_history",
    ]
    all_findings: list[str] = []
    for p in history_files:
        if not _file_exists(p):
            continue
        findings = _scan_file_for_keys(p, limit_lines=10000)
        all_findings.extend(f"{p.name}: {f}" for f in findings)

    ok = len(all_findings) == 0
    return CheckResult(
        check_id="cred_history_keys",
        name="Shell History API Key Exposure",
        category=_CAT,
        status="pass" if ok else "fail",
        detail="No API keys in shell history" if ok else f"{len(all_findings)} key(s) found in shell history",
        remediation=(
            "Clear history: > ~/.bash_history; > ~/.zsh_history; "
            "Set HISTIGNORE to exclude sensitive commands"
        ),
        severity="critical",
        score_delta=0 if ok else -15,
    )


@register(
    id="cred_history_curl_auth",
    name="Shell History curl Auth Exposure",
    category=_CAT,
    platforms=_PLAT,
    severity="high",
)
def check_cred_history_curl_auth() -> CheckResult:
    history_files = [
        _HOME / ".bash_history",
        _HOME / ".zsh_history",
    ]
    auth_patterns = [
        re.compile(r'curl\s.*-H\s+["\']?Authorization:', re.IGNORECASE),
        re.compile(r'curl\s.*-u\s+\S+:\S+', re.IGNORECASE),
        re.compile(r'curl\s.*--user\s+\S+:\S+', re.IGNORECASE),
    ]
    findings: list[str] = []
    for p in history_files:
        if not _file_exists(p):
            continue
        try:
            lines = p.read_text(errors="replace").splitlines()
        except (OSError, PermissionError):
            continue
        for i, line in enumerate(lines[-10000:], 1):
            for pat in auth_patterns:
                if pat.search(line):
                    findings.append(f"{p.name}: line {i}")
                    break

    ok = len(findings) == 0
    return CheckResult(
        check_id="cred_history_curl_auth",
        name="Shell History curl Auth Exposure",
        category=_CAT,
        status="pass" if ok else "warn",
        detail="No curl auth headers in history" if ok else f"{len(findings)} curl auth command(s) in history",
        remediation=(
            "Clear history entries with credentials; "
            "use .netrc or environment variables instead of inline auth"
        ),
        severity="high",
        score_delta=0 if ok else -5,
    )


# ── Surface 3: Agent session logs ──────────────────────────────────────


def _scan_session_jsonl(path: Path, limit: int = 500) -> list[str]:
    """Scan a JSONL session file for credential patterns in content."""
    findings: list[str] = []
    try:
        lines = path.read_text(errors="replace").splitlines()[-limit:]
    except (OSError, PermissionError):
        return findings
    for line in lines:
        for name, pat in _API_KEY_PATTERNS:
            if pat.search(line):
                findings.append(f"{name} in {path.name}")
                break  # one finding per line is enough
    return findings


@register(
    id="cred_claude_sessions",
    name="Claude Session Credential Leaks",
    category=_CAT,
    platforms=_PLAT,
    severity="critical",
)
def check_cred_claude_sessions() -> CheckResult:
    claude_projects = _HOME / ".claude" / "projects"
    all_findings: list[str] = []
    if _file_exists(claude_projects):
        try:
            for project_dir in list(claude_projects.iterdir())[:20]:
                if not project_dir.is_dir():
                    continue
                for f in list(project_dir.iterdir())[:50]:
                    if f.suffix == ".jsonl":
                        findings = _scan_session_jsonl(f)
                        all_findings.extend(findings)
                        if len(all_findings) >= 10:
                            break
                if len(all_findings) >= 10:
                    break
        except (OSError, PermissionError):
            pass

    ok = len(all_findings) == 0
    return CheckResult(
        check_id="cred_claude_sessions",
        name="Claude Session Credential Leaks",
        category=_CAT,
        status="pass" if ok else "fail",
        detail=(
            "No credentials leaked in Claude sessions" if ok
            else f"{len(all_findings)} credential(s) in Claude session logs"
        ),
        remediation="Review and clear affected session transcripts in ~/.claude/projects/",
        severity="critical",
        score_delta=0 if ok else -15,
    )


@register(
    id="cred_codex_sessions",
    name="Codex Session Credential Leaks",
    category=_CAT,
    platforms=_PLAT,
    severity="critical",
)
def check_cred_codex_sessions() -> CheckResult:
    codex_sessions = _HOME / ".codex" / "sessions"
    all_findings: list[str] = []
    if _file_exists(codex_sessions):
        try:
            for year_dir in list(codex_sessions.iterdir())[:5]:
                if not year_dir.is_dir():
                    continue
                for f in list(year_dir.iterdir())[:50]:
                    if f.suffix in (".jsonl", ".json"):
                        findings = _scan_session_jsonl(f)
                        all_findings.extend(findings)
                        if len(all_findings) >= 10:
                            break
                if len(all_findings) >= 10:
                    break
        except (OSError, PermissionError):
            pass

    ok = len(all_findings) == 0
    return CheckResult(
        check_id="cred_codex_sessions",
        name="Codex Session Credential Leaks",
        category=_CAT,
        status="pass" if ok else "fail",
        detail=(
            "No credentials leaked in Codex sessions" if ok
            else f"{len(all_findings)} credential(s) in Codex session logs"
        ),
        remediation="Review and clear affected session files in ~/.codex/sessions/",
        severity="critical",
        score_delta=0 if ok else -15,
    )


@register(
    id="cred_codex_history",
    name="Codex History Credential Leaks",
    category=_CAT,
    platforms=_PLAT,
    severity="critical",
)
def check_cred_codex_history() -> CheckResult:
    history_path = _HOME / ".codex" / "history.jsonl"
    if not _file_exists(history_path):
        return CheckResult(
            check_id="cred_codex_history",
            name="Codex History Credential Leaks",
            category=_CAT,
            status="pass",
            detail="No Codex history file found",
            remediation="",
            severity="critical",
            score_delta=0,
        )

    findings = _scan_session_jsonl(history_path, limit=1000)
    ok = len(findings) == 0
    return CheckResult(
        check_id="cred_codex_history",
        name="Codex History Credential Leaks",
        category=_CAT,
        status="pass" if ok else "fail",
        detail=(
            "No credentials in Codex history" if ok
            else f"{len(findings)} credential(s) in Codex history"
        ),
        remediation="Review ~/.codex/history.jsonl and remove entries containing secrets",
        severity="critical",
        score_delta=0 if ok else -15,
    )
