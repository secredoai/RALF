"""Resolve the current session identifier for hook invocations.

The hook subprocess is spawned fresh on each tool call; there's no
persistent Python state. To tie Bash commands to earlier content
fetches, we need a stable per-session key. Claude Code sets one of
several env vars; Codex / Gemini set others.

Resolution order:

    1. ``RALF_SESSION_ID``          — explicit override
    2. ``CLAUDE_SESSION_ID``        — Claude Code
    3. ``CLAUDE_CODE_SESSION_ID``   — Claude Code (older name)
    4. ``CODEX_SESSION_ID``         — Codex CLI
    5. ``GEMINI_SESSION_ID``        — Gemini CLI
    6. ``CLAUDE_PROJECT_DIR`` hash  — fallback when no explicit ID
    7. per-PPID fallback            — last resort

If none of these resolve, we return an empty string; callers must treat
empty-session as "no provenance available" and fall back to stateless
scoring.
"""

from __future__ import annotations

import hashlib
import os


_SESSION_ENV_KEYS = (
    "RALF_SESSION_ID",
    "CLAUDE_SESSION_ID",
    "CLAUDE_CODE_SESSION_ID",
    "CODEX_SESSION_ID",
    "GEMINI_SESSION_ID",
)


def get_session_id() -> str:
    """Return a stable session ID for the current hook invocation, or ''."""
    for key in _SESSION_ENV_KEYS:
        v = os.environ.get(key)
        if v:
            return v[:128]
    # Fallback: derive from CLAUDE_PROJECT_DIR if present
    project = os.environ.get("CLAUDE_PROJECT_DIR")
    if project:
        return "proj-" + hashlib.sha256(project.encode()).hexdigest()[:16]
    # Last resort: PPID (the invoking process). Same parent → same session
    # within a single agent instance. Good enough for short-lived flows.
    try:
        ppid = os.getppid()
        return f"ppid-{ppid}"
    except OSError:
        return ""


def get_agent_id() -> str:
    """Return the agent identifier ("claude_code", "codex", "gemini", ...)."""
    v = os.environ.get("RALF_AGENT_ID")
    if v:
        return v
    if os.environ.get("CLAUDE_SESSION_ID") or os.environ.get("CLAUDE_CODE_SESSION_ID"):
        return "claude_code"
    if os.environ.get("CODEX_SESSION_ID"):
        return "codex"
    if os.environ.get("GEMINI_SESSION_ID"):
        return "gemini"
    return "unknown"
