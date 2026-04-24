"""Gemini CLI BeforeTool adapter — stdin/stdout JSON.

Mirrors :mod:`ralf.adapters.claude_code` but for the Gemini CLI's
``BeforeTool`` hook surface.

Heads-up on uncertainty
-----------------------

The Gemini CLI's hook JSON shape is **not yet verified** against
Google's canonical ``github.com/google-gemini/gemini-cli`` repo. Per
the implementation plan, we accept the two most likely payload shapes:

1. **Claude-compatible** — ``{"tool_name": "run_shell", "tool_input": {...}}``
2. **Gemini-native**     — ``{"toolCall": {"name": "run_shell", "args": {...}}}``

If Google ships a third shape, the fix is one ``elif`` in
:func:`_extract_tool_call`.

Tool name map
-------------

We translate Gemini's tool names back to RALF's canonical tool keys
so the audit log keeps a stable schema across adapters:

    - ``run_shell``  → ``Bash``
    - ``write_file`` → ``Write``
    - ``replace``    → ``Edit``
    - ``edit``       → ``Edit`` (Gemini may use either)

Output shape
------------

We emit a Gemini-style decision::

    {"decision": "deny", "reason": "..."}

(The Claude-style ``hookSpecificOutput`` envelope is documented in the
Claude Code repo; this one is documented in the Gemini CLI repo if
they ever publish it.)
"""
from __future__ import annotations

import json
import sys
from typing import Any

from ralf.adapters import _base
from ralf.adapters._base import AdapterConfig

AGENT_NAME = "gemini_cli"


# Gemini → RALF tool name normalization. Lookups are case-insensitive
# at use time so we don't have to enumerate ``Run_Shell`` etc.
_TOOL_NAME_MAP: dict[str, str] = {
    "run_shell":  "Bash",
    "shell":      "Bash",
    "bash":       "Bash",
    "write_file": "Write",
    "write":      "Write",
    "replace":    "Edit",
    "edit":       "Edit",
}


def _deny(reason: str) -> None:
    """Emit a Gemini-style permissionDecision that blocks the tool call."""
    output = {
        "decision": "deny",
        "reason": reason,
    }
    print(json.dumps(output))


_CONFIG = AdapterConfig(
    agent=AGENT_NAME,
    session_id_env_keys=(
        "GEMINI_SESSION_ID",
        "GEMINI_CLI_SESSION",
        "GEMINI_PROJECT",
    ),
    deny=_deny,
)


def _read_payload() -> dict[str, Any]:
    try:
        return json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return {}


def _extract_tool_call(data: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Normalize the host JSON shape into ``(tool_name, args)``.

    Returns ``("", {})`` if no recognizable tool call is present.
    """
    # Shape 1: Claude-compatible.
    if "tool_name" in data:
        tool_input = data.get("tool_input") or {}
        return (
            str(data.get("tool_name", "")),
            tool_input if isinstance(tool_input, dict) else {},
        )

    # Shape 2: Gemini-native nested toolCall envelope.
    tc = data.get("toolCall") or data.get("tool_call")
    if isinstance(tc, dict):
        args = tc.get("args") or tc.get("arguments") or tc.get("input") or {}
        return (
            str(tc.get("name", "")),
            args if isinstance(args, dict) else {},
        )

    return "", {}


def _normalize_tool(name: str) -> str:
    """Map Gemini tool name → RALF canonical tool name. Empty if unknown."""
    return _TOOL_NAME_MAP.get((name or "").lower(), "")


def _handle_bash(args: dict[str, Any]) -> int:
    command = args.get("command", "")
    if not isinstance(command, str):
        return 0
    return _base.handle_bash(_CONFIG, command)


def _handle_write_like(tool_name: str, args: dict[str, Any]) -> int:
    """Score a Gemini Write/Replace/Edit invocation.

    Gemini's argument keys vary by tool:
        - ``write_file``: ``content`` + ``file_path``
        - ``replace``: ``new_string`` + ``file_path`` (Edit-equivalent)
    We accept both and let whichever is non-empty win.
    """
    content = (
        args.get("content", "")
        or args.get("new_string", "")
        or args.get("text", "")
    )
    file_path = (
        args.get("file_path", "")
        or args.get("path", "")
        or args.get("filename", "")
    )
    if not isinstance(content, str):
        return 0
    return _base.handle_file_write(
        _CONFIG,
        tool_name,
        content,
        file_path if isinstance(file_path, str) else "",
    )


def run() -> int:
    """Main hook entry point. Reads stdin JSON, dispatches by tool."""
    data = _read_payload()
    if not data:
        return 0

    raw_tool_name, args = _extract_tool_call(data)
    if not raw_tool_name:
        return 0

    canonical = _normalize_tool(raw_tool_name)
    if canonical == "Bash":
        return _handle_bash(args)
    if canonical in ("Write", "Edit"):
        return _handle_write_like(canonical, args)

    # Unknown / unmapped tool — fall through (no decision emitted, no audit).
    return 0


if __name__ == "__main__":
    sys.exit(run())
