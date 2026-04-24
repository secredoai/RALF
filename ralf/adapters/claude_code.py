"""Claude Code PreToolUse adapter — stdin/stdout JSON.

Reads Claude Code PreToolUse payloads from stdin, dispatches by tool,
writes a JSON permissionDecision to stdout, and records every verdict
to the audit log with ``agent="claude_code"``.

Supported tools: ``Bash``, ``Write``, ``Edit``, ``NotebookEdit``.

Heavy lifting (scoring, audit, pause sentinel, deobfuscator) lives in
:mod:`ralf.adapters._base`. This file is the host-specific veneer:
parsing the Claude Code JSON shape on stdin and emitting the Claude
Code permission-decision JSON on stdout.

Pause sentinel: if ``$XDG_CACHE_HOME/ralf-free/paused`` exists, every
verdict short-circuits to ``decision="paused"`` (allow + audit) with
NO scoring. Used by ``ralf-free pause`` / ``ralf-free resume``.
"""
from __future__ import annotations

import json
import sys
from typing import Any

from ralf.adapters import _base
from ralf.adapters._base import AdapterConfig

AGENT_NAME = "claude_code"


def _deny(reason: str) -> None:
    """Emit a JSON permissionDecision that blocks the tool call."""
    output = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }
    print(json.dumps(output))


def _warn(reason: str) -> None:
    """Emit a REVIEW warning via stderr AND additionalContext."""
    print(
        f"\033[33mRALF REVIEW\033[0m: {reason}  "
        f"[Check dashboard: http://127.0.0.1:7433]",
        file=sys.stderr,
    )


_CONFIG = AdapterConfig(
    agent=AGENT_NAME,
    session_id_env_keys=(
        "CLAUDE_SESSION_ID",
        "CLAUDE_CODE_SESSION_ID",
        "CLAUDE_PROJECT_DIR",
    ),
    deny=_deny,
    emit_warn=_warn,
)


def _read_payload() -> dict[str, Any]:
    try:
        return json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return {}


# ---------------------------------------------------------------------
# Handler entry points for tests and direct invocation
# ---------------------------------------------------------------------


def _handle_bash(tool_input: dict[str, Any]) -> int:
    command = tool_input.get("command", "")
    return _base.handle_bash(_CONFIG, command if isinstance(command, str) else "")


def _handle_write_like(
    tool_name: str,
    tool_input: dict[str, Any],
    *,
    content_key: str = "content",
    path_key: str = "file_path",
) -> int:
    content = tool_input.get(content_key, "") or tool_input.get("new_string", "")
    file_path = tool_input.get(path_key, "") or tool_input.get("notebook_path", "")
    return _base.handle_file_write(
        _CONFIG,
        tool_name,
        content if isinstance(content, str) else "",
        file_path if isinstance(file_path, str) else "",
    )


def run() -> int:
    """Main hook entry point. Reads stdin JSON, dispatches by tool."""
    data = _read_payload()
    if not data:
        return 0

    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})
    if not isinstance(tool_input, dict):
        return 0

    if tool_name == "Bash":
        return _handle_bash(tool_input)
    if tool_name in ("Write", "Edit"):
        return _handle_write_like(tool_name, tool_input)
    if tool_name == "NotebookEdit":
        return _handle_write_like(
            tool_name, tool_input,
            content_key="new_source", path_key="notebook_path",
        )
    # Causal-security extensions: lightweight audit/pre-checks for
    # content-fetch tools. Real injection scanning on responses happens
    # in the PostToolUse adapter (ralf.adapters.claude_code_posttooluse).
    if tool_name == "Read":
        file_path = tool_input.get("file_path", "")
        return _base.handle_read_input(
            _CONFIG, file_path if isinstance(file_path, str) else "",
        )
    if tool_name == "WebFetch":
        url = tool_input.get("url", "")
        prompt = tool_input.get("prompt", "")
        return _base.handle_webfetch_input(
            _CONFIG,
            url if isinstance(url, str) else "",
            prompt if isinstance(prompt, str) else "",
        )
    if tool_name.startswith("mcp__"):
        return _base.handle_mcp_input(_CONFIG, tool_name, tool_input)

    return 0


if __name__ == "__main__":
    sys.exit(run())
