"""Codex CLI PreToolUse adapter.

Codex uses the same PreToolUse wire format as Claude Code but with
different tool names: ``shell`` (not ``Bash``), ``write``, ``patch``.
This adapter maps those names and tags audit events as ``codex_cli``.
"""
from __future__ import annotations

import json
import sys
from typing import Any

from ralf.adapters import _base
from ralf.adapters._base import AdapterConfig

AGENT_NAME = "codex_cli"

_TOOL_MAP = {
    "shell": "Bash",
    "write": "Write",
    "patch": "Edit",
}


def _deny(reason: str) -> None:
    output = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }
    print(json.dumps(output))


def _warn(reason: str) -> None:
    print(
        f"\033[33mRALF REVIEW\033[0m: {reason}  "
        f"[Check dashboard: http://127.0.0.1:7433]",
        file=sys.stderr,
    )


_CONFIG = AdapterConfig(
    agent=AGENT_NAME,
    session_id_env_keys=(
        "CODEX_SESSION_ID",
        "CODEX_CONVERSATION_ID",
    ),
    deny=_deny,
    emit_warn=_warn,
)


def run() -> int:
    try:
        data = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return 0
    if not data or not isinstance(data, dict):
        return 0

    raw_tool = data.get("tool_name", "")
    tool_name = _TOOL_MAP.get(raw_tool, raw_tool)
    tool_input = data.get("tool_input", {})
    if not isinstance(tool_input, dict):
        return 0

    if tool_name == "Bash":
        command = tool_input.get("command", "")
        return _base.handle_bash(_CONFIG, command if isinstance(command, str) else "")

    if tool_name in ("Write", "Edit"):
        content = tool_input.get("content", "") or tool_input.get("new_string", "")
        file_path = tool_input.get("file_path", "") or tool_input.get("path", "")
        return _base.handle_file_write(
            _CONFIG, tool_name,
            content if isinstance(content, str) else "",
            file_path if isinstance(file_path, str) else "",
        )

    return 0


if __name__ == "__main__":
    sys.exit(run())
