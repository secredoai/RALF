"""Claude Code PostToolUse adapter — content ingress scanner.

Fires AFTER Claude Code has run a tool. Receives the tool's response
alongside its input. For content-fetching tools (Read, WebFetch,
mcp__*), we scan the response for prompt-injection patterns, record
it to the provenance ledger (for later taint checks on Bash commands),
and optionally emit a warning (``additionalContext``) that Claude can
read when it processes the tool output.

For MCP tools with CRITICAL-severity injection, we can rewrite the
output via ``updatedMCPToolOutput`` — Claude Code supports this only
for MCP tools, not for built-ins.

Contract (Claude Code PostToolUse JSON):
    input:
        {
            "session_id": "...",
            "transcript_path": "...",
            "cwd": "...",
            "hook_event_name": "PostToolUse",
            "tool_name": "WebFetch",
            "tool_input": {"url": "..."},
            "tool_response": {...}    // varies by tool
        }
    output (non-blocking warnings):
        {
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "additionalContext": "...",
                "updatedMCPToolOutput": "..."   // MCP-only, optional
            }
        }

Pause sentinel is honored — if RALF is paused, the adapter is a no-op.
"""

from __future__ import annotations

import json
import sys
from typing import Any

from ralf.adapters import _base
from ralf.adapters._base import AdapterConfig

AGENT_NAME = "claude_code"


# ── Output emitters ──────────────────────────────────────────────────────────

# PostToolUse outputs are accumulated across the invocation so we emit
# one combined JSON at the end (Claude Code expects a single JSON doc).
_pending_output: dict[str, Any] = {}


def _emit_warn(message: str) -> None:
    """Stage an ``additionalContext`` warning for the model."""
    ctx = _pending_output.setdefault("hookSpecificOutput", {
        "hookEventName": "PostToolUse",
    })
    # If multiple warnings fire, join them.
    existing = ctx.get("additionalContext", "")
    ctx["additionalContext"] = (
        existing + ("\n" if existing else "") + message
    )


def _emit_mcp_rewrite(safe_content: str) -> None:
    """Stage a rewrite of the MCP tool output."""
    ctx = _pending_output.setdefault("hookSpecificOutput", {
        "hookEventName": "PostToolUse",
    })
    ctx["updatedMCPToolOutput"] = safe_content


def _flush_output() -> None:
    """Print the accumulated output as a single JSON doc."""
    if _pending_output:
        print(json.dumps(_pending_output))


def _deny(reason: str) -> None:
    """PostToolUse can't deny (tool already ran) — emit a block-style decision.

    This is a no-op path for PostToolUse; kept so the AdapterConfig signature
    matches the PreToolUse adapter. If we ever need to tell Claude the
    output is forbidden, we'd use ``{"decision": "block", "reason": ...}``.
    """
    out = {
        "decision": "block",
        "reason": reason,
        "hookSpecificOutput": _pending_output.get("hookSpecificOutput", {
            "hookEventName": "PostToolUse",
            "additionalContext": reason,
        }),
    }
    print(json.dumps(out))


_CONFIG = AdapterConfig(
    agent=AGENT_NAME,
    session_id_env_keys=(
        "CLAUDE_SESSION_ID",
        "CLAUDE_CODE_SESSION_ID",
        "CLAUDE_PROJECT_DIR",
    ),
    deny=_deny,
    emit_warn=_emit_warn,
    emit_mcp_rewrite=_emit_mcp_rewrite,
)


def _read_payload() -> dict[str, Any]:
    try:
        return json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return {}


def run() -> int:
    """Main PostToolUse entry point. Reads stdin JSON, records + scans."""
    data = _read_payload()
    if not data:
        return 0

    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})
    tool_response = data.get("tool_response")
    if not isinstance(tool_input, dict):
        tool_input = {}

    # Only scan content-fetching tools. Bash/Write/Edit/NotebookEdit don't
    # need post-hook scanning because their payloads are pre-checked by the
    # PreToolUse adapter.
    if tool_name not in ("Read", "WebFetch") and not tool_name.startswith("mcp__"):
        return 0

    _base.handle_tool_result(_CONFIG, tool_name, tool_input, tool_response)
    _flush_output()
    return 0


if __name__ == "__main__":
    sys.exit(run())
