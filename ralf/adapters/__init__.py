"""Per-agent PreToolUse adapters.

Each module in this package converts an agent's PreToolUse payload
shape into a :class:`ralf.core.event.CommonEvent`, scores it via
:mod:`ralf.shared.verdict_engine`, and emits both an audit-log entry
and an agent-specific permission decision on stdout.

Currently supported agents:

    - ``claude_code`` — Claude Code's PreToolUse JSON-on-stdin
      protocol. The canonical adapter.
    - ``gemini_cli`` — Gemini CLI's BeforeTool hook (same JSON
      shape with a tool name remap).
    - ``codex_cli`` — Codex's rule file watcher (one-shot import +
      mtime poll loop). NOT a stdin/stdout adapter; lives here for
      organizational consistency.
"""
