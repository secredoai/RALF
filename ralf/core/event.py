"""``CommonEvent`` — the canonical schema every adapter writes to the audit log.

This dataclass is the strict superset of the keys documented in
:mod:`ralf.shared.audit_log` (lines 9-19 of that module). Adapters
construct one of these per verdict and pass it to
:func:`ralf.core.audit.record`.

Schema is intentionally permissive — ``command`` may be empty for
file-write events; ``file_path`` may be empty for Bash events; ``ts``
is injected by the audit log if absent. The agent name is mandatory
because the dashboard's whole point is to attribute commands to the
right agent.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class CommonEvent:
    """One audit-log row.

    Attributes:
        agent: Source agent name. Free-form string but the dashboard
            expects ``"claude_code"``, ``"gemini_cli"``, ``"codex_cli"``.
        session_id: Per-session identifier. May be ``"unknown"`` if
            the agent doesn't expose one. The dashboard groups events
            by session in the History view.
        tool: Tool name as the agent reported it (``"Bash"``,
            ``"Write"``, ``"Edit"``, ``"NotebookEdit"``, etc.).
        command: Bash command, or empty for file-write events.
        file_path: Path being written/edited, or empty for Bash events.
        decision: Verdict — one of ``"allow"`` / ``"review"`` /
            ``"block"`` / ``"paused"`` (sentinel during pause mode).
        score: Numeric score from the verdict engine. ``-1`` if no
            scoring was performed (e.g., paused).
        reason: Human-readable explanation, suitable for dashboard
            display.
        rule_hits: List of rule IDs that fired. Empty for file-write
            events (the file scanner doesn't use rule IDs) and for
            Codex sync entries.
    """
    agent: str
    session_id: str
    tool: str
    command: str
    file_path: str
    decision: str
    score: int
    reason: str
    rule_hits: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        """Return the event as a plain dict for JSONL serialization."""
        return asdict(self)
