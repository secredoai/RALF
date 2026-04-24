"""Content provenance tracking.

This package implements the causal layer between what an agent READS and
what it DOES. Every piece of content that enters the model's context
(Read, WebFetch, MCP tool output) gets logged with a trust level, a hash,
and an excerpt. Subsequent tool calls can then be checked against that
history — if a Bash command contains data that came from an untrusted
source, the command is tainted.

Architecture:

- :class:`TrustLevel` enum with 6 levels from USER (most trusted) down
  through WORKSPACE / FETCHED / MCP_RESPONSE / TOOL_OUTPUT / GENERATED.
- :class:`ContentEvent` — one record in the ledger, includes the normalized
  excerpt (redacted), SHA-256, source, timestamp, and any injection hits
  the scanner produced at ingress time.
- :class:`~ralf.provenance.ledger.ProvenanceLedger` — per-session ring
  buffer; 20 events max, 30-minute TTL, file-backed with atomic writes.
- :func:`~ralf.provenance.taint.detect_taint` — match command arguments
  against recent untrusted content.

Every ingestion path strips credentials BEFORE the excerpt touches disk.
The redaction layer is in :mod:`ralf.provenance.redaction`.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class TrustLevel(str, Enum):
    """Trust label for a piece of content.

    Ordered from most trusted (user-typed) to least trusted (model
    self-generated output being fed back in). Scoring rules use the
    ordering to decide how aggressively to taint downstream actions.
    """
    USER = "user"                     # user typed it in a prompt
    WORKSPACE = "workspace"           # file in project cwd (user owns it)
    TOOL_OUTPUT = "tool_output"       # output of a local tool (Bash, etc.)
    GENERATED = "generated"           # the model's own output
    FETCHED = "fetched"               # WebFetch / external HTTP response
    MCP_RESPONSE = "mcp_response"     # from an MCP server call


# TrustLevel → numeric rank. Higher = less trusted = more aggressive scoring.
_TRUST_RANK: dict[TrustLevel, int] = {
    TrustLevel.USER: 0,
    TrustLevel.WORKSPACE: 1,
    TrustLevel.TOOL_OUTPUT: 2,
    TrustLevel.GENERATED: 3,
    TrustLevel.FETCHED: 5,
    TrustLevel.MCP_RESPONSE: 6,
}


def trust_rank(level: TrustLevel) -> int:
    return _TRUST_RANK.get(level, 0)


def is_untrusted(level: TrustLevel) -> bool:
    """True if content from this level should be treated as adversarial."""
    return _TRUST_RANK.get(level, 0) >= _TRUST_RANK[TrustLevel.FETCHED]


@dataclass
class ContentEvent:
    """A single content-ingestion event.

    Stored in the :class:`~ralf.provenance.ledger.ProvenanceLedger`. The
    ``content_hash`` is the SHA-256 over the (already-redacted) content;
    the ``excerpt`` is a redacted first-2KB snippet for display and taint
    matching. The ``full_redacted`` content is kept up to 16KB for taint
    matching only (never displayed).
    """
    trust: TrustLevel
    source: str              # URL, file path, tool name
    timestamp: float
    content_hash: str        # SHA-256 hex of redacted content
    excerpt: str             # first 2KB of redacted content (for display)
    full_redacted: str = ""  # up to 16KB of redacted content (for taint match)
    size_bytes: int = 0      # size of ORIGINAL content (pre-redaction)
    injection_score: int = 0
    injection_hits: tuple[str, ...] = field(default_factory=tuple)
    session_id: str = ""

    def to_dict(self, include_full: bool = False) -> dict[str, Any]:
        d = {
            "trust": self.trust.value,
            "source": self.source,
            "timestamp": self.timestamp,
            "content_hash": self.content_hash,
            "excerpt": self.excerpt,
            "size_bytes": self.size_bytes,
            "injection_score": self.injection_score,
            "injection_hits": list(self.injection_hits),
            "session_id": self.session_id,
        }
        if include_full:
            d["full_redacted"] = self.full_redacted
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ContentEvent:
        try:
            trust = TrustLevel(data.get("trust", "fetched"))
        except ValueError:
            trust = TrustLevel.FETCHED
        return cls(
            trust=trust,
            source=data.get("source", ""),
            timestamp=float(data.get("timestamp", 0.0)),
            content_hash=data.get("content_hash", ""),
            excerpt=data.get("excerpt", ""),
            full_redacted=data.get("full_redacted", ""),
            size_bytes=int(data.get("size_bytes", 0)),
            injection_score=int(data.get("injection_score", 0)),
            injection_hits=tuple(data.get("injection_hits", ())),
            session_id=data.get("session_id", ""),
        )


def compute_hash(content: str) -> str:
    """Return hex SHA-256 of UTF-8-encoded content."""
    return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()


# Excerpt / storage size limits (in characters — approx bytes for ASCII).
EXCERPT_LIMIT = 2 * 1024          # 2 KB stored as display excerpt
FULL_REDACTED_LIMIT = 16 * 1024   # 16 KB stored for taint matching


def make_excerpt(content: str) -> str:
    """Clip content to the display excerpt limit."""
    if len(content) <= EXCERPT_LIMIT:
        return content
    return content[:EXCERPT_LIMIT]


def make_full_redacted(content: str) -> str:
    """Clip content to the taint-match limit."""
    if len(content) <= FULL_REDACTED_LIMIT:
        return content
    return content[:FULL_REDACTED_LIMIT]
