"""Prompt injection pattern detection library.

Covers 12 attack families documented in the 2024-2026 landscape:

  1. Instruction override  — "ignore previous instructions"
  2. Persona hijack        — DAN / "you are now" / fake-authority
  3. Prompt leak           — "repeat verbatim", "first 100 words of your prompt"
  4. Document smuggling    — HTML comments, <IMPORTANT> tags, CSS hiding
  5. Unicode smuggling     — tag block U+E0000-E007F, zero-width, bidi overrides
  6. Homoglyph             — Cyrillic/Greek letter substitution
  7. Encoded payload       — base64/hex that decodes to any other family
  8. Exfiltration          — markdown-image exfil, webhook POST, DNS tunnel
  9. MCP tool poisoning    — <IMPORTANT> in tool descriptions, sidenote params
 10. Context stuffing      — few-shot poisoning, dilution
 11. Adversarial suffix    — GCG-style random-token tails
 12. Multilingual          — "忽略前の", "игнорируй предыдущ"

Detection pipeline lives in :mod:`ralf.injection.scanner`. Patterns live
in :mod:`ralf.injection.patterns`. Unicode normalization lives in
:mod:`ralf.injection.unicode_smuggle`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Injection finding severity."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Family(str, Enum):
    """Attack family — 10 documented classes."""
    INSTRUCTION_OVERRIDE = "instruction_override"
    PERSONA_HIJACK = "persona_hijack"
    PROMPT_LEAK = "prompt_leak"
    DOC_SMUGGLING = "doc_smuggling"
    UNICODE_SMUGGLING = "unicode_smuggling"
    HOMOGLYPH = "homoglyph"
    ENCODED_PAYLOAD = "encoded_payload"
    EXFIL_PRIMITIVE = "exfil_primitive"
    MCP_POISONING = "mcp_poisoning"
    CONTEXT_STUFFING = "context_stuffing"


@dataclass(frozen=True)
class InjectionHit:
    """A single pattern match."""
    pattern_id: str
    family: Family
    severity: Severity
    score: int              # contribution to total_score (0-12 typical)
    match_text: str         # first ~200 chars of the match (redacted upstream if needed)
    evidence: str           # short human-readable explanation

    def to_dict(self) -> dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "family": self.family.value,
            "severity": self.severity.value,
            "score": self.score,
            "match_text": self.match_text[:200],
            "evidence": self.evidence,
        }


@dataclass
class InjectionResult:
    """Aggregate scan result with scoring + evidence."""
    hits: list[InjectionHit] = field(default_factory=list)
    total_score: int = 0
    normalized_content: str = ""
    decoded_spans: list[str] = field(default_factory=list)

    @property
    def worst_family(self) -> Family | None:
        if not self.hits:
            return None
        return max(self.hits, key=lambda h: h.score).family

    @property
    def max_severity(self) -> Severity | None:
        if not self.hits:
            return None
        order = {Severity.CRITICAL: 4, Severity.HIGH: 3, Severity.MEDIUM: 2, Severity.LOW: 1}
        return max(self.hits, key=lambda h: order.get(h.severity, 0)).severity

    def families_seen(self) -> set[Family]:
        return {h.family for h in self.hits}

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_score": self.total_score,
            "worst_family": self.worst_family.value if self.worst_family else None,
            "max_severity": self.max_severity.value if self.max_severity else None,
            "hit_count": len(self.hits),
            "families": sorted(f.value for f in self.families_seen()),
            "hits": [h.to_dict() for h in self.hits],
            "decoded_span_count": len(self.decoded_spans),
        }
