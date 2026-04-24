"""Injection pattern catalog — 12 attack families.

Each family is a list of ``(pattern_id, compiled_regex, severity, score, evidence)``.
Patterns run against **normalized** text (after strip_invisibles + NFKC +
fold_confusables + lowercase) except for document-smuggling patterns that
depend on angle brackets / HTML comments — those run against raw text.

Only text-based families (1, 2, 3, 4, 9, 12) live here. Unicode smuggling
(family 5) and homoglyph (family 6) are detected structurally in
:mod:`ralf.injection.unicode_smuggle`. Encoded payload (family 7) is handled
by iterative decode in :mod:`ralf.injection.scanner`. Exfil (family 8) lives
in :mod:`ralf.injection.exfil`. Adversarial suffix (family 11) is a
statistical heuristic in :mod:`ralf.injection.scanner`.

Score contributions stack within a family up to the family cap. Across
families, the scanner uses ``max + half of rest`` to prevent runaway stacking
on heavily-decorated documents.
"""

from __future__ import annotations

import re

from ralf.injection import Family, InjectionHit, Severity


# Type of a pattern row: (id, regex, severity, score, evidence).
_PatternRow = tuple[str, "re.Pattern[str]", Severity, int, str]


# ── Family 1: Instruction override ───────────────────────────────────────────

_F1_PATTERNS: list[_PatternRow] = [
    (
        "pi-ignore-previous",
        re.compile(
            r"\b(?:ignore|disregard|forget|neglect|overlook|omit|bypass|skip"
            r"|pay\s+no\s+attention\s+to|do\s+not\s+(?:follow|obey|listen\s+to))\b"
            r"(?:\s+(?:all|any|every|the|your|my))?"
            r"(?:\s+(?:prior|previous|preceding|above|foregoing|earlier|initial|former|told|original|first))?"
            r"\s+(?:content|text|instructions?|directives?|commands?|context"
            r"|conversation|input|data|messages?|prompts?|rules?|system|guidelines?"
            r"|orders?|tasks?|directions?|assignments?|talked|discussed|said)",
        ),
        Severity.CRITICAL, 10, "canonical instruction-override phrase",
    ),
    (
        # "forget everything" / "forget all" with no object noun — very common
        # task-swap attack precursor. Requires the full 2-word phrase to keep
        # false-positive risk low (casual "I forgot everything" won't match
        # because this pattern anchors on the IMPERATIVE verb at or near a
        # sentence start / punctuation boundary).
        "pi-forget-everything",
        re.compile(
            r"(?:^|[.!?\"'`\n]\s*|\b(?:please|just|now|and|then)\s+)"
            r"(?:forget|ignore|disregard|dismiss)\s+"
            r"(?:absolutely\s+)?(?:everything|all)"
            r"(?:\s+(?:you(?:'ve|\s+(?:have|were|said)))"
            r"|\s+(?:before|above|prior|previous|earlier|up\s+to\s+now|so\s+far))?"
            r"[\s,.!]",
        ),
        Severity.HIGH, 8, "forget-everything task-swap precursor",
    ),
    (
        # "Ignore [the] above and [do|say]" — classic without explicit noun.
        "pi-ignore-above-and",
        re.compile(
            r"\bignore\s+(?:the\s+)?above\b\s+(?:and|then|to)\s+(?:say|do|respond|answer|tell|print|write|return)",
        ),
        Severity.HIGH, 8, "ignore-above-and-do injection",
    ),
    # Additional evasion patterns available in extended edition.
    (
        # "Ignore your directions/instructions/rules" — slight variant where
        # the attacker uses YOUR+noun without preceding "all/the".
        "pi-ignore-your-X",
        re.compile(
            r"\bignore\s+(?:your|my)\s+"
            r"(?:directions?|instructions?|directives?|rules?|system|guidelines?|orders?|tasks?|prompts?)",
        ),
        Severity.HIGH, 8, "ignore your-X directive",
    ),
    (
        "pi-start-over",
        re.compile(
            r"(?:start\s+over|start\s+anew|begin\s+afresh|start\s+from\s+scratch"
            r"|reset\s+(?:your\s+)?(?:context|state))",
        ),
        Severity.MEDIUM, 4, "context reset phrase",
    ),
    (
        "pi-new-instructions",
        re.compile(
            r"\b(?:new|updated|revised|latest|corrected)\s+"
            r"(?:instructions?|directives?|system\s+prompt|rules?)\b",
        ),
        Severity.MEDIUM, 5, "new-instructions phrase",
    ),
    (
        "pi-you-are-now",
        re.compile(r"\byou\s+are\s+now\s+(?:a|an|in|the|operating|running|acting)\b"),
        Severity.MEDIUM, 5, "role reassignment",
    ),
    (
        "pi-developer-mode",
        re.compile(
            r"\b(?:developer|admin|root|god|debug|maintenance|unrestricted|jailbreak|sudo)\s+mode\b",
        ),
        Severity.HIGH, 7, "developer-mode request",
    ),
    (
        "pi-reveal-system",
        re.compile(
            r"\b(?:reveal|show|display|print|output|dump|leak|expose|share)\s+"
            r"(?:your\s+)?(?:system\s+)?"
            r"(?:prompt|instructions|rules|configuration|context|directives)",
        ),
        Severity.HIGH, 7, "system-prompt extraction",
    ),
]

# ── Family 2: Persona hijack ─────────────────────────────────────────────────

_F2_PATTERNS: list[_PatternRow] = [
    (
        "pi-dan-persona",
        re.compile(
            r"\b(?:dan|stan|dude|aim|kevin|evilbot|basedgpt)\b"
            r"|do\s+anything\s+now",
        ),
        Severity.CRITICAL, 10, "DAN-family persona jailbreak",
    ),
    (
        "pi-roleplay-unrestricted",
        re.compile(
            r"\b(?:pretend|act|roleplay|imagine|suppose)\s+"
            r"(?:you(?:'re|\s+are)|to\s+be)\s+.{0,40}"
            r"\b(?:no\s+restrictions?|unrestricted|without\s+"
            r"(?:rules|limits|filters|ethics|guidelines))",
        ),
        Severity.HIGH, 7, "unrestricted-roleplay request",
    ),
    (
        "pi-role-reversal",
        re.compile(
            r"\byou\s+(?:are|will\s+be)\s+the\s+(?:system|developer|admin|user|operator)\b"
            r"|\bi\s+am\s+(?:the\s+)?(?:system|developer|admin|anthropic|openai|your\s+creator)\b",
        ),
        Severity.HIGH, 6, "role reversal",
    ),
    (
        "pi-fake-authority",
        re.compile(
            r"(?:this\s+is|message\s+from|i\s+am)\s+"
            r"(?:anthropic|openai|your\s+developer|claude\s+team|model\s+team|the\s+system)",
        ),
        Severity.HIGH, 7, "fake authority claim",
    ),
]

# ── Family 3: Prompt leak ────────────────────────────────────────────────────

_F3_PATTERNS: list[_PatternRow] = [
    (
        "pi-leak-verbatim",
        re.compile(
            r"(?:repeat|echo|output|print|display|show|reproduce)\s+"
            r"(?:the\s+|your\s+)?"
            r"(?:(?:exact|complete|full|entire|verbatim|original|initial)\s+)+"
            r"(?:system\s+)?"
            r"(?:prompt|instructions|system\s+message|context|text\s+above)",
        ),
        Severity.HIGH, 7, "verbatim leak request",
    ),
    (
        "pi-leak-first-words",
        re.compile(
            r"(?:first|initial|top|beginning)\s+(?:\d+\s+)?"
            r"(?:words|lines|tokens|characters?|sentences)\s+"
            r"(?:of|from)\s+(?:your|the)\s+(?:prompt|instructions|context)",
        ),
        Severity.MEDIUM, 5, "first-N leak request",
    ),
    (
        "pi-leak-above",
        re.compile(
            r"(?:everything|all|text)\s+(?:above|before\s+this|preceding\s+this|prior\s+to)\s+"
            r"(?:this\s+(?:message|line|paragraph|point)|here|now)",
        ),
        Severity.MEDIUM, 4, "context-above leak",
    ),
    (
        # "print/show/display/output/echo/spell-check above [prompt|text|instructions]"
        # The "spell-check and print above" is a known indirection trick.
        "pi-leak-above-print",
        re.compile(
            r"(?:print|show|display|output|echo|reveal|reproduce|spell[\s-]*check"
            r"|copy)"
            r"(?:\s+(?:a|an|the|all|your))?"
            r"\s+(?:improved\s+version\s+of\s+)?"
            r"(?:above|preceding|initial|full|entire)"
            r"\s+(?:prompt|text|instructions?|message|directives?|input|system|content)",
            re.IGNORECASE,
        ),
        Severity.HIGH, 7, "print-above-prompt leak",
    ),
    (
        # "show me all your prompt[s]" / "return your embeddings" / "dump your config"
        "pi-leak-your-internals",
        re.compile(
            r"(?:show|tell|give|print|dump|reveal|output|return|share|list)\s+"
            r"(?:me\s+)?(?:all\s+)?(?:of\s+)?your\s+"
            r"(?:prompt(?:\s+texts?)?s?|instructions?|system\s+prompt|system\s+message"
            r"|configuration|context|embeddings?|weights|training\s+data"
            r"|directives?|guidelines?|rules?)",
            re.IGNORECASE,
        ),
        Severity.HIGH, 7, "leak request for internal prompts/embeddings",
    ),
]

# ── Family 4: Document smuggling ─────────────────────────────────────────────
# These patterns run against RAW (un-normalized) text — angle brackets and
# HTML comment delimiters must be preserved.

_F4_PATTERNS: list[_PatternRow] = [
    (
        "pi-html-comment-directive",
        re.compile(
            r"<!--\s*(?:SYSTEM|INSTRUCTION|IMPORTANT|NOTE\s+TO\s+AI|ATTENTION\s+AI"
            r"|DIRECTIVE|OVERRIDE)[^-]{0,500}"
            r"(?:ignore|disregard|reveal|execute|send|fetch|post|curl|wget|exec|bypass)"
            r"[^-]{0,200}-->",
            re.IGNORECASE | re.DOTALL,
        ),
        Severity.CRITICAL, 10, "hidden directive in HTML comment",
    ),
    (
        "pi-important-tag",
        re.compile(
            r"<\s*(?:IMPORTANT|SYSTEM|INSTRUCTION|ADMIN|NOTE_TO_ASSISTANT"
            r"|NOTE_TO_AI|DIRECTIVE)\s*>",
            re.IGNORECASE,
        ),
        Severity.HIGH, 8, "suspicious directive tag",
    ),
    (
        "pi-css-hide",
        re.compile(
            r"(?:font-size\s*:\s*0"
            r"|line-height\s*:\s*0"
            r"|display\s*:\s*none"
            r"|visibility\s*:\s*hidden"
            r"|opacity\s*:\s*0"
            r"|color\s*:\s*(?:white|#fff|#ffffff|transparent))",
            re.IGNORECASE,
        ),
        Severity.MEDIUM, 4, "hidden CSS style",
    ),
    (
        "pi-comment-directive",
        re.compile(
            r"(?://|#|/\*|\*|<!--)\s*"
            r"(?:TODO\s+AI|AI\s*:|ASSISTANT\s*:|CLAUDE\s*:|COPILOT\s*:"
            r"|IGNORE\s+ABOVE|SYSTEM\s+OVERRIDE|HIDDEN\s+INSTRUCTION)",
            re.IGNORECASE,
        ),
        Severity.HIGH, 7, "code-comment directive",
    ),
    (
        "pi-cdata-injection",
        re.compile(
            r"<!\[CDATA\[[^\]]{0,500}(?:ignore|system|execute|curl|fetch)[^\]]{0,200}\]\]>",
            re.IGNORECASE,
        ),
        Severity.HIGH, 7, "CDATA-wrapped directive",
    ),
]

# ── Family 9: MCP tool poisoning ─────────────────────────────────────────────

_F9_PATTERNS: list[_PatternRow] = [
    (
        "pi-mcp-sidenote-param",
        re.compile(
            r"""(?:"|')\s*sidenote\s*(?:"|')\s*:\s*(?:"|')\s*"""
            r"""(?:content|contents|data|ssh|keys|mcp\.json|env|secret)""",
        ),
        Severity.CRITICAL, 10, "MCP sidenote-param exfil (Invariant Labs PoC)",
    ),
    (
        "pi-mcp-shadowing",
        re.compile(
            r"this\s+tool\s+has\s+(?:a\s+)?(?:very\s+)?important\s+"
            r"side\s+effect\s+on\s+(?:the\s+)?(?:also\s+present|other)\s+\w+\s+tool",
        ),
        Severity.CRITICAL, 10, "MCP tool-shadowing attempt",
    ),
    (
        "pi-tool-desc-read-secrets",
        re.compile(
            r"(?:before|when|first)\s+(?:using|calling|invoking)\s+this\s+tool"
            r".{0,200}(?:read|open|cat|load)\s+.{0,40}"
            r"(?:~/\.ssh|mcp\.json|\.env|id_rsa|credentials|\.aws|\.kube)",
            re.DOTALL,
        ),
        Severity.CRITICAL, 10, "tool description reads secrets",
    ),
    (
        "pi-email-redirect",
        re.compile(
            r"(?:send|forward|redirect|cc|bcc)\s+"
            r"(?:"
            r"(?:all\s+)?(?:emails?|messages?)\s+to\s+[a-z0-9._%+-]+@[a-z0-9.-]+"
            r"|[a-z0-9._%+-]+@[a-z0-9.-]+"
            r")",
        ),
        Severity.HIGH, 8, "email exfil redirect",
    ),
    (
        "pi-tool-call-redirect",
        re.compile(
            r"(?:always|must|should)\s+(?:call|invoke|use)\s+"
            r"(?:the\s+)?(?:tool|function)\s+[\"'`]?"
            r"(?:exec|shell|run|eval|system|http_request|send_email|delete|destroy)",
        ),
        Severity.HIGH, 8, "forced tool-call redirect",
    ),
]

# Additional families available in extended edition.


# ── Assembly ─────────────────────────────────────────────────────────────────

# Families that run against NORMALIZED text (lowercased + folded).
_NORMALIZED_FAMILIES: dict[Family, list[_PatternRow]] = {
    Family.INSTRUCTION_OVERRIDE: _F1_PATTERNS,
    Family.PERSONA_HIJACK: _F2_PATTERNS,
    Family.PROMPT_LEAK: _F3_PATTERNS,
    Family.MCP_POISONING: _F9_PATTERNS,
}

# Families that run against RAW text (preserve HTML/markup + non-Latin scripts).
_RAW_FAMILIES: dict[Family, list[_PatternRow]] = {
    Family.DOC_SMUGGLING: _F4_PATTERNS,
}


def scan_patterns(
    normalized_text: str,
    raw_text: str,
) -> list[InjectionHit]:
    """Run all text-based pattern families.

    Args:
        normalized_text: lowercase + invisibles stripped + NFKC + confusables-folded.
        raw_text: original text (with markup preserved).

    Returns a list of hits. Duplicate pattern IDs across runs are allowed —
    the caller scores them.
    """
    hits: list[InjectionHit] = []

    for family, patterns in _NORMALIZED_FAMILIES.items():
        for pid, pat, sev, score, ev in patterns:
            m = pat.search(normalized_text)
            if m is None:
                continue
            hits.append(InjectionHit(
                pattern_id=pid,
                family=family,
                severity=sev,
                score=score,
                match_text=m.group(0)[:200],
                evidence=ev,
            ))

    for family, patterns in _RAW_FAMILIES.items():
        for pid, pat, sev, score, ev in patterns:
            m = pat.search(raw_text)
            if m is None:
                continue
            hits.append(InjectionHit(
                pattern_id=pid,
                family=family,
                severity=sev,
                score=score,
                match_text=m.group(0)[:200],
                evidence=ev,
            ))

    return hits


def pattern_count() -> int:
    """Total number of patterns in the catalog (for status/testing)."""
    return (
        sum(len(v) for v in _NORMALIZED_FAMILIES.values())
        + sum(len(v) for v in _RAW_FAMILIES.values())
    )
