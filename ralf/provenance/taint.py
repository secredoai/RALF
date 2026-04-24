"""Taint propagation: detect when a command argument came from untrusted content.

The taint principle: if an agent fetches untrusted content (web page, MCP
tool result, file from /tmp) and then issues a command whose arguments
contain substrings from that content, the command carries tainted
influence. This is the causal chain ``UNTRUSTED_INPUT -> EXECUTION``.

Detection strategy:

1. Tokenize the command (shlex-style).
2. For each token of interesting length:
   - Does it appear as a substring in a recent untrusted ContentEvent?
   - Does it match a URL, domain, email, or file path that appears in recent content?
3. Return TaintMatch records with the matching ContentEvent.

Scoring (applied in the verdict engine):

- Each TaintMatch adds +5 if sourced from FETCHED.
- Each TaintMatch adds +8 if sourced from MCP_RESPONSE (higher because
  MCP tools can be controlled by an attacker and output tool-call
  instructions designed for the model to follow).
- Multiple matches stack up to a family cap of +15.
"""

from __future__ import annotations

import logging
import re
import shlex
from dataclasses import dataclass
from typing import Any

from ralf.provenance import ContentEvent, TrustLevel, is_untrusted

log = logging.getLogger(__name__)

# Minimum token length to consider for taint match. Shorter tokens produce
# too many false positives (matching single words that happen to appear in
# any web page).
MIN_TAINT_TOKEN_LEN = 8

# Max token length to consider (avoid quadratic blowup on huge args).
MAX_TAINT_TOKEN_LEN = 2048

# Base scores per trust level. Taint adds to verdict score.
_TAINT_BASE_SCORE: dict[TrustLevel, int] = {
    TrustLevel.FETCHED: 5,
    TrustLevel.MCP_RESPONSE: 8,
    TrustLevel.GENERATED: 3,
    TrustLevel.TOOL_OUTPUT: 2,
}

# Cap total taint contribution to avoid runaway stacking.
TAINT_SCORE_CAP = 15


@dataclass(frozen=True)
class TaintMatch:
    """A token from the command matched to a ContentEvent in the ledger."""
    token: str
    trust: TrustLevel
    source: str                # ContentEvent.source
    content_hash: str          # ContentEvent.content_hash
    match_type: str            # "substring" | "url" | "email" | "path"

    def to_dict(self) -> dict[str, Any]:
        return {
            "token": self.token[:200],
            "trust": self.trust.value,
            "source": self.source,
            "content_hash": self.content_hash,
            "match_type": self.match_type,
        }


# ── Helpers ─────────────────────────────────────────────────────────────────


def _tokenize_command(command: str) -> list[str]:
    """Break a shell command into tokens suitable for taint matching."""
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        tokens = command.split()
    # Also split on common URL/path separators to extract embedded items
    extended: list[str] = []
    for t in tokens:
        extended.append(t)
        # If a token contains '=' (e.g., KEY=VALUE), extract the value
        if "=" in t:
            _k, _sep, v = t.partition("=")
            if v:
                extended.append(v)
    return extended


_URL_RE = re.compile(
    r"https?://[a-zA-Z0-9.\-_~:/?#\[\]@!$&'()*+,;=%]+",
    re.IGNORECASE,
)
_EMAIL_RE = re.compile(
    r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b",
)
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|io|co|ai|dev|app|xyz|site|tech|info|cloud|me|us|uk|ru|cn|de|fr)\b",
    re.IGNORECASE,
)


def _extract_signals(command: str) -> dict[str, list[str]]:
    """Extract URL, email, domain signals from a command for fast matching."""
    return {
        "urls": _URL_RE.findall(command),
        "emails": _EMAIL_RE.findall(command),
        "domains": _DOMAIN_RE.findall(command),
    }


def detect_taint(
    command: str,
    recent_events: list[ContentEvent],
    *,
    min_token_len: int = MIN_TAINT_TOKEN_LEN,
) -> list[TaintMatch]:
    """Return taint matches for ``command`` against recent content events.

    Only untrusted events (FETCHED, MCP_RESPONSE, GENERATED) are considered.
    """
    matches: list[TaintMatch] = []
    if not command or not recent_events:
        return matches

    untrusted = [e for e in recent_events if is_untrusted(e.trust)]
    if not untrusted:
        return matches

    tokens = _tokenize_command(command)
    signals = _extract_signals(command)

    # Deduplicate matches by (content_hash, match_type, token).
    seen: set[tuple[str, str, str]] = set()

    # 1. Substring match on meaningful tokens
    for tok in tokens:
        if len(tok) < min_token_len or len(tok) > MAX_TAINT_TOKEN_LEN:
            continue
        for evt in untrusted:
            if not evt.full_redacted:
                continue
            if tok in evt.full_redacted:
                key = (evt.content_hash, "substring", tok)
                if key in seen:
                    continue
                seen.add(key)
                matches.append(TaintMatch(
                    token=tok,
                    trust=evt.trust,
                    source=evt.source,
                    content_hash=evt.content_hash,
                    match_type="substring",
                ))

    # 2. URL match (lower length threshold — URLs can be short)
    for url in signals["urls"]:
        for evt in untrusted:
            if not evt.full_redacted:
                continue
            if url in evt.full_redacted:
                key = (evt.content_hash, "url", url)
                if key in seen:
                    continue
                seen.add(key)
                matches.append(TaintMatch(
                    token=url,
                    trust=evt.trust,
                    source=evt.source,
                    content_hash=evt.content_hash,
                    match_type="url",
                ))

    # 3. Email match
    for email in signals["emails"]:
        for evt in untrusted:
            if not evt.full_redacted:
                continue
            if email in evt.full_redacted:
                key = (evt.content_hash, "email", email)
                if key in seen:
                    continue
                seen.add(key)
                matches.append(TaintMatch(
                    token=email,
                    trust=evt.trust,
                    source=evt.source,
                    content_hash=evt.content_hash,
                    match_type="email",
                ))

    # 4. Domain match (strict — avoids matching on common short domains)
    for domain in signals["domains"]:
        if len(domain) < 10:
            continue
        for evt in untrusted:
            if not evt.full_redacted:
                continue
            if domain in evt.full_redacted:
                key = (evt.content_hash, "domain", domain)
                if key in seen:
                    continue
                seen.add(key)
                matches.append(TaintMatch(
                    token=domain,
                    trust=evt.trust,
                    source=evt.source,
                    content_hash=evt.content_hash,
                    match_type="url",
                ))

    return matches


def score_taint(matches: list[TaintMatch]) -> int:
    """Compute the verdict-score bonus for a list of taint matches.

    Uses trust-level-specific base scores, caps total at TAINT_SCORE_CAP.
    Multiple matches from the same source are counted once — the score
    reflects the NUMBER OF INDEPENDENT SOURCES that contributed, not the
    number of tokens matched.
    """
    if not matches:
        return 0
    # Group by unique (source, content_hash) pairs.
    unique_sources: dict[tuple[str, str], TrustLevel] = {}
    for m in matches:
        key = (m.source, m.content_hash)
        # Keep the highest-trust-rank level if multiple types of match per source
        existing = unique_sources.get(key)
        if existing is None or is_untrusted(m.trust) and not is_untrusted(existing):
            unique_sources[key] = m.trust

    total = sum(_TAINT_BASE_SCORE.get(t, 3) for t in unique_sources.values())
    return min(total, TAINT_SCORE_CAP)


def summarize_taint(matches: list[TaintMatch]) -> str:
    """Build a short human-readable summary for the verdict reason."""
    if not matches:
        return ""
    by_type: dict[str, int] = {}
    sources: set[str] = set()
    for m in matches:
        by_type[m.match_type] = by_type.get(m.match_type, 0) + 1
        sources.add(m.source)
    parts = [f"{n} {t}" for t, n in by_type.items()]
    return (
        f"tainted by {len(sources)} untrusted source(s): "
        + ", ".join(parts)
    )
