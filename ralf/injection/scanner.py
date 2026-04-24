"""Injection scanner pipeline.

End-to-end:

    raw content
        ↓  strip_invisibles (counts tag-block, zero-width, bidi, VS chars)
        ↓  NFKC (collapses fullwidth, ligatures)
        ↓  fold_confusables (Cyrillic/Greek → Latin)
        ↓  lowercase + collapse whitespace
        ↓  detect base64 / hex candidates → decode
        ↓  run :mod:`ralf.injection.patterns` (F1-4, F9, F12) on normalized + raw
        ↓  run :mod:`ralf.injection.patterns` on each decoded span (tag as F7)
        ↓  detect mixed-script (F6)
        ↓  detect adversarial suffix (F11: entropy + non-English tail)
        ↓  score: max family score + half of others

Thresholds:
- :data:`BLOCK_THRESHOLD` = 10 — final score >= 10 → BLOCK
- :data:`REVIEW_THRESHOLD` = 5 — final score >= 5 → REVIEW
- < 5 → ALLOW

The ``trust_level`` argument dampens scoring on user-typed content (where
people quote injection patterns when asking *about* them — security
documentation, tutorials, blog posts).
"""

from __future__ import annotations

import base64
import binascii
import logging
import re

from ralf.injection import (
    Family, InjectionHit, InjectionResult, Severity,
)
from ralf.injection.patterns import scan_patterns
from ralf.injection.unicode_smuggle import (
    decode_tag_block,
    normalize_for_detection,
)

log = logging.getLogger(__name__)

# Decision thresholds (match ralf.shared.verdict_engine)
BLOCK_THRESHOLD = 10
REVIEW_THRESHOLD = 5

# Max content length scanned per call (DoS guard; tool outputs can be huge)
MAX_CONTENT_LEN = 64 * 1024



# Base64 candidate — at least 32 chars (to avoid matching short hashes).
# Accepts trailing '=' padding.
_B64_CANDIDATE = re.compile(r"\b[A-Za-z0-9+/]{32,}={0,2}\b")

# URL-encoded hex: %XX sequences ≥10 in a row
# Or \xXX sequences (Python/shell escapes)
_HEX_URL = re.compile(r"(?:%[0-9a-fA-F]{2}){10,}")
_HEX_BS = re.compile(r"(?:\\x[0-9a-fA-F]{2}){10,}")


# ── Decoding helpers ─────────────────────────────────────────────────────────


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    ok = sum(1 for c in s if c.isprintable() or c in "\n\r\t ")
    return ok / len(s)


def _try_decode_b64(s: str) -> str | None:
    """Decode a base64 candidate. Return decoded text if valid UTF-8, else None.

    Applies padding, validates UTF-8 strictly, and requires ≥70% printable
    ratio in the decoded output (avoids matching random-looking binary blobs).
    """
    try:
        padded = s + "=" * (-len(s) % 4)
        raw = base64.b64decode(padded, validate=False)
        decoded = raw.decode("utf-8", errors="strict")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    if _printable_ratio(decoded) < 0.7:
        return None
    return decoded


def _try_decode_hex_url(s: str) -> str | None:
    """Decode %XX escape sequences."""
    try:
        decoded_bytes = bytes(
            int(m.group(1), 16)
            for m in re.finditer(r"%([0-9a-fA-F]{2})", s)
        )
        text = decoded_bytes.decode("utf-8", errors="strict")
    except (ValueError, UnicodeDecodeError):
        return None
    if _printable_ratio(text) < 0.7:
        return None
    return text


def _try_decode_hex_bs(s: str) -> str | None:
    """Decode \\xXX escape sequences."""
    try:
        decoded_bytes = bytes(
            int(m.group(1), 16)
            for m in re.finditer(r"\\x([0-9a-fA-F]{2})", s)
        )
        text = decoded_bytes.decode("utf-8", errors="strict")
    except (ValueError, UnicodeDecodeError):
        return None
    if _printable_ratio(text) < 0.7:
        return None
    return text


def _decode_spans(text: str) -> list[str]:
    """Decode all b64/hex candidates in a single pass. Return unique decoded strings."""
    decoded: list[str] = []
    seen: set[str] = set()
    for m in _B64_CANDIDATE.finditer(text):
        dec = _try_decode_b64(m.group(0))
        if dec and dec not in seen:
            seen.add(dec)
            decoded.append(dec)
    for m in _HEX_URL.finditer(text):
        dec = _try_decode_hex_url(m.group(0))
        if dec and dec not in seen:
            seen.add(dec)
            decoded.append(dec)
    for m in _HEX_BS.finditer(text):
        dec = _try_decode_hex_bs(m.group(0))
        if dec and dec not in seen:
            seen.add(dec)
            decoded.append(dec)
    return decoded


# Adversarial suffix heuristic (Family 11): deferred to future release.


# ── Unicode-smuggle to InjectionHit conversion ───────────────────────────────


def _unicode_hits(content: str, meta: dict) -> list[InjectionHit]:
    """Convert invisibles-counts into InjectionHits (Family 5)."""
    inv = meta["invisibles"]
    hits: list[InjectionHit] = []

    # Tag block: hostile by default. Decode to surface payload.
    if inv["tag_block"] > 0:
        decoded = decode_tag_block(content)
        hits.append(InjectionHit(
            pattern_id="pi-unicode-tags",
            family=Family.UNICODE_SMUGGLING,
            severity=Severity.CRITICAL,
            score=12,
            match_text=decoded[:200],
            evidence=(
                f"{inv['tag_block']} tag-block chars decoded to: "
                f"{decoded[:60]!r}"
            ),
        ))

    # Bidi override: hostile outside actual RTL-script text.
    if inv["bidi_override"] > 0:
        hits.append(InjectionHit(
            pattern_id="pi-bidi-override",
            family=Family.UNICODE_SMUGGLING,
            severity=Severity.HIGH,
            score=8,
            match_text="",
            evidence=f"{inv['bidi_override']} bidi-override chars",
        ))

    # Zero-width: only flag on high density (>3 per 1000 chars).
    # ZWJ is legitimate for emoji families, ZWNJ for Arabic/Indic ligatures.
    orig_len = max(meta.get("original_len", 1), 1)
    density = inv["zero_width"] / orig_len * 1000
    if density > 3:
        hits.append(InjectionHit(
            pattern_id="pi-zero-width-dense",
            family=Family.UNICODE_SMUGGLING,
            severity=Severity.MEDIUM,
            score=5,
            match_text="",
            evidence=(
                f"{inv['zero_width']} zero-width chars "
                f"(density {density:.1f}/1000)"
            ),
        ))

    # Variation selectors outside emoji context → suspicious.
    # Heuristic: if count exceeds 5 in pure-ASCII text, flag.
    if inv["variation_selectors"] > 5:
        hits.append(InjectionHit(
            pattern_id="pi-variation-selectors-dense",
            family=Family.UNICODE_SMUGGLING,
            severity=Severity.MEDIUM,
            score=5,
            match_text="",
            evidence=f"{inv['variation_selectors']} variation selectors",
        ))

    return hits


# ── Score aggregation ────────────────────────────────────────────────────────


def _aggregate_score(hits: list[InjectionHit]) -> int:
    """Aggregate per-hit scores with family-level dampening.

    - Group hits by family, take the max score per family.
    - Final = max(family_scores) + sum(other_family_scores) // 2.
    - Prevents a document with 6 doc-smuggling hits from runaway-stacking.
    """
    if not hits:
        return 0
    by_family: dict[Family, int] = {}
    for h in hits:
        by_family[h.family] = max(by_family.get(h.family, 0), h.score)
    scores_desc = sorted(by_family.values(), reverse=True)
    return scores_desc[0] + sum(s // 2 for s in scores_desc[1:])


# ── Public API ───────────────────────────────────────────────────────────────


def scan_content(
    content: str,
    trust_level: str = "fetched",
) -> InjectionResult:
    """Scan ``content`` for prompt-injection patterns.

    Args:
        content: The text to scan. Truncated to :data:`MAX_CONTENT_LEN`.
        trust_level: One of ``"user"``, ``"workspace"``, ``"fetched"``,
            ``"mcp_response"``, ``"tool_output"``, ``"generated"``.
            Non-fetched trust levels get score dampening (user-typed content
            with injection-like phrases is usually tutorials/docs).

    Returns an :class:`~ralf.injection.InjectionResult` with hits, total score,
    decoded spans, and normalized form.
    """
    if not content:
        return InjectionResult()

    if len(content) > MAX_CONTENT_LEN:
        content = content[:MAX_CONTENT_LEN]

    result = InjectionResult()

    # Step 1+2: normalize
    normalized, meta = normalize_for_detection(content)
    result.normalized_content = normalized

    # Step 3: Family 5 (unicode smuggling) hits
    result.hits.extend(_unicode_hits(content, meta))

    # Family 6 (homoglyph mixed-script): deferred to future release.

    # Step 4: pattern catalog against normalized + raw
    result.hits.extend(scan_patterns(normalized, raw_text=content))

    # Step 6: iterative decode, then re-scan each decoded span
    decoded_spans = _decode_spans(content)
    result.decoded_spans = decoded_spans
    for span in decoded_spans:
        span_normalized, _span_meta = normalize_for_detection(span)
        span_hits = scan_patterns(span_normalized, raw_text=span)
        for h in span_hits:
            # Tag these as encoded-payload (Family 7) with a score bonus.
            result.hits.append(InjectionHit(
                pattern_id=f"{h.pattern_id}-in-encoded",
                family=Family.ENCODED_PAYLOAD,
                severity=h.severity,
                score=h.score + 3,  # bonus for hiding in encoding
                match_text=h.match_text,
                evidence=f"{h.evidence} (decoded from base64/hex)",
            ))

    # Adversarial suffix (Family 11): deferred to future release.

    # Step 7: aggregate score
    raw_score = _aggregate_score(result.hits)

    # Step 9: trust-level dampening
    if trust_level == "user":
        # User-typed content: they might quote injection examples in prose.
        result.total_score = int(raw_score * 0.6)
    elif trust_level == "generated":
        # Model's own output echoing injection — also informational.
        result.total_score = int(raw_score * 0.8)
    else:
        # fetched / mcp_response / tool_output / workspace → full score
        result.total_score = raw_score

    return result


def classify(total_score: int) -> str:
    """Map a total score to ``"allow"`` | ``"review"`` | ``"block"``."""
    if total_score >= BLOCK_THRESHOLD:
        return "block"
    if total_score >= REVIEW_THRESHOLD:
        return "review"
    return "allow"
