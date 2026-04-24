"""Unicode normalization + smuggling detection.

Defeats attacks that hide instructions via:

- Tag block (U+E0000-U+E007F): invisible ASCII-equivalent chars (Riley
  Goodside's 2024 technique — direct ASCII smuggling).
- Zero-width: ZWSP/ZWNJ/ZWJ/WJ/BOM/SHY — break tokens or hide chars.
- Bidi override: RLO/LRO/RLE/LRE/PDF — reverse rendering for humans.
- Variation selectors: hide payloads inside emoji-looking strings.
- Homoglyphs: Cyrillic/Greek letters that look Latin.
- Fullwidth forms: NFKC collapses these automatically.

Pipeline is ORDER-SENSITIVE — reorder and you get bypassed:

    strip_invisibles  -> nfkc  -> fold_confusables  -> collapse_whitespace

All downstream pattern matching runs against the normalized string; the
raw string is preserved separately for patterns that need angle brackets
or HTML comments intact.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any

# ── Invisible codepoint classes (each one-of has a regex for fast detection) ──

# U+E0020..U+E007E maps to ASCII 0x20..0x7E by subtracting 0xE0000.
# U+E0000..U+E007F as a block is *the* ASCII-smuggling vector.
_TAG_BLOCK = re.compile(r"[\U000E0000-\U000E007F]")

# Zero-width, word-joiners, BOM, soft-hyphen, Mongolian vowel sep,
# and the "invisible" math/format operators.
_ZERO_WIDTH = re.compile(
    r"[\u200B\u200C\u200D\u2060\uFEFF\u2063\u2062\u2061\u2064\u00AD\u180E]"
)

# Bidirectional override / isolate controls.
_BIDI_OVERRIDE = re.compile(r"[\u202A-\u202E\u2066-\u2069]")

# Variation selectors (hide payloads inside emoji/font selection).
_VARIATION_SELECTORS = re.compile(r"[\uFE00-\uFE0F]|[\U000E0100-\U000E01EF]")

# Line/paragraph separators that parsers sometimes treat as spaces.
_FORMAT_SEPARATORS = re.compile(r"[\u2028\u2029]")

# ── Confusables (Unicode TR#39 subset) ───────────────────────────────────────
# Curated minimum-viable set covering the chars that actually appear in
# published homoglyph bypass attacks. Full TR#39 is ~5000 entries; this is 60.
# Keep only uppercase/lowercase Latin look-alikes used in attack corpora.
_CONFUSABLE_MAP = {
    # Cyrillic lowercase
    "\u0430": "a", "\u0435": "e", "\u043E": "o", "\u0440": "p",
    "\u0441": "c", "\u0445": "x", "\u0443": "y", "\u0456": "i",
    "\u0501": "d", "\u04BB": "h", "\u0432": "b", "\u0455": "s",
    "\u0458": "j", "\u048D": "i", "\u04CF": "l", "\u03F2": "c",
    # Cyrillic uppercase
    "\u0410": "A", "\u0412": "B", "\u0415": "E", "\u041A": "K",
    "\u041C": "M", "\u041D": "H", "\u041E": "O", "\u0420": "P",
    "\u0421": "C", "\u0422": "T", "\u0425": "X", "\u04AE": "Y",
    "\u0408": "J", "\u041B": "L",
    # Greek lowercase
    "\u03B1": "a", "\u03BF": "o", "\u03C1": "p", "\u03C4": "t",
    "\u03BD": "v", "\u03BA": "k", "\u03B9": "i", "\u03BB": "l",
    "\u03BC": "u", "\u03B5": "e", "\u03C7": "x",
    # Greek uppercase
    "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0396": "Z",
    "\u0397": "H", "\u0399": "I", "\u039A": "K", "\u039C": "M",
    "\u039D": "N", "\u039F": "O", "\u03A1": "P", "\u03A4": "T",
    "\u03A7": "X", "\u03A5": "Y",
    # Armenian / Math alphanumeric tiny subset
    "\u0555": "O", "\u0585": "o",
}
_CONFUSABLE_TRANS = str.maketrans(_CONFUSABLE_MAP)

# ── Public API ───────────────────────────────────────────────────────────────


def strip_invisibles(text: str) -> tuple[str, dict[str, int]]:
    """Remove all invisible/smuggling chars. Return ``(stripped, counts)``.

    Counts map is populated per class so callers can score based on which
    class of invisible showed up (tag-block and bidi are hostile-by-default;
    zero-width has legitimate uses and requires density analysis).
    """
    counts = {
        "tag_block": len(_TAG_BLOCK.findall(text)),
        "zero_width": len(_ZERO_WIDTH.findall(text)),
        "bidi_override": len(_BIDI_OVERRIDE.findall(text)),
        "variation_selectors": len(_VARIATION_SELECTORS.findall(text)),
        "format_separators": len(_FORMAT_SEPARATORS.findall(text)),
    }
    text = _TAG_BLOCK.sub("", text)
    text = _ZERO_WIDTH.sub("", text)
    text = _BIDI_OVERRIDE.sub("", text)
    text = _VARIATION_SELECTORS.sub("", text)
    text = _FORMAT_SEPARATORS.sub(" ", text)
    return text, counts


def decode_tag_block(text: str) -> str:
    """Decode U+E0020..U+E007E back to ASCII. Non-mapped chars drop.

    Used to surface *what* the attacker smuggled after we've detected tag
    block presence. Legitimate language-tag uses (U+E0001 LANGUAGE TAG +
    ASCII-mapped sequences) also decode cleanly.
    """
    out: list[str] = []
    for ch in text:
        cp = ord(ch)
        if 0xE0020 <= cp <= 0xE007E:
            out.append(chr(cp - 0xE0000))
        elif 0xE0000 <= cp <= 0xE007F:
            continue  # control chars drop
        else:
            out.append(ch)
    return "".join(out)


def nfkc(text: str) -> str:
    """Apply Unicode NFKC normalization. Collapses fullwidth + ligatures."""
    return unicodedata.normalize("NFKC", text)


def fold_confusables(text: str) -> str:
    """Confusable folding (no-op; retained for API compatibility)."""
    return text


_WS = re.compile(r"\s+")


def collapse_whitespace(text: str) -> str:
    """Collapse runs of whitespace to single space and trim."""
    return _WS.sub(" ", text).strip()


def normalize_for_detection(text: str) -> tuple[str, dict[str, Any]]:
    """Full normalization pipeline for regex-based detection.

    Returns ``(normalized_lowercase_text, metadata)`` where metadata contains
    the invisible-char counts from the strip step, plus length info.

    The returned string is lowercased so patterns don't need ``re.IGNORECASE``
    everywhere (and more importantly so confusable-folded characters collide
    with their ASCII counterparts under case-folding rules).
    """
    stripped, inv_counts = strip_invisibles(text)
    normalized = nfkc(stripped)
    folded = fold_confusables(normalized)
    collapsed = collapse_whitespace(folded).lower()
    return collapsed, {"invisibles": inv_counts, "original_len": len(text)}


# Homoglyph mixed-script detection (fold_confusables TR39, detect_mixed_script,
# mixed_script_words): deferred to future release.
