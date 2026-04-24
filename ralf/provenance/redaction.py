"""Credential redaction before storing content in the provenance ledger.

We MUST strip credentials before any content touches disk. The ledger is
a debug and correlation tool, not a secret-leak machine. Every regex here
has been sized to catch the 12 most common credential shapes. False
positives (masking legit strings) are acceptable; false negatives
(credentials slipping through) are not.

Patterns reused / extended from :mod:`ralf.detection.supply_chain`.
"""

from __future__ import annotations

import re

# ── Credential patterns ──────────────────────────────────────────────────────

# All patterns replace the matched text with ``[REDACTED:<tag>]``.
_REDACTION_PATTERNS: list[tuple[str, "re.Pattern[str]"]] = [
    # Specific provider prefixes first (highest confidence)
    ("ANTHROPIC_KEY", re.compile(r"sk-ant-[a-zA-Z0-9_-]{20,}")),
    ("OPENAI_KEY", re.compile(r"sk-[a-zA-Z0-9]{20,}")),
    ("GOOGLE_KEY", re.compile(r"AIza[a-zA-Z0-9_-]{35}")),
    ("GITHUB_PAT", re.compile(r"ghp_[a-zA-Z0-9]{36}")),
    ("GITHUB_OAUTH", re.compile(r"gho_[a-zA-Z0-9]{36}")),
    ("GITHUB_APP", re.compile(r"ghs_[a-zA-Z0-9]{36}")),
    ("GITLAB_PAT", re.compile(r"glpat-[a-zA-Z0-9-]{20}")),
    ("SLACK_TOKEN", re.compile(r"xox[bpras]-[0-9a-zA-Z-]{10,}")),
    ("AWS_ACCESS_KEY", re.compile(r"AKIA[A-Z0-9]{16}")),
    ("AWS_SECRET", re.compile(r"\b[A-Za-z0-9/+=]{40}\b(?=[^A-Za-z0-9/+=])")),
    # Private keys (any format)
    (
        "PRIVATE_KEY",
        re.compile(
            r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----"
            r"[\s\S]*?"
            r"-----END (?:RSA |OPENSSH |EC |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----",
        ),
    ),
    # Bearer tokens in HTTP headers
    (
        "BEARER_TOKEN",
        re.compile(r"Bearer\s+[a-zA-Z0-9._\-~+/]{20,}=*", re.IGNORECASE),
    ),
    # JWT tokens (three-segment base64url)
    (
        "JWT",
        re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b"),
    ),
    # Authorization Basic
    (
        "BASIC_AUTH",
        re.compile(r"Authorization:\s*Basic\s+[a-zA-Z0-9+/=]{8,}", re.IGNORECASE),
    ),
    # password / secret / token in KEY=VALUE form.
    # Note: no \b before the keyword — DATABASE_PASSWORD=... must still match
    # (underscore is a word char so \b wouldn't separate DATABASE_ from PASSWORD).
    (
        "ENV_SECRET",
        re.compile(
            r"(?i)(?:password|passwd|secret|token|api[_-]?key|apikey|auth_token"
            r"|access[_-]?token|refresh[_-]?token|private[_-]?key)"
            r"\s*[:=]\s*"
            r"[\"']?"
            r"[^\s\"'&<>\n]{6,}"  # the value (6+ chars of non-whitespace)
            r"[\"']?",
        ),
    ),
    # URL-embedded credentials
    (
        "URL_CRED",
        re.compile(r"(?:https?|ftp|git)://[^:@\s]+:[^@\s]+@[^\s]+"),
    ),
]


def redact(text: str) -> tuple[str, dict[str, int]]:
    """Strip credentials from ``text``. Return ``(redacted, counts)``.

    ``counts`` is a dict of tag → number of redactions applied. The
    resulting string has credentials replaced with ``[REDACTED:<tag>]``
    markers and is safe to store.
    """
    if not text:
        return text, {}

    counts: dict[str, int] = {}
    result = text

    for tag, pattern in _REDACTION_PATTERNS:
        count = 0
        marker = f"[REDACTED:{tag}]"

        def _sub(m: "re.Match[str]", _marker: str = marker) -> str:
            return _marker

        new, n = pattern.subn(_sub, result)
        if n > 0:
            counts[tag] = n
            count = n
            result = new

    return result, counts


def redact_and_clip(
    text: str,
    max_len: int,
) -> tuple[str, dict[str, int]]:
    """Redact first, then clip. Avoids leaking credential tails via clip.

    If the original content is larger than ``max_len`` we STILL run the
    redactor over the entire content first (so nothing slips through via
    truncation), then clip. The full redactor pass is O(n) regex, fine on
    content sized in tens of KB.
    """
    redacted, counts = redact(text)
    if len(redacted) > max_len:
        redacted = redacted[:max_len]
    return redacted, counts
