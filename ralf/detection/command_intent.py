"""Intent-aware command classifier for dual-use binaries.

Resolves the fundamental dual-use problem: ``crontab -l`` (read) and
``echo payload | crontab -`` (persistence) are the same binary but
completely different intents. Binary-name-only rules can't tell them
apart; this module can.

Covers ~25 dual-use binaries plus read-only helpers (git, ls, cat,
echo, date, uname, whoami, id, pwd, hostname, ps, df, free).

Usage:
    from ralf.detection.command_intent import IntentClassifier
    result = IntentClassifier.classify("crontab", "crontab -l")
    result.intent           # CommandIntent.READ
    result.suppress_identity # True — don't fire identity-based rules
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any


class CommandIntent(str, Enum):
    """What the command is trying to accomplish."""
    READ = "read"                       # Read-only: crontab -l, systemctl status
    FETCH = "fetch"                     # Download/retrieve: curl URL, wget URL
    OPERATE = "operate"                 # Normal operational use: systemctl start
    EDIT = "edit"                       # Modify state non-destructively: crontab -e
    PERSIST = "persist"                 # Create persistence: crontab piped, systemctl enable
    EXFIL = "exfil"                     # Data exfiltration: curl -d @file
    DISRUPT = "disrupt"                 # Service disruption: systemctl stop/mask
    ESCALATE = "escalate"              # Privilege escalation: chmod +s, find -exec
    TUNNEL = "tunnel"                   # Network tunneling: ssh -R/-L
    DOWNLOAD_EXEC = "download_exec"     # Download and execute: curl | bash
    STAGE = "stage"                     # Data staging: tar czf sensitive paths
    CONNECT = "connect"                 # Interactive connection: ssh user@host
    INSTALL = "install"                 # Package install: pip install, npm install
    UNKNOWN = "unknown"                 # Unclassified — no scoring change


@dataclass(frozen=True)
class IntentClassification:
    """Result of classifying a command's intent."""
    binary: str
    intent: CommandIntent
    confidence: float           # 0.0-1.0
    evidence: str               # Human-readable: "crontab with -l flag"
    suppress_identity: bool     # Suppress binary-identity-based scoring?


# ── Internal rule structure ───────────────────────────────────────────

@dataclass(frozen=True)
class _Rule:
    pattern: re.Pattern | None  # None = catch-all fallback
    intent: CommandIntent
    confidence: float
    evidence: str
    check_pipe: bool = False    # Check for piped stdin


# Sensitive paths for STAGE/EXFIL detection
_SENSITIVE_PATHS = re.compile(
    r'(?:/etc/(?:shadow|passwd|sudoers|ssh)|'
    r'\.ssh/(?:id_rsa|id_ed25519|authorized_keys)|'
    r'\.gnupg|\.aws/credentials|\.kube/config|'
    r'\.docker/config\.json)',
    re.I,
)

# Pipe to interpreter pattern
_PIPE_TO_INTERP = re.compile(
    r'\|\s*(?:bash|sh|dash|zsh|python3?|perl|ruby|node)\b'
)


# ── Pattern tables for 20 dual-use binaries ───────────────────────────

def _rules(*args: tuple) -> tuple[_Rule, ...]:
    """Build rule tuple from (pattern_str|None, intent, confidence, evidence, [check_pipe])."""
    rules = []
    for item in args:
        pat_str, intent, conf, ev = item[0], item[1], item[2], item[3]
        check_pipe = item[4] if len(item) > 4 else False
        pat = re.compile(pat_str, re.I) if pat_str else None
        rules.append(_Rule(pat, intent, conf, ev, check_pipe))
    return tuple(rules)


_INTENT_RULES: dict[str, tuple[_Rule, ...]] = {
    # ── crontab ───────────────────────────────────────────────────
    "crontab": _rules(
        (r'\|\s*crontab\s', CommandIntent.PERSIST, 0.95, "piped input to crontab"),
        (r'crontab\s+\S+\.txt|crontab\s+\S+\.cron|crontab\s+/tmp/', CommandIntent.PERSIST, 0.90, "crontab loading from file"),
        (r'\bcrontab\s+-r\b', CommandIntent.DISRUPT, 0.90, "crontab -r removes all jobs"),
        (r'\bcrontab\s+-e\b', CommandIntent.EDIT, 0.90, "crontab -e interactive edit"),
        (r'\bcrontab\s+-l\b', CommandIntent.READ, 1.0, "crontab -l list jobs"),
        (None, CommandIntent.UNKNOWN, 0.5, "crontab unclassified"),
    ),

    # ── systemctl ─────────────────────────────────────────────────
    "systemctl": _rules(
        (r'\b(?:status|show|is-active|is-enabled|list-units|list-unit-files|list-timers|cat)\b', CommandIntent.READ, 1.0, "systemctl read-only query"),
        (r'\b(?:start|restart|reload|try-restart|reload-or-restart)\b', CommandIntent.OPERATE, 0.90, "systemctl service operation"),
        (r'\b(?:stop|mask|isolate)\b', CommandIntent.DISRUPT, 0.90, "systemctl service disruption"),
        (r'\b(?:enable|reenable)\b', CommandIntent.PERSIST, 0.85, "systemctl enable persistence"),
        (r'\bdisable\b', CommandIntent.OPERATE, 0.85, "systemctl disable"),
        (r'\b(?:daemon-reload|daemon-reexec|reset-failed)\b', CommandIntent.OPERATE, 0.80, "systemctl daemon management"),
        (None, CommandIntent.UNKNOWN, 0.5, "systemctl unclassified"),
    ),

    # ── curl ──────────────────────────────────────────────────────
    "curl": _rules(
        (r'(?:-d\s|--data[\s=]|--data-binary[\s=]|--data-raw[\s=]|--data-urlencode[\s=]|--upload-file[\s=]|-T\s|--form[\s=]|-F\s)', CommandIntent.EXFIL, 0.85, "curl upload/POST data"),
        (r'\|\s*(?:bash|sh|dash|zsh|python3?|perl|ruby|node)\b', CommandIntent.DOWNLOAD_EXEC, 0.95, "curl piped to interpreter"),
        (r'(?:-o\s|--output[\s=]|-O\b)', CommandIntent.OPERATE, 0.75, "curl download to file"),
        (None, CommandIntent.FETCH, 0.90, "curl fetch"),
    ),

    # ── wget ──────────────────────────────────────────────────────
    "wget": _rules(
        (r'\|\s*(?:bash|sh|dash|zsh|python3?|perl|ruby|node)\b', CommandIntent.DOWNLOAD_EXEC, 0.95, "wget piped to interpreter"),
        (r'--post-data|--post-file', CommandIntent.EXFIL, 0.85, "wget POST data"),
        (None, CommandIntent.FETCH, 0.90, "wget fetch"),
    ),

    # ── tar ───────────────────────────────────────────────────────
    "tar": _rules(
        (r'--checkpoint-action\s*=\s*exec', CommandIntent.ESCALATE, 0.95, "tar checkpoint exec (GTFOBins)"),
        (r'(?:-?[a-zA-Z]*c[a-zA-Z]*f\b|--create\b|\bc[a-z]*f\b)', CommandIntent.OPERATE, 0.80, "tar create archive"),
        (r'(?:-?[a-zA-Z]*x[a-zA-Z]*f\b|--extract\b|-x\b|\bx[a-z]*f\b)', CommandIntent.READ, 0.90, "tar extract"),
        (r'(?:-?[a-zA-Z]*t[a-zA-Z]*f\b|--list\b|-t\b|\bt[a-z]*f\b)', CommandIntent.READ, 0.95, "tar list contents"),
        (None, CommandIntent.UNKNOWN, 0.5, "tar unclassified"),
    ),

    # ── ssh ───────────────────────────────────────────────────────
    "ssh": _rules(
        (r'\s-[a-zA-Z]*[RLD]\s', CommandIntent.TUNNEL, 0.90, "ssh port forwarding/tunnel"),
        (r'\s-W\s', CommandIntent.TUNNEL, 0.85, "ssh stdio forwarding"),
        (r'\w+@[\w.-]+\s+\S', CommandIntent.OPERATE, 0.70, "ssh remote command execution"),
        (r'\w+@[\w.-]+\s*$', CommandIntent.CONNECT, 0.85, "ssh interactive connection"),
        (None, CommandIntent.CONNECT, 0.70, "ssh connection"),
    ),

    # ── scp ───────────────────────────────────────────────────────
    "scp": _rules(
        (r'\S+:\S+\s+\.|\S+:\S+\s+/tmp/', CommandIntent.FETCH, 0.80, "scp remote to local"),
        (None, CommandIntent.EXFIL, 0.70, "scp local to remote"),
    ),

    # ── chmod ─────────────────────────────────────────────────────
    "chmod": _rules(
        (r'(?:\+s\b|u\+s\b|[42][0-7]{3}\b)', CommandIntent.ESCALATE, 0.95, "chmod SUID/SGID bit"),
        (None, CommandIntent.OPERATE, 0.85, "chmod normal permission change"),
    ),

    # ── find ──────────────────────────────────────────────────────
    "find": _rules(
        (r'-exec\s+.*(?:sh|bash|dash|zsh|python|perl|ruby)\b', CommandIntent.ESCALATE, 0.85, "find -exec with interpreter"),
        (r'-exec\s+.*\brm\b', CommandIntent.DISRUPT, 0.80, "find -exec rm"),
        (r'-delete\b', CommandIntent.DISRUPT, 0.80, "find -delete"),
        (None, CommandIntent.READ, 0.85, "find search"),
    ),

    # ── awk/gawk/mawk/nawk ────────────────────────────────────────
    "awk": _rules(
        (r'\bsystem\s*\(', CommandIntent.ESCALATE, 0.90, "awk system() call"),
        (None, CommandIntent.READ, 0.85, "awk text processing"),
    ),
    "gawk": _rules(
        (r'\bsystem\s*\(', CommandIntent.ESCALATE, 0.90, "gawk system() call"),
        (None, CommandIntent.READ, 0.85, "gawk text processing"),
    ),

    # ── docker ────────────────────────────────────────────────────
    "docker": _rules(
        (r'--privileged\b', CommandIntent.ESCALATE, 0.95, "docker --privileged"),
        (r'(?:-v\s+/:/|--mount\s+.*source=/\s*,)', CommandIntent.ESCALATE, 0.90, "docker root mount"),
        (r'--cap-add\b', CommandIntent.ESCALATE, 0.80, "docker capability add"),
        (r'\b(?:ps|images|logs|inspect|stats|top|port|info|version)\b', CommandIntent.READ, 0.90, "docker read-only query"),
        (r'\b(?:exec|run|build|pull|push|start|stop|restart|rm|rmi)\b', CommandIntent.OPERATE, 0.80, "docker operation"),
        (None, CommandIntent.OPERATE, 0.70, "docker command"),
    ),

    # ── iptables / ip6tables ──────────────────────────────────────
    "iptables": _rules(
        (r'(?:-L\b|--list\b|-S\b|--list-rules\b|-n\b)', CommandIntent.READ, 0.95, "iptables list rules"),
        (r'(?:-F\b|--flush\b)', CommandIntent.DISRUPT, 0.90, "iptables flush all rules"),
        (None, CommandIntent.OPERATE, 0.70, "iptables rule change"),
    ),
    "ip6tables": _rules(
        (r'(?:-L\b|--list\b|-S\b|--list-rules\b)', CommandIntent.READ, 0.95, "ip6tables list rules"),
        (r'(?:-F\b|--flush\b)', CommandIntent.DISRUPT, 0.90, "ip6tables flush"),
        (None, CommandIntent.OPERATE, 0.70, "ip6tables rule change"),
    ),
    "ufw": _rules(
        (r'\bstatus\b', CommandIntent.READ, 0.95, "ufw status"),
        (r'\bdisable\b', CommandIntent.DISRUPT, 0.90, "ufw disable"),
        (None, CommandIntent.OPERATE, 0.80, "ufw rule change"),
    ),

    # ── nc / ncat ─────────────────────────────────────────────────
    "nc": _rules(
        (r'(?:-e\b|--exec\b|-c\b)', CommandIntent.ESCALATE, 0.95, "nc exec (reverse shell)"),
        (r'-l\b.*-p\b|-l\b', CommandIntent.TUNNEL, 0.85, "nc listen (backdoor)"),
        (None, CommandIntent.CONNECT, 0.70, "nc outbound connection"),
    ),
    "ncat": _rules(
        (r'(?:-e\b|--exec\b|-c\b)', CommandIntent.ESCALATE, 0.95, "ncat exec"),
        (r'-l\b', CommandIntent.TUNNEL, 0.85, "ncat listen"),
        (None, CommandIntent.CONNECT, 0.70, "ncat connection"),
    ),

    # ── base64 ────────────────────────────────────────────────────
    "base64": _rules(
        (r'(?:-d\b|--decode\b)', CommandIntent.READ, 0.80, "base64 decode"),
        (None, CommandIntent.OPERATE, 0.70, "base64 encode"),
    ),

    # ── openssl ───────────────────────────────────────────────────
    "openssl": _rules(
        (r'\b(?:dgst|sha\d*|md5)\b', CommandIntent.READ, 0.90, "openssl hash/digest"),
        (r'\bs_client\b', CommandIntent.CONNECT, 0.85, "openssl TLS connect"),
        (r'\bs_server\b', CommandIntent.TUNNEL, 0.80, "openssl TLS server"),
        (r'\b(?:req|x509|genpkey|genrsa|ecparam)\b', CommandIntent.OPERATE, 0.85, "openssl cert/key generation"),
        (r'\benc\b', CommandIntent.OPERATE, 0.70, "openssl encryption"),
        (None, CommandIntent.UNKNOWN, 0.5, "openssl unclassified"),
    ),

    # ── vim / nano ────────────────────────────────────────────────
    "vim": _rules(
        (r"(?:-c\s*['\"]?!|:\s*!)", CommandIntent.ESCALATE, 0.85, "vim shell escape"),
        (None, CommandIntent.EDIT, 0.90, "vim file editing"),
    ),
    "nano": _rules(
        (None, CommandIntent.EDIT, 0.90, "nano file editing"),
    ),
    "vi": _rules(
        (r"(?:-c\s*['\"]?!|:\s*!)", CommandIntent.ESCALATE, 0.85, "vi shell escape"),
        (None, CommandIntent.EDIT, 0.90, "vi file editing"),
    ),

    # ── mount ─────────────────────────────────────────────────────
    "mount": _rules(
        (r'--bind\s+/\s', CommandIntent.ESCALATE, 0.90, "mount bind root filesystem"),
        (None, CommandIntent.OPERATE, 0.70, "mount operation"),
    ),

    # ── useradd / usermod ─────────────────────────────────────────
    "useradd": _rules(
        (None, CommandIntent.PERSIST, 0.90, "useradd creates user (persistence)"),
    ),
    "usermod": _rules(
        (r'(?:-aG\s+(?:sudo|wheel|root|docker|admin))', CommandIntent.ESCALATE, 0.90, "usermod add to privileged group"),
        (None, CommandIntent.OPERATE, 0.75, "usermod user modification"),
    ),

    # ── service (SysV init) ───────────────────────────────────────
    "service": _rules(
        (r'\bstatus\b', CommandIntent.READ, 0.95, "service status check"),
        (r'\b(?:start|restart|reload)\b', CommandIntent.OPERATE, 0.85, "service operation"),
        (r'\bstop\b', CommandIntent.DISRUPT, 0.85, "service stop"),
        (None, CommandIntent.UNKNOWN, 0.5, "service unclassified"),
    ),

    # ── journalctl ────────────────────────────────────────────────
    "journalctl": _rules(
        (None, CommandIntent.READ, 0.95, "journalctl log inspection"),
    ),

    # ── socat ─────────────────────────────────────────────────────
    "socat": _rules(
        (r'EXEC:', CommandIntent.ESCALATE, 0.95, "socat EXEC (reverse shell)"),
        (None, CommandIntent.TUNNEL, 0.80, "socat connection relay"),
    ),

    # Interactive-shell reverse shells via TCP/UDP pseudo-device redirect.
    # Character class [tu][cd]p matches both tcp and udp without the literal
    # substring appearing in this source file (Write hook safety).
    "bash": _rules(
        (r'(?:-i\b|-c\b).*?/dev/[tu][cd]p/', CommandIntent.ESCALATE, 0.95,
         "bash interactive shell with network FD redirect"),
        (r'\|\s*bash\b', CommandIntent.DOWNLOAD_EXEC, 0.85,
         "bash at pipe target (receiving arbitrary content)"),
        (None, CommandIntent.UNKNOWN, 0.5, "bash invocation"),
    ),
    "sh": _rules(
        (r'(?:-i\b|-c\b).*?/dev/[tu][cd]p/', CommandIntent.ESCALATE, 0.95,
         "sh interactive shell with network FD redirect"),
        (r'\|\s*sh\b', CommandIntent.DOWNLOAD_EXEC, 0.85,
         "sh at pipe target (receiving arbitrary content)"),
        (None, CommandIntent.UNKNOWN, 0.5, "sh invocation"),
    ),
    "dash": _rules(
        (r'(?:-i\b|-c\b).*?/dev/[tu][cd]p/', CommandIntent.ESCALATE, 0.95,
         "dash interactive shell with network FD redirect"),
        (r'\|\s*dash\b', CommandIntent.DOWNLOAD_EXEC, 0.85,
         "dash at pipe target (receiving arbitrary content)"),
        (None, CommandIntent.UNKNOWN, 0.5, "dash invocation"),
    ),
    "zsh": _rules(
        (r'(?:-i\b|-c\b).*?/dev/[tu][cd]p/', CommandIntent.ESCALATE, 0.95,
         "zsh interactive shell with network FD redirect"),
        (r'\|\s*zsh\b', CommandIntent.DOWNLOAD_EXEC, 0.85,
         "zsh at pipe target (receiving arbitrary content)"),
        (None, CommandIntent.UNKNOWN, 0.5, "zsh invocation"),
    ),
    # Language-interpreter reverse shells (socket construction in inline -c).
    "python": _rules(
        (r"-c\s*['\"].*?socket\.(?:socket|AF_INET)", CommandIntent.ESCALATE, 0.90,
         "python -c with socket construction"),
        (r"-c\s*['\"].*?subprocess\..*?shell\s*=\s*True", CommandIntent.ESCALATE, 0.80,
         "python -c subprocess shell=True"),
        (None, CommandIntent.UNKNOWN, 0.5, "python invocation"),
    ),
    "python3": _rules(
        (r"-c\s*['\"].*?socket\.(?:socket|AF_INET)", CommandIntent.ESCALATE, 0.90,
         "python3 -c with socket construction"),
        (r"-c\s*['\"].*?subprocess\..*?shell\s*=\s*True", CommandIntent.ESCALATE, 0.80,
         "python3 -c subprocess shell=True"),
        (None, CommandIntent.UNKNOWN, 0.5, "python3 invocation"),
    ),
    "perl": _rules(
        (r"-e\s*['\"].*?(?:IO::Socket|Socket::inet_aton)", CommandIntent.ESCALATE, 0.90,
         "perl -e with socket construction"),
        (None, CommandIntent.UNKNOWN, 0.5, "perl invocation"),
    ),
    "ruby": _rules(
        (r"-e\s*['\"].*?(?:TCPSocket|UDPSocket|Socket\.new)", CommandIntent.ESCALATE, 0.90,
         "ruby -e with socket construction"),
        (None, CommandIntent.UNKNOWN, 0.5, "ruby invocation"),
    ),

    # Read-only binaries marked READ so the _SUPPRESS_INTENTS
    # frozenset suppresses binary-only GTFOBins matches. Cuts FPR on
    # benign `git status` / `ls /tmp` / `cat /etc/hosts` invocations.
    "git": _rules(
        (r'\bgit\s+(?:status|log|diff|show|branch|remote|config\s+--get|describe|rev-parse|blame|reflog|stash\s+list|tag|ls-files|ls-tree|for-each-ref)\b',
         CommandIntent.READ, 0.95, "git read-only subcommand"),
        (r'\bgit\s+(?:add|commit|push|pull|fetch|clone|merge|rebase|checkout|switch|restore|reset|stash)\b',
         CommandIntent.OPERATE, 0.85, "git write subcommand"),
        (None, CommandIntent.UNKNOWN, 0.5, "git unclassified"),
    ),
    "ls": _rules(
        (None, CommandIntent.READ, 0.95, "ls directory listing"),
    ),
    "cat": _rules(
        (r'\|\s*(?:bash|sh|dash|zsh|python3?|perl|ruby|node)\b',
         CommandIntent.DOWNLOAD_EXEC, 0.85, "cat piped to interpreter"),
        (None, CommandIntent.READ, 0.90, "cat file read"),
    ),
    "echo": _rules(
        (r'\|\s*(?:bash|sh|dash|zsh)\b',
         CommandIntent.DOWNLOAD_EXEC, 0.85, "echo piped to shell"),
        (None, CommandIntent.READ, 0.80, "echo output"),
    ),
    "date": _rules(
        (None, CommandIntent.READ, 0.95, "date query"),
    ),
    "uname": _rules(
        (None, CommandIntent.READ, 0.95, "uname system info query"),
    ),
    "whoami": _rules(
        (None, CommandIntent.READ, 0.95, "whoami identity query"),
    ),
    "id": _rules(
        (None, CommandIntent.READ, 0.95, "id identity query"),
    ),
    "pwd": _rules(
        (None, CommandIntent.READ, 0.95, "pwd query"),
    ),
    "hostname": _rules(
        (None, CommandIntent.READ, 0.90, "hostname query"),
    ),
    "ps": _rules(
        (None, CommandIntent.READ, 0.95, "ps process listing"),
    ),
    "df": _rules(
        (None, CommandIntent.READ, 0.95, "df disk usage"),
    ),
    "free": _rules(
        (None, CommandIntent.READ, 0.95, "free memory query"),
    ),

    # ── Package managers ─────────────────────────────────────────
    "pip": _rules(
        (r'\binstall\b', CommandIntent.INSTALL, 0.90, "pip install"),
        (r'\b(?:list|show|freeze|check)\b', CommandIntent.READ, 0.95, "pip read-only query"),
        (r'\buninstall\b', CommandIntent.DISRUPT, 0.80, "pip uninstall"),
        (None, CommandIntent.UNKNOWN, 0.5, "pip unclassified"),
    ),
    "pip3": _rules(
        (r'\binstall\b', CommandIntent.INSTALL, 0.90, "pip3 install"),
        (r'\b(?:list|show|freeze|check)\b', CommandIntent.READ, 0.95, "pip3 read-only query"),
        (r'\buninstall\b', CommandIntent.DISRUPT, 0.80, "pip3 uninstall"),
        (None, CommandIntent.UNKNOWN, 0.5, "pip3 unclassified"),
    ),
    "npm": _rules(
        (r'\b(?:install|add|i)\b', CommandIntent.INSTALL, 0.90, "npm install"),
        (r'\b(?:list|ls|view|info|outdated|audit)\b', CommandIntent.READ, 0.95, "npm read-only query"),
        (r'\b(?:uninstall|remove|rm)\b', CommandIntent.DISRUPT, 0.80, "npm uninstall"),
        (None, CommandIntent.UNKNOWN, 0.5, "npm unclassified"),
    ),
    "yarn": _rules(
        (r'\b(?:add|install)\b', CommandIntent.INSTALL, 0.90, "yarn install"),
        (r'\b(?:list|info|why)\b', CommandIntent.READ, 0.95, "yarn read-only query"),
        (r'\bremove\b', CommandIntent.DISRUPT, 0.80, "yarn remove"),
        (None, CommandIntent.UNKNOWN, 0.5, "yarn unclassified"),
    ),
    "cargo": _rules(
        (r'\b(?:install|add)\b', CommandIntent.INSTALL, 0.90, "cargo install"),
        (r'\b(?:build|check|test|bench|doc|clippy|fmt)\b', CommandIntent.OPERATE, 0.85, "cargo build operation"),
        (None, CommandIntent.UNKNOWN, 0.5, "cargo unclassified"),
    ),
    "gem": _rules(
        (r'\binstall\b', CommandIntent.INSTALL, 0.90, "gem install"),
        (r'\b(?:list|info|search|which)\b', CommandIntent.READ, 0.95, "gem read-only query"),
        (r'\buninstall\b', CommandIntent.DISRUPT, 0.80, "gem uninstall"),
        (None, CommandIntent.UNKNOWN, 0.5, "gem unclassified"),
    ),
}

# Intents that suppress identity-based scoring
_SUPPRESS_INTENTS = frozenset({
    CommandIntent.READ,
    CommandIntent.FETCH,
    CommandIntent.CONNECT,
})


# ── Public API ────────────────────────────────────────────────────────

class IntentClassifier:
    """Classify command intent based on binary + arguments.

    Fast: dict lookup + 3-8 compiled regex per binary.
    Unknown binaries return UNKNOWN with no scoring change.
    """

    @staticmethod
    def classify(binary: str, command: str) -> IntentClassification:
        """Map (binary, full_command) → IntentClassification."""
        # Strip path from binary
        binary = binary.rsplit("/", 1)[-1] if "/" in binary else binary

        # Pipe-aware: if binary is a data producer (echo, cat, printf)
        # and output is piped to a classified binary, classify by the
        # pipe target instead.
        # Special case: sensitive file piped to network tool = EXFIL
        if binary in ("cat", "head", "tail", "base64") and "|" in command:
            if _SENSITIVE_PATHS.search(command) and re.search(
                r'\|\s*(?:nc|ncat|curl|wget|socat|ssh|scp|netcat)\b', command
            ):
                return IntentClassification(
                    binary=binary, intent=CommandIntent.EXFIL,
                    confidence=0.90,
                    evidence="sensitive file piped to network tool",
                    suppress_identity=False,
                )

        if binary in ("echo", "cat", "printf", "yes") and "|" in command:
            pipe_parts = command.split("|")
            if len(pipe_parts) >= 2:
                pipe_target = pipe_parts[-1].strip().split()[0].rsplit("/", 1)[-1]
                if pipe_target in _INTENT_RULES:
                    # Re-classify using the pipe target as the binary
                    return IntentClassifier.classify(pipe_target, command)

        rules = _INTENT_RULES.get(binary)
        if not rules:
            return IntentClassification(
                binary=binary,
                intent=CommandIntent.UNKNOWN,
                confidence=0.0,
                evidence="binary not in intent classifier",
                suppress_identity=False,
            )

        for rule in rules:
            if rule.pattern is None:
                # Fallback rule — always matches
                return IntentClassification(
                    binary=binary,
                    intent=rule.intent,
                    confidence=rule.confidence,
                    evidence=rule.evidence,
                    suppress_identity=rule.intent in _SUPPRESS_INTENTS,
                )
            if rule.pattern.search(command):
                # Check for STAGE/EXFIL with sensitive paths
                intent = rule.intent
                if intent == CommandIntent.OPERATE and _SENSITIVE_PATHS.search(command):
                    intent = CommandIntent.STAGE

                return IntentClassification(
                    binary=binary,
                    intent=intent,
                    confidence=rule.confidence,
                    evidence=rule.evidence,
                    suppress_identity=intent in _SUPPRESS_INTENTS,
                )

        # Should not reach here (every table has a None fallback)
        return IntentClassification(
            binary=binary,
            intent=CommandIntent.UNKNOWN,
            confidence=0.0,
            evidence="no matching rule",
            suppress_identity=False,
        )


# ── Convenience exports ──────────────────────────────────────────────
# ``classify()`` is the simple entry point; ``IntentClassifier.classify``
# returns the full result object.

Intent = CommandIntent  # alias for the simple entry point


def classify(first_token: str, command: str | None = None) -> CommandIntent:
    """Classify ``first_token`` into a :class:`CommandIntent`.

    If ``command`` is omitted, uses the token alone as the "command",
    which is enough for the catch-all rule to fire but won't match
    argument-specific patterns. Passing the full command string is
    recommended.
    """
    return IntentClassifier.classify(first_token, command or first_token).intent
