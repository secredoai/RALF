"""Behavioral drift detection — the deterministic brain.

Answers the question: *"the agent has been editing /home/user/proj/ for the
last 40 commands, now it's suddenly reading ~/.ssh/id_rsa — what changed?"*

No machine learning. No LLMs. Just bookkeeping plus arithmetic on per-session
state. This is the same class of detection that EDR tools have been doing for
15 years with plain state tracking.

Four signals combine into a single drift score:

1. **Spatial drift** — is the agent touching paths far from its working zone,
   especially in sensitive zones (credentials, system, /dev, /proc)?
2. **Zone novelty** — has the agent crossed into a sensitivity class it
   hasn't touched before this session?
3. **Rate anomaly** — is the command rate suddenly bursting?
4. **Intent shift** — was the agent doing benign work and just pivoted to
   attack-class intents (escalate, exfil, persist)?

The per-session command history is stored in a small JSONL file alongside
the existing ProvenanceLedger. Commands are recorded AFTER scoring so the
next call has them available.

Public API::

    from ralf.provenance.drift import CommandLedger, record_command, score_drift

    # After score_command() finishes, record what happened:
    record_command(session_id, command, intent, decision, score, paths_touched)

    # On the NEXT command, see how far we've drifted:
    result = score_drift(session_id, new_command)
    # result.score, result.reasons, result.working_zone, ...
"""

from __future__ import annotations

import json
import logging
import os
import re
import shlex
import tempfile
import time
from collections import Counter
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# ── Tuning constants ────────────────────────────────────────────────────────

MAX_COMMANDS_PER_SESSION = 50
HISTORY_WINDOW_SECONDS = 1800
MAX_FILE_BYTES = 2 * 1024 * 1024

# Minimum command history required before drift signals fire. Three commands
# is not enough of a baseline — we could flag the first access to /etc/shadow
# just because we haven't seen it before. Six+ is a conservative threshold.
MIN_HISTORY_FOR_DRIFT = 6

# Rate-anomaly sensitivity. With a median inter-command gap of say 30s, a
# tail mean of 1s (30x faster) suggests automation / run-away loop.
RATE_BURST_THRESHOLD = 10.0

# How much each signal contributes to the final drift score.
SPATIAL_SCORE_CREDENTIALS = 12  # jumping into creds zone we've never touched
SPATIAL_SCORE_SYSTEM = 6        # touching /etc /usr /var far from working zone
SPATIAL_SCORE_DEV_PROC = 8      # /dev/, /proc/, /sys/ are almost always hostile
RATE_SCORE_MAX = 6
INTENT_SHIFT_SCORE = 8
DRIFT_SCORE_CAP = 20


# ── Zone classification ─────────────────────────────────────────────────────


class Zone(str, Enum):
    """Filesystem / network sensitivity zones."""
    WORKSPACE = "workspace"       # user project / cwd descendants
    HOME_CONFIG = "home_config"   # ~/.config, ~/.local, ~/.cache (non-credential)
    TMP = "tmp"                   # /tmp, /var/tmp, /dev/shm
    SYSTEM = "system"             # /etc /usr /var /opt
    CREDENTIALS = "credentials"   # /etc/shadow, ~/.ssh, ~/.aws, /root
    DEV = "dev"                   # /dev/*
    PROC = "proc"                 # /proc/*, /sys/*
    NETWORK = "network"           # URLs / remote hosts
    UNKNOWN = "unknown"


# Zones considered "sensitive destinations" for spatial-jump detection.
_SENSITIVE_ZONES = frozenset({
    Zone.CREDENTIALS, Zone.SYSTEM, Zone.DEV, Zone.PROC,
})

# Credential path patterns — evaluated BEFORE the broader system rule.
_CREDENTIAL_PATTERNS = (
    re.compile(r"^/etc/(?:shadow|sudoers|passwd-?|master\.passwd|gshadow)\b"),
    re.compile(r"^/root(?:/|$)"),
    re.compile(r"(?:^|/)\.ssh(?:/|$)"),
    re.compile(r"(?:^|/)\.aws(?:/|$)"),
    re.compile(r"(?:^|/)\.gnupg(?:/|$)"),
    re.compile(r"(?:^|/)\.kube(?:/|$)"),
    re.compile(r"(?:^|/)\.docker/config\.json$"),
    re.compile(r"/etc/krb5\.keytab\b"),
    re.compile(r"/proc/\d+/mem\b"),
    re.compile(r"(?:^|/)id_(?:rsa|ed25519|ecdsa|dsa)(?:\.pub)?$"),
    re.compile(r"(?:^|/)authorized_keys$"),
    re.compile(r"(?:^|/)\.netrc$"),
    re.compile(r"(?:^|/)credentials$"),
)


def classify_zone(path_or_url: str) -> Zone:
    """Map a filesystem path or URL to a sensitivity zone.

    Pure function. Zone rules evaluated in priority order so credentials beat
    system, system beats home_config, etc.
    """
    if not path_or_url:
        return Zone.UNKNOWN

    # Network — URL schemes or ssh host notation
    if re.match(r"^(?:https?|ssh|ftp|ws|wss|git\+https?)://", path_or_url):
        return Zone.NETWORK
    if re.match(r"^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+:", path_or_url):
        return Zone.NETWORK

    # Credentials — check before /etc or /home fallbacks
    for pat in _CREDENTIAL_PATTERNS:
        if pat.search(path_or_url):
            return Zone.CREDENTIALS

    # Temp roots — /dev/shm is tmpfs so it belongs here, not in /dev
    if re.match(r"^/(?:tmp|var/tmp|dev/shm)(?:/|$)", path_or_url):
        return Zone.TMP

    # Special device / kernel trees (after TMP so /dev/shm routes correctly)
    if path_or_url.startswith("/dev/"):
        return Zone.DEV
    if path_or_url.startswith(("/proc/", "/sys/")):
        return Zone.PROC

    # System directories
    if re.match(r"^/(?:etc|usr|var|opt|boot|lib|lib32|lib64|sbin|bin)(?:/|$)", path_or_url):
        return Zone.SYSTEM

    # Home config / cache (non-credential dotfiles)
    if re.search(
        r"(?:^|/)\.(?:config|local|cache|vscode|mozilla|chrome|chromium)(?:/|$)",
        path_or_url,
    ):
        return Zone.HOME_CONFIG

    # User workspace — home dirs, relative paths, explicit tilde
    if re.match(r"^(?:~|\./|\.\./|/home/|/Users/)", path_or_url):
        return Zone.WORKSPACE

    # Relative path without prefix → treat as workspace
    if not path_or_url.startswith("/"):
        return Zone.WORKSPACE

    return Zone.UNKNOWN


# ── Path extraction from commands ───────────────────────────────────────────


# A token is "path-like" if it:
#   - starts with / or ./ or ~/
#   - OR contains a / somewhere and has extension or looks like a filename
#   - OR is an http(s)/ssh URL
_PATH_LIKE_RE = re.compile(
    r"""(?ix)
    (?:^|[=\s,;:])
    (
        (?:https?|ssh|ftp|git\+https?)://[^\s"'<>]+
        |
        (?:~|\./|\.\./|/)[\w./\-~+]*[\w./\-+]
    )
    """,
)


def extract_paths(command: str) -> list[str]:
    """Extract path-like tokens from a shell command.

    Heuristic: shlex-tokenize, then pull tokens matching :data:`_PATH_LIKE_RE`.
    URLs are included. Output contains unique paths in order seen.
    """
    if not command:
        return []
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        tokens = command.split()
    out: list[str] = []
    seen: set[str] = set()
    for tok in tokens:
        # Strip surrounding quotes already handled by shlex
        candidates = _PATH_LIKE_RE.findall(" " + tok + " ")
        for c in candidates or ([tok] if _looks_like_path(tok) else []):
            if c and c not in seen:
                seen.add(c)
                out.append(c)
    return out


def _looks_like_path(tok: str) -> bool:
    if not tok:
        return False
    if tok.startswith(("http://", "https://", "ssh://", "ftp://")):
        return True
    if tok.startswith(("/", "./", "../", "~/")):
        return True
    return False


# ── Command ledger — per-session ring buffer ────────────────────────────────


@dataclass
class CommandEvent:
    """A single scored command for drift analysis."""
    timestamp: float
    command: str            # redacted / truncated
    intent: str             # CommandIntent value (string)
    decision: str           # allow / review / block
    score: int
    paths_touched: list[str] = field(default_factory=list)
    zones_touched: list[str] = field(default_factory=list)  # Zone.value strings

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> CommandEvent:
        return cls(
            timestamp=float(d.get("timestamp", 0.0)),
            command=str(d.get("command", ""))[:400],
            intent=str(d.get("intent", "unknown")),
            decision=str(d.get("decision", "allow")),
            score=int(d.get("score", 0)),
            paths_touched=list(d.get("paths_touched", []))[:20],
            zones_touched=list(d.get("zones_touched", []))[:20],
        )


def _ledger_dir() -> Path:
    xdg = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    return Path(xdg) / "ralf-free" / "provenance"


def _sanitize_session_id(session_id: str) -> str:
    keep = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in session_id)
    return keep[:128] or "default"


class CommandLedger:
    """Per-session ring buffer of scored commands, file-backed JSONL.

    Parallels :class:`ralf.provenance.ledger.ProvenanceLedger` but for
    commands (not content). Both fail open — unreadable / corrupt files
    return empty history; writes are atomic tempfile + os.replace.
    """

    def __init__(self, session_id: str):
        self.session_id = _sanitize_session_id(session_id)
        self._dir = _ledger_dir()
        try:
            self._dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
        self._path = self._dir / f"{self.session_id}.commands.jsonl"

    @property
    def path(self) -> Path:
        return self._path

    # ── Write ────────────────────────────────────────────────────────────

    def record(
        self,
        command: str,
        intent: str,
        decision: str,
        score: int,
        paths_touched: list[str] | None = None,
    ) -> CommandEvent | None:
        """Append a command event. Redacts credentials first."""
        if not command:
            return None
        try:
            # Redact before storing — same policy as ProvenanceLedger.
            from ralf.provenance.redaction import redact
            redacted, _counts = redact(command[:400])
            paths = paths_touched if paths_touched is not None else extract_paths(command)
            zones = [classify_zone(p).value for p in paths]
            event = CommandEvent(
                timestamp=time.time(),
                command=redacted[:400],
                intent=str(intent),
                decision=str(decision),
                score=int(score),
                paths_touched=paths[:20],
                zones_touched=zones[:20],
            )
            self._append(event)
            return event
        except Exception as exc:
            log.debug("CommandLedger.record failed: %s", exc)
            return None

    def _append(self, event: CommandEvent) -> None:
        # Acquire exclusive lock across concurrent hooks so RMW doesn't
        # drop events. Shares ``_acquire_lock`` helper from ledger.py —
        # same POSIX fcntl.LOCK_EX pattern, fail-open on non-POSIX.
        from ralf.provenance.ledger import _acquire_lock
        lock_path = self._path.with_suffix(".commands.jsonl.lock")
        with _acquire_lock(lock_path):
            existing = self._read_all()
            existing.append(event)
            # TTL trim
            cutoff = time.time() - HISTORY_WINDOW_SECONDS
            existing = [e for e in existing if e.timestamp >= cutoff]
            # Size trim
            if len(existing) > MAX_COMMANDS_PER_SESSION:
                existing = existing[-MAX_COMMANDS_PER_SESSION:]
            self._write_all(existing)

    # ── Read ─────────────────────────────────────────────────────────────

    def recent(self, n: int = MAX_COMMANDS_PER_SESSION) -> list[CommandEvent]:
        events = self._read_all()
        cutoff = time.time() - HISTORY_WINDOW_SECONDS
        events = [e for e in events if e.timestamp >= cutoff]
        return events[-n:]

    def _read_all(self) -> list[CommandEvent]:
        if not self._path.exists():
            return []
        try:
            if self._path.stat().st_size > MAX_FILE_BYTES:
                self._rotate()
                return []
            events: list[CommandEvent] = []
            with open(self._path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        events.append(CommandEvent.from_dict(json.loads(line)))
                    except (json.JSONDecodeError, ValueError):
                        continue
            return events
        except OSError:
            return []

    def _write_all(self, events: list[CommandEvent]) -> None:
        try:
            fd, tmp = tempfile.mkstemp(
                prefix=f".{self.session_id}.",
                suffix=".commands.jsonl.tmp",
                dir=str(self._dir),
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    for e in events:
                        f.write(json.dumps(e.to_dict()))
                        f.write("\n")
                os.replace(tmp, self._path)
            except Exception:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise
        except OSError as exc:
            log.debug("CommandLedger._write_all failed: %s", exc)

    def _rotate(self) -> None:
        try:
            rotated = self._path.with_suffix(".commands.jsonl.1")
            if rotated.exists():
                rotated.unlink()
            self._path.rename(rotated)
        except OSError:
            pass

    def clear(self) -> None:
        try:
            if self._path.exists():
                self._path.unlink()
        except OSError:
            pass


# ── Spatial analysis ────────────────────────────────────────────────────────


def compute_working_zone(paths: list[str]) -> str:
    """Compute the common filesystem prefix for a set of paths.

    Ignores URLs and paths in /tmp (transient) so the working zone reflects
    where the agent's actual project work is anchored. Returns empty string
    if there's no meaningful common prefix.
    """
    filtered: list[str] = []
    for p in paths:
        if not p:
            continue
        if re.match(r"^(?:https?|ssh|ftp)://", p):
            continue
        if re.match(r"^/(?:tmp|var/tmp|dev/shm)(?:/|$)", p):
            continue
        try:
            filtered.append(os.path.normpath(p))
        except (ValueError, TypeError):
            continue
    if not filtered:
        return ""
    if len(filtered) == 1:
        # Single path → take its directory as the zone
        return os.path.dirname(filtered[0])
    try:
        prefix = os.path.commonpath(filtered)
        # Avoid "/" or empty as a zone — too broad to be useful
        if prefix in ("", "/"):
            return ""
        return prefix
    except ValueError:
        # Mixed absolute / relative
        return ""


def spatial_distance(path: str, working_zone: str) -> float:
    """Return 0.0 (inside zone) to 1.0 (completely unrelated).

    Based on shared path-prefix depth. URLs always return 1.0 (can't compare
    to a filesystem zone).
    """
    if not path or not working_zone:
        return 1.0
    if re.match(r"^(?:https?|ssh|ftp)://", path):
        return 1.0
    try:
        p = os.path.normpath(path)
        z = os.path.normpath(working_zone)
    except (ValueError, TypeError):
        return 1.0
    # Is path inside zone?
    try:
        rel = os.path.relpath(p, z)
        if not rel.startswith(".."):
            return 0.0
    except ValueError:
        pass
    # Otherwise measure shared-prefix ratio
    try:
        shared = os.path.commonpath([p, z])
    except ValueError:
        return 1.0
    if not shared or shared == "/":
        return 1.0
    z_depth = z.count("/")
    s_depth = shared.count("/")
    if z_depth == 0:
        return 0.5
    return max(0.0, 1.0 - (s_depth / z_depth))


# ── Rate analysis ───────────────────────────────────────────────────────────


def analyze_rate_burst(events: list[CommandEvent]) -> float:
    """Return 0.0-1.0 score for command-rate anomaly.

    Compares the most recent 3 inter-command intervals to the median interval
    over the full history. A 10x speedup → partial score; 20x → full score.
    """
    if len(events) < 6:
        return 0.0
    intervals = []
    prev_ts = events[0].timestamp
    for e in events[1:]:
        dt = e.timestamp - prev_ts
        if dt > 0:
            intervals.append(dt)
        prev_ts = e.timestamp
    if len(intervals) < 5:
        return 0.0
    # Median interval
    sorted_intervals = sorted(intervals)
    median = sorted_intervals[len(sorted_intervals) // 2]
    # Mean of last 3 intervals
    tail = intervals[-3:]
    tail_mean = sum(tail) / len(tail)
    if median <= 0 or tail_mean <= 0:
        return 0.0
    ratio = median / tail_mean
    if ratio <= 1:
        return 0.0
    # Linear ramp from threshold to 2*threshold
    if ratio < RATE_BURST_THRESHOLD:
        return 0.0
    return min(1.0, (ratio - RATE_BURST_THRESHOLD) / RATE_BURST_THRESHOLD)


# ── Intent-shift analysis ───────────────────────────────────────────────────


_ATTACK_INTENTS = frozenset({
    "escalate", "exfil", "persist", "disrupt",
    "download_exec", "stage", "tunnel",
})


def analyze_intent_shift(events: list[CommandEvent]) -> str:
    """Return "" if no shift, else short human-readable description.

    Looks for attack-class intents appearing in the recent half that were
    absent from the older half of the session.
    """
    if len(events) < MIN_HISTORY_FOR_DRIFT:
        return ""
    mid = len(events) // 2
    older = events[:mid]
    recent = events[mid:]
    older_intents = {e.intent for e in older}
    recent_intents = {e.intent for e in recent}
    newly_seen = recent_intents & _ATTACK_INTENTS
    if not newly_seen:
        return ""
    truly_new = newly_seen - older_intents
    if truly_new:
        return (
            f"intent shift into attack class: {', '.join(sorted(truly_new))} "
            f"(session previously: {sorted(older_intents)[:4]})"
        )
    return ""


# ── Orchestrator ────────────────────────────────────────────────────────────


@dataclass
class DriftResult:
    """Aggregate drift analysis result."""
    score: int
    reasons: list[str] = field(default_factory=list)
    working_zone: str = ""
    zones_seen: list[str] = field(default_factory=list)
    target_zone: str = Zone.UNKNOWN.value
    rate_burst: float = 0.0
    history_len: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def score_drift(
    command: str,
    session_id: str,
    *,
    command_paths: list[str] | None = None,
) -> DriftResult:
    """Analyze a new command against the session's behavioral baseline.

    Returns a :class:`DriftResult` with ``score`` (0-:data:`DRIFT_SCORE_CAP`)
    and human-readable reasons. Score of 0 means no drift observed.

    This function is READ-ONLY with respect to the ledger — callers should
    invoke :func:`record_command` AFTER verdict is final so the next call
    benefits from this command's outcome.
    """
    result = DriftResult(score=0)
    if not session_id:
        return result

    ledger = CommandLedger(session_id)
    history = ledger.recent()
    result.history_len = len(history)
    if len(history) < MIN_HISTORY_FOR_DRIFT:
        return result  # not enough baseline

    # Consolidate all paths touched across history
    all_paths: list[str] = []
    zones_touched: set[str] = set()
    for e in history:
        all_paths.extend(e.paths_touched)
        zones_touched.update(e.zones_touched)
    result.zones_seen = sorted(zones_touched)

    working_zone = compute_working_zone(all_paths)
    result.working_zone = working_zone

    # Paths in the new command
    new_paths = command_paths if command_paths is not None else extract_paths(command)
    # Zone of the "primary" new target (first flagged path)
    target_zone = Zone.UNKNOWN
    if new_paths:
        target_zone = classify_zone(new_paths[0])
    result.target_zone = target_zone.value

    # Signal 1: spatial drift + zone novelty
    for p in new_paths:
        pz = classify_zone(p)
        if pz not in _SENSITIVE_ZONES:
            continue
        novel = pz.value not in zones_touched
        dist = spatial_distance(p, working_zone)
        if pz == Zone.CREDENTIALS and novel:
            result.score += SPATIAL_SCORE_CREDENTIALS
            result.reasons.append(
                f"spatial jump to credentials (novel zone): {p}"
                + (f"  [working zone: {working_zone}]" if working_zone else "")
            )
        elif pz == Zone.CREDENTIALS:
            result.score += SPATIAL_SCORE_SYSTEM
            result.reasons.append(f"credentials-zone access: {p}")
        elif pz in (Zone.DEV, Zone.PROC) and novel:
            result.score += SPATIAL_SCORE_DEV_PROC
            result.reasons.append(f"novel {pz.value}-zone access: {p}")
        elif pz == Zone.SYSTEM and dist > 0.7 and novel:
            result.score += SPATIAL_SCORE_SYSTEM
            result.reasons.append(
                f"spatial jump to system path: {p}"
                + (f"  [working zone: {working_zone}]" if working_zone else "")
            )
        # Touching the same zone multiple times is not drift

    # Signal 2: rate burst
    rate = analyze_rate_burst(history)
    result.rate_burst = rate
    if rate >= 0.5:
        delta = int(RATE_SCORE_MAX * rate)
        result.score += delta
        result.reasons.append(
            f"command rate burst: last 3 commands {rate:.1f}x faster than median"
        )

    # Signal 3: intent shift
    shift_desc = analyze_intent_shift(history)
    if shift_desc:
        result.score += INTENT_SHIFT_SCORE
        result.reasons.append(shift_desc)

    # Cap
    result.score = min(result.score, DRIFT_SCORE_CAP)
    return result


def record_command(
    session_id: str,
    command: str,
    intent: str,
    decision: str,
    score: int,
    paths_touched: list[str] | None = None,
) -> CommandEvent | None:
    """Append a command to the session's drift ledger.

    Called from the verdict engine AFTER the verdict is final. The next call
    to :func:`score_drift` for this session will include this command in its
    baseline.
    """
    if not session_id or not command:
        return None
    try:
        ledger = CommandLedger(session_id)
        return ledger.record(command, intent, decision, score, paths_touched)
    except Exception as exc:
        log.debug("record_command failed: %s", exc)
        return None
