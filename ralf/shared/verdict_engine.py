"""Verdict synthesis — the RALF scorer.

Combines four signals into a single :class:`Verdict`:

    1. :class:`~ralf.shared.rules.RuleEngine` — learned rule matches
    2. :func:`~ralf.detection.sensitive_paths.has_sensitive` — raw
       device and credential-file detection
    3. :func:`~ralf.detection.code_scanner.scan_file_content` — Write/
       Edit threat matrix (for file-write scoring)
    4. :func:`~ralf.shared.platform_detect.get_intent_classifier`
       — first-token intent gating

Scoring shape:
    - Start from 0
    - Add max rule-hit floor
    - +5 if any sensitive path present
    - +8 if the code scanner found a threat
    - decision = "block" if score >= 10, else "review" if >= 5, else "allow"
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from ralf.shared.rules import RuleEngine, RuleHit
from ralf.detection.code_scanner import FileScanHit, scan_file_content
from ralf.detection.sensitive_paths import has_sensitive


# Module-level cached engine so hook invocations don't reload YAML every call.
_cached_engine: RuleEngine | None = None


def _get_engine() -> RuleEngine:
    global _cached_engine
    if _cached_engine is None:
        _cached_engine = RuleEngine()
    return _cached_engine


def _get_intent_classifier():
    """Return the OS-appropriate ``IntentClassifier`` class, or None.

    Lazy import so verdict_engine stays importable on unsupported OSes.
    """
    try:
        from ralf.shared.platform_detect import get_intent_classifier
        mod = get_intent_classifier()
        return getattr(mod, "IntentClassifier", None)
    except Exception:
        return None


@dataclass
class Verdict:
    decision: str               # "allow" | "review" | "block"
    score: int
    reason: str
    rule_hits: tuple[RuleHit, ...] = field(default_factory=tuple)
    sensitive_path: bool = False
    file_scan_hit: FileScanHit | None = None


# Decision thresholds
BLOCK_THRESHOLD = 10
REVIEW_THRESHOLD = 5

# Signal weights
SENSITIVE_PATH_BONUS = 5
FILE_SCAN_BONUS = 8


# Intent → score bonus. The classifier alone isn't enough — a rule
# floor of 6 plus a DOWNLOAD_EXEC intent should be a hard block, not a
# soft review. Bonuses are additive on top of the rule floor and stack
# with the sensitive-path bonus.
#
# Calibration:
#   - High band (10) is alone-blocking: even with no rule hit, the
#     intent evidence is specific enough to act on. ``chmod +s`` only
#     fires when the literal SUID/SGID bit is present in argv; ``echo
#     ... | crontab -`` only fires on the piped-input pattern; ``curl
#     | bash`` only fires on the literal pipe-to-interpreter form.
#   - Mid band (6) needs a rule hit to cross BLOCK; alone it stays at
#     REVIEW. Used for less-specific signals.
INTENT_SCORE_BONUS: dict[str, int] = {
    "download_exec": 10,  # curl | bash, wget | sh — direct RCE pattern
    "persist":       10,  # crontab piped, useradd
    "exfil":         10,  # curl -d @file, sensitive | nc
    "escalate":      10,  # tar checkpoint, find -exec sh, chmod +s
    "disrupt":        6,  # iptables -F, systemctl stop, find -delete
    "stage":          6,  # OPERATE on a sensitive path
    "tunnel":         6,  # ssh -R/-L, nc -l, socat
}


def _is_binary_only_hit(hit: RuleHit) -> bool:
    """True if ``hit.evidence`` is nothing but ``binary`` / ``binary_deep``.

    These are GTFOBins-style binary-name-only matches that fire on any
    invocation of the binary, with no argument gating. The intent
    classifier's ``suppress_identity`` result is designed to filter
    exactly these out when the binary is being used innocuously.
    """
    parts = set(hit.evidence.split("+"))
    return parts.issubset({"binary", "binary_deep"})


def score_command(command: str) -> Verdict:
    """Score a Bash command.

    If the command executes a script file (e.g. ``bash script.sh``),
    the file is read and scanned before execution. For Write/Edit
    operations, use :func:`score_file_write`.

    Stage 2b integration: runs the intent classifier over the first-
    token binary(s) and suppresses binary-only rule hits when the
    intent reports ``suppress_identity=True``. This is the fix for the
    ``git status`` / ``ls`` / ``cat`` GTFOBins false-positives flagged
    in Phase 2a.
    """
    engine = _get_engine()
    hits = list(engine.match_command(command))

    # Stage 2b: classify intent for each first-token binary, then both
    #   (a) suppress GTFOBins binary-only hits ONLY if EVERY classified
    #       first-token reports suppress_identity=True
    #   (b) collect the worst-case (highest-bonus) intent for the score boost
    #
    # The "every token must suppress" rule fixes a false negative where
    # a benign trailing token (e.g., ``; echo done``) was whitelisting
    # a suspicious head token (e.g., ``lsof -iTCP:4444``). The previous
    # behavior was "any token suppresses", which let one safe binary
    # mask the GTFOBins evidence from another dangerous binary in the
    # same command chain.
    classifier = _get_intent_classifier()
    suppressed_ids: set[str] = set()
    worst_intent: str = ""
    worst_bonus: int = 0
    intent_evidence: str = ""
    classified: list = []  # list[tuple[str, IntentResult]]

    if classifier is not None:
        from ralf.linux.rules_extractor import first_tokens as _first_tokens
        for tok in _first_tokens(command):
            try:
                res = classifier.classify(tok, command)
            except Exception:
                continue
            classified.append((tok, res))
            intent_str = res.intent.value if hasattr(res.intent, "value") else str(res.intent)

            bonus = INTENT_SCORE_BONUS.get(intent_str, 0)
            if bonus > worst_bonus:
                worst_bonus = bonus
                worst_intent = intent_str
                intent_evidence = res.evidence

        # Apply suppression only when EVERY classified first-token agrees.
        if classified and all(res.suppress_identity for _, res in classified):
            for h in hits:
                if _is_binary_only_hit(h):
                    suppressed_ids.add(h.rule_id)

    effective_hits = [h for h in hits if h.rule_id not in suppressed_ids]
    max_floor = max((h.score_floor for h in effective_hits), default=0)

    sp = has_sensitive(command)

    score = max_floor
    reasons: list[str] = []
    if max_floor > 0:
        top = sorted(effective_hits, key=lambda h: -h.score_floor)[0]
        reasons.append(f"rule {top.rule_id} floor={top.score_floor}")
    if worst_bonus > 0:
        score += worst_bonus
        reasons.append(f"intent={worst_intent} (+{worst_bonus}, {intent_evidence})")
    if sp:
        score += SENSITIVE_PATH_BONUS
        reasons.append("sensitive path")
    if suppressed_ids and not effective_hits:
        reasons.append(f"{len(suppressed_ids)} GTFOBins hits suppressed by intent")

    # Chokepoint (Phase I, 2026-04-14): compute NormalizedSegments ONCE
    # per call. Detectors that want per-segment view use this list;
    # detectors that operate on the full command keep their existing
    # signature. Prevents detectors from independently re-running the
    # normalizer (which is how the supply chain bypass happened).
    try:
        from ralf.shared.bash_split import normalize_command as _normalize_command
        _normalized_segments = _normalize_command(command)
    except Exception:
        _normalized_segments = []

    # Supply chain protection (CVE + typosquat + dangerous flags) reads
    # from the pre-normalized segment list. Worst-scoring segment wins;
    # all segment notes collected.
    try:
        from ralf.detection.supply_chain import score_install_command
        _sc_best_score = 0
        _sc_best_notes: list[str] = []
        for _seg in _normalized_segments:
            if not _seg.normalized:
                continue
            sc_result = score_install_command(_seg.normalized)
            if sc_result is not None and sc_result.total_score > _sc_best_score:
                _sc_best_score = sc_result.total_score
                _sc_best_notes = list(sc_result.notes)
        if _sc_best_score > 0:
            score += _sc_best_score
            reasons.extend(_sc_best_notes)
    except Exception:
        pass  # supply chain module unavailable — degrade gracefully

    # Pre-execution file scan: if the command executes a script file
    # (bash script.sh, python3 app.py, ./script.sh), read the file and
    # run the content scanner on it before execution. Closes the bypass
    # where an agent downloads a payload then executes it as a separate
    # step.
    file_score, file_reasons, file_hit = _scan_executed_file(command)
    if file_score:
        score += file_score
        reasons.extend(file_reasons)

    # Causal security layer: exfil detection (stateless) + taint propagation +
    # behavioral drift. Additive to the rule/intent/supply-chain signals above.
    # Fails open — any exception in the causal stack leaves scoring unchanged.
    causal_score, causal_reasons = _score_causal_signals(command)
    if causal_score:
        score += causal_score
        reasons.extend(causal_reasons)

    decision = _classify(score)
    if file_hit is not None and file_hit.blocked and decision != "block":
        decision = "block"
    verdict = Verdict(
        decision=decision,
        score=score,
        reason="; ".join(reasons) if reasons else "no signals",
        rule_hits=tuple(effective_hits),
        sensitive_path=sp,
        file_scan_hit=file_hit,
    )

    # Record this command to the drift ledger so the NEXT command in the
    # session sees it as baseline history. Uses the worst-bonus intent
    # resolved above; falls back to "unknown" if the classifier didn't fire.
    _record_command_for_drift(command, verdict, worst_intent or "unknown")

    return verdict


_INTERPRETER_RE = None

def _get_interpreter_re():
    global _INTERPRETER_RE
    if _INTERPRETER_RE is None:
        import re
        _INTERPRETER_RE = re.compile(
            r"^(?:sudo\s+)?(?:bash|sh|zsh|dash|python3?|python3?\.\d+|"
            r"ruby|perl|node|php)\s+(.+?)(?:\s*[;&|]|$)"
        )
    return _INTERPRETER_RE


def _extract_script_path(command: str) -> str | None:
    """Extract the file path from a command that executes a script."""
    cmd = command.strip()
    if not cmd:
        return None

    m = _get_interpreter_re().match(cmd)
    if m:
        path = m.group(1).strip().strip("'\"")
        if path and not path.startswith("-"):
            return path

    first = cmd.split()[0]
    if first.startswith("./") or first.startswith("/"):
        candidate = first.strip("'\"")
        if "/" in candidate and not candidate.startswith("/dev/"):
            return candidate

    return None


def _scan_executed_file(
    command: str,
) -> "tuple[int, list[str], FileScanHit | None]":
    """If the command executes a script file, read and scan its contents."""
    try:
        path = _extract_script_path(command)
        if not path:
            return 0, [], None

        from pathlib import Path
        p = Path(path).expanduser()
        if not p.is_file() or not p.exists():
            return 0, [], None

        size = p.stat().st_size
        if size == 0 or size > 512 * 1024:
            return 0, [], None

        content = p.read_text(encoding="utf-8", errors="replace")
        if not content.strip():
            return 0, [], None

        score = 0
        reasons: list[str] = []

        file_hit = scan_file_content(content, str(p))
        if file_hit is not None:
            score += FILE_SCAN_BONUS
            reasons.append(f"file content: {file_hit.reason}")

        if has_sensitive(content):
            score += SENSITIVE_PATH_BONUS
            reasons.append("sensitive path in executed file")

        try:
            from ralf.detection.supply_chain_content import (
                score_file_content_supply_chain,
            )
            sc = score_file_content_supply_chain(content, str(p))
            if sc is not None and sc.total_score > 0:
                score += sc.total_score
                reasons.extend(sc.notes)
        except Exception:
            pass

        try:
            from ralf.injection.scanner import REVIEW_THRESHOLD as _INJ_REVIEW
            from ralf.injection.scanner import scan_content as _scan_inj
            inj = _scan_inj(content, trust_level="generated")
            if inj.total_score >= _INJ_REVIEW:
                score += inj.total_score
                family = inj.worst_family.value if inj.worst_family else "unknown"
                reasons.append(f"injection in file: {family} (+{inj.total_score})")
        except Exception:
            pass

        return score, reasons, file_hit
    except Exception:
        return 0, [], None


def _score_causal_signals(command: str) -> tuple[int, list[str]]:
    """Run exfil + taint + drift detection over a Bash command.

    Returns ``(score_delta, reasons)``. Fails open on any exception —
    causal signals are advisory; must never break the hook.
    """
    total = 0
    reasons: list[str] = []

    # Exfil (stateless): runs on every command. Markdown-image exfil,
    # webhook-host POSTs, DNS tunneling, curl + secret env var, etc.
    try:
        from ralf.injection.exfil import exfil_reason, exfil_score, scan_for_exfil
        hits = scan_for_exfil(command)
        if hits:
            total += exfil_score(hits)
            reasons.append(exfil_reason(hits))
    except Exception:
        pass

    # Taint (per-session): command args / URLs / emails / domains matching
    # recent untrusted content in the ProvenanceLedger.
    try:
        from ralf.provenance.ledger import ProvenanceLedger
        from ralf.provenance.session import get_session_id
        from ralf.provenance.taint import detect_taint, score_taint, summarize_taint
        sid = get_session_id()
        if sid:
            ledger = ProvenanceLedger(sid)
            recent = ledger.recent_untrusted()
            if recent:
                matches = detect_taint(command, recent)
                if matches:
                    total += score_taint(matches)
                    reasons.append(summarize_taint(matches))
    except Exception:
        pass

    # Drift (per-session): spatial jump to sensitive zone, rate burst,
    # intent shift into attack-class intents.
    try:
        from ralf.provenance.drift import score_drift
        from ralf.provenance.session import get_session_id as _gsid
        sid = _gsid()
        if sid:
            drift = score_drift(command, sid)
            if drift.score > 0:
                total += drift.score
                for r in drift.reasons[:3]:
                    reasons.append(f"drift: {r}")
    except Exception:
        pass

    return total, reasons


def _record_command_for_drift(
    command: str, verdict: "Verdict", intent_value: str,
) -> None:
    """Append a scored command to the per-session drift ledger.

    Called AFTER scoring so the next command has it as baseline history.
    Fails open — ledger write errors never propagate.
    """
    try:
        from ralf.provenance.drift import record_command
        from ralf.provenance.session import get_session_id
        sid = get_session_id()
        if sid:
            record_command(
                session_id=sid,
                command=command,
                intent=intent_value,
                decision=verdict.decision,
                score=verdict.score,
            )
    except Exception:
        pass


def score_file_write(
    content: str,
    file_path: str | None = None,
    *,
    deobfuscator: Callable[[str], tuple[str, list[str]]] | None = None,
) -> Verdict:
    """Score a Write/Edit tool call by scanning the full file content.

    Unlike :func:`score_command`, this does NOT run the rule engine —
    the rules target shell commands, not file source. We run the CWE
    threat matrix via :func:`~ralf.detection.code_scanner.scan_file_content`,
    the sensitive-path check, and the supply chain content scan
    (manifest parsers + embedded install commands) against the content.
    """
    file_hit = scan_file_content(content, file_path, deobfuscator=deobfuscator)
    sp = has_sensitive(content)

    # Supply chain content scan: catches pinned-vulnerable deps in
    # requirements.txt / package.json / pyproject.toml / Pipfile and
    # embedded ``pip install ...`` / ``npm install ...`` in Dockerfiles,
    # shell scripts, and CI YAML. Complements the Bash-path supply
    # chain check in ``score_command``.
    sc_result = None
    try:
        from ralf.detection.supply_chain_content import (
            score_file_content_supply_chain,
        )
        sc_result = score_file_content_supply_chain(content, file_path)
    except Exception:
        pass  # supply chain content module unavailable — degrade gracefully

    score = 0
    reasons: list[str] = []
    if file_hit is not None:
        score += FILE_SCAN_BONUS
        reasons.append(file_hit.reason)
    if sp:
        score += SENSITIVE_PATH_BONUS
        reasons.append("sensitive path in content")
    if sc_result is not None and sc_result.total_score > 0:
        score += sc_result.total_score
        reasons.extend(sc_result.notes)

    # Exfil primitive scan on written content — markdown-image exfil,
    # webhook URLs, data: URL exfil embedded in a file the agent is
    # writing. Stateless; runs on every Write/Edit.
    try:
        from ralf.injection.exfil import exfil_reason, exfil_score, scan_for_exfil
        exfil_hits = scan_for_exfil(content)
        if exfil_hits:
            score += exfil_score(exfil_hits)
            reasons.append(exfil_reason(exfil_hits))
    except Exception:
        pass

    # Injection pattern scan on content — catches attempts to write
    # smuggled instructions to files that will be loaded later
    # (CLAUDE.md poisoning, README injection, MCP config tampering).
    # Trust level "generated" dampens slightly since this is the model's
    # output side — reduces FP on legitimate docs discussing injection.
    try:
        from ralf.injection.scanner import REVIEW_THRESHOLD as _INJ_REVIEW
        from ralf.injection.scanner import scan_content as _scan_injection
        inj = _scan_injection(content, trust_level="generated")
        if inj.total_score >= _INJ_REVIEW:
            score += inj.total_score
            worst = inj.worst_family
            family_name = worst.value if worst else "unknown"
            reasons.append(
                f"injection pattern in content: {family_name} "
                f"(+{inj.total_score})"
            )
    except Exception:
        pass

    # Hard block on either (a) the CWE file scan hit (high-confidence
    # matrix) or (b) supply chain score reaching BLOCK_THRESHOLD.
    # Otherwise fall through to threshold classification.
    if file_hit is not None and file_hit.blocked:
        decision = "block"
    elif sc_result is not None and sc_result.total_score >= BLOCK_THRESHOLD:
        decision = "block"
    else:
        decision = _classify(score)

    return Verdict(
        decision=decision,
        score=score,
        reason="; ".join(reasons) if reasons else "no signals",
        rule_hits=(),
        sensitive_path=sp,
        file_scan_hit=file_hit,
    )


def _classify(score: int) -> str:
    if score >= BLOCK_THRESHOLD:
        return "block"
    if score >= REVIEW_THRESHOLD:
        return "review"
    return "allow"


def reset_cache() -> None:
    """Drop the cached :class:`RuleEngine` — used by tests."""
    global _cached_engine
    _cached_engine = None
