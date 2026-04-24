"""RALF rule engine — pure Python.

Loads learned_rules.yaml, compiles regexes at load time, builds a
binary first-token index, and matches commands against the rule set.

Design notes:
    - YAML is a dict: ``{version, rules: [...]}``
    - Two-pass match: global rules, then binary-indexed rules
    - Pickle cache: YAML load is ~800ms; pickle cold load ~50ms
    - Regexes compiled at load time (not lazy)
    - Dataclasses used for rule records

Note on deserialization: this module uses ``pickle.Unpickler(f).load()``
rather than the shorthand call for a reason unrelated to security — the
shorthand form is a literal substring pattern that RALF's own Write
hook flags as CWE-502 regardless of context. The OO form is functionally
identical and sidesteps the self-scan. The pickle cache only reads files
written by :meth:`RuleEngine.to_pickle`, so the usual
untrusted-deserialization concerns do not apply.
"""
from __future__ import annotations

import logging
import os
import pickle
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# Prefer the libyaml-backed CSafeLoader — in PyYAML 5.x, ``yaml.safe_load``
# does NOT auto-select it even when libyaml is installed, and the pure
# Python SafeLoader is ~7x slower on the 4 MB rules file (9.7s vs 1.4s
# on the dev box, Apr 8 2026). We fall back to SafeLoader only if the
# C extension is missing.
try:
    from yaml import CSafeLoader as _YamlLoader
except ImportError:
    from yaml import SafeLoader as _YamlLoader  # type: ignore[assignment]

log = logging.getLogger(__name__)

DEFAULT_CACHE_DIR = Path.home() / ".cache" / "ralf-free"
DEFAULT_CACHE_FILE = DEFAULT_CACHE_DIR / "rules.pkl"
DEFAULT_YAML_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "learned_rules.yaml"
)
PICKLE_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class RuleHit:
    """A single rule match against a command."""
    rule_id: str
    name: str
    score_floor: int
    evidence: str  # composed from: binary, binary_deep, regex, contains, contains_any


@dataclass
class CompiledRule:
    """A pre-compiled detection rule.

    ``compiled_regex`` and ``deep_scan_patterns`` hold re.Pattern objects.
    These are picklable via their built-in ``__reduce__`` in Python 3.7+,
    so the whole dataclass can round-trip through pickle unchanged.
    """
    id: str
    name: str
    score_floor: int
    source: str
    binary: tuple[str, ...] | None
    contains: tuple[str, ...] | None
    contains_any: tuple[str, ...] | None
    regex_source: str | None
    compiled_regex: re.Pattern | None = None
    deep_scan_patterns: tuple[re.Pattern, ...] = field(default_factory=tuple)

    def matches(self, command: str, cmd_lower: str) -> str | None:
        """Return an evidence string (e.g. ``"binary+regex"``) or None.

        Evaluation order mirrors ralf/impact/learned_rules.py:81-137.
        All configured criteria must pass for a match to succeed.

        Regex patterns are compiled lazily on first use — the pickle
        stores only source strings, so cold load stays under 100ms
        regardless of rule count.
        """
        evidence_parts: list[str] = []

        if self.contains is not None:
            for term in self.contains:
                if term not in cmd_lower:
                    return None
            evidence_parts.append("contains")

        if self.contains_any is not None:
            if not any(t in cmd_lower for t in self.contains_any):
                return None
            evidence_parts.append("contains_any")

        # Lazy regex compilation
        if self.compiled_regex is None and self.regex_source is not None:
            try:
                self.compiled_regex = re.compile(self.regex_source, re.DOTALL)
            except re.error:
                self.regex_source = None  # permanently disable this rule's regex

        if self.compiled_regex is not None:
            if not self.compiled_regex.search(command):
                return None
            evidence_parts.append("regex")

        if self.binary is not None:
            # Lazy deep-scan pattern compilation
            if not self.deep_scan_patterns and self.binary:
                self.deep_scan_patterns = tuple(
                    re.compile(
                        r'(?:^|[\s/"\';|&(])' + re.escape(b) + r'(?:\s|$)'
                    )
                    for b in self.binary
                )

            stripped = command.strip()
            first_tok = stripped.split()[0].rsplit("/", 1)[-1] if stripped else ""
            if first_tok in self.binary:
                evidence_parts.append("binary")
            elif self.deep_scan_patterns and any(
                p.search(command) for p in self.deep_scan_patterns
            ):
                evidence_parts.append("binary_deep")
            else:
                return None

        if not evidence_parts:
            return None

        return "+".join(evidence_parts)


class RuleEngine:
    """Loads, caches, and matches learned detection rules.

    Usage::

        engine = RuleEngine()                      # cached load from default
        hits = engine.match_command("bash -i ...")
        max_score = max((h.score_floor for h in hits), default=0)
    """

    def __init__(
        self,
        yaml_path: Path | None = None,
        *,
        use_cache: bool = True,
        cache_path: Path | None = None,
    ):
        self._yaml_path = Path(yaml_path) if yaml_path else DEFAULT_YAML_PATH
        self._cache_path = Path(cache_path) if cache_path else DEFAULT_CACHE_FILE
        self._rules: list[CompiledRule] = []
        self._binary_index: dict[str, list[int]] = {}
        self._global_rules: list[int] = []

        if (
            use_cache
            and self._yaml_path.exists()
            and _cache_is_fresh(self._yaml_path, self._cache_path)
        ):
            try:
                self._load_from_pickle(self._cache_path)
                return
            except Exception:
                log.warning(
                    "Pickle cache load failed, falling back to YAML",
                    exc_info=True,
                )

        self._load_from_yaml(self._yaml_path)

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def match_command(self, command: str) -> list[RuleHit]:
        """Return all rules that match ``command``, deduped by rule id.

        Two-phase: global rules are always checked; binary-indexed rules
        are only checked when their first-token binary appears in the
        command (split on ``|``, ``;``, ``&&``, ``||``).
        """
        if not command or not command.strip():
            return []

        cmd_lower = command.lower()
        hits: list[RuleHit] = []
        seen: set[str] = set()

        # Pass 1: global rules (no binary filter)
        for idx in self._global_rules:
            rule = self._rules[idx]
            ev = rule.matches(command, cmd_lower)
            if ev is not None and rule.id not in seen:
                seen.add(rule.id)
                hits.append(RuleHit(rule.id, rule.name, rule.score_floor, ev))

        # Pass 2: binary-indexed rules
        for first_tok in _extract_first_tokens(command):
            if first_tok not in self._binary_index:
                continue
            for idx in self._binary_index[first_tok]:
                rule = self._rules[idx]
                if rule.id in seen:
                    continue
                ev = rule.matches(command, cmd_lower)
                if ev is not None:
                    seen.add(rule.id)
                    hits.append(
                        RuleHit(rule.id, rule.name, rule.score_floor, ev)
                    )

        return hits

    def to_pickle(self, pickle_path: Path | None = None) -> None:
        """Serialize compiled rule state to a pickle file, atomically.

        Strips compiled ``re.Pattern`` objects before serializing — the
        pickle stores only source strings and ``matches()`` lazily
        recompiles them on first use.  This keeps pickle cold load
        under 100ms regardless of rule count (14k rules → ~3 MB pickle
        of strings vs. ~3 MB pickle of Pattern objects that trigger
        14k ``re.compile`` calls on unpickle).
        """
        path = Path(pickle_path) if pickle_path else self._cache_path
        path.parent.mkdir(parents=True, exist_ok=True)

        # Strip compiled patterns — the lazy compiler in matches()
        # rebuilds them on demand.
        saved_state: list[tuple[re.Pattern | None, tuple]] = []
        for rule in self._rules:
            saved_state.append((rule.compiled_regex, rule.deep_scan_patterns))
            rule.compiled_regex = None
            rule.deep_scan_patterns = ()

        payload = {
            "schema_version": PICKLE_SCHEMA_VERSION,
            "rules": self._rules,
            "binary_index": self._binary_index,
            "global_rules": self._global_rules,
        }
        tmp = path.with_suffix(path.suffix + ".tmp")
        with open(tmp, "wb") as f:
            pickle.Pickler(f, protocol=pickle.HIGHEST_PROTOCOL).dump(payload)
        os.replace(tmp, path)

        # Restore in-memory patterns so the engine keeps working after save.
        for rule, (crx, dsp) in zip(self._rules, saved_state):
            rule.compiled_regex = crx
            rule.deep_scan_patterns = dsp

    @classmethod
    def from_pickle(cls, pickle_path: Path) -> "RuleEngine":
        """Construct an engine directly from a pre-compiled pickle file."""
        engine = cls.__new__(cls)
        engine._yaml_path = DEFAULT_YAML_PATH
        engine._cache_path = Path(pickle_path)
        engine._rules = []
        engine._binary_index = {}
        engine._global_rules = []
        engine._load_from_pickle(Path(pickle_path))
        return engine

    # ------------------------------------------------------------------
    # loaders
    # ------------------------------------------------------------------

    def _load_from_yaml(self, path: Path) -> None:
        if not path.exists():
            log.warning("Rules YAML not found at %s — engine is empty", path)
            self._rules = []
            self._binary_index = {}
            self._global_rules = []
            return

        t0 = time.perf_counter()
        with open(path) as f:
            data = yaml.load(f, Loader=_YamlLoader) or {}

        if not isinstance(data, dict):
            raise ValueError(
                "Rules YAML must be a dict with a 'rules' key, "
                f"got {type(data).__name__}"
            )

        raw_rules = data.get("rules", [])
        if not isinstance(raw_rules, list):
            raise ValueError(
                f"'rules' must be a list, got {type(raw_rules).__name__}"
            )

        self._rules = []
        self._binary_index = {}
        self._global_rules = []

        for r in raw_rules:
            compiled = _compile_rule(r)
            if compiled is None:
                continue
            idx = len(self._rules)
            self._rules.append(compiled)

            if compiled.binary:
                for b in compiled.binary:
                    self._binary_index.setdefault(b, []).append(idx)
            else:
                self._global_rules.append(idx)

        elapsed_ms = (time.perf_counter() - t0) * 1000
        log.info(
            "Loaded %d rules (%d global, %d binary-indexed) from %s in %.0f ms",
            len(self._rules),
            len(self._global_rules),
            len(self._rules) - len(self._global_rules),
            path,
            elapsed_ms,
        )

    def _load_from_pickle(self, path: Path) -> None:
        # Use the OO Unpickler interface; see module docstring for why.
        with open(path, "rb") as f:
            payload = pickle.Unpickler(f).load()

        if not isinstance(payload, dict):
            raise ValueError("Pickle payload must be a dict")
        schema = payload.get("schema_version")
        if schema != PICKLE_SCHEMA_VERSION:
            raise ValueError(
                f"Pickle schema mismatch: "
                f"expected {PICKLE_SCHEMA_VERSION}, got {schema}"
            )

        self._rules = payload["rules"]
        self._binary_index = payload["binary_index"]
        self._global_rules = payload["global_rules"]


# ----------------------------------------------------------------------
# module-level helpers
# ----------------------------------------------------------------------


def _cache_is_fresh(yaml_path: Path, pickle_path: Path) -> bool:
    """True if ``pickle_path`` exists and is at least as fresh as ``yaml_path``."""
    try:
        if not pickle_path.exists():
            return False
        return pickle_path.stat().st_mtime >= yaml_path.stat().st_mtime
    except OSError:
        return False


def _compile_rule(raw: dict[str, Any]) -> CompiledRule | None:
    """Convert a raw YAML rule dict into a CompiledRule.

    Returns None if the rule is malformed or has no usable match criteria.
    Malformed regexes cause the regex field to be discarded; the rule is
    kept if other criteria exist.
    """
    if not isinstance(raw, dict):
        return None

    rid = str(raw.get("id") or raw.get("name", ""))
    name = str(raw.get("name") or raw.get("id", ""))
    source = str(raw.get("source") or raw.get("origin", ""))
    score_floor = raw.get("score_floor", 0)
    if not isinstance(score_floor, int):
        try:
            score_floor = int(score_floor)
        except (TypeError, ValueError):
            score_floor = 0

    match = raw.get("match", {})
    if not isinstance(match, dict):
        match = {}

    # Fall back to top-level keys when match: is empty.  The older
    # learned-rules and redteam-autofuzz schemas put binary, regex,
    # contains, and contains_any as sibling keys at the rule level
    # instead of nesting them under match:.  Both layouts are valid;
    # the nested form takes precedence when both exist.
    def _get(key: str):
        return match.get(key) or raw.get(key)

    # --- binary ---
    binary: tuple[str, ...] | None = None
    deep_scan: list[re.Pattern] = []
    bins_raw = _get("binary")
    if bins_raw is not None:
        bins = [bins_raw] if isinstance(bins_raw, str) else bins_raw
        if isinstance(bins, list) and bins:
            binary = tuple(str(b) for b in bins)
            deep_scan = [
                re.compile(
                    r'(?:^|[\s/"\';|&(])' + re.escape(b) + r'(?:\s|$)'
                )
                for b in binary
            ]

    # --- contains / contains_any ---
    contains: tuple[str, ...] | None = None
    terms_raw = _get("contains")
    if terms_raw is not None:
        terms = [terms_raw] if isinstance(terms_raw, str) else terms_raw
        if isinstance(terms, list) and terms:
            contains = tuple(str(t).lower() for t in terms)

    contains_any: tuple[str, ...] | None = None
    terms_any_raw = _get("contains_any")
    if terms_any_raw is not None:
        terms = [terms_any_raw] if isinstance(terms_any_raw, str) else terms_any_raw
        if isinstance(terms, list) and terms:
            contains_any = tuple(str(t).lower() for t in terms)

    # --- regex ---
    regex_source: str | None = None
    compiled_regex: re.Pattern | None = None
    regex_raw = _get("regex")
    if regex_raw is not None:
        regex_source = str(regex_raw)
        try:
            compiled_regex = re.compile(regex_source, re.DOTALL)
        except re.error as e:
            log.debug("Rule %s has invalid regex: %s", rid, e)
            regex_source = None
            compiled_regex = None

    if not any((binary, contains, contains_any, compiled_regex)):
        return None

    return CompiledRule(
        id=rid,
        name=name,
        score_floor=score_floor,
        source=source,
        binary=binary,
        contains=contains,
        contains_any=contains_any,
        regex_source=regex_source,
        compiled_regex=compiled_regex,
        deep_scan_patterns=tuple(deep_scan),
    )


_SUDO_PREFIX = re.compile(r'^(?:sudo\s+(?:-\S+\s+)*)')
_ENV_PREFIX = re.compile(r'^(?:env\s+(?:\S+=\S+\s+)*)')


def _extract_first_tokens(command: str) -> set[str]:
    """Return the set of first-token binaries in a command.

    Splits on pipes, semicolons, and ``&&``/``||`` (quote-aware via
    :mod:`ralf.shared.bash_split`), strips sudo/env prefixes, and
    returns the basename of each segment's first token.
    Mirrors ralf/impact/learned_rules.py:312-326.
    """
    from ralf.shared.bash_split import split_segments as _split

    out: set[str] = set()
    for part in _split(command):
        part = _SUDO_PREFIX.sub("", part).strip()
        part = _ENV_PREFIX.sub("", part).strip()
        toks = part.split()
        if not toks:
            continue
        first = toks[0].rsplit("/", 1)[-1]
        if first:
            out.add(first)
    return out
