"""First-token allow / block / review list + domain control — YAML-backed.

Persisted to ``$XDG_CONFIG_HOME/ralf-free/app_control.yaml`` (defaults
to ``~/.config/ralf-free/app_control.yaml``).

YAML shape::

    allow:
      - ls
      - cat
      - git
    block:
      - nsenter
      - launchctl
    review:
      - docker
      - kubectl
    allow_domains:
      - github.com
    block_domains:
      - evil.com

Binary lookup is case-sensitive first-token basename match. Domain
lookup is case-insensitive suffix match (``x.com`` blocks
``sub.x.com``). Unknown tokens return :attr:`AppDecision.UNKNOWN`, at
which point the verdict engine falls through to the normal scoring path.
"""
from __future__ import annotations

import os
import re
import tempfile
from enum import Enum
from pathlib import Path
from typing import Any

import yaml


class AppDecision(Enum):
    ALLOW = "allow"
    BLOCK = "block"
    REVIEW = "review"
    UNKNOWN = "unknown"


def _config_dir() -> Path:
    xdg = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return Path(xdg) / "ralf-free"


DEFAULT_CONFIG_PATH = _config_dir() / "app_control.yaml"

_URL_DOMAIN_RE = re.compile(r"https?://([^/:?\s]+)", re.IGNORECASE)


class AppControl:
    """In-memory cache + file persistence for binary and domain control."""

    def __init__(self, path: Path | None = None):
        self._path = Path(path) if path else DEFAULT_CONFIG_PATH
        self._allow: set[str] = set()
        self._block: set[str] = set()
        self._review: set[str] = set()
        self._allow_domains: set[str] = set()
        self._block_domains: set[str] = set()
        self.load()

    @property
    def path(self) -> Path:
        return self._path

    # ------------------------------------------------------------------
    # binary API
    # ------------------------------------------------------------------

    def check(self, first_token: str) -> AppDecision:
        """Return the decision for ``first_token``, or UNKNOWN."""
        if not first_token:
            return AppDecision.UNKNOWN
        token = first_token.rsplit("/", 1)[-1]
        if token in self._block:
            return AppDecision.BLOCK
        if token in self._allow:
            return AppDecision.ALLOW
        if token in self._review:
            return AppDecision.REVIEW
        return AppDecision.UNKNOWN

    def add(self, first_token: str, decision: AppDecision) -> None:
        """Add ``first_token`` to the list for ``decision``, persist to disk."""
        if not first_token:
            return
        token = first_token.rsplit("/", 1)[-1]
        self._allow.discard(token)
        self._block.discard(token)
        self._review.discard(token)
        if decision == AppDecision.ALLOW:
            self._allow.add(token)
        elif decision == AppDecision.BLOCK:
            self._block.add(token)
        elif decision == AppDecision.REVIEW:
            self._review.add(token)
        self.save()

    def remove(self, first_token: str) -> bool:
        """Remove ``first_token`` from all lists. Returns True if removed."""
        if not first_token:
            return False
        token = first_token.rsplit("/", 1)[-1]
        removed = (
            token in self._allow or token in self._block or token in self._review
        )
        self._allow.discard(token)
        self._block.discard(token)
        self._review.discard(token)
        if removed:
            self.save()
        return removed

    # ------------------------------------------------------------------
    # domain API
    # ------------------------------------------------------------------

    def check_domain(self, domain: str) -> AppDecision:
        """Return the decision for ``domain`` (suffix match), or UNKNOWN."""
        if not domain:
            return AppDecision.UNKNOWN
        d = domain.lower().strip().lstrip(".")
        for blocked in self._block_domains:
            if d == blocked or d.endswith("." + blocked):
                return AppDecision.BLOCK
        for allowed in self._allow_domains:
            if d == allowed or d.endswith("." + allowed):
                return AppDecision.ALLOW
        return AppDecision.UNKNOWN

    def check_url(self, text: str) -> AppDecision:
        """Extract domains from URLs in ``text`` and check each."""
        for m in _URL_DOMAIN_RE.finditer(text):
            host = m.group(1).lower().strip()
            decision = self.check_domain(host)
            if decision != AppDecision.UNKNOWN:
                return decision
        return AppDecision.UNKNOWN

    def add_domain(self, domain: str, decision: AppDecision) -> None:
        """Add ``domain`` to the domain allow or block list."""
        if not domain:
            return
        d = domain.lower().strip().lstrip(".")
        self._allow_domains.discard(d)
        self._block_domains.discard(d)
        if decision == AppDecision.ALLOW:
            self._allow_domains.add(d)
        elif decision == AppDecision.BLOCK:
            self._block_domains.add(d)
        self.save()

    def remove_domain(self, domain: str) -> bool:
        """Remove ``domain`` from all domain lists."""
        if not domain:
            return False
        d = domain.lower().strip().lstrip(".")
        removed = d in self._allow_domains or d in self._block_domains
        self._allow_domains.discard(d)
        self._block_domains.discard(d)
        if removed:
            self.save()
        return removed

    # ------------------------------------------------------------------
    # serialization
    # ------------------------------------------------------------------

    def as_dict(self) -> dict[str, list[str]]:
        """Return the current state as a dict of sorted lists."""
        return {
            "allow": sorted(self._allow),
            "block": sorted(self._block),
            "review": sorted(self._review),
            "allow_domains": sorted(self._allow_domains),
            "block_domains": sorted(self._block_domains),
        }

    def load(self) -> None:
        """Load the YAML file. Missing file → empty state; no error."""
        if not self._path.exists():
            return
        try:
            with open(self._path) as f:
                data = yaml.safe_load(f) or {}
        except Exception:
            return
        if not isinstance(data, dict):
            return
        self._allow = set(data.get("allow", []) or [])
        self._block = set(data.get("block", []) or [])
        self._review = set(data.get("review", []) or [])
        self._allow_domains = set(
            s.lower() for s in (data.get("allow_domains", []) or [])
        )
        self._block_domains = set(
            s.lower() for s in (data.get("block_domains", []) or [])
        )

    def save(self) -> None:
        """Write the YAML file atomically."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload: dict[str, Any] = self.as_dict()
        with tempfile.NamedTemporaryFile(
            mode="w",
            dir=self._path.parent,
            prefix=self._path.name + ".",
            suffix=".tmp",
            delete=False,
        ) as tmp:
            yaml.safe_dump(payload, tmp, default_flow_style=False, sort_keys=True)
            tmp_name = tmp.name
        os.replace(tmp_name, self._path)


# ----------------------------------------------------------------------
# module-level convenience shims
# ----------------------------------------------------------------------

_default: AppControl | None = None


def _get_default() -> AppControl:
    global _default
    if _default is None:
        _default = AppControl()
    return _default


def check(first_token: str) -> AppDecision:
    """Look up ``first_token`` in the default config file."""
    return _get_default().check(first_token)


def check_domain(domain: str) -> AppDecision:
    """Look up ``domain`` in the default config file."""
    return _get_default().check_domain(domain)


def check_url(text: str) -> AppDecision:
    """Extract domains from URLs in ``text`` and check."""
    return _get_default().check_url(text)


def reset_cache() -> None:
    """Drop the cached default instance — used by tests."""
    global _default
    _default = None
