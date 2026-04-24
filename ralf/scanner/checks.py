"""Base check interface for security posture checks.

Every check module (macos.py, linux.py, credentials.py, sessions.py)
registers its checks by appending to :data:`REGISTRY`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from ralf.scanner import CheckResult


@dataclass
class Check:
    """Metadata + callable for a single posture check."""

    id: str
    name: str
    category: str
    platforms: tuple[str, ...]   # ("linux",) or ("darwin",) or ("linux", "darwin")
    severity: str                # "critical" | "high" | "medium" | "low"
    run: Callable[[], CheckResult]
    benchmark_id: str | None = None  # "CIS-5.2.7"
    section: str | None = None       # "SSH Server Configuration"


# Global registry populated by each check module at import time.
REGISTRY: list[Check] = []


def register(
    *,
    id: str,
    name: str,
    category: str,
    platforms: tuple[str, ...],
    severity: str,
    benchmark_id: str | None = None,
    section: str | None = None,
) -> Callable[[Callable[[], CheckResult]], Callable[[], CheckResult]]:
    """Decorator that registers a check function."""

    def decorator(fn: Callable[[], CheckResult]) -> Callable[[], CheckResult]:
        REGISTRY.append(Check(
            id=id,
            name=name,
            category=category,
            platforms=platforms,
            severity=severity,
            run=fn,
            benchmark_id=benchmark_id,
            section=section,
        ))
        return fn

    return decorator
