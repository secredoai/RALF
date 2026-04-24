"""Scanner runner — discover checks, execute, score.

Usage::

    from ralf.scanner.runner import run_all_checks
    report = run_all_checks()
    print(report.summary())
"""

from __future__ import annotations

import importlib
import logging
import platform

from ralf.scanner import CheckResult, ScanReport
from ralf.scanner.checks import REGISTRY

log = logging.getLogger(__name__)

# Check modules to import (each populates REGISTRY on import).
_CHECK_MODULES = (
    "ralf.scanner.macos",
    "ralf.scanner.linux",
    "ralf.scanner.credentials",
    "ralf.scanner.sessions",
)

_modules_loaded = False


def _ensure_modules() -> None:
    """Import all check modules so REGISTRY is populated."""
    global _modules_loaded
    if _modules_loaded:
        return
    for mod_name in _CHECK_MODULES:
        try:
            importlib.import_module(mod_name)
        except Exception as exc:
            log.debug("Failed to import %s: %s", mod_name, exc)
    _modules_loaded = True


def score_results(results: list[CheckResult]) -> tuple[int, str]:
    """Compute score (100 minus deductions) and letter grade."""
    score = 100
    for r in results:
        score += r.score_delta  # deltas are negative
    score = max(0, min(100, score))

    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"

    return score, grade


def run_all_checks(
    category: str = "all",
    plat: str | None = None,
    benchmark: str | None = None,
    section: str | None = None,
) -> ScanReport:
    """Discover and run all checks for the current platform.

    Args:
        category: Filter by category ("all", "host_hardening", "credential",
                  "network", "session").
        plat: Override platform detection (default: ``platform.system().lower()``).
        benchmark: Filter by benchmark prefix (e.g. "cis-ubuntu-22", "cis-macos-sonoma").
                   Matches checks whose benchmark_id starts with "CIS-".
        section: Filter by section name (substring match, case-insensitive).
    """
    _ensure_modules()

    if plat is None:
        plat = platform.system().lower()

    results: list[CheckResult] = []
    for check in REGISTRY:
        if plat not in check.platforms:
            continue
        if category != "all" and check.category != category:
            continue
        if benchmark is not None:
            if check.benchmark_id is None:
                continue
            if not check.benchmark_id.startswith("CIS-"):
                continue
        if section is not None:
            if check.section is None:
                continue
            if section.lower() not in check.section.lower():
                continue
        try:
            result = check.run()
            if check.benchmark_id and result.benchmark_id is None:
                result.benchmark_id = check.benchmark_id
            if check.section and result.section is None:
                result.section = check.section
            results.append(result)
        except Exception as exc:
            log.warning("Check %s failed: %s", check.id, exc)
            results.append(CheckResult(
                check_id=check.id,
                name=check.name,
                category=check.category,
                status="skip",
                detail=f"Check raised an exception: {exc}",
                remediation="",
                severity=check.severity,
                score_delta=0,
                benchmark_id=check.benchmark_id,
                section=check.section,
            ))

    score, grade = score_results(results)
    return ScanReport(results=results, score=score, grade=grade, platform=plat)
