"""Host security posture scanner — result model and scoring.

Provides :class:`CheckResult` (individual check outcome) and
:class:`ScanReport` (aggregated scan with score + grade).
"""

from __future__ import annotations

import platform
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class CheckResult:
    """Outcome of a single security check."""

    check_id: str       # "macos_firewall", "cred_exposure_history"
    name: str           # "macOS Firewall"
    category: str       # "host_hardening" | "credential" | "network" | "sandbox"
    status: str         # "pass" | "warn" | "fail" | "info" | "skip"
    detail: str         # "macOS Firewall is off"
    remediation: str    # "Run: sudo /usr/libexec/.../socketfilterfw --setglobalstate on"
    severity: str       # "critical" | "high" | "medium" | "low"
    score_delta: int    # -10 for fail, 0 for pass, -5 for warn
    benchmark_id: str | None = None  # "CIS-5.2.7" cross-ref (optional)
    section: str | None = None       # "SSH Server Configuration" (optional)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "check_id": self.check_id,
            "name": self.name,
            "category": self.category,
            "status": self.status,
            "detail": self.detail,
            "remediation": self.remediation,
            "severity": self.severity,
            "score_delta": self.score_delta,
        }
        if self.benchmark_id is not None:
            d["benchmark_id"] = self.benchmark_id
        if self.section is not None:
            d["section"] = self.section
        return d


@dataclass
class ScanReport:
    """Aggregated scan report with score and grade."""

    results: list[CheckResult] = field(default_factory=list)
    score: int = 100
    grade: str = "A"
    ts: str = ""
    platform: str = ""

    def __post_init__(self) -> None:
        if not self.ts:
            self.ts = datetime.now(timezone.utc).isoformat()
        if not self.platform:
            self.platform = platform.system().lower()

    def summary(self) -> str:
        """Formatted terminal output."""
        lines: list[str] = []
        lines.append(f"RALF Security Posture — {self.platform}")
        lines.append(f"Score: {self.score}/100  Grade: {self.grade}")
        lines.append(f"Scanned at: {self.ts}")
        lines.append("")

        # Group by category
        cats: dict[str, list[CheckResult]] = {}
        for r in self.results:
            cats.setdefault(r.category, []).append(r)

        status_icon = {
            "pass": "[PASS]",
            "warn": "[WARN]",
            "fail": "[FAIL]",
            "info": "[INFO]",
            "skip": "[SKIP]",
        }

        for cat, checks in sorted(cats.items()):
            lines.append(f"  {cat}")
            for c in checks:
                icon = status_icon.get(c.status, "[????]")
                lines.append(f"    {icon} {c.name}: {c.detail}")
                if c.status in ("fail", "warn") and c.remediation:
                    lines.append(f"          Fix: {c.remediation}")
            lines.append("")

        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "grade": self.grade,
            "ts": self.ts,
            "platform": self.platform,
            "results": [r.to_dict() for r in self.results],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScanReport:
        results = [
            CheckResult(**r) for r in data.get("results", [])
        ]
        return cls(
            results=results,
            score=data.get("score", 100),
            grade=data.get("grade", "A"),
            ts=data.get("ts", ""),
            platform=data.get("platform", ""),
        )
