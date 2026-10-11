"""Posture scoring. Higher = healthier (0-100). Unassessed areas never count as healthy."""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import DomainAssessment, Severity, UnauthorizedUse

_PENALTY = {
    Severity.CRITICAL: 30, Severity.HIGH: 15, Severity.MEDIUM: 7,
    Severity.LOW: 2, Severity.INFORMATIONAL: 0, Severity.NOT_ASSESSED: 0,
}


@dataclass(slots=True)
class RiskScore:
    total: int
    grade: str
    coverage_gaps: list[str] = field(default_factory=list)
    complete: bool = True  # False when any area was not assessed


def _grade(n: int) -> str:
    return "A" if n >= 90 else "B" if n >= 75 else "C" if n >= 60 else "D" if n >= 40 else "F"


class RiskEngine:
    def score(self, a: DomainAssessment) -> RiskScore:
        penalty = sum(_PENALTY[f.severity] for f in a.findings)
        penalty += sum(25 for rp in a.relay_paths
                       if rp.unauthorized_use_possible == UnauthorizedUse.CONFIRMED)
        total = max(0, 100 - penalty)
        gaps = [f"{k}: {v}" for k, v in a.coverage.items() if v != "ran"]
        for rp in a.relay_paths:
            gaps.extend(g for g in rp.coverage_gaps if g not in gaps)
        gaps.extend(f.title for f in a.findings
                    if f.severity == Severity.NOT_ASSESSED and f.title not in gaps)
        return RiskScore(total=total, grade=_grade(total),
                         coverage_gaps=list(dict.fromkeys(gaps)), complete=not gaps)
