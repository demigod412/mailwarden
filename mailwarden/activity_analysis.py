"""Turn Workspace audit events (Reports API) into findings.

Only events Google itself recorded can produce a CONFIRMED abuse status.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from .input_loader import Authorization
from .models import AbuseStatus, Category, Confidence, Finding, Severity

CONFIRMED_ABUSE_EVENTS = {
    "account_disabled_spamming_through_relay",
    "account_disabled_spamming",
    "account_disabled_hijacked",
}
SUSPICIOUS_EVENTS = {"suspicious_login", "suspicious_login_less_secure_app", "suspicious_programmatic_login"}
FAILURE_BURST = 10


def _names(items: list[dict[str, Any]]):
    for item in items:
        actor = (item.get("actor") or {}).get("email", "unknown")
        for ev in item.get("events", []):
            yield ev.get("name", ""), actor, (item.get("id") or {}).get("time", "")


def analyze_activity(events: list[dict[str, Any]], auth: Authorization) -> list[Finding]:
    dom, out = auth.domain, []
    seen: dict[str, list[tuple[str, str]]] = {}
    for name, actor, ts in _names(events):
        seen.setdefault(name, []).append((actor, ts))

    for name in sorted(CONFIRMED_ABUSE_EVENTS & seen.keys()):
        actors = sorted({a for a, _ in seen[name]})
        out.append(Finding(
            domain=dom, category=Category.ACTIVITY, component="Account audit",
            severity=Severity.CRITICAL, confidence=Confidence.HIGH,
            title=f"Google disabled account for abuse: {name}",
            evidence={"event": name, "count": len(seen[name]), "accounts": actors[:20]},
            detection_method="Reports API (login audit)",
            business_impact="Google recorded abusive sending or compromise for these accounts.",
            remediation="Reset credentials, review sent mail and relay allowlists, then re-enable.",
            abuse_status=AbuseStatus.CONFIRMED))
    for name in sorted(SUSPICIOUS_EVENTS & seen.keys()):
        out.append(Finding(
            domain=dom, category=Category.LOGIN, component="Login audit",
            severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
            title=f"{len(seen[name])} suspicious login event(s): {name}",
            evidence={"event": name, "accounts": sorted({a for a, _ in seen[name]})[:20]},
            detection_method="Reports API (login audit)",
            business_impact="Possible credential misuse; not proof of compromise.",
            remediation="Review each account, enforce 2-Step Verification, block legacy app access.",
            abuse_status=AbuseStatus.SUSPECTED))
    fails = Counter(a for a, _ in seen.get("login_failure", []))
    heavy = {a: n for a, n in fails.items() if n >= FAILURE_BURST}
    if heavy:
        out.append(Finding(
            domain=dom, category=Category.LOGIN, component="Login audit",
            severity=Severity.LOW, confidence=Confidence.MEDIUM,
            title=f"{len(heavy)} account(s) with {FAILURE_BURST}+ failed logins",
            evidence={"accounts": dict(sorted(heavy.items(), key=lambda kv: -kv[1])[:20])},
            detection_method="Reports API (login audit)",
            business_impact="Repeated failures can indicate password guessing.",
            remediation="Enforce 2-Step Verification and review these accounts."))
    if not out:
        out.append(Finding(
            domain=dom, category=Category.ACTIVITY, component="Account audit",
            severity=Severity.INFORMATIONAL, confidence=Confidence.MEDIUM,
            title="No abuse events in the retrieved audit window",
            evidence={"events_examined": sum(len(v) for v in seen.values())},
            detection_method="Reports API (login audit)",
            business_impact="Absence of events is not proof of safety; retention is tenant-dependent.",
            remediation="Re-run periodically.", abuse_status=AbuseStatus.NOT_ESTABLISHED))
    return out
