"""CSV, JSON, and HTML report generation.

Two safety properties are enforced here:
  1. HTML output is autoescaped (Jinja autoescape; templates live in templates/).
  2. A credential guard scans every finding before any file is written and
     refuses the build if credential material is detected. The guard is a
     belt-and-braces complement to log redaction; it is not the only control.
"""

from __future__ import annotations

import csv
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from jinja2 import Environment, PackageLoader

from .errors import CredentialLeakError
from . import __version__
from .models import DomainAssessment, RelayPath, Severity
from .risk_engine import RiskEngine, RiskScore

# ---------------------------------------------------------------------------
# Credential guard
# ---------------------------------------------------------------------------

# Exact key names (case-insensitive) that are never legitimate in a report.
_CRED_KEY_RE = re.compile(
    r"^(password|passwd|pwd|secret|client[_-]?secret|app[_-]?password|"
    r"api[_-]?key|refresh[_-]?token|access[_-]?token|id[_-]?token|"
    r"bearer[_-]?token|private[_-]?key|session[_-]?cookie|"
    r"cookie|authorization|auth[_-]?header|set[_-]?cookie)$",
    re.IGNORECASE,
)

# Value patterns for well-known credential formats.
_CRED_VALUE_RES = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{20,}"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),                 # Google API key
    re.compile(r"\bya29\.[0-9A-Za-z_\-]{20,}\b"),              # Google OAuth token
    re.compile(r"\b1//[0-9A-Za-z_\-]{40,}\b"),                 # Google refresh token
    re.compile(r"\bGOCSPX-[A-Za-z0-9_\-]{10,}\b"),             # Google OAuth client secret
    re.compile(r"\bghp_[A-Za-z0-9]{30,}\b"),                   # GitHub PAT
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),                       # AWS access key
]

_REDACTION_SENTINELS = {"<REDACTED>", "[REDACTED]", "<redacted>", "[redacted]", ""}


class CredentialGuardReport:
    """Container for guard results; may contain violations but never values."""

    def __init__(self) -> None:
        self.violations: list[str] = []

    def add(self, finding_id: str, where: str, reason: str) -> None:
        self.violations.append(f"{finding_id}: {where} ({reason})")

    @property
    def clean(self) -> bool:
        return not self.violations


def _walk(obj: Any, path: str = "$"):
    yield path, obj
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk(v, f"{path}.{k}")
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            yield from _walk(v, f"{path}[{i}]")


def _looks_like_secret_value(v: Any) -> bool:
    if not isinstance(v, str) or v in _REDACTION_SENTINELS:
        return False
    return any(rx.search(v) for rx in _CRED_VALUE_RES)


def scan_for_credentials(
    assessments: Iterable[DomainAssessment],
) -> CredentialGuardReport:
    """Scan finding payloads (and relay-path payloads) for credential material.

    Reports *locations*, never values. Does not raise; callers decide policy.
    """
    report = CredentialGuardReport()
    for a in assessments:
        # Findings
        for f in a.findings:
            payload = {
                "title": f.title,
                "evidence": f.evidence,
                "business_impact": f.business_impact,
                "remediation": f.remediation,
            }
            for where, node in _walk(payload):
                if isinstance(node, dict):
                    for k, v in node.items():
                        if isinstance(k, str) and _CRED_KEY_RE.match(k):
                            if not (isinstance(v, str) and v in _REDACTION_SENTINELS):
                                report.add(f.finding_id, f"{where}.{k}",
                                           "sensitive key with non-redacted value")
                elif isinstance(node, str):
                    if _looks_like_secret_value(node):
                        report.add(f.finding_id, where,
                                   "value matches known credential format")
        # Relay paths
        for rp in a.relay_paths:
            payload = {
                "evidence_source": rp.evidence_source,
                "collected_by": rp.collected_by,
                "why_not_confirmed": rp.why_not_confirmed,
                "remediation": rp.remediation,
                "allowed_senders": rp.allowed_senders,
                "authorized_cidrs": rp.authorized_cidrs,
            }
            for where, node in _walk(payload):
                if isinstance(node, str) and _looks_like_secret_value(node):
                    report.add(rp.path_id, where,
                               "value matches known credential format")
    return report


def assert_no_credentials(
    assessments: Iterable[DomainAssessment],
    *,
    strict: bool = True,
) -> CredentialGuardReport:
    """Run the guard. If strict and violations exist, raise CredentialLeakError."""
    report = scan_for_credentials(assessments)
    if strict and not report.clean:
        first = report.violations[0]
        raise CredentialLeakError(
            "Refusing to write report: potential credential material detected "
            f"in {len(report.violations)} location(s). First: {first}. "
            "Redact the offending evidence before rerunning."
        )
    return report


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------

CSV_COLUMNS = [
    "finding_id", "domain", "category", "component", "severity", "confidence",
    "title", "detection_method", "abuse_status", "timestamp",
    "business_impact", "remediation", "evidence_json",
]

ABUSE_REVIEW_COLUMNS = [
    "domain", "customer_id", "path_id", "kind",
    "authentication_required", "sender_policy", "tls_required",
    "authorized_cidrs", "abuse_exposure", "unauthorized_use_possible",
    "evidence_source", "collected_at", "collected_by",
    "why_not_confirmed", "remediation",
    "finding_ids", "coverage_gaps",
]

SPOOFING_RISK_COLUMNS = ["domain", "customer_id", "risk", "dmarc_level", "spf_level", "why"]

RELAY_EXPLOIT_COLUMNS = [
    "domain", "customer_id", "risk", "status", "ip_restriction",
    "auth_required", "relay_host", "why", "remediation",
]


def _cell(v: Any) -> Any:
    """Neutralise spreadsheet formula injection (=, +, -, @ at cell start)."""
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + v
    return v


def write_csv(assessments: Iterable[DomainAssessment], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for a in assessments:
            for f in a.findings:
                d = f.to_dict()
                writer.writerow({k: _cell(v) for k, v in {
                    "finding_id": d["finding_id"],
                    "domain": d["domain"],
                    "category": d["category"],
                    "component": d["component"],
                    "severity": d["severity"],
                    "confidence": d["confidence"],
                    "title": d["title"],
                    "detection_method": d["detection_method"],
                    "abuse_status": d["abuse_status"],
                    "timestamp": d["timestamp"],
                    "business_impact": d["business_impact"],
                    "remediation": d["remediation"],
                    "evidence_json": json.dumps(d["evidence"], default=str),
                }.items()})


def write_abuse_review(
    assessments: Iterable[DomainAssessment],
    path: Path,
) -> None:
    """One row per (domain, relay path). Customer-scoped, never cross-customer."""
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=ABUSE_REVIEW_COLUMNS)
        writer.writeheader()
        for a in assessments:
            for rp in a.relay_paths:
                writer.writerow({k: _cell(v) for k, v in {
                    "domain": rp.domain,
                    "customer_id": rp.customer_id or "",
                    "path_id": rp.path_id,
                    "kind": rp.kind,
                    "authentication_required": ("" if rp.authentication_required is None
                                                else rp.authentication_required),
                    "sender_policy": rp.sender_policy,
                    "tls_required": ("" if rp.tls_required is None else rp.tls_required),
                    "authorized_cidrs": ";".join(rp.authorized_cidrs),
                    "abuse_exposure": rp.abuse_exposure.value,
                    "unauthorized_use_possible": rp.unauthorized_use_possible.value,
                    "evidence_source": rp.evidence_source,
                    "collected_at": rp.collected_at or "",
                    "collected_by": rp.collected_by or "",
                    "why_not_confirmed": rp.why_not_confirmed,
                    "remediation": rp.remediation,
                    "finding_ids": ";".join(rp.finding_ids),
                    "coverage_gaps": ";".join(rp.coverage_gaps),
                }.items()})


def write_spoofing_risk(assessments: Iterable[DomainAssessment], path: Path) -> None:
    """One row per domain: can mail be sent *claiming to be from* this domain
    (spoofing/bulk-sending without any access to the domain's own infrastructure),
    judged from already-collected SPF/DMARC findings. Sorted worst-first."""
    from .spoofing_risk import assess_all
    rows = assess_all(list(assessments))
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=SPOOFING_RISK_COLUMNS)
        writer.writeheader()
        for r in rows:
            writer.writerow({k: _cell(v) for k, v in {
                "domain": r.domain, "customer_id": r.customer_id or "",
                "risk": r.risk, "dmarc_level": r.dmarc_level, "spf_level": r.spf_level,
                "why": r.why,
            }.items()})


def write_relay_exploit(assessments: Iterable[DomainAssessment], path: Path) -> None:
    """One row per domain: is the domain's Google Workspace SMTP relay
    (smtp-relay.gmail.com) exploitable from any IP -- i.e. no source-IP range
    restriction and no required authentication. This is a different question
    from spoofing (see write_spoofing_risk): it is about relaying THROUGH the
    domain's own relay, not forging its address. Sorted worst-first."""
    from .relay_exploit import assess_all
    rows = assess_all(list(assessments))
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=RELAY_EXPLOIT_COLUMNS)
        writer.writeheader()
        for r in rows:
            writer.writerow({k: _cell(v) for k, v in {
                "domain": r.domain, "customer_id": r.customer_id or "",
                "risk": r.risk, "status": r.status, "ip_restriction": r.ip_restriction,
                "auth_required": ("" if r.auth_required is None else r.auth_required),
                "relay_host": r.relay_host, "why": r.why, "remediation": r.remediation,
            }.items()})


# ---------------------------------------------------------------------------
# JSON + metadata
# ---------------------------------------------------------------------------

def write_json(assessments: Iterable[DomainAssessment], path: Path) -> None:
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool_version": __version__,
        "domains": [a.to_dict() for a in assessments],
    }
    path.write_text(json.dumps(payload, indent=2, default=str))


def write_metadata(
    path: Path, *, scope: str, mode: str,
    notes: list[str], started: str, finished: str,
) -> None:
    path.write_text(json.dumps({
        "tool": "mailwarden",
        "tool_version": __version__,
        "scope": scope,
        "mode": mode,
        "started_at": started,
        "finished_at": finished,
        "notes": notes,
        "permissions": ["admin.reports.audit.readonly"],
        "limitations": [
            "Reports API does not expose all relay settings; administrator "
            "evidence required.",
            "Absence of findings is not proof of security.",
            "Audit retention is tenant-dependent.",
            "Relay path verdicts are scoped to the authorized customer only; "
            "the tool does not produce a cross-customer target list.",
            "Credentials are never included in output; the reporting layer "
            "refuses to write if credential material is detected in evidence.",
        ],
    }, indent=2))


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW,
              Severity.INFORMATIONAL, Severity.NOT_ASSESSED]
_RANK = {s: i for i, s in enumerate(_SEV_ORDER)}

_DEFAULT_NEXT_STEPS = [
    "Fix CRITICAL and HIGH findings first (see 'Fix first' above).",
    "For each relay path marked 'suspected', apply its remediation, then re-export "
    "the relay settings and scan again to confirm the exposure is gone.",
    "For any path marked 'confirmed', review the cited audit events through the "
    "customer's incident-response process before changing anything else.",
    "Move DMARC from p=none to quarantine, then reject, once reports are clean.",
    "Treat every 'not assessed' item as unknown, not as safe. Provide the missing evidence.",
]


def _gate(value: bool | None, ok_text: str, bad_text: str) -> dict[str, str]:
    if value is True:
        return {"state": "ok", "text": ok_text}
    if value is False:
        return {"state": "bad", "text": bad_text}
    return {"state": "unknown", "text": "Unknown"}


def _path_view(rp: RelayPath) -> dict[str, Any]:
    sender = {"restricted": _gate(True, "Restricted", ""),
              "wildcard": _gate(False, "", "Any sender allowed")}.get(
        rp.sender_policy, _gate(None, "", ""))
    ip_gate = {"restricted": {"state": "ok", "text": "Restricted to ranges"},
               "none": {"state": "bad", "text": "Any IP accepted"},
               "unknown": {"state": "unknown", "text": "Unknown"}}.get(
        rp.ip_restriction, {"state": "unknown", "text": "Unknown"})
    return {
        "p": rp,
        "gates": [
            {"name": "Authentication", **_gate(rp.authentication_required, "Required", "Not required")},
            {"name": "Source IP restriction", **ip_gate},
            {"name": "Sender policy", **sender},
            {"name": "TLS", **_gate(rp.tls_required, "Required", "Not required")},
        ],
    }


_COV_DISPLAY_NAME = {
    "WORKSPACE_AUDIT": "Workspace audit",
    "RELAY_PROBE": "Relay probe",
    "RELAY": "Relay",
}

# Probe outcome -> (short label, is_bad). is_bad True renders a warning chip,
# False a benign "ran" chip, None a hatched "unknown/not-assessed" chip.
_PROBE_OUTCOME = {
    "open": ("open relay (any IP)", True),
    "auth_required": ("restricted (auth required)", False),
    "relay_denied": ("restricted (IP denied)", False),
    "inconclusive": ("inconclusive", None),
}


def _coverage_view(coverage: dict[str, str]) -> list[dict[str, Any]]:
    """Build the per-domain coverage chips. Most checks report a plain "ran" /
    error state; the relay probe reports "ran: <outcome>" (or "skipped: ...") and
    gets a readable label and, for an open relay, a warning chip."""
    out: list[dict[str, Any]] = []
    for key, state in coverage.items():
        name = _COV_DISPLAY_NAME.get(key, key)
        if key == "RELAY_PROBE":
            if state.startswith("ran:"):
                outcome = state.split(":", 1)[1].strip()
                desc, bad = _PROBE_OUTCOME.get(outcome, (outcome, None))
                if bad is True:
                    out.append({"cls": "warn", "icon": "⚠ ",
                                "text": f"{name}: {desc}", "title": state})
                elif bad is False:
                    out.append({"cls": "yes", "icon": "✓ ",
                                "text": f"{name}: {desc}", "title": state})
                else:  # inconclusive -> unknown, hatched like other not-assessed
                    out.append({"cls": "no hatch", "icon": "",
                                "text": f"{name}: {desc}", "title": state})
            else:  # "skipped: not authorized" and anything else
                reason = state.split(":", 1)[0].strip()
                out.append({"cls": "no hatch", "icon": "",
                            "text": f"{name}: {reason}", "title": state})
            continue
        if state == "ran":
            out.append({"cls": "yes", "icon": "✓ ", "text": name, "title": state})
        else:
            out.append({"cls": "no hatch", "icon": "", "text": f"{name}: {state}",
                        "title": state})
    return out


def _stamp_class(score: Any) -> str:
    if score is None or not score.complete and score.total >= 90:
        return "g-partial"
    return {"A": "g-a", "B": "g-b", "C": "g-c", "D": "g-d", "F": "g-f"}[score.grade]


def _build_context(assessments: list[DomainAssessment], scores: dict[str, RiskScore],
                   scope: str, mode: str, next_steps: list[str] | None) -> dict[str, Any]:
    from .spoofing_risk import LEVEL_LABEL, assess_all
    from .relay_exploit import (
        LEVEL_LABEL as EXPLOIT_LEVEL_LABEL, STATUS_LABEL as EXPLOIT_STATUS_LABEL,
        assess_all as assess_exploit_all,
    )
    engine = RiskEngine()
    totals = {s.value: 0 for s in Severity}
    abuse = {"confirmed": 0, "suspected": 0, "not_established": 0, "not_assessed": 0}
    domains, fix_first = [], []
    domain_anchor: dict[str, str] = {}
    spoof_rows = assess_all(assessments)
    spoof_counts = {"high": 0, "medium": 0, "low": 0, "unknown": 0}
    for r in spoof_rows:
        spoof_counts[r.risk] += 1
    exploit_rows = assess_exploit_all(assessments)
    exploit_counts = {"high": 0, "medium": 0, "low": 0, "none": 0, "unknown": 0}
    for r in exploit_rows:
        exploit_counts[r.risk] += 1
    for i, a in enumerate(assessments):
        sc = scores.get(a.domain) or engine.score(a)
        findings = sorted(a.findings, key=lambda f: _RANK[f.severity])
        counts = {s.value: 0 for s in Severity}
        for f in findings:
            totals[f.severity.value] += 1
            counts[f.severity.value] += 1
            if f.severity in (Severity.CRITICAL, Severity.HIGH):
                fix_first.append({"domain": a.domain, "f": f})
        for rp in a.relay_paths:
            abuse[rp.unauthorized_use_possible.value] += 1
        anchor = f"d-{i}"
        domain_anchor[a.domain] = anchor
        domains.append({
            "domain": a.domain, "customer_id": a.customer_id, "anchor": anchor,
            "risk": sc, "stamp": _stamp_class(sc), "findings": findings, "counts": counts,
            "coverage": _coverage_view(a.coverage),
            "paths": [_path_view(rp) for rp in a.relay_paths],
        })
    fix_first.sort(key=lambda x: _RANK[x["f"].severity])
    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "scope": scope, "mode": mode, "version": __version__,
        "totals": totals, "total_findings": sum(totals.values()), "sev_order": [s.value for s in _SEV_ORDER],
        "abuse": abuse, "domains": domains, "fix_first": fix_first[:8], "fix_first_total": len(fix_first),
        "next_steps": next_steps or _DEFAULT_NEXT_STEPS,
        "spoof_rows": spoof_rows, "spoof_counts": spoof_counts, "spoof_level_label": LEVEL_LABEL,
        "exploit_rows": exploit_rows, "exploit_counts": exploit_counts,
        "exploit_level_label": EXPLOIT_LEVEL_LABEL, "exploit_status_label": EXPLOIT_STATUS_LABEL,
        "domain_anchor": domain_anchor,
    }


def _env() -> Environment:
    env = Environment(loader=PackageLoader("mailwarden", "templates"), autoescape=True,
                      trim_blocks=True, lstrip_blocks=True)
    env.filters["tojson_pretty"] = lambda v: json.dumps(v, indent=2, default=str)
    return env


def write_html(
    assessments: list[DomainAssessment],
    scores: dict[str, RiskScore],
    path: Path,
    *,
    scope: str,
    mode: str = "",
    next_steps: list[str] | None = None,
) -> None:
    ctx = _build_context(assessments, scores, scope, mode, next_steps)
    path.write_text(_env().get_template("report.html.j2").render(**ctx), encoding="utf-8")


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def write_all(
    assessments: list[DomainAssessment],
    out_dir: Path,
    *,
    scope: str,
    mode: str,
    notes: list[str],
    started: str,
    finished: str,
    strict_credential_guard: bool = True,
    formats: Iterable[str] | None = None,
) -> dict[str, Path]:
    """Write all reports. Raises CredentialLeakError before writing anything
    if the credential guard finds violations and strict_credential_guard=True.
    """
    guard = assert_no_credentials(assessments, strict=strict_credential_guard)
    if not guard.clean:
        notes = notes + [f"WARNING: credential guard reported {len(guard.violations)} "
                         "violation(s) but ran in lenient mode."]
    wanted = set(formats) if formats else {"html", "csv", "json"}
    out_dir.mkdir(parents=True, exist_ok=True)
    engine = RiskEngine()
    scores = {a.domain: engine.score(a) for a in assessments}

    paths: dict[str, Path] = {"metadata": out_dir / "scan_metadata.json"}
    if "html" in wanted:
        paths["html"] = out_dir / "summary.html"
        write_html(assessments, scores, paths["html"], scope=scope, mode=mode)
    if "csv" in wanted:
        paths["csv"] = out_dir / "findings.csv"
        paths["abuse_review_csv"] = out_dir / "abuse_review.csv"
        paths["spoofing_risk_csv"] = out_dir / "spoofing_risk.csv"
        paths["relay_exploit_csv"] = out_dir / "relay_exploit.csv"
        write_csv(assessments, paths["csv"])
        write_abuse_review(assessments, paths["abuse_review_csv"])
        write_spoofing_risk(assessments, paths["spoofing_risk_csv"])
        write_relay_exploit(assessments, paths["relay_exploit_csv"])
    if "json" in wanted:
        paths["json"] = out_dir / "findings.json"
        write_json(assessments, paths["json"])
    write_metadata(paths["metadata"], scope=scope, mode=mode, notes=notes,
                   started=started, finished=finished)
    return paths
