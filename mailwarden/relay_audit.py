"""SMTP relay configuration evidence parsing, inspection, and per-path verdicts.

Design constraints (from the project brief, §5 and §7):
  * Relay evidence must come from an authorized administrator export.
  * Missing evidence -> NOT_ASSESSED, never a clean bill of health.
  * "Unverified" IPs are labelled as such, not declared malicious.
  * A confirmed "unauthorized bulk sending" verdict requires matching audit
    evidence, not just a permissive-looking configuration.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import EvidenceError
from .input_loader import Authorization
from .models import (
    AbuseExposure,
    AbuseStatus,
    Category,
    Confidence,
    Finding,
    RelayPath,
    Severity,
    UnauthorizedUse,
)

log = logging.getLogger(__name__)

REQUIRED_KEYS = {"require_tls", "require_auth", "allowed_senders"}

_WILDCARD_SENDER_TOKENS = {"*", "*@*", "any", "any@*", "all"}

# The canonical Google Workspace SMTP relay host. Used as the default when the
# evidence does not name one, since this tool is Workspace-scoped.
GOOGLE_RELAY_HOST = "smtp-relay.gmail.com"

# Tokens / networks that mean "any IP on the internet is accepted" -- i.e. the
# "Only accept mail from the specified IP addresses" box is effectively off.
_ANY_IP_TOKENS = {"any", "all", "*", "0.0.0.0", "0.0.0.0/0", "::/0", "::", "0::/0"}


def _is_any_ip_entry(raw: str) -> bool:
    s = raw.strip().lower()
    if s in _ANY_IP_TOKENS:
        return True
    try:
        net = ipaddress.ip_network(s, strict=False)
    except ValueError:
        return False
    # A /0 network (0.0.0.0/0 or ::/0) covers the entire address space.
    return net.prefixlen == 0


@dataclass(slots=True)
class RelayEvidence:
    domain: str
    source: str
    require_tls: bool | None
    require_auth: bool | None
    allowed_senders: list[str] = field(default_factory=list)
    authorized_ips: list[str] = field(default_factory=list)
    # Mirrors the Admin console "Only accept mail from the specified IP
    # addresses" checkbox. True = allowlist enforced, False = any IP accepted,
    # None = the exporter did not capture it (stays "unknown", never "clean").
    ip_restriction_enabled: bool | None = None
    relay_host: str = ""
    notes: str = ""
    collected_at: str | None = None
    collected_by: str | None = None

    @classmethod
    def from_dict(cls, payload: dict[str, Any], source: str) -> "RelayEvidence":
        missing = [k for k in REQUIRED_KEYS if k not in payload]
        if missing:
            raise EvidenceError(f"relay evidence missing keys: {missing}")
        return cls(
            domain=str(payload.get("domain", "")).lower(),
            source=source,
            require_tls=payload.get("require_tls"),
            require_auth=payload.get("require_auth"),
            allowed_senders=list(payload.get("allowed_senders") or []),
            authorized_ips=list(payload.get("authorized_ips") or []),
            ip_restriction_enabled=payload.get("ip_restriction_enabled"),
            relay_host=str(payload.get("relay_host") or ""),
            notes=str(payload.get("notes", "")),
            collected_at=payload.get("collected_at"),
            collected_by=payload.get("collected_by"),
        )

    def ip_restriction(self) -> str:
        """Classify the relay's source-IP restriction as none|restricted|unknown.

        "none" means any host on the internet is accepted (open relay posture);
        "restricted" means only specific ranges are; "unknown" means the
        evidence did not capture it, so it is reported as a gap, never as clean.
        """
        if any(_is_any_ip_entry(ip) for ip in self.authorized_ips):
            return "none"
        if self.ip_restriction_enabled is False:
            return "none"
        if self.ip_restriction_enabled is True:
            return "restricted"
        if self.authorized_ips:
            return "restricted"
        return "unknown"


def load_relay_evidence(path: Path, expected_domain: str | None = None) -> RelayEvidence:
    if not path.exists():
        raise EvidenceError(f"relay evidence not found: {path}")
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        raise EvidenceError(f"relay evidence invalid JSON: {e}") from e
    if not isinstance(data, dict):
        raise EvidenceError("relay evidence must be a JSON object")
    ev = RelayEvidence.from_dict(data, source=str(path))
    if expected_domain:
        if ev.domain and ev.domain != expected_domain.lower():
            raise EvidenceError(
                f"evidence domain '{ev.domain}' does not match expected "
                f"'{expected_domain}' (wrong file for this customer?)")
        ev.domain = expected_domain.lower()
    return ev


def _parse_networks(items: list[str]) -> list[ipaddress._BaseNetwork]:
    nets = []
    for raw in items:
        try:
            nets.append(ipaddress.ip_network(raw, strict=False))
        except ValueError:
            log.warning("relay evidence contains invalid CIDR",
                        extra={"extra_fields": {"value": raw}})
    return nets


# ---------------------------------------------------------------------------
# Findings (per-issue) -- unchanged behaviour, still emitted for CSV fidelity
# ---------------------------------------------------------------------------

def audit_relay(
    evidence: RelayEvidence,
    authorization: Authorization | None,
) -> list[Finding]:
    findings: list[Finding] = []
    domain = evidence.domain

    if evidence.require_tls is False:
        findings.append(Finding(
            domain=domain, category=Category.RELAY, component="SMTP relay",
            severity=Severity.HIGH, confidence=Confidence.HIGH,
            title="Relay does not require TLS",
            evidence={"evidence_source": evidence.source, "require_tls": False},
            detection_method="Imported relay evidence",
            business_impact="Credentials / mail content may transit in cleartext.",
            remediation="Enable 'Require TLS encryption' on the SMTP relay service.",
            abuse_status=AbuseStatus.NOT_ESTABLISHED,
        ))
    elif evidence.require_tls is True:
        findings.append(Finding(
            domain=domain, category=Category.RELAY, component="SMTP relay",
            severity=Severity.INFORMATIONAL, confidence=Confidence.HIGH,
            title="Relay requires TLS",
            evidence={"evidence_source": evidence.source},
            detection_method="Imported relay evidence",
            business_impact="Transport encryption enforced.",
            remediation="Maintain certificate rotation.",
        ))

    if evidence.require_auth is False:
        findings.append(Finding(
            domain=domain, category=Category.RELAY, component="SMTP relay",
            severity=Severity.MEDIUM, confidence=Confidence.HIGH,
            title="SMTP relay does not require authentication",
            evidence={"evidence_source": evidence.source, "require_auth": False,
                      "authorized_ips": evidence.authorized_ips},
            detection_method="Imported relay evidence",
            business_impact="Any host in an authorized IP range can relay mail.",
            remediation="Require SMTP AUTH unless the IP allowlist is strictly controlled.",
            abuse_status=(AbuseStatus.SUSPECTED if evidence.authorized_ips
                          else AbuseStatus.NOT_ESTABLISHED),
        ))

    restriction = evidence.ip_restriction()
    host = evidence.relay_host or GOOGLE_RELAY_HOST
    if restriction == "none":
        # No source-IP allowlist at all. If authentication is also off, any host
        # on the internet can submit mail through the relay -> an open relay for
        # this domain. This is the "bulk mail from any IP" exposure specifically.
        if evidence.require_auth is False:
            findings.append(Finding(
                domain=domain, category=Category.RELAY, component="SMTP relay",
                severity=Severity.HIGH, confidence=Confidence.HIGH,
                title="SMTP relay accepts mail from any IP with no authentication",
                evidence={"evidence_source": evidence.source, "relay_host": host,
                          "ip_restriction_enabled": evidence.ip_restriction_enabled,
                          "authorized_ips": evidence.authorized_ips},
                detection_method="Imported relay evidence (IP-restriction check)",
                business_impact=(
                    f"With no IP range restriction and no authentication, any host "
                    f"on the internet can relay mail through {host} as this domain "
                    "(open relay) -- usable for bulk or phishing mail."),
                remediation=(
                    "In Admin console > Apps > Google Workspace > Gmail > Routing > "
                    "SMTP relay service, enable 'Only accept mail from the specified "
                    "IP addresses' and list your sending ranges, and/or require SMTP "
                    "authentication."),
                abuse_status=AbuseStatus.SUSPECTED,
            ))
        else:
            findings.append(Finding(
                domain=domain, category=Category.RELAY, component="SMTP relay",
                severity=Severity.MEDIUM, confidence=Confidence.HIGH,
                title="SMTP relay has no IP range restriction (any IP accepted)",
                evidence={"evidence_source": evidence.source, "relay_host": host,
                          "ip_restriction_enabled": evidence.ip_restriction_enabled,
                          "authorized_ips": evidence.authorized_ips},
                detection_method="Imported relay evidence (IP-restriction check)",
                business_impact=(
                    "Any IP may submit mail; SMTP authentication is the only control "
                    "left. If a relay credential leaks, the relay is wide open."),
                remediation=(
                    "Enable 'Only accept mail from the specified IP addresses' and "
                    "list your sending ranges as defence in depth alongside SMTP AUTH."),
                abuse_status=AbuseStatus.NOT_ESTABLISHED,
            ))

    if any(s.strip().lower() in _WILDCARD_SENDER_TOKENS
           for s in evidence.allowed_senders):
        findings.append(Finding(
            domain=domain, category=Category.RELAY, component="SMTP relay",
            severity=Severity.HIGH, confidence=Confidence.HIGH,
            title="Relay accepts any sender address",
            evidence={"evidence_source": evidence.source,
                      "allowed_senders": evidence.allowed_senders},
            detection_method="Imported relay evidence",
            business_impact="Any relayed mail can forge arbitrary From: addresses.",
            remediation="Restrict 'Allowed senders' to specific domains/users.",
            abuse_status=AbuseStatus.SUSPECTED,
        ))

    if authorization is not None:
        approved = set(authorization.approved_ips)
        evidenced = _parse_networks(evidence.authorized_ips)
        unverified = []
        for net in evidenced:
            if not any(a.version == net.version and (net.subnet_of(a) or a.subnet_of(net))
                       for a in approved):
                unverified.append(str(net))
        if unverified:
            findings.append(Finding(
                domain=domain, category=Category.RELAY, component="SMTP relay",
                severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
                title=f"{len(unverified)} relay-authorized IP(s) not in customer "
                      f"inventory (unverified)",
                evidence={"unverified": unverified,
                          "inventory": [str(n) for n in approved]},
                detection_method="Set-difference against authorization manifest",
                business_impact="Unverified hosts can relay mail if left unaddressed.",
                remediation="Confirm each unverified IP with the customer before removal.",
                abuse_status=AbuseStatus.SUSPECTED,
            ))

    if not findings:
        findings.append(Finding(
            domain=domain, category=Category.RELAY, component="SMTP relay",
            severity=Severity.INFORMATIONAL, confidence=Confidence.MEDIUM,
            title="No issue found in examined relay evidence",
            evidence={"evidence_source": evidence.source},
            detection_method="Imported relay evidence review",
            business_impact=("Configuration appears consistent with policy in "
                             "provided evidence."),
            remediation="Re-export evidence after any relay change.",
        ))
    return findings


def diff_against_baseline(
    current: RelayEvidence,
    baseline: RelayEvidence,
) -> list[Finding]:
    findings: list[Finding] = []
    domain = current.domain
    if baseline.require_tls is True and current.require_tls is not True:
        findings.append(Finding(
            domain=domain, category=Category.RELAY, component="SMTP relay",
            severity=Severity.HIGH, confidence=Confidence.HIGH,
            title="TLS requirement removed since baseline",
            evidence={"baseline_source": baseline.source,
                      "current_source": current.source},
            detection_method="Baseline diff",
            business_impact="A previously enforced control has been disabled.",
            remediation="Investigate change; re-enable TLS requirement.",
            abuse_status=AbuseStatus.SUSPECTED,
        ))
    base_ips = set(baseline.authorized_ips)
    cur_ips = set(current.authorized_ips)
    new_ips = sorted(cur_ips - base_ips)
    if new_ips:
        findings.append(Finding(
            domain=domain, category=Category.RELAY, component="SMTP relay",
            severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
            title=f"New relay-authorized IPs since baseline: {len(new_ips)}",
            evidence={"added": new_ips},
            detection_method="Baseline diff",
            business_impact="New hosts may broaden relay access.",
            remediation="Validate each added IP with change management.",
        ))
    return findings


# ---------------------------------------------------------------------------
# Per-path verdict
# ---------------------------------------------------------------------------

def _classify_sender_policy(allowed_senders: list[str]) -> str:
    if not allowed_senders:
        return "unknown"
    if any(s.strip().lower() in _WILDCARD_SENDER_TOKENS for s in allowed_senders):
        return "wildcard"
    return "restricted"


def _compute_exposure(ev: RelayEvidence, sender_policy: str) -> AbuseExposure:
    auth_off = ev.require_auth is False
    wildcard = sender_policy == "wildcard"
    tls_off = ev.require_tls is False
    no_ip_restriction = ev.ip_restriction() == "none"
    # No source-IP restriction AND no authentication == open relay: the whole
    # internet can send through it, which is as exposed as a wildcard sender.
    if auth_off and (wildcard or no_ip_restriction):
        return AbuseExposure.HIGH
    if auth_off or wildcard:
        return AbuseExposure.MEDIUM
    if tls_off:
        return AbuseExposure.LOW
    return AbuseExposure.NONE


def _verdict(
    exposure: AbuseExposure,
    has_confirmed_abuse: bool,
) -> tuple[UnauthorizedUse, str]:
    """Return (verdict, why_not_confirmed_text)."""
    if exposure in (AbuseExposure.HIGH, AbuseExposure.MEDIUM):
        if has_confirmed_abuse:
            return (
                UnauthorizedUse.CONFIRMED,
                "Confirmed by Google Workspace abuse audit events "
                "(e.g. account disabled for relay spam).",
            )
        return (
            UnauthorizedUse.SUSPECTED,
            "Configuration would permit unauthenticated or over-broad sending, "
            "but no matching login or abuse audit event in the assessment window "
            "confirmed that unauthorized use actually occurred.",
        )
    if exposure == AbuseExposure.LOW:
        return (
            UnauthorizedUse.NOT_ESTABLISHED,
            "TLS-only gap; SMTP AUTH and sender restrictions are in place.",
        )
    if exposure == AbuseExposure.NONE:
        return (
            UnauthorizedUse.NOT_ESTABLISHED,
            "Authentication required, senders restricted, TLS enforced.",
        )
    return (
        UnauthorizedUse.NOT_ASSESSED,
        "Insufficient relay evidence to reach a verdict.",
    )


def _remediation_for(ev: RelayEvidence, sender_policy: str) -> str:
    parts: list[str] = []
    if ev.require_auth is False:
        parts.append("Require SMTP AUTH")
    if sender_policy == "wildcard":
        parts.append("Restrict allowed senders to specific domains/users")
    if ev.require_tls is False:
        parts.append("Enforce 'Require TLS encryption'")
    if not parts:
        return "No change needed based on the evidence examined."
    return "; ".join(parts) + "."


def _confirmed_abuse_from_findings(findings: list[Finding]) -> bool:
    return any(f.abuse_status == AbuseStatus.CONFIRMED for f in findings)


def build_relay_paths(
    evidence: RelayEvidence | None,
    authorization: Authorization | None,
    findings: list[Finding],
    coverage_gaps: list[str] | None = None,
    domain: str | None = None,
) -> list[RelayPath]:
    """Consolidate relay findings for one customer/domain into a per-path verdict.

    Never produces a cross-customer target list. Always returns at least one
    RelayPath; if evidence is missing, the path is NOT_ASSESSED.
    """
    domain = (evidence.domain if evidence
              else (domain or (authorization.domain if authorization else "unknown")))
    customer_id = authorization.customer_id if authorization else None
    coverage_gaps = coverage_gaps or []

    if evidence is None:
        return [RelayPath(
            path_id=f"RP-{uuid.uuid4().hex[:8].upper()}",
            domain=domain,
            customer_id=customer_id,
            kind="unknown",
            authentication_required=None,
            sender_policy="unknown",
            abuse_exposure=AbuseExposure.NOT_ASSESSED,
            unauthorized_use_possible=UnauthorizedUse.NOT_ASSESSED,
            evidence_source="",
            why_not_confirmed=("No relay configuration evidence was supplied for "
                               "this domain; a verdict cannot be reached."),
            remediation=("Export SMTP relay settings from the Admin console and "
                         "provide them as <domain>.relay.json."),
            coverage_gaps=list(dict.fromkeys(coverage_gaps + ["RELAY: no evidence"])),
        )]

    sender_policy = _classify_sender_policy(evidence.allowed_senders)
    exposure = _compute_exposure(evidence, sender_policy)
    confirmed = _confirmed_abuse_from_findings(findings)
    verdict, why = _verdict(exposure, confirmed)

    related_finding_ids = [f.finding_id for f in findings
                           if f.category == Category.RELAY]

    return [RelayPath(
        path_id=f"RP-{uuid.uuid4().hex[:8].upper()}",
        domain=domain,
        customer_id=customer_id,
        kind="smtp_relay",
        authentication_required=evidence.require_auth,
        sender_policy=sender_policy,
        allowed_senders=list(evidence.allowed_senders),
        authorized_cidrs=list(evidence.authorized_ips),
        tls_required=evidence.require_tls,
        ip_restriction=evidence.ip_restriction(),
        relay_host=evidence.relay_host or GOOGLE_RELAY_HOST,
        abuse_exposure=exposure,
        unauthorized_use_possible=verdict,
        evidence_source=evidence.source,
        collected_at=evidence.collected_at,
        collected_by=evidence.collected_by,
        why_not_confirmed=why,
        remediation=_remediation_for(evidence, sender_policy),
        finding_ids=related_finding_ids,
        coverage_gaps=coverage_gaps,
    )]
