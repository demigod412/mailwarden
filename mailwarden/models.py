"""Canonical data models shared across Mailwarden modules."""
from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"
    NOT_ASSESSED = "NOT_ASSESSED"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AbuseStatus(str, Enum):
    """Per-finding abuse verdict. Conservative by design."""
    CONFIRMED = "confirmed"
    SUSPECTED = "suspected"
    NOT_ESTABLISHED = "not_established"
    NOT_ASSESSED = "not_assessed"


class AbuseExposure(str, Enum):
    """How exposed a relay path is to unauthorized bulk sending."""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"
    NOT_ASSESSED = "NOT_ASSESSED"


class UnauthorizedUse(str, Enum):
    """Per-path verdict on whether unauthorized use is occurring."""
    CONFIRMED = "confirmed"
    SUSPECTED = "suspected"
    NOT_ESTABLISHED = "not_established"
    NOT_ASSESSED = "not_assessed"


class Category(str, Enum):
    SPF = "SPF"
    DKIM = "DKIM"
    DMARC = "DMARC"
    MX = "MX"
    DNSSEC = "DNSSEC"
    LOGIN = "LOGIN"
    ADMIN = "ADMIN"
    SECURITY_SETTINGS = "SECURITY_SETTINGS"
    RELAY = "RELAY"
    ACTIVITY = "ACTIVITY"
    COVERAGE = "COVERAGE"


@dataclass(slots=True)
class Finding:
    domain: str
    category: Category
    component: str
    severity: Severity
    confidence: Confidence
    title: str
    evidence: dict[str, Any]
    detection_method: str
    business_impact: str
    remediation: str
    abuse_status: AbuseStatus = AbuseStatus.NOT_ASSESSED
    finding_id: str = field(default_factory=lambda: f"F-{uuid.uuid4().hex[:10].upper()}")
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        d["category"] = self.category.value
        d["abuse_status"] = self.abuse_status.value
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Finding":
        d = dict(d)
        d["category"] = Category(d["category"])
        d["severity"] = Severity(d["severity"])
        d["confidence"] = Confidence(d["confidence"])
        d["abuse_status"] = AbuseStatus(d.get("abuse_status", "not_assessed"))
        d.setdefault("evidence", {})
        known = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in d.items() if k in known})


@dataclass(slots=True)
class RelayPath:
    """A single relaying path (e.g. SMTP relay service) for ONE customer.

    This is scoped to the authorized customer's own infrastructure. It is
    intentionally not a cross-customer target list; the tool refuses to
    aggregate paths into a "domains that can be spammed" artifact.
    """
    path_id: str
    domain: str
    customer_id: str | None
    kind: str  # "smtp_relay" | "workspace_relay" | "unknown"
    authentication_required: bool | None
    sender_policy: str  # "wildcard" | "restricted" | "unknown"
    allowed_senders: list[str] = field(default_factory=list)
    authorized_cidrs: list[str] = field(default_factory=list)
    tls_required: bool | None = None
    # "none" = accepts mail from any IP (no range restriction), "restricted" =
    # limited to specific IP ranges, "unknown" = not captured in the evidence.
    ip_restriction: str = "unknown"
    relay_host: str = ""
    abuse_exposure: AbuseExposure = AbuseExposure.NOT_ASSESSED
    unauthorized_use_possible: UnauthorizedUse = UnauthorizedUse.NOT_ASSESSED
    evidence_source: str = ""
    collected_at: str | None = None
    collected_by: str | None = None
    why_not_confirmed: str = ""
    remediation: str = ""
    finding_ids: list[str] = field(default_factory=list)
    coverage_gaps: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["abuse_exposure"] = self.abuse_exposure.value
        d["unauthorized_use_possible"] = self.unauthorized_use_possible.value
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "RelayPath":
        d = dict(d)
        d["abuse_exposure"] = AbuseExposure(d.get("abuse_exposure", "NOT_ASSESSED"))
        d["unauthorized_use_possible"] = UnauthorizedUse(
            d.get("unauthorized_use_possible", "not_assessed"))
        d.setdefault("path_id", "RP-UNKNOWN")
        d.setdefault("kind", "unknown")
        d.setdefault("sender_policy", "unknown")
        d.setdefault("authentication_required", None)
        d.setdefault("customer_id", None)
        d.setdefault("ip_restriction", "unknown")
        d.setdefault("relay_host", "")
        known = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in d.items() if k in known})


@dataclass(slots=True)
class DomainAssessment:
    domain: str
    customer_id: str | None = None
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: str | None = None
    findings: list[Finding] = field(default_factory=list)
    relay_paths: list[RelayPath] = field(default_factory=list)
    coverage: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def add_finding(self, f: Finding) -> None:
        self.findings.append(f)

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "customer_id": self.customer_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "coverage": dict(self.coverage),
            "notes": list(self.notes),
            "findings": [f.to_dict() for f in self.findings],
            "relay_paths": [rp.to_dict() for rp in self.relay_paths],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "DomainAssessment":
        a = cls(domain=d["domain"], customer_id=d.get("customer_id"))
        a.started_at = d.get("started_at", a.started_at)
        a.finished_at = d.get("finished_at")
        a.coverage = dict(d.get("coverage", {}))
        a.notes = list(d.get("notes", []))
        a.findings = [Finding.from_dict(x) for x in d.get("findings", [])]
        a.relay_paths = [RelayPath.from_dict(x) for x in d.get("relay_paths", [])]
        return a
