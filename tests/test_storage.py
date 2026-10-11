import json

from mailwarden.models import (
    AbuseExposure, Category, Confidence, DomainAssessment, Finding,
    RelayPath, Severity, UnauthorizedUse,
)
from mailwarden.storage import ResultStore


def test_relay_paths_round_trip(tmp_path):
    a = DomainAssessment(domain="example.com", customer_id="C1")
    a.add_finding(Finding(
        domain="example.com", category=Category.RELAY, component="SMTP relay",
        severity=Severity.HIGH, confidence=Confidence.HIGH,
        title="t", evidence={}, detection_method="m",
        business_impact="i", remediation="r",
    ))
    a.relay_paths.append(RelayPath(
        path_id="RP-1", domain="example.com", customer_id="C1",
        kind="smtp_relay", authentication_required=False,
        sender_policy="wildcard", allowed_senders=["*"],
        authorized_cidrs=[], tls_required=False,
        abuse_exposure=AbuseExposure.HIGH,
        unauthorized_use_possible=UnauthorizedUse.SUSPECTED,
        evidence_source="x", why_not_confirmed="why",
        remediation="fix", finding_ids=[],
    ))
    store = ResultStore(tmp_path)
    p = store.save_assessment(a)
    data = json.loads(p.read_text())
    assert data["relay_paths"][0]["path_id"] == "RP-1"
    assert data["relay_paths"][0]["unauthorized_use_possible"] == "suspected"