import csv
import json

from mailwarden.models import (
    AbuseExposure, AbuseStatus, Category, Confidence, DomainAssessment,
    Finding, RelayPath, Severity, UnauthorizedUse,
)
from mailwarden.reporting import write_all, write_html


def _assessment_with_path():
    a = DomainAssessment(domain="example.com", customer_id="C1")
    a.coverage["SPF"] = "ran"
    a.add_finding(Finding(
        domain="example.com", category=Category.SPF, component="SPF",
        severity=Severity.HIGH, confidence=Confidence.HIGH,
        title="Test <script>alert(1)</script>",
        evidence={"value": "v=spf1 -all"},
        detection_method="unit", business_impact="x", remediation="y",
        abuse_status=AbuseStatus.NOT_ESTABLISHED,
    ))
    a.relay_paths.append(RelayPath(
        path_id="RP-001",
        domain="example.com",
        customer_id="C1",
        kind="smtp_relay",
        authentication_required=False,
        sender_policy="wildcard",
        allowed_senders=["*"],
        authorized_cidrs=["203.0.113.0/28"],
        tls_required=False,
        abuse_exposure=AbuseExposure.HIGH,
        unauthorized_use_possible=UnauthorizedUse.SUSPECTED,
        evidence_source="relay/example.com.relay.json",
        collected_at="2025-01-15T12:00:00Z",
        collected_by="admin@example.com",
        why_not_confirmed="No matching audit event in window.",
        remediation="Require SMTP AUTH; restrict senders; enforce TLS.",
        finding_ids=["F-AAA"],
    ))
    a.finished_at = a.started_at
    return a


def test_html_escapes_user_content(tmp_path):
    a = _assessment_with_path()
    out = tmp_path / "summary.html"
    write_html([a], {}, out, scope="example.com")
    text = out.read_text()
    assert "<script>alert(1)</script>" not in text
    assert "&lt;script&gt;" in text


def test_write_all_creates_expected_files(tmp_path):
    a = _assessment_with_path()
    paths = write_all(
        [a], tmp_path, scope="example.com", mode="full",
        notes=[], started=a.started_at, finished=a.started_at,
    )
    for k in ("html", "csv", "abuse_review_csv", "json", "metadata"):
        assert paths[k].exists()
    meta = json.loads(paths["metadata"].read_text())
    assert any("cross-customer target list" in lim for lim in meta["limitations"])
    assert any("credential" in lim.lower() for lim in meta["limitations"])


def test_abuse_review_csv_has_one_row_per_path(tmp_path):
    a = _assessment_with_path()
    paths = write_all(
        [a], tmp_path, scope="example.com", mode="full",
        notes=[], started=a.started_at, finished=a.started_at,
    )
    with paths["abuse_review_csv"].open() as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == 1
    r = rows[0]
    assert r["domain"] == "example.com"
    assert r["customer_id"] == "C1"
    assert r["unauthorized_use_possible"] == "suspected"
    assert r["abuse_exposure"] == "HIGH"
    assert r["authentication_required"] == "False"
    # Guard against credential leakage through CSV columns
    assert "password" not in r
    assert "secret" not in r


def test_findings_json_includes_relay_paths(tmp_path):
    a = _assessment_with_path()
    paths = write_all(
        [a], tmp_path, scope="example.com", mode="full",
        notes=[], started=a.started_at, finished=a.started_at,
    )
    data = json.loads(paths["json"].read_text())
    dom = data["domains"][0]
    assert "relay_paths" in dom
    assert dom["relay_paths"][0]["path_id"] == "RP-001"
    assert dom["relay_paths"][0]["unauthorized_use_possible"] == "suspected"