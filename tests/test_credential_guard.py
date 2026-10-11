import pytest

from mailwarden.errors import CredentialLeakError
from mailwarden.models import (
    Category, Confidence, DomainAssessment, Finding, Severity,
)
from mailwarden.reporting import assert_no_credentials, scan_for_credentials


def _finding(evidence: dict, title: str = "t") -> Finding:
    return Finding(
        domain="example.com", category=Category.SPF, component="SPF",
        severity=Severity.HIGH, confidence=Confidence.HIGH,
        title=title, evidence=evidence, detection_method="m",
        business_impact="i", remediation="r",
    )


def _assessment(*findings) -> DomainAssessment:
    a = DomainAssessment(domain="example.com")
    for f in findings:
        a.add_finding(f)
    return a


def test_clean_evidence_passes():
    a = _assessment(_finding({"record": "v=spf1 -all"}))
    report = assert_no_credentials([a], strict=True)
    assert report.clean


def test_password_key_with_value_raises():
    a = _assessment(_finding({"record": "v=spf1 -all", "password": "hunter2"}))
    with pytest.raises(CredentialLeakError):
        assert_no_credentials([a], strict=True)


def test_password_key_redacted_value_passes():
    a = _assessment(_finding({"password": "<REDACTED>"}))
    report = assert_no_credentials([a], strict=True)
    assert report.clean


def test_google_api_key_value_raises():
    a = _assessment(_finding({"note": "key=AIza" + "A" * 35}))
    with pytest.raises(CredentialLeakError):
        assert_no_credentials([a], strict=True)


def test_oauth_refresh_token_value_raises():
    a = _assessment(_finding({"note": "1//" + "x" * 60}))
    with pytest.raises(CredentialLeakError):
        assert_no_credentials([a], strict=True)


def test_private_key_block_raises():
    a = _assessment(_finding({"note": "-----BEGIN RSA PRIVATE KEY-----\nMII..."}))
    with pytest.raises(CredentialLeakError):
        assert_no_credentials([a], strict=True)


def test_bearer_token_raises():
    a = _assessment(_finding({"header": "Authorization: Bearer " + "A" * 40}))
    with pytest.raises(CredentialLeakError):
        assert_no_credentials([a], strict=True)


def test_lenient_mode_reports_without_raising():
    a = _assessment(_finding({"password": "hunter2"}))
    report = assert_no_credentials([a], strict=False)
    assert not report.clean
    assert len(report.violations) >= 1
    # Ensure the violation message never contains the secret value itself.
    assert "hunter2" not in report.violations[0]


def test_scan_reports_location_not_value():
    a = _assessment(_finding({"password": "hunter2"}, title="contains secret"))
    report = scan_for_credentials([a])
    assert any("password" in v for v in report.violations)
    assert all("hunter2" not in v for v in report.violations)


def test_nested_evidence_is_scanned():
    a = _assessment(_finding({"outer": {"inner": {"client_secret": "GOCSPX-abcdefghij"}}}))
    report = scan_for_credentials([a])
    assert not report.clean