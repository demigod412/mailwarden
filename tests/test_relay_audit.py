from datetime import date
import ipaddress

from mailwarden.input_loader import Authorization
from mailwarden.models import (
    AbuseExposure, Severity, UnauthorizedUse,
)
from mailwarden.relay_audit import (
    RelayEvidence, audit_relay, build_relay_paths,
)


def _auth(ips=("203.0.113.0/24",)):
    return Authorization(
        domain="example.com", customer_id="C1", authorized=True,
        expires_on=date(2099, 1, 1),
        approved_ips=[ipaddress.ip_network(i) for i in ips],
    )


def _ev(**kw):
    base = dict(domain="example.com", source="x.relay.json",
                require_tls=True, require_auth=True,
                allowed_senders=["example.com"], authorized_ips=[])
    base.update(kw)
    return RelayEvidence(**base)


def test_missing_evidence_yields_not_assessed_path():
    paths = build_relay_paths(evidence=None, authorization=_auth(),
                              findings=[], coverage_gaps=["RELAY: no evidence"])
    assert len(paths) == 1
    p = paths[0]
    assert p.abuse_exposure == AbuseExposure.NOT_ASSESSED
    assert p.unauthorized_use_possible == UnauthorizedUse.NOT_ASSESSED
    assert p.customer_id == "C1"
    assert "no evidence" in p.why_not_confirmed.lower() or \
           "no relay configuration evidence" in p.why_not_confirmed.lower()


def test_clean_config_yields_none_exposure():
    ev = _ev()
    findings = audit_relay(ev, _auth())
    paths = build_relay_paths(ev, _auth(), findings)
    assert paths[0].abuse_exposure == AbuseExposure.NONE
    assert paths[0].unauthorized_use_possible == UnauthorizedUse.NOT_ESTABLISHED


def test_auth_off_and_wildcard_is_high_suspected():
    ev = _ev(require_auth=False, allowed_senders=["*"], require_tls=False)
    findings = audit_relay(ev, _auth())
    paths = build_relay_paths(ev, _auth(), findings)
    p = paths[0]
    assert p.abuse_exposure == AbuseExposure.HIGH
    # No confirmed audit evidence -> suspected, not confirmed
    assert p.unauthorized_use_possible == UnauthorizedUse.SUSPECTED
    assert "no matching" in p.why_not_confirmed.lower()


def test_wildcard_only_is_medium():
    ev = _ev(allowed_senders=["*"])
    findings = audit_relay(ev, _auth())
    paths = build_relay_paths(ev, _auth(), findings)
    assert paths[0].abuse_exposure == AbuseExposure.MEDIUM
    assert paths[0].sender_policy == "wildcard"
    assert paths[0].unauthorized_use_possible == UnauthorizedUse.SUSPECTED


def test_auth_off_only_is_medium():
    ev = _ev(require_auth=False)
    findings = audit_relay(ev, _auth())
    paths = build_relay_paths(ev, _auth(), findings)
    assert paths[0].abuse_exposure == AbuseExposure.MEDIUM
    assert paths[0].sender_policy == "restricted"


def test_tls_only_gap_is_low():
    ev = _ev(require_tls=False)
    findings = audit_relay(ev, _auth())
    paths = build_relay_paths(ev, _auth(), findings)
    assert paths[0].abuse_exposure == AbuseExposure.LOW
    assert paths[0].unauthorized_use_possible == UnauthorizedUse.NOT_ESTABLISHED


def test_confirmed_when_abuse_event_present():
    ev = _ev(require_auth=False, allowed_senders=["*"])
    findings = audit_relay(ev, _auth())
    # Simulate a confirmed abuse finding
    from mailwarden.models import (
        AbuseStatus, Category, Confidence, Finding,
    )
    findings.append(Finding(
        domain="example.com", category=Category.ACTIVITY, component="Account audit",
        severity=Severity.CRITICAL, confidence=Confidence.HIGH,
        title="Google disabled account for abuse: account_disabled_spamming_through_relay",
        evidence={}, detection_method="Reports API",
        business_impact="x", remediation="y",
        abuse_status=AbuseStatus.CONFIRMED,
    ))
    paths = build_relay_paths(ev, _auth(), findings)
    assert paths[0].unauthorized_use_possible == UnauthorizedUse.CONFIRMED


def test_any_ip_no_auth_emits_open_relay_finding_and_high_exposure():
    ev = _ev(require_auth=False, ip_restriction_enabled=False)
    findings = audit_relay(ev, _auth())
    titles = [f.title for f in findings]
    assert "SMTP relay accepts mail from any IP with no authentication" in titles
    open_f = next(f for f in findings
                  if f.title == "SMTP relay accepts mail from any IP with no authentication")
    assert open_f.severity == Severity.HIGH
    assert "smtp-relay.gmail.com" in open_f.business_impact
    paths = build_relay_paths(ev, _auth(), findings)
    assert paths[0].abuse_exposure == AbuseExposure.HIGH
    assert paths[0].ip_restriction == "none"
    assert paths[0].relay_host == "smtp-relay.gmail.com"


def test_any_ip_with_auth_is_medium_defence_in_depth():
    ev = _ev(require_auth=True, ip_restriction_enabled=False)
    findings = audit_relay(ev, _auth())
    titles = [f.title for f in findings]
    assert "SMTP relay has no IP range restriction (any IP accepted)" in titles
    paths = build_relay_paths(ev, _auth(), findings)
    # Auth still gates sending, so not an open relay -> not HIGH exposure.
    assert paths[0].abuse_exposure != AbuseExposure.HIGH
    assert paths[0].ip_restriction == "none"


def test_zero_slash_zero_counts_as_any_ip():
    ev = _ev(require_auth=False, authorized_ips=["0.0.0.0/0"])
    findings = audit_relay(ev, _auth())
    assert any(f.title == "SMTP relay accepts mail from any IP with no authentication"
               for f in findings)


def test_restricted_ranges_does_not_emit_open_relay_finding():
    ev = _ev(require_auth=False, authorized_ips=["203.0.113.0/28"])
    findings = audit_relay(ev, _auth())
    assert not any("any IP" in f.title for f in findings)
    paths = build_relay_paths(ev, _auth(), findings)
    assert paths[0].ip_restriction == "restricted"


def test_path_records_evidence_provenance():
    ev = RelayEvidence(
        domain="example.com", source="relay/example.com.relay.json",
        require_tls=True, require_auth=True,
        allowed_senders=["example.com"], authorized_ips=[],
        collected_at="2025-01-15T12:00:00Z", collected_by="admin@example.com",
    )
    findings = audit_relay(ev, _auth())
    paths = build_relay_paths(ev, _auth(), findings)
    assert paths[0].evidence_source == "relay/example.com.relay.json"
    assert paths[0].collected_by == "admin@example.com"
    assert paths[0].collected_at == "2025-01-15T12:00:00Z"