import json
from datetime import date

import pytest

from mailwarden.activity_analysis import analyze_activity
from mailwarden.config import AppConfig
from mailwarden.errors import InputError
from mailwarden.input_loader import Authorization, load_authorization_manifest, load_domains
from mailwarden.models import AbuseStatus, DomainAssessment, Severity
from mailwarden.risk_engine import RiskEngine
from mailwarden.demo import build_demo_assessments


def test_load_domains_validates_and_dedupes(tmp_path):
    p = tmp_path / "d.txt"
    p.write_text("# c\nExample.com\nexample.com  # dup\n")
    assert load_domains(p) == ["example.com"]
    p.write_text("not a domain\n")
    with pytest.raises(InputError):
        load_domains(p)


def test_authorization_expiry(tmp_path):
    p = tmp_path / "a.json"
    p.write_text(json.dumps([{"domain": "a.com", "customer_id": "C1", "authorized": True,
                              "expires_on": "2000-01-01", "approved_ips": ["10.0.0.0/8"]}]))
    m = load_authorization_manifest(p)
    assert not m["a.com"].is_active()
    assert m["a.com"].is_active(today=date(1999, 1, 1))
    p.write_text(json.dumps([{"domain": "a.com"}]))
    with pytest.raises(InputError):
        load_authorization_manifest(p)


def test_config_unknown_key_rejected(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text("bogus = 1\n")
    with pytest.raises(InputError):
        AppConfig.load(p)


def test_activity_confirmed_abuse_only_from_google_events():
    auth = Authorization("a.com", "C1", True)
    ev = [{"actor": {"email": "u@a.com"}, "events": [{"name": "account_disabled_spamming_through_relay"}]}]
    assert any(f.abuse_status == AbuseStatus.CONFIRMED for f in analyze_activity(ev, auth))
    quiet = analyze_activity([], auth)
    assert quiet[0].abuse_status == AbuseStatus.NOT_ESTABLISHED


def test_risk_engine_never_treats_unassessed_as_healthy():
    a = DomainAssessment(domain="a.com")
    a.coverage["RELAY"] = "no evidence provided"
    s = RiskEngine().score(a)
    assert s.total == 100 and not s.complete and s.coverage_gaps


def test_models_round_trip():
    for a in build_demo_assessments():
        b = DomainAssessment.from_dict(json.loads(json.dumps(a.to_dict(), default=str)))
        assert b.to_dict() == a.to_dict()


def test_demo_covers_all_verdicts():
    verdicts = {rp.unauthorized_use_possible.value for a in build_demo_assessments() for rp in a.relay_paths}
    assert verdicts == {"confirmed", "suspected", "not_established", "not_assessed"}
