"""Tests for the active relay probe. No real network: smtplib is faked."""
import ipaddress

import pytest

from mailwarden import relay_probe
from mailwarden.models import Category, DomainAssessment, Severity
from mailwarden.relay_exploit import assess
from mailwarden.relay_probe import (
    probe_finding, probe_relay, _in_ranges, _source_ip_from_ehlo,
)

EHLO = b"smtp-relay.gmail.com at your service, [198.51.100.9]\nSTARTTLS\nAUTH LOGIN PLAIN"


class FakeSMTP:
    """Scripted SMTP server. `script` maps ('MAIL'|'RCPT') -> (code, msg)."""
    script: dict = {}
    ehlo_msg: bytes = EHLO

    def __init__(self, host, port, timeout=None):
        self.host, self.port = host, port

    def ehlo(self):
        return 250, self.ehlo_msg

    def has_extn(self, name):
        return name.lower() == "starttls"

    def starttls(self, context=None):
        return 220, b"ok"

    def docmd(self, cmd, arg=""):
        return self.__class__.script.get(cmd, (250, b"2.1.0 OK"))

    def quit(self):
        pass

    def close(self):
        pass


@pytest.fixture
def fake_smtp(monkeypatch):
    def _install(script, ehlo_msg=EHLO):
        FakeSMTP.script = script
        FakeSMTP.ehlo_msg = ehlo_msg
        monkeypatch.setattr(relay_probe.smtplib, "SMTP", FakeSMTP)
        monkeypatch.setattr(relay_probe.smtplib, "SMTP_SSL", FakeSMTP)
    return _install


# --- helpers ---------------------------------------------------------------

def test_source_ip_parsed_from_ehlo():
    assert _source_ip_from_ehlo(EHLO) == "198.51.100.9"
    assert _source_ip_from_ehlo(b"no brackets here") is None


def test_in_ranges():
    nets = [ipaddress.ip_network("203.0.113.0/24")]
    assert _in_ranges("203.0.113.9", nets) is True
    assert _in_ranges("198.51.100.9", nets) is False
    assert _in_ranges("198.51.100.9", []) is None


# --- probe outcomes --------------------------------------------------------

def test_open_relay_detected(fake_smtp):
    fake_smtp({"MAIL": (250, b"ok"), "RCPT": (250, b"ok")})
    r = probe_relay("risky.example", approved_ips=[ipaddress.ip_network("203.0.113.0/24")])
    assert r.outcome == "open"
    assert r.ip_restriction == "none"
    assert r.source_ip == "198.51.100.9"
    assert r.source_in_authorized_range is False  # 198.51.100.9 not in 203.0.113.0/24
    assert r.reliable_open is True
    assert r.effective_ip_restriction == "none"


def test_auth_required_is_restricted(fake_smtp):
    fake_smtp({"MAIL": (530, b"5.7.0 Authentication Required")})
    r = probe_relay("safe.example")
    assert r.outcome == "auth_required"
    assert r.ip_restriction == "restricted"


def test_relay_denied_is_restricted(fake_smtp):
    fake_smtp({"MAIL": (250, b"ok"), "RCPT": (550, b"5.7.1 relay denied")})
    r = probe_relay("safe.example")
    assert r.outcome == "relay_denied"
    assert r.ip_restriction == "restricted"


def test_open_but_inside_authorized_range_is_not_reliable(fake_smtp):
    # EHLO reports an IP that IS inside the approved range -> cannot prove "any IP".
    fake_smtp({"MAIL": (250, b"ok"), "RCPT": (250, b"ok")},
              ehlo_msg=b"smtp-relay.gmail.com at your service, [203.0.113.9]")
    r = probe_relay("risky.example", approved_ips=[ipaddress.ip_network("203.0.113.0/24")])
    assert r.outcome == "open"
    assert r.source_in_authorized_range is True
    assert r.reliable_open is False
    assert r.effective_ip_restriction == "unknown"


def test_network_error_is_inconclusive(monkeypatch):
    def boom(*a, **k):
        raise OSError("connection refused")
    monkeypatch.setattr(relay_probe.smtplib, "SMTP", boom)
    monkeypatch.setattr(relay_probe.smtplib, "SMTP_SSL", boom)
    r = probe_relay("x.example")
    assert r.outcome == "inconclusive"
    assert r.ip_restriction == "unknown"
    assert any("could not complete" in n for n in r.notes)


# --- finding + exploit verdict integration ---------------------------------

def test_probe_finding_open_is_high_and_feeds_exploit(fake_smtp):
    fake_smtp({"MAIL": (250, b"ok"), "RCPT": (250, b"ok")})
    r = probe_relay("risky.example", approved_ips=[ipaddress.ip_network("203.0.113.0/24")])
    f = probe_finding(r)
    assert f.severity == Severity.HIGH
    assert f.category == Category.RELAY
    a = DomainAssessment(domain="risky.example", customer_id="C1")
    a.add_finding(f)
    verdict = assess(a)
    assert verdict.risk == "high"
    assert verdict.status == "probed"
    assert verdict.ip_restriction == "none"


def test_probe_finding_restricted_is_low_verdict(fake_smtp):
    fake_smtp({"MAIL": (530, b"5.7.0 Authentication Required")})
    r = probe_relay("safe.example")
    a = DomainAssessment(domain="safe.example", customer_id="C1")
    a.add_finding(probe_finding(r))
    verdict = assess(a)
    assert verdict.risk == "low"
    assert verdict.status == "probed"


def test_inconclusive_probe_falls_back_to_screening():
    # No conclusive probe finding -> assess uses DNS screening instead.
    from mailwarden.models import Confidence, Finding
    a = DomainAssessment(domain="g.example")
    a.add_finding(Finding(domain="g.example", category=Category.MX, component="MX",
                          severity=Severity.INFORMATIONAL, confidence=Confidence.HIGH,
                          title="MX points to Google Workspace", evidence={},
                          detection_method="MX lookup", business_impact="", remediation=""))
    a.add_finding(probe_finding(relay_probe.RelayProbeResult(
        domain="g.example", relay_host="smtp-relay.gmail.com",
        outcome="inconclusive", ip_restriction="unknown")))
    v = assess(a)
    assert v.status == "screening"  # inconclusive probe did not override screening


# --- CLI authorization gate -------------------------------------------------

def test_probe_requires_authorization():
    from argparse import Namespace
    from mailwarden.cli import _apply_probe
    from mailwarden.errors import ProbeError
    assessments = {"x.example": DomainAssessment(domain="x.example")}
    args = Namespace(probe_host="smtp-relay.gmail.com", probe_timeout=5, probe_rcpt=None)
    with pytest.raises(ProbeError):
        _apply_probe(assessments, {}, args)  # no authorization manifest -> refuse


def test_probe_skips_unauthorized_domains(monkeypatch):
    from argparse import Namespace
    from datetime import date
    from mailwarden import cli
    from mailwarden.input_loader import Authorization

    monkeypatch.setattr(cli, "step", lambda *a, **k: None)
    # Only auth.example is authorized; evil.example is not in the manifest.
    manifest = {"auth.example": Authorization(domain="auth.example", customer_id="C1",
                                              authorized=True, expires_on=date(2099, 1, 1),
                                              approved_ips=[])}
    assessments = {"auth.example": DomainAssessment(domain="auth.example"),
                   "evil.example": DomainAssessment(domain="evil.example")}

    probed = []

    def fake_probe(dom, **kw):
        probed.append(dom)
        return relay_probe.RelayProbeResult(domain=dom, relay_host="smtp-relay.gmail.com",
                                            outcome="relay_denied", ip_restriction="restricted")
    monkeypatch.setattr(cli, "_apply_probe", cli._apply_probe)  # keep real
    monkeypatch.setattr("mailwarden.relay_probe.probe_relay", fake_probe)

    args = Namespace(probe_host="smtp-relay.gmail.com", probe_timeout=5, probe_rcpt=None)
    cli._apply_probe(assessments, manifest, args)
    assert probed == ["auth.example"]              # the unauthorized domain was never probed
    assert assessments["evil.example"].coverage["RELAY_PROBE"].startswith("skipped")


# --- coverage chip rendering -----------------------------------------------

def _render(coverage):
    from mailwarden.reporting import write_html
    from mailwarden.risk_engine import RiskEngine
    import tempfile, os
    a = DomainAssessment(domain="x.com", customer_id="C1")
    a.coverage.update(coverage)
    a.finished_at = a.started_at
    fd, path = tempfile.mkstemp(suffix=".html")
    os.close(fd)
    from pathlib import Path
    write_html([a], {a.domain: RiskEngine().score(a)}, Path(path), scope="x.com")
    html = Path(path).read_text()
    os.unlink(path)
    return html


def test_open_probe_renders_warning_chip():
    html = _render({"SPF": "ran", "RELAY_PROBE": "ran: open"})
    assert "Relay probe: open relay (any IP)" in html
    assert 'class="warn"' in html


def test_restricted_probe_renders_ok_chip():
    html = _render({"RELAY_PROBE": "ran: relay_denied"})
    assert "Relay probe: restricted (IP denied)" in html


def test_skipped_probe_renders_neutral_chip():
    html = _render({"RELAY_PROBE": "skipped: not authorized"})
    assert "Relay probe: skipped" in html
    # raw internal state must not leak into the visible label
    assert "ran: open" not in html
