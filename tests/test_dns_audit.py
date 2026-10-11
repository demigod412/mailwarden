from mailwarden.config import DnsConfig
from mailwarden.demo import FakeResolver
from mailwarden.dns_audit import audit_domain
from mailwarden.models import Category, Severity

G = [(1, "aspmx.l.google.com.")]


def _titles(a, cat=None):
    return {f.title: f.severity for f in a.findings if cat is None or f.category == cat}


def test_missing_everything_is_flagged():
    a = audit_domain("x.com", DnsConfig(), FakeResolver(mx=G))
    t = _titles(a)
    assert t["No SPF record published"] == Severity.HIGH
    assert t["No DMARC record published"] == Severity.HIGH
    assert all(v == "ran" for v in a.coverage.values())


def test_plus_all_is_critical_and_hardfail_is_info():
    bad = audit_domain("x.com", DnsConfig(), FakeResolver({"x.com": ["v=spf1 +all"]}, G))
    assert Severity.CRITICAL in _titles(bad, Category.SPF).values()
    good = audit_domain("x.com", DnsConfig(), FakeResolver({"x.com": ["v=spf1 -all"]}, G))
    assert set(_titles(good, Category.SPF).values()) == {Severity.INFORMATIONAL}


def test_multiple_spf_records():
    a = audit_domain("x.com", DnsConfig(), FakeResolver({"x.com": ["v=spf1 -all", "v=spf1 ~all"]}, G))
    assert "Multiple SPF records (permanent error)" in _titles(a)


def test_spf_lookup_limit():
    inc = " ".join(f"include:s{i}.net" for i in range(11))
    a = audit_domain("x.com", DnsConfig(), FakeResolver({"x.com": [f"v=spf1 {inc} -all"]}, G))
    assert any("10-lookup" in t for t in _titles(a))


def test_dmarc_policies():
    for pol, sev in (("none", Severity.MEDIUM), ("quarantine", Severity.LOW), ("reject", Severity.INFORMATIONAL)):
        a = audit_domain("x.com", DnsConfig(), FakeResolver({"_dmarc.x.com": [f"v=DMARC1; p={pol}; rua=mailto:a@x.com"]}, G))
        assert sev in _titles(a, Category.DMARC).values()


def test_dkim_found_vs_missing_and_confidence():
    a = audit_domain("x.com", DnsConfig(), FakeResolver({"google._domainkey.x.com": ["v=DKIM1; p=ABC123"]}, G))
    assert _titles(a, Category.DKIM) == {"DKIM key published": Severity.INFORMATIONAL}
    b = audit_domain("x.com", DnsConfig(), FakeResolver(mx=G))
    f = next(f for f in b.findings if f.category == Category.DKIM)
    assert f.confidence.value == "low"  # other selectors may exist


def test_dns_error_becomes_not_assessed():
    from mailwarden.errors import DNSError

    class Boom(FakeResolver):
        def txt(self, name): raise DNSError("timeout")

    a = audit_domain("x.com", DnsConfig(), Boom(mx=G))
    assert a.coverage["SPF"].startswith("error")
    assert any(f.severity == Severity.NOT_ASSESSED and f.category == Category.SPF for f in a.findings)


def test_all_nameservers_failing_is_an_error_not_an_empty_answer(monkeypatch):
    import dns.resolver
    from mailwarden.dns_audit import DnsResolver
    from mailwarden.errors import DNSError
    import pytest

    r = DnsResolver(DnsConfig())
    monkeypatch.setattr(r._r, "resolve", lambda *a, **k: (_ for _ in ()).throw(dns.resolver.NoNameservers()))
    with pytest.raises(DNSError):
        r.txt("example.com")


def test_nonexistent_domain_stops_early_and_is_not_assessed():
    class Gone(FakeResolver):
        def domain_exists(self, name): return False

    a = audit_domain("typo.com", DnsConfig(), Gone())
    assert [f.severity for f in a.findings] == [Severity.NOT_ASSESSED]
    assert all("does not exist" in v for v in a.coverage.values())
