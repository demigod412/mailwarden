"""Offline demo data, built by running the *real* checks against a fake resolver.

No network, no credentials. Used by `mailwarden demo` so you can see the UI immediately.
"""

from __future__ import annotations

import ipaddress
from datetime import date

from .activity_analysis import analyze_activity
from .config import DnsConfig
from .dns_audit import audit_domain
from .input_loader import Authorization
from .models import DomainAssessment
from .relay_audit import RelayEvidence, audit_relay, build_relay_paths


class FakeResolver:
    def __init__(self, txt=None, mx=None, dnssec=False):
        self._txt, self._mx, self._dnssec = txt or {}, mx or [], dnssec

    def txt(self, name): return list(self._txt.get(name, []))
    def mx(self, name): return list(self._mx)
    def has_dnskey(self, name): return self._dnssec
    def domain_exists(self, name): return True


_G = [(1, "aspmx.l.google.com."), (5, "alt1.aspmx.l.google.com.")]
_KEY = "v=DKIM1; k=rsa; p=" + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A" * 3


def _auth(dom, cid, ips):
    return Authorization(domain=dom, customer_id=cid, authorized=True, expires_on=date(2099, 1, 1),
                         approved_ips=[ipaddress.ip_network(i) for i in ips])


def build_demo_assessments() -> list[DomainAssessment]:
    out: list[DomainAssessment] = []
    cfg = DnsConfig()

    # 1. Permissive relay, weak DNS: suspected abuse exposure.
    d = "acme-logistics.example"
    a = audit_domain(d, cfg, FakeResolver(
        {d: ["v=spf1 include:_spf.google.com ~all"], f"_dmarc.{d}": ["v=DMARC1; p=none"]}, _G))
    a.customer_id = "C-1042"
    au = _auth(d, "C-1042", ["203.0.113.0/28"])
    ev = RelayEvidence(d, "relay/acme-logistics.example.relay.json", True, False, ["*"],
                       [], ip_restriction_enabled=False, relay_host="smtp-relay.gmail.com",
                       collected_at="2026-10-02T09:30:00Z",
                       collected_by="it-admin@acme-logistics.example")
    for f in audit_relay(ev, au): a.add_finding(f)
    a.relay_paths = build_relay_paths(ev, au, a.findings)
    a.coverage.update({"WORKSPACE_AUDIT": "ran", "RELAY": "ran", "RELAY_PROBE": "ran: open"})
    for f in analyze_activity([{"actor": {"email": "ops@acme-logistics.example"},
                                "events": [{"name": "suspicious_login"}]}], au): a.add_finding(f)
    out.append(a)

    # 2. Well run domain.
    d = "northwind-clinic.example"
    a = audit_domain(d, cfg, FakeResolver(
        {d: ["v=spf1 include:_spf.google.com -all"], f"_dmarc.{d}": ["v=DMARC1; p=reject; rua=mailto:d@northwind-clinic.example"],
         f"google._domainkey.{d}": [_KEY]}, _G, dnssec=False))
    a.customer_id = "C-2210"
    au = _auth(d, "C-2210", ["192.0.2.0/27"])
    ev = RelayEvidence(d, "relay/northwind-clinic.example.relay.json", True, True, ["northwind-clinic.example"],
                       ["192.0.2.0/27"], collected_at="2026-10-02T11:05:00Z", collected_by="sec@northwind-clinic.example")
    for f in audit_relay(ev, au): a.add_finding(f)
    a.relay_paths = build_relay_paths(ev, au, a.findings)
    a.coverage.update({"WORKSPACE_AUDIT": "ran", "RELAY": "ran", "RELAY_PROBE": "ran: relay_denied"})
    for f in analyze_activity([], au): a.add_finding(f)
    out.append(a)

    # 3. Google recorded abuse through the relay: confirmed.
    d = "brightpath-school.example"
    a = audit_domain(d, cfg, FakeResolver({d: ["v=spf1 +all"]}, _G))
    a.customer_id = "C-3307"
    au = _auth(d, "C-3307", ["203.0.113.64/28"])
    ev = RelayEvidence(d, "relay/brightpath-school.example.relay.json", False, False, ["*"],
                       ["203.0.113.64/28"], collected_at="2026-10-03T14:20:00Z", collected_by="admin@brightpath-school.example")
    for f in audit_relay(ev, au): a.add_finding(f)
    for f in analyze_activity([{"actor": {"email": "scanner@brightpath-school.example"},
                                "events": [{"name": "account_disabled_spamming_through_relay"}]}], au):
        a.add_finding(f)
    a.relay_paths = build_relay_paths(ev, au, a.findings)
    a.coverage.update({"WORKSPACE_AUDIT": "ran", "RELAY": "ran"})
    out.append(a)

    # 4. DNS only, no authorization: relay honestly not assessed.
    d = "tailor-and-co.example"
    a = audit_domain(d, cfg, FakeResolver(
        {d: ["v=spf1 include:_spf.google.com -all"], f"_dmarc.{d}": ["v=DMARC1; p=quarantine; pct=50; rua=mailto:r@tailor-and-co.example"]}, _G))
    a.relay_paths = build_relay_paths(None, None, a.findings, ["RELAY: not in scan mode"], domain=d)
    a.coverage["RELAY_PROBE"] = "skipped: not authorized"
    out.append(a)
    for x in out:
        x.finished_at = x.started_at
    return out
