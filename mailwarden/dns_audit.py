"""Public DNS posture checks: SPF, DKIM, DMARC, MX, DNSSEC.

Everything here reads public records only. The resolver is injectable so the
checks can be unit-tested offline.
"""

from __future__ import annotations

import logging
from typing import Protocol

from .config import DnsConfig
from .errors import DNSError
from .models import (
    AbuseStatus, Category, Confidence, DomainAssessment, Finding, Severity,
)

log = logging.getLogger(__name__)
_GOOGLE_MX_SUFFIXES = ("google.com.", "googlemail.com.", "google.com", "googlemail.com")


class Resolver(Protocol):
    def txt(self, name: str) -> list[str]: ...
    def mx(self, name: str) -> list[tuple[int, str]]: ...
    def has_dnskey(self, name: str) -> bool: ...
    def domain_exists(self, name: str) -> bool: ...


class DnsResolver:
    """dnspython-backed resolver. NXDOMAIN / no-answer -> empty; timeouts raise."""

    def __init__(self, cfg: DnsConfig) -> None:
        import dns.resolver  # lazy: keeps imports cheap and tests offline
        self._dns = dns
        try:
            self._r = dns.resolver.Resolver()
        except dns.exception.DNSException as e:
            raise DNSError(f"no usable DNS resolver configuration: {e}") from e
        self._r.lifetime = self._r.timeout = cfg.timeout
        if cfg.nameservers:
            self._r.nameservers = list(cfg.nameservers)

    def _q(self, name: str, rtype: str):
        d = self._dns
        try:
            return list(self._r.resolve(name, rtype))
        except (d.resolver.NXDOMAIN, d.resolver.NoAnswer):
            return []
        except d.exception.Timeout as e:
            raise DNSError(f"timeout resolving {rtype} {name}") from e
        except d.exception.DNSException as e:
            raise DNSError(f"{type(e).__name__} resolving {rtype} {name}") from e

    def txt(self, name: str) -> list[str]:
        return ["".join(p.decode("utf-8", "replace") for p in r.strings)
                for r in self._q(name, "TXT")]

    def mx(self, name: str) -> list[tuple[int, str]]:
        return sorted((r.preference, str(r.exchange).lower()) for r in self._q(name, "MX"))

    def has_dnskey(self, name: str) -> bool:
        return bool(self._q(name, "DNSKEY"))

    def domain_exists(self, name: str) -> bool:
        """False only on NXDOMAIN (typo / unregistered). NoAnswer still means it exists."""
        d = self._dns
        try:
            self._r.resolve(name, "SOA")
        except d.resolver.NXDOMAIN:
            return False
        except d.resolver.NoAnswer:
            return True
        except d.exception.DNSException as e:
            raise DNSError(f"{type(e).__name__} resolving SOA {name}") from e
        return True


def _f(domain, cat, sev, title, evidence, method, impact, fix,
       conf=Confidence.HIGH, abuse=AbuseStatus.NOT_ASSESSED) -> Finding:
    return Finding(domain=domain, category=cat, component=cat.value, severity=sev,
                   confidence=conf, title=title, evidence=evidence,
                   detection_method=method, business_impact=impact,
                   remediation=fix, abuse_status=abuse)


# ---- SPF --------------------------------------------------------------------

def _count_lookups(r: Resolver, spf: str, seen: set[str], depth: int = 0) -> int:
    n = 0
    for tok in spf.split()[1:]:
        t = tok.lstrip("+-~?").lower()
        target = None
        if t.startswith("include:"):
            n += 1; target = t[8:]
        elif t.startswith("redirect="):
            n += 1; target = t[9:]
        elif t.startswith(("mx", "ptr", "exists:")) or t == "a" or t.startswith(("a:", "a/")):
            n += 1
        if target and target not in seen and depth < 10:
            seen.add(target)
            try:
                for rec in r.txt(target):
                    if rec.lower().startswith("v=spf1"):
                        n += _count_lookups(r, rec, seen, depth + 1)
            except DNSError:
                pass
    return n


def check_spf(domain: str, r: Resolver) -> list[Finding]:
    recs = [t for t in r.txt(domain) if t.lower().startswith("v=spf1")]
    m = "TXT lookup"
    if not recs:
        return [_f(domain, Category.SPF, Severity.HIGH, "No SPF record published",
                   {"name": domain}, m,
                   "Anyone can forge mail from this domain with no SPF signal for receivers.",
                   "Publish a v=spf1 record, e.g. 'v=spf1 include:_spf.google.com -all'.")]
    if len(recs) > 1:
        return [_f(domain, Category.SPF, Severity.HIGH, "Multiple SPF records (permanent error)",
                   {"count": len(recs)}, m,
                   "Receivers treat multiple SPF records as an error, so SPF is effectively off.",
                   "Merge into a single v=spf1 TXT record.")]
    spf = recs[0]
    out: list[Finding] = []
    toks = spf.lower().split()
    allq = next((t for t in toks if t.lstrip("+-~?") == "all"), None)
    ev = {"record": spf}
    if allq in ("+all", "all"):
        out.append(_f(domain, Category.SPF, Severity.CRITICAL, "SPF allows any sender (+all)", ev, m,
                      "Every server on the internet is authorized to send as this domain.",
                      "Replace '+all' with '-all' (or '~all' while rolling out).",
                      abuse=AbuseStatus.SUSPECTED))
    elif allq == "?all":
        out.append(_f(domain, Category.SPF, Severity.MEDIUM, "SPF is neutral (?all)", ev, m,
                      "SPF gives receivers no guidance, so forged mail is not penalised.",
                      "Move to '~all', then '-all' once DMARC reports are clean."))
    elif allq == "~all":
        out.append(_f(domain, Category.SPF, Severity.LOW, "SPF uses soft-fail (~all)", ev, m,
                      "Forged mail is flagged but usually still delivered.",
                      "Move to '-all' after confirming all legitimate senders are listed."))
    elif allq is None and not any(t.startswith("redirect=") for t in toks):
        out.append(_f(domain, Category.SPF, Severity.MEDIUM, "SPF record has no 'all' terminator",
                      ev, m, "Unlisted senders get a neutral result by default.",
                      "End the record with '-all'."))
    else:
        out.append(_f(domain, Category.SPF, Severity.INFORMATIONAL, "SPF enforces a hard fail",
                      ev, m, "Unlisted senders are rejected.", "Keep the record under review."))
    n = _count_lookups(r, spf, set())
    if n > 10:
        out.append(_f(domain, Category.SPF, Severity.MEDIUM,
                      f"SPF exceeds the 10-lookup limit ({n})", {"lookups": n}, "Recursive include walk",
                      "Receivers return a permanent error, so SPF stops protecting the domain.",
                      "Flatten includes or drop unused senders.", conf=Confidence.MEDIUM))
    return out


# ---- DMARC ------------------------------------------------------------------

def check_dmarc(domain: str, r: Resolver) -> list[Finding]:
    recs = [t for t in r.txt(f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")]
    m = "TXT lookup"
    if not recs:
        return [_f(domain, Category.DMARC, Severity.HIGH, "No DMARC record published",
                   {"name": f"_dmarc.{domain}"}, m,
                   "No policy tells receivers what to do with forged mail, and you get no reports.",
                   "Publish 'v=DMARC1; p=none; rua=mailto:dmarc@yourdomain' and tighten over time.")]
    tags = {k.strip().lower(): v.strip() for k, _, v in
            (p.partition("=") for p in recs[0].split(";") if "=" in p)}
    pol, ev, out = tags.get("p", "").lower(), {"record": recs[0]}, []
    if pol == "none":
        out.append(_f(domain, Category.DMARC, Severity.MEDIUM, "DMARC policy is monitor-only (p=none)",
                      ev, m, "Forged mail is reported but not blocked.",
                      "Move to p=quarantine, then p=reject once reports are clean."))
    elif pol == "quarantine":
        out.append(_f(domain, Category.DMARC, Severity.LOW, "DMARC quarantines but does not reject",
                      ev, m, "Forged mail goes to spam rather than being refused.",
                      "Move to p=reject when ready."))
    elif pol == "reject":
        out.append(_f(domain, Category.DMARC, Severity.INFORMATIONAL, "DMARC enforces p=reject",
                      ev, m, "Forged mail is refused by participating receivers.", "Keep monitoring reports."))
    else:
        out.append(_f(domain, Category.DMARC, Severity.HIGH, "DMARC record has no valid policy",
                      ev, m, "A malformed record is ignored by receivers.", "Add p=none|quarantine|reject."))
    if tags.get("pct", "100") not in ("100", ""):
        out.append(_f(domain, Category.DMARC, Severity.LOW, f"DMARC applies to only {tags['pct']}% of mail",
                      ev, m, "Part of the mail stream is unprotected.", "Raise pct to 100."))
    if "rua" not in tags:
        out.append(_f(domain, Category.DMARC, Severity.LOW, "DMARC has no aggregate report address (rua)",
                      ev, m, "You cannot see who sends mail as your domain.", "Add a rua=mailto: address."))
    return out


# ---- DKIM / MX / DNSSEC -----------------------------------------------------

def check_dkim(domain: str, r: Resolver, selectors: list[str]) -> list[Finding]:
    found, revoked = [], []
    for sel in selectors:
        for t in r.txt(f"{sel}._domainkey.{domain}"):
            if "p=" in t.replace(" ", ""):
                (found if t.replace(" ", "").split("p=", 1)[1].strip(";") else revoked).append(sel)
    if found:
        return [_f(domain, Category.DKIM, Severity.INFORMATIONAL, "DKIM key published",
                   {"selectors": found}, "Selector TXT lookup", "Outbound mail can be signed.",
                   "Rotate keys periodically; use 2048-bit keys.")]
    return [_f(domain, Category.DKIM, Severity.MEDIUM, "No DKIM key found for checked selectors",
               {"selectors_checked": selectors, "revoked": revoked}, "Selector TXT lookup",
               "Without DKIM, DMARC relies on SPF alone, which breaks on forwarding.",
               "Generate a DKIM key in Admin console > Gmail > Authenticate email and publish it. "
               "If you use another selector, add it to dns.dkim_selectors.",
               conf=Confidence.LOW)]


def check_mx(domain: str, r: Resolver) -> list[Finding]:
    mx = r.mx(domain)
    if not mx:
        return [_f(domain, Category.MX, Severity.MEDIUM, "No MX records", {"name": domain}, "MX lookup",
                   "Inbound mail cannot be delivered.", "Publish MX records for your mail provider.")]
    hosts = [h for _, h in mx]
    if any(h.endswith(_GOOGLE_MX_SUFFIXES) for h in hosts):
        return [_f(domain, Category.MX, Severity.INFORMATIONAL, "MX points to Google Workspace",
                   {"mx": hosts}, "MX lookup", "Mail is routed through Google.", "None.")]
    return [_f(domain, Category.MX, Severity.INFORMATIONAL, "MX does not point to Google",
               {"mx": hosts}, "MX lookup",
               "Mail is not routed through Google; Workspace-specific checks may not apply.",
               "Confirm this is intended.", conf=Confidence.MEDIUM)]


def check_dnssec(domain: str, r: Resolver) -> list[Finding]:
    if r.has_dnskey(domain):
        return [_f(domain, Category.DNSSEC, Severity.INFORMATIONAL, "DNSKEY present",
                   {}, "DNSKEY lookup", "DNS answers can be validated.",
                   "Confirm the DS record is set at the registrar.", conf=Confidence.MEDIUM)]
    return [_f(domain, Category.DNSSEC, Severity.LOW, "DNSSEC not enabled", {}, "DNSKEY lookup",
               "Spoofed DNS answers (including SPF/DMARC) cannot be detected.",
               "Enable DNSSEC at your DNS host and add the DS record at the registrar.",
               conf=Confidence.MEDIUM)]


def audit_domain(domain: str, cfg: DnsConfig, resolver: Resolver | None = None) -> DomainAssessment:
    r = resolver or DnsResolver(cfg)
    a = DomainAssessment(domain=domain)
    try:
        exists = r.domain_exists(domain)
    except DNSError as e:
        exists = True  # unknown: let each check report its own error
        log.warning("existence check failed: %s", e)
    if not exists:
        for name in ("SPF", "DKIM", "DMARC", "MX", "DNSSEC"):
            a.coverage[name] = "domain does not exist"
        a.add_finding(_f(domain, Category.COVERAGE, Severity.NOT_ASSESSED,
                         "Domain does not exist in DNS (NXDOMAIN)", {"name": domain}, "SOA lookup",
                         "No email checks are possible. This is usually a typo or an unregistered domain.",
                         "Check the spelling in your domains file."))
        return a
    checks = {
        "SPF": lambda: check_spf(domain, r),
        "DKIM": lambda: check_dkim(domain, r, cfg.dkim_selectors),
        "DMARC": lambda: check_dmarc(domain, r),
        "MX": lambda: check_mx(domain, r),
        "DNSSEC": lambda: check_dnssec(domain, r),
    }
    for name, fn in checks.items():
        try:
            for f in fn():
                a.add_finding(f)
            a.coverage[name] = "ran"
        except DNSError as e:
            log.warning("dns check failed", extra={"extra_fields": {"domain": domain, "check": name}})
            a.coverage[name] = f"error: {e}"
            a.add_finding(_f(domain, Category(name), Severity.NOT_ASSESSED,
                             f"{name} could not be checked (DNS error)", {"error": str(e)},
                             "framework", "Posture for this control is unknown.",
                             "Re-run the scan; check resolver connectivity."))
    return a
