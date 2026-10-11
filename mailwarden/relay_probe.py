"""Active, authorization-gated probe of the Google Workspace SMTP relay.

Why this exists
---------------
The Admin-console setting "Only accept mail from the specified IP addresses" is
not readable from outside a tenant -- not in DNS, WHOIS, or any public API. So a
scan with no administrator evidence can only *screen* (it sees the domain uses
Google Workspace) and must otherwise report the source-IP restriction as Unknown.

This module resolves that Unknown for domains you are AUTHORIZED to test, by
observing the relay's behaviour instead of reading its config: it connects to
smtp-relay.gmail.com and asks, without authenticating, whether the relay will
accept mail "from" the domain for an external recipient.

  * Accepted unauthenticated  -> the relay takes mail from this IP with no auth,
                                 i.e. no effective source-IP restriction (OPEN).
  * Auth required / relay denied -> the relay does NOT accept this IP unauthenticated
                                 (restricted / auth-gated).

Safety properties (enforced here and in the CLI)
------------------------------------------------
  * Authorization-gated: the CLI refuses to probe any domain without an active
    authorization entry. This is an active test and must only ever run against
    your own / your company's domains.
  * No mail is ever delivered: the probe stops at RCPT TO and never issues DATA,
    so no message body is transmitted to anyone. The default recipient is on
    `example.com` (IANA-reserved, non-deliverable) purely to exercise the relay
    decision.
  * Read-only intent: it opens a TLS connection, reads response codes, and quits.
  * Best-effort and fail-safe: any network/TLS/protocol problem yields an
    "inconclusive" result (Unknown is preserved), never a false verdict.

To be a *correct* "any IP" verdict, the probe must run from an IP that is NOT in
the domain's own sending ranges; from inside an allowed range, "accepted" cannot
distinguish "any IP" from "my IP is allowed". The probe records the public source
IP the relay reports and flags when it appears to sit inside the authorized ranges.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import smtplib
import socket
import ssl
from dataclasses import dataclass, field

from .models import AbuseStatus, Category, Confidence, Finding, Severity

log = logging.getLogger(__name__)

PROBE_FINDING_COMPONENT = "SMTP relay probe"

DEFAULT_RELAY_HOST = "smtp-relay.gmail.com"
# IANA-reserved domain; used only as an envelope recipient to exercise the relay
# decision. The probe never sends DATA, so nothing is ever delivered to it.
DEFAULT_RCPT = "relay-probe@example.com"

# (port, security) attempts, in order. 587 STARTTLS is the standard submission
# path; 465 is implicit TLS; 25 is a last resort (often blocked by ISPs).
_ATTEMPTS = (("starttls", 587), ("ssl", 465), ("plain", 25))

_IP_IN_GREETING = re.compile(r"\[([0-9A-Fa-f:.]+)\]")


@dataclass(slots=True)
class RelayProbeResult:
    domain: str
    relay_host: str
    outcome: str          # open | auth_required | relay_denied | inconclusive
    ip_restriction: str   # none | restricted | unknown
    source_ip: str | None = None
    source_in_authorized_range: bool | None = None
    port: int | None = None
    security: str | None = None
    last_code: int | None = None
    last_response: str = ""
    notes: list[str] = field(default_factory=list)

    @property
    def conclusive(self) -> bool:
        return self.outcome in ("open", "auth_required", "relay_denied")

    @property
    def reliable_open(self) -> bool:
        """An 'open' result only proves 'any IP' when the probe ran from outside
        the domain's authorized ranges."""
        return self.outcome == "open" and self.source_in_authorized_range is not True

    @property
    def effective_ip_restriction(self) -> str:
        if self.outcome == "open":
            return "none" if self.reliable_open else "unknown"
        if self.outcome in ("auth_required", "relay_denied"):
            return "restricted"
        return "unknown"


def _decode(resp: bytes | str | None) -> str:
    if resp is None:
        return ""
    if isinstance(resp, bytes):
        return resp.decode("utf-8", "replace")
    return str(resp)


def _source_ip_from_ehlo(ehlo_msg: bytes | str | None) -> str | None:
    text = _decode(ehlo_msg)
    first = text.splitlines()[0] if text else ""
    m = _IP_IN_GREETING.search(first)
    if m:
        return m.group(1)
    # Fall back to any bracketed address anywhere in the greeting.
    m = _IP_IN_GREETING.search(text)
    return m.group(1) if m else None


def _in_ranges(ip: str, approved) -> bool | None:
    if not ip or not approved:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for net in approved:
        try:
            if addr in net:
                return True
        except TypeError:
            continue
    return False


def _one_attempt(host: str, port: int, security: str, mail_from: str,
                 rcpt_to: str, timeout: float) -> RelayProbeResult:
    """Run a single connection attempt. Never sends DATA."""
    r = RelayProbeResult(domain="", relay_host=host, outcome="inconclusive",
                         ip_restriction="unknown", port=port, security=security)
    smtp: smtplib.SMTP | None = None
    try:
        ctx = ssl.create_default_context()
        if security == "ssl":
            smtp = smtplib.SMTP_SSL(host, port, timeout=timeout, context=ctx)
        else:
            smtp = smtplib.SMTP(host, port, timeout=timeout)
        code, msg = smtp.ehlo()
        r.source_ip = _source_ip_from_ehlo(msg)
        if security == "starttls":
            if not smtp.has_extn("starttls"):
                r.notes.append("server did not offer STARTTLS on this port")
                return r
            smtp.starttls(context=ctx)
            code, msg = smtp.ehlo()
            if not r.source_ip:
                r.source_ip = _source_ip_from_ehlo(msg)

        # Attempt the relay WITHOUT authenticating. Stop at RCPT TO.
        mcode, mmsg = smtp.docmd("MAIL", f"FROM:<{mail_from}>")
        r.last_code, r.last_response = mcode, _decode(mmsg)
        if mcode in (530, 538):            # auth / TLS-auth required
            r.outcome, r.ip_restriction = "auth_required", "restricted"
            return r
        if mcode >= 500:                   # sender refused outright
            r.outcome, r.ip_restriction = "relay_denied", "restricted"
            return r

        rcode, rmsg = smtp.docmd("RCPT", f"TO:<{rcpt_to}>")
        r.last_code, r.last_response = rcode, _decode(rmsg)
        if rcode in (250, 251):
            # Relay accepted an external recipient from an unauthenticated
            # connection -> it takes mail from this IP with no restriction.
            r.outcome, r.ip_restriction = "open", "none"
        elif rcode in (530, 538):
            r.outcome, r.ip_restriction = "auth_required", "restricted"
        elif rcode >= 500:
            # e.g. 550 5.7.1 relay denied / not permitted for this IP.
            r.outcome, r.ip_restriction = "relay_denied", "restricted"
        else:
            r.notes.append(f"unexpected RCPT response {rcode}")
        return r
    finally:
        if smtp is not None:
            try:
                smtp.quit()
            except (smtplib.SMTPException, OSError):
                try:
                    smtp.close()
                except OSError:
                    pass


def probe_relay(domain: str, *, host: str = DEFAULT_RELAY_HOST,
                mail_from: str | None = None, rcpt_to: str = DEFAULT_RCPT,
                timeout: float = 10.0, approved_ips=None) -> RelayProbeResult:
    """Probe one domain's relay. Returns a result; never raises on network error.

    `approved_ips` (the domain's authorized sending ranges, if known) is used only
    to warn when the probe source IP appears to be inside them, which would make an
    'open' verdict unreliable.
    """
    sender = mail_from or f"mailwarden-probe@{domain}"
    result = RelayProbeResult(domain=domain, relay_host=host, outcome="inconclusive",
                              ip_restriction="unknown")
    errors: list[str] = []
    for security, port in _ATTEMPTS:
        try:
            attempt = _one_attempt(host, port, security, sender, rcpt_to, timeout)
        except (smtplib.SMTPException, ssl.SSLError, socket.error, OSError) as e:
            errors.append(f"{security}/{port}: {type(e).__name__}: {e}")
            continue
        attempt.domain = domain
        if attempt.source_ip:
            attempt.source_in_authorized_range = _in_ranges(attempt.source_ip, approved_ips)
            if attempt.source_in_authorized_range:
                attempt.notes.append(
                    "source IP is inside the domain's authorized ranges: an "
                    "'open' result here does NOT prove the relay accepts arbitrary "
                    "IPs. Re-run from an IP outside your sending ranges.")
        if attempt.conclusive:
            return attempt
        # Inconclusive but connected: keep it unless a later attempt is conclusive.
        result = attempt
    if not result.conclusive and errors:
        result.notes.extend(errors)
        result.notes.append("could not complete an SMTP conversation on any port")
    return result


def _evidence(r: RelayProbeResult) -> dict:
    return {
        "relay_host": r.relay_host, "outcome": r.outcome,
        "source_ip": r.source_ip,
        "source_in_authorized_range": r.source_in_authorized_range,
        "port": r.port, "security": r.security,
        "smtp_code": r.last_code, "smtp_response": r.last_response,
        "notes": list(r.notes),
    }


def probe_finding(r: RelayProbeResult) -> Finding:
    """Translate a probe result into a Finding attached to the assessment.

    Carries no credentials (the probe never authenticates), so it is safe under
    the reporting credential guard.
    """
    host, ip = r.relay_host, r.source_ip or "the probe source IP"
    base = dict(domain=r.domain, category=Category.RELAY,
                component=PROBE_FINDING_COMPONENT, evidence=_evidence(r),
                detection_method="Active SMTP relay probe (unauthenticated, no DATA sent)")

    if r.reliable_open:
        return Finding(
            severity=Severity.HIGH, confidence=Confidence.HIGH,
            title="Relay probe: accepts unauthenticated mail from this IP (open relay)",
            business_impact=(
                f"An unauthenticated connection from {ip} was allowed to relay mail "
                f"as {r.domain} to an external recipient through {host}: the relay "
                "accepts mail from any IP (no effective source-IP restriction)."),
            remediation=(
                "Enable 'Only accept mail from the specified IP addresses' and list "
                "your sending ranges, and/or require SMTP authentication."),
            abuse_status=AbuseStatus.SUSPECTED, **base)

    if r.outcome == "open":  # accepted, but from inside the allowed ranges
        return Finding(
            severity=Severity.NOT_ASSESSED, confidence=Confidence.MEDIUM,
            title="Relay probe: accepted, but source IP was inside authorized ranges",
            business_impact=(
                "The relay accepted the probe, but it ran from an IP inside the "
                "domain's authorized ranges, so this does not prove the relay accepts "
                "arbitrary IPs."),
            remediation="Re-run the probe from an IP outside your sending ranges.",
            abuse_status=AbuseStatus.NOT_ASSESSED, **base)

    if r.outcome in ("auth_required", "relay_denied"):
        why = ("authentication is required" if r.outcome == "auth_required"
               else "the source IP is not permitted to relay")
        return Finding(
            severity=Severity.INFORMATIONAL, confidence=Confidence.HIGH,
            title="Relay probe: unauthenticated relay rejected (restricted)",
            business_impact=(
                f"An unauthenticated connection from {ip} could not relay mail as "
                f"{r.domain}: {why}. The relay is not open to arbitrary IPs."),
            remediation="No change needed for the source-IP restriction. Keep it enforced.",
            abuse_status=AbuseStatus.NOT_ESTABLISHED, **base)

    return Finding(
        severity=Severity.NOT_ASSESSED, confidence=Confidence.LOW,
        title="Relay probe: inconclusive",
        business_impact="The probe could not complete an SMTP conversation, so the "
                        "source-IP restriction remains unknown.",
        remediation="Check outbound SMTP (ports 587/465/25) is not blocked and re-run, "
                    "or export the relay settings from the Admin console.",
        abuse_status=AbuseStatus.NOT_ASSESSED, **base)
