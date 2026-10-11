"""Which domains could currently be used to send bulk/forged email "from" them.

This answers a different question than the relay audit. The relay audit asks
"could someone send mail THROUGH your infrastructure". This module asks "could
someone send mail that merely CLAIMS to be from your domain, with no access to
your infrastructure at all" -- the far more common way a domain gets used for
phishing or bulk spam runs, and the one that only needs SPF/DMARC to be weak.

It classifies findings DNS checks already produced; it makes no new DNS
queries, so it works instantly against already-saved scan results via
`mailwarden report`, with no rescan needed.

The judgment follows the mainstream email-security consensus: a DMARC policy
of quarantine/reject is what actually blocks delivery of forged mail at
participating receivers, regardless of SPF. SPF only matters on its own at the
(now a minority of) receivers that honour it directly rather than through
DMARC. A domain with neither control enforcing is the easiest to spoof.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import Category, DomainAssessment

_DMARC_TITLE_TO_LEVEL = {
    "No DMARC record published": "missing",
    "DMARC record has no valid policy": "broken",
    "DMARC policy is monitor-only (p=none)": "none",
    "DMARC quarantines but does not reject": "quarantine",
    "DMARC enforces p=reject": "reject",
}
_SPF_TITLE_TO_LEVEL = {
    "No SPF record published": "missing",
    "Multiple SPF records (permanent error)": "broken",
    "SPF allows any sender (+all)": "allow_all",
    "SPF is neutral (?all)": "neutral",
    "SPF record has no 'all' terminator": "no_terminator",
    "SPF uses soft-fail (~all)": "soft_fail",
    "SPF enforces a hard fail": "hard_fail",
}
_DMARC_ENFORCING = {"quarantine", "reject"}
_SPF_WEAK = {"missing", "broken", "allow_all", "neutral", "no_terminator"}

LEVEL_LABEL = {"high": "High", "medium": "Medium", "low": "Low", "unknown": "Unknown"}
LEVEL_RANK = {"high": 0, "medium": 1, "unknown": 2, "low": 3}


def _level(findings, table: dict[str, str], category: Category) -> str:
    titles = {f.title for f in findings if f.category == category}
    for title, level in table.items():
        if title in titles:
            return level
    return "unknown"  # the check didn't run (e.g. a DNS error), not that it's fine


@dataclass(slots=True)
class SpoofingRisk:
    domain: str
    customer_id: str | None
    dmarc_level: str
    spf_level: str
    risk: str  # high | medium | low | unknown
    why: str


def assess(a: DomainAssessment) -> SpoofingRisk:
    dmarc = _level(a.findings, _DMARC_TITLE_TO_LEVEL, Category.DMARC)
    spf = _level(a.findings, _SPF_TITLE_TO_LEVEL, Category.SPF)

    if dmarc in _DMARC_ENFORCING:
        risk, why = "low", (
            f"DMARC is enforcing ({dmarc}); participating receivers block or quarantine "
            "forged mail regardless of SPF.")
    elif dmarc == "unknown" or spf == "unknown":
        risk, why = "unknown", "SPF or DMARC could not be checked (see coverage gaps)."
    elif spf in _SPF_WEAK:
        risk, why = "high", (
            f"DMARC is not enforcing ({dmarc}) and SPF is weak ({spf}): a forged "
            f"\"From: anyone@{a.domain}\" email has nothing stopping its delivery.")
    elif spf == "soft_fail":
        risk, why = "medium", (
            f"DMARC is not enforcing ({dmarc}); SPF soft-fail (~all) flags forged mail "
            "but most receivers still deliver it.")
    else:  # spf == "hard_fail"
        risk, why = "medium", (
            f"DMARC is not enforcing ({dmarc}), but SPF hard-fail (-all) blocks forged "
            "mail at receivers that check SPF directly rather than through DMARC.")
    return SpoofingRisk(domain=a.domain, customer_id=a.customer_id,
                        dmarc_level=dmarc, spf_level=spf, risk=risk, why=why)


def assess_all(assessments: list[DomainAssessment]) -> list[SpoofingRisk]:
    rows = [assess(a) for a in assessments]
    rows.sort(key=lambda r: (LEVEL_RANK[r.risk], r.domain))
    return rows
