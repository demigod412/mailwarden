import csv

from mailwarden.models import Category, Confidence, DomainAssessment, Finding, Severity
from mailwarden.spoofing_risk import assess, assess_all


def _f(category: Category, title: str) -> Finding:
    return Finding(domain="x.com", category=category, component=category.value,
                   severity=Severity.INFORMATIONAL, confidence=Confidence.HIGH, title=title,
                   evidence={}, detection_method="t", business_impact="", remediation="")


def _assessment(*titles_by_category) -> DomainAssessment:
    a = DomainAssessment(domain="x.com", customer_id="C1")
    for cat, title in titles_by_category:
        a.add_finding(_f(cat, title))
    return a


def test_no_spf_no_dmarc_is_high_risk():
    a = _assessment((Category.SPF, "No SPF record published"),
                    (Category.DMARC, "No DMARC record published"))
    r = assess(a)
    assert r.risk == "high"
    assert "x.com" in r.why


def test_spf_plus_all_no_dmarc_is_high_risk():
    a = _assessment((Category.SPF, "SPF allows any sender (+all)"),
                    (Category.DMARC, "DMARC policy is monitor-only (p=none)"))
    assert assess(a).risk == "high"


def test_dmarc_reject_is_low_risk_even_with_weak_spf():
    a = _assessment((Category.SPF, "No SPF record published"),
                    (Category.DMARC, "DMARC enforces p=reject"))
    r = assess(a)
    assert r.risk == "low"


def test_dmarc_quarantine_is_low_risk():
    a = _assessment((Category.SPF, "SPF allows any sender (+all)"),
                    (Category.DMARC, "DMARC quarantines but does not reject"))
    assert assess(a).risk == "low"


def test_dmarc_none_but_spf_hard_fail_is_medium():
    a = _assessment((Category.SPF, "SPF enforces a hard fail"),
                    (Category.DMARC, "DMARC policy is monitor-only (p=none)"))
    r = assess(a)
    assert r.risk == "medium"
    assert r.spf_level == "hard_fail" and r.dmarc_level == "none"


def test_dmarc_none_but_spf_soft_fail_is_medium():
    a = _assessment((Category.SPF, "SPF uses soft-fail (~all)"),
                    (Category.DMARC, "DMARC policy is monitor-only (p=none)"))
    assert assess(a).risk == "medium"


def test_missing_checks_are_unknown_not_silently_low():
    a = DomainAssessment(domain="x.com")  # no SPF/DMARC findings at all (e.g. DNS error)
    r = assess(a)
    assert r.risk == "unknown"


def test_assess_all_sorts_worst_first():
    low = _assessment((Category.SPF, "No SPF record published"),
                      (Category.DMARC, "DMARC enforces p=reject"))
    low.domain = "safe.com"
    high = _assessment((Category.SPF, "No SPF record published"),
                       (Category.DMARC, "No DMARC record published"))
    high.domain = "risky.com"
    rows = assess_all([low, high])
    assert [r.domain for r in rows] == ["risky.com", "safe.com"]
    assert rows[0].risk == "high" and rows[1].risk == "low"


def test_write_spoofing_risk_csv(tmp_path):
    from mailwarden.reporting import write_spoofing_risk
    a = _assessment((Category.SPF, "No SPF record published"),
                    (Category.DMARC, "No DMARC record published"))
    out = tmp_path / "spoofing_risk.csv"
    write_spoofing_risk([a], out)
    rows = list(csv.DictReader(out.open()))
    assert rows[0]["domain"] == "x.com"
    assert rows[0]["risk"] == "high"
    assert rows[0]["customer_id"] == "C1"


def test_write_all_includes_spoofing_risk_csv(tmp_path):
    from mailwarden.reporting import write_all
    a = _assessment((Category.SPF, "No SPF record published"),
                    (Category.DMARC, "No DMARC record published"))
    a.finished_at = a.started_at
    paths = write_all([a], tmp_path, scope="x.com", mode="dns", notes=[],
                      started=a.started_at, finished=a.started_at)
    assert paths["spoofing_risk_csv"].exists()
    assert "x.com" in paths["spoofing_risk_csv"].read_text()


def test_html_report_includes_spoofing_panel(tmp_path):
    from mailwarden.reporting import write_html
    from mailwarden.risk_engine import RiskEngine
    a = _assessment((Category.SPF, "SPF allows any sender (+all)"),
                    (Category.DMARC, "No DMARC record published"))
    a.finished_at = a.started_at
    out = tmp_path / "summary.html"
    write_html([a], {a.domain: RiskEngine().score(a)}, out, scope="x.com")
    html = out.read_text()
    assert "bulk or phishing email" in html
    assert "High risk" in html
    assert 'href="#d-0"' in html  # links to the matching domain section, not a stray index
