import csv
import json

from mailwarden.cli import main


def test_demo_then_report_round_trip(tmp_path, capsys):
    out = tmp_path / "demo"
    assert main(["demo", "--output", str(out)]) == 0
    html = (out / "summary.html").read_text()
    assert "Mailwarden" in html and "Fix first" in html
    assert (out / "abuse_review.csv").exists()
    assert "acme-logistics.example" in capsys.readouterr().out


def test_scan_requires_authorization_for_workspace(tmp_path, capsys):
    d = tmp_path / "d.txt"
    d.write_text("example.com\n")
    assert main(["scan", "--domains", str(d), "--mode", "workspace", "--output", str(tmp_path / "o")]) == 2
    assert "active authorization" in capsys.readouterr().err


def test_report_rebuilds_from_raw(tmp_path):
    from mailwarden.demo import build_demo_assessments
    from mailwarden.storage import ResultStore
    raw = tmp_path / "raw"
    for a in build_demo_assessments():
        ResultStore(raw).save_assessment(a)
    assert main(["report", "--input", str(tmp_path), "--format", "csv"]) == 0
    assert (tmp_path / "findings.csv").exists() and not (tmp_path / "summary.html").exists()


def test_credential_guard_blocks_build(tmp_path):
    from mailwarden.demo import build_demo_assessments
    from mailwarden.storage import ResultStore
    a = build_demo_assessments()[0]
    a.findings[0].evidence["api_key"] = "hunter2"
    ResultStore(tmp_path / "raw").save_assessment(a)
    assert main(["report", "--input", str(tmp_path)]) == 3
    assert not (tmp_path / "summary.html").exists()


def test_csv_formula_injection_neutralised(tmp_path):
    from mailwarden.demo import build_demo_assessments
    from mailwarden.reporting import write_csv
    a = build_demo_assessments()[0]
    a.findings[0].title = "=HYPERLINK(\"http://evil\")"
    write_csv([a], tmp_path / "f.csv")
    rows = list(csv.DictReader((tmp_path / "f.csv").open()))
    assert rows[0]["title"].startswith("'=")


def test_authorize_generates_file_from_domain_list(tmp_path):
    from mailwarden.input_loader import load_authorization_manifest
    d = tmp_path / "domains.txt"
    d.write_text("acme.com\nfoo.org\nacme.com\n")  # duplicate on purpose
    assert main(["authorize", "--from", str(d), "--approved-ips", "203.0.113.0/28"]) == 0
    out = tmp_path / "authorization.json"
    assert out.exists()
    manifest = load_authorization_manifest(out)
    assert set(manifest) == {"acme.com", "foo.org"}  # deduped
    assert all(a.is_active() for a in manifest.values())
    assert str(manifest["acme.com"].approved_ips[0]) == "203.0.113.0/28"


def test_authorize_merges_without_clobbering_existing(tmp_path):
    import json
    from mailwarden.input_loader import load_authorization_manifest
    d = tmp_path / "domains.txt"
    d.write_text("acme.com\n")
    main(["authorize", "--from", str(d), "--customer-id", "C-KEEP",
          "--approved-ips", "203.0.113.0/28"])
    # Add a new domain and re-run; the existing entry must be preserved verbatim.
    d.write_text("acme.com\nnewco.io\n")
    assert main(["authorize", "--from", str(d)]) == 0
    manifest = load_authorization_manifest(tmp_path / "authorization.json")
    assert set(manifest) == {"acme.com", "newco.io"}
    assert manifest["acme.com"].customer_id == "C-KEEP"               # kept
    assert str(manifest["acme.com"].approved_ips[0]) == "203.0.113.0/28"  # kept
    assert manifest["newco.io"].approved_ips == []                    # new, no ips


def test_authorize_never_expiry(tmp_path):
    import json
    d = tmp_path / "domains.txt"
    d.write_text("acme.com\n")
    main(["authorize", "--from", str(d), "--expires-on", "never"])
    entry = json.loads((tmp_path / "authorization.json").read_text())["authorizations"][0]
    assert "expires_on" not in entry  # omitted -> never expires


def test_authorize_rejects_bad_expiry(tmp_path):
    d = tmp_path / "domains.txt"
    d.write_text("acme.com\n")
    assert main(["authorize", "--from", str(d), "--expires-on", "soon"]) == 2


def test_authorize_force_rewrites(tmp_path):
    from mailwarden.input_loader import load_authorization_manifest
    d = tmp_path / "domains.txt"
    d.write_text("acme.com\nold.com\n")
    main(["authorize", "--from", str(d)])
    d.write_text("acme.com\n")  # old.com dropped from the list
    main(["authorize", "--from", str(d), "--force"])  # rewrite, don't merge
    manifest = load_authorization_manifest(tmp_path / "authorization.json")
    assert set(manifest) == {"acme.com"}  # old.com gone because --force rebuilt from the list


def test_authorized_file_drives_probe_scope(tmp_path, monkeypatch):
    """End to end: authorize a list, then the probe only runs for those domains."""
    from argparse import Namespace
    from mailwarden import cli, relay_probe
    from mailwarden.input_loader import load_authorization_manifest
    from mailwarden.models import DomainAssessment
    d = tmp_path / "domains.txt"
    d.write_text("mine-a.example\nmine-b.example\n")
    main(["authorize", "--from", str(d)])
    manifest = load_authorization_manifest(tmp_path / "authorization.json")

    probed = []
    monkeypatch.setattr(cli, "step", lambda *a, **k: None)
    monkeypatch.setattr("mailwarden.relay_probe.probe_relay",
                        lambda dom, **kw: (probed.append(dom) or relay_probe.RelayProbeResult(
                            domain=dom, relay_host="smtp-relay.gmail.com",
                            outcome="relay_denied", ip_restriction="restricted")))
    assessments = {dom: DomainAssessment(domain=dom) for dom in manifest}
    cli._apply_probe(assessments, manifest, Namespace(
        probe_host="smtp-relay.gmail.com", probe_timeout=5, probe_rcpt=None))
    assert sorted(probed) == ["mine-a.example", "mine-b.example"]


def _open_relay_assessment(domain="risky.example", confirmed=False):
    from datetime import date
    import ipaddress
    from mailwarden.input_loader import Authorization
    from mailwarden.models import (
        AbuseStatus, Category, Confidence, DomainAssessment, Finding, Severity,
    )
    from mailwarden.relay_audit import RelayEvidence, audit_relay, build_relay_paths

    auth = Authorization(domain=domain, customer_id="C1", authorized=True,
                         expires_on=date(2099, 1, 1),
                         approved_ips=[ipaddress.ip_network("203.0.113.0/24")])
    ev = RelayEvidence(domain=domain, source="x.relay.json", require_tls=True,
                       require_auth=False, allowed_senders=[domain], authorized_ips=[],
                       ip_restriction_enabled=False)
    a = DomainAssessment(domain=domain, customer_id="C1")
    for f in audit_relay(ev, auth):
        a.add_finding(f)
    if confirmed:
        a.add_finding(Finding(
            domain=domain, category=Category.ACTIVITY, component="Account audit",
            severity=Severity.CRITICAL, confidence=Confidence.HIGH,
            title="Google disabled account for abuse: account_disabled_spamming_through_relay",
            evidence={}, detection_method="Reports API", business_impact="x",
            remediation="y", abuse_status=AbuseStatus.CONFIRMED))
    a.relay_paths = build_relay_paths(ev, auth, a.findings)
    a.finished_at = a.started_at
    return a


def test_relay_exploit_gate_fires_on_open_relay(tmp_path, capsys):
    from mailwarden.cli import _finish
    a = _open_relay_assessment()
    rc = _finish([a], tmp_path / "o", "x", "full", a.started_at, True,
                 fail_on_relay_exploit="high")
    assert rc == 4
    assert "relay-exploit gate failed" in capsys.readouterr().err


def test_relay_exploit_gate_confirmed_only_ignores_suspected(tmp_path):
    from mailwarden.cli import _finish
    a = _open_relay_assessment(confirmed=False)  # suspected, not confirmed
    rc = _finish([a], tmp_path / "o", "x", "full", a.started_at, True,
                 fail_on_relay_exploit="confirmed")
    assert rc == 0


def test_relay_exploit_gate_fires_on_confirmed(tmp_path):
    from mailwarden.cli import _finish
    a = _open_relay_assessment(confirmed=True)
    rc = _finish([a], tmp_path / "o", "x", "full", a.started_at, True,
                 fail_on_relay_exploit="confirmed")
    assert rc == 4


def test_relay_exploit_gate_default_off_does_not_fail(tmp_path):
    from mailwarden.cli import _finish
    a = _open_relay_assessment()
    rc = _finish([a], tmp_path / "o", "x", "full", a.started_at, True)
    assert rc == 0  # gate defaults to "none"


def test_screening_only_does_not_trip_gate(tmp_path):
    """A Google Workspace domain with no relay evidence is 'needs evidence'
    (medium/screening) -- it must NOT fail the gate, only real open relays do."""
    from mailwarden.cli import _finish
    from mailwarden.models import Category, Confidence, DomainAssessment, Finding, Severity
    from mailwarden.relay_audit import build_relay_paths
    a = DomainAssessment(domain="google-user.example")
    a.add_finding(Finding(domain="google-user.example", category=Category.MX, component="MX",
                          severity=Severity.INFORMATIONAL, confidence=Confidence.HIGH,
                          title="MX points to Google Workspace", evidence={},
                          detection_method="MX lookup", business_impact="", remediation=""))
    a.relay_paths = build_relay_paths(None, None, a.findings, ["RELAY: not in scan mode"],
                                      domain="google-user.example")
    a.finished_at = a.started_at
    rc = _finish([a], tmp_path / "o", "x", "dns", a.started_at, True,
                 fail_on_relay_exploit="high")
    assert rc == 0


def test_dns_overrides_from_cli_flags():
    import argparse
    from mailwarden.cli import _apply_dns_overrides
    from mailwarden.config import AppConfig

    cfg = AppConfig()
    args = argparse.Namespace(dns_timeout=9.0, dns_nameservers="1.1.1.1, 8.8.8.8")
    _apply_dns_overrides(cfg, args)
    assert cfg.dns.timeout == 9.0
    assert cfg.dns.nameservers == ["1.1.1.1", "8.8.8.8"]


def test_dns_overrides_leave_config_alone_when_absent():
    import argparse
    from mailwarden.cli import _apply_dns_overrides
    from mailwarden.config import AppConfig

    cfg = AppConfig()
    _apply_dns_overrides(cfg, argparse.Namespace(dns_timeout=None, dns_nameservers=None))
    assert cfg.dns.timeout == 4.0
    assert cfg.dns.nameservers == []


def test_scan_accepts_dns_tuning_flags(tmp_path):
    d = tmp_path / "d.txt"
    d.write_text("example.com\n")
    # Point at a nameserver on an address reserved for documentation (TEST-NET-1)
    # so this exercises the flag wiring without depending on network access.
    rc = main(["scan", "--domains", str(d), "--dns-timeout", "0.2",
              "--dns-nameservers", "192.0.2.1", "--output", str(tmp_path / "o")])
    assert rc == 0  # DNS errors become NOT_ASSESSED findings, not a crash
    import json
    data = json.loads((tmp_path / "o" / "findings.json").read_text())
    assert data["domains"][0]["coverage"]["SPF"].startswith("error")


def test_scan_dns_preserves_input_order_regardless_of_completion_order(monkeypatch):
    import time
    import random
    from mailwarden import cli
    from mailwarden.config import DnsConfig
    from mailwarden.models import DomainAssessment

    domains = [f"d{i}.example" for i in range(12)]
    delays = {d: random.uniform(0, 0.02) for d in domains}  # finish in scrambled order

    def fake_audit(dom, dns_cfg):
        time.sleep(delays[dom])
        return DomainAssessment(domain=dom)

    monkeypatch.setattr(cli, "audit_domain", fake_audit)
    result = cli._scan_dns(domains, DnsConfig(), workers=6, show_progress=False)
    assert list(result.keys()) == domains  # input order preserved, not completion order
    assert all(isinstance(v, DomainAssessment) for v in result.values())


def test_scan_dns_isolates_a_crash_to_one_domain(monkeypatch):
    from mailwarden import cli
    from mailwarden.config import DnsConfig
    from mailwarden.models import DomainAssessment, Severity

    def fake_audit(dom, dns_cfg):
        if dom == "broken.example":
            raise RuntimeError("boom")
        return DomainAssessment(domain=dom)

    monkeypatch.setattr(cli, "audit_domain", fake_audit)
    result = cli._scan_dns(["a.example", "broken.example", "b.example"], DnsConfig(),
                           workers=3, show_progress=False)
    assert set(result) == {"a.example", "broken.example", "b.example"}
    broken = result["broken.example"]
    assert broken.findings and broken.findings[0].severity == Severity.NOT_ASSESSED
    assert "internal error" in broken.findings[0].title.lower()
    assert not result["a.example"].findings  # unaffected domains are untouched


def test_scan_dns_workers_capped_by_domain_count(monkeypatch):
    from mailwarden import cli
    from mailwarden.config import DnsConfig
    from mailwarden.models import DomainAssessment

    monkeypatch.setattr(cli, "audit_domain", lambda dom, cfg: DomainAssessment(domain=dom))
    result = cli._scan_dns(["only-one.example"], DnsConfig(), workers=50, show_progress=False)
    assert list(result) == ["only-one.example"]


def test_full_scan_cli_uses_concurrent_dns(tmp_path, capsys):
    from mailwarden.cli import main
    d = tmp_path / "d.txt"
    d.write_text("a.example\nb.example\nc.example\n")
    rc = main(["scan", "--domains", str(d), "--mode", "dns",
              "--dns-timeout", "0.2", "--dns-nameservers", "192.0.2.1",
              "--dns-workers", "3", "--output", str(tmp_path / "o")])
    assert rc == 0
    err = capsys.readouterr().err
    assert "3 at a time" in err
    assert "domains checked" in err


def test_scan_dns_progress_lines_never_run_together(monkeypatch, capsys):
    """Each progress checkpoint must end with its own newline, even while other
    threads are logging warnings at the same time (the bug: a '\\r'-based live
    line collided with log output mid-line, e.g. '41/137 domains checkedwarning...').
    """
    import logging
    from mailwarden import cli
    from mailwarden.config import DnsConfig
    from mailwarden.models import DomainAssessment

    def fake_audit(dom, dns_cfg):
        logging.getLogger("mailwarden").warning("dns check failed  [domain=%s check=SPF]", dom)
        return DomainAssessment(domain=dom)

    monkeypatch.setattr(cli, "audit_domain", fake_audit)
    domains = [f"d{i}.example" for i in range(25)]
    cli._scan_dns(domains, DnsConfig(), workers=5, show_progress=True)
    err_lines = capsys.readouterr().err.splitlines()
    checked_lines = [ln for ln in err_lines if "domains checked" in ln]
    assert checked_lines, "expected at least one progress line"
    for ln in checked_lines:
        assert ln.strip().endswith("domains checked")  # nothing glued on after it
        assert "warning" not in ln.lower()  # a log line never shares a line with progress
