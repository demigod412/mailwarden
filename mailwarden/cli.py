"""Mailwarden command-line interface."""

from __future__ import annotations

import argparse
import concurrent.futures
import logging
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .activity_analysis import analyze_activity
from .config import AppConfig
from .dns_audit import audit_domain
from .errors import AuthorizationError, GwAuditError, InputError
from .input_loader import Authorization, load_authorization_manifest, load_domains
from .logging_setup import configure_logging
from .models import Category, Confidence, DomainAssessment, Finding, Severity
from .relay_audit import (
    audit_relay, build_relay_paths, diff_against_baseline, load_relay_evidence,
)
from .reporting import write_all
from .risk_engine import RiskEngine
from .scaffold import write_scaffold
from .storage import ResultStore
from .ui import paint, step, summary_table

log = logging.getLogger("mailwarden")
NOTES = [
    "DNS results are informational; conclusions about abuse require authorized evidence.",
    "Relay configuration is only assessed when administrator-supplied evidence exists.",
    "Relay path verdicts are scoped to the authorized customer; this tool does not "
    "produce a cross-customer target list.",
    "Credentials are never included in reports; a credential guard refuses the build "
    "if evidence contains credential-like material.",
]


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mailwarden", description=(
        "Mailwarden: customer-scoped email security and SMTP relay audit for Google Workspace"))
    p.add_argument("--version", action="version", version=f"mailwarden {__version__}")
    p.add_argument("--config", type=Path, default=None, help="optional TOML config file")
    p.add_argument("--log-level", default=None)
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("demo", help="Build a sample report from synthetic data (no network, no credentials)")
    d.add_argument("--output", type=Path, default=Path("mailwarden-demo"))
    d.add_argument("--serve", action="store_true", help="open the report in your browser afterwards")

    i = sub.add_parser("init", help="Write example input files to start from")
    i.add_argument("directory", type=Path, nargs="?", default=Path("mailwarden-inputs"))

    s = sub.add_parser("scan", help="Run an assessment")
    s.add_argument("--domains", type=Path, required=True)
    s.add_argument("--dns-timeout", type=float, default=None,
                   help="seconds to wait per DNS query (default 4.0). Raise this if you see "
                        "'LifetimeTimeout' warnings on a slow or filtered network.")
    s.add_argument("--dns-nameservers", default=None,
                   help="comma-separated resolver IPs to use instead of your system's default, "
                        "e.g. 1.1.1.1,8.8.8.8 (useful if a firewall blocks your normal DNS server)")
    s.add_argument("--dns-workers", type=int, default=8,
                   help="how many domains to check at once (default 8). Raise this for long domain "
                        "lists to finish faster; lower it if you suspect rate limiting.")
    s.add_argument("--mode", choices=["dns", "workspace", "full"], default="dns",
                   help="dns: public records only | workspace: + audit logs | full: + relay evidence")
    s.add_argument("--authorization", type=Path)
    s.add_argument("--relay-evidence-dir", type=Path)
    s.add_argument("--relay-baseline-dir", type=Path)
    s.add_argument("--output", type=Path)
    s.add_argument("--oauth-client-secrets", type=Path)
    s.add_argument("--service-account", type=Path)
    s.add_argument("--impersonate-admin")
    s.add_argument("--token-cache", type=Path, default=Path(".mailwarden_tokens"))
    s.add_argument("--fail-on", choices=["critical", "high", "none"], default="none",
                   help="exit with code 4 if findings at/above this severity exist (for CI)")
    s.add_argument("--fail-on-relay-exploit", choices=["confirmed", "high", "none"], default="none",
                   help="exit with code 4 if any domain's SMTP relay is exploitable from any IP "
                        "(for CI). 'high' fails on any evidence-backed open relay (confirmed or "
                        "suspected); 'confirmed' only when Google audit events confirm abuse. "
                        "Public-DNS 'needs evidence' screening never trips this gate.")
    s.add_argument("--lenient-credential-guard", action="store_true",
                   help="warn instead of refusing to write reports on a guard hit. NOT recommended.")
    s.add_argument("--probe-relay", action="store_true",
                   help="Actively probe smtp-relay.gmail.com to resolve the source-IP "
                        "restriction when you have no admin evidence. Requires --authorization: "
                        "ONLY domains with an active authorization entry are probed. The probe "
                        "makes an unauthenticated SMTP connection and stops at RCPT TO (no DATA, "
                        "nothing delivered). Run it from an IP OUTSIDE your sending ranges for a "
                        "valid 'any IP' verdict.")
    s.add_argument("--probe-host", default="smtp-relay.gmail.com",
                   help="relay host to probe (default smtp-relay.gmail.com)")
    s.add_argument("--probe-timeout", type=float, default=10.0,
                   help="seconds to wait per probe connection (default 10)")
    s.add_argument("--probe-rcpt", default=None,
                   help="envelope recipient for the probe (default relay-probe@example.com, an "
                        "IANA-reserved non-deliverable address). No message body is ever sent.")

    r = sub.add_parser("report", help="Regenerate reports from saved raw results")
    r.add_argument("--input", type=Path, required=True)
    r.add_argument("--format", default="html,csv,json", help="comma list of html,csv,json")
    r.add_argument("--output", type=Path)
    r.add_argument("--lenient-credential-guard", action="store_true")

    v = sub.add_parser("serve", help="View a report folder in your browser (localhost only)")
    v.add_argument("--dir", type=Path, default=None)
    v.add_argument("--port", type=int, default=8765)
    v.add_argument("--no-open", action="store_true")

    az = sub.add_parser("authorize", help=(
        "Generate/merge an authorization file from a domains list (one step instead "
        "of hand-writing JSON per domain)"))
    az.add_argument("--from", "--domains", dest="source", type=Path, required=True,
                    help="domains file to authorize (one domain per line)")
    az.add_argument("--output", type=Path, default=None,
                    help="authorization file to write (default: authorization.json next to the "
                         "domains file). An existing file is merged into, not overwritten.")
    az.add_argument("--customer-id", default="SELF",
                    help="customer id recorded on each new entry (default SELF; only used by "
                         "workspace/full modes)")
    az.add_argument("--expires-on", default=None,
                    help="expiry for new entries: YYYY-MM-DD, or 'never'. Default: one year from today.")
    az.add_argument("--approved-ips", default=None,
                    help="comma-separated CIDRs applied to every new entry (your own sending "
                         "ranges; lets the probe warn if it runs from inside them)")
    az.add_argument("--contact", default="")
    az.add_argument("--force", action="store_true",
                    help="rewrite the whole file from the list instead of merging into an existing one")

    sub.add_parser("doctor", help="Check your local environment")
    return p


# --------------------------------------------------------------------------- scan

def _authorize(domains: list[str], manifest: dict[str, Authorization], mode: str):
    if mode == "dns":
        return manifest
    missing = [d for d in domains if d not in manifest or not manifest[d].is_active()]
    if missing:
        raise AuthorizationError(
            f"not covered by an active authorization entry: {', '.join(missing)}. "
            "Add them to the authorization file (authorized: true, not expired) or use --mode dns.")
    return {d: manifest[d] for d in domains}


def _not_assessed(a: DomainAssessment, dom: str, title: str, evidence: dict, fix: str) -> Finding:
    return Finding(domain=dom, category=Category.RELAY, component="SMTP relay",
                   severity=Severity.NOT_ASSESSED, confidence=Confidence.HIGH, title=title,
                   evidence=evidence, detection_method="framework",
                   business_impact="Cannot assess relay configuration.", remediation=fix)


def _apply_relay(a: DomainAssessment, dom: str, auth: Authorization | None,
                 evidence_dir: Path | None, baseline_dir: Path | None) -> None:
    """Add relay findings, then build the path verdict from ALL findings so that
    abuse confirmed by Workspace audit events is taken into account."""
    ev = None
    if evidence_dir is None:
        a.add_finding(_not_assessed(a, dom, "Relay configuration not assessed (no evidence provided)",
                                    {"expected_path": f"{dom}.relay.json"},
                                    "Export relay settings from the Admin console and pass --relay-evidence-dir."))
        gaps = ["RELAY: no evidence"]
        a.coverage["RELAY"] = "no evidence provided"
    else:
        path = evidence_dir / f"{dom}.relay.json"
        try:
            ev = load_relay_evidence(path, expected_domain=dom)
        except GwAuditError as e:
            a.add_finding(_not_assessed(a, dom, "Relay evidence missing or malformed",
                                        {"error": str(e), "path": str(path)},
                                        "Provide a valid relay evidence JSON (see `mailwarden init`)."))
            gaps = [f"RELAY: {type(e).__name__}"]
            a.coverage["RELAY"] = "evidence unreadable"
        else:
            for f in audit_relay(ev, auth):
                a.add_finding(f)
            if baseline_dir and (baseline_dir / f"{dom}.relay.json").exists():
                try:
                    for f in diff_against_baseline(ev, load_relay_evidence(baseline_dir / f"{dom}.relay.json", dom)):
                        a.add_finding(f)
                except GwAuditError as e:
                    log.warning("baseline unreadable: %s", e)
            gaps = []
            a.coverage["RELAY"] = "ran"
    a.relay_paths = build_relay_paths(ev, auth, a.findings, gaps, domain=dom)


def _apply_probe(assessments: dict[str, DomainAssessment],
                 manifest: dict[str, Authorization], args: argparse.Namespace) -> None:
    """Run the active relay probe for AUTHORIZED domains only, attaching one
    finding per domain. Refuses entirely without an authorization manifest."""
    from .errors import ProbeError
    from .relay_probe import DEFAULT_RCPT, probe_finding, probe_relay

    if not manifest:
        raise ProbeError(
            "--probe-relay requires --authorization: it is an active test and only "
            "runs against domains you are authorized to assess.")
    authorized = [d for d in assessments if d in manifest and manifest[d].is_active()]
    skipped = [d for d in assessments if d not in authorized]
    rcpt = args.probe_rcpt or DEFAULT_RCPT
    step(f"Active relay probe for {len(authorized)} authorized domain(s)"
         + (f"; skipping {len(skipped)} unauthorized" if skipped else ""))
    for dom in skipped:
        assessments[dom].coverage["RELAY_PROBE"] = "skipped: not authorized"

    def _run(dom: str):
        return dom, probe_relay(dom, host=args.probe_host, rcpt_to=rcpt,
                                timeout=args.probe_timeout,
                                approved_ips=manifest[dom].approved_ips)

    workers = max(1, min(len(authorized) or 1, 8))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for fut in concurrent.futures.as_completed([ex.submit(_run, d) for d in authorized]):
            try:
                dom, result = fut.result()
            except Exception as e:  # a probe must never crash the scan
                log.warning("relay probe crashed: %s", e)
                continue
            assessments[dom].add_finding(probe_finding(result))
            assessments[dom].coverage["RELAY_PROBE"] = f"ran: {result.outcome}"
            if result.source_ip:
                log.info("relay probe %s: %s from %s", dom, result.outcome, result.source_ip)


def _scan_dns(domains: list[str], dns_cfg, workers: int, show_progress: bool = True
             ) -> dict[str, DomainAssessment]:
    """Run per-domain DNS checks concurrently. DNS lookups are I/O-bound (mostly
    spent waiting on the network), so a thread pool gives a large speedup on long
    domain lists without the risk a process pool would carry. Each call builds its
    own resolver, so domains never share mutable state across threads.

    Always returns exactly one assessment per domain, in the same order as
    `domains`, even if an individual domain's checks raise unexpectedly.
    """
    results: dict[str, DomainAssessment] = {}
    total = len(domains)
    done = 0
    workers = max(1, min(workers, total or 1))
    # Each domain's checks log their own warnings (via the `log` module) from worker
    # threads as they run. A single live-updating ("\r", no newline) progress line
    # would collide with those — the next warning lands mid-line instead of on its
    # own line. Printing a plain, newline-terminated line at a handful of points
    # instead keeps every line self-contained, whatever else is being logged at
    # the same time, at the cost of a scrolling counter instead of a static one.
    checkpoint = max(1, total // 20) if show_progress and total > 1 else None
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(audit_domain, dom, dns_cfg): dom for dom in domains}
        for fut in concurrent.futures.as_completed(futures):
            dom = futures[fut]
            try:
                results[dom] = fut.result()
            except Exception as e:  # one domain's checks must never kill the whole scan
                log.warning("DNS audit crashed for %s: %s", dom, e)
                a = DomainAssessment(domain=dom)
                a.add_finding(Finding(
                    domain=dom, category=Category.COVERAGE, severity=Severity.NOT_ASSESSED,
                    confidence=Confidence.HIGH, component="DNS audit",
                    title="DNS checks could not run for this domain (internal error)",
                    evidence={"error": str(e)}, detection_method="framework",
                    business_impact="Posture for this domain is unknown.",
                    remediation="Re-run the scan. If it keeps happening, report it with this error text."))
                results[dom] = a
            done += 1
            if checkpoint and (done % checkpoint == 0 or done == total):
                print(f"  {done}/{total} domains checked", file=sys.stderr)
    return {dom: results[dom] for dom in domains}  # restore input order regardless of completion order


def _apply_dns_overrides(cfg: AppConfig, args: argparse.Namespace) -> None:
    """Let --dns-timeout / --dns-nameservers win over the config file for one run."""
    if getattr(args, "dns_timeout", None):
        cfg.dns.timeout = args.dns_timeout
    if getattr(args, "dns_nameservers", None):
        cfg.dns.nameservers = [x.strip() for x in args.dns_nameservers.split(",") if x.strip()]


def _run_scan(args: argparse.Namespace) -> int:
    cfg = AppConfig.load(args.config)
    _apply_dns_overrides(cfg, args)
    if args.log_level:
        cfg.log_level = args.log_level
    configure_logging(cfg.log_level)
    started = datetime.now(timezone.utc).isoformat()

    domains = load_domains(args.domains)
    manifest = load_authorization_manifest(args.authorization) if args.authorization else {}
    manifest = _authorize(domains, manifest, args.mode)

    step(f"DNS checks for {len(domains)} domain(s)"
         + (f" ({args.dns_workers} at a time)" if len(domains) > 1 else ""))
    assessments = _scan_dns(domains, cfg.dns, args.dns_workers)
    for dom, a in assessments.items():
        if dom in manifest:
            a.customer_id = manifest[dom].customer_id

    if getattr(args, "probe_relay", False):
        _apply_probe(assessments, manifest, args)

    if args.mode in ("workspace", "full"):
        from .google_auth import CredentialBroker
        from .workspace_reports import ReportsClient
        step("Reading Workspace audit logs (read-only)")
        client = ReportsClient(CredentialBroker(
            cache_dir=args.token_cache, oauth_client_secrets=args.oauth_client_secrets,
            service_account_file=args.service_account, impersonate_admin=args.impersonate_admin), cfg.api)
        for dom in domains:
            for f in analyze_activity(client.fetch_all(manifest[dom].customer_id), manifest[dom]):
                assessments[dom].add_finding(f)
            assessments[dom].coverage["WORKSPACE_AUDIT"] = "ran"

    step("Relay assessment" if args.mode == "full" else "Relay not requested (mode is not 'full')")
    for dom, a in assessments.items():
        if args.mode == "full":
            _apply_relay(a, dom, manifest.get(dom), args.relay_evidence_dir,
                         args.relay_baseline_dir or cfg.relay_baseline_dir)
        else:
            a.relay_paths = build_relay_paths(None, manifest.get(dom), a.findings,
                                              ["RELAY: not in scan mode"], domain=dom)
        a.finished_at = datetime.now(timezone.utc).isoformat()

    out = args.output or Path(cfg.output_dir)
    store = ResultStore(out / "raw")
    for a in assessments.values():
        store.save_assessment(a)
    return _finish(list(assessments.values()), out, ",".join(domains), args.mode, started,
                   not args.lenient_credential_guard, args.fail_on,
                   fail_on_relay_exploit=args.fail_on_relay_exploit)


def _finish(assessments, out: Path, scope: str, mode: str, started: str,
            strict: bool, fail_on: str = "none", formats=None,
            fail_on_relay_exploit: str = "none") -> int:
    try:
        write_all(assessments, out, scope=scope, mode=mode, notes=NOTES, started=started,
                  finished=datetime.now(timezone.utc).isoformat(),
                  strict_credential_guard=strict, formats=formats)
    except GwAuditError as e:
        print(f"error: {e}", file=sys.stderr)
        return 3
    engine = RiskEngine()
    print()
    print(summary_table([(a, engine.score(a)) for a in assessments]))
    print(f"\nReports written to {paint(str(out), 'bold')}")
    print(f"View them:  mailwarden serve --dir {out}")
    gate_hit = False
    levels = {"critical": {Severity.CRITICAL}, "high": {Severity.CRITICAL, Severity.HIGH}}
    if fail_on in levels and any(f.severity in levels[fail_on] for a in assessments for f in a.findings):
        gate_hit = True
    if fail_on_relay_exploit != "none":
        if _relay_exploit_gate_hit(assessments, fail_on_relay_exploit):
            gate_hit = True
    return 4 if gate_hit else 0


def _relay_exploit_gate_hit(assessments, threshold: str) -> bool:
    """Return True (and print the offending domains) if any domain's SMTP relay
    is exploitable at/above the threshold. 'confirmed' = Google audit events
    confirm abuse; 'high' = any evidence-backed open relay. DNS-only 'screening'
    guesses never trip the gate -- they are not actionable failures."""
    from .relay_exploit import assess_all
    if threshold == "confirmed":
        hits = [r for r in assess_all(list(assessments)) if r.status == "confirmed"]
        label = "confirmed-abuse"
    else:  # "high"
        hits = [r for r in assess_all(list(assessments))
                if r.risk == "high" and r.status in ("confirmed", "suspected", "probed")]
        label = "open-relay (any IP, no auth)"
    if not hits:
        return False
    print(file=sys.stderr)
    print(paint(f"relay-exploit gate failed: {len(hits)} {label} domain(s):", "red"),
          file=sys.stderr)
    for r in hits:
        print(f"  - {r.domain} [{r.status}] via {r.relay_host}", file=sys.stderr)
    return True


# --------------------------------------------------------------------- other cmds

def _run_report(args: argparse.Namespace) -> int:
    cfg = AppConfig.load(args.config)
    configure_logging(args.log_level or cfg.log_level)
    if not args.input.exists():
        raise InputError(f"input dir not found: {args.input}")
    import json
    paths = sorted(args.input.rglob("*.assessment.json"))
    if not paths:
        raise InputError(f"no *.assessment.json files under {args.input} (run a scan first)")
    assessments = [DomainAssessment.from_dict(json.loads(p.read_text())) for p in paths]
    fmts = {x.strip() for x in args.format.split(",") if x.strip()}
    if not fmts <= {"html", "csv", "json"}:
        raise InputError("--format accepts: html, csv, json")
    return _finish(assessments, args.output or args.input, "rebuilt", "report",
                   assessments[0].started_at, not args.lenient_credential_guard, formats=fmts)


def _run_demo(args: argparse.Namespace) -> int:
    from .demo import build_demo_assessments
    from .serve import serve
    step("Building demo data (synthetic, offline)")
    now = datetime.now(timezone.utc).isoformat()
    rc = _finish(build_demo_assessments(), args.output, "demo (synthetic data)", "demo", now, True)
    if rc == 0 and args.serve:
        serve(args.output)
    return rc


def _run_init(args: argparse.Namespace) -> int:
    written = write_scaffold(args.directory)
    for p in written:
        print("created", p)
    if not written:
        print("nothing to do: files already exist")
    print(f"\nEdit them, then:\n  mailwarden scan --domains {args.directory}/domains.txt --mode dns")
    return 0


def _run_authorize(args: argparse.Namespace) -> int:
    """Build (or extend) an authorization file from a domains list.

    This writes authorized=true for the listed domains: running it is the user's
    explicit assertion that they own or are permitted to actively test them. It
    merges into any existing file so earlier, customised entries are preserved.
    """
    import ipaddress
    import json
    from datetime import date, timedelta

    domains = load_domains(args.source)  # validates + dedupes
    out = args.output or (args.source.parent / "authorization.json")

    # Resolve expiry for NEW entries.
    if args.expires_on and args.expires_on.strip().lower() == "never":
        expires: str | None = None
    elif args.expires_on:
        try:
            expires = date.fromisoformat(args.expires_on.strip()).isoformat()
        except ValueError:
            raise InputError(f"--expires-on must be YYYY-MM-DD or 'never', got {args.expires_on!r}")
    else:
        expires = (date.today() + timedelta(days=365)).isoformat()

    approved_ips = [x.strip() for x in (args.approved_ips or "").split(",") if x.strip()]
    for cidr in approved_ips:  # validate up front so we never write a broken file
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            raise InputError(f"--approved-ips contains an invalid CIDR: {cidr!r}")

    entries: list[dict] = []
    if out.exists() and not args.force:
        try:
            raw = json.loads(out.read_text())
        except json.JSONDecodeError as e:
            raise InputError(f"existing {out} is not valid JSON (pass --force to replace it): {e}")
        existing = raw.get("authorizations") if isinstance(raw, dict) else raw
        if not isinstance(existing, list):
            raise InputError(f"existing {out} is not in the expected format (pass --force to replace it)")
        entries = existing

    have = {str(e.get("domain", "")).lower() for e in entries if isinstance(e, dict)}
    added = 0
    for dom in domains:
        if dom in have:
            continue
        entry = {"domain": dom, "customer_id": args.customer_id, "authorized": True,
                 "expires_on": expires, "contact": args.contact, "approved_ips": approved_ips}
        if expires is None:
            entry.pop("expires_on")
        entries.append(entry)
        have.add(dom)
        added += 1

    payload = {"authorizations": entries}
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2) + "\n")

    # Validate what we just wrote, and report an honest active count.
    manifest = load_authorization_manifest(out)
    active = sum(1 for a in manifest.values() if a.is_active())
    kept = len(entries) - added
    print(f"Wrote {paint(str(out), 'bold')}: {len(entries)} entr{'y' if len(entries) == 1 else 'ies'} "
          f"({added} new, {kept} kept), {active} active.")
    print(f"New entries expire: {expires or 'never'}"
          + (f"; approved IPs: {', '.join(approved_ips)}" if approved_ips else ""))
    print(paint(
        "By authorizing these domains you assert you own them or have written permission "
        "to actively test them. Only authorized domains are probed by --probe-relay.", "yellow"))
    print(f"\nNext:\n  mailwarden scan --mode dns --domains {args.source} "
          f"--authorization {out} --probe-relay")
    return 0


def _run_doctor(_: argparse.Namespace) -> int:
    ok = True
    def line(good: bool, text: str, hint: str = "") -> None:
        nonlocal ok
        ok &= good
        print(f"  {paint('ok  ', 'green') if good else paint('FAIL', 'red')} {text}" + (f"  -> {hint}" if hint and not good else ""))
    print(f"mailwarden {__version__} on Python {platform.python_version()}")
    line(sys.version_info >= (3, 11), "Python 3.11+", "install Python 3.11 or newer")
    for mod, extra in (("dns", ""), ("jinja2", "")):
        try:
            __import__(mod); line(True, f"module {mod}")
        except ImportError:
            line(False, f"module {mod}", "pip install -e .")
    try:
        __import__("googleapiclient"); line(True, "Google API libraries (needed for workspace/full modes)")
    except ImportError:
        print(f"  {paint('skip', 'yellow')} Google API libraries not installed (only needed for workspace/full): pip install -e '.[google]'")
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.cmd == "scan": return _run_scan(args)
        if args.cmd == "report": return _run_report(args)
        if args.cmd == "demo": return _run_demo(args)
        if args.cmd == "init": return _run_init(args)
        if args.cmd == "authorize": return _run_authorize(args)
        if args.cmd == "doctor": return _run_doctor(args)
        if args.cmd == "serve":
            from .serve import serve
            d = args.dir or Path(AppConfig.load(args.config).output_dir)
            if not (d / "summary.html").exists():
                raise InputError(f"{d}/summary.html not found. Run a scan or `mailwarden demo` first.")
            serve(d, args.port, not args.no_open)
            return 0
    except GwAuditError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
