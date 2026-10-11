# Mailwarden

Customer-scoped **email security and SMTP relay audit for Google Workspace**.

Mailwarden checks a domain's public mail posture (SPF, DKIM, DMARC, MX, DNSSEC), reads Workspace
audit logs with a **read-only** scope, and judges SMTP relay settings that an administrator exports.
It produces one self-contained HTML report plus CSV/JSON for your tracker.

## Safety model (enforced in code, covered by tests)

- **Authorized scope only.** `workspace` and `full` modes refuse any domain without an active, unexpired entry in your authorization file.
- **No cross-customer target list.** Relay verdicts are per customer. The tool never aggregates "domains that can be spammed".
- **Honest verdicts.** Missing evidence is *not assessed* (hatched in the UI), never "clean". A relay path is only *confirmed* when Google's own audit events back it up; a permissive config alone is *suspected*.
- **Credential guard.** If any finding contains key/token/password-like material, the report build is refused (exit code 3). Reports never contain credentials.
- **Read-only.** The only Google scope used is `admin.reports.audit.readonly`. Tokens are cached with `0600` permissions.
- The report is escaped, uses a strict CSP, loads nothing from the internet, and CSV exports neutralise spreadsheet formulas.

## Run it locally (venv)

Requires **Python 3.11+**.

**On Windows?** See [`WINDOWS_GUIDE.md`](WINDOWS_GUIDE.md) for a one-click `scan.bat`
launcher and a step-by-step guide — no server, everything stays on your PC.

```bash
# 1. get the code and enter it
cd mailwarden

# 2. create + activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate            # Windows PowerShell: .venv\Scripts\Activate.ps1
                                     # Windows cmd:        .venv\Scripts\activate.bat

# 3. install (editable) with test tools
pip install -e ".[dev]"

# 4. check your environment
mailwarden doctor

# 5. run the test suite
pytest -q

# 6. see the UI right now: synthetic data, no network, no credentials
mailwarden demo --serve              # opens http://127.0.0.1:8765/summary.html
```

### Try it on a real domain (public DNS only, nothing to authorize)

```bash
mailwarden init my-audit                              # writes example input files
echo "yourdomain.com" > my-audit/domains.txt          # only domains you are authorized to assess
mailwarden scan --domains my-audit/domains.txt --mode dns
mailwarden serve                                      # view mailwarden-output/summary.html
```

### Full assessment (Workspace logs + relay evidence)

```bash
pip install -e ".[google]"                            # Google API libraries
# edit my-audit/authorization.json (customer_id, expiry, approved IPs)
# put the exported relay settings in my-audit/relay/<domain>.relay.json

mailwarden scan --mode full \
  --domains my-audit/domains.txt \
  --authorization my-audit/authorization.json \
  --relay-evidence-dir my-audit/relay \
  --service-account sa-key.json --impersonate-admin admin@yourdomain.com
```

Use `--oauth-client-secrets client_secret.json` instead of a service account if you prefer an interactive login.

### Other commands

| Command | What it does |
|---|---|
| `mailwarden demo [--serve]` | Build a sample report from synthetic data |
| `mailwarden init [DIR]` | Write editable example inputs |
| `mailwarden authorize --from domains.txt` | Generate/merge the authorization file from a domains list (one step instead of per-domain JSON) |
| `mailwarden scan ...` | Run an assessment (`--mode dns \| workspace \| full`) |
| `mailwarden report --input DIR [--format html,csv,json]` | Rebuild reports from saved raw results |
| `mailwarden serve [--dir DIR] [--port 8765]` | View a report folder (localhost only) |
| `mailwarden doctor` | Check Python and dependencies |

Exit codes: `0` ok, `2` input/authorization error, `3` credential guard refused the build, `4` a `--fail-on` / `--fail-on-relay-exploit` threshold was hit, `130` interrupted.
For CI:
- Spoofing/DNS posture: `mailwarden scan --mode dns --domains d.txt --fail-on high`
- Open-relay (any-IP) regression: `mailwarden scan --mode full --domains d.txt --relay-evidence-dir relay --fail-on-relay-exploit high`

`--fail-on-relay-exploit high` exits `4` if any domain's SMTP relay is exploitable from any IP (evidence-backed, confirmed or suspected); `confirmed` fires only when Google audit events confirm abuse. The public-DNS "needs evidence" screening never trips the gate. See [`examples/`](examples/) for runnable relay-evidence samples.

## Relay evidence format

`<domain>.relay.json`, exported by an administrator from *Admin console > Apps > Google Workspace > Gmail > Routing > SMTP relay service*:

```json
{
  "domain": "example.com",
  "require_tls": true,
  "require_auth": true,
  "allowed_senders": ["example.com"],
  "authorized_ips": ["203.0.113.0/28"],
  "ip_restriction_enabled": true,
  "relay_host": "smtp-relay.gmail.com",
  "collected_at": "2026-01-15T12:00:00Z",
  "collected_by": "it-admin@example.com"
}
```

`ip_restriction_enabled` mirrors the Admin console's **"Only accept mail from the specified IP
addresses"** checkbox. Set it `false` (or list `0.0.0.0/0` in `authorized_ips`) when the relay
accepts mail from any IP — that is the open-relay condition the exploitability check looks for.
Omit it if you are unsure; it is then reported as *unknown*, never as clean. `relay_host` is
optional and defaults to `smtp-relay.gmail.com`.

Optionally pass `--relay-baseline-dir` with an earlier export to flag regressions (TLS removed, new IPs).

## Outputs

`summary.html` (the report), `findings.csv`, `abuse_review.csv` (one row per relay path), `spoofing_risk.csv` and `relay_exploit.csv` (one row per domain — see below), `findings.json`, `scan_metadata.json`, plus `raw/<customer>/<domain>.assessment.json` (0600) for `mailwarden report`.

The HTML report splits the two questions below into **two tabs** near the top of `summary.html`:
*Spoofing & bulk sending* and *SMTP relay exploitability*. They are kept apart on purpose — the
fix for one is in DNS, the fix for the other is in the Admin console.

### 1. Domains that could be used to send bulk or phishing email (spoofing)

Whether someone could send mail that merely *claims* to be from a domain, using only weak
SPF/DMARC — no access to your infrastructure needed.

- **HTML report** — the *Spoofing & bulk sending* tab, sorted worst-first with a reason per verdict.
- **`spoofing_risk.csv`** — one row per domain (`risk`, `dmarc_level`, `spf_level`, `why`).
  `risk=high` means nothing currently stops forged mail from that domain being delivered.

### 2. Domains whose SMTP relay could be exploited from any IP (relay exploitability)

A *separate* question: whether someone could relay bulk mail **through** a domain's own Google
Workspace SMTP relay (`smtp-relay.gmail.com`). The relay is exploitable when it has **no source-IP
range restriction** *and* does not require authentication — then any host on the internet can send
through it as the domain (open relay). This is exactly the "allows bulk email from any IP" case.

- **HTML report** — the *SMTP relay exploitability* tab, sorted worst-first. Each row shows the
  source-IP restriction, whether auth is required, the relay host, and a verdict.
- **`relay_exploit.csv`** — one row per domain (`risk`, `status`, `ip_restriction`, `auth_required`,
  `relay_host`, `why`, `remediation`).

Verdict strength is honest about its source:

| `status` | Meaning |
|---|---|
| `confirmed` | Admin-exported relay settings show the open-relay config **and** Google audit events show it was abused. |
| `probed` ("Confirmed (probe)") | An active probe (`--probe-relay`) observed the relay accept/reject unauthenticated mail from your test IP — a real verdict with no admin access needed. |
| `suspected` | Admin-exported relay settings show the open-relay config; no abuse event confirms it was used. |
| `screening` ("Needs evidence") | Public-DNS screening only: the domain uses Google Workspace, so the relay *could* be exploitable — export the relay settings or run `--probe-relay` to confirm. |
| `not_assessed` | The Google SMTP relay does not apply (e.g. mail is not routed through Google). |

#### Getting a verdict without admin rights: `--probe-relay`

The "Only accept mail from the specified IP addresses" setting can't be read from DNS or any public
API — so with no admin evidence, the source-IP restriction is honestly *Unknown*. You can resolve it
by **observing the relay's behaviour** instead of reading its config:

```bash
# one-time: turn your domains list into an authorization file (merges if it exists)
mailwarden authorize --from my-audit\domains.txt --approved-ips 203.0.113.0/28

mailwarden scan --mode dns \
  --domains my-audit\domains.txt \
  --authorization my-audit\authorization.json \
  --probe-relay
```

`mailwarden authorize` writes `authorized: true` for every domain in the list, so running it is your
explicit assertion that you own or may test them — only list domains you're cleared to probe. It
merges into an existing file (keeping customised entries), and `--approved-ips` records your sending
ranges so the probe can warn if it's run from inside them.

The scan then makes an **unauthenticated** connection to `smtp-relay.gmail.com` and asks whether it will relay
mail "from" your domain to an external recipient. Accepted → no source-IP restriction (**High**);
rejected (auth required / relay denied) → restricted. Safety rules, enforced in code:

- **Authorized domains only.** `--probe-relay` requires `--authorization`; it probes *only* domains
  with an active authorization entry and skips the rest. It is an active test — never point it at
  domains you don't own.
- **Nothing is delivered.** The probe stops at `RCPT TO` and never sends `DATA`. The default
  recipient is `relay-probe@example.com` (IANA-reserved, non-deliverable).
- **Run it from an IP *outside* your sending ranges** (a cloud VM, a mobile hotspot). From inside an
  allowed range, "accepted" can't prove "any IP" — the tool records the source IP the relay reports
  and flags the result as unreliable if it sees it inside your authorized ranges.

Both views are derived entirely from findings already collected, so they work instantly on existing
results with `mailwarden report --input <output-dir>` — no rescan needed. To turn a *Needs evidence*
row into a definite verdict, export the relay settings and re-scan with `--relay-evidence-dir`.

## Layout

```
mailwarden/
  cli.py            commands            models.py          data model + (de)serialisation
  dns_audit.py      SPF/DKIM/DMARC/MX   relay_audit.py     relay findings + per-path verdicts
  activity_analysis.py  audit events    workspace_reports.py  Reports API client (retry/backoff)
  google_auth.py    read-only creds     risk_engine.py     score + coverage gaps
  reporting.py      CSV/JSON/HTML + credential guard        templates/report.html.j2  the UI
  spoofing_risk.py  per-domain spoofing verdict (SPF/DMARC)  relay_exploit.py  per-domain relay exploitability (any-IP open relay)
  demo.py serve.py ui.py scaffold.py config.py input_loader.py storage.py logging_setup.py
tests/              offline unit tests
```

## Limits

The Reports API does not expose every relay setting, so relay analysis needs administrator-supplied evidence. Audit retention depends on the tenant's licence. DKIM is checked only for configured selectors (default `google`), so a miss is reported with low confidence. No findings does not mean secure.
