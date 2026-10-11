# Examples

Worked examples you can run against with **no network and no credentials**. They
show the shape of the administrator-exported SMTP relay evidence and how Mailwarden
turns it into a verdict on the *SMTP relay exploitability* tab.

## Relay evidence samples (`relay/`)

An administrator exports these from **Admin console → Apps → Google Workspace →
Gmail → Routing → SMTP relay service**, one JSON file per domain named
`<domain>.relay.json`.

| File | What it represents | Verdict |
|---|---|---|
| `secure.example.com.relay.json` | IP allowlist ON, SMTP AUTH + TLS required | **Low** — not open to arbitrary IPs |
| `open-relay.example.com.relay.json` | `ip_restriction_enabled: false` **and** `require_auth: false` | **High — exploitable from any IP** (open relay) |

The one field that decides exploitability is **`ip_restriction_enabled`**:

- `true`  → "Only accept mail from the specified IP addresses" is **ON** (allowlist enforced)
- `false` → that box is **OFF**, so the relay accepts mail from **any IP**
- omitted → reported as *unknown* (a coverage gap), never as clean

Listing `0.0.0.0/0` (or `any`) in `authorized_ips` means the same thing as
`ip_restriction_enabled: false`.

## Try it

```bash
# scan the two example domains using the sample relay evidence
printf "secure.example.com\nopen-relay.example.com\n" > examples/domains.txt

mailwarden scan --mode full \
  --domains examples/domains.txt \
  --relay-evidence-dir examples/relay \
  --output examples/output

mailwarden serve --dir examples/output   # open the "SMTP relay exploitability" tab
```

`open-relay.example.com` shows up as **High / Any IP / Suspected**;
`secure.example.com` shows as **Low**. See `examples/output/relay_exploit.csv` too.

> Note: `--mode full` without `--authorization` will ask you to authorize those
> domains. These are `example.com` names you own the right to test; for your real
> domains, list them in an `authorization.json` (see `mailwarden init`). To just see
> the parsing without authorization, keep them in a throwaway run or add an
> `authorization.json` entry for each.

## CI gate

To make a scheduled/CI run **fail** when any real (evidence-backed) open relay is found:

```bash
mailwarden scan --mode full \
  --domains your-domains.txt \
  --relay-evidence-dir your-relay-evidence \
  --fail-on-relay-exploit high
```

Exit code `4` means at least one domain's relay is exploitable from any IP. The
public-DNS "needs evidence" screening never trips this gate — only exported
settings (or an active `--probe-relay` result, below) do.

## No admin rights? Resolve "Unknown" with `--probe-relay`

If you can't export the relay settings, you can still get a real verdict by probing the
relay's behaviour — see the README's *Getting a verdict without admin rights* section:

```bash
mailwarden scan --mode dns --domains my-audit\domains.txt \
  --authorization my-audit\authorization.json --probe-relay
```

Run it from an IP **outside** your sending ranges. It only probes domains you've authorized,
makes an unauthenticated connection, and **stops at RCPT TO (no message is ever sent)**.

