"""`mailwarden init`: write editable example inputs."""

from __future__ import annotations

import json
from pathlib import Path

DOMAINS = "# One domain per line. Only list domains you are authorized to assess.\nexample.com\n"

AUTH = {"authorizations": [{
    "domain": "example.com", "customer_id": "C0xxxxxxx", "authorized": True,
    "expires_on": "2099-12-31", "contact": "it-admin@example.com",
    "approved_ips": ["203.0.113.0/28"],
}]}

RELAY = {
    "domain": "example.com", "require_tls": True, "require_auth": True,
    "allowed_senders": ["example.com"], "authorized_ips": ["203.0.113.0/28"],
    # True  = "Only accept mail from the specified IP addresses" is ON (allowlist enforced).
    # False = that box is OFF, so the relay accepts mail from ANY IP (open-relay posture).
    # Omit it if you are unsure; it is then reported as unknown, never as clean.
    "ip_restriction_enabled": True,
    "relay_host": "smtp-relay.gmail.com",
    "collected_at": "2026-01-15T12:00:00Z", "collected_by": "it-admin@example.com",
    "notes": "Exported from Admin console > Apps > Google Workspace > Gmail > Routing > SMTP relay service",
}

CONFIG = '''# mailwarden.toml (all keys optional)
output_dir = "mailwarden-output"
log_level = "INFO"

[dns]
# How long to wait per DNS query before giving up. Raised above the library
# default (4.0s) because corporate networks, VPNs and some antivirus tools
# add enough latency to cause false timeouts ("LifetimeTimeout" warnings) at
# the default value, especially on Windows.
timeout = 8.0
dkim_selectors = ["google"]
# Explicit public resolvers, used instead of your system's default DNS server.
# Helpful if your normal resolver is slow, overloaded, or blocked by a
# firewall. Comment this out to use your system's default resolver instead.
nameservers = ["1.1.1.1", "8.8.8.8"]

[api]
lookback_days = 30
'''


def write_scaffold(target: Path) -> list[Path]:
    (target / "relay").mkdir(parents=True, exist_ok=True)
    files = {
        target / "domains.txt": DOMAINS,
        target / "authorization.json": json.dumps(AUTH, indent=2) + "\n",
        target / "relay" / "example.com.relay.json": json.dumps(RELAY, indent=2) + "\n",
        target / "mailwarden.toml": CONFIG,
    }
    written = []
    for p, text in files.items():
        if not p.exists():
            p.write_text(text)
            written.append(p)
    return written
