"""Domain lists and the customer authorization manifest.

Workspace and relay checks only run for domains with an active, explicit
authorization entry. DNS-only mode reads public records and needs none.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from .errors import InputError

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


@dataclass(slots=True)
class Authorization:
    domain: str
    customer_id: str
    authorized: bool
    expires_on: date | None = None
    approved_ips: list = field(default_factory=list)
    contact: str = ""

    def is_active(self, today: date | None = None) -> bool:
        if not self.authorized:
            return False
        return self.expires_on is None or (today or date.today()) <= self.expires_on


def load_domains(path: Path) -> list[str]:
    try:
        lines = Path(path).read_text().splitlines()
    except FileNotFoundError as e:
        raise InputError(f"domains file not found: {path}") from e
    out: list[str] = []
    for n, raw in enumerate(lines, 1):
        line = raw.split("#", 1)[0].strip().lower()
        if not line:
            continue
        if not _DOMAIN_RE.match(line):
            raise InputError(f"{path}:{n}: '{line}' is not a valid domain name")
        if line not in out:
            out.append(line)
    if not out:
        raise InputError(f"no domains found in {path}")
    return out


def load_authorization_manifest(path: Path) -> dict[str, Authorization]:
    try:
        data = json.loads(Path(path).read_text())
    except FileNotFoundError as e:
        raise InputError(f"authorization file not found: {path}") from e
    except json.JSONDecodeError as e:
        raise InputError(f"authorization file is not valid JSON: {e}") from e
    entries = data.get("authorizations") if isinstance(data, dict) else data
    if not isinstance(entries, list):
        raise InputError("authorization file must be a list or {'authorizations': [...]}")
    manifest: dict[str, Authorization] = {}
    for i, e in enumerate(entries):
        try:
            dom = str(e["domain"]).lower()
            cust = str(e["customer_id"])
            exp = date.fromisoformat(e["expires_on"]) if e.get("expires_on") else None
            nets = [ipaddress.ip_network(x, strict=False) for x in e.get("approved_ips", [])]
        except (KeyError, ValueError, TypeError) as ex:
            raise InputError(f"authorization entry #{i + 1} is invalid: {ex}") from ex
        manifest[dom] = Authorization(
            domain=dom, customer_id=cust, authorized=bool(e.get("authorized", False)),
            expires_on=exp, approved_ips=nets, contact=str(e.get("contact", "")),
        )
    return manifest
