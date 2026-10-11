"""Local artifact storage with per-customer isolation and restricted perms."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .models import DomainAssessment


class ResultStore:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.root, 0o700)
        except OSError:
            pass

    def customer_dir(self, customer_id: str) -> Path:
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in customer_id)
        d = self.root / safe
        d.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass
        return d

    def save_assessment(self, a: DomainAssessment) -> Path:
        cid = a.customer_id or "unscoped"
        target = self.customer_dir(cid) / f"{a.domain}.assessment.json"
        payload: dict[str, Any] = a.to_dict()
        target.write_text(json.dumps(payload, indent=2, default=str))
        try:
            os.chmod(target, 0o600)
        except OSError:
            pass
        return target