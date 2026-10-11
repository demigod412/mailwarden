"""Structured JSON-ish logging with credential redaction."""

from __future__ import annotations

import json
import logging
import re
import sys

_REDACT = re.compile(
    r"(AIza[0-9A-Za-z_\-]{35}|ya29\.[0-9A-Za-z_\-]{20,}|1//[0-9A-Za-z_\-]{40,}|"
    r"GOCSPX-[A-Za-z0-9_\-]{10,}|Bearer\s+[A-Za-z0-9._\-]{20,})"
)


class _Formatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        extra = getattr(record, "extra_fields", {}) or {}
        msg = _REDACT.sub("<REDACTED>", record.getMessage())
        tail = " ".join(f"{k}={_REDACT.sub('<REDACTED>', str(v))}" for k, v in extra.items())
        return f"{record.levelname.lower():7} {msg}" + (f"  [{tail}]" if tail else "")


def configure_logging(level: str = "INFO") -> None:
    h = logging.StreamHandler(sys.stderr)
    h.setFormatter(_Formatter())
    root = logging.getLogger("mailwarden")
    root.handlers[:] = [h]
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.propagate = False
