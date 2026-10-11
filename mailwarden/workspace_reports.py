"""Admin SDK Reports API client (login + admin audit logs) with retry/backoff."""

from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from .config import ApiConfig
from .errors import ApiError, InputError

log = logging.getLogger(__name__)
APPLICATIONS = ("login", "admin")


class ReportsClient:
    def __init__(self, broker, cfg: ApiConfig, service=None) -> None:
        self._broker, self._cfg, self._svc = broker, cfg, service

    def _service(self):
        if self._svc is None:
            try:
                from googleapiclient.discovery import build
            except ImportError as e:
                raise InputError("Google libraries missing. Run: pip install -e '.[google]'") from e
            self._svc = build("admin", "reports_v1", credentials=self._broker.credentials(),
                              cache_discovery=False)
        return self._svc

    def _execute(self, req):
        for attempt in range(self._cfg.max_retries + 1):
            try:
                return req.execute()
            except Exception as e:  # googleapiclient.errors.HttpError et al.
                status = getattr(getattr(e, "resp", None), "status", None)
                if status in (429, 500, 502, 503, 504) and attempt < self._cfg.max_retries:
                    time.sleep(min(30, 2 ** attempt))
                    continue
                raise ApiError(f"Reports API request failed (HTTP {status or 'n/a'})") from e
        raise ApiError("Reports API retries exhausted")

    def fetch_all(self, customer_id: str) -> list[dict[str, Any]]:
        start = (datetime.now(timezone.utc) - timedelta(days=self._cfg.lookback_days)).isoformat()
        items: list[dict[str, Any]] = []
        for app in APPLICATIONS:
            token = None
            while True:
                req = self._service().activities().list(
                    userKey="all", applicationName=app, customerId=customer_id,
                    startTime=start, maxResults=self._cfg.page_size, pageToken=token)
                page = self._execute(req)
                items.extend(page.get("items", []))
                token = page.get("nextPageToken")
                if not token:
                    break
        log.info("fetched audit events", extra={"extra_fields": {"count": len(items)}})
        return items
