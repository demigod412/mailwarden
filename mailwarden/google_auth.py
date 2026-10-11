"""Credential broker for the Admin SDK Reports API (read-only scope).

Tokens are cached locally with 0600 permissions and are never logged or reported.
"""

from __future__ import annotations

import os
from pathlib import Path

from .errors import AuthorizationError, InputError

SCOPES = ["https://www.googleapis.com/auth/admin.reports.audit.readonly"]


class CredentialBroker:
    def __init__(self, cache_dir: Path, oauth_client_secrets: Path | None = None,
                 service_account_file: Path | None = None,
                 impersonate_admin: str | None = None) -> None:
        self.cache_dir = Path(cache_dir)
        self.oauth_client_secrets = oauth_client_secrets
        self.service_account_file = service_account_file
        self.impersonate_admin = impersonate_admin

    def credentials(self):
        try:
            if self.service_account_file:
                from google.oauth2 import service_account
                if not self.impersonate_admin:
                    raise InputError("--impersonate-admin is required with --service-account")
                creds = service_account.Credentials.from_service_account_file(
                    str(self.service_account_file), scopes=SCOPES)
                return creds.with_subject(self.impersonate_admin)
            if self.oauth_client_secrets:
                return self._oauth()
        except ImportError as e:
            raise InputError("Google libraries missing. Run: pip install -e '.[google]'") from e
        raise AuthorizationError("provide --service-account or --oauth-client-secrets for workspace mode")

    def _oauth(self):
        from google.auth.transport.requests import Request
        from google.oauth2.credentials import Credentials
        from google_auth_oauthlib.flow import InstalledAppFlow

        self.cache_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.cache_dir, 0o700)
        token = self.cache_dir / "token.json"
        creds = Credentials.from_authorized_user_file(str(token), SCOPES) if token.exists() else None
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        elif not creds or not creds.valid:
            flow = InstalledAppFlow.from_client_secrets_file(str(self.oauth_client_secrets), SCOPES)
            creds = flow.run_local_server(port=0)
        token.write_text(creds.to_json())
        os.chmod(token, 0o600)
        return creds
