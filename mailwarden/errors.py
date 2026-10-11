"""Domain-specific exception hierarchy."""
from __future__ import annotations


class GwAuditError(Exception):
    """Base error for the audit platform."""


class InputError(GwAuditError):
    """Problem loading or validating input."""


class AuthorizationError(GwAuditError):
    """Customer is not authorized for the requested mode."""


class DNSError(GwAuditError):
    """DNS resolution / parsing error."""


class ApiError(GwAuditError):
    """Google API failure (already retried)."""


class EvidenceError(GwAuditError):
    """Missing or malformed relay evidence."""


class CredentialLeakError(GwAuditError):
    """A report would have contained credential material. Refused to write."""


class ProbeError(GwAuditError):
    """An active relay probe was requested without the authorization it requires."""