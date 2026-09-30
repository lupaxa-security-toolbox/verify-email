"""lupaxa.verify_email — syntax, DNS, and optional SMTP checks for an address."""

from __future__ import annotations

from .validator import EmailValidator, ValidationResult
from .version import __version__, get_version

__all__ = [
    "EmailValidator",
    "ValidationResult",
    "__version__",
    "get_version",
]
