"""Syntax, DNS, and optional SMTP checks for one address.

Inspection levels:

1. Syntax only. The domain must be a hostname with a dot.
2. Syntax plus DNS (MX, or A/AAAA when there is no MX). Lookup failures are unknown.
3. Syntax, DNS, and SMTP. ``RCPT`` is trusted after ``MAIL FROM`` 250.
   ``RCPT`` 250/251/252 is valid. ``552`` and enhanced status ``5.2.2`` mean the
   mailbox is full and are valid. Temporary 4xx replies, including on
   ``MAIL FROM``, count as valid. Policy and relay rejections are unknown.
4. Same probe as 3, but 4xx replies are unknown. ``552`` stays valid.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass

from .dns_utils import DNSResolver, ascii_domain
from .smtp_checker import SMTPChecker, require_port, require_timeout

_LOCAL_PART = re.compile(r"^[A-Za-z0-9!#%&'*+/=?^_`{|}~.-]+$")
_ATOM_CHAR = re.compile(r"[A-Za-z0-9!#%&'*+/=?^_`{|}~.-]")
_DOMAIN_LABEL = re.compile(r"[A-Za-z0-9-]+$")


def _unsafe(value: str) -> bool:
    return any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value)


def valid_domain(domain: str) -> bool:
    """True when ``domain`` is a dotted hostname, including Unicode labels."""
    if not domain or _unsafe(domain) or len(domain) > 253:
        return False
    try:
        encoded = ascii_domain(domain).rstrip(".")
    except UnicodeError:
        return False
    if "." not in encoded or len(encoded) > 253:
        return False
    for label in encoded.split("."):
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if _DOMAIN_LABEL.fullmatch(label) is None:
            return False
    return True


def valid_localpart(local: str) -> bool:
    """True for an ASCII atom or a UTF-8 local part that can be sent via SMTPUTF8."""
    if not local or len(local.encode("utf-8")) > 64:
        return False
    if local[0] == "." or local[-1] == "." or ".." in local:
        return False
    if any(char in "<>" or char.isspace() or ord(char) < 32 or ord(char) == 127 for char in local):
        return False
    if all(ord(char) < 128 for char in local):
        return _LOCAL_PART.fullmatch(local) is not None
    return all(ord(char) > 127 or _ATOM_CHAR.fullmatch(char) is not None for char in local)


def usable_mailbox(address: str) -> bool:
    """True when ``address`` can be used as MAIL FROM."""
    if _unsafe(address) or address.count("@") != 1:
        return False
    local, domain = address.split("@", 1)
    if not valid_localpart(local):
        return False
    return valid_domain(domain)


@dataclass
class ValidationResult:
    """Outcome of one address check."""

    status: str
    stage: str
    reason: str
    inspection: int
    address: str
    from_address: str = ""
    timeout: int = 0
    port: int = 25
    mx_hosts: list[str] | None = None

    def __str__(self) -> str:
        hosts = ", ".join(self.mx_hosts or []) or "None"
        return (
            f"{self.address} is {self.status.upper()}\n"
            f"Inspection Level: {self.inspection}\n"
            f"Stage: {self.stage}\n"
            f"Reason: {self.reason}\n"
            f"From Address: {self.from_address}\n"
            f"Timeout: {self.timeout}s\n"
            f"Port: {self.port}\n"
            f"MX Hosts: {hosts}\n"
        )

    @property
    def ok(self) -> bool:
        """True when ``status`` is ``valid``."""
        return self.status == "valid"


class EmailValidator:
    """Reusable checker. ``validate`` always returns a result and does not raise."""

    def __init__(
        self,
        inspection: int = 2,
        timeout: int = 5,
        from_address: str = "",
        debug: bool = False,
        port: int = 25,
    ) -> None:
        level = int(inspection)
        if level not in (1, 2, 3, 4):
            raise ValueError("inspection must be 1, 2, 3, or 4")
        self.inspection = level
        self.timeout = require_timeout(timeout)
        self.from_address = from_address.strip()
        self.debug = debug
        self.port = require_port(port)
        self._check_from_address()
        self.dns = DNSResolver(debug=debug, timeout=self.timeout)
        self.smtp = SMTPChecker(timeout=self.timeout, debug=debug, port=self.port)

    def _check_from_address(self) -> None:
        if self.inspection >= 3 and not self.from_address:
            raise ValueError("from_address is required when inspection is 3 or 4")
        if self.from_address and not usable_mailbox(self.from_address):
            raise ValueError("from_address is not a usable email address")

    def _dbg(self, msg: str) -> None:
        if self.debug:
            print(f"DEBUG >>> {msg}", file=sys.stderr)

    def _result(
        self,
        *,
        status: str,
        stage: str,
        reason: str,
        address: str,
        mx_hosts: list[str] | None,
    ) -> ValidationResult:
        return ValidationResult(
            status=status,
            stage=stage,
            reason=reason,
            inspection=self.inspection,
            address=address,
            from_address=self.from_address,
            timeout=self.timeout,
            port=self.port,
            mx_hosts=mx_hosts if mx_hosts is not None else [],
        )

    @staticmethod
    def _split_email(addr: str) -> tuple[str, str]:
        parts = addr.split("@", 1)
        if len(parts) == 2:
            return parts[0], parts[1]
        return parts[0], ""

    def validate(self, email: str) -> ValidationResult:
        """Check one address at this validator's inspection level."""
        email = email.strip().lstrip("\ufeff")
        if _unsafe(email) or email.count("@") != 1:
            return self._result(
                status="invalid",
                stage="basic",
                reason="not an email shape",
                address=email,
                mx_hosts=[],
            )

        local, domain = self._split_email(email)
        self._dbg(f"Validating {email}")
        if not valid_localpart(local):
            return self._result(
                status="invalid",
                stage="localpart",
                reason="invalid local part",
                address=email,
                mx_hosts=[],
            )
        if not valid_domain(domain):
            return self._result(
                status="invalid",
                stage="domain",
                reason="invalid domain",
                address=email,
                mx_hosts=[],
            )

        if self.inspection < 2:
            return self._result(
                status="valid",
                stage="syntax",
                reason="ok",
                address=email,
                mx_hosts=[],
            )

        try:
            lookup_name = ascii_domain(domain).rstrip(".")
        except UnicodeError:
            return self._result(
                status="invalid",
                stage="domain",
                reason="invalid domain",
                address=email,
                mx_hosts=[],
            )

        found = self.dns.lookup_mx(lookup_name)
        if found.error:
            return self._result(
                status="unknown",
                stage="dns",
                reason=found.error or "DNS lookup failed",
                address=email,
                mx_hosts=[],
            )
        if found.nxdomain:
            return self._result(
                status="invalid",
                stage="dns",
                reason="domain does not exist",
                address=email,
                mx_hosts=[],
            )
        if found.null_mx:
            return self._result(
                status="invalid",
                stage="dns",
                reason="null MX; domain does not accept mail",
                address=email,
                mx_hosts=[],
            )
        if not found.hosts:
            addressed = self.dns.has_address(lookup_name)
            if addressed is None:
                return self._result(
                    status="unknown",
                    stage="dns",
                    reason="DNS lookup failed",
                    address=email,
                    mx_hosts=[],
                )
            if not addressed:
                return self._result(
                    status="invalid",
                    stage="dns",
                    reason="no MX or A/AAAA for domain",
                    address=email,
                    mx_hosts=[],
                )
            mx_hosts = [lookup_name]
        else:
            mx_hosts = [host for host, _pref in found.hosts]
        if self.inspection == 2:
            return self._result(
                status="valid",
                stage="dns",
                reason="domain resolvable",
                address=email,
                mx_hosts=mx_hosts,
            )

        status, reason = self.smtp.check(
            recipient=email,
            sender=self.from_address,
            mx_hosts=mx_hosts,
            strict_tempfail=self.inspection >= 4,
        )
        return self._result(
            status=status,
            stage="smtp",
            reason=reason,
            address=email,
            mx_hosts=mx_hosts,
        )
