"""Syntax, DNS, and SMTP orchestration without live network calls."""

from __future__ import annotations

import pytest

from lupaxa.verify_email import EmailValidator
from lupaxa.verify_email.dns_utils import MxLookup


def test_syntax_only_accepts_a_plain_address() -> None:
    result = EmailValidator(inspection=1).validate("user@example.com")
    assert result.status == "valid"
    assert result.stage == "syntax"
    assert result.ok is True


def test_rejects_a_shape_that_is_not_an_address() -> None:
    result = EmailValidator(inspection=4, from_address="me@example.com").validate("not-an-email")
    assert result.status == "invalid"
    assert result.stage == "basic"


def test_rejects_a_bad_local_part() -> None:
    result = EmailValidator(inspection=1).validate(".user@example.com")
    assert result.status == "invalid"
    assert result.stage == "localpart"


def test_inspection_must_be_in_range() -> None:
    with pytest.raises(ValueError, match="inspection must be 1, 2, 3, or 4"):
        EmailValidator(inspection=0)
    with pytest.raises(ValueError, match="inspection must be 1, 2, 3, or 4"):
        EmailValidator(inspection=9, from_address="me@example.com")


def test_dns_invalid_when_the_domain_does_not_resolve(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    validator = EmailValidator(inspection=2)
    monkeypatch.setattr(validator.dns, "lookup_mx", lambda _domain: MxLookup())
    monkeypatch.setattr(validator.dns, "has_address", lambda _domain: False)
    result = validator.validate("user@example.com")
    assert result.status == "invalid"
    assert result.stage == "dns"


def test_dns_valid_when_mx_exists(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    validator = EmailValidator(inspection=2)
    monkeypatch.setattr(
        validator.dns,
        "lookup_mx",
        lambda _domain: MxLookup(hosts=[("mx.example.com", 10)]),
    )
    result = validator.validate("user@example.com")
    assert result.status == "valid"
    assert result.stage == "dns"
    assert result.mx_hosts == ["mx.example.com"]


def test_smtp_uses_the_domain_when_there_is_no_mx(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    validator = EmailValidator(inspection=3, from_address="me@example.com")
    monkeypatch.setattr(validator.dns, "lookup_mx", lambda _domain: MxLookup())
    monkeypatch.setattr(validator.dns, "has_address", lambda _domain: True)
    seen: dict[str, object] = {}

    def _check(**kwargs: object) -> tuple[str, str]:
        seen.update(kwargs)
        return "valid", "250 ok"

    monkeypatch.setattr(validator.smtp, "check", _check)
    result = validator.validate("user@example.com")
    assert result.status == "valid"
    assert result.stage == "smtp"
    assert seen["mx_hosts"] == ["example.com"]
    assert seen["strict_tempfail"] is False


def test_null_mx_is_invalid_even_when_an_address_exists(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    validator = EmailValidator(inspection=2)
    monkeypatch.setattr(validator.dns, "lookup_mx", lambda _domain: MxLookup(null_mx=True))
    monkeypatch.setattr(validator.dns, "has_address", lambda _domain: True)
    result = validator.validate("user@example.com")
    assert result.status == "invalid"
    assert result.stage == "dns"
    assert "null MX" in result.reason


def test_custom_port_is_stored() -> None:
    assert EmailValidator().port == 25
    assert EmailValidator(port=2525).smtp.port == 2525


def test_level_four_asks_for_strict_tempfail(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    validator = EmailValidator(inspection=4, from_address="me@example.com")
    monkeypatch.setattr(
        validator.dns,
        "lookup_mx",
        lambda _domain: MxLookup(hosts=[("mx.example.com", 1)]),
    )
    seen: dict[str, object] = {}

    def _check(**kwargs: object) -> tuple[str, str]:
        seen.update(kwargs)
        return "unknown", "450 try later"

    monkeypatch.setattr(validator.smtp, "check", _check)
    result = validator.validate("user@example.com")
    assert result.status == "unknown"
    assert seen["strict_tempfail"] is True
    assert "450" in str(result)


def test_smtp_requires_from_address() -> None:
    with pytest.raises(ValueError, match="from_address is required"):
        EmailValidator(inspection=3)


def test_control_characters_are_rejected() -> None:
    result = EmailValidator(inspection=1).validate("user@example.com\r\nRCPT TO:<other>")
    assert result.status == "invalid"
    assert result.stage == "basic"


def test_unicode_local_part_is_accepted() -> None:
    result = EmailValidator(inspection=1).validate("üser@example.com")
    assert result.status == "valid"
    assert result.stage == "syntax"


def test_bom_is_ignored() -> None:
    result = EmailValidator(inspection=1).validate("\ufeffuser@example.com")
    assert result.status == "valid"
    assert result.address == "user@example.com"


def test_quoted_local_part_is_rejected() -> None:
    result = EmailValidator(inspection=1).validate('"a>"@example.com')
    assert result.status == "invalid"
    assert result.stage == "localpart"


def test_domain_without_a_dot_is_rejected() -> None:
    result = EmailValidator(inspection=1).validate("user@localhost")
    assert result.status == "invalid"
    assert result.stage == "domain"


def test_unicode_domain_is_looked_up_as_punycode(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    validator = EmailValidator(inspection=2)
    seen: dict[str, str] = {}

    def lookup(domain: str) -> MxLookup:
        seen["domain"] = domain
        return MxLookup(hosts=[("mx.example", 1)])

    monkeypatch.setattr(validator.dns, "lookup_mx", lookup)
    result = validator.validate("user@münchen.example")
    assert result.status == "valid"
    assert seen["domain"].startswith("xn--")
    assert seen["domain"].endswith(".example")


def test_dns_error_is_unknown(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    validator = EmailValidator(inspection=2)
    monkeypatch.setattr(validator.dns, "lookup_mx", lambda _domain: MxLookup(error="timed out"))
    result = validator.validate("user@example.com")
    assert result.status == "unknown"
    assert result.stage == "dns"


def test_nxdomain_is_invalid(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    validator = EmailValidator(inspection=2)
    monkeypatch.setattr(validator.dns, "lookup_mx", lambda _domain: MxLookup(nxdomain=True))
    result = validator.validate("user@example.com")
    assert result.status == "invalid"
    assert result.reason == "domain does not exist"


def test_address_lookup_failure_is_unknown(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    validator = EmailValidator(inspection=2)
    monkeypatch.setattr(validator.dns, "lookup_mx", lambda _domain: MxLookup())
    monkeypatch.setattr(validator.dns, "has_address", lambda _domain: None)
    result = validator.validate("user@example.com")
    assert result.status == "unknown"
    assert result.reason == "DNS lookup failed"
