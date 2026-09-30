"""CLI entrypoint."""

from __future__ import annotations

import json
from pathlib import Path

from lupaxa.verify_email.cli import main
from lupaxa.verify_email.validator import ValidationResult
from lupaxa.verify_email.version import get_version


def _result(status: str, address: str = "user@example.com") -> ValidationResult:
    return ValidationResult(
        status=status,
        stage="dns",
        reason="domain resolvable",
        inspection=2,
        address=address,
        from_address="validator@example.com",
        timeout=5,
        mx_hosts=["mx.example.com"],
    )


def test_help_exits_zero() -> None:
    assert main(["--help"]) == 0


def test_version_flag(capsys) -> None:  # type: ignore[no-untyped-def]
    assert main(["--version"]) == 0
    assert get_version() in capsys.readouterr().out


def test_missing_address_exits_one(capsys) -> None:  # type: ignore[no-untyped-def]
    assert main([]) == 1
    assert "No email supplied" in capsys.readouterr().err


def test_valid_address_exits_zero(capsys, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(
        "lupaxa.verify_email.cli.EmailValidator.validate",
        lambda _self, _email: _result("valid"),
    )
    assert main(["user@example.com"]) == 0
    out = capsys.readouterr().out
    assert "Status:       VALID" in out
    assert "user@example.com" in out


def test_invalid_address_exits_one(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(
        "lupaxa.verify_email.cli.EmailValidator.validate",
        lambda _self, _email: _result("invalid"),
    )
    assert main(["user@example.com"]) == 1


def test_unknown_address_exits_two(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(
        "lupaxa.verify_email.cli.EmailValidator.validate",
        lambda _self, _email: _result("unknown"),
    )
    assert main(["user@example.com"]) == 2


def test_file_reports_the_worst_status(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    listing = tmp_path / "emails.txt"
    listing.write_text("# comment\n\na@example.com\nb@example.com\n", encoding="utf-8")
    statuses = iter(("valid", "unknown"))
    monkeypatch.setattr(
        "lupaxa.verify_email.cli.EmailValidator.validate",
        lambda _self, email: _result(next(statuses), email),
    )
    assert main(["--file", str(listing)]) == 2


def test_port_flag_is_passed(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    captured: dict[str, object] = {}

    def factory(**kwargs: object) -> object:
        captured.update(kwargs)

        class _Validator:
            def validate(self, email: str) -> ValidationResult:
                return _result("valid", email)

        return _Validator()

    monkeypatch.setattr("lupaxa.verify_email.cli.EmailValidator", factory)
    assert main(["user@example.com", "--port", "2525"]) == 0
    assert captured["port"] == 2525


def test_port_out_of_range_exits_two(capsys) -> None:  # type: ignore[no-untyped-def]
    assert main(["user@example.com", "--port", "0"]) == 2
    assert "port" in capsys.readouterr().err


def test_bom_is_stripped_from_the_file(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    listing = tmp_path / "emails.txt"
    listing.write_bytes("\ufeffuser@example.com\n".encode("utf-8"))
    seen: list[str] = []

    def validate(_self: object, email: str) -> ValidationResult:
        seen.append(email)
        return _result("valid", email)

    monkeypatch.setattr("lupaxa.verify_email.cli.EmailValidator.validate", validate)
    assert main(["--file", str(listing)]) == 0
    assert seen == ["user@example.com"]


def test_smtp_file_pauses_between_addresses(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    listing = tmp_path / "emails.txt"
    listing.write_text("a@example.com\nb@example.com\n", encoding="utf-8")
    pauses: list[float] = []
    monkeypatch.setattr(
        "lupaxa.verify_email.cli.time.sleep",
        lambda seconds: pauses.append(seconds),
    )
    monkeypatch.setattr(
        "lupaxa.verify_email.cli.EmailValidator.validate",
        lambda _self, email: _result("valid", email),
    )
    assert (
        main(
            [
                "--file",
                str(listing),
                "--inspection",
                "3",
                "--from-address",
                "me@example.com",
            ]
        )
        == 0
    )
    assert pauses == [1.0]


def test_delay_zero_skips_the_pause(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    listing = tmp_path / "emails.txt"
    listing.write_text("a@example.com\nb@example.com\n", encoding="utf-8")
    pauses: list[float] = []
    monkeypatch.setattr(
        "lupaxa.verify_email.cli.time.sleep",
        lambda seconds: pauses.append(seconds),
    )
    monkeypatch.setattr(
        "lupaxa.verify_email.cli.EmailValidator.validate",
        lambda _self, email: _result("valid", email),
    )
    assert (
        main(
            [
                "--file",
                str(listing),
                "--inspection",
                "3",
                "--from-address",
                "me@example.com",
                "--delay",
                "0",
            ]
        )
        == 0
    )
    assert pauses == []


def test_non_utf8_file_exits_one(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    listing = tmp_path / "emails.txt"
    listing.write_bytes(b"caf\xe9@example.com\n")
    assert main(["--file", str(listing)]) == 1
    assert "Error reading input file" in capsys.readouterr().err


def test_empty_file_exits_two(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    listing = tmp_path / "emails.txt"
    listing.write_text("# only a comment\n\n", encoding="utf-8")
    assert main(["--file", str(listing)]) == 2
    assert "No email addresses" in capsys.readouterr().err


def test_inspection_out_of_range_exits_two(capsys) -> None:  # type: ignore[no-untyped-def]
    assert main(["user@example.com", "--inspection", "9"]) == 2
    assert "inspection" in capsys.readouterr().err


def test_address_and_file_together_exit_two(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    listing = tmp_path / "emails.txt"
    listing.write_text("user@example.com\n", encoding="utf-8")
    assert main(["user@example.com", "--file", str(listing)]) == 2
    assert "not both" in capsys.readouterr().err


def test_smtp_inspection_requires_from_address(capsys) -> None:  # type: ignore[no-untyped-def]
    assert main(["user@example.com", "--inspection", "3"]) == 2
    assert "from_address" in capsys.readouterr().err


def test_json_format(capsys, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(
        "lupaxa.verify_email.cli.EmailValidator.validate",
        lambda _self, email: _result("valid", email),
    )
    assert main(["user@example.com", "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload[0]["status"] == "valid"
    assert payload[0]["address"] == "user@example.com"


def test_output_file_skips_stdout(tmp_path: Path, capsys, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(
        "lupaxa.verify_email.cli.EmailValidator.validate",
        lambda _self, email: _result("valid", email),
    )
    destination = tmp_path / "out.json"
    assert main(["user@example.com", "--format", "json", "--output", str(destination)]) == 0
    assert capsys.readouterr().out == ""
    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert payload[0]["status"] == "valid"


def test_file_with_an_invalid_exits_one(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    listing = tmp_path / "emails.txt"
    listing.write_text("a@example.com\nb@example.com\n", encoding="utf-8")
    statuses = iter(("valid", "invalid"))
    monkeypatch.setattr(
        "lupaxa.verify_email.cli.EmailValidator.validate",
        lambda _self, email: _result(next(statuses), email),
    )
    assert main(["--file", str(listing)]) == 1
