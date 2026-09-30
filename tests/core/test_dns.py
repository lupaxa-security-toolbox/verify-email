"""MX lookup order without live DNS."""

from __future__ import annotations

import subprocess

from lupaxa.verify_email.dns_utils import (
    DNSResolver,
    MxLookup,
    _dig_short_has_data,
    _host_from_exchange,
    _nslookup_shows_address,
    _parse_nslookup_mx_line,
)


def test_get_mx_sorts_by_preference(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    resolver = DNSResolver()
    monkeypatch.setattr(
        resolver,
        "_mx_dnspython",
        lambda _domain: MxLookup(hosts=[("second.example", 20), ("first.example", 5)]),
    )
    assert resolver.get_mx("example.com") == [("first.example", 5), ("second.example", 20)]


def test_get_mx_falls_through_when_dnspython_errors(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    resolver = DNSResolver()
    monkeypatch.setattr(resolver, "_mx_dnspython", lambda _domain: MxLookup(error="timed out"))
    monkeypatch.setattr(resolver, "_mx_dig", lambda _domain: MxLookup(hosts=[("mx.example", 10)]))
    monkeypatch.setattr(
        resolver,
        "_mx_nslookup",
        lambda _domain: MxLookup(hosts=[("unused.example", 1)]),
    )
    assert resolver.get_mx("example.com") == [("mx.example", 10)]


def test_empty_mx_does_not_fall_through(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    resolver = DNSResolver()
    monkeypatch.setattr(resolver, "_mx_dnspython", lambda _domain: MxLookup())
    monkeypatch.setattr(
        resolver,
        "_mx_dig",
        lambda _domain: MxLookup(hosts=[("should-not-use.example", 10)]),
    )
    monkeypatch.setattr(resolver, "_mx_nslookup", lambda _domain: MxLookup(nxdomain=True))
    found = resolver.lookup_mx("example.com")
    assert found.hosts == []
    assert found.nxdomain is False
    assert found.error == ""


def test_root_exchange_is_a_null_mx() -> None:
    assert _host_from_exchange(".") is None
    assert _host_from_exchange("mx.example.com.") == "mx.example.com"


def test_null_mx_does_not_fall_through(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    resolver = DNSResolver()
    monkeypatch.setattr(resolver, "_mx_dnspython", lambda _domain: MxLookup(null_mx=True))
    monkeypatch.setattr(
        resolver,
        "_mx_dig",
        lambda _domain: MxLookup(hosts=[("should-not-use.example", 1)]),
    )
    found = resolver.lookup_mx("example.com")
    assert found.null_mx is True
    assert found.hosts == []
    assert resolver.get_mx("example.com") == []


def test_nslookup_mx_line_formats() -> None:
    bind = _parse_nslookup_mx_line("example.com mail exchanger = 10 mx.example.com.")
    windows = _parse_nslookup_mx_line(
        "example.com MX preference = 5, mail exchanger = mx2.example.com"
    )
    assert bind == ("mx.example.com.", 10)
    assert windows == ("mx2.example.com", 5)


def test_nslookup_no_answer_is_not_nxdomain(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    resolver = DNSResolver()

    def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args,
            0,
            stdout="*** Can't find example.com: No answer\n",
            stderr="",
        )

    monkeypatch.setattr("lupaxa.verify_email.dns_utils.subprocess.run", fake_run)
    found = resolver._mx_nslookup("example.com")
    assert found.nxdomain is False
    assert found.hosts == []
    assert found.error == ""


def test_dig_aaaa_failure_is_not_a_definitive_miss(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    resolver = DNSResolver()

    def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        code = 9 if "AAAA" in args else 0
        return subprocess.CompletedProcess(args, code, stdout="", stderr="")

    monkeypatch.setattr("lupaxa.verify_email.dns_utils.subprocess.run", fake_run)
    assert resolver._address_dig("example.com") is None


def test_dig_empty_a_and_aaaa_is_a_miss(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    resolver = DNSResolver()

    def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr("lupaxa.verify_email.dns_utils.subprocess.run", fake_run)
    assert resolver._address_dig("example.com") is False


def test_dig_timeout_text_is_not_an_address() -> None:
    assert _dig_short_has_data(";; connection timed out; no servers could be reached\n") is False
    assert _dig_short_has_data("93.184.216.34\n") is True


def test_nslookup_timeout_is_not_an_address() -> None:
    timeout = ";; connection timed out; no servers could be reached\n"
    nxdomain = "** server can't find example.invalid: NXDOMAIN\n"
    answer = "Name:\texample.com\nAddress: 93.184.216.34\n"
    assert _nslookup_shows_address(timeout) is False
    assert _nslookup_shows_address(nxdomain) is False
    assert _nslookup_shows_address(answer) is True


def test_has_address_ignores_nslookup_timeout(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    resolver = DNSResolver()

    def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        if args[0] == "dig":
            return subprocess.CompletedProcess(
                args,
                9,
                stdout=";; connection timed out; no servers could be reached\n",
                stderr="",
            )
        return subprocess.CompletedProcess(
            args,
            0,
            stdout=";; connection timed out; no servers could be reached\n",
            stderr="",
        )

    def fail_socket(*_args: object, **_kwargs: object) -> None:
        raise OSError("no address")

    monkeypatch.setattr(resolver, "_address_dnspython", lambda _domain: None)
    monkeypatch.setattr("lupaxa.verify_email.dns_utils.subprocess.run", fake_run)
    monkeypatch.setattr("lupaxa.verify_email.dns_utils.socket.getaddrinfo", fail_socket)
    assert resolver.has_address("example.com") is None
