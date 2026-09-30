"""SMTP reply classification."""

from __future__ import annotations

import ssl

import pytest

from lupaxa.verify_email.smtp_checker import SMTPChecker


def test_250_is_valid() -> None:
    status, _reason = SMTPChecker.interpret_rcpt_reply("250 2.1.5 Ok", strict_tempfail=True)
    assert status == "valid"


def test_550_is_invalid() -> None:
    status, _reason = SMTPChecker.interpret_rcpt_reply("550 user unknown", strict_tempfail=False)
    assert status == "invalid"


def test_protocol_block_is_unknown() -> None:
    status, _reason = SMTPChecker.interpret_rcpt_reply(
        "550 5.5.1 Protocol error",
        strict_tempfail=False,
    )
    assert status == "unknown"


def test_251_and_252_are_valid() -> None:
    forwarded, _reason = SMTPChecker.interpret_rcpt_reply(
        "251 user not local",
        strict_tempfail=True,
    )
    accepted, _reason = SMTPChecker.interpret_rcpt_reply(
        "252 cannot verify",
        strict_tempfail=True,
    )
    assert forwarded == "valid"
    assert accepted == "valid"


@pytest.mark.parametrize(
    ("reply", "status"),
    [
        ("550 5.1.1 user does not exist", "invalid"),
        ("551 user not local", "invalid"),
        ("553 mailbox name not allowed", "invalid"),
        ("550 5.7.1 relay access denied", "unknown"),
        ("554 5.7.1 service unavailable; client host blocked", "unknown"),
        ("554 transaction failed", "unknown"),
        ("530 5.7.0 authentication required", "unknown"),
        ("550 5.2.2 mailbox full", "valid"),
        ("421 try again later", "valid"),
    ],
)
def test_reply_classes(reply: str, status: str) -> None:
    found, reason = SMTPChecker.interpret_rcpt_reply(reply, strict_tempfail=False)
    assert found == status
    if "5.2.2" in reply:
        assert reason == "mailbox is full and cannot accept emails at this time"


def test_policy_word_inside_the_address_is_ignored() -> None:
    spam = "550 5.1.1 <spam-trap@example.com> user unknown"
    blocked = "550 5.1.1 <blocked.user@example.com> user unknown"
    still_policy = "550 5.7.1 <spam-trap@example.com> rejected as spam"
    assert SMTPChecker.interpret_rcpt_reply(spam, False, address="spam-trap@example.com")[0] == (
        "invalid"
    )
    assert (
        SMTPChecker.interpret_rcpt_reply(
            blocked,
            False,
            address="blocked.user@example.com",
        )[0]
        == "invalid"
    )
    assert (
        SMTPChecker.interpret_rcpt_reply(
            still_policy,
            False,
            address="spam-trap@example.com",
        )[0]
        == "unknown"
    )


def test_421_is_unknown_when_strict() -> None:
    status, _reason = SMTPChecker.interpret_rcpt_reply("421 try again later", strict_tempfail=True)
    assert status == "unknown"


def test_reply_waits_for_the_line_ending() -> None:
    assert SMTPChecker._reply_complete("250") is False
    assert SMTPChecker._reply_complete("250 ") is False
    assert SMTPChecker._reply_complete("250-hello\r\n") is False
    assert SMTPChecker._reply_complete("250\r\n") is True
    assert SMTPChecker._reply_complete("250 OK\r\n") is True
    assert SMTPChecker._reply_complete("250-hello\r\n250 OK\r\n") is True


def test_debug_goes_to_stderr(capsys) -> None:  # type: ignore[no-untyped-def]
    SMTPChecker(debug=True)._dbg("banner")
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "banner" in captured.err


def test_552_is_valid_because_the_mailbox_is_full() -> None:
    status, reason = SMTPChecker.interpret_rcpt_reply("552 mailbox full", strict_tempfail=True)
    assert status == "valid"
    assert reason == "mailbox is full and cannot accept emails at this time"


def test_tempfail_is_valid_unless_strict() -> None:
    reply = "450 mailbox busy"
    lenient, _reason = SMTPChecker.interpret_rcpt_reply(reply, strict_tempfail=False)
    strict, _reason = SMTPChecker.interpret_rcpt_reply(reply, strict_tempfail=True)
    assert lenient == "valid"
    assert strict == "unknown"


def test_connect_uses_the_configured_port(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    seen: dict[str, object] = {}

    def fake_create(address: tuple[str, int], timeout: float) -> None:
        seen["address"] = address
        seen["timeout"] = timeout
        raise OSError("stop")

    monkeypatch.setattr("lupaxa.verify_email.smtp_checker.socket.create_connection", fake_create)
    status, _reason = SMTPChecker(port=2525, timeout=3).check(
        "user@example.com",
        "me@example.com",
        ["mx.example"],
    )
    assert status == "unknown"
    assert seen["address"] == ("mx.example", 2525)


def test_port_out_of_range() -> None:
    with pytest.raises(ValueError):
        SMTPChecker(port=0)


class _FakeSock:
    def __init__(self, replies: list[bytes]) -> None:
        self._replies = list(replies)
        self.sent: list[bytes] = []

    def recv(self, _size: int) -> bytes:
        if not self._replies:
            return b""
        return self._replies.pop(0)

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def close(self) -> None:
        return None


def test_multiline_reply_is_read_before_the_next_command(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    sock = _FakeSock(
        [
            b"220 hi\r\n",
            b"250-mx.example\r\n",
            b"250 OK\r\n",
            b"250 sender ok\r\n",
            b"250 recipient ok\r\n",
            b"221 bye\r\n",
        ]
    )
    monkeypatch.setattr(
        "lupaxa.verify_email.smtp_checker.socket.create_connection",
        lambda *_args, **_kwargs: sock,
    )
    status, _reason = SMTPChecker().check("user@example.com", "me@example.com", ["mx.example"])
    assert status == "valid"
    commands = b"".join(sock.sent)
    assert b"MAIL FROM:<me@example.com>" in commands
    assert commands.index(b"EHLO ") < commands.index(b"MAIL FROM:")


def test_mail_from_rejection_tries_the_next_host(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    first = _FakeSock([b"220 hi\r\n", b"250 OK\r\n", b"550 sender refused\r\n"])
    second = _FakeSock(
        [
            b"220 hi\r\n",
            b"250 OK\r\n",
            b"250 sender ok\r\n",
            b"250 recipient ok\r\n",
            b"221 bye\r\n",
        ]
    )
    socks = [first, second]

    def connect(*_args: object, **_kwargs: object) -> _FakeSock:
        return socks.pop(0)

    monkeypatch.setattr("lupaxa.verify_email.smtp_checker.socket.create_connection", connect)
    status, _reason = SMTPChecker().check(
        "user@example.com",
        "me@example.com",
        ["mx1.example", "mx2.example"],
    )
    assert status == "valid"
    assert b"RCPT TO:" not in b"".join(first.sent)
    assert b"RCPT TO:<user@example.com>" in b"".join(second.sent)


def test_starttls_failure_does_not_send_mail(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    sock = _FakeSock(
        [
            b"220 hi\r\n",
            b"250-STARTTLS\r\n250 OK\r\n",
            b"220 ready\r\n",
        ]
    )
    monkeypatch.setattr(
        "lupaxa.verify_email.smtp_checker.socket.create_connection",
        lambda *_args, **_kwargs: sock,
    )

    def fail_wrap(self: ssl.SSLContext, *_args: object, **_kwargs: object) -> None:
        raise ssl.SSLError("name mismatch")

    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", fail_wrap)
    status, reason = SMTPChecker().check("user@example.com", "me@example.com", ["mx.example"])
    assert status == "unknown"
    assert b"MAIL FROM:" not in b"".join(sock.sent)
    assert "setup failed" in reason


def test_mail_from_tempfail_is_valid_unless_strict(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def connect(*_args: object, **_kwargs: object) -> _FakeSock:
        return _FakeSock([b"220 hi\r\n", b"250 OK\r\n", b"451 try later\r\n"])

    monkeypatch.setattr("lupaxa.verify_email.smtp_checker.socket.create_connection", connect)
    lenient, _reason = SMTPChecker().check(
        "user@example.com",
        "me@example.com",
        ["mx.example"],
        strict_tempfail=False,
    )
    strict, _strict_reason = SMTPChecker().check(
        "user@example.com",
        "me@example.com",
        ["mx.example"],
        strict_tempfail=True,
    )
    assert lenient == "valid"
    assert strict == "unknown"


def test_port_465_is_implicit_tls(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    sock = _FakeSock(
        [
            b"220 hi\r\n",
            b"250-STARTTLS\r\n250 OK\r\n",
            b"250 sender ok\r\n",
            b"250 recipient ok\r\n",
            b"221 bye\r\n",
        ]
    )
    order: list[str] = []
    seen: dict[str, object] = {}

    def connect(*_args: object, **_kwargs: object) -> _FakeSock:
        order.append("connect")
        return sock

    def wrap(self: ssl.SSLContext, raw: _FakeSock, server_hostname: str | None = None) -> _FakeSock:
        order.append("wrap")
        seen["verify"] = self.verify_mode
        seen["check_hostname"] = self.check_hostname
        seen["host"] = server_hostname
        return raw

    original_recv = sock.recv

    def recv(size: int) -> bytes:
        order.append("recv")
        return original_recv(size)

    sock.recv = recv  # type: ignore[method-assign]
    monkeypatch.setattr("lupaxa.verify_email.smtp_checker.socket.create_connection", connect)
    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", wrap)
    status, _reason = SMTPChecker(port=465).check(
        "user@example.com",
        "me@example.com",
        ["mx.example"],
    )
    assert status == "valid"
    assert order.index("wrap") < order.index("recv")
    assert seen["verify"] == ssl.CERT_NONE
    assert seen["check_hostname"] is False
    assert b"STARTTLS\r\n" not in b"".join(sock.sent)


def test_unicode_local_part_uses_smtputf8(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    sock = _FakeSock(
        [
            b"220 hi\r\n",
            b"250-SMTPUTF8\r\n250 OK\r\n",
            b"250 sender ok\r\n",
            b"250 recipient ok\r\n",
            b"221 bye\r\n",
        ]
    )
    monkeypatch.setattr(
        "lupaxa.verify_email.smtp_checker.socket.create_connection",
        lambda *_args, **_kwargs: sock,
    )
    status, _reason = SMTPChecker().check("üser@example.com", "me@example.com", ["mx.example"])
    sent = b"".join(sock.sent)
    assert status == "valid"
    assert "üser".encode() in sent
    assert b"SMTPUTF8" in sent


def test_unicode_local_part_without_smtputf8_is_unknown(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    sock = _FakeSock([b"220 hi\r\n", b"250 OK\r\n"])
    monkeypatch.setattr(
        "lupaxa.verify_email.smtp_checker.socket.create_connection",
        lambda *_args, **_kwargs: sock,
    )
    status, reason = SMTPChecker().check("üser@example.com", "me@example.com", ["mx.example"])
    assert status == "unknown"
    assert "SMTPUTF8" in reason
    assert b"RCPT TO:" not in b"".join(sock.sent)


def test_empty_host_list_is_unknown() -> None:
    status, reason = SMTPChecker().check("user@example.com", "me@example.com", [])
    assert status == "unknown"
    assert "No MX" in reason
