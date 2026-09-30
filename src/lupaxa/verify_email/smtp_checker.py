"""SMTP probe up to RCPT TO. Never sends a message."""

from __future__ import annotations

import contextlib
import re
import socket
import ssl
import sys

_FINAL_LINE = re.compile(r"^\d{3}(?: |$)")
_ENHANCED = re.compile(r"\b([245])\.(\d{1,3})\.(\d{1,3})\b")
MAILBOX_FULL = "mailbox is full and cannot accept emails at this time"
_TEMPFAIL_CODES = {"421", "450", "451", "452", "454", "455"}
_INCONCLUSIVE_CODES = {"500", "501", "502", "503", "504", "521", "530", "535", "538"}
_MISSING_ENHANCED = {"5.1.1", "5.1.2", "5.1.3", "5.1.6", "5.1.10", "5.2.1"}
_POLICY_WORDS = (
    "protocol",
    "relay",
    "relaying",
    "blocked",
    "block list",
    "blocklist",
    "blacklist",
    "spam",
    "policy",
    "not authorized",
    "unauthorised",
    "unauthorized",
    "authentication",
    "access denied",
    "service unavailable",
    "client host",
    "administratively",
    "prohibited",
)
_MISSING_PHRASES = (
    "user unknown",
    "unknown user",
    "no such user",
    "no such recipient",
    "recipient unknown",
    "mailbox unavailable",
    "mailbox not found",
    "does not exist",
    "doesn't exist",
    "user not found",
    "invalid recipient",
    "recipient address rejected",
)


def require_port(port: int) -> int:
    """Return ``port`` when it is a TCP port, otherwise raise ``ValueError``."""
    value = int(port)
    if not 1 <= value <= 65535:
        raise ValueError("port must be between 1 and 65535")
    return value


def require_timeout(timeout: int) -> int:
    """Return ``timeout`` when it is a positive number of seconds."""
    value = int(timeout)
    if value <= 0:
        raise ValueError("timeout must be greater than 0")
    return value


def smtp_code(reply: str) -> str:
    """Return the final SMTP status code in a reply."""
    lines = [line.strip() for line in reply.splitlines() if line.strip()]
    if not lines:
        return ""
    last = lines[-1]
    if len(last) >= 3 and last[:3].isdigit():
        return last[:3]
    return ""


def smtp_mailbox(address: str) -> str:
    """Return ``local@domain`` with the domain encoded as A-labels.

    A Unicode local part is kept. The SMTP conversation then uses SMTPUTF8.
    """
    local, domain = address.split("@", 1)
    encoded = domain.encode("idna").decode("ascii").rstrip(".")
    return f"{local}@{encoded}"


def needs_smtputf8(*addresses: str) -> bool:
    """True when a local part contains a non-ASCII character."""
    for address in addresses:
        local = address.split("@", 1)[0]
        if any(ord(char) > 127 for char in local):
            return True
    return False


def _enhanced_status(reply: str) -> str:
    match = _ENHANCED.search(reply)
    if match is None:
        return ""
    return f"{match.group(1)}.{match.group(2)}.{match.group(3)}"


def _is_tempfail(code: str, reply: str) -> bool:
    if code in _TEMPFAIL_CODES:
        return True
    return _enhanced_status(reply).startswith("4.")


def _mask_mailbox(reply: str, address: str) -> str:
    """Remove an echoed mailbox so its local part cannot look like a policy word.

    ``spam-trap@example.com`` contains ``spam``. The full address is always
    removed. A local part is removed only when it contains a separator, so a
    real policy word such as ``spam`` in the reply text is kept.
    """
    if "@" not in address:
        return reply
    local = address.split("@", 1)[0]
    text = re.sub(re.escape(address), " ", reply, flags=re.IGNORECASE)
    if local and re.search(r"[^A-Za-z]", local):
        text = re.sub(re.escape(local), " ", text, flags=re.IGNORECASE)
    return text


def _contains_term(text: str, term: str) -> bool:
    """True when ``term`` appears outside a longer letter-or-digit token."""
    pattern = r"(?<![A-Za-z0-9])" + re.escape(term) + r"(?![A-Za-z0-9])"
    return re.search(pattern, text, flags=re.IGNORECASE) is not None


def _is_policy(reply: str) -> bool:
    parts = _enhanced_status(reply).split(".")
    if len(parts) == 3 and parts[1] == "7":
        return True
    return any(_contains_term(reply, word) for word in _POLICY_WORDS)


def _is_missing_mailbox(reply: str) -> bool:
    if _enhanced_status(reply) in _MISSING_ENHANCED:
        return True
    return any(_contains_term(reply, phrase) for phrase in _MISSING_PHRASES)


class SMTPChecker:
    """Talk to an MX host only far enough to classify a recipient."""

    def __init__(self, timeout: int = 5, debug: bool = False, port: int = 25) -> None:
        self.timeout = require_timeout(timeout)
        self.debug = debug
        self.port = require_port(port)

    def _dbg(self, msg: str) -> None:
        if self.debug:
            print(f"DEBUG >>> {msg}", file=sys.stderr)

    def _close(self, sock: socket.socket | None) -> None:
        if sock is None:
            return
        with contextlib.suppress(OSError):
            sock.close()

    def _tls_context(self) -> ssl.SSLContext:
        """TLS for a probe. Certificate names are not checked.

        MX hostnames often do not match the certificate. A failed handshake
        still abandons the host; the probe does not continue in cleartext.
        """
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context

    def _wrap_tls(self, sock: socket.socket, host: str) -> ssl.SSLSocket:
        return self._tls_context().wrap_socket(sock, server_hostname=host)

    def _recv_reply(self, sock: socket.socket) -> str:
        chunks: list[str] = []
        size = 0
        while size < 65536:
            data = sock.recv(4096)
            if not data:
                break
            text = data.decode(errors="ignore")
            chunks.append(text)
            size += len(text)
            if self._reply_complete("".join(chunks)):
                break
        reply = "".join(chunks)
        self._dbg(reply)
        return reply

    @staticmethod
    def _reply_complete(blob: str) -> bool:
        """True when the last reply line has arrived in full.

        A line counts only after its CRLF. ``250`` or ``250 `` with no line
        ending is still incomplete, and ``250-`` is a continuation.
        """
        if not blob.endswith(("\n", "\r")):
            return False
        lines = [line.strip() for line in blob.splitlines() if line.strip()]
        if not lines:
            return False
        return _FINAL_LINE.match(lines[-1]) is not None

    def _connect(self, host: str) -> tuple[socket.socket, str]:
        sock = socket.create_connection((host, self.port), timeout=self.timeout)
        active: socket.socket = sock
        try:
            if self.port == 465:
                active = self._wrap_tls(sock, host)
            banner = self._recv_reply(active)
        except Exception:
            self._close(active)
            if active is not sock:
                self._close(sock)
            raise
        return active, banner

    def _send(self, sock: socket.socket, msg: str, *, utf8: bool = False) -> str:
        try:
            payload = (msg + "\r\n").encode("utf-8" if utf8 else "ascii")
        except UnicodeEncodeError:
            return "000 address is not ASCII SMTP"
        try:
            sock.sendall(payload)
            self._dbg(msg)
            return self._recv_reply(sock)
        except OSError as exc:
            self._dbg(f"SMTP send/recv error: {exc}")
            return f"000 {exc}"

    @staticmethod
    def _parse_caps(ehlo_reply: str) -> list[str]:
        caps: list[str] = []
        for line in ehlo_reply.splitlines():
            line = line.strip()
            if line.startswith("250-") or line.startswith("250 "):
                caps.append(line[4:].strip().upper())
        return caps

    def _ehlo_and_maybe_starttls(
        self,
        sock: socket.socket,
        host: str,
        helo_domain: str,
    ) -> tuple[socket.socket, list[str]] | None:
        ehlo_reply = self._send(sock, f"EHLO {helo_domain}")
        if smtp_code(ehlo_reply) != "250":
            return None
        caps = self._parse_caps(ehlo_reply)
        if self.port == 465 or not any("STARTTLS" in cap for cap in caps):
            return sock, caps

        self._dbg("STARTTLS offered, upgrading connection")
        starttls_reply = self._send(sock, "STARTTLS")
        if smtp_code(starttls_reply) != "220":
            return None
        try:
            tls_sock = self._wrap_tls(sock, host)
        except ssl.SSLError as exc:
            self._dbg(f"TLS negotiation failed: {exc}")
            return None
        tls_ehlo = self._send(tls_sock, f"EHLO {helo_domain}")
        if smtp_code(tls_ehlo) != "250":
            self._close(tls_sock)
            return None
        return tls_sock, self._parse_caps(tls_ehlo)

    @staticmethod
    def interpret_rcpt_reply(
        reply: str,
        strict_tempfail: bool,
        address: str = "",
        wire_address: str = "",
    ) -> tuple[str, str]:
        """Map an SMTP reply to ``valid``, ``invalid``, or ``unknown``.

        ``address`` and ``wire_address`` are removed before policy words are
        matched, so a local part such as ``spam-trap`` is not a spam block.
        """
        code = smtp_code(reply)
        reason = reply.strip()
        enhanced = _enhanced_status(reply)
        judged = _mask_mailbox(_mask_mailbox(reply, address), wire_address)

        if code == "552" or enhanced == "5.2.2":
            return "valid", MAILBOX_FULL
        if code in ("250", "251", "252"):
            return "valid", reason
        if _is_tempfail(code, reply):
            if strict_tempfail:
                return "unknown", reason
            return "valid", reason
        if code in _INCONCLUSIVE_CODES:
            return "unknown", reason
        if code in ("550", "551", "553", "554"):
            if _is_policy(judged):
                return "unknown", reason
            if code == "554" and not _is_missing_mailbox(judged):
                return "unknown", reason
            return "invalid", reason
        return "unknown", reason

    def check(
        self,
        recipient: str,
        sender: str,
        mx_hosts: list[str],
        strict_tempfail: bool = False,
    ) -> tuple[str, str]:
        """Probe MX hosts in order. Stop on the first decisive reply."""
        if not mx_hosts:
            return "unknown", "No MX hosts available"

        try:
            sender_wire = smtp_mailbox(sender)
            recipient_wire = smtp_mailbox(recipient)
        except UnicodeError:
            return "unknown", "address is not ASCII SMTP"
        utf8 = needs_smtputf8(sender, recipient)
        helo_domain = sender_wire.split("@", 1)[-1]

        last_reason = "No successful SMTP connections"
        tempfail_reason = ""
        for host in mx_hosts:
            sock: socket.socket | None = None
            try:
                self._dbg(f"SMTP: connecting to {host}:{self.port}")
                sock, banner = self._connect(host)
                if smtp_code(banner) != "220":
                    last_reason = banner.strip() or "SMTP banner was not 220"
                    continue

                prepared = self._ehlo_and_maybe_starttls(sock, host, helo_domain)
                if prepared is None:
                    last_reason = f"SMTP setup failed for {host}"
                    continue
                active, caps = prepared
                if active is not sock:
                    sock = active
                if utf8 and not any(cap.split()[0] == "SMTPUTF8" for cap in caps):
                    last_reason = f"{host} does not support SMTPUTF8"
                    continue

                mail_from = f"MAIL FROM:<{sender_wire}>"
                if utf8:
                    mail_from += " SMTPUTF8"
                mail_reply = self._send(sock, mail_from, utf8=utf8)
                if _is_tempfail(smtp_code(mail_reply), mail_reply):
                    tempfail_reason = mail_reply.strip() or "MAIL FROM was deferred"
                    continue
                if smtp_code(mail_reply) != "250":
                    last_reason = mail_reply.strip() or "MAIL FROM was rejected"
                    continue

                reply = self._send(sock, f"RCPT TO:<{recipient_wire}>", utf8=utf8)
                status, reason = self.interpret_rcpt_reply(
                    reply,
                    strict_tempfail,
                    address=recipient,
                    wire_address=recipient_wire,
                )
                self._send(sock, "QUIT")
                if status != "unknown":
                    return status, reason
                last_reason = reason
            except OSError as exc:
                self._dbg(f"SMTP: error with {host}: {exc}")
                last_reason = f"SMTP connection to {host} failed: {exc}"
            finally:
                self._close(sock)

        if tempfail_reason:
            if strict_tempfail:
                return "unknown", tempfail_reason
            return "valid", tempfail_reason
        return "unknown", last_reason
