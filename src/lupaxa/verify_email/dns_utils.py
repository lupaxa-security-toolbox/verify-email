"""MX and address lookups, with dig and nslookup fallbacks."""

from __future__ import annotations

import socket
import subprocess
import sys
from dataclasses import dataclass, field

import dns.exception
import dns.resolver


def _host_from_exchange(raw: str) -> str | None:
    """Return an MX hostname, or None for a null MX (RFC 7505: exchange ``.``)."""
    host = raw.strip().rstrip(".")
    return host or None


def _dig_short_has_data(stdout: str) -> bool:
    """True when ``dig +short`` printed an answer rather than a comment or timeout."""
    for line in stdout.splitlines():
        line = line.strip()
        if line and not line.startswith(";"):
            return True
    return False


def _nslookup_shows_address(stdout: str) -> bool:
    """True only when nslookup printed a Name answer with an address.

    Exit status is not enough: macOS nslookup exits 0 on timeout, and the
    failure text is not the Windows phrase ``Non-existent domain``.
    """
    if "Name:" not in stdout:
        return False
    answer = stdout.split("Name:", 1)[1]
    for line in answer.splitlines():
        if "Address:" not in line and "Addresses:" not in line:
            continue
        value = line.split(":", 1)[1].strip().split("#", 1)[0].strip()
        if value:
            return True
    return False


def _parse_nslookup_mx_line(line: str) -> tuple[str, int] | None:
    """Parse one MX line from nslookup.

    BIND prints ``mail exchanger = 10 host.``. Windows prints
    ``preference = 10, mail exchanger = host``. Returns the raw exchange
    and preference. The exchange ``.`` is a null MX.
    """
    if "mail exchanger" not in line.lower():
        return None
    raw_tail = line.split("mail exchanger", 1)[1]
    if "=" not in raw_tail:
        return None
    parts = raw_tail.split("=", 1)[1].split()
    if not parts:
        return None
    token = parts[0].rstrip(",")
    if token.isdigit():
        if len(parts) < 2:
            return None
        return parts[1].rstrip(","), int(token)
    if "preference" not in line.lower() or "=" not in line:
        return None
    try:
        pref = int(line.split("preference", 1)[1].split("=", 1)[1].split(",")[0])
    except (IndexError, ValueError):
        return None
    return token, pref


def ascii_domain(domain: str) -> str:
    """Encode a domain as A-labels. A trailing dot is preserved."""
    absolute = domain.endswith(".")
    trimmed = domain[:-1] if absolute else domain
    encoded = trimmed.encode("idna").decode("ascii")
    if absolute:
        return encoded + "."
    return encoded


@dataclass
class MxLookup:
    """Outcome of an MX lookup. ``error`` is set when no resolver answered."""

    hosts: list[tuple[str, int]] = field(default_factory=list)
    null_mx: bool = False
    nxdomain: bool = False
    error: str = ""


class DNSResolver:
    """Resolve MX records, then fall back to A/AAAA when there is no MX."""

    def __init__(self, debug: bool = False, timeout: float = 5) -> None:
        self.debug = debug
        self.timeout = timeout

    def _dbg(self, msg: str) -> None:
        if self.debug:
            print(f"DEBUG >>> {msg}", file=sys.stderr)

    def _resolver(self) -> dns.resolver.Resolver:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = self.timeout
        resolver.timeout = self.timeout
        return resolver

    def _mx_dnspython(self, domain: str) -> MxLookup:
        records: list[tuple[str, int]] = []
        null_mx = False
        try:
            answer = self._resolver().resolve(domain, "MX")
            for record in answer:
                host = _host_from_exchange(str(record.exchange))
                if host is None:
                    null_mx = True
                    continue
                records.append((host, int(record.preference)))
            self._dbg(f"MX (dnspython) {domain}: {records} null={null_mx}")
        except dns.resolver.NXDOMAIN:
            return MxLookup(nxdomain=True)
        except dns.resolver.NoAnswer:
            return MxLookup()
        except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
            self._dbg(f"MX (dnspython) failed for {domain}: {exc}")
            return MxLookup(error=str(exc) or "DNS lookup failed")
        except Exception as exc:
            self._dbg(f"MX (dnspython) failed for {domain}: {exc}")
            return MxLookup(error=str(exc) or "DNS lookup failed")
        if null_mx:
            return MxLookup(null_mx=True)
        return MxLookup(hosts=records)

    def _run(self, args: list[str]) -> subprocess.CompletedProcess[str] | None:
        try:
            return subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except Exception as exc:
            self._dbg(f"{args[0]} failed: {exc}")
            return None

    def _mx_dig(self, domain: str) -> MxLookup:
        proc = self._run(["dig", "+short", "MX", domain])
        if proc is None or proc.returncode != 0:
            detail = "" if proc is None else proc.stdout.strip() or proc.stderr.strip()
            return MxLookup(error=detail or "dig MX lookup failed")
        records: list[tuple[str, int]] = []
        null_mx = False
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith(";"):
                continue
            parts = line.split()
            if len(parts) < 2 or not parts[0].isdigit():
                continue
            host = _host_from_exchange(parts[1])
            if host is None:
                null_mx = True
                continue
            records.append((host, int(parts[0])))
        if null_mx:
            return MxLookup(null_mx=True)
        return MxLookup(hosts=records)

    def _mx_nslookup(self, domain: str) -> MxLookup:
        proc = self._run(["nslookup", "-query=MX", domain])
        if proc is None:
            return MxLookup(error="nslookup MX lookup failed")
        text = proc.stdout
        lower = text.lower()
        if "timed out" in lower or "no servers could be reached" in lower:
            return MxLookup(error="nslookup timed out")
        records: list[tuple[str, int]] = []
        null_mx = False
        for line in text.splitlines():
            parsed = _parse_nslookup_mx_line(line)
            if parsed is None:
                continue
            raw, pref = parsed
            host = _host_from_exchange(raw)
            if host is None:
                null_mx = True
                continue
            records.append((host, pref))
        if null_mx:
            return MxLookup(null_mx=True)
        if records:
            return MxLookup(hosts=records)
        if "nxdomain" in lower or "non-existent domain" in lower:
            return MxLookup(nxdomain=True)
        if proc.returncode != 0:
            return MxLookup(error="nslookup MX lookup failed")
        return MxLookup()

    def lookup_mx(self, domain: str) -> MxLookup:
        """Return MX hosts, a null MX, NXDOMAIN, or an error if nobody answered.

        A successful empty answer stops the chain. Later tools are only used
        when the earlier lookup failed.
        """
        errors: list[str] = []
        for method in (self._mx_dnspython, self._mx_dig, self._mx_nslookup):
            found = method(domain)
            if found.null_mx:
                return MxLookup(null_mx=True)
            if found.hosts:
                hosts = sorted(found.hosts, key=lambda item: item[1])
                return MxLookup(hosts=hosts)
            if found.nxdomain:
                return MxLookup(nxdomain=True)
            if found.error:
                errors.append(found.error)
                continue
            return MxLookup()
        if errors:
            return MxLookup(error=errors[-1])
        return MxLookup()

    def get_mx(self, domain: str) -> list[tuple[str, int]]:
        """Return MX hosts as ``(hostname, preference)``, lowest preference first."""
        found = self.lookup_mx(domain)
        if found.null_mx or found.nxdomain or found.error:
            return []
        return list(found.hosts)

    def _address_dnspython(self, domain: str) -> bool | None:
        resolver = self._resolver()
        try:
            for rtype in ("A", "AAAA"):
                try:
                    resolver.resolve(domain, rtype)
                    self._dbg(f"{rtype} (dnspython) {domain}: found")
                    return True
                except dns.resolver.NoAnswer:
                    continue
                except dns.resolver.NXDOMAIN:
                    return False
        except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
            self._dbg(f"A (dnspython) failed for {domain}: {exc}")
            return None
        except Exception as exc:
            self._dbg(f"A (dnspython) failed for {domain}: {exc}")
            return None
        return False

    def _address_dig(self, domain: str) -> bool | None:
        saw_success = False
        saw_failure = False
        for rtype in ("A", "AAAA"):
            proc = self._run(["dig", "+short", rtype, domain])
            if proc is None or proc.returncode != 0:
                saw_failure = True
                continue
            saw_success = True
            if _dig_short_has_data(proc.stdout):
                self._dbg(f"{rtype} (dig) {domain}: {proc.stdout.strip()}")
                return True
        if saw_success and not saw_failure:
            return False
        return None

    def _address_nslookup(self, domain: str) -> bool | None:
        proc = self._run(["nslookup", domain])
        if proc is None:
            return None
        if _nslookup_shows_address(proc.stdout):
            self._dbg(f"A (nslookup) {domain}: appears resolvable")
            return True
        return None

    def _address_socket(self, domain: str) -> bool | None:
        try:
            socket.getaddrinfo(domain, None)
            self._dbg(f"A (socket) {domain}: found")
            return True
        except socket.gaierror as exc:
            text = str(exc).lower()
            if exc.errno == socket.EAI_NONAME or "not known" in text or "no address" in text:
                return False
            self._dbg(f"A (socket) {domain} failed: {exc}")
            return None
        except OSError as exc:
            self._dbg(f"A (socket) {domain} failed: {exc}")
            return None

    def has_address(self, domain: str) -> bool | None:
        """True when an address exists, False when it does not, None on lookup failure."""
        for probe in (self._address_dnspython, self._address_dig, self._address_nslookup):
            outcome = probe(domain)
            if outcome is not None:
                return outcome
        return self._address_socket(domain)
