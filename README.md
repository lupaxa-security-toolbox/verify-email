<p align="center">
  <a href="https://github.com/lupaxa-security-toolbox">
    <img src="https://raw.githubusercontent.com/the-lupaxa-project/brand-assets/master/logos/organisations/security-toolbox/readme-logo.png" alt="Security Toolbox" />
  </a>
</p>

<h1 align="center">Verify Email</h1>

Check whether an email address looks deliverable. The tool checks syntax,
then DNS (MX, with an A/AAAA fallback), and can optionally probe SMTP up to
`RCPT TO`. It never sends a message.

> **Warning:** **Authorised use only.** SMTP probing talks to someone else's
> mail server. Use it only on addresses and domains you are allowed to test.

## Install

Python 3.10 or newer. `dnspython` installs with the package.

```bash
pip install lupaxa-verify-email
verify-email --help
```

## CLI

```bash
verify-email user@example.com
verify-email user@example.com --inspection 4 --from-address probe@yourdomain.example
verify-email --file emails.txt --inspection 3 --from-address probe@yourdomain.example
verify-email user@example.com --format json --output results.json
python -m lupaxa.verify_email --version
```

`emails.txt` is one address per line. Blank lines and lines starting with `#`
are skipped. A leading UTF-8 BOM is ignored. A file with no addresses exits 2.
During SMTP checks the tool waits 1 second between addresses in a file.
`--delay 0` turns that pause off. `--delay` is 0 for syntax and DNS checks.

An MX record names a host and has no port. Inbound delivery uses port 25.
Pass `--port` when the server you want to probe is listening somewhere else.
Port 465 is implicit TLS. Any other port starts in cleartext and upgrades
when the server offers STARTTLS. The probe does not verify the certificate.
If the handshake fails, that host is skipped.

Unicode domains are looked up as A-labels. A Unicode local part is sent with
`SMTPUTF8` when the server advertises it. If the server does not, the result
is `unknown`.

`--from-address` is required for inspection levels 3 and 4. There is no
default sender. `RCPT TO` is only trusted after `MAIL FROM` returns 250.
A 4xx on `MAIL FROM` is treated like a 4xx on `RCPT TO`.
Pass an address or `--file`, not both. Inspection must be 1, 2, 3, or 4.
`--debug` writes the DNS and SMTP dialogue to stderr, so JSON on stdout stays
intact.

### CLI Flags

| Flag             | Default          | Description                                              |
| :--------------- | :--------------- | :------------------------------------------------------- |
| `--file`         | —                | File of addresses, one per line                          |
| `--inspection`   | `2`              | Depth: `1` syntax, `2` DNS, `3` SMTP lenient, `4` strict |
| `--from-address` | required for 3–4 | `MAIL FROM` address. Required when SMTP runs             |
| `--timeout`      | `5`              | DNS and SMTP timeout in seconds                          |
| `--port`         | `25`             | SMTP port. MX records do not carry one                   |
| `--format`       | `text`           | `text` blocks or a JSON list                             |
| `--output`       | stdout           | Write the chosen format to this file                     |
| `--delay`        | `1` or `0`       | Seconds between file addresses. `1` when SMTP runs       |
| `--debug`        | off              | Print DNS and SMTP dialogue to stderr                    |
| `--version`      | —                | Print the package version and exit                       |

### Exit Codes

| Code | Single address                        | File                                    |
| :--- | :------------------------------------ | :-------------------------------------- |
| 0    | `valid`                               | Every address is `valid`                |
| 1    | `invalid`, or no address was supplied | At least one address is `invalid`       |
| 2    | `unknown`, or bad usage               | No invalids, but at least one `unknown` |

Exit 1 is also used when the address file cannot be read, including a file
that is not UTF-8. Exit 2 is also used when the file has no addresses,
`--from-address` is
missing for an SMTP check, the inspection level is outside 1–4, an address
and `--file` are both set, `--delay` is negative, or the port or timeout is
unusable.

## Inspection Levels

| Level | What it checks                                   | `valid` means                                   |
| :---- | :----------------------------------------------- | :---------------------------------------------- |
| 1     | Address shape, local-part, and domain            | It looks like an email                          |
| 2     | Level 1, plus MX (or A/AAAA when there is no MX) | The domain can receive mail                     |
| 3     | Level 2, plus an SMTP probe                      | `RCPT` 250, 251, 252, or 552; 4xx counts as yes |
| 4     | Same probe as level 3                            | Same, but 4xx replies are `unknown`             |

Every run returns `valid`, `invalid`, or `unknown`. A null MX (`0 .`) or
`NXDOMAIN` is `invalid`. A DNS timeout or `SERVFAIL` is `unknown`, so a
resolver outage is not reported as a bad address.

`252` means the server will accept the message without confirming the
mailbox. Catch-all domains often answer that way, so levels 3 and 4 can
report them as `valid`.

## SMTP replies

The probe reads each reply until the final line, a status code followed by a
space rather than a hyphen, and that line has arrived in full. It tries the
next MX after a connection failure, a failed TLS handshake, a `MAIL FROM`
rejection, or an `unknown` `RCPT` reply.

| Reply                                                  | Result                                                    |
| :----------------------------------------------------- | :-------------------------------------------------------- |
| `250`, `251`, `252`                                    | `valid`                                                   |
| `552`, or enhanced status `5.2.2`                      | `valid`. The mailbox is full and cannot accept emails now |
| `421`, `450`, `451`, `452`, `454`, `455`               | `valid` at level 3, `unknown` at level 4                  |
| Other `4.x.x` enhanced status                          | Same as the 4xx row                                       |
| `550`, `551`, `553` for a missing mailbox              | `invalid`. Includes `5.1.1` and “user unknown”            |
| `550` or `554` with `5.7.x`, relay, policy, or a block | `unknown`                                                 |
| `554` with no mailbox detail                           | `unknown`                                                 |
| `500`–`504`, `521`, `530`, `535`                       | `unknown`                                                 |

`5.7.x` is a policy or security refusal. It says the server would not
complete the probe, which is different from a missing mailbox. The mailbox
echoed in the reply is ignored, so `spam-trap@example.com` is not treated as
a spam or block reply. A full
mailbox stays `valid` at both SMTP levels, and `result.ok` is true, with
the reason `mailbox is full and cannot accept emails at this time`.

## Library

```python
from lupaxa.verify_email import EmailValidator

validator = EmailValidator(
    inspection=3,
    from_address="probe@yourdomain.example",
)
result = validator.validate("user@example.com")
print(result.status, result.stage, result.reason)
```

`validate` always returns a `ValidationResult`. It does not raise for a bad
address.

| Field          | Type        | Meaning                                                  |
| :------------- | :---------- | :------------------------------------------------------- |
| `status`       | `str`       | `valid`, `invalid`, or `unknown`                         |
| `stage`        | `str`       | `basic`, `localpart`, `domain`, `syntax`, `dns`, `smtp`  |
| `reason`       | `str`       | Why that status was chosen                               |
| `inspection`   | `int`       | Level used (`1`–`4`)                                     |
| `address`      | `str`       | Address that was checked                                 |
| `from_address` | `str`       | `MAIL FROM` used for SMTP, or empty                      |
| `timeout`      | `int`       | Timeout in seconds                                       |
| `port`         | `int`       | SMTP port that was probed                                |
| `mx_hosts`     | `list[str]` | MX hosts tried, if DNS ran                               |

Some providers refuse mailbox probes. Those come back as `unknown`. A
catch-all domain can look `valid` at levels 3 and 4. A Unicode local part
is accepted at syntax and is probed only when the server offers `SMTPUTF8`.

## Development

```bash
make init
make python-install-dev
make python-check
```

<a href="https://github.com/the-lupaxa-project">
    <img src="https://raw.githubusercontent.com/the-lupaxa-project/brand-assets/master/logos/components/footer-for-child-orgs.svg" alt="The Lupaxa Project Footer" width="100%" />
</a>
