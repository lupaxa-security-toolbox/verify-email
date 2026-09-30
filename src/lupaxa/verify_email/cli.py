"""Command-line interface for email checks."""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections.abc import Iterable
from pathlib import Path

from .validator import EmailValidator, ValidationResult
from .version import get_version


def iter_emails_from_file(path: str) -> Iterable[str]:
    """Yield addresses from a text file, skipping blanks and ``#`` comments."""
    with open(path, encoding="utf-8-sig") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            yield line


def format_result(result: ValidationResult) -> str:
    """Render one result as the CLI text block."""
    hosts = ", ".join(result.mx_hosts or []) or "None"
    lines = [
        "=" * 60,
        f"Address:      {result.address}",
        f"Status:       {result.status.upper()}",
        f"Stage:        {result.stage}",
        f"Reason:       {result.reason}",
        f"Inspection:   {result.inspection}",
        f"From Address: {result.from_address}",
        f"Timeout:      {result.timeout}s",
        f"Port:         {result.port}",
        f"MX Hosts:     {hosts}",
        "=" * 60,
    ]
    return "\n".join(lines)


def render_results(results: list[ValidationResult], fmt: str) -> str:
    """Render results as text blocks or a JSON list."""
    if fmt == "json":
        payload = [
            {
                "address": item.address,
                "status": item.status,
                "stage": item.stage,
                "reason": item.reason,
                "inspection": item.inspection,
                "from_address": item.from_address,
                "timeout": item.timeout,
                "port": item.port,
                "mx_hosts": item.mx_hosts or [],
            }
            for item in results
        ]
        return json.dumps(payload, indent=2) + "\n"
    return "\n".join(format_result(item) for item in results) + "\n"


def _status_code(status: str) -> int:
    if status == "valid":
        return 0
    if status == "invalid":
        return 1
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Check whether an email address looks deliverable."
    )
    parser.add_argument("email", nargs="?", help="Address to check (omit when using --file)")
    parser.add_argument("--file", help="File containing one address per line")
    parser.add_argument(
        "--inspection",
        type=int,
        default=2,
        help="1=syntax, 2=DNS, 3=DNS+SMTP lenient, 4=DNS+SMTP strict",
    )
    parser.add_argument(
        "--from-address",
        default="",
        help="MAIL FROM address. Required for inspection levels 3 and 4",
    )
    parser.add_argument("--timeout", type=int, default=5, help="Network timeout in seconds")
    parser.add_argument(
        "--port",
        type=int,
        default=25,
        help="SMTP port (MX records have no port; 25 is the delivery default)",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="text blocks or a JSON list",
    )
    parser.add_argument("--output", help="Write results to this file instead of stdout")
    parser.add_argument(
        "--delay",
        type=float,
        default=None,
        help=(
            "Seconds between addresses in a file when SMTP runs. "
            "Default is 1 for levels 3 and 4, and 0 otherwise"
        ),
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print DNS and SMTP dialogue to stderr",
    )
    parser.add_argument("--version", action="version", version=get_version())
    return parser


def run_single(
    email: str | None,
    validator: EmailValidator,
) -> tuple[int, list[ValidationResult]]:
    if not email:
        print("No email supplied and no --file provided.", file=sys.stderr)
        return 1, []
    result = validator.validate(email)
    return _status_code(result.status), [result]


def run_bulk(
    path: str,
    validator: EmailValidator,
    delay: float = 0,
) -> tuple[int, list[ValidationResult]]:
    results: list[ValidationResult] = []
    saw_invalid = False
    saw_unknown = False
    try:
        emails = list(iter_emails_from_file(path))
    except (OSError, UnicodeError) as exc:
        print(f"Error reading input file '{path}': {exc}", file=sys.stderr)
        return 1, []
    if not emails:
        print(f"No email addresses in '{path}'.", file=sys.stderr)
        return 2, []
    for index, email in enumerate(emails):
        if index and delay > 0:
            time.sleep(delay)
        result = validator.validate(email)
        results.append(result)
        if result.status == "invalid":
            saw_invalid = True
        elif result.status == "unknown":
            saw_unknown = True
    if saw_invalid:
        return 1, results
    if saw_unknown:
        return 2, results
    return 0, results


def _emit(results: list[ValidationResult], fmt: str, output: str | None) -> int:
    if not results:
        return 0
    rendered = render_results(results, fmt)
    if output:
        try:
            Path(output).write_text(rendered, encoding="utf-8")
        except OSError as exc:
            print(f"Failed to write output file: {exc}", file=sys.stderr)
            return 2
        return 0
    sys.stdout.write(rendered)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        code = exc.code
        if code in (0, None):
            return 0
        if isinstance(code, int):
            return code
        return 2

    try:
        validator = EmailValidator(
            inspection=args.inspection,
            timeout=args.timeout,
            from_address=args.from_address,
            debug=args.debug,
            port=args.port,
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if args.delay is None:
        delay = 1.0 if args.inspection >= 3 else 0.0
    elif args.delay < 0:
        print("delay must be 0 or greater", file=sys.stderr)
        return 2
    else:
        delay = args.delay
    if args.file and args.email:
        print("Pass an address or --file, not both.", file=sys.stderr)
        return 2
    if args.file:
        code, results = run_bulk(args.file, validator, delay)
    else:
        code, results = run_single(args.email, validator)
    emit_code = _emit(results, args.format, args.output)
    if emit_code != 0:
        return emit_code
    return code
