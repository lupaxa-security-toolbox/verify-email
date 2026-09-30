"""Package CLI wiring."""

from __future__ import annotations

import lupaxa.verify_email.cli as cli_mod
from lupaxa.verify_email.__main__ import main as module_main


def test_dunder_main_is_cli_main() -> None:
    assert module_main is cli_mod.main
