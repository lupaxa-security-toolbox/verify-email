"""Package version metadata."""

from __future__ import annotations

from lupaxa.verify_email import version as version_mod
from lupaxa.verify_email.version import get_version


def test_version_is_semver_like() -> None:
    assert isinstance(version_mod.__version__, str)
    parts = version_mod.__version__.split(".")
    assert len(parts) >= 2
    assert all(part.isdigit() for part in parts[:2])


def test_get_version_matches_dunder() -> None:
    assert get_version() == version_mod.__version__
