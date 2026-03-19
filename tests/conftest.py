"""Shared fixtures and helpers for ShipSafe tests."""

from pathlib import Path

import pytest

# Base path for all test fixtures
FIXTURES_DIR = Path(__file__).parent / "fixtures"


def fixture_path(category: str, filename: str) -> Path:
    """Resolve a fixture file path under tests/fixtures/{category}/{filename}.

    Args:
        category: Subdirectory within fixtures, e.g. "vulnerable/secrets".
        filename: Name of the fixture file.

    Returns:
        Absolute Path to the fixture file.
    """
    return FIXTURES_DIR / category / filename


def read_fixture(category: str, filename: str) -> str:
    """Read and return the text content of a fixture file.

    Args:
        category: Subdirectory within fixtures, e.g. "vulnerable/secrets".
        filename: Name of the fixture file.

    Returns:
        The file content as a string.
    """
    path = fixture_path(category, filename)
    return path.read_text(encoding="utf-8")


@pytest.fixture
def vulnerable_dir() -> Path:
    """Path to the tests/fixtures/vulnerable directory."""
    return FIXTURES_DIR / "vulnerable"


@pytest.fixture
def clean_dir() -> Path:
    """Path to the tests/fixtures/clean directory."""
    return FIXTURES_DIR / "clean"
