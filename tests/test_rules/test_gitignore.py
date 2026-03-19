"""Tests for the gitignore rules (src/shipsafe/rules/gitignore.py).

These rules check .gitignore content for required entries and detect committed
.env files. Tests use a mix of inline content and fixture files.
"""

from pathlib import Path

import pytest

from shipsafe.rules.gitignore import (
    MissingEnvInGitignore,
    MissingNodeModulesInGitignore,
    MissingPycacheInGitignore,
    MissingDSStoreInGitignore,
    CommittedEnvFile,
)

FIXTURES = Path(__file__).parent.parent / "fixtures"
CLEAN_GITIGNORE = FIXTURES / "clean" / "gitignore_project"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# The clean .gitignore fixture contains: .env, node_modules/, __pycache__/, .DS_Store
CLEAN_GITIGNORE_CONTENT = _read(CLEAN_GITIGNORE / ".gitignore")


# ── Inline content for targeted tests ────────────────────────────────

GITIGNORE_MISSING_ENV = """\
node_modules/
__pycache__/
.DS_Store
dist/
"""

GITIGNORE_WITH_ENV = """\
.env
node_modules/
__pycache__/
.DS_Store
"""

GITIGNORE_MISSING_NODE_MODULES = """\
.env
__pycache__/
.DS_Store
"""

GITIGNORE_MISSING_PYCACHE = """\
.env
node_modules/
.DS_Store
"""

GITIGNORE_MISSING_DS_STORE = """\
.env
node_modules/
__pycache__/
"""

ENV_FILE_WITH_SECRETS = """\
OPENAI_API_KEY=sk-proj-testkey123
DATABASE_URL=postgres://user:pass@localhost/db
SECRET_KEY=mysecretkey
"""

ENV_FILE_NO_EQUALS = """\
# This is just a comment file
No secrets here
Just some text
"""


# ── GIT002: MissingEnvInGitignore ────────────────────────────────────


class TestMissingEnvInGitignore:
    rule = MissingEnvInGitignore()

    def test_true_positive_missing_env(self):
        """A .gitignore missing .env should trigger a finding."""
        findings = self.rule.scan(".gitignore", GITIGNORE_MISSING_ENV)
        assert len(findings) >= 1

    def test_true_negative_has_env(self):
        """A .gitignore containing .env should not trigger."""
        findings = self.rule.scan(".gitignore", GITIGNORE_WITH_ENV)
        assert len(findings) == 0

    def test_true_negative_clean_fixture(self):
        """The clean fixture .gitignore includes .env and should not trigger."""
        findings = self.rule.scan(".gitignore", CLEAN_GITIGNORE_CONTENT)
        assert len(findings) == 0


# ── GIT003: MissingNodeModulesInGitignore ────────────────────────────


class TestMissingNodeModulesInGitignore:
    rule = MissingNodeModulesInGitignore()

    def test_true_positive(self):
        """A .gitignore missing node_modules should trigger."""
        findings = self.rule.scan(".gitignore", GITIGNORE_MISSING_NODE_MODULES)
        assert len(findings) >= 1

    def test_true_negative(self):
        """The clean fixture .gitignore includes node_modules/ and should not trigger."""
        findings = self.rule.scan(".gitignore", CLEAN_GITIGNORE_CONTENT)
        assert len(findings) == 0


# ── GIT004: MissingPycacheInGitignore ────────────────────────────────


class TestMissingPycacheInGitignore:
    rule = MissingPycacheInGitignore()

    def test_true_positive(self):
        """A .gitignore missing __pycache__ should trigger."""
        findings = self.rule.scan(".gitignore", GITIGNORE_MISSING_PYCACHE)
        assert len(findings) >= 1

    def test_true_negative(self):
        """The clean fixture .gitignore includes __pycache__/ and should not trigger."""
        findings = self.rule.scan(".gitignore", CLEAN_GITIGNORE_CONTENT)
        assert len(findings) == 0


# ── GIT005: MissingDSStoreInGitignore ────────────────────────────────


class TestMissingDSStoreInGitignore:
    rule = MissingDSStoreInGitignore()

    def test_true_positive(self):
        """A .gitignore missing .DS_Store should trigger."""
        findings = self.rule.scan(".gitignore", GITIGNORE_MISSING_DS_STORE)
        assert len(findings) >= 1

    def test_true_negative(self):
        """The clean fixture .gitignore includes .DS_Store and should not trigger."""
        findings = self.rule.scan(".gitignore", CLEAN_GITIGNORE_CONTENT)
        assert len(findings) == 0


# ── GIT006: CommittedEnvFile ─────────────────────────────────────────


class TestCommittedEnvFile:
    rule = CommittedEnvFile()

    def test_true_positive_env_with_secrets(self):
        """An .env file containing key=value pairs should trigger."""
        findings = self.rule.scan(".env", ENV_FILE_WITH_SECRETS)
        assert len(findings) >= 1

    def test_true_negative_env_no_equals(self):
        """An .env file with no = signs should not trigger."""
        findings = self.rule.scan(".env", ENV_FILE_NO_EQUALS)
        assert len(findings) == 0

    def test_true_positive_with_fixture(self):
        """The vulnerable env_file.env fixture should trigger."""
        env_content = _read(FIXTURES / "vulnerable" / "secrets" / "env_file.env")
        findings = self.rule.scan(".env", env_content)
        assert len(findings) >= 1

    def test_non_env_file_ignored(self):
        """A non-.env file should not trigger even with = signs."""
        findings = self.rule.scan("config.py", ENV_FILE_WITH_SECRETS)
        assert len(findings) == 0
