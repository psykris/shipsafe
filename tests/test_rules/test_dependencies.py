"""Tests for dependency safety rules (DEP101–DEP105)."""
from pathlib import Path

import pytest

from shipsafe.rules.dependencies import (
    ExtraIndexUrl,
    KnownTyposquatPackage,
    SetupPyUnpinnedRequires,
    UnpinnedDependency,
    WildcardVersionSpecifier,
)

VULN_DIR = Path(__file__).parent.parent / "fixtures" / "vulnerable" / "dependencies"
CLEAN_DIR = Path(__file__).parent.parent / "fixtures" / "clean" / "dependencies"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# ── DEP101 ────────────────────────────────────────────────────────────


class TestExtraIndexUrl:
    rule = ExtraIndexUrl()
    vuln = _read(VULN_DIR / "requirements_bad.txt")
    clean = _read(CLEAN_DIR / "requirements_good.txt")

    def test_true_positive(self):
        findings = self.rule.scan("requirements.txt", self.vuln)
        assert len(findings) >= 1

    def test_true_negative(self):
        findings = self.rule.scan("requirements.txt", self.clean)
        assert len(findings) == 0

    def test_detects_extra_index_url(self):
        code = "--extra-index-url https://my.index.example.com/simple/"
        findings = self.rule.scan("requirements.txt", code)
        assert len(findings) >= 1

    def test_detects_in_pip_command(self):
        code = "pip install --extra-index-url https://private.index.com/ mypackage"
        findings = self.rule.scan("install.sh", code)
        assert len(findings) >= 1

    def test_applies_to_requirements(self):
        assert self.rule.applies_to("requirements.txt") is True
        assert self.rule.applies_to("requirements-dev.txt") is True
        assert self.rule.applies_to("Dockerfile") is True

    def test_rule_id(self):
        assert self.rule.id == "DEP101"


# ── DEP102 ────────────────────────────────────────────────────────────


class TestUnpinnedDependency:
    rule = UnpinnedDependency()
    vuln = _read(VULN_DIR / "requirements_bad.txt")
    clean = _read(CLEAN_DIR / "requirements_good.txt")

    def test_true_positive(self):
        findings = self.rule.scan("requirements.txt", self.vuln)
        assert len(findings) >= 1

    def test_true_negative(self):
        findings = self.rule.scan("requirements.txt", self.clean)
        assert len(findings) == 0

    def test_bare_package_name(self):
        findings = self.rule.scan("requirements.txt", "flask\n")
        assert len(findings) >= 1

    def test_pinned_package_is_safe(self):
        findings = self.rule.scan("requirements.txt", "flask==3.0.2\n")
        assert len(findings) == 0

    def test_comment_line_ignored(self):
        findings = self.rule.scan("requirements.txt", "# flask\n")
        assert len(findings) == 0

    def test_applies_to_requirements_only(self):
        assert self.rule.applies_to("requirements.txt") is True
        assert self.rule.applies_to("requirements-prod.in") is True
        assert self.rule.applies_to("setup.py") is False
        assert self.rule.applies_to("app.py") is False

    def test_rule_id(self):
        assert self.rule.id == "DEP102"


# ── DEP103 ────────────────────────────────────────────────────────────


class TestWildcardVersionSpecifier:
    rule = WildcardVersionSpecifier()
    vuln = _read(VULN_DIR / "requirements_bad.txt")
    clean = _read(CLEAN_DIR / "requirements_good.txt")

    def test_true_positive(self):
        findings = self.rule.scan("requirements.txt", self.vuln)
        assert len(findings) >= 1

    def test_true_negative_pinned(self):
        findings = self.rule.scan("requirements.txt", "flask==3.0.2\n")
        assert len(findings) == 0

    def test_true_negative_bounded_range(self):
        # Has an upper bound — acceptable
        findings = self.rule.scan("requirements.txt", "requests>=2.28,<3\n")
        assert len(findings) == 0

    def test_detects_gte_without_upper_bound(self):
        findings = self.rule.scan("requirements.txt", "requests>=2.28.0\n")
        assert len(findings) >= 1

    def test_detects_tilde_specifier(self):
        findings = self.rule.scan("requirements.txt", "sqlalchemy~=2.0\n")
        assert len(findings) >= 1

    def test_applies_to_requirements_and_setup(self):
        assert self.rule.applies_to("requirements.txt") is True
        assert self.rule.applies_to("setup.py") is True
        assert self.rule.applies_to("pyproject.toml") is True
        assert self.rule.applies_to("app.py") is False

    def test_rule_id(self):
        assert self.rule.id == "DEP103"


# ── DEP104 ────────────────────────────────────────────────────────────


class TestSetupPyUnpinnedRequires:
    rule = SetupPyUnpinnedRequires()
    vuln = _read(VULN_DIR / "setup_bad.py")
    clean = _read(CLEAN_DIR / "setup_good.py")

    def test_true_positive(self):
        findings = self.rule.scan("setup.py", self.vuln)
        assert len(findings) >= 1

    def test_true_negative(self):
        findings = self.rule.scan("setup.py", self.clean)
        assert len(findings) == 0

    def test_detects_bare_install_requires(self):
        code = "install_requires=['flask', 'requests'],"
        findings = self.rule.scan("setup.py", code)
        assert len(findings) >= 1

    def test_rule_id(self):
        assert self.rule.id == "DEP104"


# ── DEP105 ────────────────────────────────────────────────────────────


class TestKnownTyposquatPackage:
    rule = KnownTyposquatPackage()
    vuln_req = _read(VULN_DIR / "requirements_bad.txt")
    vuln_py = _read(VULN_DIR / "typosquat_imports.py")
    clean_req = _read(CLEAN_DIR / "requirements_good.txt")
    clean_py = _read(CLEAN_DIR / "safe_imports.py")

    def test_true_positive_requirements(self):
        findings = self.rule.scan("requirements.txt", self.vuln_req)
        assert len(findings) >= 1

    def test_true_positive_python_import(self):
        findings = self.rule.scan("app.py", self.vuln_py)
        assert len(findings) >= 1

    def test_true_negative_requirements(self):
        findings = self.rule.scan("requirements.txt", self.clean_req)
        assert len(findings) == 0

    def test_true_negative_python(self):
        findings = self.rule.scan("app.py", self.clean_py)
        assert len(findings) == 0

    def test_detects_colourama(self):
        findings = self.rule.scan("requirements.txt", "colourama==1.0.0\n")
        assert len(findings) >= 1

    def test_detects_import_colourama(self):
        findings = self.rule.scan("app.py", "import colourama\n")
        assert len(findings) >= 1

    def test_applies_to_requirements_and_python(self):
        assert self.rule.applies_to("requirements.txt") is True
        assert self.rule.applies_to("setup.py") is True
        assert self.rule.applies_to("app.py") is True
        assert self.rule.applies_to("readme.md") is False

    def test_rule_id(self):
        assert self.rule.id == "DEP105"

    # Phase 7: legitimate alias allowlist — these should NOT fire
    def test_allowlist_pil(self):
        findings = self.rule.scan("requirements.txt", "PIL\n")
        assert len(findings) == 0

    def test_allowlist_cv2(self):
        findings = self.rule.scan("requirements.txt", "cv2\n")
        assert len(findings) == 0

    def test_allowlist_sklearn(self):
        findings = self.rule.scan("requirements.txt", "sklearn\n")
        assert len(findings) == 0

    def test_allowlist_bs4(self):
        findings = self.rule.scan("requirements.txt", "bs4\n")
        assert len(findings) == 0

    def test_allowlist_yaml(self):
        findings = self.rule.scan("requirements.txt", "yaml\n")
        assert len(findings) == 0

    def test_allowlist_dotenv(self):
        findings = self.rule.scan("requirements.txt", "dotenv\n")
        assert len(findings) == 0

    def test_allowlist_crypto(self):
        findings = self.rule.scan("requirements.txt", "Crypto\n")
        assert len(findings) == 0

    def test_allowlist_pil_import(self):
        findings = self.rule.scan("app.py", "from PIL import Image\n")
        assert len(findings) == 0

    def test_allowlist_sklearn_import(self):
        findings = self.rule.scan("ml.py", "import sklearn\n")
        assert len(findings) == 0

    # Phase 7: actual typosquats still fire
    def test_typosquat_requets_still_fires(self):
        findings = self.rule.scan("requirements.txt", "requets\n")
        assert len(findings) >= 1

    def test_typosquat_djago_still_fires(self):
        findings = self.rule.scan("requirements.txt", "djago\n")
        assert len(findings) >= 1

    def test_typosquat_flaask_still_fires(self):
        findings = self.rule.scan("requirements.txt", "flaask\n")
        assert len(findings) >= 1
