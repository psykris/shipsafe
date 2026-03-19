"""Tests for the 6 deployment security rules (src/shipsafe/rules/deployment.py).

Each rule is tested for:
    - True positive: scanning vulnerable fixture produces >= 1 finding.
    - True negative: scanning clean fixture produces 0 findings.
"""

from pathlib import Path

from shipsafe.rules.deployment import (
    DockerfileRunningAsRoot,
    ExposedDebugAdminRoutes,
    BuildSecretsInDockerfile,
    BindingToAllInterfaces,
    ExposedSourceMaps,
    InsecureSecurityHeaders,
)

FIXTURES = Path(__file__).parent.parent / "fixtures"
VULN_DEP = FIXTURES / "vulnerable" / "deployment"
CLEAN_DEP = FIXTURES / "clean" / "deployment"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# ── DEP001: DockerfileRunningAsRoot ──────────────────────────────────

class TestDockerfileRunningAsRoot:
    rule = DockerfileRunningAsRoot()
    vuln = _read(VULN_DEP / "Dockerfile")
    safe = _read(CLEAN_DEP / "Dockerfile.safe")

    def test_true_positive(self):
        # Must pass "Dockerfile" as the path so _is_dockerfile() returns True
        findings = self.rule.scan("Dockerfile", self.vuln)
        assert len(findings) >= 1

    def test_true_negative(self):
        # Dockerfile.safe contains a USER directive
        findings = self.rule.scan("Dockerfile.safe", self.safe)
        assert len(findings) == 0

    def test_ignores_non_dockerfile(self):
        # Rule should not apply to .py files
        findings = self.rule.scan("app.py", self.vuln)
        assert len(findings) == 0


# ── DEP002: ExposedDebugAdminRoutes ──────────────────────────────────

class TestExposedDebugAdminRoutes:
    rule = ExposedDebugAdminRoutes()
    vuln = _read(VULN_DEP / "debug_routes.py")
    safe = _read(CLEAN_DEP / "safe_routes.py")

    def test_true_positive(self):
        findings = self.rule.scan("debug_routes.py", self.vuln)
        assert len(findings) >= 1

    def test_true_negative(self):
        # safe_routes.py uses /api/users, not /admin or /debug
        findings = self.rule.scan("safe_routes.py", self.safe)
        assert len(findings) == 0


# ── DEP003: BuildSecretsInDockerfile ─────────────────────────────────

class TestBuildSecretsInDockerfile:
    rule = BuildSecretsInDockerfile()
    vuln = _read(VULN_DEP / "Dockerfile.secrets")
    safe = _read(CLEAN_DEP / "Dockerfile.safe")

    def test_true_positive(self):
        findings = self.rule.scan("Dockerfile.secrets", self.vuln)
        assert len(findings) >= 1

    def test_true_negative(self):
        findings = self.rule.scan("Dockerfile.safe", self.safe)
        assert len(findings) == 0

    def test_ignores_non_dockerfile(self):
        vuln_content = "ENV API_KEY=secret123"
        findings = self.rule.scan("config.py", vuln_content)
        assert len(findings) == 0

    def test_redaction(self):
        findings = self.rule.scan("Dockerfile.secrets", self.vuln)
        for f in findings:
            assert "hardcoded_api_key_value_1234567890" not in f.snippet


# ── DEP004: BindingToAllInterfaces ───────────────────────────────────

class TestBindingToAllInterfaces:
    rule = BindingToAllInterfaces()
    vuln = _read(VULN_DEP / "bind_all_interfaces.py")
    safe = _read(CLEAN_DEP / "safe_routes.py")

    def test_true_positive(self):
        findings = self.rule.scan("bind_all_interfaces.py", self.vuln)
        assert len(findings) >= 1

    def test_true_negative(self):
        # safe_routes.py binds to 127.0.0.1
        findings = self.rule.scan("safe_routes.py", self.safe)
        assert len(findings) == 0


# ── DEP005: ExposedSourceMaps ─────────────────────────────────────────

class TestExposedSourceMaps:
    rule = ExposedSourceMaps()
    vuln = _read(VULN_DEP / "webpack.config.js")
    safe = _read(CLEAN_DEP / "safe_webpack.config.js")

    def test_true_positive(self):
        findings = self.rule.scan("webpack.config.js", self.vuln)
        assert len(findings) >= 1

    def test_true_negative(self):
        # safe_webpack.config.js has devtool: false
        findings = self.rule.scan("safe_webpack.config.js", self.safe)
        assert len(findings) == 0

    def test_scanner_applies_extension_filter(self):
        # Extension filtering is enforced by the scanner, not rule.scan().
        # Verify the rule advertises correct extensions for the scanner.
        assert ".js" in ExposedSourceMaps.file_extensions
        assert ExposedSourceMaps().applies_to("webpack.config.js") is True
        assert ExposedSourceMaps().applies_to("settings.py") is False


# ── DEP006: InsecureSecurityHeaders ──────────────────────────────────

class TestInsecureSecurityHeaders:
    rule = InsecureSecurityHeaders()
    vuln = _read(VULN_DEP / "insecure_headers.py")
    safe = _read(CLEAN_DEP / "safe_routes.py")

    def test_true_positive(self):
        findings = self.rule.scan("insecure_headers.py", self.vuln)
        assert len(findings) >= 1

    def test_true_negative(self):
        findings = self.rule.scan("safe_routes.py", self.safe)
        assert len(findings) == 0
