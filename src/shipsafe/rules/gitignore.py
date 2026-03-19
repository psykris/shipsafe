"""Git hygiene rules for ShipSafe.

Checks .gitignore for missing entries and detects committed sensitive files.
All .gitignore rules use file_extensions = ['.gitignore'] and scan the
.gitignore content for required entries. GIT006 detects .env files directly.
"""

from shipsafe.finding import Finding, Severity
from shipsafe.rules.base import Rule


class MissingEnvInGitignore(Rule):
    """GIT002: .gitignore does not include .env."""

    id = "GIT002"
    name = "Missing .env in .gitignore"
    severity = Severity.CRITICAL
    description = (
        ".gitignore does not include .env. "
        "Environment files with secrets will be committed to git."
    )
    fix = "Add this line to your .gitignore file:\n.env\n.env.*"
    guide_url = "guides/08-git-hygiene.md"
    owasp_id = "A05:2021"
    cwe_id = "CWE-538"
    confidence = "high"
    file_extensions = [".gitignore"]

    _env_patterns = (".env", ".env*", ".env.*", ".env.local", ".env.production")

    def scan(self, file_path: str, content: str) -> list[Finding]:
        lines = content.splitlines()
        for line in lines:
            stripped = line.strip()
            if stripped in self._env_patterns:
                return []
        snippet = content[:80] if content else "(empty .gitignore)"
        return [self._make_finding(file_path, 1, snippet)]


class MissingNodeModulesInGitignore(Rule):
    """GIT003: .gitignore does not include node_modules."""

    id = "GIT003"
    name = "Missing node_modules in .gitignore"
    severity = Severity.HIGH
    description = (
        ".gitignore does not include node_modules. "
        "The node_modules directory should never be committed to version control."
    )
    fix = "Add this line to your .gitignore file:\nnode_modules/"
    guide_url = "guides/08-git-hygiene.md"
    owasp_id = "A05:2021"
    cwe_id = "CWE-538"
    confidence = "high"
    file_extensions = [".gitignore"]

    _node_patterns = ("node_modules", "node_modules/", "node_modules/*")

    def scan(self, file_path: str, content: str) -> list[Finding]:
        lines = content.splitlines()
        for line in lines:
            stripped = line.strip()
            if stripped in self._node_patterns:
                return []
        snippet = content[:80] if content else "(empty .gitignore)"
        return [self._make_finding(file_path, 1, snippet)]


class MissingPycacheInGitignore(Rule):
    """GIT004: .gitignore does not include __pycache__."""

    id = "GIT004"
    name = "Missing __pycache__ in .gitignore"
    severity = Severity.MEDIUM
    description = (
        ".gitignore does not include __pycache__. "
        "Python bytecode directories should not be committed."
    )
    fix = "Add this line to your .gitignore file:\n__pycache__/"
    guide_url = "guides/08-git-hygiene.md"
    owasp_id = "A05:2021"
    cwe_id = "CWE-538"
    confidence = "high"
    file_extensions = [".gitignore"]

    _pycache_patterns = ("__pycache__", "__pycache__/", "__pycache__/*")

    def scan(self, file_path: str, content: str) -> list[Finding]:
        lines = content.splitlines()
        for line in lines:
            stripped = line.strip()
            if stripped in self._pycache_patterns:
                return []
        snippet = content[:80] if content else "(empty .gitignore)"
        return [self._make_finding(file_path, 1, snippet)]


class MissingDSStoreInGitignore(Rule):
    """GIT005: .gitignore does not include .DS_Store."""

    id = "GIT005"
    name = "Missing .DS_Store in .gitignore"
    severity = Severity.LOW
    description = (
        ".gitignore does not include .DS_Store. "
        "macOS metadata files should not be committed."
    )
    fix = "Add this line to your .gitignore file:\n.DS_Store"
    guide_url = "guides/08-git-hygiene.md"
    owasp_id = "A05:2021"
    cwe_id = "CWE-538"
    confidence = "high"
    file_extensions = [".gitignore"]

    _ds_patterns = (".DS_Store", ".DS_Store?")

    def scan(self, file_path: str, content: str) -> list[Finding]:
        lines = content.splitlines()
        for line in lines:
            stripped = line.strip()
            if stripped in self._ds_patterns:
                return []
        snippet = content[:80] if content else "(empty .gitignore)"
        return [self._make_finding(file_path, 1, snippet)]


class CommittedEnvFile(Rule):
    """GIT006: .env file found in the project."""

    id = "GIT006"
    name = "Environment file in project"
    severity = Severity.CRITICAL
    description = (
        ".env file found in the project. This file likely contains secrets "
        "and should not be committed to version control."
    )
    fix = (
        "1. Add .env to your .gitignore file\n"
        "2. Remove the .env file from version control:\n"
        "   git rm --cached .env\n"
        "3. Use environment variables or a secrets manager instead"
    )
    guide_url = "guides/08-git-hygiene.md"
    owasp_id = "A05:2021"
    cwe_id = "CWE-312"
    confidence = "high"
    file_extensions = [".env"]

    def scan(self, file_path: str, content: str) -> list[Finding]:
        if not (
            file_path.endswith(".env")
            or "/.env" in file_path
            or "\\.env" in file_path
        ):
            return []
        # Only flag if the file contains key=value pairs (actual secrets)
        if "=" in content:
            return [
                self._make_finding(
                    file_path, 1, "(env file with secrets - content redacted)"
                )
            ]
        return []
