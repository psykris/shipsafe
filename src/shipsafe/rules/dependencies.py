"""Dependency safety rules for ShipSafe.

Detects supply-chain attack vectors: --extra-index-url hijacking, unpinned
dependencies, wildcard version specifiers, setup.py without pinned versions,
and known-typosquatted package names.

All checks are fully offline — no network calls are made.

Every pattern is a class-level constant so you can audit the full catalogue
with a single grep:

    grep -A5 "patterns = \\[" src/shipsafe/rules/dependencies.py

Design invariants
-----------------
- Patterns live on the class, never hidden inside methods.
- Every fix includes concrete, copy-pasteable remediation steps.
- No network calls — uses a bundled typosquat denylist.
"""

import re

from shipsafe.finding import Finding, Severity
from shipsafe.rules.base import Rule


# ── DEP101  ExtraIndexUrl ─────────────────────────────────────────────


class ExtraIndexUrl(Rule):
    """Detect --extra-index-url in pip calls and requirements files."""

    id = "DEP101"
    name = "--extra-index-url supply chain risk"
    severity = Severity.HIGH
    description = (
        "--extra-index-url tells pip to search a second package index alongside "
        "PyPI. If any package name exists on the private index but NOT on PyPI, "
        "an attacker can publish a malicious package on PyPI with the same name "
        "and a higher version number. pip will install the attacker's package "
        "instead (dependency confusion attack)."
    )
    fix = (
        "Avoid --extra-index-url. Use --index-url to fully replace PyPI instead:\n"
        "  pip install --index-url https://my.private.index/simple/ my-private-pkg\n"
        "Or use --find-links for a local directory of pre-downloaded wheels:\n"
        "  pip install --find-links ./vendor/ my-private-pkg\n"
        "If you must use a private index, add all private package names to a\n"
        "'--trusted-host' + 'namespace' prefix to avoid name collision."
    )
    guide_url = "guides/07-dependency-safety.md"
    owasp_id = "A08:2021"
    cwe_id = "CWE-829"
    confidence = "high"

    file_extensions: list[str] = [
        ".txt", ".cfg", ".ini", ".sh", ".bash", ".py",
        "dockerfile", ".dockerfile",
    ]

    patterns: list[str] = [
        r"--extra-index-url\s+\S+",
        r"extra[-_]index[-_]url\s*=\s*\S+",
        r"extra_index_url\s*=\s*\S+",
    ]

    def applies_to(self, file_path: str) -> bool:
        lower = file_path.lower()
        # requirements*.txt / requirements*.in
        base = lower.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        if "requirement" in base:
            return True
        # Dockerfile variants
        if base.endswith(("dockerfile", ".dockerfile")) or "dockerfile" in base:
            return True
        return any(file_path.endswith(ext) for ext in self.file_extensions)

    def scan(self, file_path: str, content: str) -> list[Finding]:
        return self._scan_patterns(file_path, content)


# ── DEP102  UnpinnedDependency ────────────────────────────────────────


class UnpinnedDependency(Rule):
    """Detect bare package names without version pins in requirements files."""

    id = "DEP102"
    name = "Unpinned dependency"
    severity = Severity.MEDIUM
    description = (
        "A dependency has no version specifier (e.g. 'requests' instead of "
        "'requests==2.31.0'). Unpinned deps allow pip to install any version, "
        "meaning a future release (or a compromised package on PyPI) could be "
        "installed silently on the next deploy. This breaks reproducible builds "
        "and is a supply-chain risk."
    )
    fix = (
        "Pin all dependencies to exact versions:\n"
        "  requests==2.31.0\n"
        "  flask==3.0.0\n"
        "Generate a fully-pinned lockfile with pip-compile (pip-tools):\n"
        "  pip install pip-tools\n"
        "  pip-compile requirements.in  # produces pinned requirements.txt\n"
        "Or use Poetry / PDM which generate a lockfile automatically."
    )
    guide_url = "guides/07-dependency-safety.md"
    owasp_id = "A08:2021"
    cwe_id = "CWE-1104"
    confidence = "medium"

    # Only applies to requirements-style files
    file_extensions: list[str] = []  # handled in applies_to()

    _BARE_PKG: re.Pattern = re.compile(
        r"^([A-Za-z0-9][A-Za-z0-9_\-\.]+)\s*$"
    )
    _COMMENT_OR_BLANK: re.Pattern = re.compile(r"^\s*(?:#.*)?$")
    _OPTION_LINE: re.Pattern = re.compile(r"^\s*-")

    def applies_to(self, file_path: str) -> bool:
        lower = file_path.lower()
        base = lower.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        return "requirement" in base and (base.endswith(".txt") or base.endswith(".in"))

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if self._COMMENT_OR_BLANK.match(stripped):
                continue
            if self._OPTION_LINE.match(stripped):
                continue
            # If the line is just a package name (no version specifier)
            if self._BARE_PKG.match(stripped):
                findings.append(
                    self._make_finding(
                        file_path=file_path,
                        line_number=i,
                        snippet=stripped,
                    )
                )
        return findings


# ── DEP103  WildcardVersionSpecifier ─────────────────────────────────


class WildcardVersionSpecifier(Rule):
    """Detect >= or ~= version specifiers without an upper-bound constraint."""

    id = "DEP103"
    name = "Wildcard / unbounded version specifier"
    severity = Severity.LOW
    description = (
        "A dependency uses a >= or ~= specifier without a paired upper bound. "
        "This allows pip to install any future version, including major releases "
        "that contain breaking changes or, in worst case, a compromised release "
        "published by a maintainer whose account was hijacked."
    )
    fix = (
        "Prefer exact pinning or narrow ranges:\n"
        "  requests==2.31.0           # exact pin (most reproducible)\n"
        "  flask>=3.0,<4.0            # narrow compatible range\n"
        "Or use pip-tools / Poetry lockfiles for full reproducibility."
    )
    guide_url = "guides/07-dependency-safety.md"
    owasp_id = "A08:2021"
    cwe_id = "CWE-1104"
    confidence = "medium"

    file_extensions: list[str] = []  # handled in applies_to()

    patterns: list[str] = [
        # package>=version with no upper bound < on the same line
        r"^[A-Za-z0-9][A-Za-z0-9_\-\.]+\s*(?:>=|~=)\s*[\d\.]+\s*(?:,\s*!=[\d\.]+\s*)*$",
        # setup.py / setup.cfg: 'package>=version' in install_requires without <
        r'["\'][A-Za-z0-9][A-Za-z0-9_\-\.]+\s*(?:>=|~=)\s*[\d\.]+["\']',
    ]

    def applies_to(self, file_path: str) -> bool:
        lower = file_path.lower()
        base = lower.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        if "requirement" in base and (base.endswith(".txt") or base.endswith(".in")):
            return True
        if base in ("setup.py", "setup.cfg", "pyproject.toml"):
            return True
        return False

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for pattern in self.patterns:
                if re.search(pattern, stripped):
                    # Skip if there's already an upper bound on the same line
                    if re.search(r",\s*<[\d]", stripped):
                        break
                    findings.append(
                        self._make_finding(
                            file_path=file_path,
                            line_number=i,
                            snippet=stripped,
                        )
                    )
                    break
        return findings


# ── DEP104  SetupPyUnpinnedRequires ──────────────────────────────────


class SetupPyUnpinnedRequires(Rule):
    """Detect bare package names in install_requires / extras_require."""

    id = "DEP104"
    name = "Unpinned install_requires in setup.py"
    severity = Severity.LOW
    description = (
        "install_requires (or extras_require) in setup.py contains a package "
        "name with no version constraint. Unlike requirements.txt (which is for "
        "deployments), setup.py defines the library's dependencies for "
        "distributors. While overly strict pinning in setup.py is wrong, "
        "completely unpinned entries allow any version — including broken or "
        "malicious future releases."
    )
    fix = (
        "Add at least a minimum version constraint and an upper major-version bound:\n"
        "  install_requires=[\n"
        "      'requests>=2.28,<3',   # compatible range\n"
        "      'click>=8.0,<9',\n"
        "  ]\n"
        "For applications (not libraries), switch to a lockfile tool."
    )
    guide_url = "guides/07-dependency-safety.md"
    owasp_id = "A08:2021"

    file_extensions: list[str] = [".py", ".cfg", ".toml"]

    # Patterns shown for documentation; real logic is in scan() below
    patterns: list[str] = [
        r'install_requires\s*=\s*\[',
        r'extras_require\s*=\s*\{',
    ]

    # Matches a bare package name string (no version specifier)
    _BARE_PKG: re.Pattern = re.compile(
        r'["\']([A-Za-z][A-Za-z0-9_\-\.]+)["\']\s*[,\]]'
    )
    # Block-level patterns that introduce a deps list
    _BLOCK_START: re.Pattern = re.compile(
        r'(?:install_requires|extras_require)\s*[=:]', re.IGNORECASE
    )

    def scan(self, file_path: str, content: str) -> list[Finding]:
        # Use multiline regex to find install_requires blocks
        block_re = re.compile(
            r'(?:install_requires|extras_require)\s*[=:]\s*[\[\{][^\]\}]*[\]\}]',
            re.DOTALL,
        )
        findings = []
        for block_match in block_re.finditer(content):
            block_text = block_match.group()
            block_start_pos = block_match.start()
            # Determine the line number of the block start
            block_line = content[:block_start_pos].count("\n") + 1
            # Find all quoted strings without version specifiers
            for m in self._BARE_PKG.finditer(block_text):
                pkg = m.group(1)
                # Skip if preceded by version specifiers in the same token
                preceding = block_text[max(0, m.start() - 3):m.start()]
                if re.search(r'[><=!~]', preceding):
                    continue
                # Count lines to get accurate line number
                pkg_line = block_line + block_text[:m.start()].count("\n")
                # Only flag if there's no version specifier after the name
                after = block_text[m.end():m.end() + 20]
                if not re.search(r'[><=!~]', after.split("\n")[0]):
                    findings.append(
                        self._make_finding(
                            file_path=file_path,
                            line_number=pkg_line,
                            snippet=m.group().strip(),
                            message=(
                                f"'{pkg}' in install_requires has no version constraint. "
                                "Use 'pkg>=min,<max' or switch to a lockfile tool."
                            ),
                        )
                    )
        return findings


# ── DEP105  KnownTyposquatPackage ─────────────────────────────────────


# Bundled denylist: common typosquats and AI-hallucinated package names.
# Sourced from public PyPI typosquatting reports and security advisories.
# Format: typosquat_name -> legitimate_name
_TYPOSQUAT_DENYLIST: dict[str, str] = {
    # Classic PyPI typosquats (confirmed malicious campaigns)
    "colourama": "colorama",
    "djago": "django",
    "dajngo": "django",
    "diango": "django",
    "reqeusts": "requests",
    "requets": "requests",
    "request": "requests",
    "urllib4": "urllib3",
    "urlib3": "urllib3",
    "pillow_": "Pillow",
    "nump": "numpy",
    "numppy": "numpy",
    "nuumpy": "numpy",
    "scikitlearn": "scikit-learn",
    "flask_": "flask",
    "flaask": "flask",
    "flaskk": "flask",
    "beautifulsoupp": "beautifulsoup4",
    "panads": "pandas",
    "pandaas": "pandas",
    "matplotlibb": "matplotlib",
    "pycrpytodome": "pycryptodome",
    "pycryptodomex_": "pycryptodome",
    "cryptographyy": "cryptography",
    "crpytography": "cryptography",
    "openssl_": "pyOpenSSL",
    # AI-hallucinated packages (names that don't exist on PyPI)
    "langchainplus": "langchain",
    "langchain_plus": "langchain",
    "openai_tools": "openai",
    "anthropic_tools": "anthropic",
    "chatgpt": "openai",
    "gpt4": "openai",
    "huggingface": "huggingface-hub",
    "hugging_face": "huggingface-hub",
    "transformerss": "transformers",
    "pineconedb": "pinecone-client",
    "pinecone_client": "pinecone-client",
    "chromadb_": "chromadb",
    "weaviateclient": "weaviate-client",
    # Supply-chain campaign packages (historically abused names)
    "python-nmap_": "python-nmap",
    "setup-tools": "setuptools",
    "py-yaml": "PyYAML",
    "pyyaml_": "PyYAML",
    "python_dotenv": "python-dotenv",
}


# Legitimate package aliases that should NOT be flagged as typosquats.
# These are well-known import namespaces for popular packages.
_LEGITIMATE_ALIASES: set[str] = {
    "pil",            # Pillow (PIL is Pillow's import namespace)
    "cv2",            # opencv-python
    "sklearn",        # scikit-learn
    "bs4",            # beautifulsoup4
    "yaml",           # PyYAML
    "dotenv",         # python-dotenv
    "crypto",         # pycryptodome
    "google.cloud",   # GCP SDK namespace
}


class KnownTyposquatPackage(Rule):
    """Detect known typosquatted or AI-hallucinated package names."""

    id = "DEP105"
    name = "Known typosquatted or hallucinated package"
    severity = Severity.HIGH
    description = (
        "A package name matches a known typosquat or AI-hallucinated package. "
        "Typosquatted packages impersonate popular libraries with slight name "
        "variations and typically contain malware (credential stealers, "
        "cryptominers). AI code generators sometimes invent plausible-sounding "
        "package names that attackers then register on PyPI."
    )
    fix = (
        "Verify the exact package name on https://pypi.org before installing:\n"
        "  # Check the legitimate name\n"
        "  pip index versions <correct-package-name>\n"
        "  # Remove the suspicious package and reinstall the legitimate one.\n"
        "  pip uninstall <suspicious-name>\n"
        "  pip install <legitimate-name>==<pinned-version>"
    )
    guide_url = "guides/07-dependency-safety.md"
    owasp_id = "A08:2021"

    # Compiled pattern — built from the denylist at class creation
    _DENYLIST_PATTERN: re.Pattern = re.compile(
        r"(?i)^(?:" + "|".join(re.escape(k) for k in _TYPOSQUAT_DENYLIST) + r")(?:\s*[=<>!~]|$|\s*$)",
        re.MULTILINE,
    )

    # Inline import pattern: import colourama
    _IMPORT_PATTERN: re.Pattern = re.compile(
        r"(?i)^(?:import|from)\s+(" + "|".join(re.escape(k) for k in _TYPOSQUAT_DENYLIST) + r")\b"
    )

    file_extensions: list[str] = []  # handled in applies_to()

    # Expose patterns for grepping (human-readable summary only)
    patterns: list[str] = [r"<see _TYPOSQUAT_DENYLIST for full list>"]

    def applies_to(self, file_path: str) -> bool:
        lower = file_path.lower()
        base = lower.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        # requirements*.txt / *.in
        if "requirement" in base and (base.endswith(".txt") or base.endswith(".in")):
            return True
        # setup.py / setup.cfg / pyproject.toml
        if base in ("setup.py", "setup.cfg", "pyproject.toml"):
            return True
        # Python source files (detect bad imports)
        if base.endswith(".py"):
            return True
        return False

    def scan(self, file_path: str, content: str) -> list[Finding]:
        findings = []
        lower = file_path.lower()
        base = lower.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        is_requirements = "requirement" in base
        is_python = base.endswith(".py")

        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue

            if is_requirements:
                # Match bare typosquat name at start of line
                m = re.match(
                    r"^([A-Za-z][A-Za-z0-9_\-\.]*)\s*(?:[=<>!~]|$)",
                    stripped,
                    re.IGNORECASE,
                )
                if m:
                    pkg = m.group(1).lower().replace("-", "_").replace(".", "_")
                    # Skip legitimate aliases
                    if pkg in _LEGITIMATE_ALIASES:
                        continue
                    for typo, legit in _TYPOSQUAT_DENYLIST.items():
                        normalised_typo = typo.lower().replace("-", "_").replace(".", "_")
                        if pkg == normalised_typo:
                            findings.append(
                                self._make_finding(
                                    file_path=file_path,
                                    line_number=i,
                                    snippet=stripped,
                                    message=(
                                        f"'{m.group(1)}' resembles the known typosquat of "
                                        f"'{legit}'. Verify on pypi.org before installing."
                                    ),
                                )
                            )
                            break

            if is_python:
                # Match import statements
                m = self._IMPORT_PATTERN.match(stripped)
                if m:
                    pkg = m.group(1).lower()
                    # Skip legitimate aliases
                    if pkg in _LEGITIMATE_ALIASES:
                        continue
                    legit = _TYPOSQUAT_DENYLIST.get(pkg, _TYPOSQUAT_DENYLIST.get(pkg.replace("_", "-"), ""))
                    findings.append(
                        self._make_finding(
                            file_path=file_path,
                            line_number=i,
                            snippet=stripped,
                            message=(
                                f"'{m.group(1)}' is a known typosquat"
                                + (f" of '{legit}'" if legit else "")
                                + ". Verify on pypi.org."
                            ),
                        )
                    )

        return findings
