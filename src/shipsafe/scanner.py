"""Core scan orchestrator for ShipSafe.

Loads a profile, discovers rules, walks the file tree, runs applicable
rules against each file, and collects findings.

Design invariants
-----------------
- The scanner **never writes** to the filesystem.  It is purely a reader.
- Binary files are detected and skipped automatically.
- Paths in ``DEFAULT_EXCLUDES`` are always skipped (overridable).
- Files larger than ``MAX_FILE_SIZE`` bytes are skipped.
"""

from pathlib import Path

from shipsafe.config import DEFAULT_PROFILE, Profile, load_profile
from shipsafe.finding import Finding, ScanResult, Severity
from shipsafe.fingerprint import fingerprint_finding
from shipsafe.rules import discover_rules
from shipsafe.rules.base import Rule
from shipsafe.scoring import calculate_score

# Directories that are always excluded unless the user overrides
DEFAULT_EXCLUDES: set[str] = {
    ".git",
    "node_modules",
    "__pycache__",
    ".next",
    "dist",
    "build",
    "venv",
    ".venv",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "egg-info",
    ".eggs",
    "site-packages",
}

# Skip files larger than 1 MB — they are unlikely to be source code
MAX_FILE_SIZE: int = 1_048_576

# File extensions that are never source code
BINARY_EXTENSIONS: set[str] = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".svg",
    ".mp3", ".mp4", ".wav", ".avi", ".mov", ".flv", ".wmv",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".bin",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".pyc", ".pyo", ".class", ".o", ".obj",
    ".sqlite", ".db", ".sqlite3",
    ".lock",
}


def _load_shipsafeignore(target_path: Path) -> tuple[set[str], set[str]]:
    """Load exclusion patterns from a ``.shipsafeignore`` file.

    The file is looked up in the scan target root.  Each non-blank,
    non-comment line is treated as either a directory name or a file
    name to skip (entries with a file extension are treated as files).

    Returns:
        A tuple of (directory_names, file_names) to exclude.
    """
    ignore_file = target_path / ".shipsafeignore"
    if not ignore_file.is_file():
        return set(), set()
    dirs: set[str] = set()
    files: set[str] = set()
    try:
        for line in ignore_file.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                # Entries with a dot in the last component are file names
                if "." in Path(stripped).name and not stripped.endswith("/"):
                    files.add(stripped)
                else:
                    dirs.add(stripped.rstrip("/"))
    except OSError:
        pass
    return dirs, files


class Scanner:
    """Core scan orchestrator.

    Usage::

        scanner = Scanner(profile="saas")
        result = scanner.scan(".")
    """

    def __init__(
        self,
        profile: str = DEFAULT_PROFILE,
        exclude_paths: list[str] | None = None,
        severity_filter: list[Severity] | None = None,
        rule_ids: list[str] | None = None,
    ) -> None:
        self.profile: Profile = load_profile(profile)
        self.rules: list[Rule] = discover_rules()
        self.exclude_dirs: set[str] = (
            set(exclude_paths) if exclude_paths is not None else set(DEFAULT_EXCLUDES)
        )
        self.exclude_files: set[str] = set()
        self.severity_filter = severity_filter
        self.rule_ids = set(rule_ids) if rule_ids else None

    def scan(self, target: str) -> ScanResult:
        """Scan a directory or single file for security vulnerabilities.

        Returns:
            A ``ScanResult`` containing all findings, score, and metadata.
        """
        target_path = Path(target).resolve()

        # Merge .shipsafeignore entries with exclude sets
        ignore_dirs, ignore_files = _load_shipsafeignore(target_path)
        self.exclude_dirs |= ignore_dirs
        self.exclude_files |= ignore_files

        findings: list[Finding] = []
        files_scanned = 0

        if target_path.is_file():
            content = self._read_file(target_path)
            if content is not None:
                files_scanned = 1
                findings.extend(self._scan_file(target_path, content))
        else:
            for file_path in self._walk(target_path):
                content = self._read_file(file_path)
                if content is None:
                    continue
                files_scanned += 1
                findings.extend(self._scan_file(file_path, content))

        # Apply profile severity overrides
        for finding in findings:
            finding.severity = self.profile.effective_severity(
                finding.rule_id, finding.severity
            )

        # Filter by profile min_severity
        findings = [f for f in findings if self.profile.should_include(f.severity)]

        # Filter by user-specified severity if provided
        if self.severity_filter:
            findings = [f for f in findings if f.severity in self.severity_filter]

        # Compute stable fingerprints for every finding
        for finding in findings:
            finding.fingerprint = fingerprint_finding(
                finding.file_path, finding.rule_id, finding.snippet
            )

        # Sort: CRITICAL first, then by file path, then by line number
        findings.sort(
            key=lambda f: (-f.severity, f.file_path, f.line_number)
        )

        score, breakdown = calculate_score(findings)

        return ScanResult(
            findings=findings,
            score=score,
            score_breakdown=breakdown,
            files_scanned=files_scanned,
            profile=self.profile.name,
            target=str(target_path),
        )

    def _scan_file(self, file_path: Path, content: str) -> list[Finding]:
        """Run all applicable rules against a single file."""
        findings: list[Finding] = []
        path_str = str(file_path)

        for rule in self._applicable_rules(path_str):
            rule_findings = rule.scan(path_str, content)
            findings.extend(rule_findings)

        return findings

    def _applicable_rules(self, file_path: str) -> list[Rule]:
        """Return rules that apply to the given file path."""
        rules = []
        for rule in self.rules:
            # Filter by rule ID if specified
            if self.rule_ids and rule.id not in self.rule_ids:
                continue

            # Filter by rule prefix (profile-configured)
            if self.profile.enabled_rule_prefixes:
                prefix = rule.id.rstrip("0123456789")
                if prefix not in self.profile.enabled_rule_prefixes:
                    continue

            # Filter by file extension
            if not rule.applies_to(file_path):
                continue

            rules.append(rule)
        return rules

    def _walk(self, root: Path):
        """Walk directory tree, yielding file paths.

        Skips excluded directories, binary files, and large files.
        """
        try:
            entries = sorted(root.iterdir())
        except (PermissionError, FileNotFoundError, NotADirectoryError):
            return

        for entry in entries:
            if entry.is_dir():
                if entry.name in self.exclude_dirs:
                    continue
                # Skip .egg-info directories (name includes package prefix)
                if entry.name.endswith(".egg-info"):
                    continue
                # Skip hidden directories except .github (needed for CI workflows)
                if entry.name.startswith(".") and entry.name != ".github":
                    continue
                yield from self._walk(entry)
            elif entry.is_file():
                # Skip files listed in .shipsafeignore
                if entry.name in self.exclude_files:
                    continue
                # Skip binary extensions
                if entry.suffix.lower() in BINARY_EXTENSIONS:
                    continue
                # Skip files that are too large
                try:
                    if entry.stat().st_size > MAX_FILE_SIZE:
                        continue
                except OSError:
                    continue
                yield entry

    def _read_file(self, path: Path) -> str | None:
        """Read a file as UTF-8 text.  Returns None for binary files."""
        try:
            return path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, PermissionError, OSError):
            return None
