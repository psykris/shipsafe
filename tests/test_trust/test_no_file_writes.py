"""Trust test: No file writes.

Verify that scanning does not modify the filesystem.

Why this matters
----------------
ShipSafe is a *read-only* tool.  It scans source code to find problems
but must never create, modify, or delete files.  If a scan changed
anything — even creating a temp file, a cache directory, or a log —
users could not trust it to run safely in production repositories,
CI pipelines, or pre-commit hooks.

Strategy
--------
1. Copy the vulnerable fixtures into a fresh tmpdir.
2. Hash every file in the copy.
3. Run a full scan.
4. Hash every file again and compare.
5. Also verify no new files were created and no files were deleted.
"""

import hashlib
import shutil
from pathlib import Path

from shipsafe.scanner import Scanner


def _hash_directory(path: Path) -> dict[str, str]:
    """Create a SHA-256 hash map of all files in a directory tree.

    Keys are paths relative to *path*; values are hex digests.
    """
    hashes: dict[str, str] = {}
    for f in sorted(path.rglob("*")):
        if f.is_file():
            hashes[str(f.relative_to(path))] = hashlib.sha256(
                f.read_bytes()
            ).hexdigest()
    return hashes


def test_scanner_does_not_modify_filesystem(tmp_path: Path):
    """Verify scanning does not create, modify, or delete files."""
    src = Path(__file__).resolve().parent.parent / "fixtures" / "vulnerable"
    dst = tmp_path / "test_project"
    shutil.copytree(src, dst)

    before = _hash_directory(dst)
    assert len(before) > 0, "Fixture copy is empty — test setup error"

    scanner = Scanner(profile="saas")
    scanner.scan(str(dst))

    after = _hash_directory(dst)

    # Check no files were deleted
    deleted = set(before.keys()) - set(after.keys())
    assert deleted == set(), f"Scanner deleted files: {deleted}"

    # Check no files were created
    created = set(after.keys()) - set(before.keys())
    assert created == set(), f"Scanner created files: {created}"

    # Check no files were modified
    modified = {
        path
        for path in before
        if path in after and before[path] != after[path]
    }
    assert modified == set(), f"Scanner modified files: {modified}"


def test_scanner_does_not_modify_single_file(tmp_path: Path):
    """Verify scanning a single file leaves it untouched."""
    src = Path(__file__).resolve().parent.parent / "fixtures" / "vulnerable" / "secrets" / "hardcoded_openai_key.py"
    dst = tmp_path / "hardcoded_openai_key.py"
    shutil.copy2(src, dst)

    before_hash = hashlib.sha256(dst.read_bytes()).hexdigest()
    before_stat = dst.stat()

    scanner = Scanner(profile="saas")
    scanner.scan(str(dst))

    after_hash = hashlib.sha256(dst.read_bytes()).hexdigest()
    after_stat = dst.stat()

    assert before_hash == after_hash, "Scanner modified file content"
    assert before_stat.st_size == after_stat.st_size, "Scanner changed file size"


def test_scanner_does_not_write_outside_target(tmp_path: Path):
    """Verify scanning does not create files outside the target directory."""
    src = Path(__file__).resolve().parent.parent / "fixtures" / "vulnerable"
    dst = tmp_path / "project"
    shutil.copytree(src, dst)

    # Record everything in tmp_path before scanning
    before = set(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*"))

    scanner = Scanner(profile="saas")
    scanner.scan(str(dst))

    # Record everything in tmp_path after scanning
    after = set(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*"))

    created_outside = after - before
    assert created_outside == set(), (
        f"Scanner created files outside target directory: {created_outside}"
    )
