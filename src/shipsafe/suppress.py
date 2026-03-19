"""Finding suppression for acknowledged false positives.

Teams can mark findings as suppressed by fingerprint.  Suppressed
findings still appear in reports with a "Suppressed" badge — they
are never hidden.  This prevents alert fatigue while maintaining
a complete audit trail.

Storage: ``.shipsafe/suppress.json`` in the project root.

Format::

    [
      {
        "fingerprint": "a3f8...",
        "reason": "Intentional test fixture, not production code",
        "reviewer": "krishna@example.com",
        "date": "2026-03-11"
      }
    ]
"""

import json
from datetime import date
from pathlib import Path


def _suppress_path(project_root: str) -> Path:
    """Return the suppress file path (does not create it)."""
    return Path(project_root).resolve() / ".shipsafe" / "suppress.json"


def load_suppressions(project_root: str = ".") -> list[dict]:
    """Load the suppression list.  Returns [] if no file exists."""
    path = _suppress_path(project_root)
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def suppressed_fingerprints(project_root: str = ".") -> set[str]:
    """Return the set of suppressed fingerprints."""
    return {s["fingerprint"] for s in load_suppressions(project_root) if "fingerprint" in s}


def add_suppression(
    fingerprint: str,
    reason: str,
    reviewer: str = "",
    project_root: str = ".",
) -> Path:
    """Add a suppression entry and write the file.

    Returns the path to the suppress file.
    """
    path = _suppress_path(project_root)
    path.parent.mkdir(parents=True, exist_ok=True)

    entries = load_suppressions(project_root)

    # Avoid duplicates
    if any(e.get("fingerprint") == fingerprint for e in entries):
        return path

    entries.append({
        "fingerprint": fingerprint,
        "reason": reason,
        "reviewer": reviewer,
        "date": date.today().isoformat(),
    })

    path.write_text(json.dumps(entries, indent=2), encoding="utf-8")
    return path


def remove_suppression(fingerprint: str, project_root: str = ".") -> bool:
    """Remove a suppression entry.  Returns True if found and removed."""
    path = _suppress_path(project_root)
    entries = load_suppressions(project_root)
    before = len(entries)
    entries = [e for e in entries if e.get("fingerprint") != fingerprint]
    if len(entries) == before:
        return False
    path.write_text(json.dumps(entries, indent=2), encoding="utf-8")
    return True


def is_suppressed(fingerprint: str, project_root: str = ".") -> bool:
    """Check if a fingerprint is suppressed."""
    return fingerprint in suppressed_fingerprints(project_root)
