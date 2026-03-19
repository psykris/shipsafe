"""Local scan history stored in ``.shipsafe/history/``.

Each scan is saved as a timestamped JSON file.  Comparing the
fingerprint sets of two scans yields new, resolved, and persistent
findings — with zero network access and zero external dependencies.

Usage::

    from shipsafe.history import save_scan, load_latest, diff_scans

    save_scan(result, project_root=".")
    prev, curr = load_latest(project_root=".", count=2)
    changes = diff_scans(prev, curr)
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from shipsafe.finding import ScanResult


def _history_dir(project_root: str) -> Path:
    """Return (and create) the history directory."""
    d = Path(project_root).resolve() / ".shipsafe" / "history"
    d.mkdir(parents=True, exist_ok=True)
    return d


def save_scan(result: ScanResult, project_root: str = ".") -> Path:
    """Persist a scan result to the history directory.

    Returns the path of the created JSON file.
    """
    hdir = _history_dir(project_root)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S_%f")
    path = hdir / f"{ts}.json"
    data = result.to_dict()
    data["_meta"] = {
        "saved_at": ts,
        "fingerprints": [f.fingerprint for f in result.findings],
    }
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


def list_scans(project_root: str = ".") -> list[Path]:
    """Return scan files sorted oldest-first."""
    hdir = Path(project_root).resolve() / ".shipsafe" / "history"
    if not hdir.is_dir():
        return []
    return sorted(hdir.glob("*.json"))


def load_scan(path: Path) -> dict:
    """Load a scan result from a JSON file."""
    return json.loads(path.read_text(encoding="utf-8"))


def load_latest(project_root: str = ".", count: int = 1) -> list[dict]:
    """Load the *count* most recent scans, newest-first."""
    scans = list_scans(project_root)
    selected = scans[-count:] if len(scans) >= count else scans
    return [load_scan(p) for p in reversed(selected)]


def _fingerprints_from(scan_data: dict) -> set[str]:
    """Extract the fingerprint set from saved scan data."""
    meta = scan_data.get("_meta", {})
    fp_list = meta.get("fingerprints", [])
    if fp_list:
        return set(fp_list)
    # Fallback: extract from findings
    return {f.get("fingerprint", "") for f in scan_data.get("findings", []) if f.get("fingerprint")}


def diff_scans(
    previous: dict | None,
    current: dict,
) -> dict:
    """Compare two scans by fingerprint sets.

    Returns a dict with keys:
        new:        fingerprints in current but not in previous
        resolved:   fingerprints in previous but not in current
        persistent: fingerprints in both
    """
    if previous is None:
        curr_fps = _fingerprints_from(current)
        return {"new": curr_fps, "resolved": set(), "persistent": set()}

    prev_fps = _fingerprints_from(previous)
    curr_fps = _fingerprints_from(current)

    return {
        "new": curr_fps - prev_fps,
        "resolved": prev_fps - curr_fps,
        "persistent": curr_fps & prev_fps,
    }


def score_trend(project_root: str = ".") -> list[dict]:
    """Return a list of ``{date, score}`` dicts for all scans, oldest-first."""
    trend: list[dict] = []
    for path in list_scans(project_root):
        data = load_scan(path)
        score_val = data.get("score", {})
        if isinstance(score_val, dict):
            score_val = score_val.get("value", 0)
        ts = data.get("_meta", {}).get("saved_at", path.stem)
        trend.append({"date": ts, "score": score_val})
    return trend
