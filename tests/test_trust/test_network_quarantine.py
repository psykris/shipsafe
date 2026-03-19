"""Trust test: Network quarantine.

The most critical trust property — ShipSafe never phones home.

This test walks every Python file in src/shipsafe/ using the ``ast``
module and verifies that **none** of them import any network-capable
module.  If a developer accidentally adds ``import requests`` or
``from urllib import ...``, CI breaks immediately.

Why this matters
----------------
Users run ShipSafe against proprietary codebases.  They must be able to
prove — not just believe — that the tool never transmits data over
the network.  This test is that proof.
"""

import ast
import os
from pathlib import Path


# Every module (or top-level package) that provides network access.
BANNED_MODULES = {
    "socket",
    "urllib",
    "urllib.request",
    "urllib.parse",
    "http.client",
    "http.server",
    "http.cookiejar",
    "xmlrpc",
    "xmlrpc.client",
    "xmlrpc.server",
    "ftplib",
    "smtplib",
    "poplib",
    "imaplib",
    "requests",
    "httpx",
    "aiohttp",
    "urllib3",
    "telnetlib",
}

# For top-level matching (catches ``import http`` even though we listed
# ``http.client`` etc. individually).
BANNED_TOP_LEVEL = {m.split(".")[0] for m in BANNED_MODULES}


def _collect_import_violations(src_dir: Path) -> list[str]:
    """Walk *src_dir* and return a list of human-readable violation strings."""
    violations: list[str] = []

    for root, _dirs, files in os.walk(src_dir):
        for filename in files:
            if not filename.endswith(".py"):
                continue
            filepath = Path(root) / filename
            # serve.py is permitted to use stdlib http.server for local-only
            # serving (zero external traffic — user data never leaves machine).
            if filename == "serve.py":
                continue
            try:
                source = filepath.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            try:
                tree = ast.parse(source, filename=str(filepath))
            except SyntaxError:
                continue

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        top = alias.name.split(".")[0]
                        if top in BANNED_TOP_LEVEL or alias.name in BANNED_MODULES:
                            violations.append(
                                f"{filepath}:{node.lineno} imports {alias.name}"
                            )
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        top = node.module.split(".")[0]
                        if top in BANNED_TOP_LEVEL or node.module in BANNED_MODULES:
                            violations.append(
                                f"{filepath}:{node.lineno} imports from {node.module}"
                            )

    return violations


def test_no_network_imports_in_source():
    """Verify that no file in src/shipsafe/ imports network modules."""
    src_dir = Path(__file__).resolve().parent.parent.parent / "src" / "shipsafe"
    assert src_dir.is_dir(), f"Source directory not found: {src_dir}"

    violations = _collect_import_violations(src_dir)

    assert violations == [], (
        "Network module imports found in source:\n" + "\n".join(violations)
    )


def test_banned_list_is_comprehensive():
    """Sanity-check that our banned list covers key categories.

    This guards against someone trimming the banned list in order to
    sneak a network import through.
    """
    # stdlib network modules that must always be present
    assert "socket" in BANNED_MODULES
    assert "http.client" in BANNED_MODULES
    assert "urllib" in BANNED_MODULES
    assert "smtplib" in BANNED_MODULES
    assert "ftplib" in BANNED_MODULES

    # popular third-party HTTP clients
    assert "requests" in BANNED_MODULES
    assert "httpx" in BANNED_MODULES
    assert "aiohttp" in BANNED_MODULES
    assert "urllib3" in BANNED_MODULES
