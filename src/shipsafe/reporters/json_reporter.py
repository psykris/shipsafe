"""JSON reporter — machine-readable output for tooling integration.

Outputs a JSON document containing the full scan result with metadata
for reproducibility.  Uses only the stdlib ``json`` module.
"""

import json

from shipsafe.finding import ScanResult


def render(result: ScanResult, indent: int = 2) -> str:
    """Render a scan result as a JSON string.

    Args:
        result: The completed scan result.
        indent: JSON indentation (default 2 spaces).

    Returns:
        A formatted JSON string.
    """
    return json.dumps(result.to_dict(), indent=indent, ensure_ascii=False)
