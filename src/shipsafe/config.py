"""Profile loader for ShipSafe scan configuration.

Profiles calibrate severity levels and rule selection based on the
deployment context.  A hobby project and a SaaS handling payment data
have different threat models.

Profiles are stored as JSON files in the ``profiles/`` directory
(stdlib ``json`` — zero external dependencies).
"""

import json
from dataclasses import dataclass, field
from pathlib import Path

from shipsafe.finding import SEVERITY_MAP, Severity

_PROFILES_DIR = Path(__file__).parent / "profiles"

# Profiles that ship with ShipSafe
AVAILABLE_PROFILES = ("hobby", "saas", "enterprise")
DEFAULT_PROFILE = "saas"


@dataclass
class Profile:
    """A scan profile that controls severity thresholds and overrides."""

    name: str
    description: str
    min_severity: Severity
    severity_overrides: dict[str, Severity] = field(default_factory=dict)
    enabled_rule_prefixes: list[str] = field(default_factory=list)

    def should_include(self, severity: Severity) -> bool:
        """Return True if a finding at this severity should be reported."""
        return severity >= self.min_severity

    def effective_severity(self, rule_id: str, base_severity: Severity) -> Severity:
        """Return the effective severity for a rule, applying overrides."""
        return self.severity_overrides.get(rule_id, base_severity)


def load_profile(name: str) -> Profile:
    """Load a scan profile by name.

    Args:
        name: Profile name (e.g., "hobby", "saas").

    Returns:
        A Profile object.

    Raises:
        FileNotFoundError: If the profile JSON file does not exist.
        ValueError: If the profile JSON is invalid.
    """
    profile_path = _PROFILES_DIR / f"{name}.json"

    if not profile_path.exists():
        available = ", ".join(AVAILABLE_PROFILES)
        raise FileNotFoundError(
            f"Profile '{name}' not found at {profile_path}.\n"
            f"Available profiles: {available}"
        )

    with open(profile_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Parse severity overrides from string -> Severity enum
    overrides: dict[str, Severity] = {}
    for rule_id, sev_name in data.get("severity_overrides", {}).items():
        if sev_name in SEVERITY_MAP:
            overrides[rule_id] = SEVERITY_MAP[sev_name]

    min_sev_name = data.get("min_severity", "LOW")
    min_severity = SEVERITY_MAP.get(min_sev_name, Severity.LOW)

    return Profile(
        name=data.get("name", name),
        description=data.get("description", ""),
        min_severity=min_severity,
        severity_overrides=overrides,
        enabled_rule_prefixes=data.get("enabled_rule_prefixes", []),
    )
