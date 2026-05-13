"""Per-project .scori.toml configuration loading."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

_PROFILE_THRESHOLDS: dict[str, int] = {
    "conservative": 50,
    "balanced": 75,
    "aggressive": 90,
}

_DEFAULT_PROFILE = "balanced"
_DEFAULT_THRESHOLD = 75


def _normalize_package(name: str) -> str:
    """Normalize package name: lowercase, hyphens instead of underscores/dots."""
    return name.lower().replace("_", "-").replace(".", "-")


@dataclass
class ScoriConfig:
    threshold: int = _DEFAULT_THRESHOLD
    profile: str = _DEFAULT_PROFILE
    ignore: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, project_root: Path) -> ScoriConfig:
        """Load config from .scori.toml in project_root.

        Returns defaults if the file does not exist or is malformed.
        """
        config_path = project_root / ".scori.toml"
        if not config_path.exists():
            return cls()

        try:
            raw = tomllib.loads(config_path.read_text(encoding="utf-8"))
        except (tomllib.TOMLDecodeError, OSError):
            return cls()

        scori_section = raw.get("scori", {})
        if not isinstance(scori_section, dict):
            return cls()

        profile = scori_section.get("profile", _DEFAULT_PROFILE)
        if profile not in _PROFILE_THRESHOLDS:
            profile = _DEFAULT_PROFILE

        # Profile sets the default threshold; explicit threshold overrides it
        default_threshold = _PROFILE_THRESHOLDS[profile]
        threshold_raw = scori_section.get("threshold", default_threshold)
        try:
            threshold = int(threshold_raw)
        except (TypeError, ValueError):
            threshold = default_threshold

        ignore_section = raw.get("ignore", {})
        if not isinstance(ignore_section, dict):
            ignore_section = {}

        packages_raw = ignore_section.get("packages", [])
        if not isinstance(packages_raw, list):
            packages_raw = []

        ignore = [
            _normalize_package(str(p)) for p in packages_raw if isinstance(p, str) and p
        ]

        return cls(threshold=threshold, profile=profile, ignore=ignore)
