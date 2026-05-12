"""Shared types across scori modules."""

from typing import Literal, TypedDict

FrictionLabel = Literal["Low", "Medium", "High", "Critical"]
VersionJump = Literal["patch", "minor", "major", "unknown"]


class Dependency(TypedDict):
    name: str
    version_spec: str  # e.g. ">=2.0,<3.0"; empty means unpinned
    source_file: str  # e.g. "pyproject.toml"


class FrictionResult(TypedDict):
    name: str
    current_version: str
    latest_version: str
    score: int  # 0–100
    label: FrictionLabel
    version_jump: VersionJump
    breaking_signals: list[str]
    transitive_affected: int
    months_outdated: float
    yanked: bool
    recommendation: str
    cve_current: int  # CVEs in current version (-1 = version unresolved)
    cve_latest: int  # CVEs in latest version
    alternatives: list[str]  # suggested replacements when CVEs have no fix
