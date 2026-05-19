"""scori — Software Composition Risk Intelligence.

Score the real cost of updating a dependency.

Stable public API (guaranteed not to change in 1.x releases):
    Dependency      — TypedDict describing a declared dependency
    FrictionResult  — TypedDict with the full scored result
    FrictionLabel   — Literal["Low", "Medium", "High", "Critical"]
    VersionJump     — Literal["patch", "minor", "major", "unknown"]
    compute()       — score a single Dependency → FrictionResult
    scan()          — discover all dependencies in a project tree
"""

from .friction import compute
from .scanner import scan
from ._types import Dependency, FrictionLabel, FrictionResult, VersionJump

__version__ = "1.1.0"
__all__ = [
    "__version__",
    "compute",
    "scan",
    "Dependency",
    "FrictionLabel",
    "FrictionResult",
    "VersionJump",
]
