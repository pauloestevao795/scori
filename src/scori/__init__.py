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
from .npm import compute_npm, scan_npm
from .scanner import scan, scan_all
from ._types import Dependency, FrictionLabel, FrictionResult, VersionJump

__version__ = "1.1.1"
__all__ = [
    "__version__",
    "compute",
    "compute_npm",
    "scan",
    "scan_all",
    "scan_npm",
    "Dependency",
    "FrictionLabel",
    "FrictionResult",
    "VersionJump",
]
