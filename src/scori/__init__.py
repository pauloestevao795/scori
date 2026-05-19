"""scori — Software Composition Risk Intelligence.

Score the real cost of updating a dependency.

Stable public API (guaranteed not to change in 1.x releases):
    Dependency      — TypedDict describing a declared dependency
    FrictionResult  — TypedDict with the full scored result
    FrictionLabel   — Literal["Low", "Medium", "High", "Critical"]
    VersionJump     — Literal["patch", "minor", "major", "unknown"]
    compute()       — score a single Python dependency → FrictionResult
    compute_npm()   — score a single npm dependency → FrictionResult
    compute_go()    — score a single Go module dependency → FrictionResult
    compute_rust()  — score a single Rust (crates.io) dependency → FrictionResult
    scan()          — discover Python dependencies in a project tree
    scan_npm()      — discover npm dependencies in a project tree
    scan_go()       — discover Go dependencies in a project tree
    scan_rust()     — discover Rust dependencies in a project tree
    scan_all()      — discover all supported ecosystems in a project tree
"""

from .friction import compute
from .npm import compute_npm, scan_npm
from .golang import compute_go, scan_go
from .rust import compute_rust, scan_rust
from .scanner import scan, scan_all
from ._types import Dependency, FrictionLabel, FrictionResult, VersionJump

__version__ = "1.2.0"
__all__ = [
    "__version__",
    "compute",
    "compute_npm",
    "compute_go",
    "compute_rust",
    "scan",
    "scan_all",
    "scan_npm",
    "scan_go",
    "scan_rust",
    "Dependency",
    "FrictionLabel",
    "FrictionResult",
    "VersionJump",
]
