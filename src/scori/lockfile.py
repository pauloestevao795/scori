"""Parse uv.lock and poetry.lock to count reverse dependencies.

The transitive_affected metric answers: if I update package X, how many
other packages in the lockfile also depend on X? A high reverse-dep count
means the update has a wider blast radius — more packages may need
re-testing or adjustment.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _rdep_counts(packages: list[dict[str, object]]) -> dict[str, int]:
    """Build {normalized_name: reverse_dep_count} from a package list.

    Works for both uv.lock (deps as list of dicts) and poetry.lock
    (deps as dict of name→constraint).
    """
    rdeps: dict[str, set[str]] = {}
    for pkg in packages:
        name = _normalize(str(pkg.get("name") or ""))
        if not name:
            continue
        deps = pkg.get("dependencies", [])
        if isinstance(deps, list):
            # uv.lock: [{"name": "requests"}, ...]
            for dep in deps:
                if isinstance(dep, dict):
                    dep_name = _normalize(str(dep.get("name") or ""))
                    if dep_name:
                        rdeps.setdefault(dep_name, set()).add(name)
        elif isinstance(deps, dict):
            # poetry.lock: {"requests": "^2.28", ...}
            for dep_name in deps:
                dep_norm = _normalize(str(dep_name))
                if dep_norm:
                    rdeps.setdefault(dep_norm, set()).add(name)
    return {k: len(v) for k, v in rdeps.items()}


def parse_uv_lock(path: Path) -> dict[str, int]:
    """Return {normalized_name: reverse_dep_count} from a uv.lock file."""
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    pkgs: list[dict[str, object]] = data.get("package", [])
    return _rdep_counts(pkgs)


def parse_poetry_lock(path: Path) -> dict[str, int]:
    """Return {normalized_name: reverse_dep_count} from a poetry.lock file."""
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    pkgs: list[dict[str, object]] = data.get("package", [])
    return _rdep_counts(pkgs)


def load_transitive_counts(project_root: Path) -> dict[str, int]:
    """Try uv.lock then poetry.lock; return {} if neither is present."""
    for lockfile, parser in (
        (project_root / "uv.lock", parse_uv_lock),
        (project_root / "poetry.lock", parse_poetry_lock),
    ):
        if lockfile.exists():
            try:
                return parser(lockfile)
            except Exception:
                pass
    return {}
