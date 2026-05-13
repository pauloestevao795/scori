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


# ------------------------------ conflict detection ------------------------------


def _parse_uv_dep_graph(path: Path) -> dict[str, set[str]]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    graph: dict[str, set[str]] = {}
    for pkg in data.get("package", []):
        name = _normalize(str(pkg.get("name") or ""))
        if not name:
            continue
        deps = pkg.get("dependencies", [])
        graph[name] = {
            _normalize(str(d.get("name") or ""))
            for d in (deps if isinstance(deps, list) else [])
            if isinstance(d, dict) and d.get("name")
        }
    return graph


def _parse_poetry_dep_graph(path: Path) -> dict[str, set[str]]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    graph: dict[str, set[str]] = {}
    for pkg in data.get("package", []):
        name = _normalize(str(pkg.get("name") or ""))
        if not name:
            continue
        deps = pkg.get("dependencies", {})
        graph[name] = (
            {_normalize(str(d)) for d in deps} if isinstance(deps, dict) else set()
        )
    return graph


def _build_dep_graph(project_root: Path) -> dict[str, set[str]]:
    for lockfile, parser in (
        (project_root / "uv.lock", _parse_uv_dep_graph),
        (project_root / "poetry.lock", _parse_poetry_dep_graph),
    ):
        if lockfile.exists():
            try:
                return parser(lockfile)
            except Exception:
                pass
    return {}


def _transitive_deps(graph: dict[str, set[str]], start: str) -> set[str]:
    """BFS to collect all transitive dependencies of start."""
    visited: set[str] = set()
    queue = list(graph.get(start, set()))
    while queue:
        node = queue.pop()
        if node in visited:
            continue
        visited.add(node)
        queue.extend(graph.get(node, set()))
    return visited


def detect_update_conflicts(
    project_root: Path,
    packages: list[str],
) -> list[str]:
    """Detect pairs of packages that share transitive dependencies.

    When two packages in the same update batch share a transitive dep, updating
    them simultaneously may trigger cascading changes in that shared dep.
    Returns human-readable warning strings (one per conflicting pair).
    """
    if len(packages) < 2:
        return []
    graph = _build_dep_graph(project_root)
    if not graph:
        return []

    normed = [_normalize(p) for p in packages]
    trans = {p: _transitive_deps(graph, p) for p in normed}

    warnings: list[str] = []
    seen: set[frozenset[str]] = set()
    for i, a in enumerate(normed):
        for b in normed[i + 1 :]:
            pair: frozenset[str] = frozenset({a, b})
            if pair in seen:
                continue
            seen.add(pair)
            shared = trans[a] & trans[b]
            if not shared:
                continue
            top = sorted(shared)[:3]
            suffix = " and more" if len(shared) > 3 else ""
            warnings.append(
                f"{a} + {b} share transitive deps ({', '.join(top)}{suffix})"
                " — update and test together"
            )
    return warnings
