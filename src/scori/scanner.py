"""Dependency manifest reader.

Supported formats:
    * requirements.txt
    * pyproject.toml (PEP 621 + PEP 735 dependency-groups)
    * setup.cfg ([options].install_requires)

TODO v0.2: support poetry.lock and uv.lock — required to resolve
the real transitive tree and populate the ``transitive_affected``
field of FrictionResult with accurate data instead of the default 0.
"""

from __future__ import annotations

import configparser
import re
import tomllib
from pathlib import Path
from typing import Any

from ._types import Dependency

# Simplified PEP 508 regex: captures name + version specifier.
_REQ_RE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9_.\-]+)\s*(?P<spec>[<>=!~][^;#\s]*)?",
)


def _parse_req_line(line: str, source: str) -> Dependency | None:
    """Convert a simple PEP 508 line into a Dependency."""
    cleaned = line.split("#", 1)[0].strip()
    if not cleaned or cleaned.startswith("-"):
        return None
    m = _REQ_RE.match(cleaned)
    if not m:
        return None
    return Dependency(
        name=m.group("name"),
        version_spec=(m.group("spec") or "").strip(),
        source_file=source,
    )


def _from_requirements_txt(path: Path) -> list[Dependency]:
    deps: list[Dependency] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        dep = _parse_req_line(line, path.name)
        if dep is not None:
            deps.append(dep)
    return deps


def _from_pyproject(path: Path) -> list[Dependency]:
    data: dict[str, Any] = tomllib.loads(path.read_text(encoding="utf-8"))
    raw: list[str] = []

    project = data.get("project") or {}
    raw.extend(project.get("dependencies") or [])
    for group in (project.get("optional-dependencies") or {}).values():
        raw.extend(group)

    # PEP 735 — dependency-groups
    for group in (data.get("dependency-groups") or {}).values():
        raw.extend(group)

    deps: list[Dependency] = []
    for line in raw:
        dep = _parse_req_line(line, path.name)
        if dep is not None:
            deps.append(dep)
    return deps


def _from_setup_cfg(path: Path) -> list[Dependency]:
    cp = configparser.ConfigParser()
    cp.read(path, encoding="utf-8")
    raw: list[str] = []
    if cp.has_option("options", "install_requires"):
        raw.extend(cp.get("options", "install_requires").splitlines())
    deps: list[Dependency] = []
    for line in raw:
        dep = _parse_req_line(line, path.name)
        if dep is not None:
            deps.append(dep)
    return deps


_SKIP_DIRS = frozenset({
    ".venv", "venv", "env", ".env",
    "node_modules", "site-packages", "dist-packages",
    "__pycache__", ".git", ".tox", ".nox", "build", "dist",
    ".eggs", "*.egg-info",
})

_PARSERS: dict[str, Any] = {
    "pyproject.toml": _from_pyproject,
    "setup.cfg": _from_setup_cfg,
}


def _req_glob(root: Path) -> list[Path]:
    """Return all requirements*.txt files under root, excluding venv dirs."""
    results = []
    for p in root.rglob("requirements*.txt"):
        if not any(part in _SKIP_DIRS for part in p.parts):
            results.append(p)
    return results


def scan(project_path: str | Path) -> list[Dependency]:
    """Read all supported manifests under ``project_path``, recursively.

    Skips virtual-environment and build artifact directories so that
    packages installed in .venv/site-packages are not mistaken for
    direct dependencies.
    """
    root = Path(project_path)
    deps: list[Dependency] = []
    seen_names: set[str] = set()

    def _add(new_deps: list[Dependency]) -> None:
        for d in new_deps:
            key = d["name"].lower()
            if key not in seen_names:
                seen_names.add(key)
                deps.append(d)

    # requirements*.txt — recurse
    for req_path in sorted(_req_glob(root)):
        _add(_from_requirements_txt(req_path))

    # pyproject.toml / setup.cfg — recurse, skip venv dirs
    for fname, parser in _PARSERS.items():
        for manifest in sorted(root.rglob(fname)):
            if any(part in _SKIP_DIRS for part in manifest.parts):
                continue
            _add(parser(manifest))

    return deps
