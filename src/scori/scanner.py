"""Dependency manifest reader.

Supported formats:
    * requirements.txt
    * pyproject.toml (PEP 621 + PEP 735 dependency-groups)
    * setup.cfg ([options].install_requires)
    * Pipfile (TOML — [packages] and [dev-packages])
    * environment.yml / conda.yml (conda environment files)
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


def _from_pipfile(path: Path) -> list[Dependency]:
    data: dict[str, Any] = tomllib.loads(path.read_text(encoding="utf-8"))
    deps: list[Dependency] = []
    for section in ("packages", "dev-packages"):
        for name, spec in (data.get(section) or {}).items():
            if isinstance(spec, dict):
                spec = spec.get("version", "*")
            version_spec = "" if spec == "*" else spec
            deps.append(
                Dependency(name=name, version_spec=version_spec, source_file=path.name)
            )
    return deps


# Matches conda dep lines: name[=version] or name[>=version] etc.
_CONDA_DEP_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9_.\-]+)\s*(?P<spec>(?:[<>!]=?|==?)[^\s#;]*)?"
)


def _parse_conda_dep(entry: str, source: str) -> Dependency | None:
    entry = entry.split("#", 1)[0].strip()
    if not entry or ":" in entry:
        return None
    m = _CONDA_DEP_RE.match(entry)
    if not m:
        return None
    name = m.group("name")
    if name.lower() == "python":
        return None
    spec = (m.group("spec") or "").strip()
    # conda uses single = as exact pinning; normalise to ==
    if spec and re.match(r"^=[^=]", spec):
        spec = "=" + spec
    return Dependency(name=name, version_spec=spec, source_file=source)


def _from_conda_yml(path: Path) -> list[Dependency]:
    deps: list[Dependency] = []
    in_deps = False
    in_pip = False

    for line in path.read_text(encoding="utf-8").splitlines():
        if not in_deps:
            if line.rstrip() == "dependencies:":
                in_deps = True
            continue

        if not line.strip():
            continue

        # Top-level YAML key ends the dependencies block
        if line[0] != " " and line.strip().endswith(":"):
            break

        # pip: sub-section marker (e.g. "  - pip:")
        if re.match(r"^\s+-\s+pip:\s*$", line):
            in_pip = True
            continue

        # pip sub-items are more deeply indented than top-level deps
        if in_pip and re.match(r"^\s{4,}-\s+", line):
            entry = re.sub(r"^\s+-\s+", "", line).strip()
            dep = _parse_req_line(entry, path.name)
            if dep is not None:
                deps.append(dep)
            continue

        # Regular conda dep (2-space indent)
        if re.match(r"^\s{2}-\s+", line):
            in_pip = False
            entry = re.sub(r"^\s+-\s+", "", line).strip()
            dep = _parse_conda_dep(entry, path.name)
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
    "Pipfile": _from_pipfile,
}

_CONDA_FILENAMES = frozenset({
    "environment.yml", "environment.yaml",
    "conda.yml", "conda.yaml",
})


def _req_glob(root: Path) -> list[Path]:
    """Return all requirements*.txt files under root, excluding venv dirs."""
    results = []
    for p in root.rglob("requirements*.txt"):
        if not any(part in _SKIP_DIRS for part in p.parts):
            results.append(p)
    return results


def _conda_glob(root: Path) -> list[Path]:
    """Return all conda environment YAML files under root, excluding venv dirs."""
    results = []
    for fname in _CONDA_FILENAMES:
        for p in root.rglob(fname):
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

    # pyproject.toml / setup.cfg / Pipfile — recurse, skip venv dirs
    for fname, parser in _PARSERS.items():
        for manifest in sorted(root.rglob(fname)):
            if any(part in _SKIP_DIRS for part in manifest.parts):
                continue
            _add(parser(manifest))

    # conda environment YAML files
    for conda_path in sorted(_conda_glob(root)):
        _add(_from_conda_yml(conda_path))

    return deps


def scan_all(project_path: str | Path) -> list[Dependency]:
    """Scan all supported ecosystems (Python + npm + Go + Rust) under project_path.

    Combines manifests from all ecosystems without cross-ecosystem deduplication —
    a package name can exist in multiple registries and each is a distinct entry.
    Within each ecosystem, duplicates are still suppressed.
    """
    from .golang import scan_go
    from .npm import scan_npm  # lazy imports to avoid circular deps
    from .rust import scan_rust

    return (
        scan(project_path)
        + scan_npm(project_path)
        + scan_go(project_path)
        + scan_rust(project_path)
    )
