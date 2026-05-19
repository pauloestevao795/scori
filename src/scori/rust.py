"""Rust / crates.io ecosystem adapter for scori.

Thin adapter over the shared friction algorithm:
  - scan_rust()                   discovers dependencies from Cargo.toml files
  - compute_rust()                returns a FrictionResult using crates.io data
  - load_transitive_counts_rust() counts reverse deps from Cargo.lock

The crates.io API requires a User-Agent header identifying the caller.
OSV advisory data uses ecosystem="crates.io" (covers RustSec advisories).
"""

from __future__ import annotations

import json
import re
import time
import tomllib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import requests

from ._types import Dependency, FrictionResult
from .friction import (
    CACHE_DIR,
    CACHE_TTL_SECONDS,
    _fetch_github_changelog,
    _fetch_github_releases,
    _fetch_osv,
    _label,
    _scan_breaking,
    _version_jump,
)

_SKIP_DIRS = frozenset({
    "target", ".git", "node_modules", ".venv", "dist", "build",
    "__pycache__", ".tox", ".nox",
})

_SCORI_UA = "scori/1.2.0 (https://github.com/pauloestevao795/scori)"


# ---------------------------------------------------------------------------
# manifest scanner
# ---------------------------------------------------------------------------


def scan_rust(project_path: str | Path) -> list[Dependency]:
    """Discover dependencies from Cargo.toml files under project_path."""
    root = Path(project_path)
    deps: list[Dependency] = []
    seen: set[str] = set()

    for manifest in sorted(root.rglob("Cargo.toml")):
        if any(part in _SKIP_DIRS for part in manifest.parts):
            continue
        try:
            for dep in _from_cargo_toml(manifest):
                key = dep["name"].lower()
                if key not in seen:
                    seen.add(key)
                    deps.append(dep)
        except (OSError, tomllib.TOMLDecodeError):
            continue
    return deps


def _from_cargo_toml(path: Path) -> list[Dependency]:
    """Parse registry dependencies from a Cargo.toml file."""
    data: dict[str, Any] = tomllib.loads(path.read_text(encoding="utf-8"))
    deps: list[Dependency] = []

    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        for name, spec in (data.get(section) or {}).items():
            if isinstance(spec, dict):
                # Skip path and git deps — they are not from crates.io
                if "path" in spec or "git" in spec:
                    continue
                version_spec = str(spec.get("version") or "")
            elif isinstance(spec, str):
                version_spec = spec
            else:
                continue
            deps.append(Dependency(
                name=name,
                version_spec=version_spec,
                source_file="Cargo.toml",
            ))
    return deps


# ---------------------------------------------------------------------------
# version resolution
# ---------------------------------------------------------------------------


def _resolve_version_rust(
    name: str, version_spec: str, project_root: Path | None
) -> str:
    """Resolve installed version from Cargo.lock, or fall back to spec."""
    if project_root is not None:
        v = _from_cargo_lock(name, project_root)
        if v:
            return v
    # Strip Cargo semver requirement operators (^, ~, >=, =, etc.)
    clean = re.sub(r"[^0-9.]", "", version_spec.split(",")[0])
    if clean and re.match(r"^\d+\.", clean):
        return clean
    return "0.0.0"


def _from_cargo_lock(name: str, root: Path) -> str:
    """Return the resolved version for a crate from any Cargo.lock under root."""
    for lock in sorted(root.rglob("Cargo.lock")):
        if any(part in _SKIP_DIRS for part in lock.parts):
            continue
        try:
            data: dict[str, Any] = tomllib.loads(lock.read_text(encoding="utf-8"))
        except (tomllib.TOMLDecodeError, OSError):
            continue
        for pkg in data.get("package") or []:
            if (pkg.get("name") or "").lower() != name.lower():
                continue
            source = str(pkg.get("source") or "")
            # Accept registry packages (crates.io uses registry+ or sparse+)
            if source.startswith("registry+") or source.startswith("sparse+") or source == "":
                v = str(pkg.get("version") or "")
                if v:
                    return v
    return ""


# ---------------------------------------------------------------------------
# transitive dependency counts
# ---------------------------------------------------------------------------


def load_transitive_counts_rust(project_root: Path) -> dict[str, int]:
    """Count reverse deps from Cargo.lock dependency lists."""
    counts: dict[str, int] = {}
    for lock in sorted(project_root.rglob("Cargo.lock")):
        if any(part in _SKIP_DIRS for part in lock.parts):
            continue
        try:
            data: dict[str, Any] = tomllib.loads(lock.read_text(encoding="utf-8"))
        except (tomllib.TOMLDecodeError, OSError):
            continue
        for pkg in data.get("package") or []:
            for dep_entry in pkg.get("dependencies") or []:
                # Entry can be "name", "name version", or "name version (url)"
                dep_name = str(dep_entry).split()[0].lower()
                counts[dep_name] = counts.get(dep_name, 0) + 1
    return counts


# ---------------------------------------------------------------------------
# crates.io API client
# ---------------------------------------------------------------------------


def _rust_cache_path(name: str) -> Path:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9_.\-]", "_", name)
    return CACHE_DIR / f"rust_{safe}.json"


def _rust_cache_read(name: str) -> dict[str, Any] | None:
    path = _rust_cache_path(name)
    if not path.exists():
        return None
    if time.time() - path.stat().st_mtime > CACHE_TTL_SECONDS:
        return None
    try:
        return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))
    except json.JSONDecodeError:
        return None


def _rust_cache_write(name: str, payload: dict[str, Any]) -> None:
    _rust_cache_path(name).write_text(json.dumps(payload), encoding="utf-8")


def _fetch_rust(name: str) -> dict[str, Any]:
    """Fetch crates.io metadata + GitHub releases, with local cache."""
    cached = _rust_cache_read(name)
    if cached is not None:
        return cached

    try:
        r = requests.get(
            f"https://crates.io/api/v1/crates/{name}",
            headers={"User-Agent": _SCORI_UA},
            timeout=10,
        )
        r.raise_for_status()
        data: dict[str, Any] = r.json()
    except (requests.RequestException, ValueError):
        data = {}

    crate: dict[str, Any] = data.get("crate") or {}
    latest_version = str(
        crate.get("max_stable_version") or crate.get("newest_version") or "0.0.0"
    )

    version_times: dict[str, str] = {}
    yanked_versions: list[str] = []
    for v in data.get("versions") or []:
        num = str(v.get("num") or "")
        if not num:
            continue
        t = str(v.get("created_at") or "")
        if t:
            version_times[num] = t
        if v.get("yanked"):
            yanked_versions.append(num)

    repo_url = str(crate.get("repository") or "")
    owner_repo: tuple[str, str] | None = None
    if repo_url:
        m = re.search(r"github\.com/([^/]+)/([^/#?\.]+)", repo_url)
        if m:
            owner_repo = (m.group(1), m.group(2).removesuffix(".git"))

    releases: list[dict[str, Any]] = []
    changelog = ""
    if owner_repo is not None:
        try:
            releases = _fetch_github_releases(*owner_repo)
        except requests.RequestException:
            pass
        try:
            changelog = _fetch_github_changelog(*owner_repo)
        except requests.RequestException:
            pass

    payload: dict[str, Any] = {
        "crate": {
            "name": crate.get("name") or name,
            "latest_version": latest_version,
            "version_times": version_times,
            "yanked_versions": yanked_versions,
        },
        "releases": releases,
        "changelog": changelog,
    }
    _rust_cache_write(name, payload)
    return payload


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _rust_months_outdated(crate_data: dict[str, Any], version: str) -> float:
    t = (crate_data.get("version_times") or {}).get(version) or ""
    if not t:
        return 0.0
    try:
        published = datetime.fromisoformat(t.rstrip("Z")).replace(tzinfo=UTC)
        return (datetime.now(UTC) - published).days / 30.44
    except (ValueError, TypeError):
        return 0.0


def _rust_is_yanked(crate_data: dict[str, Any], version: str) -> bool:
    return version in (crate_data.get("yanked_versions") or [])


# ---------------------------------------------------------------------------
# compute
# ---------------------------------------------------------------------------


def compute_rust(
    dep: Dependency,
    transitive_affected: int = 0,
    project_root: Path | None = None,
) -> FrictionResult:
    """Compute FrictionResult for a Rust (crates.io) dependency."""
    data = _fetch_rust(dep["name"])
    crate: dict[str, Any] = data["crate"]
    releases: list[dict[str, Any]] = data["releases"]
    changelog: str = data.get("changelog") or ""

    latest = crate.get("latest_version") or "0.0.0"
    current = _resolve_version_rust(dep["name"], dep["version_spec"], project_root)

    jump, jump_pts = _version_jump(current, latest)
    signals = _scan_breaking(releases, current, latest, changelog)
    signal_pts = min(20, 4 * len(signals))
    transitive_pts = min(15, 3 * transitive_affected)
    months = _rust_months_outdated(crate, current)
    months_pts = min(10, int(months))
    yanked = _rust_is_yanked(crate, current)
    yanked_pts = 5 if yanked else 0

    if current not in ("0.0.0", ""):
        cve_current_total, cve_current_w, cwe_ids = _fetch_osv(
            dep["name"], current, ecosystem="crates.io"
        )
    else:
        cve_current_total, cve_current_w, cwe_ids = -1, -1, []
    cve_latest_total, cve_latest_w, _ = _fetch_osv(
        dep["name"], latest, ecosystem="crates.io"
    )

    fixed_weighted = max(0, cve_current_w - cve_latest_w) if cve_current_w > 0 else 0
    cve_pts = min(15, fixed_weighted * 3)

    score = min(
        100,
        jump_pts + signal_pts + transitive_pts + months_pts + yanked_pts + cve_pts,
    )
    label, recommendation = _label(score)

    return FrictionResult(
        name=dep["name"],
        current_version=current,
        latest_version=latest,
        score=score,
        label=label,
        version_jump=jump,
        breaking_signals=signals,
        transitive_affected=transitive_affected,
        months_outdated=months,
        yanked=yanked,
        recommendation=recommendation,
        cve_current=cve_current_total,
        cve_latest=cve_latest_total,
        cwe_ids=cwe_ids,
        alternatives=[],
    )
