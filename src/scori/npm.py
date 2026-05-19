"""Node.js / npm ecosystem adapter for scori.

Thin adapter over the shared friction algorithm:
  - scan_npm()      discovers dependencies from package.json files
  - compute_npm()   returns a FrictionResult using npm registry data
  - load_transitive_counts_npm()  counts reverse deps from package-lock.json

The scoring components are identical to the Python adapter (version jump,
breaking signals, transitive deps, CVEs via OSV, months outdated, deprecated).
"""

from __future__ import annotations

import json
import re
import time
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
    "node_modules", ".git", ".venv", "dist", "build",
    "__pycache__", ".tox", ".nox",
})


# ---------------------------------------------------------------------------
# manifest scanner
# ---------------------------------------------------------------------------


def scan_npm(project_path: str | Path) -> list[Dependency]:
    """Discover dependencies from package.json files under project_path."""
    root = Path(project_path)
    deps: list[Dependency] = []
    seen: set[str] = set()

    for manifest in sorted(root.rglob("package.json")):
        if any(part in _SKIP_DIRS for part in manifest.parts):
            continue
        try:
            data: dict[str, Any] = json.loads(manifest.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        for section in ("dependencies", "devDependencies"):
            for name, spec in (data.get(section) or {}).items():
                key = name.lower()
                if key not in seen:
                    seen.add(key)
                    deps.append(Dependency(
                        name=name,
                        version_spec=spec if isinstance(spec, str) else "",
                        source_file=manifest.name,
                    ))
    return deps


# ---------------------------------------------------------------------------
# version resolution
# ---------------------------------------------------------------------------


def _resolve_version_npm(
    name: str, version_spec: str, project_root: Path | None
) -> str:
    """Resolve installed version from lockfiles, node_modules, or spec."""
    if project_root is not None:
        v = _from_package_lock(name, project_root)
        if v:
            return v[0]
        v = _from_yarn_lock(name, project_root)
        if v:
            return v[0]
        v = _from_pnpm_lock(name, project_root)
        if v:
            return v[0]
        nm_pkg = project_root / "node_modules" / name / "package.json"
        if nm_pkg.exists():
            try:
                d: dict[str, Any] = json.loads(nm_pkg.read_text(encoding="utf-8"))
                ver = d.get("version") or ""
                if ver:
                    return str(ver)
            except (json.JSONDecodeError, OSError):
                pass

    # Strip semver range operators to get the lower-bound version
    clean = re.sub(r"[~^>=<\s]", "", version_spec.split(" ")[0])
    if clean and re.match(r"^\d+\.", clean):
        return clean
    return "0.0.0"


def _from_package_lock(name: str, root: Path) -> list[str]:
    """Resolve version from package-lock.json (supports v1, v2, v3)."""
    lock = root / "package-lock.json"
    if not lock.exists():
        return []
    try:
        data: dict[str, Any] = json.loads(lock.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    if (data.get("lockfileVersion") or 1) >= 2:
        pkgs = data.get("packages") or {}
        entry = pkgs.get(f"node_modules/{name}") or pkgs.get(name)
        if entry and entry.get("version"):
            return [str(entry["version"])]
    deps = data.get("dependencies") or {}
    entry = deps.get(name)
    if entry and entry.get("version"):
        return [str(entry["version"])]
    return []


def _from_yarn_lock(name: str, root: Path) -> list[str]:
    """Resolve version from yarn.lock (classic v1 and berry v2 formats)."""
    lock = root / "yarn.lock"
    if not lock.exists():
        return []
    try:
        text = lock.read_text(encoding="utf-8")
    except OSError:
        return []
    in_block = False
    for line in text.splitlines():
        if not in_block:
            # Block header contains the package name followed by @spec:
            if re.search(r'"?' + re.escape(name) + r'@', line) and line.rstrip().endswith(":"):
                in_block = True
        else:
            m = re.match(r'\s+version\s+"?([^\s"]+)"?', line)
            if m:
                return [m.group(1)]
            if line and not line[0].isspace():
                in_block = False
    return []


def _from_pnpm_lock(name: str, root: Path) -> list[str]:
    """Resolve version from pnpm-lock.yaml (v6, v8, v9 formats)."""
    lock = root / "pnpm-lock.yaml"
    if not lock.exists():
        return []
    try:
        text = lock.read_text(encoding="utf-8")
    except OSError:
        return []
    # Matches: "  /express@4.18.2:" or "  express@4.18.2:" or "  /@scope/pkg@1.0.0:"
    pattern = re.compile(
        r"^\s+/?" + re.escape(name) + r"@(\d[^\s:{]+)",
        re.MULTILINE,
    )
    m = pattern.search(text)
    if m:
        return [m.group(1)]
    return []


# ---------------------------------------------------------------------------
# transitive dependency counts
# ---------------------------------------------------------------------------


def load_transitive_counts_npm(project_root: Path) -> dict[str, int]:
    """Count reverse deps (packages that list each dep) from package-lock.json."""
    lock = project_root / "package-lock.json"
    if not lock.exists():
        return {}
    try:
        data: dict[str, Any] = json.loads(lock.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    counts: dict[str, int] = {}
    for info in (data.get("packages") or {}).values():
        for dep_name in (info.get("dependencies") or {}):
            key = dep_name.lower()
            counts[key] = counts.get(key, 0) + 1
    return counts


# ---------------------------------------------------------------------------
# npm registry client
# ---------------------------------------------------------------------------


def _npm_cache_path(package: str) -> Path:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9_.\-]", "_", package)
    return CACHE_DIR / f"npm_{safe}.json"


def _npm_cache_read(package: str) -> dict[str, Any] | None:
    path = _npm_cache_path(package)
    if not path.exists():
        return None
    if time.time() - path.stat().st_mtime > CACHE_TTL_SECONDS:
        return None
    try:
        return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))
    except json.JSONDecodeError:
        return None


def _npm_cache_write(package: str, payload: dict[str, Any]) -> None:
    _npm_cache_path(package).write_text(json.dumps(payload), encoding="utf-8")


def _fetch_npm(package: str) -> dict[str, Any]:
    """Fetch npm registry metadata + GitHub releases, with local cache."""
    cached = _npm_cache_read(package)
    if cached is not None:
        return cached

    url = f"https://registry.npmjs.org/{package}"
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        data = cast(dict[str, Any], r.json())
    except (requests.RequestException, ValueError):
        return {"npm": {}, "releases": [], "changelog": "", "_unavailable": True}

    # Extract GitHub repo URL from repository field
    repo_raw = data.get("repository") or {}
    repo_url = repo_raw.get("url") if isinstance(repo_raw, dict) else str(repo_raw)
    owner_repo: tuple[str, str] | None = None
    if repo_url:
        m = re.search(r"github\.com/([^/]+)/([^/#?\.]+)", str(repo_url))
        if m:
            owner_repo = (m.group(1), m.group(2).removesuffix(".git"))

    releases: list[dict[str, Any]] = []
    changelog = ""
    if owner_repo is not None:
        try:
            releases = _fetch_github_releases(*owner_repo)
        except requests.RequestException:
            releases = []
        try:
            changelog = _fetch_github_changelog(*owner_repo)
        except requests.RequestException:
            changelog = ""

    # Store a trimmed payload — skip the full versions dict (can be >1 MB)
    # Keep only deprecated version names to check yanked status cheaply.
    deprecated_versions = [
        ver
        for ver, vdata in (data.get("versions") or {}).items()
        if (vdata or {}).get("deprecated")
    ]
    payload: dict[str, Any] = {
        "npm": {
            "name": data.get("name"),
            "dist-tags": data.get("dist-tags"),
            "time": data.get("time"),
            "repository": data.get("repository"),
            "deprecated_versions": deprecated_versions,
        },
        "releases": releases,
        "changelog": changelog,
    }
    _npm_cache_write(package, payload)
    return payload


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _npm_months_outdated(npm_data: dict[str, Any], current: str) -> float:
    time_field = npm_data.get("time") or {}
    pub = time_field.get(current)
    if not pub:
        return 0.0
    try:
        published = datetime.fromisoformat(pub.rstrip("Z")).replace(tzinfo=UTC)
        return (datetime.now(UTC) - published).days / 30.44
    except (ValueError, TypeError):
        return 0.0


def _npm_is_deprecated(npm_data: dict[str, Any], version: str) -> bool:
    return version in (npm_data.get("deprecated_versions") or [])


# ---------------------------------------------------------------------------
# compute
# ---------------------------------------------------------------------------


def compute_npm(
    dep: Dependency,
    transitive_affected: int = 0,
    project_root: Path | None = None,
) -> FrictionResult:
    """Compute FrictionResult for an npm dependency."""
    data = _fetch_npm(dep["name"])

    if data.get("_unavailable"):
        current = _resolve_version_npm(dep["name"], dep["version_spec"], project_root)
        return FrictionResult(
            name=dep["name"],
            current_version=current,
            latest_version=current,
            score=0,
            label="Low",
            version_jump="unknown",
            breaking_signals=[],
            transitive_affected=transitive_affected,
            months_outdated=0.0,
            yanked=False,
            recommendation="Registry unavailable — retry when network is restored",
            cve_current=-1,
            cve_latest=-1,
            cwe_ids=[],
            alternatives=[],
        )

    npm: dict[str, Any] = data["npm"]
    releases: list[dict[str, Any]] = data["releases"]
    changelog: str = data.get("changelog") or ""

    dist_tags = npm.get("dist-tags") or {}
    latest = str(dist_tags.get("latest") or "0.0.0")
    current = _resolve_version_npm(dep["name"], dep["version_spec"], project_root)

    if current == "0.0.0":
        jump, jump_pts = "unknown", 0
    else:
        jump, jump_pts = _version_jump(current, latest)
    signals = _scan_breaking(releases, current, latest, changelog)
    signal_pts = min(20, 4 * len(signals))
    transitive_pts = min(15, 3 * transitive_affected)
    months = _npm_months_outdated(npm, current)
    months_pts = min(10, int(months))
    deprecated = _npm_is_deprecated(npm, current)
    deprecated_pts = 5 if deprecated else 0

    if current != "0.0.0":
        cve_current_total, cve_current_w, cwe_ids = _fetch_osv(
            dep["name"], current, ecosystem="npm"
        )
    else:
        cve_current_total, cve_current_w, cwe_ids = -1, -1, []
    cve_latest_total, cve_latest_w, _ = _fetch_osv(dep["name"], latest, ecosystem="npm")

    fixed_weighted = max(0, cve_current_w - cve_latest_w) if cve_current_w > 0 else 0
    cve_pts = min(15, fixed_weighted * 3)

    score = min(
        100,
        jump_pts + signal_pts + transitive_pts + months_pts + deprecated_pts + cve_pts,
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
        yanked=deprecated,
        recommendation=recommendation,
        cve_current=cve_current_total,
        cve_latest=cve_latest_total,
        cwe_ids=cwe_ids,
        alternatives=[],
    )
