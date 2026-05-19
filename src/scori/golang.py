"""Go ecosystem adapter for scori.

Thin adapter over the shared friction algorithm:
  - scan_go()                   discovers dependencies from go.mod files
  - compute_go()                returns a FrictionResult using proxy.golang.org data
  - load_transitive_counts_go() returns {} (go.sum doesn't expose reverse deps)

Module metadata is fetched from proxy.golang.org.  Breaking signals use GitHub
releases and CHANGELOG.md when the module path starts with github.com/.
OSV advisory data uses ecosystem="Go".
"""

from __future__ import annotations

import json
import re
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import requests
from packaging.version import InvalidVersion, Version

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
    "vendor", ".git", "node_modules", ".venv", "dist", "build",
    "__pycache__", ".tox", ".nox",
})


# ---------------------------------------------------------------------------
# module path escaping  (Go proxy protocol §module-paths)
# ---------------------------------------------------------------------------


def _escape_module(module: str) -> str:
    """Escape a Go module path for proxy.golang.org: A → !a."""
    return re.sub(r"([A-Z])", lambda m: "!" + m.group(1).lower(), module)


# ---------------------------------------------------------------------------
# manifest scanner
# ---------------------------------------------------------------------------


def scan_go(project_path: str | Path) -> list[Dependency]:
    """Discover dependencies from go.mod files under project_path."""
    root = Path(project_path)
    deps: list[Dependency] = []
    seen: set[str] = set()

    for manifest in sorted(root.rglob("go.mod")):
        if any(part in _SKIP_DIRS for part in manifest.parts):
            continue
        try:
            for dep in _from_go_mod(manifest):
                key = dep["name"].lower()
                if key not in seen:
                    seen.add(key)
                    deps.append(dep)
        except OSError:
            continue
    return deps


def _from_go_mod(path: Path) -> list[Dependency]:
    """Parse require directives from a go.mod file."""
    text = path.read_text(encoding="utf-8")
    raw: list[tuple[str, str]] = []

    # Single-line: require github.com/foo/bar v1.2.3
    for m in re.finditer(
        r"^require\s+(\S+)\s+(v[\w.\-+]+)\s*(?://.*)?$",
        text,
        re.MULTILINE,
    ):
        raw.append((m.group(1), m.group(2)))

    # Block:  require ( ... )
    for block in re.finditer(r"require\s*\(([^)]*)\)", text, re.DOTALL):
        for m in re.finditer(
            r"^\s+(\S+)\s+(v[\w.\-+]+)\s*(?://.*)?$",
            block.group(1),
            re.MULTILINE,
        ):
            raw.append((m.group(1), m.group(2)))

    seen: set[str] = set()
    result: list[Dependency] = []
    for module, version in raw:
        key = module.lower()
        if key not in seen:
            seen.add(key)
            result.append(Dependency(name=module, version_spec=version, source_file="go.mod"))
    return result


# ---------------------------------------------------------------------------
# version resolution
# ---------------------------------------------------------------------------


def _resolve_version_go(
    module: str, version_spec: str, project_root: Path | None
) -> str:
    """Resolve installed version from go.sum, or fall back to spec.

    Returns the version WITHOUT the leading 'v' so it is comparable with
    other ecosystem versions via packaging.version.Version.
    """
    if project_root is not None:
        v = _from_go_sum(module, project_root)
        if v:
            return v
    if version_spec and re.match(r"^v?\d+\.", version_spec):
        return version_spec.lstrip("v")
    return "0.0.0"


def _from_go_sum(module: str, root: Path) -> str:
    """Return the highest resolved version for a module from any go.sum under root."""
    candidates: list[Path] = []
    top = root / "go.sum"
    if top.exists():
        candidates.append(top)
    for p in sorted(root.rglob("go.sum")):
        if p != top and not any(part in _SKIP_DIRS for part in p.parts):
            candidates.append(p)

    pattern = re.compile(
        r"^" + re.escape(module) + r"\s+(v\S+?)\s+h\d:",
        re.MULTILINE,
    )
    all_versions: list[str] = []
    for go_sum in candidates:
        try:
            text = go_sum.read_text(encoding="utf-8")
        except OSError:
            continue
        for m in pattern.finditer(text):
            v = m.group(1)
            if "/go.mod" not in v:
                all_versions.append(v.lstrip("v"))

    if not all_versions:
        return ""

    parsed: list[tuple[Version, str]] = []
    for v in all_versions:
        try:
            parsed.append((Version(v), v))
        except InvalidVersion:
            pass
    if parsed:
        return max(parsed, key=lambda x: x[0])[1]
    return all_versions[0]


# ---------------------------------------------------------------------------
# transitive dependency counts
# ---------------------------------------------------------------------------


def load_transitive_counts_go(project_root: Path) -> dict[str, int]:
    """Go's go.sum does not encode reverse dep counts; returns empty dict."""
    return {}


# ---------------------------------------------------------------------------
# proxy.golang.org client
# ---------------------------------------------------------------------------


def _go_cache_path(module: str) -> Path:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9_.\-]", "_", module)
    return CACHE_DIR / f"go_{safe}.json"


def _go_cache_read(module: str) -> dict[str, Any] | None:
    path = _go_cache_path(module)
    if not path.exists():
        return None
    if time.time() - path.stat().st_mtime > CACHE_TTL_SECONDS:
        return None
    try:
        return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))
    except json.JSONDecodeError:
        return None


def _go_cache_write(module: str, payload: dict[str, Any]) -> None:
    _go_cache_path(module).write_text(json.dumps(payload), encoding="utf-8")


def _fetch_go(module: str) -> dict[str, Any]:
    """Fetch Go module metadata from proxy.golang.org, with local cache."""
    cached = _go_cache_read(module)
    if cached is not None:
        return cached

    escaped = _escape_module(module)
    try:
        r = requests.get(
            f"https://proxy.golang.org/{escaped}/@latest",
            timeout=10,
        )
        r.raise_for_status()
        info: dict[str, Any] = r.json()
    except (requests.RequestException, ValueError):
        info = {}

    latest_version = str(info.get("Version") or "0.0.0").lstrip("v")
    latest_time = str(info.get("Time") or "")

    owner_repo: tuple[str, str] | None = None
    if module.startswith("github.com/"):
        parts = module.split("/")
        if len(parts) >= 3:
            owner_repo = (parts[1], parts[2])

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
        "go": {
            "module": module,
            "latest_version": latest_version,
            "latest_time": latest_time,
        },
        "releases": releases,
        "changelog": changelog,
    }
    _go_cache_write(module, payload)
    return payload


# ---------------------------------------------------------------------------
# per-version publish timestamp (lazily fetched, in-memory cache)
# ---------------------------------------------------------------------------

_go_version_time_cache: dict[tuple[str, str], str] = {}


def _go_version_time(module: str, version: str) -> str:
    """Return ISO publish timestamp for a specific Go module version, or ''."""
    key = (module.lower(), version)
    if key in _go_version_time_cache:
        return _go_version_time_cache[key]
    escaped = _escape_module(module)
    v = f"v{version}" if not version.startswith("v") else version
    try:
        r = requests.get(
            f"https://proxy.golang.org/{escaped}/@v/{v}.info",
            timeout=5,
        )
        if r.ok:
            t = str(r.json().get("Time") or "")
            _go_version_time_cache[key] = t
            return t
    except (requests.RequestException, ValueError):
        pass
    _go_version_time_cache[key] = ""
    return ""


def _go_months_outdated(module: str, version: str) -> float:
    t = _go_version_time(module, version)
    if not t:
        return 0.0
    try:
        published = datetime.fromisoformat(t.rstrip("Z")).replace(tzinfo=UTC)
        return (datetime.now(UTC) - published).days / 30.44
    except (ValueError, TypeError):
        return 0.0


# ---------------------------------------------------------------------------
# compute
# ---------------------------------------------------------------------------


def compute_go(
    dep: Dependency,
    transitive_affected: int = 0,
    project_root: Path | None = None,
) -> FrictionResult:
    """Compute FrictionResult for a Go module dependency."""
    data = _fetch_go(dep["name"])
    go: dict[str, Any] = data["go"]
    releases: list[dict[str, Any]] = data["releases"]
    changelog: str = data.get("changelog") or ""

    latest = go.get("latest_version") or "0.0.0"
    current = _resolve_version_go(dep["name"], dep["version_spec"], project_root)

    if current == "0.0.0":
        jump, jump_pts = "unknown", 0
    else:
        jump, jump_pts = _version_jump(current, latest)
    signals = _scan_breaking(releases, current, latest, changelog)
    signal_pts = min(20, 4 * len(signals))
    transitive_pts = min(15, 3 * transitive_affected)
    months = _go_months_outdated(dep["name"], current) if current != "0.0.0" else 0.0
    months_pts = min(10, int(months))

    if current not in ("0.0.0", ""):
        cve_current_total, cve_current_w, cwe_ids = _fetch_osv(
            dep["name"], current, ecosystem="Go"
        )
    else:
        cve_current_total, cve_current_w, cwe_ids = -1, -1, []
    cve_latest_total, cve_latest_w, _ = _fetch_osv(dep["name"], latest, ecosystem="Go")

    fixed_weighted = max(0, cve_current_w - cve_latest_w) if cve_current_w > 0 else 0
    cve_pts = min(15, fixed_weighted * 3)

    score = min(100, jump_pts + signal_pts + transitive_pts + months_pts + cve_pts)
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
        yanked=False,
        recommendation=recommendation,
        cve_current=cve_current_total,
        cve_latest=cve_latest_total,
        cwe_ids=cwe_ids,
        alternatives=[],
    )
