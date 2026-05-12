"""Friction score computation — the core of scori.

Answers the question: is it worth updating this dependency right now, or does
the migration cost outweigh the risk of not doing it?

Sources (all free, no mandatory auth):
    * https://pypi.org/pypi/{package}/json
    * https://api.github.com/repos/{owner}/{repo}/releases
      (without token: 60 req/h; with env GITHUB_TOKEN: 5000 req/h)
    * https://api.osv.dev/v1/query  (CVE/vulnerability counts per version)

Local cache: ~/.cache/scori/{package}.json (TTL 1h) — path chosen
deliberately for consistent branding with the tool name.

Algorithm (weighted sum, max 100):
    Semantic version jump      — weight 50 (patch=5, minor=25, major=50)
    Breaking signals           — weight 20 (+4 per keyword, max 20)
    Affected transitive deps   — weight 15 (+3 per dep, max 15)
    CVEs fixed by updating     — weight 15 (+3 per fixed CVE, max 15)
    Months outdated            — weight 10 (+1 per month, max 10)
    Current version yanked     — weight 5
"""

from __future__ import annotations

import json
import os
import re
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import requests
from packaging.version import InvalidVersion, Version

from ._types import Dependency, FrictionLabel, FrictionResult, VersionJump

CACHE_DIR = Path.home() / ".cache" / "scori"
CACHE_TTL_SECONDS = 60 * 60  # 1 hour

_VENV_CANDIDATES = (".venv", "venv", "env")


def _venv_version(project_root: Path, package: str) -> str | None:
    """Look up the installed version of a package from the project venv."""
    pkg_key = re.sub(r"[-_.]+", "_", package).lower()
    for venv in _VENV_CANDIDATES:
        lib = project_root / venv / "lib"
        if not lib.is_dir():
            continue
        for py_dir in lib.iterdir():
            sp = py_dir / "site-packages"
            if not sp.is_dir():
                continue
            for dist_info in sp.glob("*.dist-info"):
                stem = dist_info.stem  # e.g. "uvicorn-0.46.0"
                idx = stem.rfind("-")
                if idx == -1:
                    continue
                dist_key = re.sub(r"[-_.]+", "_", stem[:idx]).lower()
                if dist_key == pkg_key:
                    return stem[idx + 1:]
    return None

# In-memory cache for OSV results within a single scori run.
_osv_cache: dict[tuple[str, str], int] = {}


def _fetch_osv_count(package: str, version: str) -> int:
    """Return the number of known CVEs for a given package version via OSV API."""
    key = (package.lower(), version)
    if key in _osv_cache:
        return _osv_cache[key]
    try:
        r = requests.post(
            "https://api.osv.dev/v1/query",
            json={
                "version": version,
                "package": {"name": package, "ecosystem": "PyPI"},
            },
            timeout=10,
        )
        count = len(r.json().get("vulns") or []) if r.ok else 0
    except requests.RequestException:
        count = 0
    _osv_cache[key] = count
    return count


BREAKING_KEYWORDS = [
    "breaking",
    "removed",
    "deprecated",
    "incompatible",
    "migration",
    "dropped",
    "no longer",
    "requires now",
    "changed behavior",
]

# ------------------------------ cache ------------------------------


def _cache_path(package: str) -> Path:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9_.\-]", "_", package)
    return CACHE_DIR / f"{safe}.json"


def _cache_read(package: str) -> dict[str, Any] | None:
    path = _cache_path(package)
    if not path.exists():
        return None
    if time.time() - path.stat().st_mtime > CACHE_TTL_SECONDS:
        return None
    try:
        return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))
    except json.JSONDecodeError:
        return None


def _cache_write(package: str, payload: dict[str, Any]) -> None:
    _cache_path(package).write_text(json.dumps(payload), encoding="utf-8")


# ------------------------------ HTTP ------------------------------


def _gh_headers() -> dict[str, str]:
    headers: dict[str, str] = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _fetch_pypi(package: str) -> dict[str, Any]:
    url = f"https://pypi.org/pypi/{package}/json"
    r = requests.get(url, timeout=10)
    r.raise_for_status()
    return cast(dict[str, Any], r.json())


def _fetch_github_releases(owner: str, repo: str) -> list[dict[str, Any]]:
    url = f"https://api.github.com/repos/{owner}/{repo}/releases"
    r = requests.get(url, headers=_gh_headers(), timeout=10)
    if r.status_code == 404:
        return []
    r.raise_for_status()
    return cast(list[dict[str, Any]], r.json())


def _extract_owner_repo(pypi: dict[str, Any]) -> tuple[str, str] | None:
    urls = (pypi.get("info") or {}).get("project_urls") or {}
    for value in urls.values():
        if not isinstance(value, str):
            continue
        m = re.search(r"github\.com/([^/]+)/([^/#?]+)", value)
        if m:
            return m.group(1), m.group(2).removesuffix(".git")
    return None


def _gather(package: str) -> dict[str, Any]:
    """Fetch PyPI + GitHub releases, with local cache."""
    cached = _cache_read(package)
    if cached is not None:
        return cached
    pypi = _fetch_pypi(package)
    owner_repo = _extract_owner_repo(pypi)
    releases: list[dict[str, Any]] = []
    if owner_repo is not None:
        try:
            releases = _fetch_github_releases(*owner_repo)
        except requests.RequestException:
            releases = []
    payload: dict[str, Any] = {"pypi": pypi, "releases": releases}
    _cache_write(package, payload)
    return payload


# ------------------------------ score ------------------------------


def _version_jump(current: str, latest: str) -> tuple[VersionJump, int]:
    try:
        cv = Version(current)
        lv = Version(latest)
    except InvalidVersion:
        return "unknown", 0
    if (cv.major, cv.minor, cv.micro) == (lv.major, lv.minor, lv.micro):
        return "patch", 0
    if cv.major != lv.major:
        return "major", 50
    if cv.minor != lv.minor:
        return "minor", 25
    return "patch", 5


def _scan_breaking(
    releases: list[dict[str, Any]], current: str, latest: str
) -> list[str]:
    """Search release notes for breaking keywords.

    Scans releases between current (exclusive) and latest (inclusive).
    """
    try:
        cv = Version(current)
        lv = Version(latest)
    except InvalidVersion:
        return []
    signals: list[str] = []
    for rel in releases:
        tag = (rel.get("tag_name") or "").lstrip("v")
        body = rel.get("body") or ""
        try:
            v = Version(tag)
        except InvalidVersion:
            continue
        if not (cv < v <= lv):
            continue
        body_low = body.lower()
        for kw in BREAKING_KEYWORDS:
            if kw in body_low:
                signals.append(f"'{kw}' in {tag} release notes")
    return signals


def _months_outdated(pypi: dict[str, Any], current: str) -> float:
    rels = (pypi.get("releases") or {}).get(current) or []
    key = "upload_time_iso_8601"
    uploads = [r.get(key) for r in rels if r.get(key)]
    if not uploads:
        return 0.0
    ts = min(uploads)
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return 0.0
    delta = datetime.now(UTC) - dt
    return round(delta.days / 30.0, 1)


def _is_yanked(pypi: dict[str, Any], current: str) -> bool:
    rels = (pypi.get("releases") or {}).get(current) or []
    return any(bool(r.get("yanked")) for r in rels)


def _label(score: int) -> tuple[FrictionLabel, str]:
    if score <= 25:
        return "Low", "Safe to update"
    if score <= 50:
        return "Medium", "Update with tests"
    if score <= 75:
        return "High", "Update in isolated branch"
    return "Critical", "Manual migration required — review CHANGELOG before updating"


def _current_version_from_spec(
    spec: str,
    package: str | None = None,
    project_root: Path | None = None,
) -> str:
    """Best-effort: extract the pinned/minimum version from a PEP 440 specifier.

    When spec is empty (unpinned), tries to resolve the installed version from
    the project venv before falling back to "0.0.0".
    """
    if not spec:
        if package and project_root:
            installed = _venv_version(project_root, package)
            if installed:
                return installed
        return "0.0.0"
    m = re.search(r"(\d[\w.\-+]*)", spec)
    return m.group(1) if m else "0.0.0"


def compute(
    dep: Dependency,
    transitive_affected: int = 0,
    project_root: Path | None = None,
) -> FrictionResult:
    """Compute the FrictionResult for a dependency.

    ``transitive_affected`` will be populated by the caller from the
    uv.lock/poetry.lock parser in v0.3+. Defaults to 0 for now.
    """
    data = _gather(dep["name"])
    pypi: dict[str, Any] = data["pypi"]
    releases: list[dict[str, Any]] = data["releases"]

    latest = (pypi.get("info") or {}).get("version") or "0.0.0"
    current = _current_version_from_spec(dep["version_spec"], dep["name"], project_root)

    jump, jump_pts = _version_jump(current, latest)
    signals = _scan_breaking(releases, current, latest)
    signal_pts = min(20, 4 * len(signals))
    transitive_pts = min(15, 3 * transitive_affected)
    months = _months_outdated(pypi, current)
    months_pts = min(10, int(months))
    yanked = _is_yanked(pypi, current)
    yanked_pts = 5 if yanked else 0

    cve_current = _fetch_osv_count(dep["name"], current) if current != "0.0.0" else -1
    cve_latest = _fetch_osv_count(dep["name"], latest)

    # CVE points: only when updating would actually fix vulnerabilities
    fixed_cves = max(0, cve_current - cve_latest) if cve_current > 0 else 0
    cve_pts = min(15, fixed_cves * 3)

    score = min(
        100, jump_pts + signal_pts + transitive_pts + months_pts + yanked_pts + cve_pts
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
        cve_current=cve_current,
        cve_latest=cve_latest,
    )
