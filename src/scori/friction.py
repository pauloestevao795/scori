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
import xmlrpc.client
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
                    return stem[idx + 1 :]
    return None


# In-memory OSV cache: (total_count, weighted_count, cwe_ids).
# weighted_count gives CRITICAL-severity vulnerabilities double weight.
_osv_cache: dict[tuple[str, str], tuple[int, int, list[str]]] = {}

# Mapping of CWE ID → OWASP Top 10 2021 category code.
_CWE_TO_OWASP: dict[str, str] = {
    # A01 Broken Access Control
    **dict.fromkeys(["CWE-22", "CWE-284", "CWE-285", "CWE-639", "CWE-863"], "A01"),
    # A02 Cryptographic Failures
    **dict.fromkeys(["CWE-310", "CWE-319", "CWE-326", "CWE-327", "CWE-330"], "A02"),
    # A03 Injection
    **dict.fromkeys(
        ["CWE-20", "CWE-74", "CWE-77", "CWE-78", "CWE-79", "CWE-89"], "A03"
    ),  # noqa: E501
    # A04 Insecure Design
    **dict.fromkeys(["CWE-73", "CWE-183", "CWE-209", "CWE-434", "CWE-94"], "A04"),
    # A05 Security Misconfiguration
    **dict.fromkeys(["CWE-16", "CWE-116", "CWE-601", "CWE-611"], "A05"),
    # A07 Authentication Failures
    **dict.fromkeys(["CWE-287", "CWE-295", "CWE-306", "CWE-521", "CWE-759"], "A07"),
    # A08 Software and Data Integrity Failures
    **dict.fromkeys(["CWE-494", "CWE-502", "CWE-829"], "A08"),
    # A09 Logging and Monitoring Failures
    **dict.fromkeys(["CWE-117", "CWE-223", "CWE-532", "CWE-778"], "A09"),
    # A10 Server-Side Request Forgery
    **dict.fromkeys(["CWE-918"], "A10"),
}


def _cvss_weight(vuln: dict[str, Any]) -> int:
    """Return score weight for a single vulnerability: 2 for CRITICAL, 1 otherwise."""
    db_sev = str((vuln.get("database_specific") or {}).get("severity") or "").upper()
    if db_sev == "CRITICAL":
        return 2
    return 1


def _vuln_cwe_ids(vulns: list[dict[str, Any]]) -> list[str]:
    """Collect unique CWE IDs across all returned vulnerabilities."""
    seen: set[str] = set()
    result: list[str] = []
    for v in vulns:
        for cwe in (v.get("database_specific") or {}).get("cwe_ids") or []:
            cwe_str = str(cwe)
            if cwe_str not in seen:
                seen.add(cwe_str)
                result.append(cwe_str)
    return result


def _fetch_osv(package: str, version: str) -> tuple[int, int, list[str]]:
    """Return (total_count, weighted_count, cwe_ids) via the OSV API.

    weighted_count: CRITICAL-severity vulnerabilities count double so the
    friction score responds more strongly to high-severity findings.
    cwe_ids: unique CWE weakness identifiers across all returned vulns.
    """
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
        vulns: list[dict[str, Any]] = r.json().get("vulns") or [] if r.ok else []
        total = len(vulns)
        weighted = sum(_cvss_weight(v) for v in vulns)
        cwe_ids = _vuln_cwe_ids(vulns)
    except requests.RequestException:
        total, weighted, cwe_ids = 0, 0, []
    result = (total, weighted, cwe_ids)
    _osv_cache[key] = result
    return result


def _fetch_osv_count(package: str, version: str) -> int:
    """Return total vulnerability count (backward-compatible wrapper)."""
    total, _, _ = _fetch_osv(package, version)
    return total


_alternatives_cache: dict[str, list[str]] = {}


def _fetch_alternatives_online(package: str, pypi_data: dict[str, Any]) -> list[str]:
    """Search PyPI for packages sharing keywords and verify they have 0 CVEs.

    Uses the PyPI XMLRPC search API with keywords extracted from the vulnerable
    package's own metadata, then cross-checks each candidate against the OSV
    database. Returns up to 3 alternatives with no known vulnerabilities.
    """
    pkg_key = package.lower()
    if pkg_key in _alternatives_cache:
        return _alternatives_cache[pkg_key]

    info = pypi_data.get("info") or {}
    raw_keywords: str = info.get("keywords") or ""
    classifiers: list[str] = info.get("classifiers") or []

    # Build a search query from the package keywords
    terms = [t.strip() for t in re.split(r"[,\s]+", raw_keywords) if len(t.strip()) > 2]
    # Supplement with topic classifiers (e.g. "Topic :: Internet :: WWW/HTTP")
    for c in classifiers:
        if c.startswith("Topic ::"):
            parts = c.split(" :: ")
            terms.extend(p.strip() for p in parts[1:] if len(p.strip()) > 3)

    if not terms:
        _alternatives_cache[pkg_key] = []
        return []

    query = " ".join(terms[:5])  # keep the query short

    try:
        client = xmlrpc.client.ServerProxy("https://pypi.org/pypi", use_datetime=True)
        raw: Any = client.search({"name": query, "summary": query}, "or")
        hits: list[Any] = raw if isinstance(raw, list) else []
    except Exception:
        _alternatives_cache[pkg_key] = []
        return []

    pkg_norm = re.sub(r"[-_.]+", "-", package).lower()
    seen: set[str] = {pkg_norm}
    candidates: list[str] = []
    for hit in hits[:30]:
        name = (hit.get("name") or "").strip()
        if not name:
            continue
        norm = re.sub(r"[-_.]+", "-", name).lower()
        if norm in seen:
            continue
        seen.add(norm)
        # Resolve latest version for this candidate
        try:
            r = requests.get(f"https://pypi.org/pypi/{name}/json", timeout=5)
            if not r.ok:
                continue
            candidate_latest = (r.json().get("info") or {}).get("version") or ""
            if not candidate_latest:
                continue
        except requests.RequestException:
            continue
        if _fetch_osv_count(name, candidate_latest) == 0:
            candidates.append(name)
        if len(candidates) >= 3:
            break

    _alternatives_cache[pkg_key] = candidates
    return candidates


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


def _fetch_github_changelog(owner: str, repo: str) -> str:
    """Fetch raw CHANGELOG.md from the default branch; return '' on any error."""
    for filename in ("CHANGELOG.md", "CHANGES.md", "HISTORY.md", "CHANGELOG.rst"):
        url = f"https://raw.githubusercontent.com/{owner}/{repo}/main/{filename}"
        try:
            r = requests.get(url, headers=_gh_headers(), timeout=10)
            if r.ok and r.text.strip():
                return r.text
        except requests.RequestException:
            pass
    return ""


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
    """Fetch PyPI + GitHub releases + CHANGELOG.md, with local cache."""
    cached = _cache_read(package)
    if cached is not None:
        return cached
    pypi = _fetch_pypi(package)
    owner_repo = _extract_owner_repo(pypi)
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
    payload: dict[str, Any] = {
        "pypi": pypi,
        "releases": releases,
        "changelog": changelog,
    }
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
    releases: list[dict[str, Any]],
    current: str,
    latest: str,
    changelog: str = "",
) -> list[str]:
    """Search release notes and CHANGELOG.md for breaking change signals.

    Scans releases and CHANGELOG sections between current (exclusive) and
    latest (inclusive). Also detects BREAKING CHANGE: Conventional Commit
    footers anywhere in the changelog text for the relevant version range.
    """
    try:
        cv = Version(current)
        lv = Version(latest)
    except InvalidVersion:
        return []
    signals: list[str] = []

    # --- GitHub release notes ---
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
        if "breaking change:" in body_low:
            signals.append(f"BREAKING CHANGE footer in {tag} release notes")

    # --- CHANGELOG.md ---
    if changelog:
        # Extract the portion of the CHANGELOG between current and latest.
        # Strategy: find section headers that look like version numbers and
        # collect text for versions in the (current, latest] range.
        section_re = re.compile(
            r"^#{1,3}\s+(?:v?(\d+\.\d+[\w.\-]*)|\[v?(\d+\.\d+[\w.\-]*)\])",
            re.MULTILINE,
        )
        sections: list[tuple[Version, int]] = []
        for m in section_re.finditer(changelog):
            raw = m.group(1) or m.group(2)
            try:
                sections.append((Version(raw), m.start()))
            except InvalidVersion:
                continue
        sections.sort(key=lambda x: x[0], reverse=True)

        for i, (sv, start) in enumerate(sections):
            if not (cv < sv <= lv):
                continue
            end = sections[i + 1][1] if i + 1 < len(sections) else len(changelog)
            chunk = changelog[start:end].lower()
            for kw in BREAKING_KEYWORDS:
                if kw in chunk:
                    signals.append(f"'{kw}' in CHANGELOG {sv}")
            if "breaking change:" in chunk:
                signals.append(f"BREAKING CHANGE footer in CHANGELOG {sv}")

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
    """Best-effort: resolve the current installed version of a dependency.

    Priority:
      1. Venv inspection (actual installed version, most accurate)
      2. Pinned version extracted from the specifier (e.g. ==2.31.0)
      3. Lower bound from a range specifier (e.g. >=2.31 → 2.31)
      4. "0.0.0" when nothing is resolvable
    """
    if package and project_root:
        installed = _venv_version(project_root, package)
        if installed:
            return installed
    if not spec:
        return "0.0.0"
    m = re.search(r"(\d[\w.\-+]*)", spec)
    return m.group(1) if m else "0.0.0"


def compute(
    dep: Dependency,
    transitive_affected: int = 0,
    project_root: Path | None = None,
) -> FrictionResult:
    """Compute the FrictionResult for a dependency."""
    data = _gather(dep["name"])
    pypi: dict[str, Any] = data["pypi"]
    releases: list[dict[str, Any]] = data["releases"]
    changelog: str = data.get("changelog") or ""

    latest = (pypi.get("info") or {}).get("version") or "0.0.0"
    current = _current_version_from_spec(dep["version_spec"], dep["name"], project_root)

    jump, jump_pts = _version_jump(current, latest)
    signals = _scan_breaking(releases, current, latest, changelog)
    signal_pts = min(20, 4 * len(signals))
    transitive_pts = min(15, 3 * transitive_affected)
    months = _months_outdated(pypi, current)
    months_pts = min(10, int(months))
    yanked = _is_yanked(pypi, current)
    yanked_pts = 5 if yanked else 0

    if current != "0.0.0":
        cve_current_total, cve_current_w, cwe_ids_current = _fetch_osv(
            dep["name"], current
        )
    else:
        cve_current_total, cve_current_w, cwe_ids_current = -1, -1, []
    cve_latest_total, cve_latest_w, cwe_ids_latest = _fetch_osv(dep["name"], latest)

    # Use the current version's CWEs (what the project is exposed to right now)
    cwe_ids = cwe_ids_current if cwe_ids_current else cwe_ids_latest

    # Vuln points: use weighted counts so CRITICAL vulns push the score harder.
    # Only count vulnerabilities that updating would actually fix.
    fixed_weighted = max(0, cve_current_w - cve_latest_w) if cve_current_w > 0 else 0
    cve_pts = min(15, fixed_weighted * 3)

    score = min(
        100, jump_pts + signal_pts + transitive_pts + months_pts + yanked_pts + cve_pts
    )
    label, recommendation = _label(score)

    # Suggest alternatives only when CVEs are present and updating won't fix them
    unresolved_cves = cve_current_total > 0 and cve_latest_total >= cve_current_total
    alternatives = (
        _fetch_alternatives_online(dep["name"], data["pypi"]) if unresolved_cves else []
    )

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
        alternatives=alternatives,
    )
