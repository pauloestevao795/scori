"""Tests for the npm ecosystem adapter (scori.npm)."""

import json
from pathlib import Path
from unittest.mock import patch

from scori._types import Dependency
from scori.friction import _osv_cache
from scori.npm import (
    _from_package_lock,
    _from_pnpm_lock,
    _from_yarn_lock,
    _npm_is_deprecated,
    _npm_months_outdated,
    _resolve_version_npm,
    compute_npm,
    load_transitive_counts_npm,
    scan_npm,
)

# ---------------------------------------------------------------------------
# shared fixture data
# ---------------------------------------------------------------------------

_NPM_DATA: dict = {
    "name": "express",
    "dist-tags": {"latest": "4.18.2"},
    "time": {
        "4.18.0": "2022-04-29T00:00:00.000Z",
        "4.18.2": "2023-02-16T00:00:00.000Z",
    },
    "repository": {"type": "git", "url": "https://github.com/expressjs/express.git"},
    "deprecated_versions": [],
}

_FETCH_NPM_RETURN = {"npm": _NPM_DATA, "releases": [], "changelog": ""}


# ---------------------------------------------------------------------------
# scan_npm
# ---------------------------------------------------------------------------


def test_scan_npm_reads_dependencies(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(json.dumps({
        "dependencies": {"express": "^4.18.0", "lodash": "^4.17.21"},
        "devDependencies": {"jest": "^29.0.0"},
    }))
    deps = scan_npm(tmp_path)
    names = {d["name"] for d in deps}
    assert {"express", "lodash", "jest"} <= names


def test_scan_npm_records_version_spec(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(json.dumps({
        "dependencies": {"react": "^18.2.0"},
    }))
    deps = scan_npm(tmp_path)
    react = next(d for d in deps if d["name"] == "react")
    assert react["version_spec"] == "^18.2.0"
    assert react["source_file"] == "package.json"


def test_scan_npm_skips_node_modules(tmp_path: Path) -> None:
    nm = tmp_path / "node_modules" / "lodash"
    nm.mkdir(parents=True)
    (nm / "package.json").write_text(json.dumps({"dependencies": {"evil": "1.0.0"}}))
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"safe": "1.0.0"}})
    )
    deps = scan_npm(tmp_path)
    names = {d["name"] for d in deps}
    assert "safe" in names
    assert "evil" not in names


def test_scan_npm_deduplicates_across_sections(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(json.dumps({
        "dependencies": {"react": "^18.0.0"},
        "devDependencies": {"react": "^18.0.0"},
    }))
    deps = scan_npm(tmp_path)
    assert len([d for d in deps if d["name"] == "react"]) == 1


def test_scan_npm_ignores_invalid_json(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("not json")
    deps = scan_npm(tmp_path)
    assert deps == []


# ---------------------------------------------------------------------------
# version resolution — package-lock.json
# ---------------------------------------------------------------------------


def test_from_package_lock_v2(tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 2,
        "packages": {"node_modules/express": {"version": "4.18.2"}},
    }))
    assert _from_package_lock("express", tmp_path) == ["4.18.2"]


def test_from_package_lock_v1(tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 1,
        "dependencies": {"express": {"version": "4.18.2"}},
    }))
    assert _from_package_lock("express", tmp_path) == ["4.18.2"]


def test_from_package_lock_missing_package(tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 2,
        "packages": {},
    }))
    assert _from_package_lock("express", tmp_path) == []


def test_from_package_lock_no_file(tmp_path: Path) -> None:
    assert _from_package_lock("express", tmp_path) == []


# ---------------------------------------------------------------------------
# version resolution — yarn.lock
# ---------------------------------------------------------------------------


def test_from_yarn_lock_classic(tmp_path: Path) -> None:
    (tmp_path / "yarn.lock").write_text(
        '"express@^4.18.0":\n'
        '  version "4.18.2"\n'
        '  resolved "https://registry.yarnpkg.com/express/-/express-4.18.2.tgz"\n'
    )
    assert _from_yarn_lock("express", tmp_path) == ["4.18.2"]


def test_from_yarn_lock_multi_spec(tmp_path: Path) -> None:
    (tmp_path / "yarn.lock").write_text(
        '"express@^4.17.0", "express@^4.18.0":\n'
        '  version "4.18.2"\n'
    )
    assert _from_yarn_lock("express", tmp_path) == ["4.18.2"]


def test_from_yarn_lock_no_file(tmp_path: Path) -> None:
    assert _from_yarn_lock("express", tmp_path) == []


# ---------------------------------------------------------------------------
# version resolution — pnpm-lock.yaml
# ---------------------------------------------------------------------------


def test_from_pnpm_lock(tmp_path: Path) -> None:
    (tmp_path / "pnpm-lock.yaml").write_text(
        "lockfileVersion: '6.0'\n"
        "packages:\n"
        "  /express@4.18.2:\n"
        "    resolution: {integrity: sha512-xxx}\n"
    )
    assert _from_pnpm_lock("express", tmp_path) == ["4.18.2"]


def test_from_pnpm_lock_no_slash_prefix(tmp_path: Path) -> None:
    (tmp_path / "pnpm-lock.yaml").write_text(
        "snapshots:\n"
        "  express@4.18.2:\n"
        "    dependencies:\n"
    )
    assert _from_pnpm_lock("express", tmp_path) == ["4.18.2"]


def test_from_pnpm_lock_no_file(tmp_path: Path) -> None:
    assert _from_pnpm_lock("express", tmp_path) == []


# ---------------------------------------------------------------------------
# resolve_version_npm — spec extraction fallback
# ---------------------------------------------------------------------------


def test_resolve_version_from_caret_spec(tmp_path: Path) -> None:
    assert _resolve_version_npm("express", "^4.18.0", tmp_path) == "4.18.0"


def test_resolve_version_from_tilde_spec(tmp_path: Path) -> None:
    assert _resolve_version_npm("express", "~4.18.0", tmp_path) == "4.18.0"


def test_resolve_version_exact_spec(tmp_path: Path) -> None:
    assert _resolve_version_npm("express", "4.18.0", tmp_path) == "4.18.0"


def test_resolve_version_wildcard_falls_back(tmp_path: Path) -> None:
    assert _resolve_version_npm("express", "*", tmp_path) == "0.0.0"


def test_resolve_version_lockfile_wins_over_spec(tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 2,
        "packages": {"node_modules/express": {"version": "4.18.2"}},
    }))
    assert _resolve_version_npm("express", "^4.18.0", tmp_path) == "4.18.2"


# ---------------------------------------------------------------------------
# transitive counts
# ---------------------------------------------------------------------------


def test_load_transitive_counts_npm(tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 2,
        "packages": {
            "node_modules/express": {
                "version": "4.18.2",
                "dependencies": {"body-parser": "^1.20.0", "accepts": "^1.3.0"},
            },
            "node_modules/koa": {
                "version": "2.14.2",
                "dependencies": {"accepts": "^1.3.0"},
            },
        },
    }))
    counts = load_transitive_counts_npm(tmp_path)
    assert counts["accepts"] == 2
    assert counts["body-parser"] == 1


def test_load_transitive_counts_npm_no_lockfile(tmp_path: Path) -> None:
    assert load_transitive_counts_npm(tmp_path) == {}


# ---------------------------------------------------------------------------
# npm metadata helpers
# ---------------------------------------------------------------------------


def test_npm_months_outdated_known_version() -> None:
    npm_data = {"time": {"4.18.0": "2020-01-01T00:00:00.000Z"}}
    months = _npm_months_outdated(npm_data, "4.18.0")
    assert months > 12  # well over a year ago


def test_npm_months_outdated_unknown_version() -> None:
    assert _npm_months_outdated({"time": {}}, "9.9.9") == 0.0


def test_npm_is_deprecated_true() -> None:
    assert _npm_is_deprecated({"deprecated_versions": ["4.18.0"]}, "4.18.0") is True


def test_npm_is_deprecated_false() -> None:
    assert _npm_is_deprecated({"deprecated_versions": []}, "4.18.0") is False


# ---------------------------------------------------------------------------
# compute_npm
# ---------------------------------------------------------------------------


@patch("scori.npm._fetch_npm")
def test_compute_npm_basic(mock_fetch: object, tmp_path: Path) -> None:
    _osv_cache.clear()
    _osv_cache[("express", "4.18.0", "npm")] = (0, 0, [])
    _osv_cache[("express", "4.18.2", "npm")] = (0, 0, [])
    mock_fetch.return_value = _FETCH_NPM_RETURN  # type: ignore[attr-defined]

    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 2,
        "packages": {"node_modules/express": {"version": "4.18.0"}},
    }))
    dep = Dependency(name="express", version_spec="^4.18.0", source_file="package.json")
    result = compute_npm(dep, project_root=tmp_path)

    assert result["name"] == "express"
    assert result["current_version"] == "4.18.0"
    assert result["latest_version"] == "4.18.2"
    assert result["version_jump"] == "patch"
    assert 0 <= result["score"] <= 100
    assert result["label"] in ("Low", "Medium", "High", "Critical")
    assert result["yanked"] is False


@patch("scori.npm._fetch_npm")
def test_compute_npm_deprecated_adds_score(mock_fetch: object, tmp_path: Path) -> None:
    _osv_cache.clear()
    _osv_cache[("express", "4.18.0", "npm")] = (0, 0, [])
    _osv_cache[("express", "4.18.2", "npm")] = (0, 0, [])
    deprecated_data = {
        "npm": {**_NPM_DATA, "deprecated_versions": ["4.18.0"]},
        "releases": [],
        "changelog": "",
    }
    mock_fetch.return_value = deprecated_data  # type: ignore[attr-defined]

    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 2,
        "packages": {"node_modules/express": {"version": "4.18.0"}},
    }))
    dep = Dependency(name="express", version_spec="^4.18.0", source_file="package.json")
    result = compute_npm(dep, project_root=tmp_path)
    assert result["yanked"] is True


@patch("scori.npm._fetch_npm")
def test_compute_npm_cve_score(mock_fetch: object, tmp_path: Path) -> None:
    _osv_cache.clear()
    # current has 2 CVEs, latest has 0 → should add cve_pts
    _osv_cache[("lodash", "4.17.20", "npm")] = (2, 2, ["CWE-79"])
    _osv_cache[("lodash", "4.17.21", "npm")] = (0, 0, [])
    lodash_data: dict = {
        "npm": {
            "name": "lodash",
            "dist-tags": {"latest": "4.17.21"},
            "time": {
                "4.17.20": "2020-01-01T00:00:00.000Z",
                "4.17.21": "2021-01-01T00:00:00.000Z",
            },
            "repository": {},
            "deprecated_versions": [],
        },
        "releases": [],
        "changelog": "",
    }
    mock_fetch.return_value = lodash_data  # type: ignore[attr-defined]

    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 2,
        "packages": {"node_modules/lodash": {"version": "4.17.20"}},
    }))
    dep = Dependency(name="lodash", version_spec="^4.17.20", source_file="package.json")
    result = compute_npm(dep, project_root=tmp_path)
    assert result["cve_current"] == 2
    assert result["cve_latest"] == 0
    assert result["score"] > 0


@patch("scori.npm._fetch_npm")
def test_compute_npm_transitive_affects_score(
    mock_fetch: object, tmp_path: Path
) -> None:
    _osv_cache.clear()
    _osv_cache[("express", "4.18.0", "npm")] = (0, 0, [])
    _osv_cache[("express", "4.18.2", "npm")] = (0, 0, [])
    mock_fetch.return_value = _FETCH_NPM_RETURN  # type: ignore[attr-defined]

    dep = Dependency(name="express", version_spec="^4.18.0", source_file="package.json")
    result_low = compute_npm(dep, transitive_affected=0, project_root=tmp_path)
    result_high = compute_npm(dep, transitive_affected=5, project_root=tmp_path)
    assert result_high["score"] > result_low["score"]
