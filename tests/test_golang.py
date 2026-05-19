"""Tests for the Go ecosystem adapter."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import patch

from scori.friction import _osv_cache
from scori.golang import (
    _escape_module,
    _from_go_mod,
    _from_go_sum,
    compute_go,
    load_transitive_counts_go,
    scan_go,
)

# ---------------------------------------------------------------------------
# shared mock data
# ---------------------------------------------------------------------------

_FETCH_GO_RETURN: dict[str, Any] = {
    "go": {
        "module": "github.com/gin-gonic/gin",
        "latest_version": "1.9.1",
        "latest_time": "2023-06-20T12:00:00Z",
    },
    "releases": [],
    "changelog": "",
}

# ---------------------------------------------------------------------------
# _escape_module
# ---------------------------------------------------------------------------


def test_escape_module_no_uppercase() -> None:
    assert _escape_module("github.com/foo/bar") == "github.com/foo/bar"


def test_escape_module_uppercase() -> None:
    assert _escape_module("github.com/BurntSushi/toml") == "github.com/!burnt!sushi/toml"


def test_escape_module_multiple_uppercase() -> None:
    assert _escape_module("github.com/PuerkitoBio/goquery") == "github.com/!puerkito!bio/goquery"


# ---------------------------------------------------------------------------
# _from_go_mod
# ---------------------------------------------------------------------------


def test_from_go_mod_single_line(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text(
        "module example.com/myapp\n\ngo 1.21\n\n"
        "require github.com/gin-gonic/gin v1.9.1\n"
    )
    deps = _from_go_mod(tmp_path / "go.mod")
    assert len(deps) == 1
    assert deps[0]["name"] == "github.com/gin-gonic/gin"
    assert deps[0]["version_spec"] == "v1.9.1"
    assert deps[0]["source_file"] == "go.mod"


def test_from_go_mod_block(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text(
        "module example.com/myapp\n\ngo 1.21\n\n"
        "require (\n"
        "    github.com/gin-gonic/gin v1.9.1\n"
        "    github.com/stretchr/testify v1.8.4 // indirect\n"
        ")\n"
    )
    deps = _from_go_mod(tmp_path / "go.mod")
    names = {d["name"] for d in deps}
    assert {"github.com/gin-gonic/gin", "github.com/stretchr/testify"} <= names


def test_from_go_mod_dedup(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text(
        "module example.com/myapp\n\n"
        "require github.com/foo/bar v1.0.0\n"
        "require (\n"
        "    github.com/foo/bar v1.0.0\n"
        ")\n"
    )
    deps = _from_go_mod(tmp_path / "go.mod")
    assert len([d for d in deps if d["name"] == "github.com/foo/bar"]) == 1


def test_from_go_mod_no_deps(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text("module example.com/myapp\n\ngo 1.21\n")
    deps = _from_go_mod(tmp_path / "go.mod")
    assert deps == []


# ---------------------------------------------------------------------------
# _from_go_sum
# ---------------------------------------------------------------------------


def test_from_go_sum_basic(tmp_path: Path) -> None:
    (tmp_path / "go.sum").write_text(
        "github.com/gin-gonic/gin v1.9.1 h1:abc123\n"
        "github.com/gin-gonic/gin v1.9.1/go.mod h1:def456\n"
    )
    v = _from_go_sum("github.com/gin-gonic/gin", tmp_path)
    assert v == "1.9.1"


def test_from_go_sum_returns_highest(tmp_path: Path) -> None:
    (tmp_path / "go.sum").write_text(
        "github.com/foo/bar v1.2.0 h1:aaa\n"
        "github.com/foo/bar v1.3.0 h1:bbb\n"
        "github.com/foo/bar v1.1.0 h1:ccc\n"
    )
    v = _from_go_sum("github.com/foo/bar", tmp_path)
    assert v == "1.3.0"


def test_from_go_sum_missing_module(tmp_path: Path) -> None:
    (tmp_path / "go.sum").write_text("github.com/other/pkg v1.0.0 h1:xyz\n")
    assert _from_go_sum("github.com/nonexistent/mod", tmp_path) == ""


def test_from_go_sum_no_file(tmp_path: Path) -> None:
    assert _from_go_sum("github.com/foo/bar", tmp_path) == ""


def test_from_go_sum_subdirectory(tmp_path: Path) -> None:
    sub = tmp_path / "submod"
    sub.mkdir()
    (sub / "go.sum").write_text(
        "github.com/foo/bar v2.0.0 h1:zzz\n"
    )
    v = _from_go_sum("github.com/foo/bar", tmp_path)
    assert v == "2.0.0"


# ---------------------------------------------------------------------------
# scan_go
# ---------------------------------------------------------------------------


def test_scan_go_basic(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text(
        "module example.com/myapp\n\ngo 1.21\n\n"
        "require (\n"
        "    github.com/gin-gonic/gin v1.9.1\n"
        "    github.com/sirupsen/logrus v1.9.3\n"
        ")\n"
    )
    deps = scan_go(tmp_path)
    names = {d["name"] for d in deps}
    assert {"github.com/gin-gonic/gin", "github.com/sirupsen/logrus"} <= names


def test_scan_go_dedup_across_files(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text(
        "module example.com/myapp\n\nrequire github.com/foo/bar v1.0.0\n"
    )
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "go.mod").write_text(
        "module example.com/sub\n\nrequire github.com/foo/bar v1.0.0\n"
    )
    deps = scan_go(tmp_path)
    assert len([d for d in deps if d["name"] == "github.com/foo/bar"]) == 1


def test_scan_go_skips_vendor(tmp_path: Path) -> None:
    vendor = tmp_path / "vendor"
    vendor.mkdir()
    (vendor / "go.mod").write_text(
        "module example.com/vendor\n\nrequire github.com/should/skip v1.0.0\n"
    )
    (tmp_path / "go.mod").write_text(
        "module example.com/myapp\n\nrequire github.com/real/dep v1.0.0\n"
    )
    deps = scan_go(tmp_path)
    names = {d["name"] for d in deps}
    assert "github.com/real/dep" in names
    assert "github.com/should/skip" not in names


def test_scan_go_empty_project(tmp_path: Path) -> None:
    assert scan_go(tmp_path) == []


# ---------------------------------------------------------------------------
# load_transitive_counts_go
# ---------------------------------------------------------------------------


def test_load_transitive_counts_go_always_empty(tmp_path: Path) -> None:
    (tmp_path / "go.sum").write_text("github.com/foo/bar v1.0.0 h1:abc\n")
    assert load_transitive_counts_go(tmp_path) == {}


# ---------------------------------------------------------------------------
# compute_go
# ---------------------------------------------------------------------------


@patch("scori.golang._go_version_time")
@patch("scori.golang._fetch_go")
def test_compute_go_basic(
    mock_fetch: Any,
    mock_vtime: Any,
    tmp_path: Path,
) -> None:
    _osv_cache.clear()
    _osv_cache[("github.com/gin-gonic/gin", "1.8.0", "Go")] = (0, 0, [])
    _osv_cache[("github.com/gin-gonic/gin", "1.9.1", "Go")] = (0, 0, [])
    mock_fetch.return_value = _FETCH_GO_RETURN
    mock_vtime.return_value = ""

    from scori._types import Dependency
    dep = Dependency(
        name="github.com/gin-gonic/gin",
        version_spec="v1.8.0",
        source_file="go.mod",
    )
    result = compute_go(dep, project_root=tmp_path)

    assert result["name"] == "github.com/gin-gonic/gin"
    assert result["current_version"] == "1.8.0"
    assert result["latest_version"] == "1.9.1"
    assert result["version_jump"] == "minor"
    assert result["score"] == 25
    assert result["yanked"] is False
    assert result["alternatives"] == []


@patch("scori.golang._go_version_time")
@patch("scori.golang._fetch_go")
def test_compute_go_up_to_date(
    mock_fetch: Any,
    mock_vtime: Any,
    tmp_path: Path,
) -> None:
    _osv_cache.clear()
    _osv_cache[("github.com/gin-gonic/gin", "1.9.1", "Go")] = (0, 0, [])
    mock_fetch.return_value = _FETCH_GO_RETURN
    mock_vtime.return_value = ""

    from scori._types import Dependency
    dep = Dependency(
        name="github.com/gin-gonic/gin",
        version_spec="v1.9.1",
        source_file="go.mod",
    )
    result = compute_go(dep, project_root=tmp_path)
    assert result["current_version"] == "1.9.1"
    assert result["latest_version"] == "1.9.1"
    assert result["score"] == 0


@patch("scori.golang._go_version_time")
@patch("scori.golang._fetch_go")
def test_compute_go_with_cves(
    mock_fetch: Any,
    mock_vtime: Any,
    tmp_path: Path,
) -> None:
    _osv_cache.clear()
    _osv_cache[("github.com/foo/vuln", "1.0.0", "Go")] = (2, 3, ["CWE-79"])
    _osv_cache[("github.com/foo/vuln", "1.1.0", "Go")] = (0, 0, [])
    mock_fetch.return_value = {
        "go": {
            "module": "github.com/foo/vuln",
            "latest_version": "1.1.0",
            "latest_time": "",
        },
        "releases": [],
        "changelog": "",
    }
    mock_vtime.return_value = ""

    from scori._types import Dependency
    dep = Dependency(name="github.com/foo/vuln", version_spec="v1.0.0", source_file="go.mod")
    result = compute_go(dep, project_root=tmp_path)
    assert result["cve_current"] == 2
    assert result["cve_latest"] == 0
    assert result["cwe_ids"] == ["CWE-79"]
    # CVE score: fixed_weighted=3, cve_pts=min(15, 9)=9; jump=minor=25 → total 34
    assert result["score"] == 34


@patch("scori.golang._go_version_time")
@patch("scori.golang._fetch_go")
def test_compute_go_unresolved_version(
    mock_fetch: Any,
    mock_vtime: Any,
    tmp_path: Path,
) -> None:
    _osv_cache.clear()
    _osv_cache[("github.com/foo/bar", "1.0.0", "Go")] = (0, 0, [])
    mock_fetch.return_value = {
        "go": {"module": "github.com/foo/bar", "latest_version": "1.0.0", "latest_time": ""},
        "releases": [],
        "changelog": "",
    }
    mock_vtime.return_value = ""

    from scori._types import Dependency
    # version_spec with no digit → resolves to "0.0.0"
    dep = Dependency(name="github.com/foo/bar", version_spec="", source_file="go.mod")
    result = compute_go(dep, project_root=tmp_path)
    assert result["current_version"] == "0.0.0"
    assert result["cve_current"] == -1


@patch("scori.golang._go_version_time")
@patch("scori.golang._fetch_go")
def test_compute_go_transitive_pts(
    mock_fetch: Any,
    mock_vtime: Any,
    tmp_path: Path,
) -> None:
    _osv_cache.clear()
    _osv_cache[("github.com/foo/bar", "1.0.0", "Go")] = (0, 0, [])
    _osv_cache[("github.com/foo/bar", "2.0.0", "Go")] = (0, 0, [])
    mock_fetch.return_value = {
        "go": {"module": "github.com/foo/bar", "latest_version": "2.0.0", "latest_time": ""},
        "releases": [],
        "changelog": "",
    }
    mock_vtime.return_value = ""

    from scori._types import Dependency
    dep = Dependency(name="github.com/foo/bar", version_spec="v1.0.0", source_file="go.mod")
    result = compute_go(dep, transitive_affected=3, project_root=tmp_path)
    # jump=major=50, transitive=3*3=9 → 59
    assert result["score"] == 59
    assert result["transitive_affected"] == 3
