"""Tests for the Rust ecosystem adapter."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import patch

from scori.friction import _osv_cache
from scori.rust import (
    _from_cargo_lock,
    _from_cargo_toml,
    compute_rust,
    load_transitive_counts_rust,
    scan_rust,
)

# ---------------------------------------------------------------------------
# shared mock data
# ---------------------------------------------------------------------------

_FETCH_RUST_RETURN: dict[str, Any] = {
    "crate": {
        "name": "serde",
        "latest_version": "1.0.195",
        "version_times": {
            "1.0.195": "2024-01-01T00:00:00+00:00",
            "1.0.100": "2022-06-01T00:00:00+00:00",
        },
        "yanked_versions": [],
    },
    "releases": [],
    "changelog": "",
}

# ---------------------------------------------------------------------------
# _from_cargo_toml
# ---------------------------------------------------------------------------


def test_from_cargo_toml_basic(tmp_path: Path) -> None:
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname = "my-crate"\nversion = "0.1.0"\n\n'
        "[dependencies]\n"
        'serde = "1.0"\n'
        'tokio = { version = "1.35", features = ["full"] }\n'
    )
    deps = _from_cargo_toml(tmp_path / "Cargo.toml")
    names = {d["name"] for d in deps}
    assert {"serde", "tokio"} <= names
    serde = next(d for d in deps if d["name"] == "serde")
    assert serde["version_spec"] == "1.0"
    assert serde["source_file"] == "Cargo.toml"


def test_from_cargo_toml_dev_dependencies(tmp_path: Path) -> None:
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname = "x"\nversion = "0.1.0"\n\n'
        "[dependencies]\nserde = \"1.0\"\n\n"
        "[dev-dependencies]\nmockito = \"0.31\"\n"
    )
    deps = _from_cargo_toml(tmp_path / "Cargo.toml")
    names = {d["name"] for d in deps}
    assert {"serde", "mockito"} <= names


def test_from_cargo_toml_skips_path_deps(tmp_path: Path) -> None:
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname = "x"\nversion = "0.1.0"\n\n'
        "[dependencies]\n"
        'local = { path = "../local" }\n'
        'serde = "1.0"\n'
    )
    deps = _from_cargo_toml(tmp_path / "Cargo.toml")
    names = {d["name"] for d in deps}
    assert "serde" in names
    assert "local" not in names


def test_from_cargo_toml_skips_git_deps(tmp_path: Path) -> None:
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname = "x"\nversion = "0.1.0"\n\n'
        "[dependencies]\n"
        'my-git = { git = "https://github.com/foo/bar" }\n'
        'serde = "1.0"\n'
    )
    deps = _from_cargo_toml(tmp_path / "Cargo.toml")
    names = {d["name"] for d in deps}
    assert "serde" in names
    assert "my-git" not in names


def test_from_cargo_toml_no_deps(tmp_path: Path) -> None:
    (tmp_path / "Cargo.toml").write_text('[package]\nname = "x"\nversion = "0.1.0"\n')
    assert _from_cargo_toml(tmp_path / "Cargo.toml") == []


# ---------------------------------------------------------------------------
# _from_cargo_lock
# ---------------------------------------------------------------------------


def test_from_cargo_lock_basic(tmp_path: Path) -> None:
    (tmp_path / "Cargo.lock").write_text(
        'version = 3\n\n'
        '[[package]]\n'
        'name = "serde"\n'
        'version = "1.0.195"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
    )
    v = _from_cargo_lock("serde", tmp_path)
    assert v == "1.0.195"


def test_from_cargo_lock_missing(tmp_path: Path) -> None:
    (tmp_path / "Cargo.lock").write_text(
        'version = 3\n\n'
        '[[package]]\n'
        'name = "tokio"\n'
        'version = "1.35.1"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
    )
    assert _from_cargo_lock("serde", tmp_path) == ""


def test_from_cargo_lock_no_file(tmp_path: Path) -> None:
    assert _from_cargo_lock("serde", tmp_path) == ""


def test_from_cargo_lock_case_insensitive(tmp_path: Path) -> None:
    (tmp_path / "Cargo.lock").write_text(
        'version = 3\n\n'
        '[[package]]\n'
        'name = "Serde"\n'
        'version = "1.0.0"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
    )
    v = _from_cargo_lock("serde", tmp_path)
    assert v == "1.0.0"


# ---------------------------------------------------------------------------
# load_transitive_counts_rust
# ---------------------------------------------------------------------------


def test_load_transitive_counts_rust_basic(tmp_path: Path) -> None:
    (tmp_path / "Cargo.lock").write_text(
        'version = 3\n\n'
        '[[package]]\n'
        'name = "tokio"\n'
        'version = "1.35.1"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
        'dependencies = [\n'
        '    "bytes",\n'
        '    "libc",\n'
        ']\n\n'
        '[[package]]\n'
        'name = "axum"\n'
        'version = "0.7.0"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
        'dependencies = [\n'
        '    "bytes",\n'
        '    "tokio",\n'
        ']\n'
    )
    counts = load_transitive_counts_rust(tmp_path)
    assert counts["bytes"] == 2
    assert counts["libc"] == 1
    assert counts["tokio"] == 1


def test_load_transitive_counts_rust_no_lock(tmp_path: Path) -> None:
    assert load_transitive_counts_rust(tmp_path) == {}


def test_load_transitive_counts_rust_old_format(tmp_path: Path) -> None:
    # v1/v2 Cargo.lock uses "name version (url)" format in dependencies
    (tmp_path / "Cargo.lock").write_text(
        'version = 2\n\n'
        '[[package]]\n'
        'name = "my-crate"\n'
        'version = "0.1.0"\n'
        'dependencies = [\n'
        '    "serde 1.0.195 (registry+https://github.com/rust-lang/crates.io-index)",\n'
        ']\n'
    )
    counts = load_transitive_counts_rust(tmp_path)
    assert counts["serde"] == 1


# ---------------------------------------------------------------------------
# scan_rust
# ---------------------------------------------------------------------------


def test_scan_rust_basic(tmp_path: Path) -> None:
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname = "app"\nversion = "0.1.0"\n\n'
        "[dependencies]\n"
        'serde = "1.0"\n'
        'tokio = { version = "1.35", features = ["full"] }\n'
    )
    deps = scan_rust(tmp_path)
    names = {d["name"] for d in deps}
    assert {"serde", "tokio"} <= names


def test_scan_rust_dedup_across_files(tmp_path: Path) -> None:
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname = "root"\nversion = "0.1.0"\n\n'
        "[dependencies]\nserde = \"1.0\"\n"
    )
    sub = tmp_path / "subcrate"
    sub.mkdir()
    (sub / "Cargo.toml").write_text(
        '[package]\nname = "subcrate"\nversion = "0.1.0"\n\n'
        "[dependencies]\nserde = \"1.0\"\n"
    )
    deps = scan_rust(tmp_path)
    assert len([d for d in deps if d["name"] == "serde"]) == 1


def test_scan_rust_skips_target(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "Cargo.toml").write_text(
        '[package]\nname = "build-artifact"\nversion = "0.1.0"\n\n'
        "[dependencies]\nshould-skip = \"1.0\"\n"
    )
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname = "real"\nversion = "0.1.0"\n\n'
        "[dependencies]\nserde = \"1.0\"\n"
    )
    deps = scan_rust(tmp_path)
    names = {d["name"] for d in deps}
    assert "serde" in names
    assert "should-skip" not in names


def test_scan_rust_empty_project(tmp_path: Path) -> None:
    assert scan_rust(tmp_path) == []


# ---------------------------------------------------------------------------
# compute_rust
# ---------------------------------------------------------------------------


@patch("scori.rust._fetch_rust")
def test_compute_rust_basic(mock_fetch: Any, tmp_path: Path) -> None:
    _osv_cache.clear()
    _osv_cache[("serde", "1.0.100", "crates.io")] = (0, 0, [])
    _osv_cache[("serde", "1.0.195", "crates.io")] = (0, 0, [])
    mock_fetch.return_value = _FETCH_RUST_RETURN

    from scori._types import Dependency
    dep = Dependency(name="serde", version_spec="1.0.100", source_file="Cargo.toml")
    result = compute_rust(dep, project_root=tmp_path)

    assert result["name"] == "serde"
    assert result["current_version"] == "1.0.100"
    assert result["latest_version"] == "1.0.195"
    assert result["version_jump"] == "patch"
    assert result["yanked"] is False
    assert result["alternatives"] == []


@patch("scori.rust._fetch_rust")
def test_compute_rust_up_to_date(mock_fetch: Any, tmp_path: Path) -> None:
    _osv_cache.clear()
    _osv_cache[("serde", "1.0.195", "crates.io")] = (0, 0, [])
    # No version_times so months_outdated = 0 → pure jump score only
    mock_fetch.return_value = {
        "crate": {
            "name": "serde",
            "latest_version": "1.0.195",
            "version_times": {},
            "yanked_versions": [],
        },
        "releases": [],
        "changelog": "",
    }

    from scori._types import Dependency
    dep = Dependency(name="serde", version_spec="1.0.195", source_file="Cargo.toml")
    result = compute_rust(dep, project_root=tmp_path)
    assert result["score"] == 0


@patch("scori.rust._fetch_rust")
def test_compute_rust_yanked(mock_fetch: Any, tmp_path: Path) -> None:
    _osv_cache.clear()
    _osv_cache[("bad-crate", "0.1.0", "crates.io")] = (0, 0, [])
    _osv_cache[("bad-crate", "0.2.0", "crates.io")] = (0, 0, [])
    mock_fetch.return_value = {
        "crate": {
            "name": "bad-crate",
            "latest_version": "0.2.0",
            "version_times": {"0.1.0": "2020-01-01T00:00:00+00:00"},
            "yanked_versions": ["0.1.0"],
        },
        "releases": [],
        "changelog": "",
    }

    from scori._types import Dependency
    dep = Dependency(name="bad-crate", version_spec="0.1.0", source_file="Cargo.toml")
    result = compute_rust(dep, project_root=tmp_path)
    assert result["yanked"] is True
    assert result["score"] >= 5  # yanked adds +5


@patch("scori.rust._fetch_rust")
def test_compute_rust_with_cves(mock_fetch: Any, tmp_path: Path) -> None:
    _osv_cache.clear()
    _osv_cache[("openssl", "0.9.0", "crates.io")] = (3, 5, ["CWE-310"])
    _osv_cache[("openssl", "0.10.0", "crates.io")] = (0, 0, [])
    mock_fetch.return_value = {
        "crate": {
            "name": "openssl",
            "latest_version": "0.10.0",
            "version_times": {},
            "yanked_versions": [],
        },
        "releases": [],
        "changelog": "",
    }

    from scori._types import Dependency
    dep = Dependency(name="openssl", version_spec="0.9.0", source_file="Cargo.toml")
    result = compute_rust(dep, project_root=tmp_path)
    assert result["cve_current"] == 3
    assert result["cve_latest"] == 0
    assert result["cwe_ids"] == ["CWE-310"]
    assert result["score"] > 0


@patch("scori.rust._fetch_rust")
def test_compute_rust_unresolved_version(mock_fetch: Any, tmp_path: Path) -> None:
    _osv_cache.clear()
    _osv_cache[("serde", "1.0.195", "crates.io")] = (0, 0, [])
    mock_fetch.return_value = _FETCH_RUST_RETURN

    from scori._types import Dependency
    dep = Dependency(name="serde", version_spec="", source_file="Cargo.toml")
    result = compute_rust(dep, project_root=tmp_path)
    assert result["current_version"] == "0.0.0"
    assert result["cve_current"] == -1


@patch("scori.rust._fetch_rust")
def test_compute_rust_transitive_pts(mock_fetch: Any, tmp_path: Path) -> None:
    _osv_cache.clear()
    _osv_cache[("tokio", "1.0.0", "crates.io")] = (0, 0, [])
    _osv_cache[("tokio", "1.35.1", "crates.io")] = (0, 0, [])
    mock_fetch.return_value = {
        "crate": {
            "name": "tokio",
            "latest_version": "1.35.1",
            "version_times": {},
            "yanked_versions": [],
        },
        "releases": [],
        "changelog": "",
    }

    from scori._types import Dependency
    dep = Dependency(name="tokio", version_spec="1.0.0", source_file="Cargo.toml")
    result = compute_rust(dep, transitive_affected=5, project_root=tmp_path)
    # jump=minor=25, transitive=min(15, 15)=15 → 40
    assert result["score"] == 40
    assert result["transitive_affected"] == 5
