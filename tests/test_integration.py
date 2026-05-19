"""Integration tests against real PyPI packages.

These tests make live network calls and are excluded from the default
test run. Execute them explicitly:

    pytest -m integration

They verify that compute() and scan() produce structurally valid results
against well-known real-world projects, and that the friction score
algorithm behaves sensibly for packages with known properties.
"""

import pathlib

import pytest

from scori import Dependency, FrictionResult, compute, scan

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

_VALID_LABELS: set[str] = {"Low", "Medium", "High", "Critical"}
_VALID_JUMPS: set[str] = {"patch", "minor", "major", "unknown"}


def _assert_valid(result: FrictionResult) -> None:
    assert isinstance(result["name"], str) and result["name"]
    assert isinstance(result["score"], int)
    assert 0 <= result["score"] <= 100
    assert result["label"] in _VALID_LABELS
    assert result["version_jump"] in _VALID_JUMPS
    assert isinstance(result["breaking_signals"], list)
    assert isinstance(result["transitive_affected"], int)
    assert isinstance(result["months_outdated"], (int, float))
    assert isinstance(result["yanked"], bool)
    assert isinstance(result["recommendation"], str) and result["recommendation"]
    assert isinstance(result["cve_current"], int)
    assert isinstance(result["cve_latest"], int)
    assert isinstance(result["cwe_ids"], list)
    assert isinstance(result["alternatives"], list)
    assert result["current_version"] != ""
    assert result["latest_version"] != ""


# ---------------------------------------------------------------------------
# compute() — structural validity
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_compute_requests_pinned() -> None:
    dep = Dependency(name="requests", version_spec="==2.28.0", source_file="requirements.txt")
    result = compute(dep)
    _assert_valid(result)
    assert result["name"] == "requests"
    assert result["current_version"] == "2.28.0"
    # 2.28.0 is not the latest — score must reflect some friction
    assert result["score"] > 0


@pytest.mark.integration
def test_compute_flask_pinned() -> None:
    dep = Dependency(name="flask", version_spec="==2.3.0", source_file="requirements.txt")
    result = compute(dep)
    _assert_valid(result)
    assert result["name"] == "flask"
    assert result["score"] >= 0


@pytest.mark.integration
def test_compute_numpy_major_jump() -> None:
    dep = Dependency(name="numpy", version_spec="==1.24.0", source_file="requirements.txt")
    result = compute(dep)
    _assert_valid(result)
    # numpy 1.x → 2.x is a known major jump; score should be High or Critical
    if result["version_jump"] == "major":
        assert result["score"] >= 50


@pytest.mark.integration
def test_compute_unpinned_falls_back() -> None:
    dep = Dependency(name="rich", version_spec="", source_file="requirements.txt")
    result = compute(dep)
    _assert_valid(result)
    # Without a pinned version and no local venv, current == latest → low score
    assert result["score"] >= 0


@pytest.mark.integration
def test_compute_result_is_stable() -> None:
    dep = Dependency(name="packaging", version_spec="==24.0", source_file="pyproject.toml")
    r1 = compute(dep)
    r2 = compute(dep)
    assert r1["score"] == r2["score"]
    assert r1["label"] == r2["label"]


# ---------------------------------------------------------------------------
# score semantics
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_patch_jump_scores_lower_than_major() -> None:
    patch = Dependency(name="certifi", version_spec="==2023.11.17", source_file="r.txt")
    major = Dependency(name="django", version_spec="==3.2.0", source_file="r.txt")

    patch_result = compute(patch)
    major_result = compute(major)

    _assert_valid(patch_result)
    _assert_valid(major_result)

    if patch_result["version_jump"] == "patch" and major_result["version_jump"] == "major":
        assert patch_result["score"] < major_result["score"]


# ---------------------------------------------------------------------------
# scan() — real-world project layout
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_scan_scori_itself() -> None:
    """scan() can read scori's own pyproject.toml without errors."""
    repo_root = pathlib.Path(__file__).parent.parent
    deps = scan(repo_root)
    names = {d["name"].lower() for d in deps}
    assert {"requests", "rich", "packaging"} <= names


