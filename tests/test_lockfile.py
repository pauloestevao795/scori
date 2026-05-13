from pathlib import Path

from scori.lockfile import (
    detect_update_conflicts,
    load_transitive_counts,
    parse_poetry_lock,
    parse_uv_lock,
)

_UV_LOCK = """\
version = 1
requires-python = ">=3.11"

[[package]]
name = "fastapi"
version = "0.115.8"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "anyio" },
    { name = "starlette" },
]

[[package]]
name = "starlette"
version = "0.41.3"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "anyio" },
]

[[package]]
name = "anyio"
version = "4.7.0"
source = { registry = "https://pypi.org/simple" }
"""

_POETRY_LOCK = """\
[[package]]
name = "fastapi"
version = "0.115.8"
description = "FastAPI framework"
optional = false
python-versions = ">=3.8"
files = []

[package.dependencies]
anyio = ">=3.0"
starlette = ">=0.40"

[[package]]
name = "starlette"
version = "0.41.3"
description = "Starlette ASGI framework"
optional = false
python-versions = ">=3.8"
files = []

[package.dependencies]
anyio = ">=3.0"

[[package]]
name = "anyio"
version = "4.7.0"
description = "Async I/O"
optional = false
python-versions = ">=3.9"
files = []
"""


def test_parse_uv_lock(tmp_path: Path) -> None:
    lock = tmp_path / "uv.lock"
    lock.write_text(_UV_LOCK, encoding="utf-8")
    counts = parse_uv_lock(lock)
    # anyio is depended on by both fastapi and starlette
    assert counts["anyio"] == 2
    # starlette is depended on by fastapi only
    assert counts["starlette"] == 1
    # fastapi has no reverse deps in this lockfile
    assert counts.get("fastapi", 0) == 0


def test_parse_poetry_lock(tmp_path: Path) -> None:
    lock = tmp_path / "poetry.lock"
    lock.write_text(_POETRY_LOCK, encoding="utf-8")
    counts = parse_poetry_lock(lock)
    assert counts["anyio"] == 2
    assert counts["starlette"] == 1
    assert counts.get("fastapi", 0) == 0


def test_load_transitive_counts_uv_lock(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text(_UV_LOCK, encoding="utf-8")
    counts = load_transitive_counts(tmp_path)
    assert counts["anyio"] == 2


def test_load_transitive_counts_poetry_lock(tmp_path: Path) -> None:
    (tmp_path / "poetry.lock").write_text(_POETRY_LOCK, encoding="utf-8")
    counts = load_transitive_counts(tmp_path)
    assert counts["anyio"] == 2


def test_load_transitive_counts_no_lockfile(tmp_path: Path) -> None:
    assert load_transitive_counts(tmp_path) == {}


def test_load_transitive_counts_prefers_uv_lock(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text(_UV_LOCK, encoding="utf-8")
    (tmp_path / "poetry.lock").write_text(_POETRY_LOCK, encoding="utf-8")
    counts = load_transitive_counts(tmp_path)
    # Should parse uv.lock first and return its results
    assert "anyio" in counts


def test_load_transitive_counts_corrupt_lockfile(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text("not valid toml !!!", encoding="utf-8")
    assert load_transitive_counts(tmp_path) == {}


# ------------------------------ conflict detection ------------------------------


def test_detect_update_conflicts_shared_dep(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text(_UV_LOCK, encoding="utf-8")
    # fastapi and starlette both transitively depend on anyio
    warnings = detect_update_conflicts(tmp_path, ["fastapi", "starlette"])
    assert len(warnings) == 1
    assert "fastapi" in warnings[0]
    assert "starlette" in warnings[0]
    assert "anyio" in warnings[0]


def test_detect_update_conflicts_no_shared_dep(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text(_UV_LOCK, encoding="utf-8")
    # fastapi and anyio: anyio has no deps so no shared transitive dep
    warnings = detect_update_conflicts(tmp_path, ["fastapi", "anyio"])
    assert warnings == []


def test_detect_update_conflicts_single_package(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text(_UV_LOCK, encoding="utf-8")
    assert detect_update_conflicts(tmp_path, ["fastapi"]) == []


def test_detect_update_conflicts_no_lockfile(tmp_path: Path) -> None:
    assert detect_update_conflicts(tmp_path, ["fastapi", "starlette"]) == []


def test_detect_update_conflicts_poetry_lock(tmp_path: Path) -> None:
    (tmp_path / "poetry.lock").write_text(_POETRY_LOCK, encoding="utf-8")
    warnings = detect_update_conflicts(tmp_path, ["fastapi", "starlette"])
    assert len(warnings) == 1
    assert "anyio" in warnings[0]
