from pathlib import Path

from scori.scanner import scan


def test_scan_requirements_txt(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "requests>=2.31\nrich==13.0  # comentário\n"
    )
    deps = scan(tmp_path)
    names = {d["name"] for d in deps}
    assert "requests" in names
    assert "rich" in names


def test_scan_pyproject(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndependencies = ["packaging>=24.0"]\n'
    )
    deps = scan(tmp_path)
    assert deps[0]["name"] == "packaging"


def test_scan_setup_cfg(tmp_path: Path) -> None:
    (tmp_path / "setup.cfg").write_text(
        "[options]\ninstall_requires =\n    flask>=3.0\n    sqlalchemy\n"
    )
    deps = scan(tmp_path)
    names = {d["name"] for d in deps}
    assert {"flask", "sqlalchemy"} <= names
