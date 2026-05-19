from pathlib import Path

from scori.scanner import scan


def test_scan_pipfile(tmp_path: Path) -> None:
    (tmp_path / "Pipfile").write_text(
        '[packages]\nrequests = ">=2.28"\nflask = "*"\ndjango = {version = "==4.2.0"}\n'
        '[dev-packages]\npytest = ">=7.0"\n'
    )
    deps = scan(tmp_path)
    names = {d["name"].lower() for d in deps}
    assert {"requests", "flask", "django", "pytest"} <= names
    django = next(d for d in deps if d["name"].lower() == "django")
    assert django["version_spec"] == "==4.2.0"
    flask = next(d for d in deps if d["name"].lower() == "flask")
    assert flask["version_spec"] == ""


def test_scan_conda_yml(tmp_path: Path) -> None:
    (tmp_path / "environment.yml").write_text(
        "name: myenv\n"
        "dependencies:\n"
        "  - numpy=1.24.0\n"
        "  - scipy>=1.10\n"
        "  - pip:\n"
        "    - requests==2.31.0\n"
        "    - flask>=2.0\n"
    )
    deps = scan(tmp_path)
    names = {d["name"].lower() for d in deps}
    assert {"numpy", "scipy", "requests", "flask"} <= names
    numpy = next(d for d in deps if d["name"].lower() == "numpy")
    assert numpy["version_spec"] == "==1.24.0"


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
