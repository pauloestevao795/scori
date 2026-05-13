from pathlib import Path
from unittest.mock import patch

import pytest

from scori._types import FrictionResult
from scori.fix import (
    _apply_updates,
    _build_pr_body,
    _update_line,
    create_pr,
)


def _result(name: str, score: int = 10) -> FrictionResult:
    return FrictionResult(
        name=name,
        current_version="1.0.0",
        latest_version="2.0.0",
        score=score,
        label="Low",  # type: ignore[arg-type]
        version_jump="major",
        breaking_signals=[],
        transitive_affected=0,
        months_outdated=0.0,
        yanked=False,
        recommendation="Safe to update",
        cve_current=0,
        cve_latest=0,
        cwe_ids=[],
        alternatives=[],
    )


def test_update_line_requirements_txt() -> None:
    line = "requests>=2.28.0\n"
    result = _update_line(line, "requests", "2.32.3")
    assert result == "requests==2.32.3\n"


def test_update_line_pinned() -> None:
    line = "django==3.2.0\n"
    result = _update_line(line, "django", "5.1.0")
    assert result == "django==5.1.0\n"


def test_update_line_no_match() -> None:
    assert _update_line("# comment\n", "requests", "2.32.3") is None
    assert _update_line("flask>=2.0\n", "requests", "2.32.3") is None


def test_apply_updates_writes_file(tmp_path: Path) -> None:
    req = tmp_path / "requirements.txt"
    req.write_text("requests>=2.28.0\nflask>=2.0\n", encoding="utf-8")
    updates = [("requests", "2.28.0", "2.32.3", "requirements.txt")]
    applied = _apply_updates(tmp_path, updates)
    assert applied == 1
    content = req.read_text()
    assert "requests==2.32.3" in content
    assert "flask>=2.0" in content  # unchanged


def test_apply_updates_missing_file(tmp_path: Path) -> None:
    updates = [("requests", "2.28.0", "2.32.3", "nonexistent.txt")]
    applied = _apply_updates(tmp_path, updates)
    assert applied == 0


def test_build_pr_body_contains_package_names() -> None:
    updates = [("requests", "2.28.0", "2.32.3", "requirements.txt")]
    results = [_result("requests", score=8)]
    body = _build_pr_body(updates, results)
    assert "requests" in body
    assert "2.28.0" in body
    assert "2.32.3" in body
    assert "scori" in body


def test_create_pr_dry_run(tmp_path: Path) -> None:
    result = create_pr(
        project_root=tmp_path,
        updates=[("requests", "2.28.0", "2.32.3", "requirements.txt")],
        results=[_result("requests")],
        dry_run=True,
    )
    assert result["dry_run"] is True
    assert result["pr_url"] is None
    assert "branch" in result


def test_create_pr_requires_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    with pytest.raises(ValueError, match="GITHUB_TOKEN"):
        create_pr(
            project_root=tmp_path,
            updates=[("requests", "2.28.0", "2.32.3", "requirements.txt")],
            results=[_result("requests")],
            dry_run=False,
        )


def test_create_pr_requires_github_remote(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_fake")
    with (
        patch("scori.fix._git", return_value=(0, "")),
        patch("scori.fix.detect_github_remote", return_value=None),
        patch("scori.fix.has_uncommitted_changes", return_value=False),
        pytest.raises(ValueError, match="GitHub remote"),
    ):
        create_pr(
            project_root=tmp_path,
            updates=[("requests", "2.28.0", "2.32.3", "requirements.txt")],
            results=[_result("requests")],
            dry_run=False,
        )


def test_create_pr_aborts_on_dirty_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_fake")
    with (
        patch("scori.fix.detect_github_remote", return_value=("owner", "repo")),
        patch("scori.fix.has_uncommitted_changes", return_value=True),
        pytest.raises(ValueError, match="uncommitted"),
    ):
        create_pr(
            project_root=tmp_path,
            updates=[("requests", "2.28.0", "2.32.3", "requirements.txt")],
            results=[_result("requests")],
            dry_run=False,
        )
