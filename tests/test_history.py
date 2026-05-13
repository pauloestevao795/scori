import json
from pathlib import Path

from scori.history import compute_trends, load_history, save_snapshot


def _make_result(name: str, score: int) -> dict:  # type: ignore[type-arg]
    return {"name": name, "score": score}


def test_save_snapshot_creates_jsonl(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from scori import history as hist_mod

    monkeypatch.setattr(hist_mod, "_HISTORY_DIR", tmp_path / "history")
    results = [_make_result("requests", 8), _make_result("django", 78)]
    save_snapshot(tmp_path, results)  # type: ignore[arg-type]

    files = list((tmp_path / "history").glob("*.jsonl"))
    assert len(files) == 1
    lines = files[0].read_text().strip().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["scores"]["requests"] == 8
    assert entry["scores"]["django"] == 78


def test_load_history_returns_entries(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from scori import history as hist_mod

    monkeypatch.setattr(hist_mod, "_HISTORY_DIR", tmp_path / "history")
    save_snapshot(tmp_path, [_make_result("requests", 8)])  # type: ignore[arg-type]
    save_snapshot(tmp_path, [_make_result("requests", 12)])  # type: ignore[arg-type]

    history = load_history(tmp_path)
    assert len(history) == 2
    assert history[0]["scores"]["requests"] == 8
    assert history[1]["scores"]["requests"] == 12


def test_load_history_limit(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from scori import history as hist_mod

    monkeypatch.setattr(hist_mod, "_HISTORY_DIR", tmp_path / "history")
    for score in range(20):
        save_snapshot(tmp_path, [_make_result("pkg", score)])  # type: ignore[arg-type]

    history = load_history(tmp_path, limit=5)
    assert len(history) == 5
    # should be last 5
    assert history[-1]["scores"]["pkg"] == 19


def test_load_history_no_file(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from scori import history as hist_mod

    monkeypatch.setattr(hist_mod, "_HISTORY_DIR", tmp_path / "history")
    assert load_history(tmp_path) == []


def test_compute_trends_increasing() -> None:
    history = [
        {"scores": {"requests": 10}},
        {"scores": {"requests": 20}},
        {"scores": {"requests": 30}},
    ]
    trends = compute_trends(history)
    assert trends["requests"] == "↑"


def test_compute_trends_decreasing() -> None:
    history = [
        {"scores": {"requests": 30}},
        {"scores": {"requests": 20}},
        {"scores": {"requests": 10}},
    ]
    trends = compute_trends(history)
    assert trends["requests"] == "↓"


def test_compute_trends_stable() -> None:
    history = [
        {"scores": {"requests": 8}},
        {"scores": {"requests": 8}},
        {"scores": {"requests": 8}},
    ]
    trends = compute_trends(history)
    assert trends["requests"] == "—"


def test_compute_trends_fluctuating() -> None:
    history = [
        {"scores": {"requests": 10}},
        {"scores": {"requests": 30}},
        {"scores": {"requests": 15}},
    ]
    trends = compute_trends(history)
    assert trends["requests"] == "↕"


def test_compute_trends_single_entry() -> None:
    history = [{"scores": {"requests": 10}}]
    trends = compute_trends(history)
    assert trends == {}
