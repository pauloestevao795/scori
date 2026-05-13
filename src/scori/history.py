"""Score history — store and retrieve per-project friction score snapshots."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from ._types import FrictionResult

_HISTORY_DIR = Path.home() / ".local" / "share" / "scori" / "history"


def _project_key(project_root: Path) -> str:
    """Return a 12-character SHA-256 hex digest of the resolved project path."""
    resolved = str(project_root.resolve())
    return hashlib.sha256(resolved.encode()).hexdigest()[:12]


def _history_file(project_root: Path) -> Path:
    return _HISTORY_DIR / f"{_project_key(project_root)}.jsonl"


def save_snapshot(project_root: Path, results: list[FrictionResult]) -> None:
    """Append one JSONL line with the current timestamp and scores."""
    _HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    scores = {r["name"]: r["score"] for r in results}
    entry = {"ts": int(time.time()), "scores": scores}
    with _history_file(project_root).open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")


def load_history(project_root: Path, limit: int = 10) -> list[dict]:  # type: ignore[type-arg]
    """Return the last *limit* history entries, oldest first."""
    path = _history_file(project_root)
    if not path.exists():
        return []

    lines = path.read_text(encoding="utf-8").splitlines()
    entries: list[dict] = []  # type: ignore[type-arg]
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    return entries[-limit:]


def compute_trends(history: list[dict]) -> dict[str, str]:  # type: ignore[type-arg]
    """Compute a trend symbol for each package across the history window.

    Returns a dict mapping package name to one of:
        "↑"  — last score higher than first (getting riskier)
        "↓"  — last score lower than first (improving)
        "—"  — stable (first == last for all entries)
        "↕"  — fluctuating (mixed direction across entries)
    """
    if len(history) < 2:
        return {}

    # Collect all package names across all entries
    all_packages: set[str] = set()
    for entry in history:
        all_packages.update(entry.get("scores", {}).keys())

    trends: dict[str, str] = {}
    for pkg in all_packages:
        scores = [
            entry["scores"][pkg] for entry in history if pkg in entry.get("scores", {})
        ]
        if len(scores) < 2:
            trends[pkg] = "—"
            continue

        first = scores[0]
        last = scores[-1]

        # Check if there is any non-monotonic movement
        going_up = any(scores[i] < scores[i + 1] for i in range(len(scores) - 1))
        going_down = any(scores[i] > scores[i + 1] for i in range(len(scores) - 1))

        if going_up and going_down:
            trends[pkg] = "↕"
        elif first == last and not going_up and not going_down:
            trends[pkg] = "—"
        elif last > first:
            trends[pkg] = "↑"
        else:
            trends[pkg] = "↓"

    return trends
