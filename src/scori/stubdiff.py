"""Heuristic stub-diff: detect public API removals between two package versions.

Downloads both wheels from PyPI, extracts .pyi stubs (falling back to .py
source files), and reports public names that exist in the current version but
are absent in the latest — a strong signal that the update contains breaking
API changes.

Used as an opt-in breaking-signal source (scori friction --stub-diff) since
it requires downloading additional wheel files.
"""

from __future__ import annotations

import re
import tempfile
import zipfile
from pathlib import Path
from typing import Any

import requests

_PUBLIC_DEF_RE = re.compile(
    r"^(?:def |class )\s*([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE
)


def _wheel_url(package: str, version: str) -> str | None:
    """Return the download URL of the best wheel for package==version."""
    try:
        r = requests.get(f"https://pypi.org/pypi/{package}/{version}/json", timeout=10)
        if not r.ok:
            return None
        urls: list[dict[str, Any]] = r.json().get("urls") or []
        # Prefer pure-Python wheels (smallest, no platform noise)
        for u in urls:
            fname: str = u.get("filename") or ""
            if fname.endswith(".whl") and "none-any" in fname:
                return str(u.get("url") or "")
        for u in urls:
            fname = u.get("filename") or ""
            if fname.endswith(".whl"):
                return str(u.get("url") or "")
    except requests.RequestException:
        pass
    return None


def _download(url: str, dest: Path) -> bool:
    try:
        r = requests.get(url, timeout=30, stream=True)
        if not r.ok:
            return False
        dest.write_bytes(r.content)
        return True
    except requests.RequestException:
        return False


def _public_names(wheel_path: Path) -> set[str]:
    """Extract public symbol names from .pyi stubs inside a wheel zip."""
    names: set[str] = set()
    try:
        with zipfile.ZipFile(wheel_path) as zf:
            candidates = [n for n in zf.namelist() if n.endswith(".pyi")]
            if not candidates:
                candidates = [
                    n
                    for n in zf.namelist()
                    if n.endswith(".py") and "__pycache__" not in n
                ]
            for entry in candidates:
                try:
                    text = zf.read(entry).decode("utf-8", errors="replace")
                    for m in _PUBLIC_DEF_RE.finditer(text):
                        sym = m.group(1)
                        if not sym.startswith("_"):
                            names.add(sym)
                except Exception:
                    continue
    except Exception:
        pass
    return names


def stub_signals(package: str, current: str, latest: str) -> list[str]:
    """Return breaking-signal strings from public API diff between current and latest.

    Downloads both wheels into a temp directory, extracts public names, and
    returns a list of signal strings describing removed symbols. Returns [] on
    any failure (network error, unsupported format, etc.).
    """
    if current in ("0.0.0", latest):
        return []

    cur_url = _wheel_url(package, current)
    lat_url = _wheel_url(package, latest)
    if not cur_url or not lat_url:
        return []

    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        if not _download(cur_url, tmpdir / "current.whl"):
            return []
        if not _download(lat_url, tmpdir / "latest.whl"):
            return []

        cur_names = _public_names(tmpdir / "current.whl")
        lat_names = _public_names(tmpdir / "latest.whl")

    removed = cur_names - lat_names
    if not removed:
        return []

    examples = sorted(removed)[:5]
    suffix = " (and more)" if len(removed) > 5 else ""
    return [f"API removal in stubs: {', '.join(examples)}{suffix}"]
