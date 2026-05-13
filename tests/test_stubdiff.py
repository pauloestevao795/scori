import io
import zipfile
from pathlib import Path

import responses as rsps

from scori.stubdiff import _public_names, _wheel_url, stub_signals


def _make_wheel(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def test_public_names_from_pyi(tmp_path: Path) -> None:
    wheel = tmp_path / "pkg.whl"
    wheel.write_bytes(
        _make_wheel(
            {
                "pkg/__init__.pyi": (
                    "def connect() -> None: ...\n"
                    "class Client: ...\n"
                    "def _private() -> None: ...\n"
                )
            }
        )
    )
    names = _public_names(wheel)
    assert "connect" in names
    assert "Client" in names
    assert "_private" not in names


def test_public_names_falls_back_to_py(tmp_path: Path) -> None:
    wheel = tmp_path / "pkg.whl"
    wheel.write_bytes(
        _make_wheel({"pkg/client.py": "def send(): pass\nclass Session: pass\n"})
    )
    names = _public_names(wheel)
    assert "send" in names
    assert "Session" in names


def test_public_names_empty_wheel(tmp_path: Path) -> None:
    wheel = tmp_path / "pkg.whl"
    wheel.write_bytes(_make_wheel({}))
    assert _public_names(wheel) == set()


def test_stub_signals_same_version() -> None:
    assert stub_signals("requests", "2.31.0", "2.31.0") == []


def test_stub_signals_zero_version() -> None:
    assert stub_signals("requests", "0.0.0", "2.32.3") == []


@rsps.activate
def test_stub_signals_detects_removal(tmp_path: Path) -> None:
    rsps.add(
        rsps.GET,
        "https://pypi.org/pypi/mypkg/1.0.0/json",
        json={
            "urls": [
                {
                    "filename": "mypkg-1.0.0-py3-none-any.whl",
                    "url": "https://files.pypi.org/mypkg-1.0.0-py3-none-any.whl",
                }
            ]
        },
        status=200,
    )
    rsps.add(
        rsps.GET,
        "https://pypi.org/pypi/mypkg/2.0.0/json",
        json={
            "urls": [
                {
                    "filename": "mypkg-2.0.0-py3-none-any.whl",
                    "url": "https://files.pypi.org/mypkg-2.0.0-py3-none-any.whl",
                }
            ]
        },
        status=200,
    )
    rsps.add(
        rsps.GET,
        "https://files.pypi.org/mypkg-1.0.0-py3-none-any.whl",
        body=_make_wheel(
            {"mypkg/__init__.pyi": "def old_api(): ...\ndef kept(): ...\n"}
        ),
        status=200,
    )
    rsps.add(
        rsps.GET,
        "https://files.pypi.org/mypkg-2.0.0-py3-none-any.whl",
        body=_make_wheel({"mypkg/__init__.pyi": "def kept(): ...\n"}),
        status=200,
    )

    signals = stub_signals("mypkg", "1.0.0", "2.0.0")
    assert len(signals) == 1
    assert "old_api" in signals[0]
    assert "API removal" in signals[0]


@rsps.activate
def test_stub_signals_no_removal() -> None:
    rsps.add(
        rsps.GET,
        "https://pypi.org/pypi/mypkg/1.0.0/json",
        json={
            "urls": [
                {
                    "filename": "mypkg-1.0.0-py3-none-any.whl",
                    "url": "https://files.pypi.org/mypkg-1.0.0.whl",
                }
            ]
        },
        status=200,
    )
    rsps.add(
        rsps.GET,
        "https://pypi.org/pypi/mypkg/2.0.0/json",
        json={
            "urls": [
                {
                    "filename": "mypkg-2.0.0-py3-none-any.whl",
                    "url": "https://files.pypi.org/mypkg-2.0.0.whl",
                }
            ]
        },
        status=200,
    )
    rsps.add(
        rsps.GET,
        "https://files.pypi.org/mypkg-1.0.0.whl",
        body=_make_wheel({"mypkg/__init__.pyi": "def api(): ...\n"}),
        status=200,
    )
    rsps.add(
        rsps.GET,
        "https://files.pypi.org/mypkg-2.0.0.whl",
        body=_make_wheel(
            {"mypkg/__init__.pyi": "def api(): ...\ndef new_api(): ...\n"}
        ),
        status=200,
    )

    assert stub_signals("mypkg", "1.0.0", "2.0.0") == []


@rsps.activate
def test_wheel_url_prefers_none_any() -> None:
    rsps.add(
        rsps.GET,
        "https://pypi.org/pypi/requests/2.31.0/json",
        json={
            "urls": [
                {
                    "filename": "requests-2.31.0-cp311-cp311-linux.whl",
                    "url": "https://x/cp.whl",
                },
                {
                    "filename": "requests-2.31.0-py3-none-any.whl",
                    "url": "https://x/any.whl",
                },
            ]
        },
        status=200,
    )
    assert _wheel_url("requests", "2.31.0") == "https://x/any.whl"


@rsps.activate
def test_wheel_url_not_found() -> None:
    rsps.add(rsps.GET, "https://pypi.org/pypi/mypkg/1.0.0/json", status=404)
    assert _wheel_url("mypkg", "1.0.0") is None
