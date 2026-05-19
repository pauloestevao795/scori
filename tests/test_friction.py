from pathlib import Path
from unittest.mock import MagicMock, patch

import responses as rsps

from scori._types import Dependency
from scori.friction import (
    _CWE_TO_OWASP,
    _alternatives_cache,
    _current_version_from_spec,
    _cvss_weight,
    _fetch_alternatives_online,
    _fetch_osv,
    _fetch_osv_count,
    _label,
    _osv_cache,
    _scan_breaking,
    _venv_version,
    _version_jump,
    _vuln_cwe_ids,
)


def test_version_jump_major() -> None:
    assert _version_jump("3.0.0", "5.0.0") == ("major", 50)


def test_version_jump_minor() -> None:
    assert _version_jump("3.2.0", "3.5.0") == ("minor", 25)


def test_version_jump_patch() -> None:
    assert _version_jump("3.2.0", "3.2.5") == ("patch", 5)


def test_version_jump_equal() -> None:
    assert _version_jump("3.2.0", "3.2.0") == ("patch", 0)


def test_version_jump_invalid() -> None:
    assert _version_jump("abc", "1.0.0") == ("unknown", 0)


def test_label_buckets() -> None:
    assert _label(10)[0] == "Low"
    assert _label(40)[0] == "Medium"
    assert _label(60)[0] == "High"
    assert _label(90)[0] == "Critical"


def test_current_version_from_spec() -> None:
    assert _current_version_from_spec(">=2.31") == "2.31"
    assert _current_version_from_spec("==3.2.0") == "3.2.0"
    assert _current_version_from_spec("") == "0.0.0"


def test_venv_version_found(tmp_path: Path) -> None:
    sp = tmp_path / ".venv" / "lib" / "python3.11" / "site-packages"
    (sp / "uvicorn-0.46.0.dist-info").mkdir(parents=True)
    assert _venv_version(tmp_path, "uvicorn") == "0.46.0"


def test_venv_version_normalized_name(tmp_path: Path) -> None:
    sp = tmp_path / ".venv" / "lib" / "python3.11" / "site-packages"
    (sp / "python_jose-3.3.0.dist-info").mkdir(parents=True)
    assert _venv_version(tmp_path, "python-jose") == "3.3.0"


def test_venv_version_not_found(tmp_path: Path) -> None:
    assert _venv_version(tmp_path, "uvicorn") is None


def test_current_version_from_spec_resolves_venv(tmp_path: Path) -> None:
    sp = tmp_path / ".venv" / "lib" / "python3.11" / "site-packages"
    (sp / "uvicorn-0.46.0.dist-info").mkdir(parents=True)
    assert _current_version_from_spec("", "uvicorn", tmp_path) == "0.46.0"


def test_current_version_from_spec_fallback_no_venv(tmp_path: Path) -> None:
    assert _current_version_from_spec("", "uvicorn", tmp_path) == "0.0.0"


@rsps.activate
def test_fetch_osv_count_with_vulns() -> None:
    _osv_cache.clear()
    rsps.add(
        rsps.POST,
        "https://api.osv.dev/v1/query",
        json={"vulns": [{"id": "GHSA-1"}, {"id": "GHSA-2"}]},
        status=200,
    )
    assert _fetch_osv_count("python-jose", "3.3.0") == 2


@rsps.activate
def test_fetch_osv_count_no_vulns() -> None:
    _osv_cache.clear()
    rsps.add(
        rsps.POST,
        "https://api.osv.dev/v1/query",
        json={},
        status=200,
    )
    assert _fetch_osv_count("requests", "2.32.0") == 0


@rsps.activate
def test_fetch_osv_count_api_error() -> None:
    _osv_cache.clear()
    rsps.add(rsps.POST, "https://api.osv.dev/v1/query", status=500)
    assert _fetch_osv_count("requests", "2.32.0") == 0


def test_fetch_osv_count_uses_cache() -> None:
    _osv_cache.clear()
    _osv_cache[("requests", "2.32.0", "PyPI")] = (3, 3, [])
    assert _fetch_osv_count("requests", "2.32.0") == 3


@rsps.activate
def test_fetch_osv_critical_cvss_weight() -> None:
    _osv_cache.clear()
    rsps.add(
        rsps.POST,
        "https://api.osv.dev/v1/query",
        json={
            "vulns": [
                {
                    "id": "GHSA-1",
                    "database_specific": {
                        "severity": "CRITICAL",
                        "cwe_ids": ["CWE-79"],
                    },
                },
                {
                    "id": "GHSA-2",
                    "database_specific": {
                        "severity": "HIGH",
                        "cwe_ids": ["CWE-89"],
                    },
                },
            ]
        },
        status=200,
    )
    total, weighted, cwe_ids = _fetch_osv("python-jose", "3.3.0")
    assert total == 2
    assert weighted == 3  # 2 (CRITICAL) + 1 (HIGH)
    assert "CWE-79" in cwe_ids
    assert "CWE-89" in cwe_ids


def test_vuln_cwe_ids_deduplication() -> None:
    vulns = [
        {"database_specific": {"cwe_ids": ["CWE-79", "CWE-89"]}},
        {"database_specific": {"cwe_ids": ["CWE-79"]}},  # duplicate
    ]
    ids = _vuln_cwe_ids(vulns)
    assert ids.count("CWE-79") == 1
    assert "CWE-89" in ids


def test_cwe_to_owasp_mapping() -> None:
    assert _CWE_TO_OWASP["CWE-79"] == "A03"  # XSS → Injection
    assert _CWE_TO_OWASP["CWE-89"] == "A03"  # SQL Injection
    assert _CWE_TO_OWASP["CWE-918"] == "A10"  # SSRF


def test_cvss_weight_critical() -> None:
    assert _cvss_weight({"database_specific": {"severity": "CRITICAL"}}) == 2


def test_cvss_weight_high() -> None:
    assert _cvss_weight({"database_specific": {"severity": "HIGH"}}) == 1


def test_cvss_weight_no_severity() -> None:
    assert _cvss_weight({}) == 1


def test_scan_breaking_detects_changelog_keywords() -> None:
    changelog = """\
## [2.0.0]
This release has a breaking change to the API.
Removed the old endpoint.

## [1.0.0]
Initial release.
"""
    signals = _scan_breaking([], "1.0.0", "2.0.0", changelog)
    assert any("CHANGELOG" in s or "changelog" in s.lower() for s in signals)


def test_scan_breaking_ignores_out_of_range_changelog() -> None:
    changelog = """\
## [2.0.0]
Nothing special here.

## [1.5.0]
breaking change here

## [1.0.0]
Initial release.
"""
    # current=1.5.0, latest=2.0.0 — the breaking in 1.5.0 is NOT in range
    signals = _scan_breaking([], "1.5.0", "2.0.0", changelog)
    assert all("1.5.0" not in s for s in signals)


def test_dependency_typeddict() -> None:
    d: Dependency = {
        "name": "x",
        "version_spec": ">=1.0",
        "source_file": "pyproject.toml",
    }
    assert d["name"] == "x"


@rsps.activate
def test_fetch_alternatives_online_returns_safe_package() -> None:
    _alternatives_cache.clear()
    _osv_cache.clear()

    pypi_data = {"info": {"keywords": "http client rest", "classifiers": []}}

    xmlrpc_result = [{"name": "httpx"}, {"name": "requests"}]
    mock_client = MagicMock()
    mock_client.search.return_value = xmlrpc_result

    rsps.add(
        rsps.GET,
        "https://pypi.org/pypi/httpx/json",
        json={"info": {"version": "0.27.0"}},
        status=200,
    )
    rsps.add(
        rsps.POST,
        "https://api.osv.dev/v1/query",
        json={},
        status=200,
    )

    with patch("xmlrpc.client.ServerProxy", return_value=mock_client):
        result = _fetch_alternatives_online("requests", pypi_data)

    assert "httpx" in result


def test_fetch_alternatives_online_no_keywords() -> None:
    _alternatives_cache.clear()
    pypi_data: dict = {"info": {"keywords": "", "classifiers": []}}
    result = _fetch_alternatives_online("some-unknown-lib", pypi_data)
    assert result == []


def test_fetch_alternatives_online_uses_cache() -> None:
    _alternatives_cache["cached-pkg"] = ["safepkg"]
    pypi_data: dict = {"info": {"keywords": "x y z", "classifiers": []}}
    result = _fetch_alternatives_online("cached-pkg", pypi_data)
    assert result == ["safepkg"]
