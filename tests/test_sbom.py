from scori._types import FrictionResult
from scori.sbom import _purl, to_cyclonedx


def _result(name: str, score: int = 20, label: str = "Low") -> FrictionResult:
    return FrictionResult(
        name=name,
        current_version="1.0.0",
        latest_version="1.1.0",
        score=score,
        label=label,  # type: ignore[arg-type]
        version_jump="minor",
        breaking_signals=[],
        transitive_affected=0,
        months_outdated=1.0,
        yanked=False,
        recommendation="Safe to update",
        cve_current=0,
        cve_latest=0,
        cwe_ids=[],
        alternatives=[],
    )


def test_purl_format() -> None:
    assert _purl("Requests", "2.31.0") == "pkg:pypi/requests@2.31.0"
    assert _purl("python-jose", "3.3.0") == "pkg:pypi/python-jose@3.3.0"


def test_to_cyclonedx_structure() -> None:
    bom = to_cyclonedx(
        [_result("requests"), _result("django", score=78, label="Critical")]
    )
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.5"
    assert bom["version"] == 1
    assert bom["serialNumber"].startswith("urn:uuid:")
    assert "metadata" in bom
    assert len(bom["components"]) == 2


def test_to_cyclonedx_component_fields() -> None:
    bom = to_cyclonedx([_result("requests")])
    comp = bom["components"][0]
    assert comp["type"] == "library"
    assert comp["name"] == "requests"
    assert comp["version"] == "1.0.0"
    assert comp["purl"] == "pkg:pypi/requests@1.0.0"
    assert comp["bom-ref"] == "pkg:pypi/requests@1.0.0"


def test_to_cyclonedx_scori_properties() -> None:
    bom = to_cyclonedx([_result("requests", score=20, label="Low")])
    props = {p["name"]: p["value"] for p in bom["components"][0]["properties"]}
    assert props["scori:friction-score"] == "20"
    assert props["scori:label"] == "Low"
    assert props["scori:version-jump"] == "minor"
    assert props["scori:latest-version"] == "1.1.0"
    assert props["scori:breaking-signals"] == "0"


def test_to_cyclonedx_cwe_ids() -> None:
    r = _result("requests")
    r["cwe_ids"] = ["CWE-79", "CWE-89"]
    bom = to_cyclonedx([r])
    props = {p["name"]: p["value"] for p in bom["components"][0]["properties"]}
    assert props["scori:cwe-ids"] == "CWE-79,CWE-89"


def test_to_cyclonedx_empty() -> None:
    bom = to_cyclonedx([])
    assert bom["components"] == []


def test_to_cyclonedx_metadata_tool() -> None:
    bom = to_cyclonedx([_result("requests")])
    tools = bom["metadata"]["tools"]
    assert any(t["name"] == "scori" for t in tools)
