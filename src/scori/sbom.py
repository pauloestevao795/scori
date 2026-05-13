"""CycloneDX 1.5 SBOM generation from FrictionResult data.

Spec: https://cyclonedx.org/specification/overview/
Each component carries scori-specific properties alongside standard fields,
enabling downstream compliance tooling (NTIA, EU CRA, US EO 14028) to
consume both the inventory and the friction/vulnerability context.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from . import __version__
from ._types import FrictionResult


def _purl(name: str, version: str) -> str:
    return f"pkg:pypi/{name.lower()}@{version}"


def to_cyclonedx(results: list[FrictionResult]) -> dict[str, Any]:
    """Return a CycloneDX 1.5 BOM dict from a list of FrictionResult entries."""
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    components: list[dict[str, Any]] = []
    for r in results:
        components.append(
            {
                "type": "library",
                "bom-ref": _purl(r["name"], r["current_version"]),
                "name": r["name"],
                "version": r["current_version"],
                "purl": _purl(r["name"], r["current_version"]),
                "properties": [
                    {"name": "scori:friction-score", "value": str(r["score"])},
                    {"name": "scori:label", "value": r["label"]},
                    {"name": "scori:version-jump", "value": r["version_jump"]},
                    {"name": "scori:latest-version", "value": r["latest_version"]},
                    {
                        "name": "scori:cwe-ids",
                        "value": ",".join(r["cwe_ids"]) if r["cwe_ids"] else "",
                    },
                    {
                        "name": "scori:breaking-signals",
                        "value": str(len(r["breaking_signals"])),
                    },
                ],
            }
        )

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "metadata": {
            "timestamp": now,
            "tools": [
                {
                    "vendor": "scori",
                    "name": "scori",
                    "version": __version__,
                }
            ],
        },
        "components": components,
    }
