"""Format raw NVD CVE responses into a clean, LLM-friendly structure.

The NVD API returns deeply nested JSON with a lot of fields that aren't useful
for vulnerability triage. This module extracts the signal: description, CVSS
scores, severity, affected products, and references.
"""

from __future__ import annotations

from typing import Any


def format_cve(raw: dict[str, Any]) -> dict[str, Any]:
    """Extract the triage-relevant fields from an NVD CVE response.

    Args:
        raw: The full JSON response from the NVD CVE API.

    Returns:
        A flat-ish dict with the fields that matter for vulnerability triage.
    """
    cve = raw["vulnerabilities"][0]["cve"]

    return {
        "cve_id": cve.get("id"),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "status": cve.get("vulnStatus"),
        "description": _extract_description(cve),
        "cvss": _extract_cvss(cve),
        "weaknesses": _extract_weaknesses(cve),
        "references": _extract_references(cve),
        "source_url": f"https://nvd.nist.gov/vuln/detail/{cve.get('id')}",
    }


def _extract_description(cve: dict[str, Any]) -> str:
    """Get the English-language description, falling back to the first available."""
    descriptions = cve.get("descriptions", [])
    for desc in descriptions:
        if desc.get("lang") == "en":
            return desc.get("value", "")
    return descriptions[0].get("value", "") if descriptions else ""


def _extract_cvss(cve: dict[str, Any]) -> dict[str, Any] | None:
    """Pull the best-available CVSS score, preferring v3.1 > v3.0 > v2."""
    metrics = cve.get("metrics", {})

    for key in ("cvssMetricV31", "cvssMetricV30"):
        if entries := metrics.get(key):
            data = entries[0]["cvssData"]
            return {
                "version": data.get("version"),
                "base_score": data.get("baseScore"),
                "severity": data.get("baseSeverity"),
                "vector": data.get("vectorString"),
                "attack_vector": data.get("attackVector"),
                "attack_complexity": data.get("attackComplexity"),
                "privileges_required": data.get("privilegesRequired"),
                "user_interaction": data.get("userInteraction"),
            }

    if entries := metrics.get("cvssMetricV2"):
        data = entries[0]["cvssData"]
        return {
            "version": data.get("version"),
            "base_score": data.get("baseScore"),
            "severity": entries[0].get("baseSeverity"),
            "vector": data.get("vectorString"),
        }

    return None


def _extract_weaknesses(cve: dict[str, Any]) -> list[str]:
    """Get CWE identifiers (e.g. 'CWE-79') associated with this CVE."""
    cwes: list[str] = []
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            value = desc.get("value", "")
            if value.startswith("CWE-") and value not in cwes:
                cwes.append(value)
    return cwes


def _extract_references(cve: dict[str, Any], limit: int = 8) -> list[dict[str, Any]]:
    """Get reference URLs with their tags (e.g. 'Patch', 'Exploit', 'Vendor Advisory')."""
    refs = []
    for ref in cve.get("references", [])[:limit]:
        refs.append(
            {
                "url": ref.get("url"),
                "tags": ref.get("tags", []),
                "source": ref.get("source"),
            }
        )
    return refs
