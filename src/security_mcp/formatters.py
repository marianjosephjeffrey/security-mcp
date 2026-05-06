"""Format raw API responses into clean, LLM-friendly structures.

The goal: extract signal, drop noise, add semantic meaning where raw numbers
(e.g. "epss: 0.04127") would otherwise force the LLM to guess at thresholds.
"""

from __future__ import annotations

from typing import Any


# ============================================================
# CVE formatting
# ============================================================

def format_cve(cve: dict[str, Any]) -> dict[str, Any]:
    """Extract the triage-relevant fields from an inner NVD CVE object.

    Args:
        cve: The 'cve' dict from inside an NVD response (use nvd.extract_cve()).
    """
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
    descriptions = cve.get("descriptions", [])
    for desc in descriptions:
        if desc.get("lang") == "en":
            return desc.get("value", "")
    return descriptions[0].get("value", "") if descriptions else ""


def _extract_cvss(cve: dict[str, Any]) -> dict[str, Any] | None:
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
    cwes: list[str] = []
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            value = desc.get("value", "")
            if value.startswith("CWE-") and value not in cwes:
                cwes.append(value)
    return cwes


def _extract_references(cve: dict[str, Any], limit: int = 8) -> list[dict[str, Any]]:
    refs = []
    for ref in cve.get("references", [])[:limit]:
        refs.append({
            "url": ref.get("url"),
            "tags": ref.get("tags", []),
            "source": ref.get("source"),
        })
    return refs


# ============================================================
# EPSS formatting
# ============================================================

def format_epss(epss: dict[str, Any] | None) -> dict[str, Any]:
    """Format an EPSS lookup result, adding human-readable interpretation.

    EPSS percentiles are the actually-useful number — the raw probability is
    almost always below 5% even for high-risk CVEs. Industry convention:
      - >= 0.95 percentile: very high priority (top 5% of all CVEs)
      - >= 0.90 percentile: high priority (top 10%)
      - >= 0.50 percentile: moderate (above the median)
      - <  0.50 percentile: low priority by EPSS alone
    """
    if epss is None:
        return {
            "available": False,
            "note": "EPSS has no score for this CVE yet (typical for CVEs published in the last few days).",
        }

    percentile = epss.get("percentile") or 0.0
    if percentile >= 0.95:
        priority = "very high"
    elif percentile >= 0.90:
        priority = "high"
    elif percentile >= 0.50:
        priority = "moderate"
    else:
        priority = "low"

    return {
        "available": True,
        "epss_probability": epss.get("epss"),
        "percentile": percentile,
        "priority": priority,
        "interpretation": (
            f"{percentile:.1%} of CVEs score lower than this one. "
            f"Estimated {(epss.get('epss') or 0) * 100:.2f}% chance of "
            f"observed exploitation in the next 30 days."
        ),
        "score_date": epss.get("date"),
        "source_url": "https://www.first.org/epss",
    }


# ============================================================
# KEV formatting
# ============================================================

def format_kev(kev: dict[str, Any] | None) -> dict[str, Any]:
    """Format a KEV lookup result.

    Being on KEV means CISA has confirmed real-world exploitation. This is a
    binary "patch immediately" signal that overrides almost any CVSS or EPSS
    consideration.
    """
    if kev is None:
        return {
            "on_kev_catalog": False,
            "note": "Not in CISA's Known Exploited Vulnerabilities catalog.",
        }

    return {
        "on_kev_catalog": True,
        "vendor": kev.get("vendorProject"),
        "product": kev.get("product"),
        "vulnerability_name": kev.get("vulnerabilityName"),
        "date_added_to_kev": kev.get("dateAdded"),
        "due_date": kev.get("dueDate"),
        "required_action": kev.get("requiredAction"),
        "known_ransomware_use": kev.get("knownRansomwareCampaignUse") == "Known",
        "short_description": kev.get("shortDescription"),
        "notes": kev.get("notes"),
        "source_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    }
