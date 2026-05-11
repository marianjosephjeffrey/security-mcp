"""Extract affected-version information from NVD CVE records.

NVD's `configurations` field expresses which products and versions are
vulnerable, using the CPE (Common Platform Enumeration) format plus
optional version-range bounds.

Each `cpeMatch` entry has:
  - criteria:               A CPE 2.3 string like cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*
  - versionStartIncluding:  Optional lower bound (inclusive)
  - versionStartExcluding:  Optional lower bound (exclusive)
  - versionEndIncluding:    Optional upper bound (inclusive)
  - versionEndExcluding:    Optional upper bound (exclusive)
  - vulnerable:             true/false (an AND configuration may include non-vulnerable items)

This module flattens that nested structure into a readable per-product
summary, grouping ranges by vendor:product and producing human-readable
range strings like "2.0 (inclusive) to 2.15.0 (exclusive)".
"""

from __future__ import annotations

from typing import Any


def extract_affected_versions(cve: dict[str, Any]) -> dict[str, Any]:
    """Build a structured summary of vulnerable products and version ranges.

    Args:
        cve: The inner CVE object from an NVD response (use nvd.extract_cve()).

    Returns:
        A dict listing each unique vendor:product affected, the vulnerable
        version ranges (in plain English), and any explicitly-pinned safe
        versions noted by NVD.
    """
    configurations = cve.get("configurations", [])

    # vendor:product -> { "ranges": [...], "exact_versions": set(), "safe_versions": set() }
    by_product: dict[str, dict[str, Any]] = {}

    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable"):
                    continue
                _process_match(match, by_product)

    products = []
    for key, data in sorted(by_product.items()):
        vendor, product = key.split(":", 1) if ":" in key else ("unknown", key)
        products.append({
            "vendor": vendor,
            "product": product,
            "vulnerable_ranges": data["ranges"],
            "vulnerable_specific_versions": sorted(data["exact_versions"]),
        })

    return {
        "cve_id": cve.get("id"),
        "affected_products": products,
        "guidance_note": _build_guidance(products),
        "source": "NIST NVD configurations field",
        "limitations": (
            "NVD lists vulnerable version ranges only. To find the latest safe "
            "version, check the vendor's release page or package registry — "
            "newer versions outside these ranges may exist but could have their "
            "own CVEs not yet listed here."
        ),
    }


def _process_match(match: dict[str, Any], by_product: dict[str, dict[str, Any]]) -> None:
    """Parse one cpeMatch entry into the per-product summary."""
    criteria = match.get("criteria", "")
    parsed = _parse_cpe(criteria)
    if not parsed:
        return

    key = f"{parsed['vendor']}:{parsed['product']}"
    bucket = by_product.setdefault(key, {"ranges": [], "exact_versions": set()})

    start_inc = match.get("versionStartIncluding")
    start_exc = match.get("versionStartExcluding")
    end_inc = match.get("versionEndIncluding")
    end_exc = match.get("versionEndExcluding")

    # Two cases:
    #   1. A range is defined (any of the four bounds is set) -> describe the range.
    #   2. No range bounds -> the CPE's own version field IS the affected version.
    if any([start_inc, start_exc, end_inc, end_exc]):
        bucket["ranges"].append({
            "start_including": start_inc,
            "start_excluding": start_exc,
            "end_including": end_inc,
            "end_excluding": end_exc,
            "human_readable": _format_range(start_inc, start_exc, end_inc, end_exc),
        })
    else:
        cpe_version = parsed["version"]
        if cpe_version and cpe_version not in ("*", "-"):
            bucket["exact_versions"].add(cpe_version)


def _parse_cpe(cpe: str) -> dict[str, str] | None:
    """Parse a CPE 2.3 formatted string.

    Format: cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:...
    Returns vendor, product, version, or None if the string is malformed.
    """
    if not cpe.startswith("cpe:2.3:"):
        return None
    parts = cpe.split(":")
    if len(parts) < 6:
        return None
    return {
        "part": parts[2],     # 'a' = application, 'o' = OS, 'h' = hardware
        "vendor": parts[3],
        "product": parts[4],
        "version": parts[5],
    }


def _format_range(
    start_inc: str | None,
    start_exc: str | None,
    end_inc: str | None,
    end_exc: str | None,
) -> str:
    """Build a human-readable range string from version bound fields."""
    if start_inc:
        lower = f"{start_inc} (inclusive)"
    elif start_exc:
        lower = f"{start_exc} (exclusive)"
    else:
        lower = "any earlier version"

    if end_inc:
        upper = f"{end_inc} (inclusive)"
    elif end_exc:
        upper = f"{end_exc} (exclusive)"
    else:
        upper = "any later version"

    return f"from {lower} up to {upper}"


def _build_guidance(products: list[dict[str, Any]]) -> str:
    """Produce a short note explaining what to do with the version info."""
    if not products:
        return (
            "No version-specific configuration data is available in NVD for this CVE. "
            "Refer to the vendor advisory for affected versions."
        )
    return (
        "Versions listed above are confirmed vulnerable per NVD. To find a safe "
        "version, pick the latest release from your package manager or vendor "
        "that falls outside ALL listed ranges. Verify against other CVEs for the "
        "same product before deploying."
    )
