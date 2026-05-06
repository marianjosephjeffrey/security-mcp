"""CISA KEV (Known Exploited Vulnerabilities) catalog client.

CISA publishes a JSON file listing every CVE they've observed being actively
exploited in the wild. This is the single most important "should I drop
everything and patch this?" signal in the industry — being on the KEV list
means real attackers are using this RIGHT NOW.

The catalog is a single ~1MB JSON file refreshed roughly weekdays. Rather than
hitting CISA on every query, we download once and cache in memory, refreshing
daily. This is the right tradeoff: KEV doesn't change minute-to-minute, and
in-memory dict lookup is instant.

Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""

from __future__ import annotations

import time
from typing import Any

import httpx

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
USER_AGENT = "security-mcp/0.2.0"
DEFAULT_TIMEOUT = 60.0  # The file is ~1MB, give it room
CACHE_TTL_SECONDS = 24 * 60 * 60  # Refresh once a day


class KevError(Exception):
    """Raised when the KEV catalog can't be fetched."""


# Module-level cache. Lives for the duration of the server process.
_cache: dict[str, dict[str, Any]] = {}
_cache_loaded_at: float = 0.0
_catalog_meta: dict[str, Any] = {}


async def _load_catalog() -> None:
    """Download the KEV catalog and rebuild the in-memory cache."""
    global _cache, _cache_loaded_at, _catalog_meta

    headers = {"User-Agent": USER_AGENT}
    try:
        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
            response = await client.get(KEV_FEED_URL, headers=headers)
    except httpx.RequestError as e:
        raise KevError(f"Network error contacting CISA KEV: {e}") from e

    if response.status_code != 200:
        raise KevError(f"CISA KEV returned HTTP {response.status_code}")

    payload = response.json()
    vulnerabilities = payload.get("vulnerabilities", [])

    # Index by CVE ID for O(1) lookup.
    _cache = {v["cveID"]: v for v in vulnerabilities if "cveID" in v}
    _cache_loaded_at = time.time()
    _catalog_meta = {
        "title": payload.get("title"),
        "catalog_version": payload.get("catalogVersion"),
        "date_released": payload.get("dateReleased"),
        "count": payload.get("count", len(vulnerabilities)),
    }


async def _ensure_loaded() -> None:
    """Load the catalog if it's missing or stale."""
    if not _cache or (time.time() - _cache_loaded_at) > CACHE_TTL_SECONDS:
        await _load_catalog()


async def lookup_kev(cve_id: str) -> dict[str, Any] | None:
    """Check whether a CVE appears in the CISA KEV catalog.

    Returns:
        The KEV entry dict if found (with vendor, product, dateAdded,
        requiredAction, dueDate, knownRansomwareCampaignUse, etc.), or
        None if the CVE is not on the catalog.

    Raises:
        KevError: If the catalog can't be fetched at all.
    """
    await _ensure_loaded()
    return _cache.get(cve_id)


async def get_catalog_meta() -> dict[str, Any]:
    """Return metadata about the loaded KEV catalog (version, date, count)."""
    await _ensure_loaded()
    return dict(_catalog_meta)
