"""EPSS (Exploit Prediction Scoring System) API client.

EPSS is maintained by FIRST.org and provides daily-updated probabilities that a
CVE will be exploited in the wild within the next 30 days.

API docs: https://www.first.org/epss/api
No auth required, no rate limit documented (be polite — batch when possible).

Two numbers come back:
  - epss:       Probability (0.0 to 1.0) of exploitation in the next 30 days.
  - percentile: Where this CVE ranks vs all others. 0.95 = "more likely to be
                exploited than 95% of all known CVEs."

Percentile is what most analysts actually use, since the raw probability for any
given CVE is usually low even when relative risk is high.
"""

from __future__ import annotations

from typing import Any

import httpx

EPSS_BASE_URL = "https://api.first.org/data/v1/epss"
USER_AGENT = "security-mcp/0.2.0"
DEFAULT_TIMEOUT = 30.0


class EpssError(Exception):
    """Raised when the EPSS API returns an error or unexpected response."""


async def fetch_epss(cve_id: str) -> dict[str, Any] | None:
    """Fetch the EPSS score for a single CVE.

    Returns:
        A dict with 'epss', 'percentile', 'date', and 'cve' fields, or None
        if EPSS has no score for this CVE (which happens for very recent CVEs
        — EPSS lags published CVEs by a few days).

    Raises:
        EpssError: For network failures or non-200 responses.
    """
    headers = {"User-Agent": USER_AGENT}
    params = {"cve": cve_id}

    try:
        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
            response = await client.get(EPSS_BASE_URL, params=params, headers=headers)
    except httpx.RequestError as e:
        raise EpssError(f"Network error contacting EPSS: {e}") from e

    if response.status_code != 200:
        raise EpssError(f"EPSS returned HTTP {response.status_code}: {response.text[:200]}")

    payload = response.json()
    data = payload.get("data", [])
    if not data:
        return None

    entry = data[0]
    # The API returns string-encoded floats; convert for easier reasoning.
    return {
        "cve": entry.get("cve"),
        "epss": float(entry["epss"]) if entry.get("epss") else None,
        "percentile": float(entry["percentile"]) if entry.get("percentile") else None,
        "date": entry.get("date"),
    }
