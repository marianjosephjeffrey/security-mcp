"""NVD (National Vulnerability Database) API client.

Talks to the NIST NVD 2.0 REST API to retrieve CVE data.
Docs: https://nvd.nist.gov/developers/vulnerabilities

Without an API key: ~5 requests per 30 seconds.
With a free API key: ~50 requests per 30 seconds.
Get one at: https://nvd.nist.gov/developers/request-an-api-key
"""

from __future__ import annotations

import os
from typing import Any

import httpx

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
USER_AGENT = "security-mcp/0.2.0"
DEFAULT_TIMEOUT = 30.0


class NvdError(Exception):
    """Raised when the NVD API returns an error or unexpected response."""


async def fetch_cve(cve_id: str) -> dict[str, Any]:
    """Fetch a single CVE record from the NVD.

    Returns the full NVD response dict. Use `extract_cve()` to get just the
    inner CVE object.

    Raises:
        NvdError: If the request fails, is rate-limited, or the CVE isn't found.
    """
    headers = {"User-Agent": USER_AGENT}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    params = {"cveId": cve_id}

    try:
        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
            response = await client.get(NVD_BASE_URL, params=params, headers=headers)
    except httpx.RequestError as e:
        raise NvdError(f"Network error contacting NVD: {e}") from e

    if response.status_code == 404:
        raise NvdError(f"CVE {cve_id} not found in NVD")
    if response.status_code == 403:
        raise NvdError(
            "NVD rejected the request (403). You may be rate-limited; "
            "consider setting NVD_API_KEY."
        )
    if response.status_code != 200:
        raise NvdError(f"NVD returned HTTP {response.status_code}: {response.text[:200]}")

    data = response.json()
    if data.get("totalResults", 0) == 0 or not data.get("vulnerabilities"):
        raise NvdError(f"CVE {cve_id} not found in NVD")

    return data


def extract_cve(raw: dict[str, Any]) -> dict[str, Any]:
    """Extract the inner CVE object from an NVD API response wrapper."""
    return raw["vulnerabilities"][0]["cve"]
