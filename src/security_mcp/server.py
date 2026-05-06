"""Security MCP server - entry point.

Exposes security intelligence tools via the Model Context Protocol.

Currently implemented:
  - lookup_cve: Retrieve detailed information about a CVE from the NVD.

Adding a new tool is intentionally simple:
  1. Add an API client in src/security_mcp/api/ (one file per data source).
  2. Add a formatter in formatters.py if the response needs cleaning up.
  3. Add a new @mcp.tool() function below.
"""

from __future__ import annotations

import re
from typing import Any

from fastmcp import FastMCP

from security_mcp.api.nvd import NvdError, fetch_cve
from security_mcp.formatters import format_cve

mcp = FastMCP("security-mcp")

# CVE IDs follow the pattern CVE-YYYY-NNNN+ (4 or more digits after the year).
CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


@mcp.tool()
async def lookup_cve(cve_id: str) -> dict[str, Any]:
    """Look up detailed information about a CVE from the NIST National Vulnerability Database.

    Use this tool whenever the user asks about a specific CVE identifier
    (e.g. "What is CVE-2024-3400?", "Is CVE-2021-44228 critical?", "Tell me about Log4Shell's CVE").
    Returns the description, CVSS score and severity, affected weakness types (CWEs),
    and reference links including patches and exploit advisories.

    Args:
        cve_id: A CVE identifier in the format CVE-YYYY-NNNN (e.g. "CVE-2024-3400").

    Returns:
        A dict with the CVE's description, CVSS score, severity, CWEs, and references.
    """
    cve_id = cve_id.strip().upper()

    if not CVE_ID_PATTERN.match(cve_id):
        return {
            "error": f"Invalid CVE ID format: {cve_id!r}. Expected format: CVE-YYYY-NNNN "
            "(e.g. CVE-2024-3400)."
        }

    try:
        raw = await fetch_cve(cve_id)
    except NvdError as e:
        return {"error": str(e), "cve_id": cve_id}

    return format_cve(raw)


def main() -> None:
    """Entry point for the `security-mcp` console script."""
    mcp.run()


if __name__ == "__main__":
    main()
