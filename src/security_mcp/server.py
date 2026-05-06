"""Security MCP server.

Exposed tools:
  - lookup_cve         : NVD CVE record (description, CVSS, CWEs, references).
  - get_epss_score     : Exploit Prediction Scoring System probability.
  - check_kev_status   : Whether the CVE is on CISA's actively-exploited list.
  - triage_cve         : Combines all three above into a verdict.
  - get_mitigation     : Patch and advisory references plus CWE-based guidance.
"""

from __future__ import annotations

import re
from typing import Any

from fastmcp import FastMCP

from security_mcp.api.epss import EpssError, fetch_epss
from security_mcp.api.kev import KevError, lookup_kev
from security_mcp.api.nvd import NvdError, extract_cve, fetch_cve
from security_mcp.formatters import format_cve, format_epss, format_kev
from security_mcp.mitigation import extract_mitigation
from security_mcp.triage import triage

mcp = FastMCP("security-mcp")

CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def _validate_cve_id(cve_id: str) -> str | dict[str, Any]:
    """Return cleaned CVE ID, or an error dict if invalid."""
    cleaned = cve_id.strip().upper()
    if not CVE_ID_PATTERN.match(cleaned):
        return {
            "error": f"Invalid CVE ID format: {cve_id!r}. Expected format: CVE-YYYY-NNNN "
                     "(e.g. CVE-2024-3400)."
        }
    return cleaned


# ============================================================
# Tool 1: lookup_cve
# ============================================================

@mcp.tool()
async def lookup_cve(cve_id: str) -> dict[str, Any]:
    """Look up detailed information about a CVE from the NIST National Vulnerability Database.

    Use this whenever the user asks about a specific CVE identifier (e.g. "What is
    CVE-2024-3400?", "Tell me about Log4Shell"). Returns description, CVSS score,
    CWEs, and reference links. For a full risk assessment, use `triage_cve` instead.

    Args:
        cve_id: A CVE identifier in the format CVE-YYYY-NNNN.
    """
    validated = _validate_cve_id(cve_id)
    if isinstance(validated, dict):
        return validated

    try:
        raw = await fetch_cve(validated)
    except NvdError as e:
        return {"error": str(e), "cve_id": validated}

    return format_cve(extract_cve(raw))


# ============================================================
# Tool 2: get_epss_score
# ============================================================

@mcp.tool()
async def get_epss_score(cve_id: str) -> dict[str, Any]:
    """Get the EPSS (Exploit Prediction Scoring System) score for a CVE.

    EPSS estimates the probability that a CVE will be exploited in the wild
    within the next 30 days, based on observed exploitation activity and
    vulnerability characteristics. Updated daily by FIRST.org.

    The percentile is usually more useful than the raw probability — a 95th
    percentile CVE is more likely to be exploited than 95% of all known CVEs.

    Args:
        cve_id: A CVE identifier in the format CVE-YYYY-NNNN.
    """
    validated = _validate_cve_id(cve_id)
    if isinstance(validated, dict):
        return validated

    try:
        result = await fetch_epss(validated)
    except EpssError as e:
        return {"error": str(e), "cve_id": validated}

    return format_epss(result)


# ============================================================
# Tool 3: check_kev_status
# ============================================================

@mcp.tool()
async def check_kev_status(cve_id: str) -> dict[str, Any]:
    """Check whether a CVE is on CISA's Known Exploited Vulnerabilities (KEV) catalog.

    KEV listings indicate confirmed active exploitation in the wild — this is
    the strongest "patch immediately" signal in the industry. CISA maintains
    this catalog, and US federal agencies are required to remediate listed
    CVEs by specific due dates.

    Args:
        cve_id: A CVE identifier in the format CVE-YYYY-NNNN.
    """
    validated = _validate_cve_id(cve_id)
    if isinstance(validated, dict):
        return validated

    try:
        result = await lookup_kev(validated)
    except KevError as e:
        return {"error": str(e), "cve_id": validated}

    return format_kev(result)


# ============================================================
# Tool 4: triage_cve (the orchestrator — the actually-useful tool)
# ============================================================

@mcp.tool()
async def triage_cve(cve_id: str) -> dict[str, Any]:
    """Run a full triage on a CVE: combines CVSS severity, EPSS exploitation
    probability, and CISA KEV status into a single verdict with reasoning.

    Use this whenever the user is trying to decide whether/when to patch a CVE,
    or asks "is this critical?" / "should I worry about this?" / "what's the
    risk?" This is the most useful tool in the suite — a single CVE lookup
    rarely tells you what to actually do; this one does.

    Returns a decision (PATCH_IMMEDIATELY / PATCH_THIS_WEEK / PATCH_NEXT_CYCLE
    / MONITOR / UNKNOWN) plus the supporting data and the rules that produced
    the decision.

    Args:
        cve_id: A CVE identifier in the format CVE-YYYY-NNNN.
    """
    validated = _validate_cve_id(cve_id)
    if isinstance(validated, dict):
        return validated

    return await triage(validated)


# ============================================================
# Tool 5: get_mitigation
# ============================================================

@mcp.tool()
async def get_mitigation(cve_id: str) -> dict[str, Any]:
    """Get mitigation and remediation guidance for a CVE.

    Pulls patch links, vendor advisories, and CISA-required actions directly
    from authoritative sources (NVD references and the KEV catalog). For
    vulnerability classes (CWEs) where applicable, also includes generic
    hardening guidance.

    This tool deliberately does NOT generate CVE-specific remediation steps
    from training data — only sourced, verifiable references and standard
    CWE-class guidance.

    Use this when the user asks "how do I fix this?" / "is there a patch?" /
    "what should I do about this?"

    Args:
        cve_id: A CVE identifier in the format CVE-YYYY-NNNN.
    """
    validated = _validate_cve_id(cve_id)
    if isinstance(validated, dict):
        return validated

    # Fetch the CVE record (always required).
    try:
        raw = await fetch_cve(validated)
    except NvdError as e:
        return {"error": str(e), "cve_id": validated}
    cve = extract_cve(raw)

    # Try to fetch KEV — but if it fails, mitigation still works without it.
    kev_entry = None
    try:
        kev_entry = await lookup_kev(validated)
    except KevError:
        pass  # Non-fatal; mitigation just won't include KEV-required action.

    return extract_mitigation(cve, kev_entry)


def main() -> None:
    """Entry point for the `security-mcp` console script."""
    mcp.run()


if __name__ == "__main__":
    main()
