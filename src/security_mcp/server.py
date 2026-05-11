"""Security MCP server.

Exposed tools (8 total):

  Per-CVE intelligence:
    - lookup_cve                : NVD CVE record
    - get_epss_score            : Exploit Prediction Scoring System probability
    - check_kev_status          : Active-exploitation check (CISA KEV)
    - search_exploit_db         : Public exploit code search (Exploit-DB)
    - get_mitigation            : Patch + advisory + CWE guidance
    - map_to_attack_techniques  : CVE -> MITRE ATT&CK techniques via CWE/CAPEC

  Orchestrators:
    - triage_cve                : CVSS + EPSS + KEV + ExploitDB -> verdict
    - bulk_triage               : Triage a list of CVEs in parallel, sorted by priority
"""

from __future__ import annotations

import re
from typing import Any

from fastmcp import FastMCP

from security_mcp.api.epss import EpssError, fetch_epss
from security_mcp.api.exploitdb import ExploitDbError, lookup_exploits
from security_mcp.api.kev import KevError, lookup_kev
from security_mcp.api.nvd import NvdError, extract_cve, fetch_cve
from security_mcp.attack_map import map_cwes_to_attack
from security_mcp.bulk import bulk_triage as _bulk_triage
from security_mcp.formatters import format_cve, format_epss, format_exploits, format_kev
from security_mcp.mitigation import extract_mitigation
from security_mcp.triage import triage

mcp = FastMCP("security-mcp")

CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def _validate_cve_id(cve_id: str) -> str | dict[str, Any]:
    cleaned = cve_id.strip().upper()
    if not CVE_ID_PATTERN.match(cleaned):
        return {
            "error": f"Invalid CVE ID format: {cve_id!r}. Expected format: CVE-YYYY-NNNN."
        }
    return cleaned


# ============================================================
# Tool 1: lookup_cve
# ============================================================

@mcp.tool()
async def lookup_cve(cve_id: str) -> dict[str, Any]:
    """Look up detailed information about a CVE from the NIST National Vulnerability Database.

    Use whenever the user asks about a specific CVE identifier. Returns description,
    CVSS score, CWEs, and reference links. For a full risk assessment use `triage_cve`.

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
    within the next 30 days, based on observed exploitation activity. Updated
    daily by FIRST.org.

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
    """Check whether a CVE is on CISA's Known Exploited Vulnerabilities catalog.

    KEV listings indicate confirmed active exploitation. US federal agencies are
    required to remediate listed CVEs by specific due dates.

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
# Tool 4: search_exploit_db (NEW)
# ============================================================

@mcp.tool()
async def search_exploit_db(cve_id: str) -> dict[str, Any]:
    """Search Exploit-DB for public exploit code matching a CVE.

    Use whenever the user asks whether a working exploit exists, or wants to
    understand how easily a vulnerability could be weaponized. Public exploit
    code dramatically lowers the skill bar for attackers — its existence is
    a strong urgency signal independent of CVSS.

    Returns the count of available exploits and details (author, date,
    platform) of the most recent ones, plus direct links to Exploit-DB.

    Args:
        cve_id: A CVE identifier in the format CVE-YYYY-NNNN.
    """
    validated = _validate_cve_id(cve_id)
    if isinstance(validated, dict):
        return validated
    try:
        exploits = await lookup_exploits(validated)
    except ExploitDbError as e:
        return {"error": str(e), "cve_id": validated}
    return format_exploits(exploits)


# ============================================================
# Tool 5: triage_cve
# ============================================================

@mcp.tool()
async def triage_cve(cve_id: str) -> dict[str, Any]:
    """Run a full triage on a CVE: combines CVSS severity, EPSS exploitation
    probability, CISA KEV status, AND public exploit availability into a single
    verdict with reasoning.

    Use this whenever the user is trying to decide whether or when to patch a
    CVE, or asks "is this critical?" / "should I worry about this?" / "what's
    the risk?" This is the most useful tool in the suite.

    Returns a decision (PATCH_IMMEDIATELY / PATCH_THIS_WEEK / PATCH_NEXT_CYCLE
    / MONITOR / UNKNOWN) plus the supporting data and rules that produced it.

    Args:
        cve_id: A CVE identifier in the format CVE-YYYY-NNNN.
    """
    validated = _validate_cve_id(cve_id)
    if isinstance(validated, dict):
        return validated
    return await triage(validated)


# ============================================================
# Tool 6: bulk_triage (NEW)
# ============================================================

@mcp.tool()
async def bulk_triage(cve_ids: list[str]) -> dict[str, Any]:
    """Triage multiple CVEs in parallel and return them in patch-priority order.

    Use whenever the user provides a list of CVEs (e.g. scanner output, a patch
    backlog, a list of CVEs mentioned in an article) and wants to know which to
    address first. Runs all triages concurrently (asyncio.gather with bounded
    concurrency) and sorts results by verdict priority then CVSS score.

    Capped at 50 CVEs per call. Split larger batches across multiple calls.

    Args:
        cve_ids: A list of CVE identifiers, e.g. ["CVE-2021-44228", "CVE-2024-3400"].
    """
    return await _bulk_triage(cve_ids)


# ============================================================
# Tool 7: get_mitigation
# ============================================================

@mcp.tool()
async def get_mitigation(cve_id: str) -> dict[str, Any]:
    """Get mitigation and remediation guidance for a CVE.

    Pulls patch links, vendor advisories, and CISA-required actions from
    authoritative sources (NVD references and the KEV catalog). For
    vulnerability classes (CWEs) where applicable, also includes generic
    hardening guidance.

    Does NOT generate CVE-specific remediation from training data — only
    sourced, verifiable references plus standard CWE-class guidance.

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
    cve = extract_cve(raw)
    kev_entry = None
    try:
        kev_entry = await lookup_kev(validated)
    except KevError:
        pass
    return extract_mitigation(cve, kev_entry)


# ============================================================
# Tool 8: map_to_attack_techniques (NEW)
# ============================================================

@mcp.tool()
async def map_to_attack_techniques(cve_id: str) -> dict[str, Any]:
    """Map a CVE to MITRE ATT&CK techniques via its CWE classifications.

    Use this when the user is doing threat modeling, building detections, or
    asking "how would an attacker use this?" Translates the vulnerability
    classes (CWEs) of a CVE into the MITRE ATT&CK techniques an adversary
    would employ to exploit them — bridging the gap between a vulnerability
    record and the attacker behaviors a SOC team monitors for.

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

    cve = extract_cve(raw)
    formatted = format_cve(cve)
    cwes = formatted.get("weaknesses", [])

    if not cwes:
        return {
            "cve_id": validated,
            "error": "No CWE classifications found for this CVE; ATT&CK mapping requires CWEs.",
            "cwes_found": [],
        }

    mapping = map_cwes_to_attack(cwes)
    return {
        "cve_id": validated,
        "cwes_used_for_mapping": cwes,
        **mapping,
    }


def main() -> None:
    """Entry point for the `security-mcp` console script."""
    mcp.run()


if __name__ == "__main__":
    main()
