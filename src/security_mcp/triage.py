"""Triage orchestrator.

Fuses CVE + EPSS + KEV + ExploitDB data into a single patch-priority decision.

The logic is explainable and rule-based on purpose. We do NOT use the LLM to
make the decision — the LLM consumes the structured verdict we produce.

Decision rules (in priority order):

  1. PATCH_IMMEDIATELY:
        On CISA KEV, OR
        (CVSS >= 9.0 AND EPSS percentile >= 0.90), OR
        (CVSS >= 9.0 AND public exploit code exists)
  2. PATCH_THIS_WEEK:
        CVSS >= 7.0 AND (EPSS percentile >= 0.50 OR public exploit exists)
  3. PATCH_NEXT_CYCLE:
        CVSS >= 7.0 (high severity but no exploitation pressure)
  4. MONITOR:
        CVSS < 7.0 AND EPSS percentile < 0.90 AND no public exploit
  5. UNKNOWN:
        Insufficient data
"""

from __future__ import annotations

import asyncio
from typing import Any

from security_mcp.api import epss as epss_api
from security_mcp.api import exploitdb as exploitdb_api
from security_mcp.api import kev as kev_api
from security_mcp.api import nvd as nvd_api
from security_mcp.formatters import format_cve, format_epss, format_exploits, format_kev


async def triage(cve_id: str) -> dict[str, Any]:
    """Run a CVE through CVSS + EPSS + KEV + ExploitDB and return a verdict.

    All four lookups happen in parallel. Total latency = slowest of the four.
    """
    nvd_task = nvd_api.fetch_cve(cve_id)
    epss_task = epss_api.fetch_epss(cve_id)
    kev_task = kev_api.lookup_kev(cve_id)
    exploits_task = exploitdb_api.lookup_exploits(cve_id)

    nvd_result, epss_result, kev_result, exploits_result = await asyncio.gather(
        nvd_task, epss_task, kev_task, exploits_task, return_exceptions=True
    )

    if isinstance(nvd_result, Exception):
        return {"error": f"CVE lookup failed: {nvd_result}", "cve_id": cve_id}

    cve = nvd_api.extract_cve(nvd_result)
    cve_formatted = format_cve(cve)

    epss_data = None if isinstance(epss_result, Exception) else epss_result
    kev_data = None if isinstance(kev_result, Exception) else kev_result
    exploits_data = [] if isinstance(exploits_result, Exception) else exploits_result

    epss_formatted = format_epss(epss_data)
    kev_formatted = format_kev(kev_data)
    exploits_formatted = format_exploits(exploits_data)

    verdict = _decide(cve_formatted, epss_formatted, kev_formatted, exploits_formatted)

    return {
        "cve_id": cve_id,
        "verdict": verdict,
        "cve": cve_formatted,
        "epss": epss_formatted,
        "kev": kev_formatted,
        "exploits": exploits_formatted,
        "partial_data_warnings": _collect_warnings(epss_result, kev_result, exploits_result),
    }


def _decide(
    cve: dict[str, Any],
    epss: dict[str, Any],
    kev: dict[str, Any],
    exploits: dict[str, Any],
) -> dict[str, Any]:
    """Apply the decision rules to produce a verdict and reasoning."""
    cvss = cve.get("cvss") or {}
    base_score = cvss.get("base_score")

    on_kev = kev.get("on_kev_catalog", False)
    epss_percentile = epss.get("percentile") if epss.get("available") else None
    has_public_exploit = exploits.get("public_exploits_available", False)
    exploit_count = exploits.get("count", 0)

    reasons: list[str] = []

    # ====== Rule 1: PATCH_IMMEDIATELY ======
    if on_kev:
        reasons.append("Listed on CISA KEV — confirmed real-world exploitation.")
        if kev.get("known_ransomware_use"):
            reasons.append("Has been used in ransomware campaigns.")
        return _verdict("PATCH_IMMEDIATELY", reasons, cvss, epss_percentile, on_kev, exploit_count)

    if base_score is not None and base_score >= 9.0:
        if epss_percentile is not None and epss_percentile >= 0.90:
            reasons.append(
                f"Critical CVSS ({base_score}) plus high exploitation likelihood "
                f"(EPSS {epss_percentile:.0%} percentile)."
            )
            return _verdict("PATCH_IMMEDIATELY", reasons, cvss, epss_percentile, on_kev, exploit_count)
        if has_public_exploit:
            reasons.append(
                f"Critical CVSS ({base_score}) plus {exploit_count} public exploit(s) available."
            )
            return _verdict("PATCH_IMMEDIATELY", reasons, cvss, epss_percentile, on_kev, exploit_count)

    # ====== Rule 2: PATCH_THIS_WEEK ======
    if base_score is not None and base_score >= 7.0:
        if epss_percentile is not None and epss_percentile >= 0.50:
            reasons.append(
                f"High severity (CVSS {base_score}) with above-median exploitation "
                f"likelihood (EPSS {epss_percentile:.0%} percentile)."
            )
            return _verdict("PATCH_THIS_WEEK", reasons, cvss, epss_percentile, on_kev, exploit_count)
        if has_public_exploit:
            reasons.append(
                f"High severity (CVSS {base_score}) with public exploit code available."
            )
            return _verdict("PATCH_THIS_WEEK", reasons, cvss, epss_percentile, on_kev, exploit_count)

    # ====== Rule 3: PATCH_NEXT_CYCLE ======
    if base_score is not None and base_score >= 7.0:
        if epss_percentile is None:
            reasons.append(
                f"High severity (CVSS {base_score}); no EPSS data yet, "
                "so exploitation likelihood unknown."
            )
        else:
            reasons.append(
                f"High severity (CVSS {base_score}), but low exploitation "
                f"likelihood (EPSS {epss_percentile:.0%} percentile)."
            )
        return _verdict("PATCH_NEXT_CYCLE", reasons, cvss, epss_percentile, on_kev, exploit_count)

    # ====== Rule 4: MONITOR ======
    if base_score is not None:
        reasons.append(f"Moderate or low severity (CVSS {base_score}).")
        if epss_percentile is not None:
            reasons.append(f"Exploitation likelihood is low (EPSS {epss_percentile:.0%} percentile).")
        return _verdict("MONITOR", reasons, cvss, epss_percentile, on_kev, exploit_count)

    # ====== Rule 5: UNKNOWN ======
    reasons.append("CVSS score is missing from this CVE; can't apply standard triage rules.")
    return _verdict("UNKNOWN", reasons, cvss, epss_percentile, on_kev, exploit_count)


def _verdict(
    decision: str,
    reasons: list[str],
    cvss: dict[str, Any],
    epss_percentile: float | None,
    on_kev: bool,
    exploit_count: int,
) -> dict[str, Any]:
    return {
        "decision": decision,
        "reasoning": reasons,
        "inputs_used": {
            "cvss_score": cvss.get("base_score"),
            "cvss_severity": cvss.get("severity"),
            "epss_percentile": epss_percentile,
            "on_cisa_kev": on_kev,
            "public_exploits_count": exploit_count,
        },
    }


def _collect_warnings(epss_result: Any, kev_result: Any, exploits_result: Any) -> list[str]:
    warnings: list[str] = []
    if isinstance(epss_result, Exception):
        warnings.append(f"EPSS lookup failed: {epss_result}")
    if isinstance(kev_result, Exception):
        warnings.append(f"KEV lookup failed: {kev_result}")
    if isinstance(exploits_result, Exception):
        warnings.append(f"ExploitDB lookup failed: {exploits_result}")
    return warnings
