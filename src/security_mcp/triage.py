"""Triage orchestrator.

This module fuses CVE + EPSS + KEV data into a single decision: should this
vulnerability be patched immediately, scheduled in a normal cycle, or
deprioritized?

The logic is explainable and rule-based on purpose. We do NOT use the LLM to
make the decision — the LLM consumes the structured verdict we produce. This
keeps the reasoning auditable and consistent.

Decision rules (in priority order):

  1. PATCH_IMMEDIATELY:  On CISA KEV, OR (CVSS >= 9.0 AND EPSS percentile >= 0.90)
  2. PATCH_THIS_WEEK:    CVSS >= 7.0 AND EPSS percentile >= 0.50
  3. PATCH_NEXT_CYCLE:   CVSS >= 7.0 (high severity but no exploitation pressure)
  4. MONITOR:            CVSS < 7.0 AND EPSS percentile < 0.90
  5. UNKNOWN:            Insufficient data (CVE missing CVSS, etc.)

These are reasonable defaults — your organization may want different
thresholds. The point is that the rules are explicit and visible.
"""

from __future__ import annotations

import asyncio
from typing import Any

from security_mcp.api import epss as epss_api
from security_mcp.api import kev as kev_api
from security_mcp.api import nvd as nvd_api
from security_mcp.formatters import format_cve, format_epss, format_kev


async def triage(cve_id: str) -> dict[str, Any]:
    """Run a CVE through CVSS + EPSS + KEV and return a structured verdict.

    All three lookups happen in parallel — total latency is the slowest of
    the three, not the sum.
    """
    # Run all three lookups concurrently. return_exceptions=True so one
    # failure (e.g. EPSS down) doesn't kill the whole triage.
    nvd_task = nvd_api.fetch_cve(cve_id)
    epss_task = epss_api.fetch_epss(cve_id)
    kev_task = kev_api.lookup_kev(cve_id)

    nvd_result, epss_result, kev_result = await asyncio.gather(
        nvd_task, epss_task, kev_task, return_exceptions=True
    )

    # CVE lookup failure is fatal — without it we can't triage anything.
    if isinstance(nvd_result, Exception):
        return {"error": f"CVE lookup failed: {nvd_result}", "cve_id": cve_id}

    cve = nvd_api.extract_cve(nvd_result)
    cve_formatted = format_cve(cve)

    # EPSS or KEV failures are partial — note them and continue.
    epss_data = None if isinstance(epss_result, Exception) else epss_result
    kev_data = None if isinstance(kev_result, Exception) else kev_result

    epss_formatted = format_epss(epss_data)
    kev_formatted = format_kev(kev_data)

    verdict = _decide(cve_formatted, epss_formatted, kev_formatted)

    return {
        "cve_id": cve_id,
        "verdict": verdict,
        "cve": cve_formatted,
        "epss": epss_formatted,
        "kev": kev_formatted,
        "partial_data_warnings": _collect_warnings(epss_result, kev_result),
    }


def _decide(
    cve: dict[str, Any],
    epss: dict[str, Any],
    kev: dict[str, Any],
) -> dict[str, Any]:
    """Apply the decision rules to produce a verdict and reasoning."""
    cvss = cve.get("cvss") or {}
    base_score = cvss.get("base_score")

    on_kev = kev.get("on_kev_catalog", False)
    epss_percentile = epss.get("percentile") if epss.get("available") else None

    reasons: list[str] = []

    # Rule 1: KEV or critical+exploited
    if on_kev:
        reasons.append("Listed on CISA KEV — confirmed real-world exploitation.")
        if kev.get("known_ransomware_use"):
            reasons.append("Has been used in ransomware campaigns.")
        return _verdict("PATCH_IMMEDIATELY", reasons, cvss, epss_percentile, on_kev)

    if base_score is not None and base_score >= 9.0 and epss_percentile is not None and epss_percentile >= 0.90:
        reasons.append(f"Critical CVSS ({base_score}) plus high exploitation likelihood (EPSS {epss_percentile:.0%} percentile).")
        return _verdict("PATCH_IMMEDIATELY", reasons, cvss, epss_percentile, on_kev)

    # Rule 2: high+ severity with above-median exploitation likelihood
    if base_score is not None and base_score >= 7.0 and epss_percentile is not None and epss_percentile >= 0.50:
        reasons.append(f"High severity (CVSS {base_score}) with above-median exploitation likelihood (EPSS {epss_percentile:.0%} percentile).")
        return _verdict("PATCH_THIS_WEEK", reasons, cvss, epss_percentile, on_kev)

    # Rule 3: high severity but no exploitation signal
    if base_score is not None and base_score >= 7.0:
        if epss_percentile is None:
            reasons.append(f"High severity (CVSS {base_score}); no EPSS data yet, so exploitation likelihood unknown.")
        else:
            reasons.append(f"High severity (CVSS {base_score}), but low exploitation likelihood (EPSS {epss_percentile:.0%} percentile).")
        return _verdict("PATCH_NEXT_CYCLE", reasons, cvss, epss_percentile, on_kev)

    # Rule 4: lower severity
    if base_score is not None:
        reasons.append(f"Moderate or low severity (CVSS {base_score}).")
        if epss_percentile is not None:
            reasons.append(f"Exploitation likelihood is low (EPSS {epss_percentile:.0%} percentile).")
        return _verdict("MONITOR", reasons, cvss, epss_percentile, on_kev)

    # Rule 5: not enough data
    reasons.append("CVSS score is missing from this CVE; can't apply standard triage rules.")
    return _verdict("UNKNOWN", reasons, cvss, epss_percentile, on_kev)


def _verdict(
    decision: str,
    reasons: list[str],
    cvss: dict[str, Any],
    epss_percentile: float | None,
    on_kev: bool,
) -> dict[str, Any]:
    return {
        "decision": decision,
        "reasoning": reasons,
        "inputs_used": {
            "cvss_score": cvss.get("base_score"),
            "cvss_severity": cvss.get("severity"),
            "epss_percentile": epss_percentile,
            "on_cisa_kev": on_kev,
        },
    }


def _collect_warnings(epss_result: Any, kev_result: Any) -> list[str]:
    warnings: list[str] = []
    if isinstance(epss_result, Exception):
        warnings.append(f"EPSS lookup failed; verdict made without exploitation likelihood data: {epss_result}")
    if isinstance(kev_result, Exception):
        warnings.append(f"KEV lookup failed; verdict made without active-exploitation data: {kev_result}")
    return warnings
