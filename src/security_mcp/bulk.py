"""Bulk triage: run triage on many CVEs in parallel and produce a prioritized list.

This is the killer feature for real security work. Vulnerability scanners
output dozens or hundreds of CVEs per scan; a security engineer has to figure
out which to patch first. This tool replaces that workflow.

Architecture:
  - Use asyncio.Semaphore to cap concurrency (NVD rate-limits aggressive callers).
  - asyncio.gather with return_exceptions so one failure doesn't kill the batch.
  - Sort results by the rank of their verdict, then by CVSS as a tie-breaker.
"""

from __future__ import annotations

import asyncio
from typing import Any

from security_mcp.triage import triage

# NVD allows ~5 req/30s without an API key. With concurrent triages each
# firing NVD + EPSS + KEV, we throttle to keep NVD happy. KEV is cached
# after the first call so it adds no real load; EPSS is generous.
DEFAULT_CONCURRENCY = 5
MAX_BATCH_SIZE = 50

# Priority ranking for sorting. Lower number = patch sooner.
VERDICT_RANK: dict[str, int] = {
    "PATCH_IMMEDIATELY": 0,
    "PATCH_THIS_WEEK": 1,
    "PATCH_NEXT_CYCLE": 2,
    "MONITOR": 3,
    "UNKNOWN": 4,
}


async def bulk_triage(
    cve_ids: list[str],
    concurrency: int = DEFAULT_CONCURRENCY,
) -> dict[str, Any]:
    """Triage many CVEs in parallel and return them in priority order.

    Args:
        cve_ids: List of CVE identifiers. Capped at MAX_BATCH_SIZE.
        concurrency: Max simultaneous triage operations (default 5).

    Returns:
        A dict with the prioritized list plus a summary count per verdict.
    """
    # De-dupe while preserving order, normalize case.
    seen: set[str] = set()
    cleaned: list[str] = []
    for cve in cve_ids:
        normalized = cve.strip().upper()
        if normalized and normalized not in seen:
            seen.add(normalized)
            cleaned.append(normalized)

    if not cleaned:
        return {"error": "No valid CVE IDs provided.", "results": []}

    if len(cleaned) > MAX_BATCH_SIZE:
        return {
            "error": (
                f"Batch too large: {len(cleaned)} CVEs given, max is {MAX_BATCH_SIZE}. "
                "Split the request into smaller batches."
            ),
            "results": [],
        }

    semaphore = asyncio.Semaphore(concurrency)

    async def _bounded_triage(cve_id: str) -> dict[str, Any]:
        async with semaphore:
            try:
                return await triage(cve_id)
            except Exception as e:
                # Defensive: triage() itself shouldn't raise, but just in case.
                return {"cve_id": cve_id, "error": f"Unexpected error: {e}"}

    results = await asyncio.gather(*[_bounded_triage(c) for c in cleaned])

    # Split into successes vs failures.
    successes = [r for r in results if "verdict" in r]
    failures = [r for r in results if "verdict" not in r]

    # Sort successes by verdict rank, then CVSS score (descending).
    successes.sort(key=_sort_key)

    summary = _summarize(successes)
    summary["failed_lookups"] = len(failures)

    return {
        "summary": summary,
        "prioritized": successes,
        "failures": failures,
    }


def _sort_key(result: dict[str, Any]) -> tuple[int, float]:
    """Sort key: lower verdict rank first, then higher CVSS first."""
    verdict = result.get("verdict", {})
    decision = verdict.get("decision", "UNKNOWN")
    rank = VERDICT_RANK.get(decision, 99)

    cvss = (result.get("cve") or {}).get("cvss") or {}
    score = cvss.get("base_score") or 0.0

    # Negative score so higher CVSS sorts first within the same rank.
    return (rank, -float(score))


def _summarize(successes: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a counts-by-verdict summary."""
    counts: dict[str, int] = {k: 0 for k in VERDICT_RANK}
    for r in successes:
        decision = (r.get("verdict") or {}).get("decision", "UNKNOWN")
        counts[decision] = counts.get(decision, 0) + 1

    return {
        "total_triaged": len(successes),
        "counts_by_verdict": counts,
        "top_priority_count": counts.get("PATCH_IMMEDIATELY", 0) + counts.get("PATCH_THIS_WEEK", 0),
    }
