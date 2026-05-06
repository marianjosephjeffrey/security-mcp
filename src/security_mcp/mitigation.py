"""Mitigation guidance extractor.

There's no clean public API for "how do I fix CVE-X." So this module does the
honest thing: it extracts real, sourced mitigation information from data we
already have, rather than fabricating advice.

Two sources of mitigation data we can trust:

  1. NVD reference tags. NVD tags every reference with categories like
     'Patch', 'Mitigation', 'Vendor Advisory', 'Third Party Advisory',
     'Exploit'. We pull these out and group them. This tells the user
     EXACTLY where to find the fix — straight from the vendor.

  2. CISA KEV required_action. If the CVE is on KEV, CISA spells out the
     required mitigation explicitly (often "Apply updates per vendor
     instructions" with a federal due date for government agencies).

  3. CWE-based generic guidance. The CWE tells us the *class* of weakness.
     For common CWEs we provide a short pointer to the standard hardening
     pattern — not specific to the CVE, but useful when no patch exists yet.

We deliberately do NOT generate vulnerability-specific remediation steps from
training data. That's where hallucination kills people.
"""

from __future__ import annotations

from typing import Any


# Reference tags that NVD uses, grouped by what they're useful for.
PATCH_TAGS = {"Patch", "Release Notes"}
ADVISORY_TAGS = {"Vendor Advisory", "Third Party Advisory", "Mitigation", "US Government Resource"}
EXPLOIT_TAGS = {"Exploit", "Proof-of-Concept", "Issue Tracking"}


# Generic hardening guidance for the most common CWE classes. Intentionally
# brief — these point users toward standard practices, not CVE-specific fixes.
CWE_GUIDANCE: dict[str, str] = {
    "CWE-79": "Cross-site scripting. Sanitize and context-encode all user input rendered in HTML; apply a strict Content-Security-Policy.",
    "CWE-89": "SQL injection. Use parameterized queries / prepared statements; never concatenate user input into SQL.",
    "CWE-22": "Path traversal. Canonicalize and validate file paths; reject inputs containing '..' or absolute paths.",
    "CWE-78": "OS command injection. Avoid shell invocation; if unavoidable, use argument arrays (not strings) with strict allowlists.",
    "CWE-94": "Code injection. Never eval untrusted input; use safe parsers and structured data formats.",
    "CWE-502": "Unsafe deserialization. Avoid deserializing untrusted data; use a safe format (JSON) over pickle/Java-serialization/YAML.",
    "CWE-287": "Improper authentication. Enforce strong session management, MFA where possible, and rate-limit auth endpoints.",
    "CWE-863": "Incorrect authorization. Centralize access checks; verify permissions on every privileged operation, not just the entry point.",
    "CWE-918": "Server-side request forgery (SSRF). Allowlist outbound destinations; block requests to internal IP ranges and metadata endpoints.",
    "CWE-352": "CSRF. Use SameSite cookies and per-request anti-CSRF tokens for state-changing endpoints.",
    "CWE-434": "Unrestricted file upload. Validate file type by content (not extension); store uploads outside the webroot; scan for malware.",
    "CWE-20": "Improper input validation. Validate all inputs against an allowlist of expected shapes/sizes before use.",
    "CWE-119": "Memory safety violation. Patch and rebuild; consider memory-safe languages or compiler hardening (ASLR, stack canaries) where rebuild isn't possible.",
    "CWE-200": "Information exposure. Audit error messages and API responses for sensitive data leakage; apply principle of least disclosure.",
    "CWE-269": "Improper privilege management. Run services with least privilege; audit role assignments and capability grants.",
    "CWE-798": "Hard-coded credentials. Rotate the credential immediately; move secrets to a vault and reference at runtime.",
    "CWE-862": "Missing authorization. Add explicit authorization checks on every protected resource; default to deny.",
    "CWE-77": "Command injection. Same guidance as CWE-78 — argument arrays with allowlists, no shell invocation.",
    "CWE-416": "Use-after-free. Apply the vendor patch; this class of bug isn't fixable through configuration.",
    "CWE-787": "Out-of-bounds write. Apply the vendor patch; deploy compensating controls (WAF, network segmentation) until you can.",
    "CWE-125": "Out-of-bounds read. Apply the vendor patch; this often leaks memory contents and may chain with other vulnerabilities.",
    "CWE-770": "Resource exhaustion. Add rate limiting and resource quotas at the application or proxy layer.",
    "CWE-1188": "Insecure default. Review the product's hardening guide; the default configuration should not be used in production.",
}


def extract_mitigation(
    cve: dict[str, Any],
    kev_entry: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a structured mitigation summary from an NVD CVE record + KEV data.

    Args:
        cve: The inner CVE object from an NVD response.
        kev_entry: Optional KEV catalog entry for this CVE (if any).

    Returns:
        A dict with patches, advisories, KEV-required action, generic CWE
        guidance, and exploit references for awareness.
    """
    references = cve.get("references", [])

    patches: list[dict[str, Any]] = []
    advisories: list[dict[str, Any]] = []
    exploits: list[dict[str, Any]] = []
    other: list[dict[str, Any]] = []

    for ref in references:
        url = ref.get("url")
        tags = set(ref.get("tags", []))
        source = ref.get("source")
        entry = {"url": url, "tags": sorted(tags), "source": source}

        if tags & PATCH_TAGS:
            patches.append(entry)
        elif tags & ADVISORY_TAGS:
            advisories.append(entry)
        elif tags & EXPLOIT_TAGS:
            exploits.append(entry)
        else:
            other.append(entry)

    # CWE-based generic guidance, deduplicated.
    cwes = _collect_cwes(cve)
    cwe_guidance = []
    for cwe in cwes:
        guidance = CWE_GUIDANCE.get(cwe)
        if guidance:
            cwe_guidance.append({"cwe": cwe, "guidance": guidance})

    # KEV-required action takes top priority if present.
    kev_action = None
    if kev_entry:
        kev_action = {
            "required_action": kev_entry.get("requiredAction"),
            "due_date_for_us_federal_agencies": kev_entry.get("dueDate"),
            "source": "CISA Known Exploited Vulnerabilities catalog",
        }

    has_concrete_fix = bool(patches or advisories or kev_action)

    return {
        "cve_id": cve.get("id"),
        "has_concrete_fix": has_concrete_fix,
        "kev_required_action": kev_action,
        "patches": patches,
        "vendor_advisories": advisories,
        "cwe_based_guidance": cwe_guidance,
        "exploit_references": exploits,
        "other_references": other,
        "guidance_note": _build_guidance_note(has_concrete_fix, patches, advisories, kev_action),
    }


def _collect_cwes(cve: dict[str, Any]) -> list[str]:
    cwes: list[str] = []
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            value = desc.get("value", "")
            if value.startswith("CWE-") and value not in cwes:
                cwes.append(value)
    return cwes


def _build_guidance_note(
    has_concrete_fix: bool,
    patches: list[Any],
    advisories: list[Any],
    kev_action: dict[str, Any] | None,
) -> str:
    if kev_action:
        return (
            "This CVE is on the CISA KEV catalog. Follow the required action above. "
            "US federal civilian agencies must remediate by the due date; private "
            "organizations should treat KEV listings as urgent."
        )
    if patches:
        return (
            "Vendor patches are available — see the patches list. Apply them per "
            "your change-management process; verify version after patching."
        )
    if advisories:
        return (
            "No direct patch reference, but vendor or third-party advisories exist. "
            "Read those for the official mitigation steps before deploying any "
            "configuration-based workaround."
        )
    return (
        "No patches or advisories are linked from the NVD record. This is common "
        "for very recent CVEs. Check the vendor's security page directly, and use "
        "the CWE-based guidance below as a placeholder hardening measure."
    )
