"""MITRE ATT&CK technique mapping for CVEs.

The full path from CVE to ATT&CK is: CVE → CWE → CAPEC → ATT&CK technique.
MITRE publishes all of this as STIX/JSON, but the data is large (tens of MB),
changes slowly, and only ~112 of 546 CAPECs have direct ATT&CK mappings.

We take a pragmatic shortcut: bundle a curated CWE → ATT&CK technique lookup
in the source. This is the same approach used by NopSec, IBM, and several
academic mappings. Tradeoff: we get fast, offline lookups at the cost of
needing to refresh the table when MITRE updates its mappings (rarely — once
or twice a year).

Each ATT&CK entry includes:
  - id:       the technique ID (e.g. "T1190")
  - name:     human-readable name
  - tactic:   the kill-chain phase (e.g. "Initial Access")
  - url:      direct link to attack.mitre.org

The mapping is one-to-many: a single CWE typically enables multiple techniques.
"""

from __future__ import annotations

from typing import Any

# Curated CWE → list of ATT&CK techniques.
# Derived from MITRE CAPEC↔ATT&CK mappings + common AppSec practice.
CWE_TO_ATTACK: dict[str, list[dict[str, str]]] = {
    "CWE-20": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
    ],
    "CWE-22": [
        {"id": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery"},
        {"id": "T1005", "name": "Data from Local System", "tactic": "Collection"},
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    ],
    "CWE-77": [
        {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    ],
    "CWE-78": [
        {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    ],
    "CWE-79": [
        {"id": "T1059.007", "name": "JavaScript", "tactic": "Execution"},
        {"id": "T1185", "name": "Browser Session Hijacking", "tactic": "Collection"},
    ],
    "CWE-89": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        {"id": "T1005", "name": "Data from Local System", "tactic": "Collection"},
    ],
    "CWE-94": [
        {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    ],
    "CWE-119": [
        {"id": "T1203", "name": "Exploitation for Client Execution", "tactic": "Execution"},
        {"id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
    ],
    "CWE-125": [
        {"id": "T1005", "name": "Data from Local System", "tactic": "Collection"},
        {"id": "T1212", "name": "Exploitation for Credential Access", "tactic": "Credential Access"},
    ],
    "CWE-190": [
        {"id": "T1203", "name": "Exploitation for Client Execution", "tactic": "Execution"},
    ],
    "CWE-200": [
        {"id": "T1592", "name": "Gather Victim Host Information", "tactic": "Reconnaissance"},
        {"id": "T1005", "name": "Data from Local System", "tactic": "Collection"},
    ],
    "CWE-269": [
        {"id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
        {"id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion"},
    ],
    "CWE-287": [
        {"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access"},
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    ],
    "CWE-295": [
        {"id": "T1557", "name": "Adversary-in-the-Middle", "tactic": "Credential Access"},
    ],
    "CWE-306": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        {"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access"},
    ],
    "CWE-327": [
        {"id": "T1552", "name": "Unsecured Credentials", "tactic": "Credential Access"},
    ],
    "CWE-352": [
        {"id": "T1185", "name": "Browser Session Hijacking", "tactic": "Collection"},
    ],
    "CWE-400": [
        {"id": "T1499", "name": "Endpoint Denial of Service", "tactic": "Impact"},
    ],
    "CWE-416": [
        {"id": "T1203", "name": "Exploitation for Client Execution", "tactic": "Execution"},
        {"id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
    ],
    "CWE-434": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        {"id": "T1505.003", "name": "Web Shell", "tactic": "Persistence"},
    ],
    "CWE-476": [
        {"id": "T1499", "name": "Endpoint Denial of Service", "tactic": "Impact"},
    ],
    "CWE-502": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
    ],
    "CWE-522": [
        {"id": "T1552", "name": "Unsecured Credentials", "tactic": "Credential Access"},
    ],
    "CWE-732": [
        {"id": "T1222", "name": "File and Directory Permissions Modification", "tactic": "Defense Evasion"},
        {"id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
    ],
    "CWE-770": [
        {"id": "T1499", "name": "Endpoint Denial of Service", "tactic": "Impact"},
    ],
    "CWE-787": [
        {"id": "T1203", "name": "Exploitation for Client Execution", "tactic": "Execution"},
        {"id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
    ],
    "CWE-798": [
        {"id": "T1552.001", "name": "Credentials In Files", "tactic": "Credential Access"},
        {"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access"},
    ],
    "CWE-862": [
        {"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access"},
        {"id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
    ],
    "CWE-863": [
        {"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access"},
        {"id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
    ],
    "CWE-918": [
        {"id": "T1090", "name": "Proxy", "tactic": "Command and Control"},
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    ],
}

ATTACK_BASE_URL = "https://attack.mitre.org/techniques/"


def _technique_with_url(t: dict[str, str]) -> dict[str, str]:
    """Add the canonical attack.mitre.org URL to a technique entry."""
    technique_path = t["id"].replace(".", "/")  # sub-techniques use slashes
    return {**t, "url": f"{ATTACK_BASE_URL}{technique_path}/"}


def map_cwes_to_attack(cwes: list[str]) -> dict[str, Any]:
    """Map a list of CWE IDs to MITRE ATT&CK techniques.

    Returns a deduplicated, tactic-grouped view of the techniques an attacker
    is likely to use given these weakness classes.
    """
    seen: dict[str, dict[str, str]] = {}  # technique_id -> technique
    by_cwe: dict[str, list[dict[str, str]]] = {}
    unmapped: list[str] = []

    for cwe in cwes:
        techniques = CWE_TO_ATTACK.get(cwe)
        if not techniques:
            unmapped.append(cwe)
            continue
        enriched = [_technique_with_url(t) for t in techniques]
        by_cwe[cwe] = enriched
        for t in enriched:
            seen[t["id"]] = t

    # Group all unique techniques by tactic (kill-chain phase).
    by_tactic: dict[str, list[dict[str, str]]] = {}
    for t in seen.values():
        by_tactic.setdefault(t["tactic"], []).append(t)
    for tactic in by_tactic:
        by_tactic[tactic].sort(key=lambda x: x["id"])

    return {
        "techniques_by_cwe": by_cwe,
        "techniques_by_tactic": by_tactic,
        "unique_techniques": sorted(seen.values(), key=lambda x: x["id"]),
        "unmapped_cwes": unmapped,
        "summary": (
            f"{len(seen)} unique ATT&CK technique(s) across "
            f"{len(by_tactic)} tactic(s)" if seen else "No ATT&CK mappings available for these CWEs"
        ),
    }
