# security-mcp

An MCP server that gives a MCP Client five tools for security work. CVE lookup, exploitation scoring, active-exploitation checks, automated triage, and remediation guidance — all sourced from authoritative public feeds (NIST NVD, FIRST EPSS, CISA KEV).

## Why this exists

Base Claude can describe famous CVEs from training data, but for real security work that's not enough:

- **Knowledge cutoff.** Claude doesn't know about CVEs published after its training data — and worse, will sometimes confidently hallucinate details for unfamiliar CVE IDs.
- **No correlation.** A CVSS score alone doesn't tell you whether to patch tonight or next month. You need exploitation likelihood (EPSS) and active-exploitation status (KEV) too.
- **No accountability.** Decisions made on hallucinated data can't be audited.

This MCP server fixes all three. Every claim is grounded in a real, current API response.

---

## Tools

| Tool | Source | What it answers |
|------|--------|-----------------|
| `lookup_cve` | NIST NVD | "What is this CVE?" |
| `get_epss_score` | FIRST EPSS | "How likely is it to be exploited?" |
| `check_kev_status` | CISA KEV | "Is it being actively exploited right now?" |
| `triage_cve` | All three combined | "Should I patch it, and how urgently?" |
| `get_mitigation` | NVD + KEV | "How do I fix it?" |

The interesting tool is `triage_cve` — it fans out three parallel API calls and applies explicit rules to produce a single decision (`PATCH_IMMEDIATELY` / `PATCH_THIS_WEEK` / `PATCH_NEXT_CYCLE` / `MONITOR` / `UNKNOWN`) with auditable reasoning.

---

## Setup

Requires Python 3.10+. Using `uv` is recommended but `pip` works too.

```bash
cd security-mcp
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Example

In MCP Client:

> **You:** Triage CVE-2021-44228 for me.
>
> **MCP Client:** *[calls `triage_cve`]*
>
> **Decision: PATCH_IMMEDIATELY**
>
> Reasoning:
> - Listed on CISA KEV — confirmed real-world exploitation
> - Has been used in ransomware campaigns
>
> CVSS: 10.0 (CRITICAL) · EPSS: 99.99th percentile · On KEV: yes (added 2021-12-10)

> **You:** How do I fix it?
>
> **MCP Client:** *[calls `get_mitigation`]*
>
> CISA-required action: Apply updates per vendor instructions (US federal due date: 2021-12-24).
> Patch: github.com/apache/logging-log4j2/pull/608
> Vendor advisory: logging.apache.org/log4j/2.x/security.html
> CWE-20 / CWE-502 hardening guidance also included.

---