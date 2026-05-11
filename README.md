# security-mcp

> A Model Context Protocol server that turns Claude into a vulnerability triage analyst.

`security-mcp` gives Claude eight tools for security work — CVE lookup, exploitation scoring, active-exploitation checks, public-exploit search, automated triage, bulk triage, remediation guidance, and MITRE ATT&CK mapping — all sourced from authoritative public feeds (NIST NVD, FIRST EPSS, CISA KEV, Exploit-DB, MITRE).

Ask Claude *"triage these 30 CVEs from my latest scan"* and get back a single prioritized patch list with reasoning for each verdict.

---

## Why this exists

Base Claude can describe famous CVEs from training data, but for real security work that's not enough:

- **Knowledge cutoff.** Claude doesn't know about CVEs published after its training data — and worse, will sometimes confidently hallucinate details.
- **No correlation.** A CVSS score alone doesn't tell you whether to patch tonight. You need exploitation likelihood (EPSS), active-exploitation status (KEV), and public-exploit availability (Exploit-DB).
- **No scale.** Real scans produce dozens to hundreds of CVEs — one-by-one triage doesn't work.
- **No accountability.** Decisions made on hallucinated data can't be audited.

This MCP server fixes all four. Every claim is grounded in a real, current API response, and bulk operations make analyst workflows feasible in seconds instead of hours.

---

## Tools

| Tool | Source | What it answers |
|------|--------|-----------------|
| `lookup_cve` | NIST NVD | "What is this CVE?" |
| `get_epss_score` | FIRST EPSS | "How likely is it to be exploited?" |
| `check_kev_status` | CISA KEV | "Is it being actively exploited right now?" |
| `search_exploit_db` | Exploit-DB | "Is there public exploit code?" |
| `triage_cve` | All four above | "Should I patch it, and how urgently?" |
| `bulk_triage` | All four above | "Prioritize this list of CVEs." |
| `get_mitigation` | NVD + KEV | "How do I fix it?" |
| `map_to_attack_techniques` | MITRE ATT&CK / CWE | "How would an attacker use this?" |

The flagship tools are `triage_cve` (single CVE → verdict with reasoning) and `bulk_triage` (list of CVEs → prioritized patch list). They fan out parallel API calls across four data sources and apply explicit rules to produce auditable decisions.

---

## Example

In Claude Desktop:

> **You:** Triage these CVEs: CVE-2021-44228, CVE-2024-3400, CVE-2014-0160.
>
> **Claude:** *[calls `bulk_triage`]*
>
> Triaged 3 of 3 in 1.4 seconds.
>
> 1. **CVE-2021-44228 — PATCH_IMMEDIATELY** (CVSS 10.0, on KEV, 8 public exploits)
> 2. **CVE-2024-3400 — PATCH_IMMEDIATELY** (CVSS 10.0, on KEV)
> 3. **CVE-2014-0160 — PATCH_THIS_WEEK** (CVSS 7.5, EPSS 95th percentile, 4 public exploits)

> **You:** How would an attacker use CVE-2021-44228?
>
> **Claude:** *[calls `map_to_attack_techniques`]*
>
> Via CWE-502 (unsafe deserialization), an attacker would use:
> - T1190 *Exploit Public-Facing Application* (Initial Access)
> - T1059 *Command and Scripting Interpreter* (Execution)
>
> This places the threat in the initial-access and execution phases of the kill chain.

---

## Requirements

- Python 3.10 or newer
- [Claude Desktop](https://claude.ai/download) (the MCP host)
- macOS, Linux, or Windows

No paid API keys required. An optional free NVD key raises NVD's rate limit from ~5 requests per 30 seconds to ~50.

---

## Installation

### 1. Clone and install

```bash
git clone https://github.com/YOUR_USERNAME/security-mcp.git
cd security-mcp
python3 -m venv .venv
source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install --upgrade pip
pip install -e .
```

### 2. Find your venv's Python path

```bash
which python                  # Windows: where python
```

### 3. Configure Claude Desktop

Edit your Claude Desktop config:

- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "security-mcp": {
      "command": "/absolute/path/from/which-python",
      "args": ["-m", "security_mcp.server"]
    }
  }
}
```

To use an NVD API key, add an `env` block:

```json
{
  "mcpServers": {
    "security-mcp": {
      "command": "/absolute/path/from/which-python",
      "args": ["-m", "security_mcp.server"],
      "env": { "NVD_API_KEY": "your-key-here" }
    }
  }
}
```

### 4. Restart Claude Desktop

Fully quit Claude Desktop (Cmd+Q on macOS), reopen, and start a new chat. Try:

> Triage CVE-2021-44228 for me.

---

## Usage

Phrasing nudges Claude toward different tools:

| You ask... | Tool used |
|------------|-----------|
| "What is CVE-2024-3400?" | `lookup_cve` |
| "What's the EPSS score for CVE-XXX?" | `get_epss_score` |
| "Is CVE-XXX actively exploited?" | `check_kev_status` |
| "Are there exploits for CVE-XXX?" | `search_exploit_db` |
| "Should I patch CVE-XXX?" | `triage_cve` |
| "Prioritize these CVEs: ..." | `bulk_triage` |
| "How do I fix CVE-XXX?" | `get_mitigation` |
| "How would an attacker use CVE-XXX?" | `map_to_attack_techniques` |

---

## Triage decision rules

Applied in priority order:

| Decision | Conditions |
|----------|------------|
| **PATCH_IMMEDIATELY** | On CISA KEV, **OR** (CVSS ≥ 9.0 AND EPSS percentile ≥ 0.90), **OR** (CVSS ≥ 9.0 AND public exploit exists) |
| **PATCH_THIS_WEEK** | CVSS ≥ 7.0 AND (EPSS percentile ≥ 0.50 **OR** public exploit exists) |
| **PATCH_NEXT_CYCLE** | CVSS ≥ 7.0 (high severity but no exploitation pressure) |
| **MONITOR** | CVSS < 7.0 AND EPSS percentile < 0.90 AND no public exploit |
| **UNKNOWN** | Insufficient data |

Edit `src/security_mcp/triage.py` to match your organization's risk tolerance.

---

## Architecture

```
src/security_mcp/
├── server.py           MCP tool definitions (thin @mcp.tool() wrappers)
├── formatters.py       Cleans raw API responses for the LLM
├── mitigation.py       Patch/advisory extraction + CWE-class guidance
├── triage.py           Orchestrator: 4-way parallel calls + decision rules
├── bulk.py             Bulk triage with bounded concurrency and priority sort
├── attack_map.py       CWE → MITRE ATT&CK technique mapping
└── api/
    ├── nvd.py          NIST NVD client
    ├── epss.py         FIRST EPSS client
    ├── kev.py          CISA KEV client (24h in-memory cache)
    └── exploitdb.py    Exploit-DB CSV catalog client (24h in-memory cache)
```

Design principles:

- **Thin tool layer.** Each `@mcp.tool()` function is ~20 lines: validate input, call the client, format the result, return.
- **One file per data source.** Adding a new source means adding one file in `api/`.
- **Parallel API calls.** `triage_cve` fans out four concurrent lookups via `asyncio.gather`; `bulk_triage` adds bounded concurrency on top.
- **Caching where it counts.** Large, slow-changing feeds (KEV catalog, Exploit-DB CSV) are cached in-memory for 24 hours after first fetch.
- **Decision logic is rule-based, not LLM-based.** Triage rules live in plain Python so verdicts are reproducible and auditable.
- **No fabricated remediation.** `get_mitigation` only surfaces references already tagged in the NVD record, plus generic CWE guidance.

---

## Limitations

- **English-only descriptions.** Non-English content is dropped.
- **EPSS data lags new CVEs by a few days.** Triage handles this gracefully.
- **KEV is US-government-focused.** International equivalents may be more relevant in some contexts.
- **ATT&CK mapping uses a bundled curated lookup.** Not every CWE has direct ATT&CK mappings — MITRE itself only maps ~112 of 546 CAPECs to ATT&CK.
- **Bulk triage is capped at 50 CVEs per call** to avoid hammering NVD's rate limit.

---

## License

MIT.

---

## Acknowledgments

- [FastMCP](https://gofastmcp.com/) for the Python MCP framework
- [NIST NVD](https://nvd.nist.gov/) for the CVE data feed
- [FIRST.org](https://www.first.org/epss/) for EPSS
- [CISA](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) for the KEV catalog
- [Exploit-DB](https://www.exploit-db.com/) for public exploit data
- [MITRE](https://attack.mitre.org/) for ATT&CK and CWE
