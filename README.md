# security-mcp

An MCP server that gives Claude security intelligence tools. Starting small with one
tool — `lookup_cve` — and designed to grow.

## What it does (so far)

| Tool         | Source           | Purpose                                                |
|--------------|------------------|--------------------------------------------------------|
| `lookup_cve` | NIST NVD API 2.0 | Fetch CVSS score, severity, description, CWEs, refs    |

## Setup

Requires Python 3.10+. Using `uv` is recommended but `pip` works too.

```bash
cd security-mcp
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Try it

Once connected, ask MCP Client things like:

- "What's CVE-2024-3400?"
- "Is CVE-2021-44228 critical? Show me the references."
- "Lookup CVE-2014-0160 and explain what it does."