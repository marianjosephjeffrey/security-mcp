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

### Optional: get an NVD API key

NVD allows ~5 requests per 30 seconds without a key, ~50/30s with one. For a single-user
MCP server you probably don't need a key, but if you start hitting rate limits, get a
free one at https://nvd.nist.gov/developers/request-an-api-key and set it via:

```bash
export NVD_API_KEY="your-key-here"
```

## Run it standalone (sanity check)

```bash
python -m security_mcp.server
```

This starts the server on stdio. It will sit there waiting for an MCP client to connect —
that's correct. Press Ctrl+C to exit.

## Connect to Claude Desktop

Edit your Claude Desktop config:

- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

Add an entry under `mcpServers`:

```json
{
  "mcpServers": {
    "security-mcp": {
      "command": "/absolute/path/to/security-mcp/.venv/bin/python",
      "args": ["-m", "security_mcp.server"]
    }
  }
}
```

Use the **absolute path** to the Python interpreter inside your venv — Claude Desktop
won't pick up your shell's PATH. Then fully quit Claude Desktop (not just close the
window) and reopen it. You should see an MCP indicator at the bottom of the chat input.

To pass an API key, add an `env` block:

```json
{
  "mcpServers": {
    "security-mcp": {
      "command": "/absolute/path/to/security-mcp/.venv/bin/python",
      "args": ["-m", "security_mcp.server"],
      "env": { "NVD_API_KEY": "your-key-here" }
    }
  }
}
```

## Try it

Once connected, ask Claude things like:

- "What's CVE-2024-3400?"
- "Is CVE-2021-44228 critical? Show me the references."
- "Lookup CVE-2014-0160 and explain what it does."

## Project layout

```
security-mcp/
├── pyproject.toml
├── README.md
└── src/security_mcp/
    ├── __init__.py
    ├── server.py            # MCP server + tool definitions (decorated functions)
    ├── formatters.py        # Cleans up raw API responses for the LLM
    └── api/
        ├── __init__.py
        └── nvd.py           # HTTP client for the NVD API
```

The split is deliberate: each external API gets its own client file, the server
file holds only thin tool wrappers, and formatters live separately so they can be
unit-tested without network calls.

## Adding a new tool

The pattern, in three steps:

1. **Add the API client** — create `src/security_mcp/api/<source>.py` with an `async`
   function that calls the upstream API and returns the raw JSON (or raises a custom
   exception). Mirror the shape of `nvd.py`.

2. **Add a formatter** (if needed) — extract the fields that matter into a clean dict
   in `formatters.py`. Skip this step if the raw response is already well-shaped.

3. **Register the tool** — add a new `@mcp.tool()` function to `server.py`. Validate
   inputs with a regex or simple check, call your client, format the result, return it.
   Catch your custom exception and return `{"error": ...}` rather than raising.

That's the whole pattern. Suggested next tools, in roughly increasing complexity:

- `get_epss_score` — exploitation probability from FIRST EPSS (no auth, simple GET)
- `check_kev_status` — whether CVE is in CISA's Known Exploited Vulnerabilities catalog
- `bulk_cve_lookup` — fetch multiple CVEs in parallel using `asyncio.gather`
