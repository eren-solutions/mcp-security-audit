# Eren Security Auditor — MCP Server

AI-powered code security auditor exposed via the [Model Context Protocol](https://modelcontextprotocol.io/) (MCP). Scans GitHub repositories for vulnerabilities using LLM-powered analysis and returns structured findings with OWASP Top 10 and CWE references.

## Tools

| Tool | Description |
|------|-------------|
| `security_scan` | Run a full security audit on a GitHub repository (1-10 min) |
| `audit_status` | Check the status of a running or completed audit |
| `audit_list` | List recent security audits with summary info |
| `audit_stats` | Get aggregate statistics (total audits, findings, risk scores) |

## Quick Start

### Streamable HTTP (remote clients, MCP directories)

```bash
pip install mcp
AUDIT_ENDPOINT=https://your-api-host AUDIT_API_KEY=your-key python server.py --transport streamable-http --port 8200
```

Server runs at `http://localhost:8200/mcp`.

### stdio (Claude Desktop, local MCP clients)

```bash
pip install mcp
AUDIT_ENDPOINT=https://your-api-host AUDIT_API_KEY=your-key python server.py --transport stdio
```

### Claude Desktop Configuration

Add to `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "security-audit": {
      "command": "python",
      "args": ["path/to/server.py", "--transport", "stdio"],
      "env": {
        "AUDIT_ENDPOINT": "https://your-api-host",
        "AUDIT_API_KEY": "your-key"
      }
    }
  }
}
```

### Docker

```bash
docker build -t mcp-security-audit .
docker run -p 8200:8200 -e AUDIT_ENDPOINT=https://your-api-host -e AUDIT_API_KEY=your-key mcp-security-audit
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AUDIT_ENDPOINT` | *(required)* | Audit API base URL |
| `AUDIT_API_KEY` | *(required)* | API key for authentication |
| `PORT` | `8200` | HTTP server port |
| `HOST` | `0.0.0.0` | HTTP bind address |
| `SCAN_FREE_TIER` | `1` | Free scans per day per client |
| `SCAN_PRICE_USD` | `0.25` | Price in USD for paid scan (x402 payload) |
| `SCAN_WALLET_ADDRESS` | *(empty)* | USDC/Base wallet address for payment instructions |
| `MCP_BILLING_DB` | `/opt/mcp-audit/billing.db` | SQLite path for rate limit + API key data |
| `MCP_BILLING_ENABLED` | `true` | Set to `false` to disable billing entirely |

## Access Tiers

**Free tier**: `SCAN_FREE_TIER` scans/day per session (default: 1). No key needed.

**Paid tier**: Unlimited scans. Pass an API key as the `api_key` parameter or in the `X-API-Key` header. Keys are generated after BTC payment confirmation.

**Payment required (x402)**: When the free tier is exhausted and no valid API key is provided, `security_scan` returns a JSON payload with HTTP 402 semantics:

```json
{
  "error": "payment_required",
  "http_status": 402,
  "message": "Free tier exhausted (1 scan/day). Add X-API-Key header with a paid key, or pay $0.25 USDC to scan.",
  "free_tier": { "scans_per_day": 1, "resets": "00:00 UTC" },
  "payment": {
    "price": "0.25",
    "currency": "USDC",
    "network": "base",
    "address": "YOUR_WALLET_ADDRESS",
    "message": "Pay $0.25 USDC on Base to https://eren-solutions.com/audit/pay"
  }
}
```

## Example Usage

Once connected via an MCP client:

```
> Use security_scan to audit https://github.com/juice-shop/juice-shop

Scanning juice-shop/juice-shop (master branch)...
Found 47 findings across 200 files.

Risk Score: 72/100

Critical: 3 | High: 8 | Medium: 15 | Low: 12 | Info: 9

Top findings:
- [CRITICAL] SQL Injection in /routes/search.ts (CWE-89)
- [CRITICAL] Insecure JWT Secret (CWE-798)
- [HIGH] XSS via DOM manipulation in /frontend/src/... (CWE-79)
```

## How It Works

```
MCP Client → MCP Server (this repo) → Audit API → Clone repo → LLM scan → Findings
```

The server proxies tool calls to the Eren Security Auditor API, which:
1. Clones the target repository
2. Scans source files using LLM-powered analysis
3. Categorizes findings by OWASP Top 10 and CWE
4. Generates risk scores and remediation guidance

## License

MIT
