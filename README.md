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
