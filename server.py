"""
Eren Security Auditor — MCP Server.

AI-powered code security auditor exposed via the Model Context Protocol (MCP).
Scans GitHub repositories for vulnerabilities using LLM-powered analysis and
returns structured findings with OWASP/CWE references and remediation guidance.

Supports both Streamable HTTP and stdio transports.

Usage:
    # Streamable HTTP (for MCP directories, remote clients)
    python server.py --transport streamable-http --port 8200

    # stdio (for local MCP clients like Claude Desktop)
    python server.py --transport stdio

    # With custom endpoint
    AUDIT_ENDPOINT=http://your-server AUDIT_API_KEY=your-key python server.py

Environment variables:
    AUDIT_ENDPOINT  - Audit API base URL (required)
    AUDIT_API_KEY   - API key for authentication
    PORT            - Server port for HTTP transport (default: 8200)
    HOST            - Server bind address (default: 0.0.0.0)
"""

import json
import os
import sys
import time
import urllib.request
import urllib.error
from typing import Any

from mcp.server.fastmcp import FastMCP

# ── Configuration ────────────────────────────────────────────────────

AUDIT_ENDPOINT = os.environ.get("AUDIT_ENDPOINT", "")
AUDIT_API_KEY = os.environ.get("AUDIT_API_KEY", "")

mcp = FastMCP(
    "Eren Security Auditor",
    instructions=(
        "AI-powered code security auditor. Scans GitHub repositories for "
        "vulnerabilities using LLM-powered analysis. Returns structured "
        "findings with OWASP Top 10 and CWE references, risk scores, "
        "and actionable remediation guidance."
    ),
    host=os.environ.get("HOST", "0.0.0.0"),
    port=int(os.environ.get("PORT", "8200")),
)


# ── HTTP helpers ─────────────────────────────────────────────────────


def _api_call(method: str, path: str, body: dict | None = None, timeout: int = 300) -> dict:
    """Call the audit proxy API."""
    url = f"{AUDIT_ENDPOINT}{path}"
    headers = {
        "User-Agent": "MCP-Security-Audit/1.0",
        "Accept": "application/json",
    }
    if AUDIT_API_KEY:
        headers["X-API-Key"] = AUDIT_API_KEY

    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=data, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")
        try:
            return {"error": json.loads(error_body).get("error", error_body), "status": e.code}
        except json.JSONDecodeError:
            return {"error": error_body, "status": e.code}
    except urllib.error.URLError as e:
        return {"error": f"Connection failed: {e.reason}"}


def _poll_audit(audit_id: str, max_polls: int = 120, interval: int = 5) -> dict:
    """Poll an audit until it completes or fails."""
    for _ in range(max_polls):
        result = _api_call("GET", f"/v1/audit/{audit_id}")
        status = result.get("status", "")
        if status in ("completed", "failed"):
            return result
        if "error" in result and "status" not in result:
            return result
        time.sleep(interval)

    return {"error": "Audit timed out", "audit_id": audit_id}


# ── MCP Tools ────────────────────────────────────────────────────────


@mcp.tool()
def security_scan(repo_url: str, branch: str = "main") -> str:
    """Run a security audit on a GitHub repository.

    Clones the repo, scans source files for vulnerabilities using
    LLM-powered analysis, and returns structured findings with
    OWASP/CWE references and remediation guidance.

    Takes 1-10 minutes depending on repo size.

    Args:
        repo_url: GitHub repository URL (e.g. https://github.com/owner/repo)
        branch: Branch to scan (default: main)
    """
    submit = _api_call("POST", "/v1/audit", {"repo_url": repo_url, "branch": branch})

    if "error" in submit:
        return json.dumps({"error": submit["error"]}, indent=2)

    audit_id = submit.get("audit_id") or submit.get("id")
    if not audit_id:
        return json.dumps({"error": "No audit ID returned", "response": submit}, indent=2)

    result = _poll_audit(audit_id)

    response: dict[str, Any] = {
        "audit_id": audit_id,
        "repo": result.get("repo_name", repo_url),
        "status": result.get("status", "unknown"),
        "risk_score": result.get("risk_score", 0),
        "files_scanned": result.get("files_scanned", 0),
    }

    if result.get("duration_ms"):
        response["duration_seconds"] = round(result["duration_ms"] / 1000, 1)

    if result.get("status") == "completed":
        response["severity_counts"] = {
            "critical": result.get("critical_count", 0),
            "high": result.get("high_count", 0),
            "medium": result.get("medium_count", 0),
            "low": result.get("low_count", 0),
            "info": result.get("info_count", 0),
        }
        response["findings"] = [
            {
                "severity": f.get("severity", ""),
                "title": f.get("title", ""),
                "file_path": f.get("file_path", ""),
                "line_number": f.get("line_number"),
                "cwe_id": f.get("cwe_id", ""),
                "owasp_category": f.get("owasp_category", ""),
                "description": f.get("description", ""),
                "recommendation": f.get("recommendation", ""),
            }
            for f in result.get("findings", [])
        ]

    if result.get("error_message"):
        response["error"] = result["error_message"]
    elif result.get("error"):
        response["error"] = result["error"]

    return json.dumps(response, indent=2)


@mcp.tool()
def audit_status(audit_id: str) -> str:
    """Check the status of a running or completed audit.

    Returns audit metadata, findings count, risk score, and
    full findings list if the audit is complete.

    Args:
        audit_id: The audit ID returned by security_scan
    """
    result = _api_call("GET", f"/v1/audit/{audit_id}")

    if "error" in result and "status" not in result:
        return json.dumps({"error": result["error"]}, indent=2)

    response: dict[str, Any] = {
        "audit_id": result.get("id", audit_id),
        "repo": result.get("repo_name", ""),
        "status": result.get("status", ""),
        "risk_score": result.get("risk_score", 0),
        "files_scanned": result.get("files_scanned", 0),
        "findings_count": result.get("findings_count", 0),
    }

    if result.get("status") == "completed" and result.get("findings"):
        response["findings"] = [
            {
                "severity": f.get("severity", ""),
                "title": f.get("title", ""),
                "file_path": f.get("file_path", ""),
                "cwe_id": f.get("cwe_id", ""),
                "recommendation": f.get("recommendation", ""),
            }
            for f in result["findings"]
        ]

    if result.get("error_message"):
        response["error"] = result["error_message"]

    return json.dumps(response, indent=2)


@mcp.tool()
def audit_list(limit: int = 10) -> str:
    """List recent security audits with summary information.

    Args:
        limit: Max audits to return (default: 10, max: 50)
    """
    limit = min(max(limit, 1), 50)
    result = _api_call("GET", f"/v1/audits?limit={limit}")

    if "error" in result:
        return json.dumps({"error": result["error"]}, indent=2)

    audits = result if isinstance(result, list) else result.get("audits", [])
    response = [
        {
            "audit_id": a.get("id", ""),
            "repo": a.get("repo_name", ""),
            "status": a.get("status", ""),
            "risk_score": a.get("risk_score", 0),
            "findings_count": a.get("findings_count", 0),
            "started_at": a.get("started_at", ""),
        }
        for a in audits
    ]
    return json.dumps(response, indent=2)


@mcp.tool()
def audit_stats() -> str:
    """Get aggregate audit statistics.

    Returns total audits, findings count, average risk score,
    and severity breakdown.
    """
    result = _api_call("GET", "/v1/stats")

    if "error" in result:
        return json.dumps({"error": result["error"]}, indent=2)

    return json.dumps(result, indent=2)


# ── Entry point ──────────────────────────────────────────────────────


def main():
    """Run the MCP server."""
    global AUDIT_ENDPOINT, AUDIT_API_KEY

    import argparse

    parser = argparse.ArgumentParser(description="Eren Security Auditor — MCP Server")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8200")))
    parser.add_argument("--host", default=os.environ.get("HOST", "0.0.0.0"))
    parser.add_argument("--endpoint", help="Audit API endpoint URL")
    parser.add_argument("--api-key", help="Audit API key")
    parser.add_argument("--transport", choices=["streamable-http", "stdio"], default="streamable-http")
    args = parser.parse_args()

    if args.endpoint:
        AUDIT_ENDPOINT = args.endpoint
    if args.api_key:
        AUDIT_API_KEY = args.api_key

    mcp.settings.host = args.host
    mcp.settings.port = args.port

    if not AUDIT_ENDPOINT:
        print("[mcp-audit] ERROR: AUDIT_ENDPOINT is required. Set via env var or --endpoint flag.", file=sys.stderr)
        sys.exit(1)

    print(f"[mcp-audit] Starting on {args.host}:{args.port}", file=sys.stderr)
    print(f"[mcp-audit] Endpoint: {AUDIT_ENDPOINT}", file=sys.stderr)
    print(f"[mcp-audit] Transport: {args.transport}", file=sys.stderr)

    mcp.run(transport=args.transport)


if __name__ == "__main__":
    main()
