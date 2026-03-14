"""
Eren Security Auditor — MCP Server.

AI-powered code security auditor exposed via the Model Context Protocol (MCP).
Scans GitHub repositories for vulnerabilities using LLM-powered analysis and
returns structured findings with OWASP/CWE references and remediation guidance.
"""

import json
import os
import sys
import time
import urllib.request
import urllib.error
from typing import Any, Annotated

from mcp.server.fastmcp import FastMCP
from pydantic import Field

AUDIT_ENDPOINT = os.environ.get("AUDIT_ENDPOINT", "")
AUDIT_API_KEY = os.environ.get("AUDIT_API_KEY", "")

mcp = FastMCP(
    "Eren Security Auditor",
    instructions=(
        "AI-powered code security auditor. Submit a GitHub repository URL to "
        "security_scan and receive structured vulnerability findings with "
        "OWASP Top 10 and CWE references, risk scores, and remediation guidance. "
        "Use audit_status to check progress, audit_list for history, audit_stats "
        "for aggregate metrics."
    ),
    host=os.environ.get("HOST", "0.0.0.0"),
    port=int(os.environ.get("PORT", "8200")),
)


def _api_call(method: str, path: str, body: dict | None = None, timeout: int = 300) -> dict:
    url = f"{AUDIT_ENDPOINT}{path}"
    headers = {"User-Agent": "MCP-Security-Audit/1.0", "Accept": "application/json"}
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
    for _ in range(max_polls):
        result = _api_call("GET", f"/v1/audit/{audit_id}")
        status = result.get("status", "")
        if status in ("completed", "failed"):
            return result
        if "error" in result and "status" not in result:
            return result
        time.sleep(interval)
    return {"error": "Audit timed out", "audit_id": audit_id}


@mcp.tool(annotations={
    "title": "Security Scan",
    "readOnlyHint": False,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": True,
})
def security_scan(
    repo_url: Annotated[str, Field(description="GitHub repository URL to scan, e.g. https://github.com/owner/repo.")],
    branch: Annotated[str, Field(description="Git branch to scan. Defaults to main.")] = "main",
) -> str:
    """Run a full security audit on a GitHub repository. Clones the repo, scans source files with LLM-powered analysis, returns OWASP/CWE findings with remediation. Takes 1-10 minutes."""
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


@mcp.tool(annotations={
    "title": "Audit Status",
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": False,
})
def audit_status(
    audit_id: Annotated[str, Field(description="The audit ID returned by security_scan.")],
) -> str:
    """Check the status of a running or completed security audit. Returns findings if complete."""
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


@mcp.tool(annotations={
    "title": "List Audits",
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": False,
})
def audit_list(
    limit: Annotated[int, Field(description="Maximum number of audits to return (1-50).")] = 10,
) -> str:
    """List recent security audits with summary information including status and risk scores."""
    limit = min(max(limit, 1), 50)
    result = _api_call("GET", f"/v1/audits?limit={limit}")
    if "error" in result:
        return json.dumps({"error": result["error"]}, indent=2)
    audits = result if isinstance(result, list) else result.get("audits", [])
    return json.dumps([
        {
            "audit_id": a.get("id", ""),
            "repo": a.get("repo_name", ""),
            "status": a.get("status", ""),
            "risk_score": a.get("risk_score", 0),
            "findings_count": a.get("findings_count", 0),
            "started_at": a.get("started_at", ""),
        }
        for a in audits
    ], indent=2)


@mcp.tool(annotations={
    "title": "Audit Statistics",
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": False,
})
def audit_stats() -> str:
    """Get aggregate audit statistics — total scans, findings breakdown by severity, average risk score."""
    result = _api_call("GET", "/v1/stats")
    if "error" in result:
        return json.dumps({"error": result["error"]}, indent=2)
    return json.dumps(result, indent=2)


@mcp.prompt()
def scan_workflow() -> str:
    """Step-by-step guide to scan a repository for security vulnerabilities."""
    return (
        "To scan a repository:\n\n"
        "1. Call security_scan with the GitHub repo URL\n"
        "2. Wait 1-10 minutes for completion\n"
        "3. Review findings — each has severity, CWE ID, OWASP category\n"
        "4. Follow remediation recommendations\n"
        "5. Use audit_status if scan was interrupted\n\n"
        "Checks: SQL injection, XSS, command injection, path traversal, "
        "hardcoded secrets, insecure crypto, SSRF, and more."
    )


@mcp.prompt()
def interpret_results() -> str:
    """How to interpret audit results and prioritize fixes."""
    return (
        "Interpreting results:\n\n"
        "- risk_score: 0-100 (0=clean, 100=critical)\n"
        "- Severity: critical > high > medium > low > info\n"
        "- CWE IDs: cwe.mitre.org for details\n"
        "- OWASP: maps to OWASP Top 10 2021\n\n"
        "Fix critical/high first, then medium. Low/info are best-practice."
    )


def main():
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
    mcp.settings.transport_security.enable_dns_rebinding_protection = False
    if not AUDIT_ENDPOINT:
        print("[mcp-audit] ERROR: AUDIT_ENDPOINT is required.", file=sys.stderr)
        sys.exit(1)
    mcp.run(transport=args.transport)


if __name__ == "__main__":
    main()
