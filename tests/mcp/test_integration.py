"""Integration test: full hunt workflow via MCP.

Creates a hunt, runs recon, tests for vulns, analyzes, and drafts a report —
all through MCP tool calls with mocked adapters/vuln functions.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from boba.core.models import (
    Confidence,
    Severity,
    ToolResult,
    VulnTestResult,
)

pytestmark = pytest.mark.usefixtures("_patch_resources")


def _text(content_blocks):
    return json.loads(content_blocks[0].text)


def _make_tool_result(tool_name, records):
    return ToolResult(
        tool_name=tool_name,
        command=[tool_name],
        exit_code=0,
        raw_stdout="",
        raw_stderr="",
        duration_seconds=1.0,
        records=records,
    )


async def test_full_hunt_workflow(mcp_server, mcp_resources):
    """End-to-end: create → recon → vuln test → analyze → report."""

    # ── 1. Create hunt ──────────────────────────────────────────────────
    content, _ = await mcp_server.call_tool("hunt_create", {"name": "Integration Test"})
    hunt = _text(content)
    hunt_id = hunt["hunt_id"]
    assert hunt["status"] == "active"

    # ── 2. Recon: subdomains ────────────────────────────────────────────
    subdomain_records = [
        {"subdomain": "api.example.com", "source": "subfinder"},
        {"subdomain": "www.example.com", "source": "subfinder"},
    ]
    with patch(
        "boba.tools.recon.SubfinderAdapter.run",
        AsyncMock(return_value=_make_tool_result("subfinder", subdomain_records)),
    ):
        content, _ = await mcp_server.call_tool(
            "recon_subdomains", {"hunt_id": hunt_id, "domains": ["example.com"]}
        )
    recon_data = _text(content)
    assert recon_data["summary"]["records_found"] == 2

    # ── 3. Verify context has subdomains ────────────────────────────────
    content, _ = await mcp_server.call_tool("context_subdomains", {"hunt_id": hunt_id})
    subs = _text(content)
    assert len(subs) == 2

    # ── 4. Recon: hosts ─────────────────────────────────────────────────
    host_records = [
        {
            "host": "api.example.com",
            "ip": "1.2.3.4",
            "port": 443,
            "scheme": "https",
            "url": "https://api.example.com",
            "status_code": 200,
            "title": "API",
            "webserver": "nginx",
            "content_length": 500,
            "content_type": "application/json",
        }
    ]
    with patch(
        "boba.tools.recon.HttpxRunnerAdapter.run",
        AsyncMock(return_value=_make_tool_result("httpx", host_records)),
    ):
        content, _ = await mcp_server.call_tool(
            "recon_hosts", {"hunt_id": hunt_id, "targets": ["api.example.com"]}
        )
    assert _text(content)["summary"]["records_found"] == 1

    # ── 5. Check stats ──────────────────────────────────────────────────
    content, _ = await mcp_server.call_tool("context_stats", {"hunt_id": hunt_id})
    stats = _text(content)
    assert stats["subdomains"] == 2
    assert stats["hosts"] == 1
    assert stats["hosts_alive"] == 1

    # ── 6. Create sessions for authenticated testing ────────────────────
    await mcp_server.call_tool(
        "session_create",
        {"hunt_id": hunt_id, "name": "user_a", "target_url": "https://api.example.com"},
    )
    await mcp_server.call_tool(
        "session_login_token",
        {"hunt_id": hunt_id, "session_name": "user_a", "token": "tok_a"},
    )
    await mcp_server.call_tool(
        "session_create",
        {"hunt_id": hunt_id, "name": "user_b", "target_url": "https://api.example.com"},
    )
    await mcp_server.call_tool(
        "session_login_token",
        {"hunt_id": hunt_id, "session_name": "user_b", "token": "tok_b"},
    )

    # Verify sessions
    content, _ = await mcp_server.call_tool("session_list", {"hunt_id": hunt_id})
    assert len(_text(content)) == 2

    # ── 7. Vulnerability test: SQLi ─────────────────────────────────────
    mock_client = MagicMock()
    mock_client.request = AsyncMock()
    mock_client.close = AsyncMock()
    mcp_resources._http_clients[hunt_id] = mock_client

    sqli_result = VulnTestResult(
        test_type="sqli",
        vulnerable=True,
        confidence=Confidence.CONFIRMED,
        title="SQL Injection in search parameter",
        description="Error-based SQLi confirmed",
        severity=Severity.HIGH,
        evidence=[{"type": "error_message", "detail": "syntax error near 'OR'"}],
        request_ids=[1, 2, 3],
    )
    with patch("boba.mcp.tools_vuln.vuln.test_sqli", AsyncMock(return_value=sqli_result)):
        content, _ = await mcp_server.call_tool(
            "test_sqli",
            {
                "hunt_id": hunt_id,
                "url": "https://api.example.com/search",
                "param": "q",
                "session_name": "user_a",
            },
        )
    vuln_data = _text(content)
    assert vuln_data["vulnerable"] is True
    assert vuln_data["severity"] == "high"

    # ── 8. Analysis: coverage + severity ────────────────────────────────
    from dataclasses import dataclass, field

    @dataclass
    class FakeCoverage:
        total_endpoints: int = 5
        tested_endpoints: int = 1
        untested_endpoints: int = 4
        coverage_by_test_type: dict = field(default_factory=lambda: {"sqli": 1})
        gaps: list = field(default_factory=list)

    with patch(
        "boba.mcp.tools_analysis.coverage.get_coverage_summary",
        return_value=FakeCoverage(),
    ):
        content, _ = await mcp_server.call_tool("analyze_coverage", {"hunt_id": hunt_id})
    cov = _text(content)
    assert cov["tested_endpoints"] == 1

    scored = [
        {
            "finding_id": 1,
            "title": "SQL Injection",
            "cvss_score": 8.6,
            "cvss_severity": "high",
            "payout_min": 2500,
            "payout_max": 7500,
        }
    ]
    with patch("boba.mcp.tools_analysis.severity.score_findings", return_value=scored):
        content, _ = await mcp_server.call_tool(
            "analyze_severity", {"hunt_id": hunt_id, "platform": "hackerone"}
        )
    severity_data = _text(content)
    assert severity_data[0]["cvss_score"] == 8.6

    # ── 9. Report draft ─────────────────────────────────────────────────
    from boba.core.models import ReportDraft, ReportStatus

    draft = ReportDraft(
        id=1,
        hunt_id=hunt_id,
        finding_id=1,
        title="SQL Injection in search parameter",
        severity=Severity.HIGH,
        cvss_score=8.6,
        summary="Error-based SQL injection in the q parameter",
        steps=["Navigate to /search", "Set q='OR 1=1--", "Observe SQL error"],
        impact="Full database read access",
        remediation="Use parameterized queries",
        status=ReportStatus.DRAFT,
    )
    with patch("boba.mcp.tools_reporting.draft.draft_finding_report", return_value=draft):
        content, _ = await mcp_server.call_tool(
            "report_draft", {"hunt_id": hunt_id, "finding_id": 1}
        )
    report_data = _text(content)
    assert report_data["title"] == "SQL Injection in search parameter"
    assert len(report_data["steps"]) == 3

    # ── 10. Close hunt ──────────────────────────────────────────────────
    content, _ = await mcp_server.call_tool("hunt_close", {"hunt_id": hunt_id})
    assert _text(content)["status"] == "completed"
