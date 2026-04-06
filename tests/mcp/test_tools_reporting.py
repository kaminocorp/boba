"""Tests for MCP reporting tools."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from unittest.mock import patch

import pytest

from boba.core.models import ReportDraft, ReportStatus, Severity

pytestmark = pytest.mark.usefixtures("_patch_resources")


def _text(content_blocks) -> dict | list:
    return json.loads(content_blocks[0].text)


async def _create_hunt(mcp_server, name="Report Test"):
    content, _ = await mcp_server.call_tool("hunt_create", {"name": name})
    return json.loads(content[0].text)["hunt_id"]


def _fake_report_draft(**overrides) -> ReportDraft:
    defaults = dict(
        id=1,
        hunt_id="test",
        finding_id=10,
        title="SQLi in search parameter",
        severity=Severity.HIGH,
        cvss_score=8.6,
        summary="SQL injection found in the q parameter",
        steps=["Navigate to /search", "Inject payload in q"],
        impact="Full database access",
        remediation="Use parameterized queries",
        status=ReportStatus.DRAFT,
    )
    defaults.update(overrides)
    return ReportDraft(**defaults)


# -- report_draft -------------------------------------------------------------


async def test_report_draft_finding(mcp_server):
    hunt_id = await _create_hunt(mcp_server)
    draft = _fake_report_draft()

    with patch("boba.mcp.tools_reporting.draft.draft_finding_report", return_value=draft):
        content, _ = await mcp_server.call_tool(
            "report_draft", {"hunt_id": hunt_id, "finding_id": 10}
        )

    data = _text(content)
    assert data["title"] == "SQLi in search parameter"
    assert data["severity"] == "high"


async def test_report_draft_chain(mcp_server):
    hunt_id = await _create_hunt(mcp_server)
    draft = _fake_report_draft(chain_id=5, finding_id=None, title="XSS + CSRF Chain")

    with patch("boba.mcp.tools_reporting.draft.draft_chain_report", return_value=draft):
        content, _ = await mcp_server.call_tool("report_draft", {"hunt_id": hunt_id, "chain_id": 5})

    data = _text(content)
    assert data["title"] == "XSS + CSRF Chain"


async def test_report_draft_requires_id(mcp_server):
    hunt_id = await _create_hunt(mcp_server)
    with pytest.raises(Exception, match="finding_id or chain_id"):
        await mcp_server.call_tool("report_draft", {"hunt_id": hunt_id})


# -- report_format ------------------------------------------------------------


async def test_report_format(mcp_server, mcp_resources):
    hunt_id = await _create_hunt(mcp_server)
    ctx = mcp_resources.get_context()

    # Seed a finding first (FK constraint on reports.finding_id)
    finding_id = ctx.upsert_finding(
        hunt_id,
        {
            "finding_type": "sqli",
            "severity": "high",
            "title": "Test Finding",
            "url": "https://example.com/search",
            "method": "GET",
            "parameter": "q",
        },
    )

    # Seed a report referencing that finding
    report_id = ctx.upsert_report(
        hunt_id,
        {
            "finding_id": finding_id,
            "title": "Test Finding",
            "severity": "high",
            "summary": "A test finding",
            "steps": ["Step 1"],
            "impact": "High impact",
            "remediation": "Fix it",
            "status": "draft",
            "platform": "generic",
        },
    )

    with patch("boba.mcp.tools_reporting.formatter.format_markdown", return_value="# Report\nTest"):
        content, _ = await mcp_server.call_tool(
            "report_format",
            {"hunt_id": hunt_id, "report_id": report_id, "platform": "markdown"},
        )

    data = _text(content)
    assert data["platform"] == "markdown"
    assert "Report" in data["content"]


async def test_report_format_not_found(mcp_server):
    hunt_id = await _create_hunt(mcp_server)
    with pytest.raises(Exception, match="not found"):
        await mcp_server.call_tool("report_format", {"hunt_id": hunt_id, "report_id": 99999})


# -- report_poc ---------------------------------------------------------------


async def test_report_poc(mcp_server, tmp_path):
    hunt_id = await _create_hunt(mcp_server)

    @dataclass
    class FakePoC:
        finding_id: int | None = 10
        chain_id: int | None = None
        screenshots: list = field(default_factory=list)
        http_dumps: list = field(default_factory=list)
        output_dir: str = ""

    with patch("boba.mcp.tools_reporting.poc.package_poc", return_value=FakePoC()):
        content, _ = await mcp_server.call_tool(
            "report_poc",
            {"hunt_id": hunt_id, "finding_id": 10, "output_dir": str(tmp_path)},
        )

    data = _text(content)
    assert data["finding_id"] == 10


# -- report_list / report_show ------------------------------------------------


async def test_report_list_empty(mcp_server):
    hunt_id = await _create_hunt(mcp_server)
    content, _ = await mcp_server.call_tool("report_list", {"hunt_id": hunt_id})
    assert _text(content) == []


async def test_report_show_not_found(mcp_server):
    hunt_id = await _create_hunt(mcp_server)
    with pytest.raises(Exception, match="not found"):
        await mcp_server.call_tool("report_show", {"hunt_id": hunt_id, "report_id": 99999})
