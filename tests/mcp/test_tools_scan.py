"""Tests for MCP scan tools — mock adapter.run() to avoid real binaries."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest

from boba.core.models import ToolResult

pytestmark = pytest.mark.usefixtures("_patch_resources")


def _make_result(tool_name: str, records: list[dict]) -> ToolResult:
    return ToolResult(
        tool_name=tool_name,
        command=[tool_name],
        exit_code=0,
        raw_stdout="",
        raw_stderr="",
        duration_seconds=5.0,
        records=records,
        filtered_count=0,
    )


def _text(content_blocks) -> dict:
    return json.loads(content_blocks[0].text)


async def _create_hunt(mcp_server, name="Scan Test"):
    content, _ = await mcp_server.call_tool("hunt_create", {"name": name})
    return json.loads(content[0].text)["hunt_id"]


async def test_scan_nuclei(mcp_server):
    hunt_id = await _create_hunt(mcp_server)
    records = [
        {
            "template_id": "exposed-panels",
            "template_name": "Exposed Admin Panel",
            "severity": "medium",
            "host": "https://example.com",
            "url": "https://example.com/admin",
            "matched_at": "https://example.com/admin",
            "description": "Admin panel exposed",
            "tags": ["panel", "exposure"],
        }
    ]
    mock_run = AsyncMock(return_value=_make_result("nuclei", records))

    with patch("boba.tools.scan.NucleiAdapter.run", mock_run):
        content, _ = await mcp_server.call_tool(
            "scan_nuclei", {"hunt_id": hunt_id, "targets": ["https://example.com"]}
        )

    data = _text(content)
    assert data["summary"]["tool"] == "nuclei"
    assert data["summary"]["records_found"] == 1


async def test_scan_nuclei_with_severity_filter(mcp_server):
    hunt_id = await _create_hunt(mcp_server)
    mock_run = AsyncMock(return_value=_make_result("nuclei", []))

    with patch("boba.tools.scan.NucleiAdapter.run", mock_run):
        content, _ = await mcp_server.call_tool(
            "scan_nuclei",
            {"hunt_id": hunt_id, "targets": ["https://example.com"], "severity": "critical,high"},
        )

    data = _text(content)
    assert data["summary"]["records_found"] == 0


async def test_scan_nuclei_persists_findings(mcp_server, mcp_resources):
    hunt_id = await _create_hunt(mcp_server)
    records = [
        {
            "template_id": "cve-2021-44228",
            "template_name": "Log4Shell RCE",
            "severity": "critical",
            "host": "https://example.com",
            "url": "https://example.com/api",
            "matched_at": "https://example.com/api",
            "description": "Log4j RCE",
            "tags": ["cve", "rce"],
        }
    ]
    mock_run = AsyncMock(return_value=_make_result("nuclei", records))

    with patch("boba.tools.scan.NucleiAdapter.run", mock_run):
        await mcp_server.call_tool(
            "scan_nuclei", {"hunt_id": hunt_id, "targets": ["https://example.com"]}
        )

    findings = mcp_resources.get_context().get_findings(hunt_id)
    assert len(findings) >= 1
    assert any("Log4Shell" in f.get("title", "") for f in findings)
