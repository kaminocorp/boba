"""Tests for MCP analysis tools."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from unittest.mock import patch

import pytest

pytestmark = pytest.mark.usefixtures("_patch_resources")


def _text(content_blocks) -> dict | list:
    return json.loads(content_blocks[0].text)


async def _create_hunt(mcp_server, name="Analysis Test"):
    content, _ = await mcp_server.call_tool("hunt_create", {"name": name})
    return json.loads(content[0].text)["hunt_id"]


# -- analyze_coverage ---------------------------------------------------------


async def test_analyze_coverage(mcp_server):
    hunt_id = await _create_hunt(mcp_server)

    @dataclass
    class FakeSummary:
        total_endpoints: int = 10
        tested_endpoints: int = 3
        untested_endpoints: int = 7
        coverage_by_test_type: dict = field(default_factory=lambda: {"sqli": 2, "xss": 1})
        gaps: list = field(default_factory=list)

    with patch("boba.mcp.tools_analysis.coverage.get_coverage_summary", return_value=FakeSummary()):
        content, _ = await mcp_server.call_tool("analyze_coverage", {"hunt_id": hunt_id})

    data = _text(content)
    assert data["total_endpoints"] == 10
    assert data["tested_endpoints"] == 3


# -- analyze_coverage_gaps ----------------------------------------------------


async def test_analyze_coverage_gaps(mcp_server):
    hunt_id = await _create_hunt(mcp_server)
    gaps = [{"url": "https://example.com/admin", "missing_tests": ["sqli", "xss"]}]

    with patch("boba.mcp.tools_analysis.coverage.get_coverage_gaps", return_value=gaps):
        content, _ = await mcp_server.call_tool("analyze_coverage_gaps", {"hunt_id": hunt_id})

    data = _text(content)
    assert len(data) == 1
    assert "sqli" in data[0]["missing_tests"]


# -- analyze_dedupe -----------------------------------------------------------


async def test_analyze_dedupe_dry_run(mcp_server):
    hunt_id = await _create_hunt(mcp_server)

    @dataclass
    class FakeGroup:
        id: int = 1
        hunt_id: str = ""
        canonical_id: int = 10
        finding_ids: list = field(default_factory=lambda: [10, 11])
        reason: str = "same URL and type"

    with patch("boba.mcp.tools_analysis.dedup.deduplicate_findings", return_value=[FakeGroup()]):
        content, _ = await mcp_server.call_tool(
            "analyze_dedupe", {"hunt_id": hunt_id, "dry_run": True}
        )

    data = _text(content)
    assert len(data) == 1
    assert data[0]["finding_ids"] == [10, 11]


# -- analyze_severity ---------------------------------------------------------


async def test_analyze_severity(mcp_server):
    hunt_id = await _create_hunt(mcp_server)
    scored = [
        {
            "finding_id": 1,
            "title": "SQLi in search",
            "cvss_score": 8.6,
            "cvss_severity": "high",
        }
    ]

    with patch("boba.mcp.tools_analysis.severity.score_findings", return_value=scored):
        content, _ = await mcp_server.call_tool(
            "analyze_severity", {"hunt_id": hunt_id, "platform": "hackerone"}
        )

    data = _text(content)
    assert len(data) == 1
    assert data[0]["cvss_score"] == 8.6


# -- analyze_chain ------------------------------------------------------------


async def test_analyze_chain(mcp_server):
    hunt_id = await _create_hunt(mcp_server)

    @dataclass
    class FakeChain:
        id: int = 1
        hunt_id: str = ""
        title: str = "XSS + CSRF → ATO"
        description: str = "Chain leads to account takeover"
        severity: str = "critical"
        confidence: str = "validated"
        cvss_score: float = 9.8
        cvss_vector: str = ""
        finding_ids: list = field(default_factory=lambda: [1, 2])
        chain_order: list = field(default_factory=lambda: [1, 2])
        impact: str = "Account takeover"
        prerequisites: list = field(default_factory=list)
        tags: list = field(default_factory=list)

    with patch("boba.mcp.tools_analysis.chaining.detect_chains", return_value=[FakeChain()]):
        content, _ = await mcp_server.call_tool("analyze_chain", {"hunt_id": hunt_id})

    data = _text(content)
    assert len(data) == 1
    assert data[0]["title"] == "XSS + CSRF → ATO"


# -- analyze_prioritize -------------------------------------------------------


async def test_analyze_prioritize(mcp_server):
    hunt_id = await _create_hunt(mcp_server)
    endpoints = [
        {
            "url": "https://example.com/api/user",
            "priority_score": 0.95,
            "suggested_tests": ["idor"],
        },
        {"url": "https://example.com/search", "priority_score": 0.8, "suggested_tests": ["sqli"]},
    ]

    with patch("boba.mcp.tools_analysis.prioritize.prioritize_endpoints", return_value=endpoints):
        content, _ = await mcp_server.call_tool(
            "analyze_prioritize", {"hunt_id": hunt_id, "top": 5}
        )

    data = _text(content)
    assert len(data) == 2
    assert data[0]["priority_score"] == 0.95


# -- error cases --------------------------------------------------------------


async def test_analysis_invalid_hunt(mcp_server):
    with pytest.raises(Exception):
        await mcp_server.call_tool("analyze_coverage", {"hunt_id": "nonexistent00"})
