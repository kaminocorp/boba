"""Tests for MCP enum tools — mock adapter.run() to avoid real binaries."""

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
        duration_seconds=2.0,
        records=records,
        filtered_count=0,
    )


def _text(content_blocks) -> dict:
    return json.loads(content_blocks[0].text)


async def _create_hunt(mcp_server, name="Enum Test"):
    content, _ = await mcp_server.call_tool("hunt_create", {"name": name})
    return json.loads(content[0].text)["hunt_id"]


# -- enum_directories ---------------------------------------------------------


async def test_enum_directories(mcp_server):
    hunt_id = await _create_hunt(mcp_server)
    records = [
        {"url": "https://example.com/admin", "status_code": 200, "content_length": 500},
        {"url": "https://example.com/backup", "status_code": 403, "content_length": 0},
    ]
    mock_run = AsyncMock(return_value=_make_result("ffuf", records))

    with patch("boba.tools.enum.FfufAdapter.run", mock_run):
        content, _ = await mcp_server.call_tool(
            "enum_directories", {"hunt_id": hunt_id, "url": "https://example.com"}
        )

    data = _text(content)
    assert data["summary"]["tool"] == "ffuf"
    assert data["summary"]["records_found"] == 2


async def test_enum_directories_with_extensions(mcp_server):
    hunt_id = await _create_hunt(mcp_server)
    records = [{"url": "https://example.com/config.php", "status_code": 200, "content_length": 0}]
    mock_run = AsyncMock(return_value=_make_result("ffuf", records))

    with patch("boba.tools.enum.FfufAdapter.run", mock_run):
        content, _ = await mcp_server.call_tool(
            "enum_directories",
            {"hunt_id": hunt_id, "url": "https://example.com", "extensions": ["php", "txt"]},
        )

    data = _text(content)
    assert data["summary"]["records_found"] == 1


# -- enum_crawl ---------------------------------------------------------------


async def test_enum_crawl(mcp_server):
    hunt_id = await _create_hunt(mcp_server)
    records = [
        {"url": "https://example.com/page1", "source": "katana"},
        {"url": "https://example.com/page2", "source": "katana"},
    ]
    mock_run = AsyncMock(return_value=_make_result("katana", records))

    with patch("boba.tools.enum.KatanaAdapter.run", mock_run):
        content, _ = await mcp_server.call_tool(
            "enum_crawl", {"hunt_id": hunt_id, "targets": ["https://example.com"], "depth": 2}
        )

    data = _text(content)
    assert data["summary"]["tool"] == "katana"
    assert data["summary"]["records_found"] == 2


async def test_enum_crawl_persists_urls(mcp_server, mcp_resources):
    hunt_id = await _create_hunt(mcp_server)
    records = [{"url": "https://example.com/found", "source": "katana"}]
    mock_run = AsyncMock(return_value=_make_result("katana", records))

    with patch("boba.tools.enum.KatanaAdapter.run", mock_run):
        await mcp_server.call_tool(
            "enum_crawl", {"hunt_id": hunt_id, "targets": ["https://example.com"]}
        )

    saved = mcp_resources.get_context().get_urls(hunt_id)
    assert any(u["url"] == "https://example.com/found" for u in saved)
