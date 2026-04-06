"""Tests for MCP recon tools — mock adapter.run() to avoid real binaries."""

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
        duration_seconds=1.5,
        records=records,
        filtered_count=0,
    )


def _text(content_blocks) -> dict:
    return json.loads(content_blocks[0].text)


# -- helpers to create a hunt via MCP -----------------------------------------


async def _create_hunt(mcp_server, name="Test Hunt"):
    content, _ = await mcp_server.call_tool("hunt_create", {"name": name})
    return json.loads(content[0].text)["hunt_id"]


# -- recon_subdomains ---------------------------------------------------------


async def test_recon_subdomains(mcp_server):
    hunt_id = await _create_hunt(mcp_server)
    records = [
        {"subdomain": "api.example.com", "source": "subfinder"},
        {"subdomain": "mail.example.com", "source": "subfinder"},
    ]
    mock_run = AsyncMock(return_value=_make_result("subfinder", records))

    with patch("boba.tools.recon.SubfinderAdapter.run", mock_run):
        content, _ = await mcp_server.call_tool(
            "recon_subdomains", {"hunt_id": hunt_id, "domains": ["example.com"]}
        )

    data = _text(content)
    assert data["summary"]["tool"] == "subfinder"
    assert data["summary"]["records_found"] == 2
    assert len(data["records"]) == 2


async def test_recon_subdomains_persists_to_context(mcp_server, mcp_resources):
    hunt_id = await _create_hunt(mcp_server)
    records = [{"subdomain": "new.example.com", "source": "subfinder"}]
    mock_run = AsyncMock(return_value=_make_result("subfinder", records))

    with patch("boba.tools.recon.SubfinderAdapter.run", mock_run):
        await mcp_server.call_tool(
            "recon_subdomains", {"hunt_id": hunt_id, "domains": ["example.com"]}
        )

    saved = mcp_resources.get_context().get_subdomains(hunt_id)
    assert any(s["subdomain"] == "new.example.com" for s in saved)


async def test_recon_subdomains_empty_domains(mcp_server):
    hunt_id = await _create_hunt(mcp_server)
    content, _ = await mcp_server.call_tool("recon_subdomains", {"hunt_id": hunt_id, "domains": []})
    data = _text(content)
    assert data["summary"]["records_found"] == 0


# -- recon_hosts --------------------------------------------------------------


async def test_recon_hosts(mcp_server):
    hunt_id = await _create_hunt(mcp_server)
    records = [
        {
            "host": "api.example.com",
            "ip": "1.2.3.4",
            "port": 443,
            "scheme": "https",
            "url": "https://api.example.com",
            "status_code": 200,
            "title": "API",
            "webserver": "nginx",
            "content_length": 100,
            "content_type": "text/html",
        }
    ]
    mock_run = AsyncMock(return_value=_make_result("httpx", records))

    with patch("boba.tools.recon.HttpxRunnerAdapter.run", mock_run):
        content, _ = await mcp_server.call_tool(
            "recon_hosts", {"hunt_id": hunt_id, "targets": ["api.example.com"]}
        )

    data = _text(content)
    assert data["summary"]["tool"] == "httpx"
    assert data["summary"]["records_found"] == 1


# -- recon_ports --------------------------------------------------------------


async def test_recon_ports(mcp_server):
    hunt_id = await _create_hunt(mcp_server)
    records = [{"host": "api.example.com", "ip": "1.2.3.4", "port": 443, "protocol": "tcp"}]
    mock_run = AsyncMock(return_value=_make_result("naabu", records))

    with patch("boba.tools.recon.NaabuAdapter.run", mock_run):
        content, _ = await mcp_server.call_tool(
            "recon_ports", {"hunt_id": hunt_id, "targets": ["api.example.com"]}
        )

    data = _text(content)
    assert data["summary"]["tool"] == "naabu"
    assert data["summary"]["records_found"] == 1


async def test_recon_ports_with_port_range(mcp_server):
    hunt_id = await _create_hunt(mcp_server)
    records = [{"host": "api.example.com", "ip": "1.2.3.4", "port": 8080, "protocol": "tcp"}]
    mock_run = AsyncMock(return_value=_make_result("naabu", records))

    with patch("boba.tools.recon.NaabuAdapter.run", mock_run):
        content, _ = await mcp_server.call_tool(
            "recon_ports",
            {"hunt_id": hunt_id, "targets": ["api.example.com"], "port_range": "8080-8090"},
        )

    data = _text(content)
    assert data["summary"]["records_found"] == 1


# -- recon_urls ---------------------------------------------------------------


async def test_recon_urls(mcp_server):
    hunt_id = await _create_hunt(mcp_server)
    records = [
        {"url": "https://example.com/login", "source": "gau"},
        {"url": "https://example.com/api/v1", "source": "waybackurls"},
    ]
    # urls() runs two adapters in parallel — mock both
    mock_gau = AsyncMock(return_value=_make_result("gau", records[:1]))
    mock_wb = AsyncMock(return_value=_make_result("waybackurls", records[1:]))

    with (
        patch("boba.tools.recon.GauAdapter.run", mock_gau),
        patch("boba.tools.recon.WaybackurlsAdapter.run", mock_wb),
    ):
        content, _ = await mcp_server.call_tool(
            "recon_urls", {"hunt_id": hunt_id, "domains": ["example.com"]}
        )

    data = _text(content)
    assert data["summary"]["records_found"] == 2


# -- recon_tech ---------------------------------------------------------------


async def test_recon_tech(mcp_server):
    hunt_id = await _create_hunt(mcp_server)
    records = [
        {
            "host": "https://example.com",
            "technologies": [
                {"name": "nginx", "category": "Web servers", "version": "1.21"},
            ],
        }
    ]
    mock_run = AsyncMock(return_value=_make_result("whatweb", records))

    with patch("boba.tools.recon.WhatwebAdapter.run", mock_run):
        content, _ = await mcp_server.call_tool(
            "recon_tech", {"hunt_id": hunt_id, "targets": ["https://example.com"]}
        )

    data = _text(content)
    assert data["summary"]["tool"] == "whatweb"


# -- error cases --------------------------------------------------------------


async def test_recon_invalid_hunt_id(mcp_server):
    with pytest.raises(Exception, match="[Nn]ot found|[Nn]o hunt"):
        await mcp_server.call_tool(
            "recon_subdomains", {"hunt_id": "bad_id_000000", "domains": ["example.com"]}
        )
