"""Tests for MCP context query tools — seed DB, then query via MCP."""

from __future__ import annotations

import json

import pytest

pytestmark = pytest.mark.usefixtures("_patch_resources")


def _text(content_blocks) -> list | dict:
    return json.loads(content_blocks[0].text)


async def _create_hunt(mcp_server, name="Context Test"):
    content, _ = await mcp_server.call_tool("hunt_create", {"name": name})
    return json.loads(content[0].text)["hunt_id"]


def _seed_subdomains(ctx, hunt_id):
    ctx.upsert_records(
        hunt_id,
        "subdomain",
        [
            {"subdomain": "api.example.com", "source": "subfinder"},
            {"subdomain": "mail.example.com", "source": "subfinder"},
        ],
        source="subfinder",
    )


def _seed_hosts(ctx, hunt_id):
    ctx.upsert_records(
        hunt_id,
        "host",
        [
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
            },
            {
                "host": "dead.example.com",
                "ip": None,
                "port": None,
                "scheme": None,
                "url": None,
                "status_code": 0,
            },
        ],
        source="httpx",
    )


def _seed_ports(ctx, hunt_id):
    ctx.upsert_records(
        hunt_id,
        "port",
        [
            {"host": "api.example.com", "ip": "1.2.3.4", "port": 443, "protocol": "tcp"},
            {"host": "api.example.com", "ip": "1.2.3.4", "port": 8080, "protocol": "tcp"},
        ],
        source="naabu",
    )


def _seed_urls(ctx, hunt_id):
    ctx.upsert_records(
        hunt_id,
        "url",
        [
            {"url": "https://example.com/login", "host": "example.com", "source": "gau"},
            {"url": "https://example.com/admin", "host": "example.com", "source": "waybackurls"},
        ],
        source="gau",
    )


def _seed_technologies(ctx, hunt_id):
    ctx.upsert_records(
        hunt_id,
        "technology",
        [
            {
                "name": "nginx",
                "category": "Web servers",
                "version": "1.21",
                "host": "api.example.com",
                "confidence": 100,
                "source": "whatweb",
            },
        ],
        source="whatweb",
    )


def _seed_directories(ctx, hunt_id):
    ctx.upsert_records(
        hunt_id,
        "directory",
        [
            {
                "url": "https://example.com/admin",
                "status_code": 200,
                "content_length": 500,
                "content_type": "text/html",
                "source": "ffuf",
            },
            {
                "url": "https://example.com/backup",
                "status_code": 403,
                "content_length": 0,
                "source": "ffuf",
            },
        ],
        source="ffuf",
    )


# -- context_subdomains -------------------------------------------------------


async def test_context_subdomains(mcp_server, mcp_resources):
    hunt_id = await _create_hunt(mcp_server)
    _seed_subdomains(mcp_resources.get_context(), hunt_id)

    content, _ = await mcp_server.call_tool("context_subdomains", {"hunt_id": hunt_id})
    data = _text(content)
    assert len(data) == 2
    names = {s["subdomain"] for s in data}
    assert "api.example.com" in names


async def test_context_subdomains_empty(mcp_server):
    hunt_id = await _create_hunt(mcp_server)
    content, _ = await mcp_server.call_tool("context_subdomains", {"hunt_id": hunt_id})
    assert _text(content) == []


# -- context_hosts ------------------------------------------------------------


async def test_context_hosts_all(mcp_server, mcp_resources):
    hunt_id = await _create_hunt(mcp_server)
    _seed_hosts(mcp_resources.get_context(), hunt_id)

    content, _ = await mcp_server.call_tool("context_hosts", {"hunt_id": hunt_id})
    data = _text(content)
    assert len(data) == 2


async def test_context_hosts_alive_only(mcp_server, mcp_resources):
    hunt_id = await _create_hunt(mcp_server)
    _seed_hosts(mcp_resources.get_context(), hunt_id)

    content, _ = await mcp_server.call_tool(
        "context_hosts", {"hunt_id": hunt_id, "alive_only": True}
    )
    data = _text(content)
    assert len(data) == 1
    assert data[0]["host"] == "api.example.com"


# -- context_ports ------------------------------------------------------------


async def test_context_ports(mcp_server, mcp_resources):
    hunt_id = await _create_hunt(mcp_server)
    _seed_ports(mcp_resources.get_context(), hunt_id)

    content, _ = await mcp_server.call_tool("context_ports", {"hunt_id": hunt_id})
    data = _text(content)
    assert len(data) == 2


async def test_context_ports_filtered_by_host(mcp_server, mcp_resources):
    hunt_id = await _create_hunt(mcp_server)
    _seed_ports(mcp_resources.get_context(), hunt_id)

    content, _ = await mcp_server.call_tool(
        "context_ports", {"hunt_id": hunt_id, "host": "api.example.com"}
    )
    data = _text(content)
    assert len(data) == 2  # both ports belong to api.example.com


# -- context_urls -------------------------------------------------------------


async def test_context_urls(mcp_server, mcp_resources):
    hunt_id = await _create_hunt(mcp_server)
    _seed_urls(mcp_resources.get_context(), hunt_id)

    content, _ = await mcp_server.call_tool("context_urls", {"hunt_id": hunt_id})
    data = _text(content)
    assert len(data) == 2


# -- context_tech -------------------------------------------------------------


async def test_context_tech(mcp_server, mcp_resources):
    hunt_id = await _create_hunt(mcp_server)
    _seed_technologies(mcp_resources.get_context(), hunt_id)

    content, _ = await mcp_server.call_tool("context_tech", {"hunt_id": hunt_id})
    data = _text(content)
    assert len(data) == 1
    assert data[0]["name"] == "nginx"


# -- context_directories ------------------------------------------------------


async def test_context_directories(mcp_server, mcp_resources):
    hunt_id = await _create_hunt(mcp_server)
    _seed_directories(mcp_resources.get_context(), hunt_id)

    content, _ = await mcp_server.call_tool("context_directories", {"hunt_id": hunt_id})
    data = _text(content)
    assert len(data) == 2


async def test_context_directories_with_prefix(mcp_server, mcp_resources):
    hunt_id = await _create_hunt(mcp_server)
    _seed_directories(mcp_resources.get_context(), hunt_id)

    content, _ = await mcp_server.call_tool(
        "context_directories", {"hunt_id": hunt_id, "url_prefix": "https://example.com/admin"}
    )
    data = _text(content)
    assert len(data) == 1
    assert data[0]["url"] == "https://example.com/admin"


# -- context_findings ---------------------------------------------------------


async def test_context_findings_empty(mcp_server):
    hunt_id = await _create_hunt(mcp_server)
    content, _ = await mcp_server.call_tool("context_findings", {"hunt_id": hunt_id})
    assert _text(content) == []


# -- context_sessions ---------------------------------------------------------


async def test_context_sessions_empty(mcp_server):
    hunt_id = await _create_hunt(mcp_server)
    content, _ = await mcp_server.call_tool("context_sessions", {"hunt_id": hunt_id})
    assert _text(content) == []


# -- context_http_history -----------------------------------------------------


async def test_context_http_history_empty(mcp_server):
    hunt_id = await _create_hunt(mcp_server)
    content, _ = await mcp_server.call_tool("context_http_history", {"hunt_id": hunt_id})
    assert _text(content) == []


# -- context_tool_runs --------------------------------------------------------


async def test_context_tool_runs_empty(mcp_server):
    hunt_id = await _create_hunt(mcp_server)
    content, _ = await mcp_server.call_tool("context_tool_runs", {"hunt_id": hunt_id})
    assert _text(content) == []


# -- context_stats ------------------------------------------------------------


async def test_context_stats(mcp_server, mcp_resources):
    hunt_id = await _create_hunt(mcp_server)
    _seed_subdomains(mcp_resources.get_context(), hunt_id)
    _seed_hosts(mcp_resources.get_context(), hunt_id)

    content, _ = await mcp_server.call_tool("context_stats", {"hunt_id": hunt_id})
    data = _text(content)
    assert data["subdomains"] == 2
    assert data["hosts"] == 2
    assert data["hosts_alive"] == 1


async def test_context_stats_invalid_hunt(mcp_server):
    with pytest.raises(Exception):
        await mcp_server.call_tool("context_stats", {"hunt_id": "nonexistent00"})
