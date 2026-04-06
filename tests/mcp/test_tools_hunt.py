"""Tests for MCP hunt management tools."""

from __future__ import annotations

import json

import pytest


pytestmark = pytest.mark.usefixtures("_patch_resources")


# -- helpers ------------------------------------------------------------------


def _text(content_blocks) -> dict:
    """Extract and parse the JSON text from an MCP tool response."""
    return json.loads(content_blocks[0].text)


# -- hunt_create --------------------------------------------------------------


async def test_create_hunt(mcp_server):
    content, _ = await mcp_server.call_tool("hunt_create", {"name": "Acme Corp"})
    data = _text(content)
    assert data["name"] == "Acme Corp"
    assert data["status"] == "active"
    assert len(data["hunt_id"]) == 12
    assert data["scope_rules"] == 0


async def test_create_hunt_with_scope_yaml(mcp_server, tmp_path):
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text(
        "rules:\n"
        "  - pattern: '*.example.com'\n"
        "    type: domain\n"
        "    action: include\n"
        "  - pattern: 'internal.example.com'\n"
        "    type: domain\n"
        "    action: exclude\n"
    )
    content, _ = await mcp_server.call_tool(
        "hunt_create", {"name": "Scoped Hunt", "scope_yaml": str(scope_file)}
    )
    data = _text(content)
    assert data["scope_rules"] == 2


# -- hunt_list ----------------------------------------------------------------


async def test_list_empty(mcp_server):
    content, _ = await mcp_server.call_tool("hunt_list", {})
    data = _text(content)
    assert data == []


async def test_list_after_create(mcp_server):
    await mcp_server.call_tool("hunt_create", {"name": "Hunt A"})
    await mcp_server.call_tool("hunt_create", {"name": "Hunt B"})
    content, _ = await mcp_server.call_tool("hunt_list", {})
    data = _text(content)
    assert len(data) == 2
    names = {h["name"] for h in data}
    assert names == {"Hunt A", "Hunt B"}


# -- hunt_status --------------------------------------------------------------


async def test_status_returns_stats(mcp_server):
    create_content, _ = await mcp_server.call_tool("hunt_create", {"name": "Stats Hunt"})
    hunt_id = _text(create_content)["hunt_id"]

    content, _ = await mcp_server.call_tool("hunt_status", {"hunt_id": hunt_id})
    data = _text(content)
    assert data["hunt_id"] == hunt_id
    assert data["name"] == "Stats Hunt"
    assert data["status"] == "active"
    assert "stats" in data
    assert data["stats"]["subdomains"] == 0


async def test_status_invalid_hunt_id(mcp_server):
    with pytest.raises(Exception, match="[Nn]ot found|[Nn]o hunt"):
        await mcp_server.call_tool("hunt_status", {"hunt_id": "bad_id_000000"})


# -- hunt_pause / resume / close ----------------------------------------------


async def test_pause_and_resume(mcp_server):
    create_content, _ = await mcp_server.call_tool("hunt_create", {"name": "Lifecycle"})
    hunt_id = _text(create_content)["hunt_id"]

    # Pause
    content, _ = await mcp_server.call_tool("hunt_pause", {"hunt_id": hunt_id})
    assert _text(content)["status"] == "paused"

    # Resume
    content, _ = await mcp_server.call_tool("hunt_resume", {"hunt_id": hunt_id})
    assert _text(content)["status"] == "active"


async def test_close_hunt(mcp_server):
    create_content, _ = await mcp_server.call_tool("hunt_create", {"name": "To Close"})
    hunt_id = _text(create_content)["hunt_id"]

    content, _ = await mcp_server.call_tool("hunt_close", {"hunt_id": hunt_id})
    assert _text(content)["status"] == "completed"


async def test_close_is_terminal(mcp_server):
    """Cannot pause or resume a completed hunt."""
    create_content, _ = await mcp_server.call_tool("hunt_create", {"name": "Terminal"})
    hunt_id = _text(create_content)["hunt_id"]
    await mcp_server.call_tool("hunt_close", {"hunt_id": hunt_id})

    with pytest.raises(Exception):
        await mcp_server.call_tool("hunt_pause", {"hunt_id": hunt_id})

    with pytest.raises(Exception):
        await mcp_server.call_tool("hunt_resume", {"hunt_id": hunt_id})


async def test_pause_invalid_hunt(mcp_server):
    with pytest.raises(Exception):
        await mcp_server.call_tool("hunt_pause", {"hunt_id": "nonexistent00"})


async def test_resume_active_hunt_raises(mcp_server):
    """Resuming an already active hunt is an invalid transition."""
    create_content, _ = await mcp_server.call_tool("hunt_create", {"name": "Active"})
    hunt_id = _text(create_content)["hunt_id"]

    with pytest.raises(Exception):
        await mcp_server.call_tool("hunt_resume", {"hunt_id": hunt_id})


# -- round-trip persistence ---------------------------------------------------


async def test_hunt_persists_across_calls(mcp_server):
    """Create via MCP, verify via status — proves SQLite persistence works."""
    create_content, _ = await mcp_server.call_tool("hunt_create", {"name": "Persist Test"})
    hunt_id = _text(create_content)["hunt_id"]

    status_content, _ = await mcp_server.call_tool("hunt_status", {"hunt_id": hunt_id})
    data = _text(status_content)
    assert data["name"] == "Persist Test"
    assert data["hunt_id"] == hunt_id
