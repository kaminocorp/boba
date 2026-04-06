"""Tests for MCP server lifecycle and tool listing."""

from __future__ import annotations

import pytest


pytestmark = pytest.mark.usefixtures("_patch_resources")


async def test_list_tools_returns_all_tools(mcp_server):
    """Server exposes all 65 tools."""
    tools = await mcp_server.list_tools()
    names = {t.name for t in tools}
    assert len(names) == 65
    # Spot-check each category
    assert "hunt_create" in names
    assert "recon_subdomains" in names
    assert "enum_directories" in names
    assert "scan_nuclei" in names
    assert "context_subdomains" in names
    assert "session_create" in names
    assert "http_request" in names
    assert "browser_navigate" in names
    assert "oob_create_listener" in names
    assert "test_sqli" in names
    assert "analyze_coverage" in names
    assert "report_draft" in names


async def test_tool_schemas_have_descriptions(mcp_server):
    """Every tool has a non-empty description."""
    tools = await mcp_server.list_tools()
    for tool in tools:
        assert tool.description, f"{tool.name} missing description"


async def test_hunt_create_schema_has_required_name(mcp_server):
    """hunt_create requires 'name', scope_yaml is optional."""
    tools = await mcp_server.list_tools()
    create_tool = next(t for t in tools if t.name == "hunt_create")
    schema = create_tool.inputSchema
    assert "name" in schema.get("required", [])
    assert "scope_yaml" not in schema.get("required", [])


async def test_server_name():
    """Server identifies itself as 'boba'."""
    from boba.mcp.server import mcp

    assert mcp.name == "boba"


async def test_resources_shutdown(mcp_resources):
    """shutdown() releases the HuntManager and is safe to call multiple times."""
    # Force manager creation
    mcp_resources.get_manager()
    assert mcp_resources._manager is not None

    await mcp_resources.shutdown()
    assert mcp_resources._manager is None

    # Double shutdown is safe
    await mcp_resources.shutdown()
    assert mcp_resources._manager is None
