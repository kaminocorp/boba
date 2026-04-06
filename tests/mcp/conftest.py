"""Shared fixtures for MCP server tests."""

from __future__ import annotations

import pytest

from boba.mcp.resources import ServerResources


@pytest.fixture
def mcp_resources(tmp_path):
    """ServerResources backed by a temporary directory."""
    res = ServerResources(data_dir=tmp_path)
    yield res
    # Synchronous cleanup — shutdown() is async but we just close the manager
    if res._manager is not None:
        res._manager.close_context()
        res._manager = None


@pytest.fixture
def _patch_resources(mcp_resources, monkeypatch):
    """Swap the module-level ``resources`` in server.py with a temp-backed one.

    Any test (or test class) that uses this fixture will have all MCP tool
    calls routed to the temporary database.
    """
    import boba.mcp.server as server_mod
    import boba.mcp.tools_analysis as analysis_mod
    import boba.mcp.tools_context as ctx_mod
    import boba.mcp.tools_enum as enum_mod
    import boba.mcp.tools_hunt as hunt_mod
    import boba.mcp.tools_interaction as interaction_mod
    import boba.mcp.tools_recon as recon_mod
    import boba.mcp.tools_reporting as reporting_mod
    import boba.mcp.tools_scan as scan_mod
    import boba.mcp.tools_vuln as vuln_mod

    for mod in (
        server_mod,
        hunt_mod,
        recon_mod,
        enum_mod,
        scan_mod,
        ctx_mod,
        interaction_mod,
        vuln_mod,
        analysis_mod,
        reporting_mod,
    ):
        monkeypatch.setattr(mod, "resources", mcp_resources)


@pytest.fixture
def mcp_server(_patch_resources):
    """The FastMCP instance with resources patched to a temp directory.

    Usage::

        async def test_something(mcp_server):
            content, _ = await mcp_server.call_tool("hunt_list", {})
    """
    from boba.mcp.server import mcp

    return mcp
