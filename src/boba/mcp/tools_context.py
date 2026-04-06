"""MCP tools for querying persisted data — read-only context queries."""

from __future__ import annotations

from typing import Annotated

from boba.mcp.serializers import serialize_result
from boba.mcp.server import mcp, resources


@mcp.tool(description="List all discovered subdomains for a hunt")
async def context_subdomains(
    hunt_id: Annotated[str, "Hunt ID"],
) -> str:
    ctx = resources.get_context()
    return serialize_result(ctx.get_subdomains(hunt_id))


@mcp.tool(description="List discovered hosts (optionally only alive ones)")
async def context_hosts(
    hunt_id: Annotated[str, "Hunt ID"],
    alive_only: Annotated[bool, "Only return hosts with a live HTTP response"] = False,
) -> str:
    ctx = resources.get_context()
    return serialize_result(ctx.get_hosts(hunt_id, alive_only=alive_only))


@mcp.tool(description="List discovered open ports (optionally filter by host)")
async def context_ports(
    hunt_id: Annotated[str, "Hunt ID"],
    host: Annotated[str | None, "Filter by specific host"] = None,
) -> str:
    ctx = resources.get_context()
    return serialize_result(ctx.get_ports(hunt_id, host=host))


@mcp.tool(description="List discovered URLs (optionally filter by host)")
async def context_urls(
    hunt_id: Annotated[str, "Hunt ID"],
    host: Annotated[str | None, "Filter by specific host"] = None,
) -> str:
    ctx = resources.get_context()
    return serialize_result(ctx.get_urls(hunt_id, host=host))


@mcp.tool(description="List detected technologies (optionally filter by host)")
async def context_tech(
    hunt_id: Annotated[str, "Hunt ID"],
    host: Annotated[str | None, "Filter by specific host"] = None,
) -> str:
    ctx = resources.get_context()
    return serialize_result(ctx.get_technologies(hunt_id, host=host))


@mcp.tool(description="List discovered directories (optionally filter by URL prefix)")
async def context_directories(
    hunt_id: Annotated[str, "Hunt ID"],
    url_prefix: Annotated[str | None, "Filter by URL prefix"] = None,
) -> str:
    ctx = resources.get_context()
    return serialize_result(ctx.get_directories(hunt_id, url_prefix=url_prefix))


@mcp.tool(description="List vulnerability findings (optionally filter by type or severity)")
async def context_findings(
    hunt_id: Annotated[str, "Hunt ID"],
    finding_type: Annotated[str | None, "Filter by finding type (e.g. 'sqli', 'xss')"] = None,
    severity: Annotated[str | None, "Filter by severity (e.g. 'critical', 'high')"] = None,
) -> str:
    ctx = resources.get_context()
    return serialize_result(ctx.get_findings(hunt_id, finding_type=finding_type, severity=severity))


@mcp.tool(description="List authentication sessions for a hunt")
async def context_sessions(
    hunt_id: Annotated[str, "Hunt ID"],
) -> str:
    ctx = resources.get_context()
    return serialize_result(ctx.get_sessions(hunt_id))


@mcp.tool(description="Query HTTP request/response history")
async def context_http_history(
    hunt_id: Annotated[str, "Hunt ID"],
    host: Annotated[str | None, "Filter by host"] = None,
    method: Annotated[str | None, "Filter by HTTP method (GET, POST, etc.)"] = None,
    status_code: Annotated[int | None, "Filter by response status code"] = None,
    limit: Annotated[int, "Maximum number of records to return"] = 100,
) -> str:
    ctx = resources.get_context()
    return serialize_result(
        ctx.query_http_history(
            hunt_id, host=host, method=method, status_code=status_code, limit=limit
        )
    )


@mcp.tool(description="List tool execution history for a hunt")
async def context_tool_runs(
    hunt_id: Annotated[str, "Hunt ID"],
) -> str:
    ctx = resources.get_context()
    return serialize_result(ctx.get_tool_runs(hunt_id))


@mcp.tool(description="Get aggregate discovery statistics for a hunt")
async def context_stats(
    hunt_id: Annotated[str, "Hunt ID"],
) -> str:
    resources.get_hunt(hunt_id)  # validate hunt exists
    ctx = resources.get_context()
    return serialize_result(ctx.get_hunt_stats(hunt_id))
