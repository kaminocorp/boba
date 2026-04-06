"""MCP tools for reconnaissance — subdomain, host, port, URL, and tech discovery."""

from __future__ import annotations

from typing import Annotated

from boba.core.models import AdapterConfig
from boba.mcp.serializers import serialize_tool_result
from boba.mcp.server import mcp, resources
from boba.tools import recon


@mcp.tool(description="Discover subdomains for target domains using subfinder")
async def recon_subdomains(
    hunt_id: Annotated[str, "Hunt ID"],
    domains: Annotated[list[str], "Target domains to enumerate subdomains for"],
    timeout_seconds: Annotated[int, "Timeout in seconds"] = 300,
) -> str:
    ctx = resources.get_context()
    hunt = resources.get_hunt(hunt_id)
    config = AdapterConfig(timeout_seconds=timeout_seconds)
    result = await recon.subdomains(ctx, hunt, domains, config=config)
    return serialize_tool_result(result)


@mcp.tool(description="Check which hosts are alive using httpx (defaults to all known subdomains)")
async def recon_hosts(
    hunt_id: Annotated[str, "Hunt ID"],
    targets: Annotated[
        list[str] | None, "Specific targets to probe (omit to use all subdomains)"
    ] = None,
    timeout_seconds: Annotated[int, "Timeout in seconds"] = 300,
) -> str:
    ctx = resources.get_context()
    hunt = resources.get_hunt(hunt_id)
    config = AdapterConfig(timeout_seconds=timeout_seconds)
    result = await recon.hosts(ctx, hunt, targets=targets, config=config)
    return serialize_tool_result(result)


@mcp.tool(description="Port scan live hosts using naabu (defaults to all alive hosts)")
async def recon_ports(
    hunt_id: Annotated[str, "Hunt ID"],
    targets: Annotated[list[str] | None, "Specific hosts to scan (omit to use alive hosts)"] = None,
    port_range: Annotated[str | None, "Port range to scan (e.g. '80,443,8080' or '1-1000')"] = None,
    timeout_seconds: Annotated[int, "Timeout in seconds"] = 300,
) -> str:
    ctx = resources.get_context()
    hunt = resources.get_hunt(hunt_id)
    config = AdapterConfig(timeout_seconds=timeout_seconds)
    result = await recon.ports(ctx, hunt, targets=targets, port_range=port_range, config=config)
    return serialize_tool_result(result)


@mcp.tool(description="Discover historical URLs using gau and waybackurls")
async def recon_urls(
    hunt_id: Annotated[str, "Hunt ID"],
    domains: Annotated[list[str], "Target domains to discover URLs for"],
    timeout_seconds: Annotated[int, "Timeout in seconds"] = 300,
) -> str:
    ctx = resources.get_context()
    hunt = resources.get_hunt(hunt_id)
    config = AdapterConfig(timeout_seconds=timeout_seconds)
    result = await recon.urls(ctx, hunt, domains, config=config)
    return serialize_tool_result(result)


@mcp.tool(description="Fingerprint technology stacks on live hosts using whatweb")
async def recon_tech(
    hunt_id: Annotated[str, "Hunt ID"],
    targets: Annotated[
        list[str] | None, "Specific URLs to fingerprint (omit to use alive hosts)"
    ] = None,
    timeout_seconds: Annotated[int, "Timeout in seconds"] = 300,
) -> str:
    ctx = resources.get_context()
    hunt = resources.get_hunt(hunt_id)
    config = AdapterConfig(timeout_seconds=timeout_seconds)
    result = await recon.tech(ctx, hunt, targets=targets, config=config)
    return serialize_tool_result(result)
