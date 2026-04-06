"""MCP tools for enumeration — directory fuzzing and web crawling."""

from __future__ import annotations

from typing import Annotated

from boba.core.models import AdapterConfig
from boba.mcp.serializers import serialize_tool_result
from boba.mcp.server import mcp, resources
from boba.tools import enum


@mcp.tool(description="Fuzz for directories and files using ffuf")
async def enum_directories(
    hunt_id: Annotated[str, "Hunt ID"],
    url: Annotated[str, "Target URL to fuzz (FUZZ keyword appended if missing)"],
    wordlist: Annotated[str | None, "Path to wordlist file"] = None,
    match_codes: Annotated[str, "HTTP status codes to match (comma-separated)"] = "200,301,302,403",
    extensions: Annotated[
        list[str] | None, "File extensions to append (e.g. ['php', 'txt'])"
    ] = None,
    timeout_seconds: Annotated[int, "Timeout in seconds"] = 300,
) -> str:
    ctx = resources.get_context()
    hunt = resources.get_hunt(hunt_id)
    config = AdapterConfig(timeout_seconds=timeout_seconds)
    result = await enum.directories(
        ctx,
        hunt,
        url=url,
        wordlist=wordlist,
        match_codes=match_codes,
        extensions=extensions,
        config=config,
    )
    return serialize_tool_result(result)


@mcp.tool(description="Crawl web applications using katana (defaults to alive hosts)")
async def enum_crawl(
    hunt_id: Annotated[str, "Hunt ID"],
    targets: Annotated[list[str] | None, "URLs to crawl (omit to use alive hosts)"] = None,
    depth: Annotated[int, "Crawl depth"] = 3,
    timeout_seconds: Annotated[int, "Timeout in seconds"] = 300,
) -> str:
    ctx = resources.get_context()
    hunt = resources.get_hunt(hunt_id)
    config = AdapterConfig(timeout_seconds=timeout_seconds)
    result = await enum.crawl(ctx, hunt, targets=targets, depth=depth, config=config)
    return serialize_tool_result(result)
