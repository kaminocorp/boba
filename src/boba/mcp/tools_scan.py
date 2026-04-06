"""MCP tools for scanning — Nuclei vulnerability scanning."""

from __future__ import annotations

from typing import Annotated

from boba.core.models import AdapterConfig
from boba.mcp.serializers import serialize_tool_result
from boba.mcp.server import mcp, resources
from boba.tools import scan


@mcp.tool(description="Run Nuclei vulnerability scanner against targets (defaults to alive hosts)")
async def scan_nuclei(
    hunt_id: Annotated[str, "Hunt ID"],
    targets: Annotated[list[str] | None, "URLs to scan (omit to use alive hosts)"] = None,
    severity: Annotated[str | None, "Filter by severity (e.g. 'critical,high')"] = None,
    tags: Annotated[str | None, "Filter by template tags (e.g. 'cve,misconfig')"] = None,
    templates: Annotated[str | None, "Path to custom templates directory or file"] = None,
    timeout_seconds: Annotated[int, "Timeout in seconds"] = 300,
) -> str:
    ctx = resources.get_context()
    hunt = resources.get_hunt(hunt_id)
    config = AdapterConfig(timeout_seconds=timeout_seconds)
    result = await scan.nuclei_scan(
        ctx,
        hunt,
        targets=targets,
        severity=severity,
        tags=tags,
        templates=templates,
        config=config,
    )
    return serialize_tool_result(result)
