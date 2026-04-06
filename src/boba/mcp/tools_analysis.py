"""MCP tools for analysis — coverage, dedup, severity, chaining, prioritization."""

from __future__ import annotations

from typing import Annotated

from boba.analysis import chaining, coverage, dedup, prioritize, severity
from boba.mcp.serializers import serialize_result
from boba.mcp.server import mcp, resources


@mcp.tool(description="Get coverage summary showing tested vs untested endpoints")
async def analyze_coverage(
    hunt_id: Annotated[str, "Hunt ID"],
    host: Annotated[str | None, "Filter by specific host"] = None,
    test_types: Annotated[list[str] | None, "Filter by test types (e.g. ['sqli', 'xss'])"] = None,
) -> str:
    resources.get_hunt(hunt_id)
    ctx = resources.get_context()
    result = coverage.get_coverage_summary(ctx, hunt_id, host=host, test_types=test_types)
    return serialize_result(result)


@mcp.tool(description="Identify untested endpoints and missing test coverage")
async def analyze_coverage_gaps(
    hunt_id: Annotated[str, "Hunt ID"],
    test_types: Annotated[list[str] | None, "Test types to check (e.g. ['sqli', 'xss'])"] = None,
    host: Annotated[str | None, "Filter by specific host"] = None,
) -> str:
    resources.get_hunt(hunt_id)
    ctx = resources.get_context()
    result = coverage.get_coverage_gaps(ctx, hunt_id, test_types=test_types, host=host)
    return serialize_result(result)


@mcp.tool(description="Deduplicate findings (dry_run=true to preview without changes)")
async def analyze_dedupe(
    hunt_id: Annotated[str, "Hunt ID"],
    dry_run: Annotated[bool, "Preview dedup groups without persisting"] = False,
) -> str:
    resources.get_hunt(hunt_id)
    ctx = resources.get_context()
    groups = dedup.deduplicate_findings(ctx, hunt_id, dry_run=dry_run)
    return serialize_result(groups)


@mcp.tool(description="Score findings with CVSS and estimate bounty payouts")
async def analyze_severity(
    hunt_id: Annotated[str, "Hunt ID"],
    finding_ids: Annotated[list[int] | None, "Specific finding IDs to score (omit for all)"] = None,
    platform: Annotated[str | None, "Platform for payout estimates: hackerone, bugcrowd"] = None,
) -> str:
    resources.get_hunt(hunt_id)
    ctx = resources.get_context()
    result = severity.score_findings(ctx, hunt_id, finding_ids=finding_ids, platform=platform)
    return serialize_result(result)


@mcp.tool(description="Detect attack chains — combinations of findings that escalate severity")
async def analyze_chain(
    hunt_id: Annotated[str, "Hunt ID"],
) -> str:
    resources.get_hunt(hunt_id)
    ctx = resources.get_context()
    chains = chaining.detect_chains(ctx, hunt_id)
    return serialize_result(chains)


@mcp.tool(description="Prioritize endpoints by likelihood of vulnerabilities")
async def analyze_prioritize(
    hunt_id: Annotated[str, "Hunt ID"],
    top: Annotated[int | None, "Return only the top N endpoints"] = None,
) -> str:
    resources.get_hunt(hunt_id)
    ctx = resources.get_context()
    result = prioritize.prioritize_endpoints(ctx, hunt_id, top=top)
    return serialize_result(result)
