"""MCP tools for reporting — draft, format, PoC packaging, report management."""

from __future__ import annotations

from typing import Annotated

from boba.mcp.serializers import serialize_result
from boba.mcp.server import mcp, resources
from boba.reporting import draft, formatter, poc


@mcp.tool(description="Draft a vulnerability report from a finding or attack chain")
async def report_draft(
    hunt_id: Annotated[str, "Hunt ID"],
    finding_id: Annotated[int | None, "Finding ID to draft report for"] = None,
    chain_id: Annotated[int | None, "Chain ID to draft report for"] = None,
) -> str:
    resources.get_hunt(hunt_id)
    ctx = resources.get_context()
    if chain_id is not None:
        result = draft.draft_chain_report(ctx, hunt_id, chain_id)
    elif finding_id is not None:
        result = draft.draft_finding_report(ctx, hunt_id, finding_id)
    else:
        raise ValueError("Either finding_id or chain_id must be provided")
    return serialize_result(result)


@mcp.tool(description="Format a report for a specific platform (HackerOne, Bugcrowd, Markdown)")
async def report_format(
    hunt_id: Annotated[str, "Hunt ID"],
    report_id: Annotated[int, "Report ID to format"],
    platform: Annotated[str, "Target platform: hackerone, bugcrowd, markdown"] = "markdown",
) -> str:
    resources.get_hunt(hunt_id)
    ctx = resources.get_context()
    report_row = ctx.get_report(report_id)
    if report_row is None:
        raise ValueError(f"Report {report_id} not found")

    # Reconstruct a ReportDraft from the DB row for the formatter
    from boba.core.models import Platform, ReportDraft, ReportStatus, Severity

    def _safe_enum(enum_cls, value, default):
        try:
            return enum_cls(value) if value else default
        except ValueError:
            return default

    report_obj = ReportDraft(
        id=report_row.get("id", 0),
        hunt_id=report_row.get("hunt_id", hunt_id),
        finding_id=report_row.get("finding_id"),
        chain_id=report_row.get("chain_id"),
        title=report_row.get("title", ""),
        severity=_safe_enum(Severity, report_row.get("severity"), Severity.INFO),
        cvss_score=report_row.get("cvss_score", 0.0),
        cvss_vector=report_row.get("cvss_vector", ""),
        summary=report_row.get("summary", ""),
        steps=report_row.get("steps", []),
        impact=report_row.get("impact", ""),
        remediation=report_row.get("remediation", ""),
        evidence_refs=report_row.get("evidence_refs", []),
        request_ids=report_row.get("request_ids", []),
        platform=_safe_enum(Platform, report_row.get("platform"), Platform.GENERIC),
        status=_safe_enum(ReportStatus, report_row.get("status"), ReportStatus.DRAFT),
    )

    format_fns = {
        "hackerone": formatter.format_hackerone,
        "bugcrowd": formatter.format_bugcrowd,
        "markdown": formatter.format_markdown,
    }
    format_fn = format_fns.get(platform)
    if format_fn is None:
        raise ValueError(f"Unknown platform '{platform}', expected: {', '.join(format_fns)}")

    formatted = format_fn(report_obj)
    return serialize_result({"report_id": report_id, "platform": platform, "content": formatted})


@mcp.tool(description="Package PoC evidence (HTTP dumps, screenshots) for a finding or chain")
async def report_poc(
    hunt_id: Annotated[str, "Hunt ID"],
    finding_id: Annotated[int | None, "Finding ID"] = None,
    chain_id: Annotated[int | None, "Chain ID"] = None,
    output_dir: Annotated[str, "Directory to write PoC files"] = ".",
) -> str:
    resources.get_hunt(hunt_id)
    ctx = resources.get_context()
    result = poc.package_poc(
        ctx, hunt_id, finding_id=finding_id, chain_id=chain_id, output_dir=output_dir
    )
    return serialize_result(result)


@mcp.tool(description="List all reports for a hunt (optionally filter by status)")
async def report_list(
    hunt_id: Annotated[str, "Hunt ID"],
    status: Annotated[str | None, "Filter by status: draft, ready, submitted"] = None,
) -> str:
    resources.get_hunt(hunt_id)
    ctx = resources.get_context()
    reports = ctx.get_reports(hunt_id, status=status)
    return serialize_result(reports)


@mcp.tool(description="Get a single report by ID")
async def report_show(
    hunt_id: Annotated[str, "Hunt ID"],
    report_id: Annotated[int, "Report ID"],
) -> str:
    resources.get_hunt(hunt_id)
    ctx = resources.get_context()
    report = ctx.get_report(report_id)
    if report is None:
        raise ValueError(f"Report {report_id} not found")
    return serialize_result(report)
