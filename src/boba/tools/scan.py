"""High-level scanning tools — Nuclei and template-based vulnerability detection."""

from __future__ import annotations

import logging

from boba.adapters.nuclei import NucleiAdapter
from boba.core.context import HuntContext
from boba.core.models import AdapterConfig, Hunt, ToolResult
from boba.core.scope import ScopeEngine

logger = logging.getLogger(__name__)


async def nuclei_scan(
    context: HuntContext,
    hunt: Hunt,
    targets: list[str] | None = None,
    severity: str | None = None,
    tags: str | None = None,
    templates: str | None = None,
    config: AdapterConfig | None = None,
) -> ToolResult:
    """Run Nuclei against targets with optional filters.

    If no targets given, pulls alive hosts from context.
    Results are persisted to the findings table.
    """
    if targets is None:
        alive = context.get_hosts(hunt.id, alive_only=True)
        targets = list({h["url"] for h in alive if h.get("url")})

    if not targets:
        return ToolResult(
            tool_name="nuclei",
            command=[],
            exit_code=0,
            raw_stdout="",
            raw_stderr="",
            duration_seconds=0.0,
            records=[],
        )

    config = config or AdapterConfig()
    if severity:
        config.extra_args_dict["severity"] = severity
    if tags:
        config.extra_args_dict["tags"] = tags
    if templates:
        config.extra_args_dict["templates"] = templates

    scope = ScopeEngine(hunt.scope)
    adapter = NucleiAdapter(scope_engine=scope)
    result = await adapter.run(targets=targets, config=config)

    # Persist findings
    for record in result.records:
        context.upsert_finding(
            hunt.id,
            {
                "finding_type": record.get("finding_type", "nuclei"),
                "severity": record.get("severity", "info"),
                "title": f"[{record.get('template_id', '')}] {record.get('template_name', '')}",
                "description": record.get("description", ""),
                "url": record.get("url", ""),
                "template_id": record.get("template_id"),
                "tags": record.get("tags", []),
            },
        )

    context.log_tool_run(hunt.id, result)
    return result
