"""High-level reconnaissance tools — compose adapters with context and scope."""

from __future__ import annotations

import asyncio
import logging

from boba.adapters.gau import GauAdapter
from boba.adapters.httpx_runner import HttpxRunnerAdapter
from boba.adapters.naabu import NaabuAdapter
from boba.adapters.subfinder import SubfinderAdapter
from boba.adapters.waybackurls import WaybackurlsAdapter
from boba.adapters.whatweb import WhatwebAdapter
from boba.core.context import HuntContext
from boba.core.models import AdapterConfig, Hunt, ToolResult
from boba.core.scope import ScopeEngine

logger = logging.getLogger(__name__)


async def subdomains(
    context: HuntContext,
    hunt: Hunt,
    domains: list[str],
    config: AdapterConfig | None = None,
) -> ToolResult:
    """
    Discover subdomains using subfinder.

    Runs subfinder with all sources, scope-filters, persists to context.
    """
    if not domains:
        return _empty_result("subfinder")

    scope = ScopeEngine(hunt.scope)
    adapter = SubfinderAdapter(scope_engine=scope)
    result = await adapter.run(targets=domains, config=config)
    context.upsert_records(hunt.id, "subdomain", result.records, source="subfinder")
    context.log_tool_run(hunt.id, result)
    return result


async def hosts(
    context: HuntContext,
    hunt: Hunt,
    targets: list[str] | None = None,
    config: AdapterConfig | None = None,
) -> ToolResult:
    """
    Check which subdomains are live using httpx.

    If no targets given, pulls all subdomains from context.
    """
    if targets is None:
        subs = context.get_subdomains(hunt.id)
        targets = [s["subdomain"] for s in subs]

    if not targets:
        return _empty_result("httpx")

    scope = ScopeEngine(hunt.scope)
    adapter = HttpxRunnerAdapter(scope_engine=scope)
    result = await adapter.run(targets=targets, config=config)
    context.upsert_records(hunt.id, "host", result.records)
    context.log_tool_run(hunt.id, result)
    return result


async def ports(
    context: HuntContext,
    hunt: Hunt,
    targets: list[str] | None = None,
    port_range: str | None = None,
    config: AdapterConfig | None = None,
) -> ToolResult:
    """
    Port scan live hosts using naabu.

    If no targets given, pulls alive hosts from context.
    """
    if targets is None:
        alive = context.get_hosts(hunt.id, alive_only=True)
        targets = list({h["host"] for h in alive})

    if not targets:
        return _empty_result("naabu")

    config = config or AdapterConfig()
    if port_range:
        config.extra_args_dict["ports"] = port_range

    scope = ScopeEngine(hunt.scope)
    adapter = NaabuAdapter(scope_engine=scope)
    result = await adapter.run(targets=targets, config=config)
    context.upsert_records(hunt.id, "port", result.records)
    context.log_tool_run(hunt.id, result)
    return result


async def urls(
    context: HuntContext,
    hunt: Hunt,
    domains: list[str],
    config: AdapterConfig | None = None,
) -> ToolResult:
    """
    Discover historical URLs using gau AND waybackurls in parallel.

    Merges and deduplicates results. Sources are tracked per URL.
    """
    if not domains:
        return _empty_result("recon.urls")

    scope = ScopeEngine(hunt.scope)
    gau_adapter = GauAdapter(scope_engine=scope)
    wayback_adapter = WaybackurlsAdapter(scope_engine=scope)

    results = await asyncio.gather(
        gau_adapter.run(targets=domains, config=config),
        wayback_adapter.run(targets=domains, config=config),
        return_exceptions=True,
    )

    all_records: list[dict] = []
    total_filtered = 0
    max_duration = 0.0

    for result, name in zip(results, ["gau", "waybackurls"]):
        if isinstance(result, Exception):
            logger.warning("%s failed: %s", name, result)
            continue
        context.upsert_records(hunt.id, "url", result.records, source=name)
        context.log_tool_run(hunt.id, result)
        all_records.extend(result.records)
        total_filtered += result.filtered_count
        max_duration = max(max_duration, result.duration_seconds)

    return ToolResult(
        tool_name="recon.urls",
        command=[],
        exit_code=0,
        raw_stdout="",
        raw_stderr="",
        duration_seconds=max_duration,
        records=all_records,
        filtered_count=total_filtered,
    )


async def tech(
    context: HuntContext,
    hunt: Hunt,
    targets: list[str] | None = None,
    config: AdapterConfig | None = None,
) -> ToolResult:
    """
    Fingerprint technology stacks on live hosts using whatweb.

    If no targets given, pulls alive host URLs from context.
    """
    if targets is None:
        alive = context.get_hosts(hunt.id, alive_only=True)
        targets = [h["url"] for h in alive if h.get("url")]

    if not targets:
        return _empty_result("whatweb")

    scope = ScopeEngine(hunt.scope)
    adapter = WhatwebAdapter(scope_engine=scope)
    result = await adapter.run(targets=targets, config=config)

    # Whatweb records contain nested technologies — flatten for persistence
    flat_techs = []
    for record in result.records:
        host = record.get("host", "")
        for t in record.get("technologies") or []:
            flat_techs.append({**t, "host": host})
    if flat_techs:
        context.upsert_records(hunt.id, "technology", flat_techs, source="whatweb")
    context.log_tool_run(hunt.id, result)
    return result


def _empty_result(tool_name: str) -> ToolResult:
    return ToolResult(
        tool_name=tool_name,
        command=[],
        exit_code=0,
        raw_stdout="",
        raw_stderr="",
        duration_seconds=0.0,
        records=[],
    )
