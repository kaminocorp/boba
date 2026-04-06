"""High-level reconnaissance tools — compose adapters with context and scope."""

from __future__ import annotations

import asyncio
import copy
import logging
from pathlib import Path

import httpx

from boba.adapters.gau import GauAdapter
from boba.adapters.gitleaks import GitleaksAdapter
from boba.adapters.httpx_runner import HttpxRunnerAdapter
from boba.adapters.naabu import NaabuAdapter
from boba.adapters.subfinder import SubfinderAdapter
from boba.adapters.waybackurls import WaybackurlsAdapter
from boba.adapters.whatweb import WhatwebAdapter
from boba.core.context import HuntContext
from boba.core.models import AdapterConfig, Hunt, ToolResult
from boba.core.scope import ScopeEngine

logger = logging.getLogger(__name__)
_GITHUB_API_BASE = "https://api.github.com"


def _is_repo_locator(target: str) -> bool:
    """Return True when target is a concrete repo path/URL, not an org/user handle."""
    if not target:
        return False
    if target.startswith(("http://", "https://", "ssh://", "git@")):
        return True
    expanded = Path(target).expanduser()
    return target.startswith(("/", "./", "../", "~/")) or expanded.exists()


async def _list_public_github_repos(owner: str) -> list[str]:
    """Enumerate public repos for a GitHub org/user handle."""
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "boba",
    }
    repos: list[str] = []
    async with httpx.AsyncClient(timeout=20.0, follow_redirects=True, headers=headers) as client:
        page = 1
        while True:
            resp = await client.get(
                f"{_GITHUB_API_BASE}/users/{owner}/repos",
                params={"per_page": 100, "page": page, "type": "public"},
            )
            if resp.status_code == 404:
                raise ValueError(f"GitHub org/user '{owner}' not found")
            resp.raise_for_status()
            payload = resp.json()
            if not isinstance(payload, list):
                raise ValueError(f"Unexpected GitHub API response for '{owner}'")
            if not payload:
                break
            repos.extend(
                item.get("clone_url") or item.get("html_url") or ""
                for item in payload
                if isinstance(item, dict)
            )
            if len(payload) < 100:
                break
            page += 1
    return [repo for repo in repos if repo]


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
    context.upsert_records(hunt.id, "host", result.records, source="httpx")
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

    config = copy.deepcopy(config) if config else AdapterConfig()
    if port_range:
        config.extra_args_dict["ports"] = port_range

    scope = ScopeEngine(hunt.scope)
    adapter = NaabuAdapter(scope_engine=scope)
    result = await adapter.run(targets=targets, config=config)
    context.upsert_records(hunt.id, "port", result.records, source="naabu")
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
    seen_urls: set[str] = set()
    total_filtered = 0
    max_duration = 0.0

    for result, name in zip(results, ["gau", "waybackurls"]):
        if isinstance(result, Exception):
            logger.warning("%s failed: %s", name, result)
            continue
        context.upsert_records(hunt.id, "url", result.records, source=name)
        context.log_tool_run(hunt.id, result)
        # Deduplicate by URL across adapters
        for rec in result.records:
            url_key = rec.get("url", "")
            if url_key not in seen_urls:
                seen_urls.add(url_key)
                all_records.append(rec)
        total_filtered += result.filtered_count
        max_duration = max(max_duration, result.duration_seconds)

    # If all adapters failed, report non-zero exit code so callers can
    # distinguish "both URL sources failed" from "found 0 URLs".
    adapter_failures = sum(1 for r in results if isinstance(r, Exception))
    all_failed = adapter_failures == len(results)

    return ToolResult(
        tool_name="recon.urls",
        command=[],
        exit_code=1 if all_failed else 0,
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


async def secrets(
    context: HuntContext,
    hunt: Hunt,
    target: str,
    repo: str | None = None,
    config: AdapterConfig | None = None,
) -> ToolResult:
    """
    Scan git repositories for leaked secrets using gitleaks.

    target: GitHub org, user, or repo path/URL.
    repo: specific repo URL (overrides target).
    """
    explicit_repo = repo or target
    if not explicit_repo:
        return _empty_result("gitleaks")

    config = copy.deepcopy(config) if config else AdapterConfig()
    if repo:
        scan_targets = [repo]
    elif _is_repo_locator(target):
        scan_targets = [target]
    else:
        try:
            scan_targets = await _list_public_github_repos(target)
        except Exception as exc:
            logger.warning("Failed to enumerate GitHub repos for %s: %s", target, exc)
            return ToolResult(
                tool_name="gitleaks",
                command=[],
                exit_code=1,
                raw_stdout="",
                raw_stderr=str(exc),
                duration_seconds=0.0,
                records=[],
            )

    if not scan_targets:
        return _empty_result("gitleaks")

    scope = ScopeEngine(hunt.scope)
    if len(scan_targets) == 1:
        adapter = GitleaksAdapter(scope_engine=scope)
        result = await adapter.run(targets=scan_targets, config=config)
        context.upsert_records(hunt.id, "secret", result.records, source="gitleaks")
        context.log_tool_run(hunt.id, result)
        return result

    merged_records: list[dict] = []
    total_filtered = 0
    total_duration = 0.0
    exit_code = 0
    stderr_parts: list[str] = []

    for scan_target in scan_targets:
        adapter = GitleaksAdapter(scope_engine=scope)
        result = await adapter.run(targets=[scan_target], config=config)
        context.upsert_records(hunt.id, "secret", result.records, source="gitleaks")
        context.log_tool_run(hunt.id, result)
        merged_records.extend(result.records)
        total_filtered += result.filtered_count
        total_duration += result.duration_seconds
        exit_code = max(exit_code, result.exit_code)
        if result.raw_stderr.strip():
            stderr_parts.append(result.raw_stderr.strip())

    return ToolResult(
        tool_name="gitleaks",
        command=[],
        exit_code=exit_code,
        raw_stdout="",
        raw_stderr="\n".join(stderr_parts),
        duration_seconds=total_duration,
        records=merged_records,
        filtered_count=total_filtered,
    )


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
