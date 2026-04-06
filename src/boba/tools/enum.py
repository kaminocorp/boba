"""High-level enumeration tools — compose adapters with context and scope."""

from __future__ import annotations

import copy
import logging

from boba.adapters.arjun import ArjunAdapter
from boba.adapters.ffuf import FfufAdapter
from boba.adapters.katana import KatanaAdapter
from boba.adapters.kiterunner import KiterunnerAdapter
from boba.core.context import HuntContext
from boba.core.models import AdapterConfig, Hunt, ToolResult
from boba.core.scope import ScopeEngine

logger = logging.getLogger(__name__)


async def parameters(
    context: HuntContext,
    hunt: Hunt,
    url: str,
    method: str = "GET",
    body_type: str | None = None,
    config: AdapterConfig | None = None,
) -> ToolResult:
    """Discover hidden parameters on a known endpoint using Arjun."""
    config = copy.deepcopy(config) if config else AdapterConfig()
    config.extra_args_dict["method"] = method.upper()
    if body_type:
        config.extra_args_dict["body_type"] = body_type.lower()

    scope = ScopeEngine(hunt.scope)
    adapter = ArjunAdapter(scope_engine=scope)
    result = await adapter.run(targets=[url], config=config)
    context.upsert_records(hunt.id, "parameter", result.records, source="arjun")
    context.log_tool_run(hunt.id, result)
    return result


async def directories(
    context: HuntContext,
    hunt: Hunt,
    url: str,
    wordlist: str | None = None,
    match_codes: str = "200,301,302,403",
    extensions: list[str] | None = None,
    config: AdapterConfig | None = None,
) -> ToolResult:
    """
    Fuzz for directories and files using ffuf.

    Automatically appends /FUZZ to the URL if not present.
    """
    config = copy.deepcopy(config) if config else AdapterConfig()
    if wordlist:
        config.extra_args_dict["wordlist"] = wordlist
    config.extra_args_dict["match_codes"] = match_codes
    if extensions:
        config.extra_args.extend(["-e", ",".join(extensions)])

    scope = ScopeEngine(hunt.scope)
    adapter = FfufAdapter(scope_engine=scope)
    result = await adapter.run(targets=[url], config=config)
    context.upsert_records(hunt.id, "directory", result.records, source="ffuf")
    context.log_tool_run(hunt.id, result)
    return result


async def crawl(
    context: HuntContext,
    hunt: Hunt,
    targets: list[str] | None = None,
    depth: int | str = 3,
    config: AdapterConfig | None = None,
) -> ToolResult:
    """
    Crawl web applications using katana.

    If no targets given, pulls alive host URLs from context.
    """
    if targets is None:
        alive = context.get_hosts(hunt.id, alive_only=True)
        targets = [h["url"] for h in alive if h.get("url")]

    if not targets:
        return ToolResult(
            tool_name="katana",
            command=[],
            exit_code=0,
            raw_stdout="",
            raw_stderr="",
            duration_seconds=0.0,
            records=[],
        )

    config = copy.deepcopy(config) if config else AdapterConfig()
    config.extra_args_dict["depth"] = str(depth)

    scope = ScopeEngine(hunt.scope)
    adapter = KatanaAdapter(scope_engine=scope)
    result = await adapter.run(targets=targets, config=config)
    context.upsert_records(hunt.id, "url", result.records, source="katana")
    context.log_tool_run(hunt.id, result)
    return result


async def api(
    context: HuntContext,
    hunt: Hunt,
    url: str | None = None,
    targets: list[str] | None = None,
    wordlist: str | None = None,
    config: AdapterConfig | None = None,
) -> ToolResult:
    """
    Discover API endpoints using Kiterunner.

    If no targets given, pulls alive host URLs from context.
    """
    if targets is None and url:
        targets = [url]
    elif targets is None:
        alive = context.get_hosts(hunt.id, alive_only=True)
        targets = [h["url"] for h in alive if h.get("url")]

    if not targets:
        return ToolResult(
            tool_name="kiterunner",
            command=[],
            exit_code=0,
            raw_stdout="",
            raw_stderr="",
            duration_seconds=0.0,
            records=[],
        )

    config = copy.deepcopy(config) if config else AdapterConfig()
    if wordlist:
        config.extra_args_dict["wordlist"] = wordlist

    scope = ScopeEngine(hunt.scope)
    adapter = KiterunnerAdapter(scope_engine=scope)
    result = await adapter.run(targets=targets, config=config)
    context.upsert_records(hunt.id, "api_endpoint", result.records, source="kiterunner")
    context.log_tool_run(hunt.id, result)
    return result
