"""Boba CLI — Typer-based command interface for agents and humans."""

from __future__ import annotations

import asyncio
import logging
from contextlib import contextmanager
from pathlib import Path
from typing import Annotated, Any, Generator, Optional

import typer

from boba.cli.formatters import console, format_output, print_error, print_info, print_success
from boba.core.config import get_db_path

logger = logging.getLogger(__name__)

app = typer.Typer(
    name="boba",
    help="Agent-native bug bounty hunting framework.",
    no_args_is_help=True,
)

# ═══════════════════ Global options ═══════════════════

FormatOption = Annotated[str, typer.Option("--format", "-f", help="Output format: json or table")]
DataDirOption = Annotated[
    Optional[Path], typer.Option("--data-dir", help="Data directory (default: ~/.boba)")
]


def _get_manager(data_dir: Path | None = None):
    from boba.core.hunt import HuntManager

    db_path = str(data_dir / "boba.db") if data_dir else str(get_db_path())
    return HuntManager(db_path=db_path)


def _safe_close(manager) -> None:
    """Close manager context without masking the original exception."""
    try:
        manager.close_context()
    except Exception as exc:
        logger.debug("Failed to close manager: %s", exc)


def _safe_close_http(client) -> None:
    """Close HttpClient connection pool without masking the original exception.

    Uses a new event loop since the previous asyncio.run() already closed its loop.
    The httpx AsyncClient handles cross-loop closure gracefully.
    """
    if client is None:
        return
    try:
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(client.close())
        finally:
            loop.close()
    except Exception as exc:
        logger.debug("Failed to close HTTP client: %s", exc)


@contextmanager
def _managed(data_dir: Path | None = None) -> Generator[Any, None, None]:
    """Context manager for CLI commands: creates manager, handles errors, cleans up."""
    manager = _get_manager(data_dir)
    try:
        yield manager
    except typer.Exit:
        raise
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(1)
    finally:
        _safe_close(manager)


@contextmanager
def _managed_http(data_dir: Path | None, hunt_id: str) -> Generator[tuple[Any, Any], None, None]:
    """Context manager for HTTP commands: creates manager + HttpClient, cleans up both."""
    manager = _get_manager(data_dir)
    client = None
    try:
        client = _get_http_client(manager, hunt_id)
        yield manager, client
    except typer.Exit:
        raise
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(1)
    finally:
        _safe_close_http(client)
        _safe_close(manager)


def _get_http_client(manager, hunt_id: str):
    """Create an HttpClient with history sink for a hunt. Returns (client, sink)."""
    from boba.interaction.history import HttpHistorySink
    from boba.interaction.http import HttpClient

    manager.get(hunt_id)
    sink = HttpHistorySink(manager.context, hunt_id)
    return HttpClient(sink)


def _get_browser_manager(manager, hunt_id: str):
    """Create a BrowserManager with history sink for a hunt."""
    from boba.core.models import BrowserConfig
    from boba.interaction.browser import BrowserManager
    from boba.interaction.history import HttpHistorySink

    manager.get(hunt_id)
    sink = HttpHistorySink(manager.context, hunt_id)
    config = BrowserConfig(headless=True)
    return BrowserManager(config, sink)


def _get_session_manager(manager, hunt_id: str):
    """Create a SessionManager for a hunt."""
    from boba.interaction.session import SessionManager

    manager.get(hunt_id)
    return SessionManager(manager.context, hunt_id)


def _parse_headers(header_list: list[str] | None) -> dict[str, str]:
    """Parse CLI header arguments (KEY:VALUE) into a dict."""
    if not header_list:
        return {}
    headers: dict[str, str] = {}
    for h in header_list:
        if ":" not in h:
            print_error(f"Invalid header format: '{h}' (expected KEY:VALUE)")
            raise typer.Exit(1)
        k, v = h.split(":", 1)
        headers[k.strip()] = v.strip()
    return headers


def _parse_targets(targets: str | None) -> list[str] | None:
    """Parse a comma-separated target string into a list, or None if empty."""
    if not targets:
        return None
    result = [t.strip() for t in targets.split(",") if t.strip()]
    return result or None


# ═══════════════════ HUNT COMMANDS ═══════════════════

hunt_app = typer.Typer(help="Hunt lifecycle management.")
app.add_typer(hunt_app, name="hunt")


@hunt_app.command("create")
def hunt_create(
    name: Annotated[str, typer.Option("--name", "-n", help="Hunt name")],
    scope: Annotated[Optional[Path], typer.Option("--scope", "-s", help="Scope YAML file")] = None,
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """Create a new hunt."""
    with _managed(data_dir) as manager:
        hunt = manager.create(name=name, scope_yaml=scope)
        if fmt == "json":
            format_output(
                {
                    "id": hunt.id,
                    "name": hunt.name,
                    "status": hunt.status.value,
                    "scope_rules": len(hunt.scope.rules),
                },
                fmt="json",
            )
        else:
            print_success(f"Hunt created: {hunt.id}")
            console.print(f"  Name: {hunt.name}")
            console.print(f"  Scope rules: {len(hunt.scope.rules)}")


@hunt_app.command("list")
def hunt_list(fmt: FormatOption = "table", data_dir: DataDirOption = None) -> None:
    """List all hunts."""
    with _managed(data_dir) as manager:
        hunts = manager.list_hunts()
        records = [
            {"id": h.id, "name": h.name, "status": h.status.value, "created_at": str(h.created_at)}
            for h in hunts
        ]
        format_output(records, fmt=fmt, title="Hunts")


@hunt_app.command("status")
def hunt_status(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """Show hunt status and statistics."""
    with _managed(data_dir) as manager:
        hunt = manager.get(hunt_id)
        stats = manager.stats(hunt_id)
        info = {
            "id": hunt.id,
            "name": hunt.name,
            "status": hunt.status.value,
            "scope_rules": len(hunt.scope.rules),
            **stats,
        }
        format_output(info, fmt=fmt, title=f"Hunt: {hunt.name}")


@hunt_app.command("pause")
def hunt_pause(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    data_dir: DataDirOption = None,
) -> None:
    """Pause a hunt."""
    with _managed(data_dir) as manager:
        manager.pause(hunt_id)
        print_success(f"Hunt {hunt_id} paused.")


@hunt_app.command("resume")
def hunt_resume(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    data_dir: DataDirOption = None,
) -> None:
    """Resume a paused hunt."""
    with _managed(data_dir) as manager:
        manager.resume(hunt_id)
        print_success(f"Hunt {hunt_id} resumed.")


@hunt_app.command("close")
def hunt_close(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    data_dir: DataDirOption = None,
) -> None:
    """Close/complete a hunt."""
    with _managed(data_dir) as manager:
        manager.close(hunt_id)
        print_success(f"Hunt {hunt_id} closed.")


# ═══════════════════ RECON COMMANDS ═══════════════════

recon_app = typer.Typer(help="Reconnaissance tools.")
app.add_typer(recon_app, name="recon")


@recon_app.command("subdomains")
def recon_subdomains(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    domain: Annotated[list[str], typer.Option("--domain", "-d", help="Target domain(s)")],
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """Discover subdomains using subfinder."""
    with _managed(data_dir) as manager:
        from boba.tools import recon

        hunt = manager.get(hunt_id)
        result = asyncio.run(recon.subdomains(manager.context, hunt, domain))
        if fmt == "json":
            format_output(
                {
                    "tool": "subfinder",
                    "found": len(result.records),
                    "filtered": result.filtered_count,
                    "records": result.records,
                },
                fmt="json",
            )
        else:
            format_output(result.records, fmt="table", title="Subdomains")
            print_info(
                f"Found {len(result.records)} subdomains "
                f"({result.filtered_count} filtered out-of-scope)"
            )


@recon_app.command("hosts")
def recon_hosts(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    targets: Annotated[
        Optional[str], typer.Option("--targets", "-t", help="Comma-separated hosts")
    ] = None,
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """Check which subdomains are live using httpx."""
    with _managed(data_dir) as manager:
        from boba.tools import recon

        hunt = manager.get(hunt_id)
        target_list = _parse_targets(targets)
        result = asyncio.run(recon.hosts(manager.context, hunt, target_list))
        if fmt == "json":
            format_output(
                {"tool": "httpx", "found": len(result.records), "records": result.records},
                fmt="json",
            )
        else:
            format_output(
                result.records,
                fmt="table",
                columns=["host", "status_code", "title", "webserver", "technologies"],
                title="Live Hosts",
            )


@recon_app.command("ports")
def recon_ports(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    targets: Annotated[
        Optional[str], typer.Option("--targets", "-t", help="Comma-separated hosts")
    ] = None,
    range_: Annotated[
        Optional[str], typer.Option("--range", "-r", help="Port range (e.g., 1-1000)")
    ] = None,
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """Port scan live hosts using naabu."""
    with _managed(data_dir) as manager:
        from boba.tools import recon

        hunt = manager.get(hunt_id)
        target_list = _parse_targets(targets)
        result = asyncio.run(recon.ports(manager.context, hunt, target_list, range_))
        if fmt == "json":
            format_output(
                {"tool": "naabu", "found": len(result.records), "records": result.records},
                fmt="json",
            )
        else:
            format_output(result.records, fmt="table", title="Open Ports")


@recon_app.command("urls")
def recon_urls(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    domain: Annotated[list[str], typer.Option("--domain", "-d", help="Target domain(s)")],
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """Discover historical URLs using gau + waybackurls."""
    with _managed(data_dir) as manager:
        from boba.tools import recon

        hunt = manager.get(hunt_id)
        result = asyncio.run(recon.urls(manager.context, hunt, domain))
        if fmt == "json":
            format_output(
                {
                    "tool": "recon.urls",
                    "found": len(result.records),
                    "filtered": result.filtered_count,
                    "records": result.records,
                },
                fmt="json",
            )
        else:
            format_output(
                result.records,
                fmt="table",
                columns=["url", "host", "path", "source"],
                title="Discovered URLs",
            )


@recon_app.command("tech")
def recon_tech(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    targets: Annotated[
        Optional[str], typer.Option("--targets", "-t", help="Comma-separated URLs")
    ] = None,
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """Fingerprint technologies using whatweb."""
    with _managed(data_dir) as manager:
        from boba.tools import recon

        hunt = manager.get(hunt_id)
        target_list = _parse_targets(targets)
        result = asyncio.run(recon.tech(manager.context, hunt, target_list))
        if fmt == "json":
            format_output(
                {"tool": "whatweb", "found": len(result.records), "records": result.records},
                fmt="json",
            )
        else:
            # Flatten technologies for table display
            rows = []
            for record in result.records:
                for t in record.get("technologies", []):
                    rows.append(
                        {
                            "host": record.get("host", ""),
                            "technology": t.get("name", ""),
                            "version": t.get("version", ""),
                        }
                    )
            format_output(rows, fmt="table", title="Technologies")


# ═══════════════════ ENUM COMMANDS ═══════════════════

enum_app = typer.Typer(help="Enumeration tools.")
app.add_typer(enum_app, name="enum")


@enum_app.command("parameters")
def enum_parameters(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    url: Annotated[str, typer.Option("--url", "-u", help="Target URL")],
    method: Annotated[str, typer.Option("--method", "-X", help="HTTP method")] = "GET",
    body_type: Annotated[
        Optional[str], typer.Option("--body-type", help="POST body type: json or form")
    ] = None,
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """Discover hidden parameters using Arjun."""
    with _managed(data_dir) as manager:
        from boba.tools import enum

        hunt = manager.get(hunt_id)
        result = asyncio.run(
            enum.parameters(manager.context, hunt, url, method=method, body_type=body_type)
        )
        if fmt == "json":
            format_output(
                {"tool": "arjun", "found": len(result.records), "records": result.records},
                fmt="json",
            )
        else:
            format_output(
                result.records,
                fmt="table",
                columns=["url", "method", "name", "param_type", "confirmed"],
                title="Parameters",
            )


@enum_app.command("directories")
def enum_directories(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    url: Annotated[str, typer.Option("--url", "-u", help="Target URL (FUZZ keyword optional)")],
    wordlist: Annotated[
        Optional[str], typer.Option("--wordlist", "-w", help="Wordlist path")
    ] = None,
    match_codes: Annotated[
        str, typer.Option("--match-codes", "-mc", help="Status codes to match")
    ] = "200,301,302,403",
    extensions: Annotated[
        Optional[str], typer.Option("--extensions", "-e", help="File extensions (comma-separated)")
    ] = None,
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """Fuzz for directories and files using ffuf."""
    with _managed(data_dir) as manager:
        from boba.tools import enum

        hunt = manager.get(hunt_id)
        ext_list = _parse_targets(extensions)
        result = asyncio.run(
            enum.directories(manager.context, hunt, url, wordlist, match_codes, ext_list)
        )
        if fmt == "json":
            format_output(
                {"tool": "ffuf", "found": len(result.records), "records": result.records},
                fmt="json",
            )
        else:
            format_output(
                result.records,
                fmt="table",
                columns=["url", "status_code", "content_length", "content_type"],
                title="Directories",
            )


@enum_app.command("crawl")
def enum_crawl(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    targets: Annotated[
        Optional[str], typer.Option("--targets", "-t", help="Comma-separated URLs")
    ] = None,
    depth: Annotated[int, typer.Option("--depth", "-d", help="Crawl depth")] = 3,
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """Crawl web applications using katana."""
    with _managed(data_dir) as manager:
        from boba.tools import enum

        hunt = manager.get(hunt_id)
        target_list = _parse_targets(targets)
        result = asyncio.run(enum.crawl(manager.context, hunt, target_list, depth))
        if fmt == "json":
            format_output(
                {"tool": "katana", "found": len(result.records), "records": result.records},
                fmt="json",
            )
        else:
            format_output(
                result.records,
                fmt="table",
                columns=["url", "host", "path", "source"],
                title="Crawled URLs",
            )


# ═══════════════════ CONTEXT COMMANDS ═══════════════════

context_app = typer.Typer(help="Query discovered data.")
app.add_typer(context_app, name="context")


@context_app.command("subdomains")
def ctx_subdomains(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """List discovered subdomains."""
    with _managed(data_dir) as manager:
        records = manager.context.get_subdomains(hunt_id)
        format_output(records, fmt=fmt, title="Subdomains")


@context_app.command("hosts")
def ctx_hosts(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    alive_only: Annotated[bool, typer.Option("--alive-only", help="Only show live hosts")] = False,
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """List discovered hosts."""
    with _managed(data_dir) as manager:
        records = manager.context.get_hosts(hunt_id, alive_only=alive_only)
        format_output(
            records,
            fmt=fmt,
            columns=["host", "ip", "port", "scheme", "status_code", "title", "webserver"],
            title="Hosts",
        )


@context_app.command("ports")
def ctx_ports(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    host: Annotated[Optional[str], typer.Option("--host", help="Filter by host")] = None,
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """List discovered ports."""
    with _managed(data_dir) as manager:
        records = manager.context.get_ports(hunt_id, host=host)
        format_output(records, fmt=fmt, title="Ports")


@context_app.command("urls")
def ctx_urls(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    host: Annotated[Optional[str], typer.Option("--host", help="Filter by host")] = None,
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """List discovered URLs."""
    with _managed(data_dir) as manager:
        records = manager.context.get_urls(hunt_id, host=host)
        format_output(
            records, fmt=fmt, columns=["url", "method", "status_code", "sources"], title="URLs"
        )


@context_app.command("tech")
def ctx_tech(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    host: Annotated[Optional[str], typer.Option("--host", help="Filter by host")] = None,
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """List discovered technologies."""
    with _managed(data_dir) as manager:
        records = manager.context.get_technologies(hunt_id, host=host)
        format_output(records, fmt=fmt, title="Technologies")


@context_app.command("parameters")
def ctx_parameters(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    url: Annotated[Optional[str], typer.Option("--url", help="Filter by exact URL")] = None,
    method: Annotated[Optional[str], typer.Option("--method", help="Filter by method")] = None,
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """List discovered parameters."""
    with _managed(data_dir) as manager:
        records = manager.context.get_parameters(hunt_id, url=url, method=method)
        format_output(
            records,
            fmt=fmt,
            columns=["url", "method", "name", "param_type", "confirmed", "sources"],
            title="Parameters",
        )


@context_app.command("directories")
def ctx_directories(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    url_prefix: Annotated[
        Optional[str], typer.Option("--url-prefix", help="Filter by URL prefix")
    ] = None,
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """List discovered directories."""
    with _managed(data_dir) as manager:
        records = manager.context.get_directories(hunt_id, url_prefix=url_prefix)
        format_output(
            records,
            fmt=fmt,
            columns=["url", "status_code", "content_length", "content_type"],
            title="Directories",
        )


@context_app.command("runs")
def ctx_runs(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """List tool run history."""
    with _managed(data_dir) as manager:
        records = manager.context.get_tool_runs(hunt_id)
        format_output(
            records,
            fmt=fmt,
            columns=[
                "tool_name",
                "status",
                "duration_seconds",
                "records_found",
                "records_filtered",
                "started_at",
            ],
            title="Tool Runs",
        )


@context_app.command("stats")
def ctx_stats(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """Show hunt statistics."""
    with _managed(data_dir) as manager:
        stats = manager.stats(hunt_id)
        format_output(stats, fmt=fmt, title="Hunt Statistics")


# ═══════════════════ BROWSER COMMANDS ═══════════════════

browser_app = typer.Typer(help="Browser automation (Playwright).")
app.add_typer(browser_app, name="browser")


@browser_app.command("navigate")
def browser_navigate(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    url: Annotated[str, typer.Option("--url", "-u", help="URL to navigate to")],
    context_name: Annotated[
        str, typer.Option("--context", "-c", help="Browser context name")
    ] = "default",
    wait_until: Annotated[str, typer.Option("--wait-until", help="Wait condition")] = "networkidle",
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """Navigate to a URL and capture traffic."""
    with _managed(data_dir) as manager:
        browser = _get_browser_manager(manager, hunt_id)

        async def _run():
            await browser.start()
            try:
                info = await browser.navigate(url, context_name, wait_until)
                return info
            finally:
                await browser.stop()

        info = asyncio.run(_run())
        data = {
            "url": info.url,
            "final_url": info.final_url,
            "status_code": info.status_code,
            "title": info.title,
            "content_type": info.content_type,
            "timing_ms": info.timing_ms,
            "requests_captured": info.requests_captured,
        }
        format_output(data, fmt=fmt, title="Navigation Result")


@browser_app.command("screenshot")
def browser_screenshot(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    path: Annotated[str, typer.Option("--path", "-p", help="Screenshot file path")],
    url: Annotated[str, typer.Option("--url", "-u", help="URL to screenshot")],
    full_page: Annotated[bool, typer.Option("--full-page", help="Capture full page")] = True,
    data_dir: DataDirOption = None,
) -> None:
    """Take a screenshot of a web page."""
    with _managed(data_dir) as manager:
        browser = _get_browser_manager(manager, hunt_id)

        async def _run():
            await browser.start()
            try:
                await browser.navigate(url)
                return await browser.screenshot(path, full_page=full_page)
            finally:
                await browser.stop()

        result_path = asyncio.run(_run())
        print_success(f"Screenshot saved: {result_path}")


@browser_app.command("extract")
def browser_extract(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    url: Annotated[str, typer.Option("--url", "-u", help="URL to extract from")],
    fmt: FormatOption = "json",
    data_dir: DataDirOption = None,
) -> None:
    """Extract structured DOM data from a page."""
    with _managed(data_dir) as manager:
        from dataclasses import asdict

        browser = _get_browser_manager(manager, hunt_id)

        async def _run():
            await browser.start()
            try:
                await browser.navigate(url)
                return await browser.extract()
            finally:
                await browser.stop()

        dom = asyncio.run(_run())
        format_output(asdict(dom), fmt=fmt, title="DOM Extraction")


# ═══════════════════ HTTP COMMANDS ═══════════════════

http_app = typer.Typer(help="HTTP request tools (Repeater/Intruder).")
app.add_typer(http_app, name="http")


@http_app.command("request")
def http_request(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    url: Annotated[str, typer.Option("--url", "-u", help="Target URL")],
    method: Annotated[str, typer.Option("--method", "-m", help="HTTP method")] = "GET",
    header: Annotated[
        Optional[list[str]], typer.Option("--header", "-H", help="Header (KEY:VALUE)")
    ] = None,
    body: Annotated[Optional[str], typer.Option("--body", "-b", help="Request body")] = None,
    fmt: FormatOption = "json",
    data_dir: DataDirOption = None,
) -> None:
    """Send a crafted HTTP request."""
    with _managed_http(data_dir, hunt_id) as (manager, client):
        headers = _parse_headers(header)
        resp = asyncio.run(
            client.request(
                method=method,
                url=url,
                headers=headers or None,
                body=body,
            )
        )
        data = {
            "request_id": resp.request_id,
            "status_code": resp.status_code,
            "body_length": len(resp.body),
            "elapsed_ms": resp.elapsed_ms,
            "body_preview": resp.body_text[:500],
        }
        format_output(data, fmt=fmt, title="HTTP Response")


@http_app.command("replay")
def http_replay(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    request_id: Annotated[int, typer.Option("--request-id", help="ID from http_history")],
    modify_header: Annotated[
        Optional[list[str]], typer.Option("--modify-header", help="Override header (KEY:VALUE)")
    ] = None,
    modify_body: Annotated[
        Optional[str], typer.Option("--modify-body", help="Override body")
    ] = None,
    fmt: FormatOption = "json",
    data_dir: DataDirOption = None,
) -> None:
    """Replay a request from HTTP history with modifications."""
    with _managed_http(data_dir, hunt_id) as (manager, client):
        modifications: dict = {}
        if modify_header:
            modifications["headers"] = _parse_headers(modify_header)
        if modify_body:
            modifications["body"] = modify_body

        resp = asyncio.run(client.replay(request_id, modifications or None))
        data = {
            "request_id": resp.request_id,
            "status_code": resp.status_code,
            "body_length": len(resp.body),
            "elapsed_ms": resp.elapsed_ms,
            "parent_request_id": request_id,
        }
        format_output(data, fmt=fmt, title="Replay Result")


@http_app.command("compare")
def http_compare(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    id_a: Annotated[int, typer.Option("--id-a", help="First response ID")],
    id_b: Annotated[int, typer.Option("--id-b", help="Second response ID")],
    fmt: FormatOption = "json",
    data_dir: DataDirOption = None,
) -> None:
    """Compare two HTTP responses."""
    with _managed_http(data_dir, hunt_id) as (manager, client):
        from dataclasses import asdict

        result = asyncio.run(client.compare(id_a, id_b))
        format_output(asdict(result), fmt=fmt, title="Response Comparison")


# ═══════════════════ SESSION COMMANDS ═══════════════════

session_app = typer.Typer(help="Session management for authenticated testing.")
app.add_typer(session_app, name="session")


@session_app.command("create")
def session_create(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    name: Annotated[str, typer.Option("--name", "-n", help="Session name")],
    target: Annotated[str, typer.Option("--target", "-t", help="Target URL")],
    method: Annotated[str, typer.Option("--method", "-m", help="Auth method")] = "form",
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """Create a new session."""
    with _managed(data_dir) as manager:
        from boba.core.models import AuthMethod

        try:
            auth_method = AuthMethod(method)
        except ValueError:
            valid = [m.value for m in AuthMethod]
            print_error(f"Invalid auth method '{method}'. Valid: {valid}")
            raise typer.Exit(1)
        mgr = _get_session_manager(manager, hunt_id)
        state = mgr.create(name, target, auth_method)
        if fmt == "json":
            format_output(
                {
                    "name": state.name,
                    "target_url": state.target_url,
                    "auth_method": state.auth_method.value,
                },
                fmt="json",
            )
        else:
            print_success(f"Session '{name}' created for {target}")


@session_app.command("login-token")
def session_login_token(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    name: Annotated[str, typer.Argument(help="Session name")],
    token: Annotated[str, typer.Option("--token", "-t", help="Bearer token")],
    data_dir: DataDirOption = None,
) -> None:
    """Set a Bearer token on a session."""
    with _managed(data_dir) as manager:
        mgr = _get_session_manager(manager, hunt_id)
        mgr.login_bearer(name, token)
        print_success(f"Bearer token set on session '{name}'")


@session_app.command("list")
def session_list(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """List all sessions."""
    with _managed(data_dir) as manager:
        mgr = _get_session_manager(manager, hunt_id)
        sessions = mgr.list_sessions()
        records = [
            {
                "name": s.name,
                "target_url": s.target_url,
                "auth_method": s.auth_method.value,
                "is_valid": s.is_valid,
            }
            for s in sessions
        ]
        format_output(records, fmt=fmt, title="Sessions")


@session_app.command("delete")
def session_delete(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    name: Annotated[str, typer.Argument(help="Session name")],
    data_dir: DataDirOption = None,
) -> None:
    """Delete a session."""
    with _managed(data_dir) as manager:
        mgr = _get_session_manager(manager, hunt_id)
        mgr.delete(name)
        print_success(f"Session '{name}' deleted")


# ═══════════════════ SCAN COMMANDS ═══════════════════

scan_app = typer.Typer(help="Vulnerability scanning tools.")
app.add_typer(scan_app, name="scan")


@scan_app.command("nuclei")
def scan_nuclei(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    targets: Annotated[
        Optional[str], typer.Option("--targets", "-t", help="Comma-separated URLs")
    ] = None,
    severity: Annotated[
        Optional[str],
        typer.Option("--severity", "-s", help="Severity filter (e.g., high,critical)"),
    ] = None,
    tags: Annotated[
        Optional[str], typer.Option("--tags", help="Tag filter (e.g., cve,exposure)")
    ] = None,
    templates: Annotated[
        Optional[str], typer.Option("--templates", help="Custom templates directory")
    ] = None,
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """Run Nuclei vulnerability scanner."""
    with _managed(data_dir) as manager:
        from boba.tools import scan

        hunt = manager.get(hunt_id)
        target_list = _parse_targets(targets)
        result = asyncio.run(
            scan.nuclei_scan(
                manager.context,
                hunt,
                target_list,
                severity,
                tags,
                templates,
            )
        )
        if fmt == "json":
            format_output(
                {"tool": "nuclei", "found": len(result.records), "records": result.records},
                fmt="json",
            )
        else:
            format_output(
                result.records,
                fmt="table",
                columns=["template_id", "severity", "url", "template_name"],
                title="Nuclei Findings",
            )


# ═══════════════════ ANALYZE COMMANDS ═══════════════════

analyze_app = typer.Typer(help="Analysis tools — coverage, dedup, severity, chaining.")
app.add_typer(analyze_app, name="analyze")


@analyze_app.command("coverage")
def analyze_coverage_cmd(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    host: Annotated[Optional[str], typer.Option("--host", help="Filter by host")] = None,
    untested_only: Annotated[
        bool, typer.Option("--untested-only", help="Show only untested endpoints")
    ] = False,
    test_type: Annotated[
        Optional[str],
        typer.Option("--test-type", "-t", help="Filter by test types (comma-separated)"),
    ] = None,
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """Show coverage summary or untested endpoints."""
    with _managed(data_dir) as manager:
        from boba.analysis.coverage import get_coverage_summary, get_coverage_gaps

        test_types = [t.strip() for t in test_type.split(",")] if test_type else None

        if untested_only:
            gaps = get_coverage_gaps(manager.context, hunt_id, test_types=test_types, host=host)
            format_output(
                gaps,
                fmt=fmt,
                columns=["url", "method", "test_type"],
                title="Untested Endpoints",
            )
        else:
            from dataclasses import asdict

            summary = get_coverage_summary(
                manager.context,
                hunt_id,
                host=host,
                test_types=test_types,
            )
            if fmt == "json":
                format_output(asdict(summary), fmt="json")
            else:
                from rich.table import Table

                t = Table(title="Coverage Summary")
                t.add_column("Metric")
                t.add_column("Value", justify="right")
                t.add_row("Total endpoints", str(summary.total_endpoints))
                t.add_row("Tested", str(summary.tested_endpoints))
                t.add_row("Untested", str(summary.untested_endpoints))
                for tt, count in sorted(summary.coverage_by_test_type.items()):
                    t.add_row(f"  {tt}", str(count))
                t.add_row("Coverage gaps", str(len(summary.gaps)))
                console.print(t)


@analyze_app.command("dedupe")
def analyze_dedupe_cmd(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Show groups without persisting")
    ] = False,
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """Deduplicate findings — group findings that share the same root cause."""
    with _managed(data_dir) as manager:
        from boba.analysis.dedup import deduplicate_findings
        from dataclasses import asdict

        groups = deduplicate_findings(manager.context, hunt_id, dry_run=dry_run)

        if not groups:
            print_info("No duplicate findings detected.")
            return

        if fmt == "json":
            format_output([asdict(g) for g in groups], fmt="json")
        else:
            from rich.table import Table

            t = Table(title=f"Dedup Groups{' (dry run)' if dry_run else ''}")
            t.add_column("Group ID")
            t.add_column("Canonical")
            t.add_column("Members")
            t.add_column("Reason")
            for g in groups:
                t.add_row(
                    str(g.id),
                    str(g.canonical_id),
                    ", ".join(str(fid) for fid in g.finding_ids),
                    g.reason,
                )
            console.print(t)
            print_info(
                f"{len(groups)} group(s) found, {sum(len(g.finding_ids) for g in groups)} findings grouped."
            )


@analyze_app.command("severity")
def analyze_severity_cmd(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    finding_id: Annotated[
        Optional[int], typer.Option("--finding-id", help="Score a single finding")
    ] = None,
    platform: Annotated[
        Optional[str],
        typer.Option("--platform", help="Include payout estimates (hackerone, bugcrowd)"),
    ] = None,
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """Score findings with CVSS 3.1 and estimate payouts."""
    with _managed(data_dir) as manager:
        from boba.analysis.severity import score_findings

        ids = [finding_id] if finding_id else None
        scored = score_findings(manager.context, hunt_id, finding_ids=ids, platform=platform)

        if not scored:
            print_info("No findings to score.")
            return

        columns = [
            "finding_id",
            "title",
            "finding_type",
            "cvss_score",
            "cvss_severity",
            "cvss_vector",
        ]
        if platform:
            columns.extend(["payout_min", "payout_max"])

        format_output(scored, fmt=fmt, columns=columns, title="Severity Assessment")


@analyze_app.command("chain")
def analyze_chain_cmd(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    finding_ids: Annotated[
        Optional[str],
        typer.Option(
            "--finding-ids", help="Suggest chains for specific finding IDs (comma-separated)"
        ),
    ] = None,
    validate: Annotated[
        Optional[int], typer.Option("--validate", help="Mark a chain ID as validated")
    ] = None,
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """Detect or suggest vulnerability chains."""
    with _managed(data_dir) as manager:
        from dataclasses import asdict

        if validate is not None:
            from boba.analysis.chaining import validate_chain

            chain = validate_chain(manager.context, hunt_id, validate)
            if chain:
                print_success(f"Chain {validate} marked as validated.")
                format_output(asdict(chain), fmt=fmt, title="Validated Chain")
            else:
                print_error(f"Chain {validate} not found.")
                raise typer.Exit(1)
            return

        if finding_ids:
            from boba.analysis.chaining import suggest_chains

            try:
                ids = [int(x.strip()) for x in finding_ids.split(",")]
            except ValueError:
                print_error("--finding-ids must be comma-separated integers (e.g., '1,2,3')")
                raise typer.Exit(1)
            chains = suggest_chains(manager.context, hunt_id, ids)
        else:
            from boba.analysis.chaining import detect_chains

            chains = detect_chains(manager.context, hunt_id)

        if not chains:
            print_info("No chains detected.")
            return

        if fmt == "json":
            format_output([asdict(c) for c in chains], fmt="json")
        else:
            from rich.table import Table

            t = Table(title="Attack Chains")
            t.add_column("ID")
            t.add_column("Severity")
            t.add_column("CVSS")
            t.add_column("Title")
            t.add_column("Findings")
            t.add_column("Confidence")
            for c in chains:
                t.add_row(
                    str(c.id),
                    c.severity.value,
                    f"{c.cvss_score:.1f}",
                    c.title,
                    ", ".join(str(fid) for fid in c.finding_ids),
                    c.confidence.value,
                )
            console.print(t)


@analyze_app.command("prioritize")
def analyze_prioritize_cmd(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    top: Annotated[Optional[int], typer.Option("--top", help="Show only top N endpoints")] = None,
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """Rank untested endpoints by vulnerability likelihood."""
    with _managed(data_dir) as manager:
        from boba.analysis.prioritize import prioritize_endpoints

        results = prioritize_endpoints(manager.context, hunt_id, top=top)

        if not results:
            print_info("No untested endpoints to prioritize.")
            return

        format_output(
            results,
            fmt=fmt,
            columns=["priority_score", "url", "method", "suggested_tests", "reasons"],
            title="Prioritized Endpoints",
        )


# ═══════════════════ REPORT COMMANDS ═══════════════════

report_app = typer.Typer(help="Report generation and management.")
app.add_typer(report_app, name="report")


@report_app.command("draft")
def report_draft_cmd(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    finding_id: Annotated[Optional[int], typer.Option("--finding-id", help="Finding ID")] = None,
    chain_id: Annotated[Optional[int], typer.Option("--chain-id", help="Chain ID")] = None,
    fmt: FormatOption = "json",
    data_dir: DataDirOption = None,
) -> None:
    """Generate a report draft from a finding or chain."""
    if not finding_id and not chain_id:
        print_error("Provide --finding-id or --chain-id")
        raise typer.Exit(1)

    with _managed(data_dir) as manager:
        from boba.reporting.draft import draft_finding_report, draft_chain_report
        from dataclasses import asdict

        if finding_id:
            draft = draft_finding_report(manager.context, hunt_id, finding_id)
        else:
            draft = draft_chain_report(manager.context, hunt_id, chain_id)

        format_output(asdict(draft), fmt=fmt, title="Report Draft")


@report_app.command("format")
def report_format_cmd(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    report_id: Annotated[int, typer.Option("--report-id", "-r", help="Report ID")],
    platform: Annotated[
        str, typer.Option("--platform", "-p", help="Platform: hackerone, bugcrowd, markdown")
    ] = "markdown",
    data_dir: DataDirOption = None,
) -> None:
    """Format a report for a specific platform."""
    with _managed(data_dir) as manager:
        from boba.reporting.formatter import format_hackerone, format_bugcrowd, format_markdown
        from boba.core.models import ReportDraft, Severity, ReportStatus

        report_data = manager.context.get_report(report_id)
        if not report_data:
            print_error(f"Report {report_id} not found")
            raise typer.Exit(1)
        if report_data["hunt_id"] != hunt_id:
            print_error(f"Report {report_id} does not belong to hunt '{hunt_id}'")
            raise typer.Exit(1)

        # Reconstruct ReportDraft from DB data
        draft = ReportDraft(
            id=report_data["id"],
            hunt_id=report_data["hunt_id"],
            finding_id=report_data.get("finding_id"),
            chain_id=report_data.get("chain_id"),
            title=report_data["title"],
            severity=Severity(report_data.get("severity", "info")),
            cvss_score=report_data.get("cvss_score") or 0.0,
            cvss_vector=report_data.get("cvss_vector") or "",
            summary=report_data.get("summary") or "",
            steps=report_data.get("steps", []),
            impact=report_data.get("impact") or "",
            remediation=report_data.get("remediation") or "",
            evidence_refs=report_data.get("evidence_refs", []),
            request_ids=report_data.get("request_ids", []),
            status=ReportStatus(report_data.get("status", "draft")),
        )

        formatters = {
            "hackerone": format_hackerone,
            "bugcrowd": format_bugcrowd,
            "markdown": format_markdown,
        }
        formatter = formatters.get(platform)
        if not formatter:
            print_error(f"Invalid platform '{platform}'. Valid: {', '.join(formatters)}")
            raise typer.Exit(1)
        console.print(formatter(draft))


@report_app.command("poc")
def report_poc_cmd(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    finding_id: Annotated[Optional[int], typer.Option("--finding-id", help="Finding ID")] = None,
    chain_id: Annotated[Optional[int], typer.Option("--chain-id", help="Chain ID")] = None,
    output_dir: Annotated[
        str, typer.Option("--output-dir", "-o", help="Output directory")
    ] = "./poc",
    data_dir: DataDirOption = None,
) -> None:
    """Package PoC evidence into a directory."""
    if not finding_id and not chain_id:
        print_error("Provide --finding-id or --chain-id")
        raise typer.Exit(1)

    with _managed(data_dir) as manager:
        from boba.reporting.poc import package_poc

        pkg = package_poc(
            manager.context,
            hunt_id,
            finding_id=finding_id,
            chain_id=chain_id,
            output_dir=output_dir,
        )
        print_success(f"PoC packaged: {len(pkg.http_dumps)} HTTP dump(s), output: {pkg.output_dir}")


@report_app.command("list")
def report_list_cmd(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    status: Annotated[Optional[str], typer.Option("--status", help="Filter by status")] = None,
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """List all reports for a hunt."""
    with _managed(data_dir) as manager:
        reports = manager.context.get_reports(hunt_id, status=status)
        format_output(
            reports,
            fmt=fmt,
            columns=["id", "title", "severity", "status", "platform", "cvss_score"],
            title="Reports",
        )


@report_app.command("show")
def report_show_cmd(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    report_id: Annotated[int, typer.Option("--report-id", "-r", help="Report ID")],
    fmt: FormatOption = "json",
    data_dir: DataDirOption = None,
) -> None:
    """Show a full report."""
    with _managed(data_dir) as manager:
        report = manager.context.get_report(report_id)
        if not report:
            print_error(f"Report {report_id} not found")
            raise typer.Exit(1)
        if report["hunt_id"] != hunt_id:
            print_error(f"Report {report_id} does not belong to hunt '{hunt_id}'")
            raise typer.Exit(1)
        format_output(report, fmt=fmt, title="Report")


# ═══════════════════ TEST COMMANDS ═══════════════════

test_app = typer.Typer(help="Vulnerability testing tools.")
app.add_typer(test_app, name="test")


@test_app.command("idor")
def test_idor_cmd(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    endpoint: Annotated[str, typer.Option("--endpoint", "-e", help="Endpoint URL")],
    session_a: Annotated[str, typer.Option("--session-a", help="Owner session name")],
    session_b: Annotated[str, typer.Option("--session-b", help="Attacker session name")],
    method: Annotated[str, typer.Option("--method", "-m", help="HTTP method")] = "GET",
    fmt: FormatOption = "json",
    data_dir: DataDirOption = None,
) -> None:
    """Test for Insecure Direct Object Reference (IDOR)."""
    with _managed_http(data_dir, hunt_id) as (manager, client):
        from boba.tools import vuln
        from dataclasses import asdict

        sess_mgr = _get_session_manager(manager, hunt_id)
        sa = sess_mgr.get(session_a)
        sb = sess_mgr.get(session_b)
        if not sa or not sb:
            print_error("Session not found")
            raise typer.Exit(1)

        result = asyncio.run(
            vuln.test_idor(
                client,
                sa,
                sb,
                endpoint,
                method,
                context=manager.context,
                hunt_id=hunt_id,
            )
        )
        format_output(asdict(result), fmt=fmt, title="IDOR Test Result")


@test_app.command("ssrf")
def test_ssrf_cmd(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    url: Annotated[str, typer.Option("--url", "-u", help="Target URL")],
    param: Annotated[str, typer.Option("--param", "-p", help="Parameter name")] = "url",
    method: Annotated[str, typer.Option("--method", "-m", help="HTTP method")] = "GET",
    fmt: FormatOption = "json",
    data_dir: DataDirOption = None,
) -> None:
    """Test for Server-Side Request Forgery (SSRF)."""
    with _managed_http(data_dir, hunt_id) as (manager, client):
        from boba.tools import vuln
        from dataclasses import asdict

        result = asyncio.run(
            vuln.test_ssrf(
                client,
                url,
                method,
                injection_points=[{"location": "url_param", "name": param}],
                context=manager.context,
                hunt_id=hunt_id,
            )
        )
        format_output(asdict(result), fmt=fmt, title="SSRF Test Result")


@test_app.command("xss")
def test_xss_cmd(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    url: Annotated[str, typer.Option("--url", "-u", help="Target URL")],
    param: Annotated[str, typer.Option("--param", "-p", help="Parameter name")] = "q",
    method: Annotated[str, typer.Option("--method", "-m", help="HTTP method")] = "GET",
    fmt: FormatOption = "json",
    data_dir: DataDirOption = None,
) -> None:
    """Test for Cross-Site Scripting (XSS)."""
    with _managed_http(data_dir, hunt_id) as (manager, client):
        from boba.tools import vuln
        from dataclasses import asdict

        result = asyncio.run(
            vuln.test_xss(
                client,
                url,
                method,
                params={param: ""},
                context=manager.context,
                hunt_id=hunt_id,
            )
        )
        format_output(asdict(result), fmt=fmt, title="XSS Test Result")


@test_app.command("sqli")
def test_sqli_cmd(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    url: Annotated[str, typer.Option("--url", "-u", help="Target URL")],
    param: Annotated[str, typer.Option("--param", "-p", help="Parameter name")] = "id",
    method: Annotated[str, typer.Option("--method", "-m", help="HTTP method")] = "GET",
    fmt: FormatOption = "json",
    data_dir: DataDirOption = None,
) -> None:
    """Test for SQL Injection."""
    with _managed_http(data_dir, hunt_id) as (manager, client):
        from boba.tools import vuln
        from dataclasses import asdict

        result = asyncio.run(
            vuln.test_sqli(
                client,
                url,
                method,
                params={param: "1"},
                context=manager.context,
                hunt_id=hunt_id,
            )
        )
        format_output(asdict(result), fmt=fmt, title="SQLi Test Result")


@test_app.command("auth")
def test_auth_cmd(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    endpoint: Annotated[str, typer.Option("--endpoint", "-e", help="Endpoint URL")],
    jwt: Annotated[Optional[str], typer.Option("--jwt", help="JWT token to test")] = None,
    fmt: FormatOption = "json",
    data_dir: DataDirOption = None,
) -> None:
    """Test authentication/authorization controls."""
    with _managed_http(data_dir, hunt_id) as (manager, client):
        from boba.tools import vuln
        from dataclasses import asdict

        result = asyncio.run(
            vuln.test_auth(
                client,
                endpoint,
                jwt_token=jwt,
                context=manager.context,
                hunt_id=hunt_id,
            )
        )
        format_output(asdict(result), fmt=fmt, title="Auth Test Result")


@test_app.command("race")
def test_race_cmd(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    url: Annotated[str, typer.Option("--url", "-u", help="Target URL")],
    method: Annotated[str, typer.Option("--method", "-m", help="HTTP method")] = "POST",
    body: Annotated[Optional[str], typer.Option("--body", "-b", help="Request body")] = None,
    concurrency: Annotated[
        int, typer.Option("--concurrency", "-c", help="Concurrent requests")
    ] = 10,
    session_name: Annotated[str, typer.Option("--session", "-s", help="Session name")] = "",
    fmt: FormatOption = "json",
    data_dir: DataDirOption = None,
) -> None:
    """Test for race conditions."""
    with _managed_http(data_dir, hunt_id) as (manager, client):
        from boba.tools import vuln
        from boba.core.models import SessionState
        from dataclasses import asdict

        sess = SessionState(name=session_name or "default", target_url=url)
        if session_name:
            sess_mgr = _get_session_manager(manager, hunt_id)
            s = sess_mgr.get(session_name)
            if not s:
                print_error(f"Session '{session_name}' not found")
                raise typer.Exit(1)
            sess = s

        result = asyncio.run(
            vuln.test_race(
                client,
                sess,
                url,
                method,
                body,
                concurrency,
                context=manager.context,
                hunt_id=hunt_id,
            )
        )
        format_output(asdict(result), fmt=fmt, title="Race Condition Test Result")


@test_app.command("redirect")
def test_redirect_cmd(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    url: Annotated[str, typer.Option("--url", "-u", help="Target URL")],
    param: Annotated[str, typer.Option("--param", "-p", help="Parameter name")] = "next",
    fmt: FormatOption = "json",
    data_dir: DataDirOption = None,
) -> None:
    """Test for open redirect."""
    with _managed_http(data_dir, hunt_id) as (manager, client):
        from boba.tools import vuln
        from dataclasses import asdict

        result = asyncio.run(
            vuln.test_redirect(
                client,
                url,
                param,
                context=manager.context,
                hunt_id=hunt_id,
            )
        )
        format_output(asdict(result), fmt=fmt, title="Redirect Test Result")


@test_app.command("csrf")
def test_csrf_cmd(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    url: Annotated[str, typer.Option("--url", "-u", help="Target URL")],
    session_name: Annotated[str, typer.Option("--session", "-s", help="Session name")],
    method: Annotated[str, typer.Option("--method", "-m", help="HTTP method")] = "POST",
    body: Annotated[Optional[str], typer.Option("--body", "-b", help="Request body")] = None,
    fmt: FormatOption = "json",
    data_dir: DataDirOption = None,
) -> None:
    """Test for Cross-Site Request Forgery."""
    with _managed_http(data_dir, hunt_id) as (manager, client):
        from boba.tools import vuln
        from dataclasses import asdict

        sess_mgr = _get_session_manager(manager, hunt_id)
        sess = sess_mgr.get(session_name)
        if not sess:
            print_error(f"Session '{session_name}' not found")
            raise typer.Exit(1)

        result = asyncio.run(
            vuln.test_csrf(
                client,
                sess,
                url,
                method,
                body,
                context=manager.context,
                hunt_id=hunt_id,
            )
        )
        format_output(asdict(result), fmt=fmt, title="CSRF Test Result")


@test_app.command("mass-assign")
def test_mass_assign_cmd(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    url: Annotated[str, typer.Option("--url", "-u", help="Target URL")],
    session_name: Annotated[str, typer.Option("--session", "-s", help="Session name")],
    method: Annotated[str, typer.Option("--method", "-m", help="HTTP method")] = "PUT",
    fmt: FormatOption = "json",
    data_dir: DataDirOption = None,
) -> None:
    """Test for mass assignment."""
    with _managed_http(data_dir, hunt_id) as (manager, client):
        from boba.tools import vuln
        from dataclasses import asdict

        sess_mgr = _get_session_manager(manager, hunt_id)
        sess = sess_mgr.get(session_name)
        if not sess:
            print_error(f"Session '{session_name}' not found")
            raise typer.Exit(1)

        result = asyncio.run(
            vuln.test_mass_assign(
                client,
                sess,
                url,
                method,
                context=manager.context,
                hunt_id=hunt_id,
            )
        )
        format_output(asdict(result), fmt=fmt, title="Mass Assignment Test Result")


@test_app.command("reset")
def test_reset_cmd(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    url: Annotated[str, typer.Option("--url", "-u", help="Reset endpoint URL")],
    email_param: Annotated[
        str, typer.Option("--email-param", help="Email parameter name")
    ] = "email",
    fmt: FormatOption = "json",
    data_dir: DataDirOption = None,
) -> None:
    """Test password reset flow."""
    with _managed_http(data_dir, hunt_id) as (manager, client):
        from boba.tools import vuln
        from dataclasses import asdict

        result = asyncio.run(
            vuln.test_reset(
                client,
                url,
                email_param,
                context=manager.context,
                hunt_id=hunt_id,
            )
        )
        format_output(asdict(result), fmt=fmt, title="Password Reset Test Result")


@test_app.command("ai")
def test_ai_cmd(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    url: Annotated[str, typer.Option("--url", "-u", help="Target URL")],
    param: Annotated[str, typer.Option("--param", "-p", help="Parameter name")] = "message",
    fmt: FormatOption = "json",
    data_dir: DataDirOption = None,
) -> None:
    """Test for AI/LLM prompt injection."""
    with _managed_http(data_dir, hunt_id) as (manager, client):
        from boba.tools import vuln
        from dataclasses import asdict

        result = asyncio.run(
            vuln.test_ai(
                client,
                url,
                param,
                context=manager.context,
                hunt_id=hunt_id,
            )
        )
        format_output(asdict(result), fmt=fmt, title="AI Prompt Injection Test Result")


# ═══════════════════ CONTEXT EXTENSIONS ═══════════════════


@context_app.command("http-history")
def ctx_http_history(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    host: Annotated[Optional[str], typer.Option("--host", help="Filter by host")] = None,
    method: Annotated[Optional[str], typer.Option("--method", help="Filter by method")] = None,
    status: Annotated[Optional[int], typer.Option("--status", help="Filter by status code")] = None,
    source: Annotated[Optional[str], typer.Option("--source", help="Filter by source")] = None,
    limit: Annotated[int, typer.Option("--limit", help="Max results")] = 100,
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """Query HTTP history."""
    with _managed(data_dir) as manager:
        records = manager.context.query_http_history(
            hunt_id,
            host=host,
            method=method,
            status_code=status,
            source=source,
            limit=limit,
        )
        # For table display, strip verbose fields; for JSON, keep everything
        # so machine consumers (agents) get the full record.
        if fmt == "table":
            for r in records:
                r.pop("request_headers", None)
                r.pop("response_headers", None)
                r.pop("request_body", None)
                r.pop("response_body", None)
                r.pop("request_body_ref", None)
                r.pop("response_body_ref", None)
        format_output(
            records,
            fmt=fmt,
            columns=["id", "method", "url", "status_code", "source", "elapsed_ms", "session_name"],
            title="HTTP History",
        )


@context_app.command("findings")
def ctx_findings(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    type_: Annotated[Optional[str], typer.Option("--type", help="Filter by finding type")] = None,
    severity: Annotated[
        Optional[str], typer.Option("--severity", help="Filter by severity")
    ] = None,
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """List vulnerability findings."""
    with _managed(data_dir) as manager:
        records = manager.context.get_findings(hunt_id, finding_type=type_, severity=severity)
        format_output(
            records,
            fmt=fmt,
            columns=["finding_type", "severity", "title", "url", "confirmed"],
            title="Findings",
        )


@context_app.command("sessions")
def ctx_sessions(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """List active sessions."""
    with _managed(data_dir) as manager:
        records = manager.context.get_sessions(hunt_id)
        format_output(
            records,
            fmt=fmt,
            columns=["name", "target_url", "auth_method", "is_valid", "last_used_at"],
            title="Sessions",
        )


@context_app.command("oob")
def ctx_oob(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """List OOB listeners and interactions."""
    with _managed(data_dir) as manager:
        records = manager.context.get_oob_listeners(hunt_id)
        format_output(
            records,
            fmt=fmt,
            columns=["listener_id", "callback_domain", "purpose", "target_url", "parameter"],
            title="OOB Listeners",
        )


if __name__ == "__main__":
    app()
