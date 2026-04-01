"""Boba CLI — Typer-based command interface for agents and humans."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated, Optional

import typer

from boba.cli.formatters import console, format_output, print_error, print_info, print_success
from boba.core.config import get_db_path

app = typer.Typer(
    name="boba",
    help="Agent-native bug bounty hunting framework.",
    no_args_is_help=True,
)

# ═══════════════════ Global options ═══════════════════

FormatOption = Annotated[
    str, typer.Option("--format", "-f", help="Output format: json or table")
]
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
    except Exception:
        pass


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
    except Exception:
        pass


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
    manager = _get_manager(data_dir)
    try:
        hunt = manager.create(name=name, scope_yaml=scope)
        if fmt == "json":
            format_output(
                {"id": hunt.id, "name": hunt.name, "status": hunt.status.value}, fmt="json"
            )
        else:
            print_success(f"Hunt created: {hunt.id}")
            console.print(f"  Name: {hunt.name}")
            console.print(f"  Scope rules: {len(hunt.scope.rules)}")
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(1)
    finally:
        _safe_close(manager)


@hunt_app.command("list")
def hunt_list(fmt: FormatOption = "table", data_dir: DataDirOption = None) -> None:
    """List all hunts."""
    manager = _get_manager(data_dir)
    try:
        hunts = manager.list_hunts()
        records = [
            {"id": h.id, "name": h.name, "status": h.status.value, "created_at": str(h.created_at)}
            for h in hunts
        ]
        format_output(records, fmt=fmt, title="Hunts")
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(1)
    finally:
        _safe_close(manager)


@hunt_app.command("status")
def hunt_status(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """Show hunt status and statistics."""
    manager = _get_manager(data_dir)
    try:
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
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(1)
    finally:
        _safe_close(manager)


@hunt_app.command("pause")
def hunt_pause(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    data_dir: DataDirOption = None,
) -> None:
    """Pause a hunt."""
    manager = _get_manager(data_dir)
    try:
        manager.pause(hunt_id)
        print_success(f"Hunt {hunt_id} paused.")
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(1)
    finally:
        _safe_close(manager)


@hunt_app.command("resume")
def hunt_resume(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    data_dir: DataDirOption = None,
) -> None:
    """Resume a paused hunt."""
    manager = _get_manager(data_dir)
    try:
        manager.resume(hunt_id)
        print_success(f"Hunt {hunt_id} resumed.")
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(1)
    finally:
        _safe_close(manager)


@hunt_app.command("close")
def hunt_close(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    data_dir: DataDirOption = None,
) -> None:
    """Close/complete a hunt."""
    manager = _get_manager(data_dir)
    try:
        manager.close(hunt_id)
        print_success(f"Hunt {hunt_id} closed.")
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(1)
    finally:
        _safe_close(manager)


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
    manager = _get_manager(data_dir)
    try:
        from boba.tools import recon

        hunt = manager.get(hunt_id)
        result = asyncio.run(recon.subdomains(manager.context, hunt, domain))
        if fmt == "json":
            format_output(
                {"tool": "subfinder", "found": len(result.records),
                 "filtered": result.filtered_count, "records": result.records},
                fmt="json",
            )
        else:
            format_output(result.records, fmt="table", title="Subdomains")
            print_info(
                f"Found {len(result.records)} subdomains "
                f"({result.filtered_count} filtered out-of-scope)"
            )
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(1)
    finally:
        _safe_close(manager)


@recon_app.command("hosts")
def recon_hosts(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    targets: Annotated[Optional[str], typer.Option("--targets", "-t", help="Comma-separated hosts")] = None,
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """Check which subdomains are live using httpx."""
    manager = _get_manager(data_dir)
    try:
        from boba.tools import recon

        hunt = manager.get(hunt_id)
        target_list = [t.strip() for t in targets.split(",")] if targets else None
        result = asyncio.run(recon.hosts(manager.context, hunt, target_list))
        if fmt == "json":
            format_output(
                {"tool": "httpx", "found": len(result.records), "records": result.records},
                fmt="json",
            )
        else:
            format_output(
                result.records, fmt="table",
                columns=["host", "status_code", "title", "webserver", "technologies"],
                title="Live Hosts",
            )
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(1)
    finally:
        _safe_close(manager)


@recon_app.command("ports")
def recon_ports(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    targets: Annotated[Optional[str], typer.Option("--targets", "-t", help="Comma-separated hosts")] = None,
    range_: Annotated[Optional[str], typer.Option("--range", "-r", help="Port range (e.g., 1-1000)")] = None,
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """Port scan live hosts using naabu."""
    manager = _get_manager(data_dir)
    try:
        from boba.tools import recon

        hunt = manager.get(hunt_id)
        target_list = [t.strip() for t in targets.split(",")] if targets else None
        result = asyncio.run(recon.ports(manager.context, hunt, target_list, range_))
        if fmt == "json":
            format_output(
                {"tool": "naabu", "found": len(result.records), "records": result.records},
                fmt="json",
            )
        else:
            format_output(result.records, fmt="table", title="Open Ports")
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(1)
    finally:
        _safe_close(manager)


@recon_app.command("urls")
def recon_urls(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    domain: Annotated[list[str], typer.Option("--domain", "-d", help="Target domain(s)")],
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """Discover historical URLs using gau + waybackurls."""
    manager = _get_manager(data_dir)
    try:
        from boba.tools import recon

        hunt = manager.get(hunt_id)
        result = asyncio.run(recon.urls(manager.context, hunt, domain))
        if fmt == "json":
            format_output(
                {"tool": "recon.urls", "found": len(result.records),
                 "filtered": result.filtered_count, "records": result.records},
                fmt="json",
            )
        else:
            format_output(
                result.records, fmt="table",
                columns=["url", "host", "path", "source"],
                title="Discovered URLs",
            )
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(1)
    finally:
        _safe_close(manager)


@recon_app.command("tech")
def recon_tech(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    targets: Annotated[Optional[str], typer.Option("--targets", "-t", help="Comma-separated URLs")] = None,
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """Fingerprint technologies using whatweb."""
    manager = _get_manager(data_dir)
    try:
        from boba.tools import recon

        hunt = manager.get(hunt_id)
        target_list = [t.strip() for t in targets.split(",")] if targets else None
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
                    rows.append({
                        "host": record.get("host", ""),
                        "technology": t.get("name", ""),
                        "version": t.get("version", ""),
                    })
            format_output(rows, fmt="table", title="Technologies")
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(1)
    finally:
        _safe_close(manager)


# ═══════════════════ ENUM COMMANDS ═══════════════════

enum_app = typer.Typer(help="Enumeration tools.")
app.add_typer(enum_app, name="enum")


@enum_app.command("directories")
def enum_directories(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    url: Annotated[str, typer.Option("--url", "-u", help="Target URL (FUZZ keyword optional)")],
    wordlist: Annotated[Optional[str], typer.Option("--wordlist", "-w", help="Wordlist path")] = None,
    match_codes: Annotated[str, typer.Option("--match-codes", "-mc", help="Status codes to match")] = "200,301,302,403",
    extensions: Annotated[Optional[str], typer.Option("--extensions", "-e", help="File extensions (comma-separated)")] = None,
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """Fuzz for directories and files using ffuf."""
    manager = _get_manager(data_dir)
    try:
        from boba.tools import enum

        hunt = manager.get(hunt_id)
        ext_list = [e.strip() for e in extensions.split(",")] if extensions else None
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
                result.records, fmt="table",
                columns=["url", "status_code", "content_length", "content_type"],
                title="Directories",
            )
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(1)
    finally:
        _safe_close(manager)


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
    manager = _get_manager(data_dir)
    try:
        records = manager.context.get_subdomains(hunt_id)
        format_output(records, fmt=fmt, title="Subdomains")
    finally:
        _safe_close(manager)


@context_app.command("hosts")
def ctx_hosts(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    alive_only: Annotated[bool, typer.Option("--alive-only", help="Only show live hosts")] = False,
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """List discovered hosts."""
    manager = _get_manager(data_dir)
    try:
        records = manager.context.get_hosts(hunt_id, alive_only=alive_only)
        format_output(
            records, fmt=fmt,
            columns=["host", "ip", "port", "scheme", "status_code", "title", "webserver"],
            title="Hosts",
        )
    finally:
        _safe_close(manager)


@context_app.command("ports")
def ctx_ports(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    host: Annotated[Optional[str], typer.Option("--host", help="Filter by host")] = None,
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """List discovered ports."""
    manager = _get_manager(data_dir)
    try:
        records = manager.context.get_ports(hunt_id, host=host)
        format_output(records, fmt=fmt, title="Ports")
    finally:
        _safe_close(manager)


@context_app.command("urls")
def ctx_urls(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    host: Annotated[Optional[str], typer.Option("--host", help="Filter by host")] = None,
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """List discovered URLs."""
    manager = _get_manager(data_dir)
    try:
        records = manager.context.get_urls(hunt_id, host=host)
        format_output(
            records, fmt=fmt, columns=["url", "method", "status_code", "sources"], title="URLs"
        )
    finally:
        _safe_close(manager)


@context_app.command("tech")
def ctx_tech(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    host: Annotated[Optional[str], typer.Option("--host", help="Filter by host")] = None,
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """List discovered technologies."""
    manager = _get_manager(data_dir)
    try:
        records = manager.context.get_technologies(hunt_id, host=host)
        format_output(records, fmt=fmt, title="Technologies")
    finally:
        _safe_close(manager)


@context_app.command("directories")
def ctx_directories(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    url_prefix: Annotated[Optional[str], typer.Option("--url-prefix", help="Filter by URL prefix")] = None,
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """List discovered directories."""
    manager = _get_manager(data_dir)
    try:
        records = manager.context.get_directories(hunt_id, url_prefix=url_prefix)
        format_output(
            records, fmt=fmt,
            columns=["url", "status_code", "content_length", "content_type"],
            title="Directories",
        )
    finally:
        _safe_close(manager)


@context_app.command("runs")
def ctx_runs(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """List tool run history."""
    manager = _get_manager(data_dir)
    try:
        records = manager.context.get_tool_runs(hunt_id)
        format_output(
            records, fmt=fmt,
            columns=["tool_name", "status", "duration_seconds", "records_found", "records_filtered", "started_at"],
            title="Tool Runs",
        )
    finally:
        _safe_close(manager)


@context_app.command("stats")
def ctx_stats(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """Show hunt statistics."""
    manager = _get_manager(data_dir)
    try:
        stats = manager.stats(hunt_id)
        format_output(stats, fmt=fmt, title="Hunt Statistics")
    finally:
        _safe_close(manager)


# ═══════════════════ BROWSER COMMANDS ═══════════════════

browser_app = typer.Typer(help="Browser automation (Playwright).")
app.add_typer(browser_app, name="browser")


@browser_app.command("navigate")
def browser_navigate(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    url: Annotated[str, typer.Option("--url", "-u", help="URL to navigate to")],
    context_name: Annotated[str, typer.Option("--context", "-c", help="Browser context name")] = "default",
    wait_until: Annotated[str, typer.Option("--wait-until", help="Wait condition")] = "networkidle",
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """Navigate to a URL and capture traffic."""
    manager = _get_manager(data_dir)
    try:
        from boba.core.models import BrowserConfig
        from boba.interaction.browser import BrowserManager
        from boba.interaction.history import HttpHistorySink

        manager.get(hunt_id)
        sink = HttpHistorySink(manager.context, hunt_id)
        config = BrowserConfig(headless=True)
        browser = BrowserManager(config, sink)

        async def _run():
            await browser.start()
            try:
                info = await browser.navigate(url, context_name, wait_until)
                return info
            finally:
                await browser.stop()

        info = asyncio.run(_run())
        data = {
            "url": info.url, "final_url": info.final_url,
            "status_code": info.status_code, "title": info.title,
            "content_type": info.content_type, "timing_ms": info.timing_ms,
            "requests_captured": info.requests_captured,
        }
        format_output(data, fmt=fmt, title="Navigation Result")
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(1)
    finally:
        _safe_close(manager)


@browser_app.command("screenshot")
def browser_screenshot(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    path: Annotated[str, typer.Option("--path", "-p", help="Screenshot file path")],
    url: Annotated[str, typer.Option("--url", "-u", help="URL to screenshot")],
    full_page: Annotated[bool, typer.Option("--full-page", help="Capture full page")] = True,
    data_dir: DataDirOption = None,
) -> None:
    """Take a screenshot of a web page."""
    manager = _get_manager(data_dir)
    try:
        from boba.core.models import BrowserConfig
        from boba.interaction.browser import BrowserManager
        from boba.interaction.history import HttpHistorySink

        manager.get(hunt_id)
        sink = HttpHistorySink(manager.context, hunt_id)
        config = BrowserConfig(headless=True)
        browser = BrowserManager(config, sink)

        async def _run():
            await browser.start()
            try:
                await browser.navigate(url)
                return await browser.screenshot(path, full_page=full_page)
            finally:
                await browser.stop()

        result_path = asyncio.run(_run())
        print_success(f"Screenshot saved: {result_path}")
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(1)
    finally:
        _safe_close(manager)


@browser_app.command("extract")
def browser_extract(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    url: Annotated[str, typer.Option("--url", "-u", help="URL to extract from")],
    fmt: FormatOption = "json",
    data_dir: DataDirOption = None,
) -> None:
    """Extract structured DOM data from a page."""
    manager = _get_manager(data_dir)
    try:
        from boba.core.models import BrowserConfig
        from boba.interaction.browser import BrowserManager
        from boba.interaction.history import HttpHistorySink
        from dataclasses import asdict

        manager.get(hunt_id)
        sink = HttpHistorySink(manager.context, hunt_id)
        config = BrowserConfig(headless=True)
        browser = BrowserManager(config, sink)

        async def _run():
            await browser.start()
            try:
                await browser.navigate(url)
                return await browser.extract()
            finally:
                await browser.stop()

        dom = asyncio.run(_run())
        format_output(asdict(dom), fmt=fmt, title="DOM Extraction")
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(1)
    finally:
        _safe_close(manager)


# ═══════════════════ HTTP COMMANDS ═══════════════════

http_app = typer.Typer(help="HTTP request tools (Repeater/Intruder).")
app.add_typer(http_app, name="http")


@http_app.command("request")
def http_request(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    url: Annotated[str, typer.Option("--url", "-u", help="Target URL")],
    method: Annotated[str, typer.Option("--method", "-m", help="HTTP method")] = "GET",
    header: Annotated[Optional[list[str]], typer.Option("--header", "-H", help="Header (KEY:VALUE)")] = None,
    body: Annotated[Optional[str], typer.Option("--body", "-b", help="Request body")] = None,
    fmt: FormatOption = "json",
    data_dir: DataDirOption = None,
) -> None:
    """Send a crafted HTTP request."""
    manager = _get_manager(data_dir)
    client = None
    try:
        from boba.interaction.history import HttpHistorySink
        from boba.interaction.http import HttpClient

        manager.get(hunt_id)
        sink = HttpHistorySink(manager.context, hunt_id)
        client = HttpClient(sink)

        headers = {}
        if header:
            for h in header:
                if ":" not in h:
                    print_error(f"Invalid header format: '{h}' (expected KEY:VALUE)")
                    raise typer.Exit(1)
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()

        resp = asyncio.run(client.request(
            method=method, url=url, headers=headers or None, body=body,
        ))
        data = {
            "request_id": resp.request_id,
            "status_code": resp.status_code,
            "body_length": len(resp.body),
            "elapsed_ms": resp.elapsed_ms,
            "body_preview": resp.body_text[:500],
        }
        format_output(data, fmt=fmt, title="HTTP Response")
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(1)
    finally:
        _safe_close_http(client)
        _safe_close(manager)


@http_app.command("replay")
def http_replay(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    request_id: Annotated[int, typer.Option("--request-id", help="ID from http_history")],
    modify_header: Annotated[Optional[list[str]], typer.Option("--modify-header", help="Override header (KEY:VALUE)")] = None,
    modify_body: Annotated[Optional[str], typer.Option("--modify-body", help="Override body")] = None,
    fmt: FormatOption = "json",
    data_dir: DataDirOption = None,
) -> None:
    """Replay a request from HTTP history with modifications."""
    manager = _get_manager(data_dir)
    client = None
    try:
        from boba.interaction.history import HttpHistorySink
        from boba.interaction.http import HttpClient

        manager.get(hunt_id)
        sink = HttpHistorySink(manager.context, hunt_id)
        client = HttpClient(sink)

        modifications: dict = {}
        if modify_header:
            headers = {}
            for h in modify_header:
                if ":" not in h:
                    print_error(f"Invalid header format: '{h}' (expected KEY:VALUE)")
                    raise typer.Exit(1)
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()
            modifications["headers"] = headers
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
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(1)
    finally:
        _safe_close_http(client)
        _safe_close(manager)


@http_app.command("compare")
def http_compare(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    id_a: Annotated[int, typer.Option("--id-a", help="First response ID")],
    id_b: Annotated[int, typer.Option("--id-b", help="Second response ID")],
    fmt: FormatOption = "json",
    data_dir: DataDirOption = None,
) -> None:
    """Compare two HTTP responses."""
    manager = _get_manager(data_dir)
    client = None
    try:
        from boba.interaction.history import HttpHistorySink
        from boba.interaction.http import HttpClient
        from dataclasses import asdict

        manager.get(hunt_id)
        sink = HttpHistorySink(manager.context, hunt_id)
        client = HttpClient(sink)

        result = asyncio.run(client.compare(id_a, id_b))
        format_output(asdict(result), fmt=fmt, title="Response Comparison")
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(1)
    finally:
        _safe_close_http(client)
        _safe_close(manager)


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
    manager = _get_manager(data_dir)
    try:
        from boba.core.models import AuthMethod
        from boba.interaction.session import SessionManager

        try:
            auth_method = AuthMethod(method)
        except ValueError:
            valid = [m.value for m in AuthMethod]
            print_error(f"Invalid auth method '{method}'. Valid: {valid}")
            raise typer.Exit(1)
        manager.get(hunt_id)
        mgr = SessionManager(manager.context, hunt_id)
        state = mgr.create(name, target, auth_method)
        if fmt == "json":
            format_output({"name": state.name, "target_url": state.target_url,
                           "auth_method": state.auth_method.value}, fmt="json")
        else:
            print_success(f"Session '{name}' created for {target}")
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(1)
    finally:
        _safe_close(manager)


@session_app.command("login-token")
def session_login_token(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    name: Annotated[str, typer.Argument(help="Session name")],
    token: Annotated[str, typer.Option("--token", "-t", help="Bearer token")],
    data_dir: DataDirOption = None,
) -> None:
    """Set a Bearer token on a session."""
    manager = _get_manager(data_dir)
    try:
        from boba.interaction.session import SessionManager

        manager.get(hunt_id)
        mgr = SessionManager(manager.context, hunt_id)
        mgr.login_bearer(name, token)
        print_success(f"Bearer token set on session '{name}'")
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(1)
    finally:
        _safe_close(manager)


@session_app.command("list")
def session_list(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """List all sessions."""
    manager = _get_manager(data_dir)
    try:
        from boba.interaction.session import SessionManager

        manager.get(hunt_id)
        mgr = SessionManager(manager.context, hunt_id)
        sessions = mgr.list_sessions()
        records = [
            {"name": s.name, "target_url": s.target_url,
             "auth_method": s.auth_method.value, "is_valid": s.is_valid}
            for s in sessions
        ]
        format_output(records, fmt=fmt, title="Sessions")
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(1)
    finally:
        _safe_close(manager)


@session_app.command("delete")
def session_delete(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    name: Annotated[str, typer.Argument(help="Session name")],
    data_dir: DataDirOption = None,
) -> None:
    """Delete a session."""
    manager = _get_manager(data_dir)
    try:
        from boba.interaction.session import SessionManager

        manager.get(hunt_id)
        mgr = SessionManager(manager.context, hunt_id)
        mgr.delete(name)
        print_success(f"Session '{name}' deleted")
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(1)
    finally:
        _safe_close(manager)


# ═══════════════════ SCAN COMMANDS ═══════════════════

scan_app = typer.Typer(help="Vulnerability scanning tools.")
app.add_typer(scan_app, name="scan")


@scan_app.command("nuclei")
def scan_nuclei(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    targets: Annotated[Optional[str], typer.Option("--targets", "-t", help="Comma-separated URLs")] = None,
    severity: Annotated[Optional[str], typer.Option("--severity", "-s", help="Severity filter (e.g., high,critical)")] = None,
    tags: Annotated[Optional[str], typer.Option("--tags", help="Tag filter (e.g., cve,exposure)")] = None,
    templates: Annotated[Optional[str], typer.Option("--templates", help="Custom templates directory")] = None,
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """Run Nuclei vulnerability scanner."""
    manager = _get_manager(data_dir)
    try:
        from boba.tools import scan

        hunt = manager.get(hunt_id)
        target_list = [t.strip() for t in targets.split(",")] if targets else None
        result = asyncio.run(scan.nuclei_scan(
            manager.context, hunt, target_list, severity, tags, templates,
        ))
        if fmt == "json":
            format_output(
                {"tool": "nuclei", "found": len(result.records), "records": result.records},
                fmt="json",
            )
        else:
            format_output(
                result.records, fmt="table",
                columns=["template_id", "severity", "url", "template_name"],
                title="Nuclei Findings",
            )
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(1)
    finally:
        _safe_close(manager)


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
    manager = _get_manager(data_dir)
    client = None
    try:
        from boba.interaction.history import HttpHistorySink
        from boba.interaction.http import HttpClient
        from boba.interaction.session import SessionManager
        from boba.tools import vuln
        from dataclasses import asdict

        manager.get(hunt_id)
        sink = HttpHistorySink(manager.context, hunt_id)
        client = HttpClient(sink)
        sess_mgr = SessionManager(manager.context, hunt_id)
        sa = sess_mgr.get(session_a)
        sb = sess_mgr.get(session_b)
        if not sa or not sb:
            print_error("Session not found")
            raise typer.Exit(1)

        result = asyncio.run(vuln.test_idor(client, sa, sb, endpoint, method))
        format_output(asdict(result), fmt=fmt, title="IDOR Test Result")
    except typer.Exit:
        raise
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(1)
    finally:
        _safe_close_http(client)
        _safe_close(manager)


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
    manager = _get_manager(data_dir)
    client = None
    try:
        from boba.interaction.history import HttpHistorySink
        from boba.interaction.http import HttpClient
        from boba.tools import vuln
        from dataclasses import asdict

        manager.get(hunt_id)
        sink = HttpHistorySink(manager.context, hunt_id)
        client = HttpClient(sink)

        result = asyncio.run(vuln.test_ssrf(
            client, url, method,
            injection_points=[{"location": "url_param", "name": param}],
        ))
        format_output(asdict(result), fmt=fmt, title="SSRF Test Result")
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(1)
    finally:
        _safe_close_http(client)
        _safe_close(manager)


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
    manager = _get_manager(data_dir)
    client = None
    try:
        from boba.interaction.history import HttpHistorySink
        from boba.interaction.http import HttpClient
        from boba.tools import vuln
        from dataclasses import asdict

        manager.get(hunt_id)
        sink = HttpHistorySink(manager.context, hunt_id)
        client = HttpClient(sink)

        result = asyncio.run(vuln.test_xss(
            client, url, method, params={param: ""},
        ))
        format_output(asdict(result), fmt=fmt, title="XSS Test Result")
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(1)
    finally:
        _safe_close_http(client)
        _safe_close(manager)


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
    manager = _get_manager(data_dir)
    client = None
    try:
        from boba.interaction.history import HttpHistorySink
        from boba.interaction.http import HttpClient
        from boba.tools import vuln
        from dataclasses import asdict

        manager.get(hunt_id)
        sink = HttpHistorySink(manager.context, hunt_id)
        client = HttpClient(sink)

        result = asyncio.run(vuln.test_sqli(
            client, url, method, params={param: "1"},
        ))
        format_output(asdict(result), fmt=fmt, title="SQLi Test Result")
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(1)
    finally:
        _safe_close_http(client)
        _safe_close(manager)


@test_app.command("auth")
def test_auth_cmd(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    endpoint: Annotated[str, typer.Option("--endpoint", "-e", help="Endpoint URL")],
    jwt: Annotated[Optional[str], typer.Option("--jwt", help="JWT token to test")] = None,
    fmt: FormatOption = "json",
    data_dir: DataDirOption = None,
) -> None:
    """Test authentication/authorization controls."""
    manager = _get_manager(data_dir)
    client = None
    try:
        from boba.interaction.history import HttpHistorySink
        from boba.interaction.http import HttpClient
        from boba.tools import vuln
        from dataclasses import asdict

        manager.get(hunt_id)
        sink = HttpHistorySink(manager.context, hunt_id)
        client = HttpClient(sink)

        result = asyncio.run(vuln.test_auth(client, endpoint, jwt_token=jwt))
        format_output(asdict(result), fmt=fmt, title="Auth Test Result")
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(1)
    finally:
        _safe_close_http(client)
        _safe_close(manager)


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
    manager = _get_manager(data_dir)
    try:
        records = manager.context.query_http_history(
            hunt_id, host=host, method=method, status_code=status,
            source=source, limit=limit,
        )
        # Simplify for display
        for r in records:
            r.pop("request_headers", None)
            r.pop("response_headers", None)
            r.pop("request_body", None)
            r.pop("response_body", None)
            r.pop("request_body_ref", None)
            r.pop("response_body_ref", None)
        format_output(
            records, fmt=fmt,
            columns=["id", "method", "url", "status_code", "source", "elapsed_ms", "session_name"],
            title="HTTP History",
        )
    finally:
        _safe_close(manager)


@context_app.command("findings")
def ctx_findings(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    type_: Annotated[Optional[str], typer.Option("--type", help="Filter by finding type")] = None,
    severity: Annotated[Optional[str], typer.Option("--severity", help="Filter by severity")] = None,
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """List vulnerability findings."""
    manager = _get_manager(data_dir)
    try:
        records = manager.context.get_findings(hunt_id, finding_type=type_, severity=severity)
        format_output(
            records, fmt=fmt,
            columns=["finding_type", "severity", "title", "url", "confirmed"],
            title="Findings",
        )
    finally:
        _safe_close(manager)


@context_app.command("sessions")
def ctx_sessions(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """List active sessions."""
    manager = _get_manager(data_dir)
    try:
        records = manager.context.get_sessions(hunt_id)
        format_output(
            records, fmt=fmt,
            columns=["name", "target_url", "auth_method", "is_valid", "last_used_at"],
            title="Sessions",
        )
    finally:
        _safe_close(manager)


@context_app.command("oob")
def ctx_oob(
    hunt_id: Annotated[str, typer.Argument(help="Hunt ID")],
    fmt: FormatOption = "table",
    data_dir: DataDirOption = None,
) -> None:
    """List OOB listeners and interactions."""
    manager = _get_manager(data_dir)
    try:
        records = manager.context.get_oob_listeners(hunt_id)
        format_output(
            records, fmt=fmt,
            columns=["listener_id", "callback_domain", "purpose", "target_url", "parameter"],
            title="OOB Listeners",
        )
    finally:
        _safe_close(manager)


if __name__ == "__main__":
    app()
