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
        manager.close_context()


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
    finally:
        manager.close_context()


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
        manager.close_context()


@hunt_app.command("pause")
def hunt_pause(
    hunt_id: Annotated[str, typer.Argument()],
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
        manager.close_context()


@hunt_app.command("resume")
def hunt_resume(
    hunt_id: Annotated[str, typer.Argument()],
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
        manager.close_context()


@hunt_app.command("close")
def hunt_close(
    hunt_id: Annotated[str, typer.Argument()],
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
        manager.close_context()


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
        manager.close_context()


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
        target_list = targets.split(",") if targets else None
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
        manager.close_context()


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
        target_list = targets.split(",") if targets else None
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
        manager.close_context()


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
        manager.close_context()


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
        target_list = targets.split(",") if targets else None
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
        manager.close_context()


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
        ext_list = extensions.split(",") if extensions else None
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
        manager.close_context()


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
        manager.close_context()


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
        manager.close_context()


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
        manager.close_context()


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
        manager.close_context()


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
        manager.close_context()


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
        manager.close_context()


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
        manager.close_context()


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
        manager.close_context()


if __name__ == "__main__":
    app()
