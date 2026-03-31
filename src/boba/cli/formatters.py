"""Output formatters — JSON for agents, Rich tables for humans."""

from __future__ import annotations

import json
import sys
from typing import Any

from rich.console import Console
from rich.table import Table

console = Console()


def format_output(
    data: list[dict[str, Any]] | dict[str, Any],
    fmt: str = "table",
    columns: list[str] | None = None,
    title: str | None = None,
) -> None:
    """
    Print data in the requested format.

    Args:
        data: List of records or a single dict.
        fmt: "json" for machine-readable, "table" for human-readable.
        columns: Which keys to show as table columns (auto-detected if None).
        title: Optional table title.
    """
    if fmt == "json":
        _print_json(data)
    else:
        _print_table(data, columns, title)


def _print_json(data: list[dict] | dict) -> None:
    json.dump(data, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")


def _print_table(
    data: list[dict] | dict,
    columns: list[str] | None = None,
    title: str | None = None,
) -> None:
    if isinstance(data, dict):
        # Single dict — print as key/value pairs
        table = Table(title=title, show_header=True)
        table.add_column("Field", style="cyan")
        table.add_column("Value")
        for key, value in data.items():
            table.add_row(str(key), str(value))
        console.print(table)
        return

    if not data:
        console.print("[dim]No results.[/dim]")
        return

    # Auto-detect columns from first record
    if columns is None:
        columns = _auto_columns(data[0])

    table = Table(title=title, show_header=True, show_lines=False)
    for col in columns:
        table.add_column(col, overflow="fold")

    for record in data:
        row = []
        for col in columns:
            val = record.get(col, "")
            if isinstance(val, list):
                val = ", ".join(str(v) for v in val)
            row.append(str(val) if val is not None else "")
        table.add_row(*row)

    console.print(table)
    console.print(f"[dim]{len(data)} results[/dim]")


def _auto_columns(record: dict) -> list[str]:
    """Pick meaningful columns, excluding internal IDs and raw data."""
    skip = {"id", "hunt_id", "first_seen_at", "last_seen_at", "last_checked_at", "sources"}
    cols = [k for k in record.keys() if k not in skip]
    # Limit to reasonable width
    return cols[:8]


def print_success(message: str) -> None:
    console.print(f"[green]{message}[/green]")


def print_error(message: str) -> None:
    console.print(f"[red]Error: {message}[/red]", style="bold")


def print_info(message: str) -> None:
    console.print(f"[dim]{message}[/dim]")
