"""Boba MCP server — agent-native tool access."""

from __future__ import annotations

import os


def main() -> None:
    """Entry point for the ``boba-mcp`` command."""
    try:
        from boba.mcp.server import mcp  # noqa: WPS433 — deferred to avoid import-time side-effects
    except ImportError as exc:
        raise SystemExit(
            f"boba-mcp requires the 'mcp' optional dependency ({exc}).\n"
            "Install with: pip install 'boba-hunter[mcp]'"
        ) from exc

    transport = os.environ.get("BOBA_MCP_TRANSPORT", "stdio")
    try:
        port = int(os.environ.get("BOBA_MCP_PORT", "3000"))
    except ValueError:
        port = 3000
    if transport == "streamable-http":
        mcp.run(transport="streamable-http", port=port)
    else:
        mcp.run()
