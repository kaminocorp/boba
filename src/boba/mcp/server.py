"""FastMCP server instance and lifecycle hooks."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

from mcp.server.fastmcp import FastMCP

from boba.mcp.resources import ServerResources

# Module-level resources — shared across all tool calls.
resources = ServerResources(
    data_dir=Path(os.environ.get("BOBA_DATA_DIR", ".")),
)


@asynccontextmanager
async def _lifespan(_server: FastMCP) -> AsyncIterator[dict]:
    """Manage resource lifecycle: startup → yield → shutdown."""
    yield {}
    await resources.shutdown()


mcp = FastMCP(
    name="boba",
    instructions=(
        "Boba is an agent-native bug bounty hunting toolkit. "
        "Start with hunt_create to set up a scoped engagement, "
        "then use recon/enum/test/analyze/report tools."
    ),
    lifespan=_lifespan,
)


# Register tool modules — each module decorates functions with @mcp.tool
from boba.mcp import tools_analysis as _tools_analysis  # noqa: F401, E402
from boba.mcp import tools_context as _tools_context  # noqa: F401, E402
from boba.mcp import tools_enum as _tools_enum  # noqa: F401, E402
from boba.mcp import tools_hunt as _tools_hunt  # noqa: F401, E402
from boba.mcp import tools_interaction as _tools_interaction  # noqa: F401, E402
from boba.mcp import tools_recon as _tools_recon  # noqa: F401, E402
from boba.mcp import tools_reporting as _tools_reporting  # noqa: F401, E402
from boba.mcp import tools_scan as _tools_scan  # noqa: F401, E402
from boba.mcp import tools_vuln as _tools_vuln  # noqa: F401, E402
