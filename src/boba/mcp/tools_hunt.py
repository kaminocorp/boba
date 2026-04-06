"""MCP tools for hunt lifecycle management."""

from __future__ import annotations

from typing import Annotated

from boba.mcp.serializers import serialize_result
from boba.mcp.server import mcp, resources


@mcp.tool(description="Create a new bug bounty hunt with scope boundaries")
async def hunt_create(
    name: Annotated[str, "Name for the hunt engagement"],
    scope_yaml: Annotated[str | None, "YAML string defining scope rules"] = None,
) -> str:
    manager = resources.get_manager()
    hunt = manager.create(name=name, scope_yaml=scope_yaml)
    return serialize_result(
        {
            "hunt_id": hunt.id,
            "name": hunt.name,
            "status": hunt.status.value,
            "scope_rules": len(hunt.scope.rules),
        }
    )


@mcp.tool(description="Get hunt details and discovery statistics")
async def hunt_status(
    hunt_id: Annotated[str, "Hunt ID"],
) -> str:
    manager = resources.get_manager()
    hunt = manager.get(hunt_id)
    stats = manager.stats(hunt_id)
    return serialize_result(
        {
            "hunt_id": hunt.id,
            "name": hunt.name,
            "status": hunt.status.value,
            "created_at": str(hunt.created_at),
            "updated_at": str(hunt.updated_at),
            "scope_rules": len(hunt.scope.rules),
            "stats": stats,
        }
    )


@mcp.tool(description="List all hunts")
async def hunt_list() -> str:
    manager = resources.get_manager()
    hunts = manager.list_hunts()
    return serialize_result(
        [
            {
                "hunt_id": h.id,
                "name": h.name,
                "status": h.status.value,
                "created_at": str(h.created_at),
            }
            for h in hunts
        ]
    )


@mcp.tool(description="Pause an active hunt")
async def hunt_pause(
    hunt_id: Annotated[str, "Hunt ID to pause"],
) -> str:
    manager = resources.get_manager()
    hunt = manager.pause(hunt_id)
    return serialize_result(
        {
            "hunt_id": hunt.id,
            "status": hunt.status.value,
        }
    )


@mcp.tool(description="Resume a paused hunt")
async def hunt_resume(
    hunt_id: Annotated[str, "Hunt ID to resume"],
) -> str:
    manager = resources.get_manager()
    hunt = manager.resume(hunt_id)
    return serialize_result(
        {
            "hunt_id": hunt.id,
            "status": hunt.status.value,
        }
    )


@mcp.tool(description="Close a hunt (mark as completed)")
async def hunt_close(
    hunt_id: Annotated[str, "Hunt ID to close"],
) -> str:
    manager = resources.get_manager()
    hunt = manager.close(hunt_id)
    return serialize_result(
        {
            "hunt_id": hunt.id,
            "status": hunt.status.value,
        }
    )
