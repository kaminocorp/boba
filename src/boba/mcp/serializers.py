"""Dataclass → JSON string converters for MCP tool responses."""

from __future__ import annotations

import dataclasses
import json
from typing import Any


def serialize_result(obj: Any) -> str:
    """Convert any Boba result to a JSON string suitable for an MCP response.

    Handles:
    - dataclass instances (recursively via ``dataclasses.asdict``)
    - lists of dataclasses / dicts
    - plain dicts
    - scalar fallback via ``str()``
    """
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return json.dumps(dataclasses.asdict(obj), default=str)
    if isinstance(obj, list):
        return json.dumps(
            [dataclasses.asdict(item) if dataclasses.is_dataclass(item) else item for item in obj],
            default=str,
        )
    if isinstance(obj, dict):
        return json.dumps(obj, default=str)
    return str(obj)


def serialize_tool_result(result: Any) -> str:
    """Serialize a :class:`ToolResult` with a human-readable summary prefix.

    Returns a JSON object with ``summary`` (lightweight metadata) and
    ``records`` (the full list of parsed records).
    """
    summary: dict[str, Any] = {
        "tool": result.tool_name,
        "records_found": len(result.records),
        "filtered_out": result.filtered_count,
        "duration_seconds": result.duration_seconds,
        "timed_out": result.timed_out,
    }
    if result.exit_code != 0:
        summary["exit_code"] = result.exit_code
        summary["stderr"] = (result.raw_stderr or "")[:500]
    payload = {"summary": summary, "records": result.records}
    return json.dumps(payload, default=str)
