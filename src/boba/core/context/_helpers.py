"""Shared helper functions for HuntContext modules."""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _resolve_upsert_id(
    conn: sqlite3.Connection,
    cursor: sqlite3.Cursor,
    table: str,
    where_clause: str,
    params: tuple,
) -> int:
    """Resolve row ID after INSERT ON CONFLICT DO UPDATE.

    SQLite's last_insert_rowid() is undefined on the update path of an
    UPSERT. When lastrowid is falsy we fall back to a SELECT on the
    unique-key columns.
    """
    row_id = cursor.lastrowid
    if row_id:
        return row_id
    row = conn.execute(f"SELECT id FROM {table} WHERE {where_clause}", params).fetchone()
    return row[0] if row else 0


def _parse_json_field(
    value: str | None, default: str = "{}", *, label: str = "field", record_id: Any = "?"
) -> Any:
    """Parse a JSON field with fallback, logging warnings on malformed data."""
    try:
        return json.loads(value or default)
    except (json.JSONDecodeError, TypeError) as exc:
        logger.warning("Malformed %s in record %s: %s", label, record_id, exc)
        return json.loads(default)


def _json_array_merge(a: str | None, b: str | None) -> str:
    """Merge two JSON arrays safely. Registered as a SQLite custom function.

    Handles all edge cases: null, 'null', '[]', non-array JSON, malformed JSON.
    Always returns a valid JSON array string.
    """

    def _parse_array(val: str | None) -> list:
        if not val or val in ("null", "[]"):
            return []
        try:
            parsed = json.loads(val)
        except (json.JSONDecodeError, TypeError):
            return []
        if isinstance(parsed, list):
            return parsed
        return [parsed]

    arr_a = _parse_array(a)
    arr_b = _parse_array(b)
    # Deduplicate: preserve order, skip items already in arr_a.
    # For unhashable items (dicts), fall back to membership check.
    seen: set = set()
    merged: list = []
    for item in arr_a + arr_b:
        try:
            key = (
                json.dumps(item, sort_keys=True, default=str)
                if isinstance(item, (dict, list))
                else item
            )
        except (TypeError, ValueError):
            key = str(item)
        if key not in seen:
            seen.add(key)
            merged.append(item)
    return json.dumps(merged) if merged else "[]"
