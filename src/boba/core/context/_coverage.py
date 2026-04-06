"""Coverage tracking operations mixin."""

from __future__ import annotations

import sqlite3
from typing import Any

from boba.core.context._helpers import _now, _resolve_upsert_id


class CoverageMixin:
    """Tracks which endpoints have been tested with which vulnerability checks."""

    _conn: sqlite3.Connection

    def _maybe_commit(self) -> None: ...  # provided by HuntContext

    def upsert_coverage(self, hunt_id: str, entry: dict[str, Any]) -> int:
        """Record that a URL/parameter was tested with a specific test type.

        Returns the row ID.
        """
        now = _now()
        cursor = self._conn.execute(
            """INSERT INTO coverage
                (hunt_id, url, method, parameter, test_type, tested_at,
                 tool_run_id, finding_id, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(hunt_id, url, method, parameter, test_type) DO UPDATE SET
                tested_at = excluded.tested_at,
                tool_run_id = COALESCE(excluded.tool_run_id, coverage.tool_run_id),
                finding_id = COALESCE(excluded.finding_id, coverage.finding_id),
                notes = COALESCE(excluded.notes, coverage.notes)""",
            (
                hunt_id,
                entry["url"],
                entry.get("method", "GET"),
                entry.get("parameter", ""),
                entry["test_type"],
                entry.get("tested_at", now),
                entry.get("tool_run_id"),
                entry.get("finding_id"),
                entry.get("notes"),
            ),
        )
        self._maybe_commit()
        return _resolve_upsert_id(
            self._conn,
            cursor,
            "coverage",
            "hunt_id = ? AND url = ? AND method = ? AND parameter = ? AND test_type = ?",
            (
                hunt_id,
                entry["url"],
                entry.get("method", "GET"),
                entry.get("parameter", ""),
                entry["test_type"],
            ),
        )

    def get_coverage(
        self,
        hunt_id: str,
        url: str | None = None,
        test_type: str | None = None,
        host: str | None = None,
    ) -> list[dict[str, Any]]:
        """Query coverage records with optional filters."""
        sql = "SELECT * FROM coverage WHERE hunt_id = ?"
        params: list[Any] = [hunt_id]

        if url:
            sql += " AND url = ?"
            params.append(url)
        if test_type:
            sql += " AND test_type = ?"
            params.append(test_type)
        if host:
            escaped = host.replace("%", "\\%").replace("_", "\\_")
            sql += " AND url LIKE ? ESCAPE '\\'"
            params.append(f"%://{escaped}%")

        sql += " ORDER BY tested_at DESC"
        rows = self._conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def get_untested_endpoints(
        self,
        hunt_id: str,
        test_types: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Return known endpoints that have no coverage row for given test types.

        Discovers endpoints from urls and directories tables.
        Returns list of {url, method, test_type} dicts.
        """
        if not test_types:
            test_types = ["idor", "ssrf", "xss", "sqli", "auth"]

        placeholders = ",".join("?" for _ in test_types)

        # Collect known endpoint URLs from urls + directories tables
        sql = f"""
            SELECT ep.url, ep.method, tt.test_type
            FROM (
                SELECT url, method FROM urls WHERE hunt_id = ?
                UNION
                SELECT url, 'GET' as method FROM directories WHERE hunt_id = ?
            ) ep
            CROSS JOIN (
                SELECT value AS test_type FROM json_each(json_array({placeholders}))
            ) tt
            LEFT JOIN coverage c
                ON c.hunt_id = ?
                AND c.url = ep.url
                AND c.method = ep.method
                AND c.test_type = tt.test_type
            WHERE c.id IS NULL
            ORDER BY ep.url, tt.test_type
        """
        params = [hunt_id, hunt_id] + test_types + [hunt_id]
        rows = self._conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]
