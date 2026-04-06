"""Query operations mixin."""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timedelta
from typing import Any

from boba.core.errors import HuntNotFoundError
from boba.core.models import ToolResult

from boba.core.context._helpers import _now

logger = logging.getLogger(__name__)


class QueryMixin:
    """Read-only query methods and tool run logging."""

    _conn: sqlite3.Connection

    def _ensure_hunt(self, hunt_id: str) -> None:
        """Raise HuntNotFoundError if hunt_id does not exist."""
        row = self._conn.execute("SELECT 1 FROM hunts WHERE id = ?", (hunt_id,)).fetchone()
        if not row:
            raise HuntNotFoundError(f"Hunt '{hunt_id}' not found")

    def get_subdomains(self, hunt_id: str) -> list[dict[str, Any]]:
        self._ensure_hunt(hunt_id)
        rows = self._conn.execute(
            "SELECT * FROM subdomains WHERE hunt_id = ? ORDER BY subdomain", (hunt_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_hosts(self, hunt_id: str, alive_only: bool = False) -> list[dict[str, Any]]:
        self._ensure_hunt(hunt_id)
        sql = "SELECT * FROM hosts WHERE hunt_id = ?"
        if alive_only:
            sql += " AND status_code IS NOT NULL AND status_code > 0"
        sql += " ORDER BY host"
        rows = self._conn.execute(sql, (hunt_id,)).fetchall()
        return [dict(r) for r in rows]

    def get_ports(self, hunt_id: str, host: str | None = None) -> list[dict[str, Any]]:
        self._ensure_hunt(hunt_id)
        if host:
            rows = self._conn.execute(
                "SELECT * FROM ports WHERE hunt_id = ? AND host = ? ORDER BY port",
                (hunt_id, host),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM ports WHERE hunt_id = ? ORDER BY host, port", (hunt_id,)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_urls(self, hunt_id: str, host: str | None = None) -> list[dict[str, Any]]:
        self._ensure_hunt(hunt_id)
        if host:
            rows = self._conn.execute(
                "SELECT * FROM urls WHERE hunt_id = ? AND host = ? ORDER BY url",
                (hunt_id, host),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM urls WHERE hunt_id = ? ORDER BY url", (hunt_id,)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_technologies(self, hunt_id: str, host: str | None = None) -> list[dict[str, Any]]:
        self._ensure_hunt(hunt_id)
        if host:
            rows = self._conn.execute(
                "SELECT * FROM technologies WHERE hunt_id = ? AND host = ? ORDER BY name",
                (hunt_id, host),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM technologies WHERE hunt_id = ? ORDER BY host, name", (hunt_id,)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_directories(self, hunt_id: str, url_prefix: str | None = None) -> list[dict[str, Any]]:
        self._ensure_hunt(hunt_id)
        if url_prefix:
            # Escape LIKE wildcards (% and _) so caller input is matched literally
            escaped = url_prefix.replace("%", "\\%").replace("_", "\\_")
            rows = self._conn.execute(
                "SELECT * FROM directories WHERE hunt_id = ? AND url LIKE ? ESCAPE '\\' ORDER BY url",
                (hunt_id, f"{escaped}%"),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM directories WHERE hunt_id = ? ORDER BY url", (hunt_id,)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_parameters(
        self,
        hunt_id: str,
        url: str | None = None,
        method: str | None = None,
    ) -> list[dict[str, Any]]:
        self._ensure_hunt(hunt_id)
        sql = "SELECT * FROM parameters WHERE hunt_id = ?"
        params: list[Any] = [hunt_id]
        if url:
            sql += " AND url = ?"
            params.append(url)
        if method:
            sql += " AND method = ?"
            params.append(method.upper())
        sql += " ORDER BY url, method, name"
        rows = self._conn.execute(sql, tuple(params)).fetchall()
        return [dict(r) for r in rows]

    def get_secrets(
        self,
        hunt_id: str,
        secret_type: str | None = None,
        repo: str | None = None,
    ) -> list[dict[str, Any]]:
        self._ensure_hunt(hunt_id)
        sql = "SELECT * FROM secrets WHERE hunt_id = ?"
        params: list[Any] = [hunt_id]
        if secret_type:
            sql += " AND secret_type = ?"
            params.append(secret_type)
        if repo:
            sql += " AND repo = ?"
            params.append(repo)
        sql += " ORDER BY rule_id, file_path"
        rows = self._conn.execute(sql, tuple(params)).fetchall()
        return [dict(r) for r in rows]

    def get_api_endpoints(
        self,
        hunt_id: str,
        host: str | None = None,
        method: str | None = None,
    ) -> list[dict[str, Any]]:
        self._ensure_hunt(hunt_id)
        sql = "SELECT * FROM api_endpoints WHERE hunt_id = ?"
        params: list[Any] = [hunt_id]
        if host:
            sql += " AND host = ?"
            params.append(host)
        if method:
            sql += " AND method = ?"
            params.append(method.upper())
        sql += " ORDER BY host, path, method"
        rows = self._conn.execute(sql, tuple(params)).fetchall()
        return [dict(r) for r in rows]

    def get_tool_runs(self, hunt_id: str) -> list[dict[str, Any]]:
        self._ensure_hunt(hunt_id)
        rows = self._conn.execute(
            "SELECT * FROM tool_runs WHERE hunt_id = ? ORDER BY started_at DESC", (hunt_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    def log_tool_run(self, hunt_id: str, result: ToolResult) -> int:
        self._ensure_hunt(hunt_id)
        finished_at = _now()
        # Compute started_at from finished time minus duration for accurate audit trails
        try:
            finished_dt = datetime.fromisoformat(finished_at)
            started_dt = finished_dt - timedelta(seconds=result.duration_seconds)
            started_at = started_dt.isoformat()
        except (ValueError, OverflowError):
            started_at = finished_at
        cursor = self._conn.execute(
            """INSERT INTO tool_runs
                (hunt_id, tool_name, command_json, status, started_at, finished_at,
                 duration_seconds, exit_code, records_found, records_filtered, timed_out, error_message)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                hunt_id,
                result.tool_name,
                json.dumps(result.command),
                "completed" if result.exit_code == 0 and not result.timed_out else "failed",
                started_at,
                finished_at,
                result.duration_seconds,
                result.exit_code,
                len(result.records),
                result.filtered_count,
                1 if result.timed_out else 0,
                result.raw_stderr[:1000] if result.exit_code != 0 else None,
            ),
        )
        self._conn.commit()
        return cursor.lastrowid or 0

    _STATS_TABLES = frozenset(
        {
            "subdomains",
            "hosts",
            "ports",
            "urls",
            "technologies",
            "directories",
            "parameters",
            "secrets",
            "api_endpoints",
            "http_history",
            "sessions",
            "findings",
            "coverage",
        }
    )

    def get_hunt_stats(self, hunt_id: str) -> dict[str, int]:
        stats = {}
        for table in sorted(self._STATS_TABLES):
            row = self._conn.execute(
                f"SELECT COUNT(*) as cnt FROM {table} WHERE hunt_id = ?",
                (hunt_id,),  # noqa: S608
            ).fetchone()
            stats[table] = row["cnt"] if row else 0
        # alive hosts specifically
        row = self._conn.execute(
            "SELECT COUNT(*) as cnt FROM hosts WHERE hunt_id = ? AND status_code IS NOT NULL AND status_code > 0",
            (hunt_id,),
        ).fetchone()
        stats["hosts_alive"] = row["cnt"] if row else 0
        return stats
