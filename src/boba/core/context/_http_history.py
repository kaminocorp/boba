"""HTTP history operations mixin."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from boba.core.context._helpers import _now, _parse_json_field


class HttpHistoryMixin:
    """HTTP request/response history recording and querying."""

    _conn: sqlite3.Connection

    def insert_http_record(self, hunt_id: str, record: dict[str, Any]) -> int:
        """Insert a single HTTP exchange. Returns the row ID."""
        now = _now()
        cursor = self._conn.execute(
            """INSERT INTO http_history
                (hunt_id, session_name, tool_run_id, source,
                 method, url, host, path, query,
                 request_headers, request_body, request_body_ref, content_type,
                 status_code, response_headers, response_body, response_body_ref,
                 response_length, response_content_type,
                 elapsed_ms, tls_version, ip_address, resource_type,
                 is_redirect, redirect_url,
                 parent_request_id, tags, notes, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                hunt_id,
                record.get("session_name"),
                record.get("tool_run_id"),
                record.get("source", "manual"),
                record["method"],
                record["url"],
                record["host"],
                record.get("path", "/"),
                record.get("query"),
                json.dumps(record.get("request_headers", {})),
                record.get("request_body"),
                record.get("request_body_ref"),
                record.get("content_type"),
                record.get("status_code"),
                json.dumps(record.get("response_headers", {})),
                record.get("response_body"),
                record.get("response_body_ref"),
                record.get("response_length"),
                record.get("response_content_type"),
                record.get("elapsed_ms"),
                record.get("tls_version"),
                record.get("ip_address"),
                record.get("resource_type"),
                1 if record.get("is_redirect") else 0,
                record.get("redirect_url"),
                record.get("parent_request_id"),
                json.dumps(record.get("tags", [])),
                record.get("notes"),
                now,
            ),
        )
        self._conn.commit()
        return cursor.lastrowid or 0

    def get_http_record(self, record_id: int) -> dict[str, Any] | None:
        """Get a single HTTP history record by ID."""
        row = self._conn.execute("SELECT * FROM http_history WHERE id = ?", (record_id,)).fetchone()
        if not row:
            return None
        result = dict(row)
        for field, default in [
            ("request_headers", "{}"),
            ("response_headers", "{}"),
            ("tags", "[]"),
        ]:
            result[field] = _parse_json_field(
                result[field], default, label=field, record_id=record_id
            )
        return result

    def query_http_history(
        self,
        hunt_id: str,
        host: str | None = None,
        method: str | None = None,
        status_code: int | None = None,
        source: str | None = None,
        session_name: str | None = None,
        path_prefix: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Query HTTP history with filters."""
        sql = "SELECT * FROM http_history WHERE hunt_id = ?"
        params: list[Any] = [hunt_id]

        if host:
            sql += " AND host = ?"
            params.append(host)
        if method:
            sql += " AND method = ?"
            params.append(method)
        if status_code is not None:
            sql += " AND status_code = ?"
            params.append(status_code)
        if source:
            sql += " AND source = ?"
            params.append(source)
        if session_name:
            sql += " AND session_name = ?"
            params.append(session_name)
        if path_prefix:
            # Escape LIKE wildcards (% and _) so caller input is matched literally
            escaped = path_prefix.replace("%", "\\%").replace("_", "\\_")
            sql += " AND path LIKE ? ESCAPE '\\'"
            params.append(f"{escaped}%")

        sql += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        rows = self._conn.execute(sql, params).fetchall()
        results = []
        for row in rows:
            r = dict(row)
            rid = r.get("id", "?")
            for field, default in [
                ("request_headers", "{}"),
                ("response_headers", "{}"),
                ("tags", "[]"),
            ]:
                r[field] = _parse_json_field(r[field], default, label=field, record_id=rid)
            results.append(r)
        return results

    def update_http_record_tags(self, record_id: int, tags: list[str]) -> None:
        """Add tags to an HTTP history record (merges with existing)."""
        existing = self.get_http_record(record_id)
        if not existing:
            return
        merged = list(set(existing.get("tags", []) + tags))
        self._conn.execute(
            "UPDATE http_history SET tags = ? WHERE id = ?",
            (json.dumps(merged), record_id),
        )
        self._conn.commit()

    def update_http_record_notes(self, record_id: int, notes: str) -> None:
        """Set notes on an HTTP history record."""
        self._conn.execute("UPDATE http_history SET notes = ? WHERE id = ?", (notes, record_id))
        self._conn.commit()
