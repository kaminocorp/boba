"""Session operations mixin."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from boba.core.context._helpers import _now, _parse_json_field


class SessionMixin:
    """Authenticated session persistence."""

    _conn: sqlite3.Connection

    def upsert_session(self, hunt_id: str, session: dict[str, Any]) -> None:
        """Create or update a named session."""
        now = _now()
        self._conn.execute(
            """INSERT INTO sessions
                (hunt_id, name, target_url, auth_method, cookies_json, headers_json,
                 tokens_json, storage_state, is_valid, created_at, last_used_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(hunt_id, name) DO UPDATE SET
                target_url = excluded.target_url,
                auth_method = excluded.auth_method,
                cookies_json = excluded.cookies_json,
                headers_json = excluded.headers_json,
                tokens_json = excluded.tokens_json,
                storage_state = excluded.storage_state,
                is_valid = excluded.is_valid,
                last_used_at = excluded.last_used_at""",
            (
                hunt_id,
                session["name"],
                session["target_url"],
                session.get("auth_method", "form"),
                json.dumps(session.get("cookies", {})),
                json.dumps(session.get("headers", {})),
                json.dumps(session.get("tokens", {})),
                json.dumps(session["storage_state"]) if session.get("storage_state") else None,
                1 if session.get("is_valid", True) else 0,
                now,
                now,
            ),
        )
        self._conn.commit()

    def get_session(self, hunt_id: str, name: str) -> dict[str, Any] | None:
        """Get a named session."""
        row = self._conn.execute(
            "SELECT * FROM sessions WHERE hunt_id = ? AND name = ?", (hunt_id, name)
        ).fetchone()
        if not row:
            return None
        return self._deserialize_session_row(dict(row), hunt_id)

    def get_sessions(self, hunt_id: str) -> list[dict[str, Any]]:
        """List all sessions for a hunt."""
        rows = self._conn.execute(
            "SELECT * FROM sessions WHERE hunt_id = ? ORDER BY name", (hunt_id,)
        ).fetchall()
        return [self._deserialize_session_row(dict(row), hunt_id) for row in rows]

    def _deserialize_session_row(self, r: dict[str, Any], hunt_id: str) -> dict[str, Any]:
        """Convert a raw sessions row into a deserialized dict."""
        label = f"session {hunt_id}/{r.get('name', '?')}"
        for json_col, dest_key in [
            ("cookies_json", "cookies"),
            ("headers_json", "headers"),
            ("tokens_json", "tokens"),
        ]:
            r[dest_key] = _parse_json_field(
                r.pop(json_col, "{}"), "{}", label=json_col, record_id=label
            )
        r["storage_state"] = (
            _parse_json_field(r["storage_state"], "null", label="storage_state", record_id=label)
            if r.get("storage_state")
            else None
        )
        r["is_valid"] = bool(r["is_valid"])
        return r

    def delete_session(self, hunt_id: str, name: str) -> None:
        """Delete a named session."""
        self._conn.execute("DELETE FROM sessions WHERE hunt_id = ? AND name = ?", (hunt_id, name))
        self._conn.commit()

    def touch_session(self, hunt_id: str, name: str) -> None:
        """Update last_used_at for a session."""
        self._conn.execute(
            "UPDATE sessions SET last_used_at = ? WHERE hunt_id = ? AND name = ?",
            (_now(), hunt_id, name),
        )
        self._conn.commit()
