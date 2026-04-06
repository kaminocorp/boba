"""Out-of-band listener operations mixin."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from boba.core.context._helpers import _now, _parse_json_field


class OobMixin:
    """OOB (out-of-band) listener persistence for blind vuln testing."""

    _conn: sqlite3.Connection

    def insert_oob_listener(self, hunt_id: str, listener: dict[str, Any]) -> int:
        """Insert an OOB listener record."""
        now = _now()
        cursor = self._conn.execute(
            """INSERT INTO oob_listeners
                (hunt_id, listener_id, callback_domain, purpose,
                 test_payload, target_url, parameter, interactions,
                 created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(hunt_id, listener_id) DO UPDATE SET
                interactions = excluded.interactions""",
            (
                hunt_id,
                listener["listener_id"],
                listener["callback_domain"],
                listener.get("purpose"),
                listener.get("test_payload"),
                listener.get("target_url"),
                listener.get("parameter"),
                json.dumps(listener.get("interactions", [])),
                now,
                listener.get("expires_at"),
            ),
        )
        self._conn.commit()
        return cursor.lastrowid or 0

    def update_oob_interactions(
        self, hunt_id: str, listener_id: str, interactions: list[dict[str, Any]]
    ) -> None:
        """Update the interactions list for an OOB listener."""
        self._conn.execute(
            "UPDATE oob_listeners SET interactions = ? WHERE hunt_id = ? AND listener_id = ?",
            (json.dumps(interactions), hunt_id, listener_id),
        )
        self._conn.commit()

    def get_oob_listeners(self, hunt_id: str) -> list[dict[str, Any]]:
        """List all OOB listeners for a hunt."""
        rows = self._conn.execute(
            "SELECT * FROM oob_listeners WHERE hunt_id = ? ORDER BY created_at DESC",
            (hunt_id,),
        ).fetchall()
        results = []
        for row in rows:
            r = dict(row)
            r["interactions"] = _parse_json_field(
                r["interactions"],
                "[]",
                label="interactions",
                record_id=r.get("listener_id", "?"),
            )
            results.append(r)
        return results
