"""Deduplication group operations mixin."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from boba.core.context._helpers import _now, _parse_json_field, _resolve_upsert_id


class DedupMixin:
    """Finding deduplication group management."""

    _conn: sqlite3.Connection

    def get_finding_by_id(self, finding_id: int) -> dict[str, Any] | None: ...  # FindingMixin

    def insert_dedup_group(self, hunt_id: str, group: dict[str, Any]) -> int:
        """Insert a dedup group. Returns the row ID."""
        now = _now()
        cursor = self._conn.execute(
            """INSERT INTO dedup_groups
                (hunt_id, canonical_id, finding_ids, reason, created_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(hunt_id, canonical_id) DO UPDATE SET
                finding_ids = excluded.finding_ids,
                reason = excluded.reason""",
            (
                hunt_id,
                group["canonical_id"],
                json.dumps(group.get("finding_ids", [])),
                group["reason"],
                now,
            ),
        )
        self._conn.commit()
        return _resolve_upsert_id(
            self._conn,
            cursor,
            "dedup_groups",
            "hunt_id = ? AND canonical_id = ?",
            (hunt_id, group["canonical_id"]),
        )

    def get_dedup_groups(self, hunt_id: str) -> list[dict[str, Any]]:
        """List all dedup groups for a hunt."""
        rows = self._conn.execute(
            "SELECT * FROM dedup_groups WHERE hunt_id = ? ORDER BY created_at DESC",
            (hunt_id,),
        ).fetchall()
        results = []
        for row in rows:
            r = dict(row)
            r["finding_ids"] = _parse_json_field(
                r["finding_ids"], "[]", label="finding_ids", record_id=r.get("id", "?")
            )
            results.append(r)
        return results

    def delete_dedup_groups(self, hunt_id: str) -> int:
        """Delete all dedup groups for a hunt. Returns rows deleted."""
        cursor = self._conn.execute("DELETE FROM dedup_groups WHERE hunt_id = ?", (hunt_id,))
        self._conn.commit()
        return cursor.rowcount

    def is_duplicate(self, hunt_id: str, finding_id: int) -> bool:
        """Check if a finding is a non-canonical member of any dedup group."""
        row = self._conn.execute(
            """
            SELECT canonical_id FROM dedup_groups
            WHERE hunt_id = ?
              AND EXISTS (
                SELECT 1 FROM json_each(finding_ids) WHERE value = ?
              )
            """,
            (hunt_id, finding_id),
        ).fetchone()
        if not row:
            return False
        return finding_id != row["canonical_id"]

    def get_canonical_finding(self, hunt_id: str, finding_id: int) -> dict[str, Any] | None:
        """If finding is in a dedup group, return the canonical finding; else return itself."""
        row = self._conn.execute(
            """
            SELECT canonical_id FROM dedup_groups
            WHERE hunt_id = ?
              AND EXISTS (
                SELECT 1 FROM json_each(finding_ids) WHERE value = ?
              )
            """,
            (hunt_id, finding_id),
        ).fetchone()
        if row:
            return self.get_finding_by_id(row["canonical_id"])
        return self.get_finding_by_id(finding_id)
