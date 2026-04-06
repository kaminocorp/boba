"""Attack chain operations mixin."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from boba.core.context._helpers import _now, _parse_json_field, _resolve_upsert_id


class ChainMixin:
    """Attack chain persistence — multi-finding vulnerability chains."""

    _conn: sqlite3.Connection

    def upsert_chain(self, hunt_id: str, chain: dict[str, Any]) -> int:
        """Insert or update an attack chain. Returns the row ID."""
        now = _now()
        cursor = self._conn.execute(
            """INSERT INTO chains
                (hunt_id, title, description, severity, confidence,
                 cvss_score, cvss_vector, finding_ids, chain_order,
                 impact, prerequisites, tags, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(hunt_id, title) DO UPDATE SET
                description = excluded.description,
                severity = excluded.severity,
                confidence = excluded.confidence,
                cvss_score = excluded.cvss_score,
                cvss_vector = excluded.cvss_vector,
                finding_ids = excluded.finding_ids,
                chain_order = excluded.chain_order,
                impact = excluded.impact,
                prerequisites = excluded.prerequisites,
                tags = excluded.tags,
                updated_at = excluded.updated_at""",
            (
                hunt_id,
                chain["title"],
                chain.get("description"),
                chain.get("severity", "info"),
                chain.get("confidence", "hypothetical"),
                chain.get("cvss_score"),
                chain.get("cvss_vector"),
                json.dumps(chain.get("finding_ids", [])),
                json.dumps(chain.get("chain_order", [])),
                chain.get("impact"),
                json.dumps(chain.get("prerequisites", [])),
                json.dumps(chain.get("tags", [])),
                now,
                now,
            ),
        )
        self._conn.commit()
        return _resolve_upsert_id(
            self._conn,
            cursor,
            "chains",
            "hunt_id = ? AND title = ?",
            (hunt_id, chain["title"]),
        )

    def get_chains(self, hunt_id: str, severity: str | None = None) -> list[dict[str, Any]]:
        """Query chains with optional severity filter."""
        sql = "SELECT * FROM chains WHERE hunt_id = ?"
        params: list[Any] = [hunt_id]
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        sql += " ORDER BY cvss_score DESC, created_at DESC"
        rows = self._conn.execute(sql, params).fetchall()
        results = []
        for row in rows:
            r = dict(row)
            cid = r.get("id", "?")
            for field in ("finding_ids", "chain_order", "prerequisites", "tags"):
                r[field] = _parse_json_field(r[field], "[]", label=field, record_id=cid)
            results.append(r)
        return results

    def get_chain(self, chain_id: int) -> dict[str, Any] | None:
        """Get a single chain by ID."""
        row = self._conn.execute("SELECT * FROM chains WHERE id = ?", (chain_id,)).fetchone()
        if not row:
            return None
        r = dict(row)
        cid = r.get("id", "?")
        for field in ("finding_ids", "chain_order", "prerequisites", "tags"):
            r[field] = _parse_json_field(r[field], "[]", label=field, record_id=cid)
        return r

    def update_chain_confidence(self, chain_id: int, confidence: str) -> None:
        """Update a chain's confidence status."""
        self._conn.execute(
            "UPDATE chains SET confidence = ?, updated_at = ? WHERE id = ?",
            (confidence, _now(), chain_id),
        )
        self._conn.commit()

    def delete_chains(self, hunt_id: str) -> int:
        """Delete all chains for a hunt. Returns rows deleted."""
        cursor = self._conn.execute("DELETE FROM chains WHERE hunt_id = ?", (hunt_id,))
        self._conn.commit()
        return cursor.rowcount
