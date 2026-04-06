"""Finding operations mixin."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from boba.core.context._helpers import _now, _parse_json_field, _resolve_upsert_id


class FindingMixin:
    """Vulnerability finding persistence and queries."""

    _conn: sqlite3.Connection

    def upsert_finding(self, hunt_id: str, finding: dict[str, Any]) -> int:
        """Upsert a vulnerability finding. Returns the row ID."""
        now = _now()
        cursor = self._conn.execute(
            """INSERT INTO findings
                (hunt_id, finding_type, severity, title, description,
                 url, endpoint, parameter, method, evidence, request_ids,
                 tool_run_id, confirmed, false_positive, reported,
                 template_id, tags, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(hunt_id, finding_type, url, method, parameter) DO UPDATE SET
                severity = COALESCE(excluded.severity, findings.severity),
                title = COALESCE(excluded.title, findings.title),
                description = COALESCE(excluded.description, findings.description),
                evidence = json_array_merge(findings.evidence, excluded.evidence),
                request_ids = json_array_merge(findings.request_ids, excluded.request_ids),
                tool_run_id = excluded.tool_run_id,
                confirmed = MAX(findings.confirmed, excluded.confirmed),
                false_positive = MAX(findings.false_positive, excluded.false_positive),
                reported = MAX(findings.reported, excluded.reported),
                template_id = excluded.template_id,
                tags = excluded.tags,
                updated_at = excluded.updated_at""",
            (
                hunt_id,
                finding["finding_type"],
                finding.get("severity", "info"),
                finding["title"],
                finding.get("description"),
                finding.get("url") or "",
                finding.get("endpoint"),
                finding.get("parameter") or "",
                finding.get("method") or "",
                json.dumps(
                    finding["evidence"]
                    if isinstance(finding.get("evidence"), list)
                    else []
                    if finding.get("evidence") is None
                    else [finding["evidence"]]
                ),
                json.dumps(finding.get("request_ids", [])),
                finding.get("tool_run_id"),
                1 if finding.get("confirmed") else 0,
                1 if finding.get("false_positive") else 0,
                1 if finding.get("reported") else 0,
                finding.get("template_id"),
                json.dumps(finding.get("tags", [])),
                now,
                now,
            ),
        )
        self._conn.commit()
        return _resolve_upsert_id(
            self._conn,
            cursor,
            "findings",
            "hunt_id = ? AND finding_type = ? AND url = ? AND method = ? AND parameter = ?",
            (
                hunt_id,
                finding["finding_type"],
                finding.get("url") or "",
                finding.get("method") or "",
                finding.get("parameter") or "",
            ),
        )

    def get_findings(
        self,
        hunt_id: str,
        finding_type: str | None = None,
        severity: str | None = None,
    ) -> list[dict[str, Any]]:
        """Query findings with optional filters."""
        sql = "SELECT * FROM findings WHERE hunt_id = ?"
        params: list[Any] = [hunt_id]
        if finding_type:
            sql += " AND finding_type = ?"
            params.append(finding_type)
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        sql += " ORDER BY created_at DESC"
        rows = self._conn.execute(sql, params).fetchall()
        results = []
        for row in rows:
            r = dict(row)
            fid = r.get("id", "?")
            r["evidence"] = (
                _parse_json_field(r["evidence"], "null", label="evidence", record_id=fid)
                if r.get("evidence")
                else None
            )
            r["request_ids"] = _parse_json_field(
                r["request_ids"], "[]", label="request_ids", record_id=fid
            )
            r["tags"] = _parse_json_field(r["tags"], "[]", label="tags", record_id=fid)
            r["confirmed"] = bool(r["confirmed"])
            r["false_positive"] = bool(r["false_positive"])
            r["reported"] = bool(r["reported"])
            results.append(r)
        return results

    def get_finding_by_id(self, finding_id: int) -> dict[str, Any] | None:
        """Get a single finding by its primary key."""
        row = self._conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
        if not row:
            return None
        r = dict(row)
        fid = r.get("id", "?")
        r["evidence"] = (
            _parse_json_field(r["evidence"], "null", label="evidence", record_id=fid)
            if r.get("evidence")
            else None
        )
        r["request_ids"] = _parse_json_field(
            r["request_ids"], "[]", label="request_ids", record_id=fid
        )
        r["tags"] = _parse_json_field(r["tags"], "[]", label="tags", record_id=fid)
        r["confirmed"] = bool(r["confirmed"])
        r["false_positive"] = bool(r["false_positive"])
        r["reported"] = bool(r["reported"])
        return r
