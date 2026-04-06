"""Report operations mixin."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from boba.core.context._helpers import _now, _parse_json_field


class ReportMixin:
    """Vulnerability report persistence and lifecycle."""

    _conn: sqlite3.Connection

    def upsert_report(self, hunt_id: str, report: dict[str, Any]) -> int:
        """Insert or update a report. Returns the row ID.

        Uses the appropriate partial unique index depending on whether the report
        is for a finding-only, chain-only, or both. SQLite treats NULL as distinct
        in UNIQUE constraints, so we must target the correct partial index.
        """
        now = _now()
        finding_id = report.get("finding_id")
        chain_id = report.get("chain_id")

        values = (
            hunt_id,
            finding_id,
            chain_id,
            report["title"],
            report["severity"],
            report.get("cvss_score"),
            report.get("cvss_vector"),
            report.get("summary"),
            json.dumps(report.get("steps", [])),
            report.get("impact"),
            report.get("remediation"),
            json.dumps(report.get("evidence_refs", [])),
            json.dumps(report.get("request_ids", [])),
            report.get("platform"),
            report.get("platform_report_id"),
            report.get("platform_status"),
            report.get("submitted_at"),
            report.get("status", "draft"),
            now,
            now,
        )

        _UPDATE_SET = """
                title = excluded.title,
                severity = excluded.severity,
                cvss_score = excluded.cvss_score,
                cvss_vector = excluded.cvss_vector,
                summary = excluded.summary,
                steps = excluded.steps,
                impact = excluded.impact,
                remediation = excluded.remediation,
                evidence_refs = excluded.evidence_refs,
                request_ids = excluded.request_ids,
                platform = COALESCE(excluded.platform, reports.platform),
                platform_report_id = COALESCE(excluded.platform_report_id, reports.platform_report_id),
                platform_status = COALESCE(excluded.platform_status, reports.platform_status),
                submitted_at = COALESCE(excluded.submitted_at, reports.submitted_at),
                status = excluded.status,
                updated_at = excluded.updated_at"""

        _INSERT_COLS = """INSERT INTO reports
                (hunt_id, finding_id, chain_id, title, severity,
                 cvss_score, cvss_vector, summary, steps, impact,
                 remediation, evidence_refs, request_ids,
                 platform, platform_report_id, platform_status,
                 submitted_at, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"""

        if finding_id is not None and chain_id is None:
            # Finding-only report — target the partial index idx_reports_finding
            sql = f"""{_INSERT_COLS}
            ON CONFLICT(hunt_id, finding_id) WHERE chain_id IS NULL DO UPDATE SET{_UPDATE_SET}"""
        elif chain_id is not None and finding_id is None:
            # Chain-only report — target the partial index idx_reports_chain
            sql = f"""{_INSERT_COLS}
            ON CONFLICT(hunt_id, chain_id) WHERE finding_id IS NULL DO UPDATE SET{_UPDATE_SET}"""
        elif finding_id is not None and chain_id is not None:
            # Both set — use table constraint
            sql = f"""{_INSERT_COLS}
            ON CONFLICT(hunt_id, finding_id, chain_id) DO UPDATE SET{_UPDATE_SET}"""
        else:
            raise ValueError("upsert_report requires at least one of finding_id or chain_id")

        cursor = self._conn.execute(sql, values)
        self._conn.commit()
        row_id = cursor.lastrowid
        if row_id:
            return row_id
        # Fallback: query by unique key for the update path
        if finding_id is not None and chain_id is None:
            row = self._conn.execute(
                "SELECT id FROM reports WHERE hunt_id = ? AND finding_id = ? AND chain_id IS NULL",
                (hunt_id, finding_id),
            ).fetchone()
        elif chain_id is not None and finding_id is None:
            row = self._conn.execute(
                "SELECT id FROM reports WHERE hunt_id = ? AND chain_id = ? AND finding_id IS NULL",
                (hunt_id, chain_id),
            ).fetchone()
        else:
            row = self._conn.execute(
                "SELECT id FROM reports WHERE hunt_id = ? AND finding_id = ? AND chain_id = ?",
                (hunt_id, finding_id, chain_id),
            ).fetchone()
        return row[0] if row else 0

    def get_reports(
        self,
        hunt_id: str,
        status: str | None = None,
        platform: str | None = None,
    ) -> list[dict[str, Any]]:
        """Query reports with optional filters."""
        sql = "SELECT * FROM reports WHERE hunt_id = ?"
        params: list[Any] = [hunt_id]
        if status:
            sql += " AND status = ?"
            params.append(status)
        if platform:
            sql += " AND platform = ?"
            params.append(platform)
        sql += " ORDER BY created_at DESC"
        rows = self._conn.execute(sql, params).fetchall()
        return [self._deserialize_report_row(dict(r)) for r in rows]

    def get_report(self, report_id: int) -> dict[str, Any] | None:
        """Get a single report by ID."""
        row = self._conn.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
        if not row:
            return None
        return self._deserialize_report_row(dict(row))

    def _deserialize_report_row(self, r: dict[str, Any]) -> dict[str, Any]:
        rid = r.get("id", "?")
        for field in ("steps", "evidence_refs", "request_ids"):
            r[field] = _parse_json_field(r[field], "[]", label=field, record_id=rid)
        return r

    def update_report_status(
        self,
        report_id: int,
        status: str,
        platform_report_id: str | None = None,
        platform_status: str | None = None,
    ) -> None:
        """Update a report's status and optional platform fields."""
        updates = ["status = ?", "updated_at = ?"]
        params: list[Any] = [status, _now()]
        if platform_report_id is not None:
            updates.append("platform_report_id = ?")
            params.append(platform_report_id)
        if platform_status is not None:
            updates.append("platform_status = ?")
            params.append(platform_status)
        params.append(report_id)
        self._conn.execute(f"UPDATE reports SET {', '.join(updates)} WHERE id = ?", params)
        self._conn.commit()
