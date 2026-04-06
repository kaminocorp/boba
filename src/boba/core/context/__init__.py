"""Hunt context — SQLite persistence for all hunt data."""

from __future__ import annotations

import logging
import sqlite3
from typing import Any

from boba.core.context._helpers import _json_array_merge, _parse_json_field
from boba.core.context._schema import _SCHEMA_SQL
from boba.core.context._hunt_crud import HuntCrudMixin
from boba.core.context._upserts import UpsertMixin
from boba.core.context._queries import QueryMixin
from boba.core.context._http_history import HttpHistoryMixin
from boba.core.context._sessions import SessionMixin
from boba.core.context._findings import FindingMixin
from boba.core.context._oob import OobMixin
from boba.core.context._coverage import CoverageMixin
from boba.core.context._dedup import DedupMixin
from boba.core.context._chains import ChainMixin
from boba.core.context._reports import ReportMixin

logger = logging.getLogger(__name__)

# Re-export for backward compatibility (used by tests/test_fixes_0214.py)
__all__ = ["HuntContext", "_parse_json_field"]


class HuntContext(
    HuntCrudMixin,
    UpsertMixin,
    QueryMixin,
    HttpHistoryMixin,
    SessionMixin,
    FindingMixin,
    OobMixin,
    CoverageMixin,
    DedupMixin,
    ChainMixin,
    ReportMixin,
):
    """SQLite-backed persistence for all hunt data.

    **Thread safety**: HuntContext is NOT thread-safe. It wraps a single
    ``sqlite3.Connection`` (which defaults to ``check_same_thread=True``).
    Each thread must use its own HuntContext instance.
    """

    def __init__(self, db_path: str):
        self._db_path = db_path
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._in_transaction = False

        # Register custom SQL functions
        self._conn.create_function("json_array_merge", 2, _json_array_merge, deterministic=True)

        result = self._conn.execute("PRAGMA journal_mode=WAL").fetchone()
        if result[0].upper() != "WAL":
            raise RuntimeError(
                f"Failed to enable SQLite WAL mode (got '{result[0]}'). "
                "Check database file permissions and available disk space."
            )

        self._conn.execute("PRAGMA foreign_keys=ON")
        fk = self._conn.execute("PRAGMA foreign_keys").fetchone()
        if not fk[0]:
            logger.warning("Failed to enable foreign_keys")

        self._create_tables()
        self._maybe_migrate()

    def _create_tables(self) -> None:
        self._conn.executescript(_SCHEMA_SQL)

    def _maybe_migrate(self) -> None:
        """Apply schema migrations for existing databases.

        Uses explicit transaction (BEGIN/COMMIT) around the table rebuild to
        ensure atomicity — an interrupted migration will roll back cleanly.
        """
        # Clean up leftover temp table from a prior interrupted migration (shouldn't
        # happen with WAL journaling, but guard against manual DB edits).
        existing_tables = {
            r[0]
            for r in self._conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        if "_findings_old" in existing_tables and "findings" not in existing_tables:
            self._conn.execute("ALTER TABLE _findings_old RENAME TO findings")
            self._conn.commit()
        elif "_findings_old" in existing_tables:
            self._conn.execute("DROP TABLE _findings_old")
            self._conn.commit()

        columns = {row[1] for row in self._conn.execute("PRAGMA table_info(findings)").fetchall()}
        if "method" not in columns:
            logger.info("Migrating findings table: adding 'method' column + updated UNIQUE")
            try:
                with self._conn:
                    self._conn.execute("ALTER TABLE findings RENAME TO _findings_old")
                    self._conn.execute("""
                        CREATE TABLE findings (
                            id               INTEGER PRIMARY KEY AUTOINCREMENT,
                            hunt_id          TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
                            finding_type     TEXT NOT NULL,
                            severity         TEXT NOT NULL DEFAULT 'info',
                            title            TEXT NOT NULL,
                            description      TEXT,
                            url              TEXT,
                            endpoint         TEXT,
                            parameter        TEXT NOT NULL DEFAULT '',
                            method           TEXT NOT NULL DEFAULT '',
                            evidence         TEXT,
                            request_ids      TEXT DEFAULT '[]',
                            tool_run_id      INTEGER REFERENCES tool_runs(id),
                            confirmed        INTEGER DEFAULT 0,
                            false_positive   INTEGER DEFAULT 0,
                            reported         INTEGER DEFAULT 0,
                            template_id      TEXT,
                            tags             TEXT DEFAULT '[]',
                            created_at       TEXT NOT NULL,
                            updated_at       TEXT NOT NULL,
                            UNIQUE(hunt_id, finding_type, url, method, parameter)
                        )
                    """)
                    self._conn.execute("""
                        INSERT INTO findings
                            (id, hunt_id, finding_type, severity, title, description,
                             url, endpoint, parameter, method, evidence, request_ids,
                             tool_run_id, confirmed, false_positive, reported,
                             template_id, tags, created_at, updated_at)
                        SELECT
                            id, hunt_id, finding_type, severity, title, description,
                            url, endpoint, parameter, '', evidence, request_ids,
                            tool_run_id, confirmed, false_positive, reported,
                            template_id, tags, created_at, updated_at
                        FROM _findings_old
                    """)
                    self._conn.execute("DROP TABLE _findings_old")
            except Exception:
                raise

    def _maybe_commit(self) -> None:
        """Commit unless inside a batch transaction (upsert_records)."""
        if not self._in_transaction:
            self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> HuntContext:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()
