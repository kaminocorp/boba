"""Hunt context — SQLite persistence for all hunt data."""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from boba.core.errors import HuntNotFoundError
from boba.core.models import (
    Hunt,
    HuntStatus,
    ScopeAction,
    ScopeConfig,
    ScopeRule,
    ScopeRuleType,
    ToolResult,
)

logger = logging.getLogger(__name__)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_json_field(
    value: str | None, default: str = "{}", *, label: str = "field", record_id: Any = "?"
) -> Any:
    """Parse a JSON field with fallback, logging warnings on malformed data."""
    try:
        return json.loads(value or default)
    except (json.JSONDecodeError, TypeError) as exc:
        logger.warning("Malformed %s in record %s: %s", label, record_id, exc)
        return json.loads(default)


_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS hunts (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'active',
    scope_json  TEXT NOT NULL,
    config_json TEXT NOT NULL DEFAULT '{}',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scope_rules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id     TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    pattern     TEXT NOT NULL,
    rule_type   TEXT NOT NULL,
    action      TEXT NOT NULL DEFAULT 'include',
    UNIQUE(hunt_id, pattern, rule_type)
);

CREATE TABLE IF NOT EXISTS subdomains (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id       TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    subdomain     TEXT NOT NULL,
    root_domain   TEXT,
    sources       TEXT NOT NULL DEFAULT '[]',
    first_seen_at TEXT NOT NULL,
    last_seen_at  TEXT NOT NULL,
    UNIQUE(hunt_id, subdomain)
);

CREATE TABLE IF NOT EXISTS hosts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id         TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    host            TEXT NOT NULL,
    ip              TEXT,
    port            INTEGER NOT NULL DEFAULT 0,
    scheme          TEXT NOT NULL DEFAULT '',
    url             TEXT,
    status_code     INTEGER,
    title           TEXT,
    webserver       TEXT,
    content_length  INTEGER,
    content_type    TEXT,
    technologies    TEXT DEFAULT '[]',
    tls_version     TEXT,
    final_url       TEXT,
    first_seen_at   TEXT NOT NULL,
    last_seen_at    TEXT NOT NULL,
    last_checked_at TEXT NOT NULL,
    UNIQUE(hunt_id, host, port, scheme)
);

CREATE TABLE IF NOT EXISTS ports (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id       TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    host          TEXT NOT NULL,
    ip            TEXT,
    port          INTEGER NOT NULL,
    protocol      TEXT NOT NULL DEFAULT 'tcp',
    first_seen_at TEXT NOT NULL,
    last_seen_at  TEXT NOT NULL,
    UNIQUE(hunt_id, host, port, protocol)
);

CREATE TABLE IF NOT EXISTS urls (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id       TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    url           TEXT NOT NULL,
    host          TEXT,
    path          TEXT,
    query         TEXT,
    method        TEXT NOT NULL DEFAULT 'GET',
    status_code   INTEGER,
    sources       TEXT NOT NULL DEFAULT '[]',
    found_on      TEXT,
    first_seen_at TEXT NOT NULL,
    last_seen_at  TEXT NOT NULL,
    UNIQUE(hunt_id, url, method)
);

CREATE TABLE IF NOT EXISTS technologies (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id       TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    host          TEXT NOT NULL,
    name          TEXT NOT NULL,
    version       TEXT,
    detail        TEXT,
    sources       TEXT NOT NULL DEFAULT '[]',
    first_seen_at TEXT NOT NULL,
    last_seen_at  TEXT NOT NULL,
    UNIQUE(hunt_id, host, name)
);

CREATE TABLE IF NOT EXISTS directories (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id           TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    url               TEXT NOT NULL,
    input_value       TEXT,
    status_code       INTEGER NOT NULL,
    content_length    INTEGER,
    word_count        INTEGER,
    line_count        INTEGER,
    content_type      TEXT,
    redirect_location TEXT,
    first_seen_at     TEXT NOT NULL,
    last_seen_at      TEXT NOT NULL,
    UNIQUE(hunt_id, url)
);

CREATE TABLE IF NOT EXISTS tool_runs (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id          TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    tool_name        TEXT NOT NULL,
    command_json     TEXT NOT NULL,
    status           TEXT NOT NULL,
    started_at       TEXT NOT NULL,
    finished_at      TEXT,
    duration_seconds REAL,
    exit_code        INTEGER,
    records_found    INTEGER,
    records_filtered INTEGER,
    timed_out        INTEGER DEFAULT 0,
    error_message    TEXT
);

CREATE INDEX IF NOT EXISTS idx_subdomains_hunt    ON subdomains(hunt_id);
CREATE INDEX IF NOT EXISTS idx_hosts_hunt         ON hosts(hunt_id);
CREATE INDEX IF NOT EXISTS idx_hosts_status       ON hosts(hunt_id, status_code);
CREATE INDEX IF NOT EXISTS idx_ports_hunt         ON ports(hunt_id);
CREATE INDEX IF NOT EXISTS idx_ports_host         ON ports(hunt_id, host);
CREATE INDEX IF NOT EXISTS idx_urls_hunt          ON urls(hunt_id);
CREATE INDEX IF NOT EXISTS idx_urls_host          ON urls(hunt_id, host);
CREATE INDEX IF NOT EXISTS idx_technologies_hunt  ON technologies(hunt_id);
CREATE INDEX IF NOT EXISTS idx_directories_hunt   ON directories(hunt_id);
CREATE INDEX IF NOT EXISTS idx_tool_runs_hunt     ON tool_runs(hunt_id);
CREATE INDEX IF NOT EXISTS idx_tool_runs_status   ON tool_runs(hunt_id, status);

-- ═══════════════════ V2: Interaction tables ═══════════════════

CREATE TABLE IF NOT EXISTS http_history (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id               TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    session_name          TEXT,
    tool_run_id           INTEGER REFERENCES tool_runs(id),
    source                TEXT NOT NULL DEFAULT 'manual',

    method                TEXT NOT NULL,
    url                   TEXT NOT NULL,
    host                  TEXT NOT NULL,
    path                  TEXT NOT NULL DEFAULT '/',
    query                 TEXT,
    request_headers       TEXT NOT NULL DEFAULT '{}',
    request_body          TEXT,
    request_body_ref      TEXT,
    content_type          TEXT,

    status_code           INTEGER,
    response_headers      TEXT DEFAULT '{}',
    response_body         TEXT,
    response_body_ref     TEXT,
    response_length       INTEGER,
    response_content_type TEXT,

    elapsed_ms            REAL,
    tls_version           TEXT,
    ip_address            TEXT,
    resource_type         TEXT,
    is_redirect           INTEGER DEFAULT 0,
    redirect_url          TEXT,

    parent_request_id     INTEGER REFERENCES http_history(id),
    tags                  TEXT DEFAULT '[]',
    notes                 TEXT,

    timestamp             TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_http_hist_hunt       ON http_history(hunt_id);
CREATE INDEX IF NOT EXISTS idx_http_hist_host       ON http_history(hunt_id, host);
CREATE INDEX IF NOT EXISTS idx_http_hist_status     ON http_history(hunt_id, status_code);
CREATE INDEX IF NOT EXISTS idx_http_hist_session    ON http_history(hunt_id, session_name);
CREATE INDEX IF NOT EXISTS idx_http_hist_source     ON http_history(hunt_id, source);
CREATE INDEX IF NOT EXISTS idx_http_hist_method_url ON http_history(hunt_id, method, url);
CREATE INDEX IF NOT EXISTS idx_http_hist_timestamp  ON http_history(hunt_id, timestamp);

CREATE TABLE IF NOT EXISTS sessions (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id          TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    name             TEXT NOT NULL,
    target_url       TEXT NOT NULL,
    auth_method      TEXT NOT NULL DEFAULT 'form',
    cookies_json     TEXT NOT NULL DEFAULT '{}',
    headers_json     TEXT NOT NULL DEFAULT '{}',
    tokens_json      TEXT NOT NULL DEFAULT '{}',
    storage_state    TEXT,
    is_valid         INTEGER DEFAULT 1,
    created_at       TEXT NOT NULL,
    last_used_at     TEXT NOT NULL,
    UNIQUE(hunt_id, name)
);

CREATE TABLE IF NOT EXISTS findings (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id          TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    finding_type     TEXT NOT NULL,
    severity         TEXT NOT NULL DEFAULT 'info',
    title            TEXT NOT NULL,
    description      TEXT,
    url              TEXT,
    endpoint         TEXT,
    parameter        TEXT NOT NULL DEFAULT '',
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
    UNIQUE(hunt_id, finding_type, url, parameter)
);

CREATE INDEX IF NOT EXISTS idx_findings_hunt     ON findings(hunt_id);
CREATE INDEX IF NOT EXISTS idx_findings_type     ON findings(hunt_id, finding_type);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(hunt_id, severity);

CREATE TABLE IF NOT EXISTS oob_listeners (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id          TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    listener_id      TEXT NOT NULL,
    callback_domain  TEXT NOT NULL,
    purpose          TEXT,
    test_payload     TEXT,
    target_url       TEXT,
    parameter        TEXT,
    interactions     TEXT DEFAULT '[]',
    created_at       TEXT NOT NULL,
    expires_at       TEXT,
    UNIQUE(hunt_id, listener_id)
);
"""


class HuntContext:
    """SQLite-backed persistence for all hunt data."""

    def __init__(self, db_path: str):
        self._db_path = db_path
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._in_transaction = False

        result = self._conn.execute("PRAGMA journal_mode=WAL").fetchone()
        if result[0].upper() != "WAL":
            logger.warning("Failed to enable WAL mode; got %s", result[0])

        self._conn.execute("PRAGMA foreign_keys=ON")
        fk = self._conn.execute("PRAGMA foreign_keys").fetchone()
        if not fk[0]:
            logger.warning("Failed to enable foreign_keys")

        self._create_tables()

    def _create_tables(self) -> None:
        self._conn.executescript(_SCHEMA_SQL)

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

    # ═══════════════════ HUNT CRUD ═══════════════════

    def create_hunt(self, hunt: Hunt) -> str:
        now = _now()
        scope_json = json.dumps(
            {
                "rules": [
                    {"pattern": r.pattern, "type": r.rule_type.value, "action": r.action.value}
                    for r in hunt.scope.rules
                ]
            }
        )
        with self._conn:
            self._conn.execute(
                "INSERT INTO hunts (id, name, status, scope_json, config_json, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    hunt.id,
                    hunt.name,
                    hunt.status.value,
                    scope_json,
                    json.dumps(hunt.config),
                    now,
                    now,
                ),
            )
            for rule in hunt.scope.rules:
                self._conn.execute(
                    "INSERT OR IGNORE INTO scope_rules (hunt_id, pattern, rule_type, action) VALUES (?, ?, ?, ?)",
                    (hunt.id, rule.pattern, rule.rule_type.value, rule.action.value),
                )
        return hunt.id

    def get_hunt(self, hunt_id: str) -> Hunt:
        row = self._conn.execute("SELECT * FROM hunts WHERE id = ?", (hunt_id,)).fetchone()
        if not row:
            raise HuntNotFoundError(f"Hunt '{hunt_id}' not found")
        return self._row_to_hunt(row)

    def list_hunts(self) -> list[Hunt]:
        rows = self._conn.execute("SELECT * FROM hunts ORDER BY created_at DESC").fetchall()
        return [self._row_to_hunt(r) for r in rows]

    # Valid state transitions: active→paused, active→completed, paused→active, paused→completed
    _VALID_TRANSITIONS: dict[HuntStatus, frozenset[HuntStatus]] = {
        HuntStatus.ACTIVE: frozenset({HuntStatus.PAUSED, HuntStatus.COMPLETED}),
        HuntStatus.PAUSED: frozenset({HuntStatus.ACTIVE, HuntStatus.COMPLETED}),
        HuntStatus.COMPLETED: frozenset(),  # terminal state
    }

    def update_hunt_status(self, hunt_id: str, status: HuntStatus) -> None:
        hunt = self.get_hunt(hunt_id)  # raises if not found
        current = HuntStatus(hunt.status) if isinstance(hunt.status, str) else hunt.status
        allowed = self._VALID_TRANSITIONS.get(current, frozenset())
        if status not in allowed:
            raise ValueError(
                f"Cannot transition hunt '{hunt_id}' from {current.value} to {status.value}. "
                f"Allowed transitions: {', '.join(s.value for s in sorted(allowed, key=lambda s: s.value)) or 'none (terminal state)'}"
            )
        self._conn.execute(
            "UPDATE hunts SET status = ?, updated_at = ? WHERE id = ?",
            (status.value, _now(), hunt_id),
        )
        self._conn.commit()

    def _row_to_hunt(self, row: sqlite3.Row) -> Hunt:
        try:
            scope_data = json.loads(row["scope_json"])
        except (json.JSONDecodeError, TypeError) as exc:
            logger.warning("Malformed scope_json for hunt %s: %s", row["id"], exc)
            scope_data = {"rules": []}
        rules = [
            ScopeRule(
                pattern=r["pattern"],
                rule_type=ScopeRuleType(r["type"]),
                action=ScopeAction(r["action"]),
            )
            for r in scope_data.get("rules", [])
        ]
        try:
            config = json.loads(row["config_json"])
        except (json.JSONDecodeError, TypeError) as exc:
            logger.warning("Malformed config_json for hunt %s: %s", row["id"], exc)
            config = {}
        return Hunt(
            id=row["id"],
            name=row["name"],
            status=HuntStatus(row["status"]),
            scope=ScopeConfig(rules=rules),
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            config=config,
        )

    # ═══════════════════ UPSERT METHODS ═══════════════════

    def upsert_subdomain(
        self, hunt_id: str, subdomain: str, root_domain: str = "", source: str = ""
    ) -> None:
        now = _now()
        sources_json = json.dumps([source]) if source else "[]"
        self._conn.execute(
            """INSERT INTO subdomains (hunt_id, subdomain, root_domain, sources, first_seen_at, last_seen_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(hunt_id, subdomain) DO UPDATE SET
                sources = (
                    SELECT json_group_array(DISTINCT value) FROM (
                        SELECT value FROM json_each(subdomains.sources)
                        UNION ALL
                        SELECT ?
                    ) WHERE value != '' AND value IS NOT NULL
                ),
                last_seen_at = excluded.last_seen_at""",
            (hunt_id, subdomain, root_domain, sources_json, now, now, source),
        )
        self._maybe_commit()

    def upsert_host(self, hunt_id: str, record: dict[str, Any]) -> None:
        now = _now()
        techs = json.dumps(record.get("technologies", []))
        self._conn.execute(
            """INSERT INTO hosts
                (hunt_id, host, ip, port, scheme, url, status_code, title, webserver,
                 content_length, content_type, technologies, tls_version, final_url,
                 first_seen_at, last_seen_at, last_checked_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(hunt_id, host, port, scheme) DO UPDATE SET
                ip = excluded.ip,
                url = excluded.url,
                status_code = excluded.status_code,
                title = excluded.title,
                webserver = excluded.webserver,
                content_length = excluded.content_length,
                content_type = excluded.content_type,
                technologies = excluded.technologies,
                tls_version = excluded.tls_version,
                final_url = excluded.final_url,
                last_seen_at = excluded.last_seen_at,
                last_checked_at = excluded.last_checked_at""",
            (
                hunt_id,
                record.get("host", ""),
                record.get("ip"),
                record.get("port") or 0,
                record.get("scheme") or "",
                record.get("url"),
                record.get("status_code"),
                record.get("title"),
                record.get("webserver"),
                record.get("content_length"),
                record.get("content_type"),
                techs,
                record.get("tls_version"),
                record.get("final_url"),
                now,
                now,
                now,
            ),
        )
        self._maybe_commit()

    def upsert_port(self, hunt_id: str, record: dict[str, Any]) -> None:
        now = _now()
        self._conn.execute(
            """INSERT INTO ports (hunt_id, host, ip, port, protocol, first_seen_at, last_seen_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(hunt_id, host, port, protocol) DO UPDATE SET
                ip = excluded.ip,
                last_seen_at = excluded.last_seen_at""",
            (
                hunt_id,
                record["host"],
                record.get("ip"),
                record["port"],
                record.get("protocol", "tcp"),
                now,
                now,
            ),
        )
        self._maybe_commit()

    def upsert_url(self, hunt_id: str, record: dict[str, Any]) -> None:
        now = _now()
        source = record.get("source", "")
        sources_json = json.dumps([source]) if source else "[]"
        self._conn.execute(
            """INSERT INTO urls
                (hunt_id, url, host, path, query, method, status_code, sources,
                 found_on, first_seen_at, last_seen_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(hunt_id, url, method) DO UPDATE SET
                sources = (
                    SELECT json_group_array(DISTINCT value) FROM (
                        SELECT value FROM json_each(urls.sources)
                        UNION ALL
                        SELECT ?
                    ) WHERE value != '' AND value IS NOT NULL
                ),
                status_code = CASE
                    WHEN excluded.status_code IS NOT NULL AND excluded.status_code > 0
                    THEN excluded.status_code
                    ELSE urls.status_code
                END,
                last_seen_at = excluded.last_seen_at""",
            (
                hunt_id,
                record["url"],
                record.get("host"),
                record.get("path"),
                record.get("query"),
                record.get("method", "GET"),
                record.get("status_code"),
                sources_json,
                record.get("found_on"),
                now,
                now,
                source,
            ),
        )
        self._maybe_commit()

    def upsert_technology(
        self, hunt_id: str, host: str, tech: dict[str, Any], source: str = ""
    ) -> None:
        now = _now()
        sources_json = json.dumps([source]) if source else "[]"
        self._conn.execute(
            """INSERT INTO technologies
                (hunt_id, host, name, version, detail, sources, first_seen_at, last_seen_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(hunt_id, host, name) DO UPDATE SET
                version = CASE
                    WHEN excluded.version IS NOT NULL AND excluded.version != ''
                    THEN excluded.version
                    ELSE technologies.version
                END,
                detail = CASE
                    WHEN excluded.detail IS NOT NULL AND excluded.detail != ''
                    THEN excluded.detail
                    ELSE technologies.detail
                END,
                sources = (
                    SELECT json_group_array(DISTINCT value) FROM (
                        SELECT value FROM json_each(technologies.sources)
                        UNION ALL
                        SELECT ?
                    ) WHERE value != '' AND value IS NOT NULL
                ),
                last_seen_at = excluded.last_seen_at""",
            (
                hunt_id,
                host,
                tech["name"],
                tech.get("version"),
                tech.get("detail"),
                sources_json,
                now,
                now,
                source,
            ),
        )
        self._maybe_commit()

    def upsert_directory(self, hunt_id: str, record: dict[str, Any]) -> None:
        now = _now()
        self._conn.execute(
            """INSERT INTO directories
                (hunt_id, url, input_value, status_code, content_length,
                 word_count, line_count, content_type, redirect_location,
                 first_seen_at, last_seen_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(hunt_id, url) DO UPDATE SET
                status_code = excluded.status_code,
                content_length = excluded.content_length,
                word_count = excluded.word_count,
                line_count = excluded.line_count,
                content_type = excluded.content_type,
                redirect_location = excluded.redirect_location,
                last_seen_at = excluded.last_seen_at""",
            (
                hunt_id,
                record["url"],
                record.get("input_value"),
                record.get("status_code", 0),
                record.get("content_length"),
                record.get("word_count"),
                record.get("line_count"),
                record.get("content_type"),
                record.get("redirect_location"),
                now,
                now,
            ),
        )
        self._maybe_commit()

    def upsert_records(
        self, hunt_id: str, table: str, records: list[dict[str, Any]], source: str = ""
    ) -> None:
        """Batch upsert — wraps all writes in a single transaction."""
        dispatch: dict[str, Any] = {
            "subdomain": lambda r: self.upsert_subdomain(
                hunt_id, r["subdomain"], r.get("root_domain", ""), source or r.get("source", "")
            ),
            "host": lambda r: self.upsert_host(hunt_id, r),
            "port": lambda r: self.upsert_port(hunt_id, r),
            "url": lambda r: self.upsert_url(hunt_id, r),
            "technology": lambda r: self.upsert_technology(
                hunt_id, r.get("host", ""), r, source or r.get("source", "")
            ),
            "directory": lambda r: self.upsert_directory(hunt_id, r),
        }
        fn = dispatch.get(table)
        if not fn:
            raise ValueError(f"Unknown table: {table}")
        self._in_transaction = True
        try:
            with self._conn:
                for record in records:
                    fn(record)
        finally:
            self._in_transaction = False

    # ═══════════════════ QUERIES ═══════════════════

    def get_subdomains(self, hunt_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM subdomains WHERE hunt_id = ? ORDER BY subdomain", (hunt_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_hosts(self, hunt_id: str, alive_only: bool = False) -> list[dict[str, Any]]:
        sql = "SELECT * FROM hosts WHERE hunt_id = ?"
        if alive_only:
            sql += " AND status_code IS NOT NULL AND status_code > 0"
        sql += " ORDER BY host"
        rows = self._conn.execute(sql, (hunt_id,)).fetchall()
        return [dict(r) for r in rows]

    def get_ports(self, hunt_id: str, host: str | None = None) -> list[dict[str, Any]]:
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

    def get_tool_runs(self, hunt_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM tool_runs WHERE hunt_id = ? ORDER BY started_at DESC", (hunt_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    def log_tool_run(self, hunt_id: str, result: ToolResult) -> int:
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
            "http_history",
            "sessions",
            "findings",
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

    # ═══════════════════ V2: HTTP HISTORY ═══════════════════

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

    # ═══════════════════ V2: SESSIONS ═══════════════════

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

    # ═══════════════════ V2: FINDINGS ═══════════════════

    def upsert_finding(self, hunt_id: str, finding: dict[str, Any]) -> int:
        """Upsert a vulnerability finding. Returns the row ID."""
        now = _now()
        cursor = self._conn.execute(
            """INSERT INTO findings
                (hunt_id, finding_type, severity, title, description,
                 url, endpoint, parameter, evidence, request_ids,
                 tool_run_id, confirmed, false_positive, reported,
                 template_id, tags, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(hunt_id, finding_type, url, parameter) DO UPDATE SET
                severity = excluded.severity,
                title = excluded.title,
                description = excluded.description,
                evidence = CASE
                    WHEN findings.evidence IS NULL
                        OR findings.evidence IN ('null', '[]')
                        THEN excluded.evidence
                    WHEN excluded.evidence IS NULL
                        OR excluded.evidence IN ('null', '[]')
                        THEN findings.evidence
                    ELSE substr(findings.evidence, 1,
                                length(findings.evidence) - 1)
                         || ',' || substr(excluded.evidence, 2)
                END,
                request_ids = CASE
                    WHEN findings.request_ids IS NULL
                        OR findings.request_ids IN ('null', '[]')
                        THEN excluded.request_ids
                    WHEN excluded.request_ids IS NULL
                        OR excluded.request_ids IN ('null', '[]')
                        THEN findings.request_ids
                    ELSE substr(findings.request_ids, 1,
                                length(findings.request_ids) - 1)
                         || ',' || substr(excluded.request_ids, 2)
                END,
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
                finding.get("url"),
                finding.get("endpoint"),
                finding.get("parameter", ""),
                json.dumps(finding.get("evidence")) if finding.get("evidence") else None,
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
        return cursor.lastrowid or 0

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

    # ═══════════════════ V2: OOB LISTENERS ═══════════════════

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
