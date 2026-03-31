"""Hunt context — SQLite persistence for all hunt data."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
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


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


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
"""


class HuntContext:
    """SQLite-backed persistence for all hunt data."""

    def __init__(self, db_path: str):
        self._db_path = db_path
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._create_tables()

    def _create_tables(self) -> None:
        self._conn.executescript(_SCHEMA_SQL)

    def close(self) -> None:
        self._conn.close()

    # ═══════════════════ HUNT CRUD ═══════════════════

    def create_hunt(self, hunt: Hunt) -> str:
        now = _now()
        scope_json = json.dumps(
            {"rules": [{"pattern": r.pattern, "type": r.rule_type.value, "action": r.action.value} for r in hunt.scope.rules]}
        )
        self._conn.execute(
            "INSERT INTO hunts (id, name, status, scope_json, config_json, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (hunt.id, hunt.name, hunt.status.value, scope_json, json.dumps(hunt.config), now, now),
        )
        for rule in hunt.scope.rules:
            self._conn.execute(
                "INSERT OR IGNORE INTO scope_rules (hunt_id, pattern, rule_type, action) VALUES (?, ?, ?, ?)",
                (hunt.id, rule.pattern, rule.rule_type.value, rule.action.value),
            )
        self._conn.commit()
        return hunt.id

    def get_hunt(self, hunt_id: str) -> Hunt:
        row = self._conn.execute("SELECT * FROM hunts WHERE id = ?", (hunt_id,)).fetchone()
        if not row:
            raise HuntNotFoundError(f"Hunt '{hunt_id}' not found")
        return self._row_to_hunt(row)

    def list_hunts(self) -> list[Hunt]:
        rows = self._conn.execute("SELECT * FROM hunts ORDER BY created_at DESC").fetchall()
        return [self._row_to_hunt(r) for r in rows]

    def update_hunt_status(self, hunt_id: str, status: HuntStatus) -> None:
        self.get_hunt(hunt_id)  # raises if not found
        self._conn.execute(
            "UPDATE hunts SET status = ?, updated_at = ? WHERE id = ?",
            (status.value, _now(), hunt_id),
        )
        self._conn.commit()

    def _row_to_hunt(self, row: sqlite3.Row) -> Hunt:
        scope_data = json.loads(row["scope_json"])
        rules = [
            ScopeRule(
                pattern=r["pattern"],
                rule_type=ScopeRuleType(r["type"]),
                action=ScopeAction(r["action"]),
            )
            for r in scope_data.get("rules", [])
        ]
        return Hunt(
            id=row["id"],
            name=row["name"],
            status=HuntStatus(row["status"]),
            scope=ScopeConfig(rules=rules),
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            config=json.loads(row["config_json"]),
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
                hunt_id, record.get("host", ""), record.get("ip"),
                record.get("port") or 0, record.get("scheme") or "",
                record.get("url"), record.get("status_code"),
                record.get("title"), record.get("webserver"), record.get("content_length"),
                record.get("content_type"), techs, record.get("tls_version"),
                record.get("final_url"), now, now, now,
            ),
        )

    def upsert_port(self, hunt_id: str, record: dict[str, Any]) -> None:
        now = _now()
        self._conn.execute(
            """INSERT INTO ports (hunt_id, host, ip, port, protocol, first_seen_at, last_seen_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(hunt_id, host, port, protocol) DO UPDATE SET
                ip = excluded.ip,
                last_seen_at = excluded.last_seen_at""",
            (
                hunt_id, record["host"], record.get("ip"), record["port"],
                record.get("protocol", "tcp"), now, now,
            ),
        )

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
                hunt_id, record["url"], record.get("host"), record.get("path"),
                record.get("query"), record.get("method", "GET"), record.get("status_code"),
                sources_json, record.get("found_on"), now, now, source,
            ),
        )

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
            (hunt_id, host, tech["name"], tech.get("version"), tech.get("detail"),
             sources_json, now, now, source),
        )

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
                hunt_id, record["url"], record.get("input_value"),
                record.get("status_code", 0), record.get("content_length"),
                record.get("word_count"), record.get("line_count"),
                record.get("content_type"), record.get("redirect_location"),
                now, now,
            ),
        )

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
            "directory": lambda r: self.upsert_directory(hunt_id, r),
        }
        fn = dispatch.get(table)
        if not fn:
            raise ValueError(f"Unknown table: {table}")
        with self._conn:
            for record in records:
                fn(record)

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

    def get_directories(
        self, hunt_id: str, url_prefix: str | None = None
    ) -> list[dict[str, Any]]:
        if url_prefix:
            rows = self._conn.execute(
                "SELECT * FROM directories WHERE hunt_id = ? AND url LIKE ? ORDER BY url",
                (hunt_id, f"{url_prefix}%"),
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
        now = _now()
        cursor = self._conn.execute(
            """INSERT INTO tool_runs
                (hunt_id, tool_name, command_json, status, started_at, finished_at,
                 duration_seconds, exit_code, records_found, records_filtered, timed_out, error_message)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                hunt_id, result.tool_name, json.dumps(result.command),
                "completed" if result.exit_code == 0 and not result.timed_out else "failed",
                now, now, result.duration_seconds, result.exit_code,
                len(result.records), result.filtered_count,
                1 if result.timed_out else 0,
                result.raw_stderr[:1000] if result.exit_code != 0 else None,
            ),
        )
        self._conn.commit()
        return cursor.lastrowid or 0

    def get_hunt_stats(self, hunt_id: str) -> dict[str, int]:
        stats = {}
        for table in ["subdomains", "hosts", "ports", "urls", "technologies", "directories"]:
            row = self._conn.execute(
                f"SELECT COUNT(*) as cnt FROM {table} WHERE hunt_id = ?", (hunt_id,)  # noqa: S608
            ).fetchone()
            stats[table] = row["cnt"] if row else 0
        # alive hosts specifically
        row = self._conn.execute(
            "SELECT COUNT(*) as cnt FROM hosts WHERE hunt_id = ? AND status_code IS NOT NULL AND status_code > 0",
            (hunt_id,),
        ).fetchone()
        stats["hosts_alive"] = row["cnt"] if row else 0
        return stats
