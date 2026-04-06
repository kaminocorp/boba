"""Entity upsert operations mixin."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from boba.core.context._helpers import _now


class UpsertMixin:
    """Upsert methods for all entity tables."""

    _conn: sqlite3.Connection
    _in_transaction: bool

    def _maybe_commit(self) -> None: ...  # provided by HuntContext

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
                ip = COALESCE(excluded.ip, hosts.ip),
                url = COALESCE(excluded.url, hosts.url),
                status_code = COALESCE(excluded.status_code, hosts.status_code),
                title = COALESCE(excluded.title, hosts.title),
                webserver = COALESCE(excluded.webserver, hosts.webserver),
                content_length = COALESCE(excluded.content_length, hosts.content_length),
                content_type = COALESCE(excluded.content_type, hosts.content_type),
                technologies = CASE WHEN excluded.technologies = '[]'
                    THEN hosts.technologies ELSE excluded.technologies END,
                tls_version = COALESCE(excluded.tls_version, hosts.tls_version),
                final_url = COALESCE(excluded.final_url, hosts.final_url),
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
                ip = COALESCE(excluded.ip, ports.ip),
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
                status_code = COALESCE(excluded.status_code, directories.status_code),
                content_length = COALESCE(excluded.content_length, directories.content_length),
                word_count = COALESCE(excluded.word_count, directories.word_count),
                line_count = COALESCE(excluded.line_count, directories.line_count),
                content_type = COALESCE(excluded.content_type, directories.content_type),
                redirect_location = COALESCE(excluded.redirect_location, directories.redirect_location),
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

    def upsert_parameter(self, hunt_id: str, record: dict[str, Any], source: str = "") -> None:
        now = _now()
        sources_json = json.dumps([source]) if source else "[]"
        self._conn.execute(
            """INSERT INTO parameters
                (hunt_id, url, method, name, param_type, sources, confirmed, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(hunt_id, url, method, name, param_type) DO UPDATE SET
                sources = (
                    SELECT json_group_array(DISTINCT value) FROM (
                        SELECT value FROM json_each(parameters.sources)
                        UNION ALL
                        SELECT ?
                    ) WHERE value != '' AND value IS NOT NULL
                ),
                confirmed = MAX(parameters.confirmed, excluded.confirmed),
                updated_at = excluded.updated_at""",
            (
                hunt_id,
                record["url"],
                (record.get("method") or "GET").upper(),
                record["name"],
                record.get("param_type", "query"),
                sources_json,
                1 if record.get("confirmed") else 0,
                now,
                now,
                source,
            ),
        )
        self._maybe_commit()

    def upsert_secret(self, hunt_id: str, record: dict[str, Any], source: str = "") -> None:
        now = _now()
        sources_json = json.dumps([source]) if source else "[]"
        rule_id = record.get("rule_id", "unknown")
        secret_type = record.get("secret_type", "other")
        file_path = record.get("file_path", "")
        repo = record.get("repo", "")
        line_number = record.get("line_number")
        match_preview = record.get("match_preview", "")
        commit_sha = record.get("commit", record.get("commit_sha", ""))
        author = record.get("author", "")
        date = record.get("date", "")
        entropy = record.get("entropy")

        if line_number is None:
            existing = self._conn.execute(
                """SELECT id FROM secrets
                WHERE hunt_id = ? AND repo = ? AND file_path = ? AND rule_id = ?
                  AND line_number IS NULL""",
                (hunt_id, repo, file_path, rule_id),
            ).fetchone()
            if existing:
                self._conn.execute(
                    """UPDATE secrets SET
                        secret_type = ?,
                        match_preview = CASE
                            WHEN ? != '' THEN ?
                            ELSE match_preview
                        END,
                        commit_sha = CASE
                            WHEN ? != '' THEN ?
                            ELSE commit_sha
                        END,
                        author = CASE
                            WHEN ? != '' THEN ?
                            ELSE author
                        END,
                        date = CASE
                            WHEN ? != '' THEN ?
                            ELSE date
                        END,
                        entropy = COALESCE(?, entropy),
                        sources = (
                            SELECT json_group_array(DISTINCT value) FROM (
                                SELECT value FROM json_each(secrets.sources)
                                UNION ALL
                                SELECT ?
                            ) WHERE value != '' AND value IS NOT NULL
                        )
                    WHERE id = ?""",
                    (
                        secret_type,
                        match_preview,
                        match_preview,
                        commit_sha,
                        commit_sha,
                        author,
                        author,
                        date,
                        date,
                        entropy,
                        source,
                        existing["id"],
                    ),
                )
            else:
                self._conn.execute(
                    """INSERT INTO secrets
                        (hunt_id, rule_id, secret_type, file_path, repo,
                         line_number, match_preview, commit_sha, author, date,
                         entropy, sources, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        hunt_id,
                        rule_id,
                        secret_type,
                        file_path,
                        repo,
                        None,
                        match_preview,
                        commit_sha,
                        author,
                        date,
                        entropy,
                        sources_json,
                        now,
                    ),
                )
        else:
            self._conn.execute(
                """INSERT INTO secrets
                    (hunt_id, rule_id, secret_type, file_path, repo,
                     line_number, match_preview, commit_sha, author, date,
                     entropy, sources, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(hunt_id, repo, file_path, rule_id, line_number) DO UPDATE SET
                    secret_type = excluded.secret_type,
                    match_preview = CASE
                        WHEN excluded.match_preview != '' THEN excluded.match_preview
                        ELSE secrets.match_preview
                    END,
                    commit_sha = CASE
                        WHEN excluded.commit_sha != '' THEN excluded.commit_sha
                        ELSE secrets.commit_sha
                    END,
                    author = CASE
                        WHEN excluded.author != '' THEN excluded.author
                        ELSE secrets.author
                    END,
                    date = CASE
                        WHEN excluded.date != '' THEN excluded.date
                        ELSE secrets.date
                    END,
                    entropy = COALESCE(excluded.entropy, secrets.entropy),
                    sources = (
                        SELECT json_group_array(DISTINCT value) FROM (
                            SELECT value FROM json_each(secrets.sources)
                            UNION ALL
                            SELECT ?
                        ) WHERE value != '' AND value IS NOT NULL
                    )""",
                (
                    hunt_id,
                    rule_id,
                    secret_type,
                    file_path,
                    repo,
                    line_number,
                    match_preview,
                    commit_sha,
                    author,
                    date,
                    entropy,
                    sources_json,
                    now,
                    source,
                ),
            )
        self._maybe_commit()

    def upsert_api_endpoint(self, hunt_id: str, record: dict[str, Any], source: str = "") -> None:
        now = _now()
        sources_json = json.dumps([source]) if source else "[]"
        self._conn.execute(
            """INSERT INTO api_endpoints
                (hunt_id, url, method, status_code, content_type, content_length,
                 host, path, framework, sources, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(hunt_id, url, method) DO UPDATE SET
                status_code = COALESCE(excluded.status_code, api_endpoints.status_code),
                content_type = CASE
                    WHEN excluded.content_type != '' THEN excluded.content_type
                    ELSE api_endpoints.content_type
                END,
                content_length = COALESCE(excluded.content_length, api_endpoints.content_length),
                host = CASE
                    WHEN excluded.host != '' THEN excluded.host
                    ELSE api_endpoints.host
                END,
                path = CASE
                    WHEN excluded.path != '' THEN excluded.path
                    ELSE api_endpoints.path
                END,
                framework = CASE
                    WHEN excluded.framework != '' THEN excluded.framework
                    ELSE api_endpoints.framework
                END,
                sources = (
                    SELECT json_group_array(DISTINCT value) FROM (
                        SELECT value FROM json_each(api_endpoints.sources)
                        UNION ALL
                        SELECT ?
                    ) WHERE value != '' AND value IS NOT NULL
                ),
                updated_at = excluded.updated_at""",
            (
                hunt_id,
                record.get("url", ""),
                (record.get("method") or "GET").upper(),
                record.get("status_code"),
                record.get("content_type", ""),
                record.get("content_length"),
                record.get("host", ""),
                record.get("path", ""),
                record.get("framework", ""),
                sources_json,
                now,
                now,
                source,
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
            "parameter": lambda r: self.upsert_parameter(hunt_id, r, source or r.get("source", "")),
            "secret": lambda r: self.upsert_secret(hunt_id, r, source or r.get("source", "")),
            "api_endpoint": lambda r: self.upsert_api_endpoint(
                hunt_id, r, source or r.get("source", "")
            ),
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
