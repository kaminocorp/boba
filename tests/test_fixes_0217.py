"""Tests for 0.2.17 fixes: adapter type guards, base.py JSON_OBJECT parsing,
finding upsert flag preservation, HttpClient response body limit, CLI cleanup logging."""

from __future__ import annotations

import logging
from unittest.mock import MagicMock

from boba.core.context import HuntContext
from boba.core.models import ScopeConfig


# ---------------------------------------------------------------------------
# Adapter type guard tests
# ---------------------------------------------------------------------------


class TestFfufTypeGuard:
    """ffuf parse_record handles non-dict 'input' field."""

    def test_input_field_is_none(self):
        from boba.adapters.ffuf import FfufAdapter
        from boba.core.scope import ScopeEngine

        scope = ScopeEngine(ScopeConfig(rules=[]))
        adapter = FfufAdapter(scope_engine=scope)
        record = adapter.parse_record({"url": "http://a.com/test", "input": None, "status": 200})
        assert record["input_value"] == ""

    def test_input_field_is_string(self):
        from boba.adapters.ffuf import FfufAdapter
        from boba.core.scope import ScopeEngine

        scope = ScopeEngine(ScopeConfig(rules=[]))
        adapter = FfufAdapter(scope_engine=scope)
        record = adapter.parse_record({"url": "http://a.com/test", "input": "bad", "status": 200})
        assert record["input_value"] == ""

    def test_input_field_is_dict(self):
        from boba.adapters.ffuf import FfufAdapter
        from boba.core.scope import ScopeEngine

        scope = ScopeEngine(ScopeConfig(rules=[]))
        adapter = FfufAdapter(scope_engine=scope)
        record = adapter.parse_record(
            {"url": "http://a.com/admin", "input": {"FUZZ": "admin"}, "status": 200}
        )
        assert record["input_value"] == "admin"


class TestKatanaTypeGuard:
    """katana parse_record handles non-dict 'request'/'response' fields."""

    def _adapter(self):
        from boba.adapters.katana import KatanaAdapter
        from boba.core.scope import ScopeEngine

        return KatanaAdapter(scope_engine=ScopeEngine(ScopeConfig(rules=[])))

    def test_request_is_none(self):
        adapter = self._adapter()
        record = adapter.parse_record(
            {"endpoint": "http://a.com/page", "request": None, "response": None}
        )
        assert record["method"] == "GET"
        assert record["status_code"] is None

    def test_request_is_string(self):
        adapter = self._adapter()
        record = adapter.parse_record(
            {"endpoint": "http://a.com/page", "request": "invalid", "response": "invalid"}
        )
        assert record["method"] == "GET"

    def test_request_is_dict(self):
        adapter = self._adapter()
        record = adapter.parse_record(
            {
                "endpoint": "http://a.com/page",
                "request": {"method": "POST", "endpoint": "http://a.com/page"},
                "response": {"status_code": 200},
            }
        )
        assert record["method"] == "POST"
        assert record["status_code"] == 200


class TestHttpxRunnerTypeGuard:
    """httpx parse_record handles non-list 'a' field and non-dict 'tls' field."""

    def _adapter(self):
        from boba.adapters.httpx_runner import HttpxRunnerAdapter
        from boba.core.scope import ScopeEngine

        return HttpxRunnerAdapter(scope_engine=ScopeEngine(ScopeConfig(rules=[])))

    def test_a_field_is_string(self):
        adapter = self._adapter()
        record = adapter.parse_record(
            {"input": "example.com", "a": "192.168.1.1", "host": "example.com"}
        )
        # Should NOT take first char of string; should fall back to empty string
        assert record["ip"] == ""

    def test_a_field_is_list(self):
        adapter = self._adapter()
        record = adapter.parse_record({"input": "example.com", "a": ["1.2.3.4", "5.6.7.8"]})
        assert record["ip"] == "1.2.3.4"

    def test_tls_field_is_none(self):
        adapter = self._adapter()
        record = adapter.parse_record({"input": "example.com", "tls": None})
        assert record["tls_version"] == ""

    def test_tls_field_is_string(self):
        adapter = self._adapter()
        record = adapter.parse_record({"input": "example.com", "tls": "TLS1.2"})
        assert record["tls_version"] == ""

    def test_tls_field_is_dict(self):
        adapter = self._adapter()
        record = adapter.parse_record({"input": "example.com", "tls": {"version": "TLS1.3"}})
        assert record["tls_version"] == "TLS1.3"


class TestNucleiTypeGuard:
    """nuclei parse_record handles non-dict 'info' field."""

    def _adapter(self):
        from boba.adapters.nuclei import NucleiAdapter
        from boba.core.scope import ScopeEngine

        return NucleiAdapter(scope_engine=ScopeEngine(ScopeConfig(rules=[])))

    def test_info_field_is_none(self):
        adapter = self._adapter()
        record = adapter.parse_record(
            {"template-id": "test-123", "info": None, "host": "example.com"}
        )
        assert record["template_name"] == ""
        assert record["severity"] == "info"

    def test_info_field_is_string(self):
        adapter = self._adapter()
        record = adapter.parse_record(
            {"template-id": "test-123", "info": "invalid", "host": "example.com"}
        )
        assert record["template_name"] == ""

    def test_info_field_is_dict(self):
        adapter = self._adapter()
        record = adapter.parse_record(
            {
                "template-id": "test-123",
                "info": {"name": "Test Vuln", "severity": "high"},
                "host": "example.com",
            }
        )
        assert record["template_name"] == "Test Vuln"
        assert record["severity"] == "high"


class TestNaabuSafeInt:
    """naabu parse_record uses _safe_int for port field."""

    def _adapter(self):
        from boba.adapters.naabu import NaabuAdapter
        from boba.core.scope import ScopeEngine

        return NaabuAdapter(scope_engine=ScopeEngine(ScopeConfig(rules=[])))

    def test_port_is_string(self):
        adapter = self._adapter()
        record = adapter.parse_record({"host": "a.com", "port": "8080"})
        assert record["port"] == 8080
        assert isinstance(record["port"], int)

    def test_port_is_none(self):
        adapter = self._adapter()
        record = adapter.parse_record({"host": "a.com", "port": None})
        assert record["port"] == 0

    def test_port_is_invalid_string(self):
        adapter = self._adapter()
        record = adapter.parse_record({"host": "a.com", "port": "not_a_port"})
        assert record["port"] == 0


# ---------------------------------------------------------------------------
# BaseAdapter JSON_OBJECT parsing for non-dict values
# ---------------------------------------------------------------------------


class TestBaseAdapterJsonObjectParsing:
    """BaseAdapter.parse_output handles non-dict JSON in JSON_OBJECT mode."""

    def test_json_string_value(self):
        from boba.adapters.ffuf import FfufAdapter
        from boba.core.models import OutputFormat
        from boba.core.scope import ScopeEngine

        scope = ScopeEngine(ScopeConfig(rules=[]))
        adapter = FfufAdapter(scope_engine=scope)
        assert adapter.OUTPUT_FORMAT == OutputFormat.JSON_OBJECT
        # Simulate tool outputting a bare string as JSON
        records, parse_errors = adapter.parse_output('"just a string"')
        assert records == []
        assert parse_errors == 1

    def test_json_number_value(self):
        from boba.adapters.ffuf import FfufAdapter
        from boba.core.scope import ScopeEngine

        scope = ScopeEngine(ScopeConfig(rules=[]))
        adapter = FfufAdapter(scope_engine=scope)
        records, parse_errors = adapter.parse_output("42")
        assert records == []
        assert parse_errors == 1

    def test_json_null_value(self):
        from boba.adapters.ffuf import FfufAdapter
        from boba.core.scope import ScopeEngine

        scope = ScopeEngine(ScopeConfig(rules=[]))
        adapter = FfufAdapter(scope_engine=scope)
        records, parse_errors = adapter.parse_output("null")
        assert records == []
        assert parse_errors == 1


# ---------------------------------------------------------------------------
# Finding upsert flag preservation
# ---------------------------------------------------------------------------


class TestFindingUpsertFlagPreservation:
    """upsert_finding preserves manual confirmed/false_positive flags via MAX()."""

    def test_manual_confirmed_not_overwritten(self, tmp_path):
        ctx = HuntContext(str(tmp_path / "test.db"))
        hunt_id = "test-hunt"
        ctx._conn.execute(
            "INSERT INTO hunts (id, name, status, scope_json, created_at, updated_at) "
            "VALUES (?, 'Test', 'active', '{}', datetime('now'), datetime('now'))",
            (hunt_id,),
        )
        ctx._conn.commit()

        # First insert: confirmed by tool
        ctx.upsert_finding(
            hunt_id,
            {
                "finding_type": "xss",
                "title": "XSS on /page",
                "url": "http://a.com/page",
                "parameter": "q",
                "confirmed": True,
            },
        )

        # Verify confirmed=1
        row = ctx._conn.execute(
            "SELECT confirmed FROM findings WHERE hunt_id=? AND url=?",
            (hunt_id, "http://a.com/page"),
        ).fetchone()
        assert row[0] == 1

        # Re-scan: tool does NOT confirm (confirmed=False)
        ctx.upsert_finding(
            hunt_id,
            {
                "finding_type": "xss",
                "title": "XSS on /page (rescan)",
                "url": "http://a.com/page",
                "parameter": "q",
                "confirmed": False,
            },
        )

        # confirmed should still be 1 (preserved via MAX)
        row = ctx._conn.execute(
            "SELECT confirmed FROM findings WHERE hunt_id=? AND url=?",
            (hunt_id, "http://a.com/page"),
        ).fetchone()
        assert row[0] == 1
        ctx.close()

    def test_false_positive_not_overwritten(self, tmp_path):
        ctx = HuntContext(str(tmp_path / "test.db"))
        hunt_id = "test-hunt"
        ctx._conn.execute(
            "INSERT INTO hunts (id, name, status, scope_json, created_at, updated_at) "
            "VALUES (?, 'Test', 'active', '{}', datetime('now'), datetime('now'))",
            (hunt_id,),
        )
        ctx._conn.commit()

        # Mark as false positive manually
        ctx.upsert_finding(
            hunt_id,
            {
                "finding_type": "sqli",
                "title": "SQLi on /api",
                "url": "http://a.com/api",
                "parameter": "id",
                "false_positive": True,
            },
        )

        # Re-scan: tool doesn't set false_positive
        ctx.upsert_finding(
            hunt_id,
            {
                "finding_type": "sqli",
                "title": "SQLi on /api (rescan)",
                "url": "http://a.com/api",
                "parameter": "id",
                "false_positive": False,
            },
        )

        row = ctx._conn.execute(
            "SELECT false_positive FROM findings WHERE hunt_id=? AND url=?",
            (hunt_id, "http://a.com/api"),
        ).fetchone()
        assert row[0] == 1
        ctx.close()

    def test_upgrade_from_unconfirmed_to_confirmed(self, tmp_path):
        ctx = HuntContext(str(tmp_path / "test.db"))
        hunt_id = "test-hunt"
        ctx._conn.execute(
            "INSERT INTO hunts (id, name, status, scope_json, created_at, updated_at) "
            "VALUES (?, 'Test', 'active', '{}', datetime('now'), datetime('now'))",
            (hunt_id,),
        )
        ctx._conn.commit()

        # Initial: not confirmed
        ctx.upsert_finding(
            hunt_id,
            {
                "finding_type": "xss",
                "title": "XSS on /page",
                "url": "http://a.com/page",
                "parameter": "q",
                "confirmed": False,
            },
        )

        # Second pass: confirmed
        ctx.upsert_finding(
            hunt_id,
            {
                "finding_type": "xss",
                "title": "XSS on /page",
                "url": "http://a.com/page",
                "parameter": "q",
                "confirmed": True,
            },
        )

        row = ctx._conn.execute(
            "SELECT confirmed FROM findings WHERE hunt_id=? AND url=?",
            (hunt_id, "http://a.com/page"),
        ).fetchone()
        assert row[0] == 1
        ctx.close()


# ---------------------------------------------------------------------------
# HttpClient response body size limit
# ---------------------------------------------------------------------------


class TestHttpClientResponseLimit:
    """HttpClient truncates oversized response bodies."""

    def test_max_response_bytes_stored(self):
        from boba.interaction.http import HttpClient

        sink = MagicMock()
        client = HttpClient(sink=sink, max_response_bytes=1024)
        assert client._max_response_bytes == 1024

    def test_default_max_response_bytes(self):
        from boba.interaction.http import HttpClient, DEFAULT_MAX_RESPONSE_BYTES

        sink = MagicMock()
        client = HttpClient(sink=sink)
        assert client._max_response_bytes == DEFAULT_MAX_RESPONSE_BYTES
        assert DEFAULT_MAX_RESPONSE_BYTES == 50 * 1024 * 1024


# ---------------------------------------------------------------------------
# CLI cleanup logging
# ---------------------------------------------------------------------------


class TestCliCleanupLogging:
    """CLI _safe_close logs exceptions instead of silently swallowing."""

    def test_safe_close_logs_on_failure(self, caplog):
        from boba.cli.main import _safe_close

        manager = MagicMock()
        manager.close_context.side_effect = RuntimeError("db locked")
        with caplog.at_level(logging.DEBUG, logger="boba.cli.main"):
            _safe_close(manager)
        assert "db locked" in caplog.text

    def test_safe_close_http_logs_on_failure(self, caplog):
        from boba.cli.main import _safe_close_http

        client = MagicMock()

        # Make the close coroutine raise
        async def bad_close():
            raise RuntimeError("connection reset")

        client.close = bad_close
        with caplog.at_level(logging.DEBUG, logger="boba.cli.main"):
            _safe_close_http(client)
        assert "connection reset" in caplog.text
