"""Tests for V3 coverage tracking — schema, context methods, analysis, auto-recording, CLI."""

from __future__ import annotations

import json

import pytest

from boba.analysis.coverage import get_coverage_gaps, get_coverage_summary
from boba.core.models import (
    AuthMethod,
    Hunt,
    HttpResponse,
    ScopeConfig,
    SessionState,
)
from boba.interaction.history import HttpHistorySink
from boba.interaction.http import HttpClient
from boba.tools import vuln


@pytest.fixture
def hunt_id(context):
    hunt = Hunt(id="cov_test_001", name="Coverage Test", scope=ScopeConfig())
    context.create_hunt(hunt)
    return hunt.id


@pytest.fixture
def sink(context, hunt_id, tmp_path):
    s = HttpHistorySink(context, hunt_id)
    s._body_dir = tmp_path / "bodies"
    s._body_dir.mkdir()
    return s


@pytest.fixture
def session_a():
    return SessionState(
        name="user_a",
        target_url="https://app.example.com",
        auth_method=AuthMethod.COOKIE,
        cookies={"session": "tok_a"},
        headers={"Cookie": "session=tok_a"},
    )


@pytest.fixture
def session_b():
    return SessionState(
        name="user_b",
        target_url="https://app.example.com",
        auth_method=AuthMethod.COOKIE,
        cookies={"session": "tok_b"},
        headers={"Cookie": "session=tok_b"},
    )


def _make_response(status_code, body_text, request_id=1):
    return HttpResponse(
        request_id=request_id,
        status_code=status_code,
        headers={"content-type": "text/html"},
        body=body_text.encode(),
        body_text=body_text,
        elapsed_ms=50.0,
    )


# ═══════════════════ Context CRUD ═══════════════════


class TestCoverageUpsertAndQuery:
    def test_basic_insert_and_query(self, context, hunt_id):
        """Insert a coverage row and query it back."""
        row_id = context.upsert_coverage(
            hunt_id,
            {
                "url": "https://app.example.com/api/users/1",
                "method": "GET",
                "parameter": "id",
                "test_type": "idor",
            },
        )
        assert row_id > 0

        rows = context.get_coverage(hunt_id)
        assert len(rows) == 1
        assert rows[0]["url"] == "https://app.example.com/api/users/1"
        assert rows[0]["test_type"] == "idor"
        assert rows[0]["parameter"] == "id"

    def test_unique_constraint_updates(self, context, hunt_id):
        """Same endpoint + test type updates, doesn't duplicate."""
        context.upsert_coverage(
            hunt_id,
            {
                "url": "https://app.example.com/search",
                "method": "GET",
                "parameter": "q",
                "test_type": "xss",
                "notes": "first run",
            },
        )
        context.upsert_coverage(
            hunt_id,
            {
                "url": "https://app.example.com/search",
                "method": "GET",
                "parameter": "q",
                "test_type": "xss",
                "notes": "second run",
            },
        )

        rows = context.get_coverage(hunt_id)
        assert len(rows) == 1
        assert rows[0]["notes"] == "second run"

    def test_different_test_types_not_deduped(self, context, hunt_id):
        """Same URL but different test types are separate rows."""
        for tt in ["idor", "xss", "sqli"]:
            context.upsert_coverage(
                hunt_id,
                {
                    "url": "https://app.example.com/api/users/1",
                    "method": "GET",
                    "test_type": tt,
                },
            )

        rows = context.get_coverage(hunt_id)
        assert len(rows) == 3

    def test_filter_by_test_type(self, context, hunt_id):
        """Filtering by test_type returns only matching rows."""
        context.upsert_coverage(
            hunt_id,
            {
                "url": "https://app.example.com/a",
                "test_type": "xss",
            },
        )
        context.upsert_coverage(
            hunt_id,
            {
                "url": "https://app.example.com/b",
                "test_type": "sqli",
            },
        )

        rows = context.get_coverage(hunt_id, test_type="xss")
        assert len(rows) == 1
        assert rows[0]["test_type"] == "xss"

    def test_filter_by_host(self, context, hunt_id):
        """Filtering by host matches URL substring."""
        context.upsert_coverage(
            hunt_id,
            {
                "url": "https://app.example.com/a",
                "test_type": "xss",
            },
        )
        context.upsert_coverage(
            hunt_id,
            {
                "url": "https://other.example.com/b",
                "test_type": "xss",
            },
        )

        rows = context.get_coverage(hunt_id, host="app.example.com")
        assert len(rows) == 1
        assert "app.example.com" in rows[0]["url"]


# ═══════════════════ Untested endpoints ═══════════════════


class TestUntestedEndpoints:
    def test_untested_from_urls_table(self, context, hunt_id):
        """Endpoints in urls table appear as untested when no coverage exists."""
        context.upsert_url(
            hunt_id,
            {
                "url": "https://app.example.com/api/users",
                "host": "app.example.com",
                "path": "/api/users",
                "method": "GET",
            },
        )

        gaps = context.get_untested_endpoints(hunt_id, test_types=["idor", "xss"])
        assert len(gaps) == 2
        test_types = {g["test_type"] for g in gaps}
        assert test_types == {"idor", "xss"}

    def test_untested_from_directories_table(self, context, hunt_id):
        """Endpoints in directories table appear as untested."""
        context.upsert_directory(
            hunt_id,
            {
                "url": "https://app.example.com/admin",
                "status_code": 200,
            },
        )

        gaps = context.get_untested_endpoints(hunt_id, test_types=["auth"])
        assert len(gaps) == 1
        assert gaps[0]["url"] == "https://app.example.com/admin"
        assert gaps[0]["test_type"] == "auth"

    def test_tested_endpoint_excluded_from_gaps(self, context, hunt_id):
        """An endpoint with a coverage row for a test type is NOT a gap."""
        context.upsert_url(
            hunt_id,
            {
                "url": "https://app.example.com/search",
                "host": "app.example.com",
                "path": "/search",
                "method": "GET",
            },
        )
        context.upsert_coverage(
            hunt_id,
            {
                "url": "https://app.example.com/search",
                "method": "GET",
                "test_type": "xss",
            },
        )

        gaps = context.get_untested_endpoints(hunt_id, test_types=["xss"])
        assert len(gaps) == 0

    def test_partial_coverage_shows_remaining_gaps(self, context, hunt_id):
        """Endpoint tested for XSS but not SQLI still shows SQLI gap."""
        context.upsert_url(
            hunt_id,
            {
                "url": "https://app.example.com/search",
                "host": "app.example.com",
                "path": "/search",
                "method": "GET",
            },
        )
        context.upsert_coverage(
            hunt_id,
            {
                "url": "https://app.example.com/search",
                "method": "GET",
                "test_type": "xss",
            },
        )

        gaps = context.get_untested_endpoints(hunt_id, test_types=["xss", "sqli"])
        assert len(gaps) == 1
        assert gaps[0]["test_type"] == "sqli"


# ═══════════════════ Auto-recording from vuln tools ═══════════════════


class TestAutoRecordCoverage:
    @pytest.mark.asyncio
    async def test_idor_records_coverage(self, context, hunt_id, sink, session_a, session_b):
        """Running test_idor with context auto-records a coverage row."""
        client = HttpClient(sink)
        call_count = 0

        async def mock_request(**kwargs):
            nonlocal call_count
            call_count += 1
            if "user_a" in (kwargs.get("session_name") or ""):
                return _make_response(200, '{"id":1,"name":"alice"}', call_count)
            if "user_b" in (kwargs.get("session_name") or ""):
                return _make_response(200, '{"id":1,"name":"alice"}', call_count)
            return _make_response(401, "Unauthorized", call_count)

        client.request = mock_request

        await vuln.test_idor(
            client,
            session_a,
            session_b,
            endpoint="https://app.example.com/api/users/1",
            context=context,
            hunt_id=hunt_id,
        )

        rows = context.get_coverage(hunt_id)
        assert len(rows) == 1
        assert rows[0]["test_type"] == "idor"
        assert rows[0]["url"] == "https://app.example.com/api/users/1"

    @pytest.mark.asyncio
    async def test_xss_records_coverage(self, context, hunt_id, sink):
        """Running test_xss with context auto-records a coverage row per param."""
        client = HttpClient(sink)

        async def mock_request(**kwargs):
            return _make_response(200, "<html>safe</html>", 1)

        client.request = mock_request

        await vuln.test_xss(
            client,
            "https://app.example.com/search",
            params={"q": "", "lang": ""},
            payloads=["<script>alert(1)</script>"],
            context=context,
            hunt_id=hunt_id,
        )

        rows = context.get_coverage(hunt_id)
        assert len(rows) == 2
        params = {r["parameter"] for r in rows}
        assert params == {"q", "lang"}

    @pytest.mark.asyncio
    async def test_sqli_records_coverage(self, context, hunt_id, sink):
        """Running test_sqli with context auto-records a coverage row."""
        client = HttpClient(sink)

        async def mock_request(**kwargs):
            return _make_response(200, "<html>ok</html>", 1)

        client.request = mock_request

        await vuln.test_sqli(
            client,
            "https://app.example.com/search",
            params={"id": "1"},
            payloads=["'"],
            context=context,
            hunt_id=hunt_id,
        )

        rows = context.get_coverage(hunt_id)
        assert len(rows) == 1
        assert rows[0]["test_type"] == "sqli"

    @pytest.mark.asyncio
    async def test_no_coverage_without_context(self, context, hunt_id, sink, session_a, session_b):
        """When context is not passed, no coverage is recorded (backwards compatible)."""
        client = HttpClient(sink)

        async def mock_request(**kwargs):
            return _make_response(401, "Denied", 1)

        client.request = mock_request

        await vuln.test_idor(
            client,
            session_a,
            session_b,
            endpoint="https://app.example.com/api/users/1",
        )

        # No coverage row — context was not passed
        rows = context.get_coverage(hunt_id)
        assert len(rows) == 0


# ═══════════════════ Analysis module ═══════════════════


class TestCoverageSummary:
    def test_summary_counts(self, context, hunt_id):
        """Summary correctly counts total, tested, and untested endpoints."""
        # Add 3 known endpoints
        for path in ["/api/users", "/api/posts", "/api/settings"]:
            context.upsert_url(
                hunt_id,
                {
                    "url": f"https://app.example.com{path}",
                    "host": "app.example.com",
                    "path": path,
                    "method": "GET",
                },
            )

        # Test 2 of them
        context.upsert_coverage(
            hunt_id,
            {
                "url": "https://app.example.com/api/users",
                "method": "GET",
                "test_type": "idor",
            },
        )
        context.upsert_coverage(
            hunt_id,
            {
                "url": "https://app.example.com/api/posts",
                "method": "GET",
                "test_type": "xss",
            },
        )

        summary = get_coverage_summary(context, hunt_id)
        assert summary.total_endpoints == 3
        assert summary.tested_endpoints == 2
        assert summary.untested_endpoints == 1
        assert summary.coverage_by_test_type == {"idor": 1, "xss": 1}
        assert len(summary.gaps) > 0  # untested endpoint × test types

    def test_summary_empty_hunt(self, context, hunt_id):
        """Summary for a hunt with no endpoints returns zeros."""
        summary = get_coverage_summary(context, hunt_id)
        assert summary.total_endpoints == 0
        assert summary.tested_endpoints == 0
        assert summary.untested_endpoints == 0

    def test_gaps_filtered_by_host(self, context, hunt_id):
        """get_coverage_gaps filters by host."""
        context.upsert_url(
            hunt_id,
            {
                "url": "https://app.example.com/a",
                "host": "app.example.com",
                "method": "GET",
            },
        )
        context.upsert_url(
            hunt_id,
            {
                "url": "https://other.example.com/b",
                "host": "other.example.com",
                "method": "GET",
            },
        )

        gaps = get_coverage_gaps(context, hunt_id, test_types=["xss"], host="app.example.com")
        assert len(gaps) == 1
        assert "app.example.com" in gaps[0]["url"]


# ═══════════════════ Coverage in hunt stats ═══════════════════


class TestCoverageInStats:
    def test_stats_includes_coverage_count(self, context, hunt_id):
        """get_hunt_stats includes coverage count."""
        context.upsert_coverage(
            hunt_id,
            {
                "url": "https://app.example.com/a",
                "test_type": "xss",
            },
        )
        stats = context.get_hunt_stats(hunt_id)
        assert stats["coverage"] == 1


# ═══════════════════ CLI ═══════════════════


class TestCLICoverage:
    def test_cli_analyze_coverage_json(self, tmp_path):
        """CLI analyze coverage --format json produces valid JSON."""
        from typer.testing import CliRunner
        from boba.cli.main import app
        from boba.core.hunt import HuntManager

        runner = CliRunner()
        # CLI uses data_dir / "boba.db" — must match
        db_path = str(tmp_path / "boba.db")
        mgr = HuntManager(db_path=db_path)
        hunt = mgr.create(name="CLI Test")

        # Add an endpoint
        mgr.context.upsert_url(
            hunt.id,
            {
                "url": "https://app.example.com/api",
                "host": "app.example.com",
                "method": "GET",
            },
        )
        mgr.close_context()

        result = runner.invoke(
            app,
            [
                "analyze",
                "coverage",
                hunt.id,
                "--format",
                "json",
                "--data-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert "total_endpoints" in data
        assert data["total_endpoints"] == 1

    def test_cli_analyze_coverage_untested_only(self, tmp_path):
        """CLI analyze coverage --untested-only shows gaps."""
        from typer.testing import CliRunner
        from boba.cli.main import app
        from boba.core.hunt import HuntManager

        runner = CliRunner()
        db_path = str(tmp_path / "boba.db")
        mgr = HuntManager(db_path=db_path)
        hunt = mgr.create(name="CLI Test")
        mgr.context.upsert_url(
            hunt.id,
            {
                "url": "https://app.example.com/api",
                "host": "app.example.com",
                "method": "GET",
            },
        )
        mgr.close_context()

        result = runner.invoke(
            app,
            [
                "analyze",
                "coverage",
                hunt.id,
                "--untested-only",
                "--test-type",
                "xss",
                "--format",
                "json",
                "--data-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert len(data) == 1
        assert data[0]["test_type"] == "xss"
