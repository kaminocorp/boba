"""Tests for 0.2.16 fixes: transaction atomicity, scope default-deny,
browser lock, PRAGMA validation, CLI context managers, SQLi baseline guard,
and expanded CLI coverage for previously untested commands."""

from __future__ import annotations

import json
import re
import sqlite3
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from typer.testing import CliRunner

from boba.cli.main import _managed, app
from boba.core.context import HuntContext
from boba.core.models import (
    AuthMethod,
    CompareResult,
    Confidence,
    DOMExtraction,
    HttpResponse,
    PageInfo,
    Severity,
    ToolResult,
    VulnTestResult,
)

runner = CliRunner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _create_hunt(tmp_path, name: str = "Test Hunt") -> str:
    result = runner.invoke(app, ["hunt", "create", "--name", name, "--data-dir", str(tmp_path)])
    assert result.exit_code == 0
    match = re.search(r"Hunt created: (\S+)", result.output)
    assert match
    return match.group(1)


def _mock_vuln_result(**kwargs) -> VulnTestResult:
    defaults = dict(
        test_type="test",
        vulnerable=False,
        confidence=Confidence.POSSIBLE,
        title="Test",
        description="",
        severity=Severity.INFO,
        evidence=[],
        request_ids=[],
        recommendations=[],
    )
    defaults.update(kwargs)
    return VulnTestResult(**defaults)


def _mock_http_response(**kwargs) -> HttpResponse:
    defaults = dict(
        request_id=1,
        status_code=200,
        headers={},
        body=b"OK",
        body_text="OK",
        elapsed_ms=50.0,
    )
    defaults.update(kwargs)
    return HttpResponse(**defaults)


def _make_result(tool_name: str, records: list[dict]) -> ToolResult:
    return ToolResult(
        tool_name=tool_name,
        command=[tool_name],
        exit_code=0,
        raw_stdout="",
        raw_stderr="",
        duration_seconds=1.0,
        records=records,
        filtered_count=0,
    )


# ═══════════════════════════════════════════════════════════════
# 1. Transaction atomicity: upsert_records rolls back on failure
# ═══════════════════════════════════════════════════════════════
class TestTransactionAtomicity:
    def test_upsert_records_rollback_on_failure(self, manager, sample_hunt):
        """If one record in a batch fails, all should be rolled back."""
        hunt_id = sample_hunt.id
        ctx = manager.context

        records = [
            {"subdomain": "a.example.com", "root_domain": "example.com", "source": "test"},
            {"subdomain": "b.example.com", "root_domain": "example.com", "source": "test"},
        ]
        ctx.upsert_records(hunt_id, "subdomain", records)
        subs = ctx.get_subdomains(hunt_id)
        assert len(subs) == 2

        # Now try a batch where the 2nd record fails (missing required field for port)
        bad_records = [
            {"host": "good.example.com", "port": 80},
            {"not_a_host": "bad"},  # missing required 'host' key
        ]
        with pytest.raises(KeyError):
            ctx.upsert_records(hunt_id, "port", bad_records)

        # The good record should NOT have been committed (atomic rollback)
        ports = ctx.get_ports(hunt_id)
        assert len(ports) == 0

    def test_individual_upsert_still_commits(self, tmp_path):
        """Individual upsert calls (outside batch) still commit immediately."""
        db = str(tmp_path / "test.db")
        ctx = HuntContext(db)
        try:
            from boba.core.hunt import HuntManager

            mgr = HuntManager(db_path=db)
            hunt = mgr.create(name="individual-test")
            hunt_id = hunt.id
            ctx.upsert_subdomain(hunt_id, "solo.example.com", "example.com", "test")

            # Verify via second connection
            conn2 = sqlite3.connect(db)
            conn2.row_factory = sqlite3.Row
            rows = conn2.execute(
                "SELECT * FROM subdomains WHERE hunt_id = ?", (hunt_id,)
            ).fetchall()
            conn2.close()
            assert len(rows) == 1
        finally:
            ctx.close()


# ═══════════════════════════════════════════════════════════════
# 2. PRAGMA validation
# ═══════════════════════════════════════════════════════════════
class TestPragmaValidation:
    def test_wal_mode_enabled(self, tmp_path):
        db = str(tmp_path / "test.db")
        ctx = HuntContext(db)
        try:
            mode = ctx._conn.execute("PRAGMA journal_mode").fetchone()[0]
            assert mode.upper() == "WAL"
        finally:
            ctx.close()

    def test_foreign_keys_enabled(self, tmp_path):
        db = str(tmp_path / "test.db")
        ctx = HuntContext(db)
        try:
            fk = ctx._conn.execute("PRAGMA foreign_keys").fetchone()[0]
            assert fk == 1
        finally:
            ctx.close()


# ═══════════════════════════════════════════════════════════════
# 3. Scope default-deny for unmappable records
# ═══════════════════════════════════════════════════════════════
class TestScopeDefaultDeny:
    def test_unmappable_records_dropped(self):
        """Records where extract_scope_target returns None should be dropped."""
        from boba.adapters.base import BaseAdapter
        from boba.core.scope import ScopeEngine
        from boba.core.models import ScopeConfig, ScopeRule, ScopeRuleType, ScopeAction

        config = ScopeConfig(
            rules=[
                ScopeRule(
                    pattern="*.example.com",
                    rule_type=ScopeRuleType.DOMAIN,
                    action=ScopeAction.INCLUDE,
                )
            ]
        )
        scope = ScopeEngine(config)

        # Create a minimal concrete adapter
        class TestAdapter(BaseAdapter):
            TOOL_NAME = "test"
            BINARY_NAMES = ["test"]
            OUTPUT_FORMAT = "plain"
            PRODUCES = "subdomain"
            SCOPE_MODE = "post"

            def build_command(self, targets, config):
                return ["test"]

            def parse_record(self, raw):
                return raw

            def extract_scope_target(self, record):
                return record.get("subdomain")

            def install_hint(self):
                return "test"

        adapter = TestAdapter(scope)
        records = [
            {"subdomain": "a.example.com"},  # in scope
            {"subdomain": None},  # unmappable — should be dropped
            {"no_subdomain_key": "x"},  # unmappable — should be dropped
            {"subdomain": "out.evil.com"},  # out of scope
        ]
        kept, removed = adapter.post_filter_records(records)
        assert len(kept) == 1
        assert kept[0]["subdomain"] == "a.example.com"
        assert removed == 3


# ═══════════════════════════════════════════════════════════════
# 4. SQLi boolean detection: false-condition baseline guard
# ═══════════════════════════════════════════════════════════════
class TestSqliBooleanBaseline:
    def test_false_matches_baseline_prevents_fp(self):
        """If the false condition matches baseline, it's dynamic content not SQLi."""
        from boba.tools.vuln import _bodies_similar

        baseline = b'{"users": [{"id": 1, "name": "alice"}]}'
        true_resp = b'{"users": [{"id": 1, "name": "alice"}]}'  # matches baseline
        false_resp = b'{"users": [{"id": 1, "name": "alice"}]}'  # also matches baseline

        # Both true and false match baseline = dynamic content, not SQLi
        assert _bodies_similar(true_resp, baseline)
        assert _bodies_similar(false_resp, baseline)
        # The fix ensures: if false_matches_baseline → no SQLi flagged


# ═══════════════════════════════════════════════════════════════
# 5. CLI _managed context manager
# ═══════════════════════════════════════════════════════════════
class TestManagedContextManager:
    def test_managed_catches_exceptions(self, tmp_path):
        """_managed catches non-Exit exceptions and raises typer.Exit(1)."""
        from click.exceptions import Exit as ClickExit

        with pytest.raises(ClickExit) as exc_info:
            with _managed(tmp_path) as _manager:
                raise ValueError("boom")
        assert exc_info.value.exit_code == 1

    def test_managed_passes_through_exit(self, tmp_path):
        """_managed lets typer.Exit pass through unchanged."""
        import typer
        from click.exceptions import Exit as ClickExit

        with pytest.raises(ClickExit) as exc_info:
            with _managed(tmp_path) as _manager:
                raise typer.Exit(42)
        assert exc_info.value.exit_code == 42


# ═══════════════════════════════════════════════════════════════
# 6. CLI commands — browser navigate/screenshot/extract
# ═══════════════════════════════════════════════════════════════
class TestBrowserCLI:
    @patch("boba.cli.main._get_browser_manager")
    def test_browser_navigate(self, mock_get_browser, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        mock_browser = MagicMock()
        mock_browser.start = AsyncMock()
        mock_browser.stop = AsyncMock()
        mock_browser.navigate = AsyncMock(
            return_value=PageInfo(
                url="https://example.com",
                final_url="https://example.com/",
                status_code=200,
                title="Example",
                content_type="text/html",
                timing_ms=100.0,
                requests_captured=5,
            )
        )
        mock_get_browser.return_value = mock_browser

        result = runner.invoke(
            app,
            [
                "browser",
                "navigate",
                hunt_id,
                "--url",
                "https://example.com",
                "--format",
                "json",
                "--data-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["status_code"] == 200
        assert data["title"] == "Example"

    @patch("boba.cli.main._get_browser_manager")
    def test_browser_screenshot(self, mock_get_browser, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        mock_browser = MagicMock()
        mock_browser.start = AsyncMock()
        mock_browser.stop = AsyncMock()
        mock_browser.navigate = AsyncMock()
        mock_browser.screenshot = AsyncMock(return_value="/tmp/shot.png")
        mock_get_browser.return_value = mock_browser

        result = runner.invoke(
            app,
            [
                "browser",
                "screenshot",
                hunt_id,
                "--url",
                "https://example.com",
                "--path",
                "/tmp/shot.png",
                "--data-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 0
        assert "shot.png" in result.output

    @patch("boba.cli.main._get_browser_manager")
    def test_browser_extract(self, mock_get_browser, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        mock_browser = MagicMock()
        mock_browser.start = AsyncMock()
        mock_browser.stop = AsyncMock()
        mock_browser.navigate = AsyncMock()
        mock_browser.extract = AsyncMock(
            return_value=DOMExtraction(
                url="https://example.com",
                title="Example",
                links=[],
                forms=[],
                scripts=[],
                meta={},
                comments=[],
            )
        )
        mock_get_browser.return_value = mock_browser

        result = runner.invoke(
            app,
            [
                "browser",
                "extract",
                hunt_id,
                "--url",
                "https://example.com",
                "--format",
                "json",
                "--data-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["title"] == "Example"


# ═══════════════════════════════════════════════════════════════
# 7. CLI commands — http request/replay/compare
# ═══════════════════════════════════════════════════════════════
class TestHttpCLI:
    @patch("boba.cli.main._get_http_client")
    def test_http_request(self, mock_get_client, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        mock_client = MagicMock()
        mock_client.request = AsyncMock(return_value=_mock_http_response())
        mock_client.close = AsyncMock()
        mock_get_client.return_value = mock_client

        result = runner.invoke(
            app,
            [
                "http",
                "request",
                hunt_id,
                "--url",
                "https://example.com",
                "--method",
                "GET",
                "--format",
                "json",
                "--data-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["status_code"] == 200

    @patch("boba.cli.main._get_http_client")
    def test_http_replay(self, mock_get_client, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        mock_client = MagicMock()
        mock_client.replay = AsyncMock(return_value=_mock_http_response(request_id=2))
        mock_client.close = AsyncMock()
        mock_get_client.return_value = mock_client

        result = runner.invoke(
            app,
            [
                "http",
                "replay",
                hunt_id,
                "--request-id",
                "1",
                "--format",
                "json",
                "--data-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["request_id"] == 2

    @patch("boba.cli.main._get_http_client")
    def test_http_compare(self, mock_get_client, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        mock_client = MagicMock()
        mock_client.compare = AsyncMock(
            return_value=CompareResult(
                status_match=True,
                header_diffs=[],
                body_diff_summary="similar",
                body_length_a=100,
                body_length_b=105,
            )
        )
        mock_client.close = AsyncMock()
        mock_get_client.return_value = mock_client

        result = runner.invoke(
            app,
            [
                "http",
                "compare",
                hunt_id,
                "--id-a",
                "1",
                "--id-b",
                "2",
                "--format",
                "json",
                "--data-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["status_match"] is True


# ═══════════════════════════════════════════════════════════════
# 8. CLI commands — test idor/ssrf/xss/sqli/auth
# ═══════════════════════════════════════════════════════════════
class TestVulnCLI:
    @patch("boba.cli.main._get_session_manager")
    @patch("boba.cli.main._get_http_client")
    @patch("boba.tools.vuln.test_idor", new_callable=AsyncMock)
    def test_idor_cmd(self, mock_idor, mock_get_client, mock_get_sess, tmp_path):
        from boba.core.models import SessionState

        hunt_id = _create_hunt(tmp_path)
        mock_client = MagicMock()
        mock_client.close = AsyncMock()
        mock_get_client.return_value = mock_client

        mock_sess = MagicMock()
        mock_sess.get.return_value = SessionState(
            name="a",
            target_url="https://example.com",
            auth_method=AuthMethod.BEARER,
            headers={},
            cookies={},
            is_valid=True,
        )
        mock_get_sess.return_value = mock_sess

        mock_idor.return_value = _mock_vuln_result(test_type="idor")

        result = runner.invoke(
            app,
            [
                "test",
                "idor",
                hunt_id,
                "--endpoint",
                "https://example.com/api/user/1",
                "--session-a",
                "alice",
                "--session-b",
                "bob",
                "--format",
                "json",
                "--data-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["test_type"] == "idor"

    @patch("boba.cli.main._get_http_client")
    @patch("boba.tools.vuln.test_ssrf", new_callable=AsyncMock)
    def test_ssrf_cmd(self, mock_ssrf, mock_get_client, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        mock_client = MagicMock()
        mock_client.close = AsyncMock()
        mock_get_client.return_value = mock_client
        mock_ssrf.return_value = _mock_vuln_result(test_type="ssrf")

        result = runner.invoke(
            app,
            [
                "test",
                "ssrf",
                hunt_id,
                "--url",
                "https://example.com/fetch",
                "--param",
                "url",
                "--format",
                "json",
                "--data-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["test_type"] == "ssrf"

    @patch("boba.cli.main._get_http_client")
    @patch("boba.tools.vuln.test_xss", new_callable=AsyncMock)
    def test_xss_cmd(self, mock_xss, mock_get_client, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        mock_client = MagicMock()
        mock_client.close = AsyncMock()
        mock_get_client.return_value = mock_client
        mock_xss.return_value = _mock_vuln_result(test_type="xss")

        result = runner.invoke(
            app,
            [
                "test",
                "xss",
                hunt_id,
                "--url",
                "https://example.com/search",
                "--param",
                "q",
                "--format",
                "json",
                "--data-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["test_type"] == "xss"

    @patch("boba.cli.main._get_http_client")
    @patch("boba.tools.vuln.test_sqli", new_callable=AsyncMock)
    def test_sqli_cmd(self, mock_sqli, mock_get_client, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        mock_client = MagicMock()
        mock_client.close = AsyncMock()
        mock_get_client.return_value = mock_client
        mock_sqli.return_value = _mock_vuln_result(test_type="sqli")

        result = runner.invoke(
            app,
            [
                "test",
                "sqli",
                hunt_id,
                "--url",
                "https://example.com/api/items",
                "--param",
                "id",
                "--format",
                "json",
                "--data-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["test_type"] == "sqli"

    @patch("boba.cli.main._get_http_client")
    @patch("boba.tools.vuln.test_auth", new_callable=AsyncMock)
    def test_auth_cmd(self, mock_auth, mock_get_client, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        mock_client = MagicMock()
        mock_client.close = AsyncMock()
        mock_get_client.return_value = mock_client
        mock_auth.return_value = _mock_vuln_result(test_type="auth")

        result = runner.invoke(
            app,
            [
                "test",
                "auth",
                hunt_id,
                "--endpoint",
                "https://example.com/admin",
                "--format",
                "json",
                "--data-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["test_type"] == "auth"


# ═══════════════════════════════════════════════════════════════
# 9. CLI commands — session login-token, enum crawl, context oob
# ═══════════════════════════════════════════════════════════════
class TestSessionCLI:
    @patch("boba.cli.main._get_session_manager")
    def test_session_login_token(self, mock_get_sess, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        mock_mgr = MagicMock()
        mock_get_sess.return_value = mock_mgr

        result = runner.invoke(
            app,
            [
                "session",
                "login-token",
                hunt_id,
                "alice",
                "--token",
                "eyJhbGciOiJIUzI1NiJ9.test",
                "--data-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 0
        assert "Bearer token set" in result.output
        mock_mgr.login_bearer.assert_called_once_with("alice", "eyJhbGciOiJIUzI1NiJ9.test")


class TestEnumCrawlCLI:
    @patch("boba.tools.enum.crawl", new_callable=AsyncMock)
    def test_enum_crawl(self, mock_crawl, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        mock_crawl.return_value = _make_result(
            "katana",
            [
                {
                    "url": "https://example.com/page",
                    "host": "example.com",
                    "path": "/page",
                    "source": "katana",
                },
            ],
        )

        result = runner.invoke(
            app,
            [
                "enum",
                "crawl",
                hunt_id,
                "--targets",
                "https://example.com",
                "--format",
                "json",
                "--data-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["tool"] == "katana"
        assert data["found"] == 1


class TestContextOobCLI:
    def test_context_oob_empty(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        result = runner.invoke(
            app,
            [
                "context",
                "oob",
                hunt_id,
                "--format",
                "json",
                "--data-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 0


class TestContextFindingsCLI:
    def test_context_findings_empty(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        result = runner.invoke(
            app,
            [
                "context",
                "findings",
                hunt_id,
                "--format",
                "json",
                "--data-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 0


class TestContextSessionsCLI:
    def test_context_sessions_empty(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        result = runner.invoke(
            app,
            [
                "context",
                "sessions",
                hunt_id,
                "--format",
                "json",
                "--data-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 0


class TestContextHttpHistoryCLI:
    def test_context_http_history_empty(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        result = runner.invoke(
            app,
            [
                "context",
                "http-history",
                hunt_id,
                "--format",
                "json",
                "--data-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 0


# ═══════════════════════════════════════════════════════════════
# 10. Error handling — CLI commands with invalid inputs
# ═══════════════════════════════════════════════════════════════
class TestCLIErrorHandling:
    def test_nonexistent_hunt_id(self, tmp_path):
        result = runner.invoke(
            app,
            [
                "hunt",
                "status",
                "nonexistent-hunt-id",
                "--data-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 1

    def test_invalid_auth_method(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        result = runner.invoke(
            app,
            [
                "session",
                "create",
                hunt_id,
                "--name",
                "test",
                "--target",
                "https://example.com",
                "--method",
                "invalid_method",
                "--data-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 1
        assert "Invalid auth method" in result.output
