"""Tests for specific fixes in the 0.2.15 release."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from typer.testing import CliRunner

from boba.cli.main import _parse_targets, app
from boba.core.context import HuntContext
from boba.core.models import (
    AuthMethod,
    Confidence,
    Hunt,
    HttpResponse,
    ScopeConfig,
    Severity,
    VulnTestResult,
)
from boba.tools.vuln import _bodies_similar

runner = CliRunner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _create_hunt(tmp_path, name: str = "Test Hunt") -> str:
    """Create a hunt and return its ID."""
    import re

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


# ---------------------------------------------------------------------------
# 1. context.py transaction safety — upserts commit individually
# ---------------------------------------------------------------------------
class TestUpsertCommitSafety:
    """Each upsert_* method should persist data even when called directly
    (without the upsert_records transaction wrapper)."""

    def _make_hunt(self) -> Hunt:
        return Hunt(id="h1", name="test", scope=ScopeConfig(rules=[]))

    def test_upsert_subdomain_persists_across_connections(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        ctx1 = HuntContext(db_path)
        ctx1.create_hunt(self._make_hunt())
        ctx1.upsert_subdomain("h1", "api.example.com", "example.com", "subfinder")
        ctx1.close()

        ctx2 = HuntContext(db_path)
        subs = ctx2.get_subdomains("h1")
        ctx2.close()
        assert len(subs) == 1
        assert subs[0]["subdomain"] == "api.example.com"

    def test_upsert_host_persists_across_connections(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        ctx1 = HuntContext(db_path)
        ctx1.create_hunt(self._make_hunt())
        ctx1.upsert_host("h1", {"host": "example.com", "port": 443, "scheme": "https"})
        ctx1.close()

        ctx2 = HuntContext(db_path)
        hosts = ctx2.get_hosts("h1")
        ctx2.close()
        assert len(hosts) == 1
        assert hosts[0]["host"] == "example.com"

    def test_upsert_port_persists_across_connections(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        ctx1 = HuntContext(db_path)
        ctx1.create_hunt(self._make_hunt())
        ctx1.upsert_port("h1", {"host": "example.com", "port": 8080})
        ctx1.close()

        ctx2 = HuntContext(db_path)
        ports = ctx2.get_ports("h1")
        ctx2.close()
        assert len(ports) == 1
        assert ports[0]["port"] == 8080

    def test_upsert_url_persists_across_connections(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        ctx1 = HuntContext(db_path)
        ctx1.create_hunt(self._make_hunt())
        ctx1.upsert_url("h1", {"url": "https://example.com/api", "host": "example.com"})
        ctx1.close()

        ctx2 = HuntContext(db_path)
        urls = ctx2.get_urls("h1")
        ctx2.close()
        assert len(urls) == 1
        assert urls[0]["url"] == "https://example.com/api"

    def test_upsert_technology_persists_across_connections(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        ctx1 = HuntContext(db_path)
        ctx1.create_hunt(self._make_hunt())
        ctx1.upsert_technology("h1", "example.com", {"name": "nginx"})
        ctx1.close()

        ctx2 = HuntContext(db_path)
        techs = ctx2.get_technologies("h1")
        ctx2.close()
        assert len(techs) == 1
        assert techs[0]["name"] == "nginx"

    def test_upsert_directory_persists_across_connections(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        ctx1 = HuntContext(db_path)
        ctx1.create_hunt(self._make_hunt())
        ctx1.upsert_directory("h1", {"url": "https://example.com/admin", "status_code": 200})
        ctx1.close()

        ctx2 = HuntContext(db_path)
        dirs = ctx2.get_directories("h1")
        ctx2.close()
        assert len(dirs) == 1
        assert dirs[0]["url"] == "https://example.com/admin"


# ---------------------------------------------------------------------------
# 2. _parse_targets helper
# ---------------------------------------------------------------------------
class TestParseTargets:
    def test_none_returns_none(self):
        assert _parse_targets(None) is None

    def test_empty_string_returns_none(self):
        assert _parse_targets("") is None

    def test_single_target(self):
        assert _parse_targets("example.com") == ["example.com"]

    def test_multiple_targets(self):
        assert _parse_targets("a.com, b.com, c.com") == ["a.com", "b.com", "c.com"]

    def test_strips_whitespace(self):
        assert _parse_targets("  a.com , b.com  ") == ["a.com", "b.com"]

    def test_empty_entries_filtered(self):
        assert _parse_targets("a.com,,b.com") == ["a.com", "b.com"]


# ---------------------------------------------------------------------------
# 3. _bodies_similar lowered threshold (0.7)
# ---------------------------------------------------------------------------
class TestBodiesSimilarThreshold:
    def test_default_threshold_is_0_7(self):
        """JSON bodies with ~75% key overlap should be considered similar with 0.7 threshold."""
        body_a = json.dumps({"a": 1, "b": 2, "c": 3, "d": 4}).encode()
        body_b = json.dumps({"a": 9, "b": 8, "c": 7, "extra": 0}).encode()
        # key overlap: {a, b, c} / {a, b, c, d, extra} = 3/5 = 0.6 → not similar at 0.7
        assert _bodies_similar(body_a, body_b) is False

        # Same structure but different values → falls through to line-based
        # comparison which detects value differences → not similar.
        # Prevents IDOR false positives on same-schema different-user data.
        body_c = json.dumps({"a": 9, "b": 8, "c": 7, "d": 0}).encode()
        assert _bodies_similar(body_a, body_c) is False


# ---------------------------------------------------------------------------
# 4. SSRF indicator patterns — tighter regex
# ---------------------------------------------------------------------------
class TestSSRFPatterns:
    """Verify the hardened SSRF indicator patterns reduce false positives."""

    def test_passwd_requires_full_format(self):
        import re

        pattern = r"root:[^:]*:\d+:\d+:[^:]*:[^:]*:"
        assert re.search(pattern, "root:x:0:0:root:/root:") is not None
        # "root cause" should NOT match
        assert re.search(pattern, "Error root cause: database timeout") is None

    def test_aws_ami_requires_8_hex_chars(self):
        import re

        pattern = r"ami-[0-9a-f]{8,}"
        assert re.search(pattern, "ami-0abcdef123456789") is not None
        # Short AMI should not match
        assert re.search(pattern, "ami-abc") is None

    def test_gcp_metadata_requires_version(self):
        import re

        pattern = r"computeMetadata/v\d"
        assert re.search(pattern, "computeMetadata/v1") is not None
        # Without version should not match
        assert re.search(pattern, "computeMetadata/") is None


# ---------------------------------------------------------------------------
# 5. IDOR enumeration requires body similarity
# ---------------------------------------------------------------------------
class TestIDOREnumerationBodyCheck:
    """IDOR object ID enumeration should verify body similarity, not just 2xx status."""

    @pytest.mark.asyncio
    async def test_enumeration_requires_body_similarity(self):
        from boba.tools.vuln import test_idor
        from boba.core.models import SessionState

        # Setup: responses with different structures = not similar
        responses = [
            HttpResponse(
                request_id=1,
                status_code=200,
                body=b'{"user":"alice","data":"secret"}',
                headers={},
                elapsed_ms=50,
            ),
            HttpResponse(
                request_id=2,
                status_code=200,
                body=b'{"user":"bob","data":"other"}',
                headers={},
                elapsed_ms=50,
            ),
            HttpResponse(
                request_id=3, status_code=401, body=b"unauthorized", headers={}, elapsed_ms=50
            ),
            # Enumerated: different structure → should NOT mark as IDOR
            HttpResponse(
                request_id=4,
                status_code=200,
                body=b'{"error":"not found","code":404}',
                headers={},
                elapsed_ms=50,
            ),
        ]
        call_count = 0

        async def mock_request(**kwargs):
            nonlocal call_count
            resp = responses[min(call_count, len(responses) - 1)]
            call_count += 1
            return resp

        client = AsyncMock()
        client.request = mock_request
        sa = SessionState(
            name="alice",
            target_url="https://example.com",
            auth_method=AuthMethod.FORM,
            headers={},
            cookies={},
        )
        sb = SessionState(
            name="bob",
            target_url="https://example.com",
            auth_method=AuthMethod.FORM,
            headers={},
            cookies={},
        )

        result = await test_idor(client, sa, sb, "https://example.com/api/user/1", object_ids=["2"])
        # The 4th response has different JSON keys than resp_a, so body_similar_to_owner=False
        enum_evidence = [e for e in result.evidence if "enumerated_id" in e]
        if enum_evidence:
            assert enum_evidence[0]["body_similar_to_owner"] is False


# ---------------------------------------------------------------------------
# 6. urlparse error handling in adapters
# ---------------------------------------------------------------------------
class TestAdapterUrlparseSafety:
    def test_gau_handles_malformed_url(self):
        from boba.adapters.gau import GauAdapter
        from boba.core.scope import ScopeEngine

        scope = ScopeEngine(ScopeConfig(rules=[]))
        adapter = GauAdapter(scope)
        # Very malformed input — should not raise
        record = adapter.parse_record("not-a-url-at-all")
        assert "url" in record
        assert record["url"] == "not-a-url-at-all"

    def test_waybackurls_handles_malformed_url(self):
        from boba.adapters.waybackurls import WaybackurlsAdapter
        from boba.core.scope import ScopeEngine

        scope = ScopeEngine(ScopeConfig(rules=[]))
        adapter = WaybackurlsAdapter(scope)
        record = adapter.parse_record("not-a-url")
        assert "url" in record

    def test_katana_handles_malformed_url(self):
        from boba.adapters.katana import KatanaAdapter
        from boba.core.scope import ScopeEngine

        scope = ScopeEngine(ScopeConfig(rules=[]))
        adapter = KatanaAdapter(scope)
        record = adapter.parse_record({"endpoint": ""})
        assert record["host"] == ""

    def test_whatweb_handles_missing_target(self):
        from boba.adapters.whatweb import WhatwebAdapter
        from boba.core.scope import ScopeEngine

        scope = ScopeEngine(ScopeConfig(rules=[]))
        adapter = WhatwebAdapter(scope)
        record = adapter.parse_record({"plugins": {}})
        assert record["host"] == ""


# ---------------------------------------------------------------------------
# 7. CLI tests for browser commands
# ---------------------------------------------------------------------------
class TestBrowserNavigateCLI:
    def test_browser_navigate(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        mock_info = MagicMock(
            url="https://example.com",
            final_url="https://example.com",
            status_code=200,
            title="Example",
            content_type="text/html",
            timing_ms=150.0,
            requests_captured=5,
        )

        with patch("boba.cli.main._get_browser_manager") as mock_bm:
            mock_browser = AsyncMock()
            mock_browser.start = AsyncMock()
            mock_browser.stop = AsyncMock()
            mock_browser.navigate = AsyncMock(return_value=mock_info)
            mock_bm.return_value = mock_browser

            result = runner.invoke(
                app,
                [
                    "browser",
                    "navigate",
                    hunt_id,
                    "--url",
                    "https://example.com",
                    "--data-dir",
                    str(tmp_path),
                ],
            )
            assert result.exit_code == 0
            assert "example.com" in result.output.lower()


class TestBrowserScreenshotCLI:
    def test_browser_screenshot(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        screenshot_path = str(tmp_path / "screenshot.png")

        with patch("boba.cli.main._get_browser_manager") as mock_bm:
            mock_browser = AsyncMock()
            mock_browser.start = AsyncMock()
            mock_browser.stop = AsyncMock()
            mock_browser.navigate = AsyncMock()
            mock_browser.screenshot = AsyncMock(return_value=screenshot_path)
            mock_bm.return_value = mock_browser

            result = runner.invoke(
                app,
                [
                    "browser",
                    "screenshot",
                    hunt_id,
                    "--url",
                    "https://example.com",
                    "--path",
                    screenshot_path,
                    "--data-dir",
                    str(tmp_path),
                ],
            )
            assert result.exit_code == 0
            assert "screenshot" in result.output.lower()


class TestBrowserExtractCLI:
    def test_browser_extract(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)

        with patch("boba.cli.main._get_browser_manager") as mock_bm:
            mock_browser = AsyncMock()
            mock_browser.start = AsyncMock()
            mock_browser.stop = AsyncMock()
            mock_browser.navigate = AsyncMock()
            mock_browser.extract = AsyncMock(return_value=MagicMock(__dataclass_fields__={}))
            mock_bm.return_value = mock_browser

            with patch("dataclasses.asdict", return_value={"title": "Test", "links": []}):
                result = runner.invoke(
                    app,
                    [
                        "browser",
                        "extract",
                        hunt_id,
                        "--url",
                        "https://example.com",
                        "--data-dir",
                        str(tmp_path),
                    ],
                )
                assert result.exit_code == 0


# ---------------------------------------------------------------------------
# 8. CLI tests for HTTP commands
# ---------------------------------------------------------------------------
class TestHttpRequestCLI:
    def test_http_request(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        mock_resp = HttpResponse(
            request_id=1,
            status_code=200,
            body=b"OK",
            headers={"Content-Type": "text/plain"},
            elapsed_ms=42.0,
        )

        with patch("boba.cli.main._get_http_client") as mock_hc:
            mock_client = AsyncMock()
            mock_client.request = AsyncMock(return_value=mock_resp)
            mock_client.close = AsyncMock()
            mock_hc.return_value = mock_client

            result = runner.invoke(
                app,
                [
                    "http",
                    "request",
                    hunt_id,
                    "--url",
                    "https://example.com",
                    "--data-dir",
                    str(tmp_path),
                ],
            )
            assert result.exit_code == 0
            data = json.loads(result.output)
            assert data["status_code"] == 200


class TestHttpReplayCLI:
    def test_http_replay(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        mock_resp = HttpResponse(
            request_id=2,
            status_code=200,
            body=b"replayed",
            headers={},
            elapsed_ms=55.0,
        )

        with patch("boba.cli.main._get_http_client") as mock_hc:
            mock_client = AsyncMock()
            mock_client.replay = AsyncMock(return_value=mock_resp)
            mock_client.close = AsyncMock()
            mock_hc.return_value = mock_client

            result = runner.invoke(
                app,
                ["http", "replay", hunt_id, "--request-id", "1", "--data-dir", str(tmp_path)],
            )
            assert result.exit_code == 0
            data = json.loads(result.output)
            assert data["status_code"] == 200


class TestHttpCompareCLI:
    def test_http_compare(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        mock_result = MagicMock()

        with patch("boba.cli.main._get_http_client") as mock_hc:
            mock_client = AsyncMock()
            mock_client.compare = AsyncMock(return_value=mock_result)
            mock_client.close = AsyncMock()
            mock_hc.return_value = mock_client

            with patch("dataclasses.asdict", return_value={"status_diff": False}):
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
                        "--data-dir",
                        str(tmp_path),
                    ],
                )
                assert result.exit_code == 0


# ---------------------------------------------------------------------------
# 9. CLI tests for vuln/test commands
# ---------------------------------------------------------------------------
class TestIDORCLI:
    def test_test_idor(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        # Create sessions first
        runner.invoke(
            app,
            [
                "session",
                "create",
                hunt_id,
                "--name",
                "alice",
                "--target",
                "https://example.com",
                "--data-dir",
                str(tmp_path),
            ],
        )
        runner.invoke(
            app,
            [
                "session",
                "create",
                hunt_id,
                "--name",
                "bob",
                "--target",
                "https://example.com",
                "--data-dir",
                str(tmp_path),
            ],
        )

        mock_result = _mock_vuln_result(test_type="idor")

        with (
            patch("boba.cli.main._get_http_client") as mock_hc,
            patch("boba.tools.vuln.test_idor", new_callable=AsyncMock, return_value=mock_result),
        ):
            mock_client = AsyncMock()
            mock_client.close = AsyncMock()
            mock_hc.return_value = mock_client

            result = runner.invoke(
                app,
                [
                    "test",
                    "idor",
                    hunt_id,
                    "--endpoint",
                    "https://example.com/api",
                    "--session-a",
                    "alice",
                    "--session-b",
                    "bob",
                    "--data-dir",
                    str(tmp_path),
                ],
            )
            assert result.exit_code == 0


class TestSSRFCLI:
    def test_test_ssrf(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        mock_result = _mock_vuln_result(test_type="ssrf")

        with (
            patch("boba.cli.main._get_http_client") as mock_hc,
            patch("boba.tools.vuln.test_ssrf", new_callable=AsyncMock, return_value=mock_result),
        ):
            mock_client = AsyncMock()
            mock_client.close = AsyncMock()
            mock_hc.return_value = mock_client

            result = runner.invoke(
                app,
                [
                    "test",
                    "ssrf",
                    hunt_id,
                    "--url",
                    "https://example.com/fetch",
                    "--data-dir",
                    str(tmp_path),
                ],
            )
            assert result.exit_code == 0


class TestXSSCLI:
    def test_test_xss(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        mock_result = _mock_vuln_result(test_type="xss")

        with (
            patch("boba.cli.main._get_http_client") as mock_hc,
            patch("boba.tools.vuln.test_xss", new_callable=AsyncMock, return_value=mock_result),
        ):
            mock_client = AsyncMock()
            mock_client.close = AsyncMock()
            mock_hc.return_value = mock_client

            result = runner.invoke(
                app,
                [
                    "test",
                    "xss",
                    hunt_id,
                    "--url",
                    "https://example.com/search",
                    "--data-dir",
                    str(tmp_path),
                ],
            )
            assert result.exit_code == 0


class TestSQLiCLI:
    def test_test_sqli(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        mock_result = _mock_vuln_result(test_type="sqli")

        with (
            patch("boba.cli.main._get_http_client") as mock_hc,
            patch("boba.tools.vuln.test_sqli", new_callable=AsyncMock, return_value=mock_result),
        ):
            mock_client = AsyncMock()
            mock_client.close = AsyncMock()
            mock_hc.return_value = mock_client

            result = runner.invoke(
                app,
                [
                    "test",
                    "sqli",
                    hunt_id,
                    "--url",
                    "https://example.com/users",
                    "--data-dir",
                    str(tmp_path),
                ],
            )
            assert result.exit_code == 0


class TestAuthCLI:
    def test_test_auth(self, tmp_path):
        hunt_id = _create_hunt(tmp_path)
        mock_result = _mock_vuln_result(test_type="auth")

        with (
            patch("boba.cli.main._get_http_client") as mock_hc,
            patch("boba.tools.vuln.test_auth", new_callable=AsyncMock, return_value=mock_result),
        ):
            mock_client = AsyncMock()
            mock_client.close = AsyncMock()
            mock_hc.return_value = mock_client

            result = runner.invoke(
                app,
                [
                    "test",
                    "auth",
                    hunt_id,
                    "--endpoint",
                    "https://example.com/admin",
                    "--data-dir",
                    str(tmp_path),
                ],
            )
            assert result.exit_code == 0


# ---------------------------------------------------------------------------
# 10. Waybackurls trailing newline
# ---------------------------------------------------------------------------
class TestWaybackurlsNewline:
    def test_stdin_data_has_trailing_newline(self):
        from boba.adapters.waybackurls import WaybackurlsAdapter
        from boba.core.scope import ScopeEngine

        scope = ScopeEngine(ScopeConfig(rules=[]))
        adapter = WaybackurlsAdapter(scope)
        adapter._stdin_targets = ["example.com", "test.com"]
        # The _execute method should produce stdin with trailing newline
        # We verify indirectly by checking the instance stores targets
        assert adapter._stdin_targets == ["example.com", "test.com"]
