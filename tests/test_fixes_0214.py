"""Tests for specific fixes in the 0.2.14 release."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest
import typer

from boba.adapters.httpx_runner import _safe_int
from boba.cli.main import _parse_headers, enum_app
from boba.core.context import _parse_json_field
from boba.core.models import AdapterConfig, HttpResponse
from boba.tools.vuln import _bodies_similar, _extract_json_keys


# ---------------------------------------------------------------------------
# 1. _bodies_similar JSON-aware comparison
# ---------------------------------------------------------------------------
class TestBodiesSimilarJSON:
    """_bodies_similar should use JSON key-structure comparison for JSON bodies."""

    def test_same_keys_different_values_are_similar(self):
        body_a = json.dumps({"user": "alice", "id": 1, "role": "admin"}).encode()
        body_b = json.dumps({"user": "bob", "id": 2, "role": "viewer"}).encode()
        assert _bodies_similar(body_a, body_b) is True

    def test_different_keys_are_not_similar(self):
        body_a = json.dumps({"user": "alice", "id": 1}).encode()
        body_b = json.dumps({"error": "not found", "code": 404}).encode()
        assert _bodies_similar(body_a, body_b) is False

    def test_non_json_uses_line_overlap(self):
        # Need enough shared lines so overlap exceeds 0.8 threshold
        shared = b"line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9"
        body_a = shared + b"\nextra_a"
        body_b = shared + b"\nextra_b"
        assert _bodies_similar(body_a, body_b) is True

    def test_identical_bodies_are_similar(self):
        body = b'{"a": 1}'
        assert _bodies_similar(body, body) is True

    def test_empty_body_vs_nonempty_not_similar(self):
        assert _bodies_similar(b"", b'{"a": 1}') is False


# ---------------------------------------------------------------------------
# 2. httpx adapter _safe_int() guard
# ---------------------------------------------------------------------------
class TestSafeInt:
    def test_none_returns_none(self):
        assert _safe_int(None) is None

    def test_int_passthrough(self):
        assert _safe_int(80) == 80

    def test_string_int(self):
        assert _safe_int("443") == 443

    def test_non_numeric_string_returns_none(self):
        assert _safe_int("abc") is None

    def test_empty_string_returns_none(self):
        assert _safe_int("") is None


# ---------------------------------------------------------------------------
# 3. _parse_json_field helper
# ---------------------------------------------------------------------------
class TestParseJsonField:
    def test_valid_json(self):
        assert _parse_json_field('{"a": 1}') == {"a": 1}

    def test_malformed_json_returns_default(self):
        result = _parse_json_field("{bad json", default="{}")
        assert result == {}

    def test_none_input_returns_default(self):
        result = _parse_json_field(None, default="[]")
        assert result == []

    def test_empty_string_with_dict_default(self):
        result = _parse_json_field("", default="{}")
        assert result == {}


# ---------------------------------------------------------------------------
# 4. _extract_json_keys helper
# ---------------------------------------------------------------------------
class TestExtractJsonKeys:
    def test_nested_dict_keys(self):
        data = {"a": {"b": 1, "c": {"d": 2}}}
        keys = _extract_json_keys(data)
        assert "a" in keys
        assert "a.b" in keys
        assert "a.c" in keys
        assert "a.c.d" in keys

    def test_list_notation(self):
        data = {"items": [{"id": 1}]}
        keys = _extract_json_keys(data)
        assert "items" in keys
        assert "items[]" in keys
        assert "items[].id" in keys

    def test_empty_dict_returns_empty_set(self):
        assert _extract_json_keys({}) == set()


# ---------------------------------------------------------------------------
# 5. Config deepcopy in scan.py
# ---------------------------------------------------------------------------
class TestNucleiScanConfigDeepcopy:
    @pytest.mark.asyncio
    async def test_config_not_mutated(self):
        """Passing a config to nuclei_scan should not mutate the original."""
        from unittest.mock import patch, AsyncMock as AM

        from boba.core.models import Hunt, ScopeAction, ScopeConfig, ScopeRule, ScopeRuleType
        from boba.core.models import ToolResult

        config = AdapterConfig(extra_args=["--original"], extra_args_dict={})
        original_args = list(config.extra_args)
        original_dict = dict(config.extra_args_dict)

        mock_context = MagicMock()
        mock_context.get_hosts.return_value = [{"url": "https://example.com"}]
        mock_context.log_tool_run = MagicMock()
        mock_context.upsert_finding = MagicMock()

        hunt = Hunt(
            id="h1",
            name="test",
            status="active",
            scope=ScopeConfig(
                rules=[
                    ScopeRule(
                        pattern="*.example.com",
                        rule_type=ScopeRuleType.DOMAIN,
                        action=ScopeAction.INCLUDE,
                    )
                ]
            ),
            created_at="2024-01-01",
            updated_at="2024-01-01",
        )

        mock_result = ToolResult(
            tool_name="nuclei",
            command=[],
            exit_code=0,
            raw_stdout="",
            raw_stderr="",
            duration_seconds=0.0,
            records=[],
        )

        with patch("boba.tools.scan.NucleiAdapter") as MockAdapter:
            instance = MockAdapter.return_value
            instance.run = AM(return_value=mock_result)

            from boba.tools.scan import nuclei_scan

            await nuclei_scan(
                mock_context,
                hunt,
                targets=["https://example.com"],
                severity="high",
                config=config,
            )

        # Original config should be unchanged
        assert config.extra_args == original_args
        assert config.extra_args_dict == original_dict


# ---------------------------------------------------------------------------
# 6. XSS HTML entity detection
# ---------------------------------------------------------------------------
class TestXssHtmlEntityDetection:
    @pytest.mark.asyncio
    async def test_html_encoded_reflection_detected(self):
        """When the server HTML-encodes the payload, evidence type should be
        'reflected_html_encoded'."""
        from boba.tools.vuln import test_xss

        payload = "<script>alert(1)</script>"
        # Server encodes < and > as HTML entities
        encoded_body = "Hello &lt;script&gt;alert(1)&lt;/script&gt; world"

        mock_response = HttpResponse(
            request_id=1,
            status_code=200,
            headers={"content-type": "text/html"},
            body_text=encoded_body,
        )

        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=mock_response)

        result = await test_xss(
            http_client=mock_client,
            url="https://example.com/search",
            params={"q": ""},
            payloads=[payload],
        )

        # Should find the HTML-encoded reflection evidence
        html_encoded_evidence = [
            e for e in result.evidence if e.get("type") == "reflected_html_encoded"
        ]
        assert len(html_encoded_evidence) >= 1
        assert html_encoded_evidence[0]["payload"] == payload


# ---------------------------------------------------------------------------
# 7. CLI _parse_headers helper
# ---------------------------------------------------------------------------
class TestParseHeaders:
    def test_valid_header(self):
        result = _parse_headers(["Authorization:Bearer token"])
        assert result == {"Authorization": "Bearer token"}

    def test_invalid_header_raises_exit(self):
        with pytest.raises((SystemExit, typer.Exit)):
            _parse_headers(["no-colon-here"])

    def test_none_returns_empty(self):
        assert _parse_headers(None) == {}

    def test_multiple_headers(self):
        result = _parse_headers(["X-Foo:bar", "X-Baz:qux"])
        assert result == {"X-Foo": "bar", "X-Baz": "qux"}

    def test_colon_in_value_splits_on_first(self):
        result = _parse_headers(["Authorization:Basic dXNlcjpwYXNz"])
        assert result == {"Authorization": "Basic dXNlcjpwYXNz"}


# ---------------------------------------------------------------------------
# 8. CLI enum crawl command exists
# ---------------------------------------------------------------------------
class TestEnumCrawlCommand:
    def test_crawl_command_registered(self):
        """The 'crawl' command should be registered on enum_app."""
        command_names = [cmd.name for cmd in enum_app.registered_commands]
        assert "crawl" in command_names
