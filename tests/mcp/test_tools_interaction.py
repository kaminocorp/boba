"""Tests for MCP interaction tools — sessions, HTTP, browser, OOB."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from unittest.mock import AsyncMock, MagicMock

import pytest

pytestmark = pytest.mark.usefixtures("_patch_resources")


def _text(content_blocks) -> dict | list:
    return json.loads(content_blocks[0].text)


async def _create_hunt(mcp_server, name="Interaction Test"):
    content, _ = await mcp_server.call_tool("hunt_create", {"name": name})
    return json.loads(content[0].text)["hunt_id"]


# =============================================================================
# Session tools
# =============================================================================


class TestSessionLifecycle:
    async def test_create_session(self, mcp_server):
        hunt_id = await _create_hunt(mcp_server)
        content, _ = await mcp_server.call_tool(
            "session_create",
            {"hunt_id": hunt_id, "name": "user_a", "target_url": "https://app.example.com"},
        )
        data = _text(content)
        assert data["name"] == "user_a"
        assert data["target_url"] == "https://app.example.com"
        assert data["auth_method"] == "form"
        assert data["is_valid"] is True

    async def test_login_bearer(self, mcp_server):
        hunt_id = await _create_hunt(mcp_server)
        await mcp_server.call_tool(
            "session_create",
            {"hunt_id": hunt_id, "name": "api", "target_url": "https://api.example.com"},
        )
        content, _ = await mcp_server.call_tool(
            "session_login_token",
            {"hunt_id": hunt_id, "session_name": "api", "token": "tok_abc"},
        )
        data = _text(content)
        assert data["auth_method"] == "bearer"
        assert "Bearer tok_abc" in data["headers"].get("Authorization", "")

    async def test_login_basic(self, mcp_server):
        hunt_id = await _create_hunt(mcp_server)
        await mcp_server.call_tool(
            "session_create",
            {"hunt_id": hunt_id, "name": "basic_user", "target_url": "https://example.com"},
        )
        content, _ = await mcp_server.call_tool(
            "session_login_basic",
            {
                "hunt_id": hunt_id,
                "session_name": "basic_user",
                "username": "admin",
                "password": "secret",
            },
        )
        data = _text(content)
        assert data["auth_method"] == "basic"
        assert "Authorization" in data["headers"]

    async def test_login_cookies(self, mcp_server):
        hunt_id = await _create_hunt(mcp_server)
        await mcp_server.call_tool(
            "session_create",
            {"hunt_id": hunt_id, "name": "cookie_user", "target_url": "https://example.com"},
        )
        content, _ = await mcp_server.call_tool(
            "session_login_cookies",
            {
                "hunt_id": hunt_id,
                "session_name": "cookie_user",
                "cookies": {"session_id": "abc123", "csrf": "xyz"},
            },
        )
        data = _text(content)
        assert data["cookies"]["session_id"] == "abc123"

    async def test_login_header(self, mcp_server):
        hunt_id = await _create_hunt(mcp_server)
        await mcp_server.call_tool(
            "session_create",
            {"hunt_id": hunt_id, "name": "header_user", "target_url": "https://example.com"},
        )
        content, _ = await mcp_server.call_tool(
            "session_login_header",
            {
                "hunt_id": hunt_id,
                "session_name": "header_user",
                "header_name": "X-API-Key",
                "header_value": "key_123",
            },
        )
        data = _text(content)
        assert data["headers"]["X-API-Key"] == "key_123"

    async def test_list_sessions(self, mcp_server):
        hunt_id = await _create_hunt(mcp_server)
        await mcp_server.call_tool(
            "session_create",
            {"hunt_id": hunt_id, "name": "s1", "target_url": "https://example.com"},
        )
        await mcp_server.call_tool(
            "session_create",
            {"hunt_id": hunt_id, "name": "s2", "target_url": "https://example.com"},
        )
        content, _ = await mcp_server.call_tool("session_list", {"hunt_id": hunt_id})
        data = _text(content)
        assert len(data) == 2
        names = {s["name"] for s in data}
        assert names == {"s1", "s2"}

    async def test_delete_session(self, mcp_server):
        hunt_id = await _create_hunt(mcp_server)
        await mcp_server.call_tool(
            "session_create",
            {"hunt_id": hunt_id, "name": "to_delete", "target_url": "https://example.com"},
        )
        content, _ = await mcp_server.call_tool(
            "session_delete", {"hunt_id": hunt_id, "session_name": "to_delete"}
        )
        data = _text(content)
        assert data["deleted"] == "to_delete"

        # Verify it's gone
        list_content, _ = await mcp_server.call_tool("session_list", {"hunt_id": hunt_id})
        assert _text(list_content) == []


# =============================================================================
# HTTP tools (mocked HttpClient)
# =============================================================================


@dataclass
class FakeHttpResponse:
    request_id: int = 1
    status_code: int = 200
    headers: dict = field(default_factory=lambda: {"content-type": "text/html"})
    body: bytes = b"<html>OK</html>"
    body_text: str = "<html>OK</html>"
    elapsed_ms: float = 50.0
    redirect_chain: list = field(default_factory=list)


@dataclass
class FakeCompareResult:
    status_match: bool = True
    status_a: int = 200
    status_b: int = 200
    header_diffs: list = field(default_factory=list)
    body_diff_summary: str = "identical"
    body_length_a: int = 100
    body_length_b: int = 100
    timing_diff_ms: float = 5.0


@dataclass
class FakeFuzzResult:
    total_requests: int = 3
    results: list = field(default_factory=list)
    anomalies: list = field(default_factory=list)
    baseline_status: int = 200
    baseline_length: int = 100


class TestHttpTools:
    async def test_http_request(self, mcp_server, mcp_resources):
        hunt_id = await _create_hunt(mcp_server)
        mock_client = MagicMock()
        mock_client.request = AsyncMock(return_value=FakeHttpResponse())
        mcp_resources._http_clients[hunt_id] = mock_client

        content, _ = await mcp_server.call_tool(
            "http_request", {"hunt_id": hunt_id, "url": "https://example.com", "method": "GET"}
        )
        data = _text(content)
        assert data["status_code"] == 200
        assert data["request_id"] == 1
        mock_client.request.assert_called_once()

    async def test_http_request_with_session(self, mcp_server, mcp_resources):
        hunt_id = await _create_hunt(mcp_server)

        # Create a session with a bearer token
        await mcp_server.call_tool(
            "session_create",
            {"hunt_id": hunt_id, "name": "auth", "target_url": "https://example.com"},
        )
        await mcp_server.call_tool(
            "session_login_token",
            {"hunt_id": hunt_id, "session_name": "auth", "token": "tok_test"},
        )

        mock_client = MagicMock()
        mock_client.request = AsyncMock(return_value=FakeHttpResponse())
        mcp_resources._http_clients[hunt_id] = mock_client

        await mcp_server.call_tool(
            "http_request",
            {
                "hunt_id": hunt_id,
                "url": "https://example.com/api",
                "session_name": "auth",
            },
        )

        # Verify session headers were merged
        call_kwargs = mock_client.request.call_args
        headers = call_kwargs.kwargs.get("headers") or call_kwargs[1].get("headers")
        assert "Authorization" in headers

    async def test_http_replay(self, mcp_server, mcp_resources):
        hunt_id = await _create_hunt(mcp_server)
        mock_client = MagicMock()
        mock_client.replay = AsyncMock(return_value=FakeHttpResponse(request_id=2))
        mcp_resources._http_clients[hunt_id] = mock_client

        content, _ = await mcp_server.call_tool(
            "http_replay",
            {"hunt_id": hunt_id, "request_id": 1, "modify_headers": {"X-Test": "true"}},
        )
        data = _text(content)
        assert data["request_id"] == 2
        mock_client.replay.assert_called_once_with(1, modifications={"headers": {"X-Test": "true"}})

    async def test_http_compare(self, mcp_server, mcp_resources):
        hunt_id = await _create_hunt(mcp_server)
        mock_client = MagicMock()
        mock_client.compare = AsyncMock(return_value=FakeCompareResult())
        mcp_resources._http_clients[hunt_id] = mock_client

        content, _ = await mcp_server.call_tool(
            "http_compare", {"hunt_id": hunt_id, "request_id_a": 1, "request_id_b": 2}
        )
        data = _text(content)
        assert data["status_match"] is True
        assert data["body_diff_summary"] == "identical"

    async def test_http_fuzz(self, mcp_server, mcp_resources):
        hunt_id = await _create_hunt(mcp_server)
        mock_client = MagicMock()
        mock_client.fuzz = AsyncMock(return_value=FakeFuzzResult())
        mcp_resources._http_clients[hunt_id] = mock_client

        content, _ = await mcp_server.call_tool(
            "http_fuzz",
            {
                "hunt_id": hunt_id,
                "url": "https://example.com/search?q=§test§",
                "payloads": {"test": ["<script>", "' OR 1=1--"]},
            },
        )
        data = _text(content)
        assert data["total_requests"] == 3


# =============================================================================
# Browser tools (mocked BrowserManager)
# =============================================================================


@dataclass
class FakePageInfo:
    url: str = "https://example.com"
    final_url: str = "https://example.com"
    status_code: int = 200
    title: str = "Example"
    content_type: str = "text/html"
    headers: dict = field(default_factory=dict)
    cookies: list = field(default_factory=list)
    timing_ms: float = 150.0
    requests_captured: int = 5


@dataclass
class FakeDOMExtraction:
    url: str = "https://example.com"
    title: str = "Example"
    forms: list = field(default_factory=list)
    links: list = field(default_factory=lambda: [{"href": "/login", "text": "Login"}])
    scripts: list = field(default_factory=list)
    meta: dict = field(default_factory=dict)
    comments: list = field(default_factory=list)
    inputs: list = field(default_factory=list)
    text_content: str = ""


class TestBrowserTools:
    async def test_browser_navigate(self, mcp_server, mcp_resources):
        hunt_id = await _create_hunt(mcp_server)
        mock_browser = MagicMock()
        mock_browser.navigate = AsyncMock(return_value=FakePageInfo())
        mock_browser.start = AsyncMock()
        mock_browser.apply_session = AsyncMock()
        mcp_resources._browser = mock_browser

        content, _ = await mcp_server.call_tool(
            "browser_navigate", {"hunt_id": hunt_id, "url": "https://example.com"}
        )
        data = _text(content)
        assert data["title"] == "Example"
        assert data["status_code"] == 200

    async def test_browser_screenshot(self, mcp_server, mcp_resources, tmp_path):
        hunt_id = await _create_hunt(mcp_server)
        out_path = str(tmp_path / "shot.png")
        mock_browser = MagicMock()
        mock_browser.screenshot = AsyncMock(return_value=out_path)
        mcp_resources._browser = mock_browser

        content, _ = await mcp_server.call_tool(
            "browser_screenshot", {"hunt_id": hunt_id, "output_path": out_path}
        )
        data = _text(content)
        assert data["path"] == out_path

    async def test_browser_extract(self, mcp_server, mcp_resources):
        hunt_id = await _create_hunt(mcp_server)
        mock_browser = MagicMock()
        mock_browser.extract = AsyncMock(return_value=FakeDOMExtraction())
        mcp_resources._browser = mock_browser

        content, _ = await mcp_server.call_tool("browser_extract", {"hunt_id": hunt_id})
        data = _text(content)
        assert data["title"] == "Example"
        assert len(data["links"]) == 1


# =============================================================================
# OOB tools (mocked OOBManager)
# =============================================================================


class TestOOBTools:
    async def test_oob_create_listener(self, mcp_server, mcp_resources):
        hunt_id = await _create_hunt(mcp_server)
        mock_oob = MagicMock()
        mock_oob.start = AsyncMock()
        mock_oob.create_listener = AsyncMock(return_value="abc123.oast.live")
        mcp_resources._oob_managers[hunt_id] = mock_oob

        content, _ = await mcp_server.call_tool(
            "oob_create_listener",
            {"hunt_id": hunt_id, "purpose": "blind SSRF", "target_url": "https://example.com"},
        )
        data = _text(content)
        assert data["callback_domain"] == "abc123.oast.live"
        assert data["purpose"] == "blind SSRF"

    async def test_oob_get_payload(self, mcp_server, mcp_resources):
        hunt_id = await _create_hunt(mcp_server)
        mock_oob = MagicMock()
        mock_oob.get_payload_url = MagicMock(return_value="http://abc123.oast.live")
        mcp_resources._oob_managers[hunt_id] = mock_oob

        content, _ = await mcp_server.call_tool(
            "oob_get_payload",
            {"hunt_id": hunt_id, "callback_domain": "abc123.oast.live"},
        )
        data = _text(content)
        assert data["payload_url"] == "http://abc123.oast.live"

    async def test_oob_poll(self, mcp_server, mcp_resources):
        hunt_id = await _create_hunt(mcp_server)
        interactions = [
            {"type": "http", "remote_address": "1.2.3.4", "timestamp": "2026-01-01T00:00:00Z"}
        ]
        mock_oob = MagicMock()
        mock_oob.poll = AsyncMock(return_value=interactions)
        mcp_resources._oob_managers[hunt_id] = mock_oob

        content, _ = await mcp_server.call_tool(
            "oob_poll", {"hunt_id": hunt_id, "timeout_seconds": 5}
        )
        data = _text(content)
        assert len(data) == 1
        assert data[0]["type"] == "http"


# =============================================================================
# Resource cleanup
# =============================================================================


class TestResourceCleanup:
    async def test_shutdown_closes_http_clients(self, mcp_resources):
        mock_client = MagicMock()
        mock_client.close = AsyncMock()
        mcp_resources._http_clients["hunt1"] = mock_client

        await mcp_resources.shutdown()
        mock_client.close.assert_called_once()
        assert len(mcp_resources._http_clients) == 0

    async def test_shutdown_stops_browser(self, mcp_resources):
        mock_browser = MagicMock()
        mock_browser.stop = AsyncMock()
        mcp_resources._browser = mock_browser

        await mcp_resources.shutdown()
        mock_browser.stop.assert_called_once()
        assert mcp_resources._browser is None

    async def test_shutdown_stops_oob_managers(self, mcp_resources):
        mock_oob = MagicMock()
        mock_oob.stop = AsyncMock()
        mcp_resources._oob_managers["hunt1"] = mock_oob

        await mcp_resources.shutdown()
        mock_oob.stop.assert_called_once()
        assert len(mcp_resources._oob_managers) == 0
