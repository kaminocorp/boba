"""Tests for BrowserManager — mocked Playwright to avoid browser dependency."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from boba.core.models import BrowserConfig, Hunt, ScopeConfig, SessionState, AuthMethod
from boba.interaction.browser import BrowserManager
from boba.interaction.history import HttpHistorySink


@pytest.fixture
def hunt_id(context):
    hunt = Hunt(id="browser_test01", name="Browser Test", scope=ScopeConfig())
    context.create_hunt(hunt)
    return hunt.id


@pytest.fixture
def sink(context, hunt_id, tmp_path):
    s = HttpHistorySink(context, hunt_id)
    s._body_dir = tmp_path / "bodies"
    s._body_dir.mkdir()
    return s


@pytest.fixture
def config():
    return BrowserConfig(headless=True)


def _mock_page():
    """Create a mock Playwright Page with all necessary methods."""
    page = AsyncMock()
    page.url = "https://example.com/"
    page.title = AsyncMock(return_value="Example Domain")
    page.goto = AsyncMock()
    page.screenshot = AsyncMock()
    page.evaluate = AsyncMock(
        return_value={
            "forms": [
                {
                    "action": "/login",
                    "method": "post",
                    "inputs": [
                        {"name": "username", "type": "text", "value": "", "id": "user"},
                    ],
                }
            ],
            "links": [{"href": "https://example.com/about", "text": "About"}],
            "scripts": [{"src": "https://example.com/app.js"}],
            "meta": {"description": "Example site"},
            "comments": ["TODO: remove debug endpoint"],
            "inputs": [{"name": "username", "type": "text", "value": "", "id": "user"}],
            "textContent": "Welcome to Example",
        }
    )
    page.fill = AsyncMock()
    page.click = AsyncMock()
    page.wait_for_load_state = AsyncMock()
    page.on = MagicMock()
    page.context = AsyncMock()
    page.context.cookies = AsyncMock(
        return_value=[{"name": "session", "value": "abc123", "domain": "example.com", "path": "/"}]
    )
    return page


def _mock_response(status=200, url="https://example.com/"):
    """Create a mock Playwright Response."""
    resp = AsyncMock()
    resp.status = status
    resp.url = url
    resp.all_headers = AsyncMock(return_value={"content-type": "text/html"})
    resp.request = MagicMock()
    resp.request.method = "GET"
    resp.request.timing = {"responseEnd": 100}
    return resp


class TestBrowserLifecycle:
    @pytest.mark.asyncio
    async def test_start_and_stop(self, config, sink):
        mgr = BrowserManager(config, sink)

        pw_instance = AsyncMock()
        browser = AsyncMock()
        pw_instance.chromium.launch = AsyncMock(return_value=browser)

        mock_pw_cm = AsyncMock()
        mock_pw_cm.start = AsyncMock(return_value=pw_instance)

        with patch.dict(
            "sys.modules",
            {
                "playwright.async_api": MagicMock(
                    async_playwright=MagicMock(return_value=mock_pw_cm)
                )
            },
        ):
            await mgr.start()
            assert mgr._browser is not None

            await mgr.stop()
            assert mgr._browser is None


class TestNavigate:
    @pytest.mark.asyncio
    async def test_navigate_returns_page_info(self, config, sink):
        mgr = BrowserManager(config, sink)

        page = _mock_page()
        mock_response = _mock_response()
        page.goto = AsyncMock(return_value=mock_response)

        # Mock browser and context
        mock_context = AsyncMock()
        mock_context.new_page = AsyncMock(return_value=page)
        mock_context.cookies = AsyncMock(return_value=[])

        mock_browser = AsyncMock()
        mock_browser.new_context = AsyncMock(return_value=mock_context)

        mgr._browser = mock_browser
        mgr._playwright = MagicMock()  # Mark as started

        info = await mgr.navigate("https://example.com/", context_name="default")
        assert info.url == "https://example.com/"
        assert info.title == "Example Domain"
        assert info.status_code == 200


class TestExtract:
    @pytest.mark.asyncio
    async def test_extract_dom(self, config, sink):
        mgr = BrowserManager(config, sink)

        page = _mock_page()
        mock_context = AsyncMock()
        mock_context.new_page = AsyncMock(return_value=page)
        mock_context.cookies = AsyncMock(return_value=[])

        mock_browser = AsyncMock()
        mock_browser.new_context = AsyncMock(return_value=mock_context)

        mgr._browser = mock_browser
        mgr._playwright = MagicMock()

        # Create the context first
        await mgr.get_or_create_context("default")

        dom = await mgr.extract("default")
        assert dom.title == "Example Domain"
        assert len(dom.forms) == 1
        assert dom.forms[0]["action"] == "/login"
        assert len(dom.links) == 1
        assert dom.links[0]["href"] == "https://example.com/about"
        assert len(dom.comments) == 1
        assert "debug endpoint" in dom.comments[0]
        assert dom.text_content == "Welcome to Example"


class TestScreenshot:
    @pytest.mark.asyncio
    async def test_screenshot(self, config, sink, tmp_path):
        mgr = BrowserManager(config, sink)

        page = _mock_page()
        mock_context = AsyncMock()
        mock_context.new_page = AsyncMock(return_value=page)
        mock_context.cookies = AsyncMock(return_value=[])

        mock_browser = AsyncMock()
        mock_browser.new_context = AsyncMock(return_value=mock_context)

        mgr._browser = mock_browser
        mgr._playwright = MagicMock()

        await mgr.get_or_create_context("default")
        path = await mgr.screenshot(tmp_path / "evidence" / "test.png")
        page.screenshot.assert_called_once()
        assert str(path).endswith("test.png")


class TestSessionApplication:
    @pytest.mark.asyncio
    async def test_apply_session(self, config, sink):
        mgr = BrowserManager(config, sink)

        mock_context = AsyncMock()
        mock_context.new_page = AsyncMock(return_value=_mock_page())
        mock_context.cookies = AsyncMock(return_value=[])
        mock_context.add_cookies = AsyncMock()
        mock_context.set_extra_http_headers = AsyncMock()

        mock_browser = AsyncMock()
        mock_browser.new_context = AsyncMock(return_value=mock_context)

        mgr._browser = mock_browser
        mgr._playwright = MagicMock()

        session = SessionState(
            name="user_a",
            target_url="https://app.example.com",
            auth_method=AuthMethod.BEARER,
            cookies={"session": "tok123"},
            headers={"Authorization": "Bearer tok123"},
        )

        await mgr.apply_session(session)
        assert "user_a" in mgr._contexts
        mock_context.set_extra_http_headers.assert_called_once_with(
            {"Authorization": "Bearer tok123"}
        )
