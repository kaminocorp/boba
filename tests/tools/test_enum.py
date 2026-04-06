"""Tests for high-level enumeration tool functions."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch


from boba.core.models import ToolResult
from boba.tools import enum


def _make_result(tool_name: str, records: list[dict]) -> ToolResult:
    """Build a fake ToolResult for mocking adapter.run()."""
    return ToolResult(
        tool_name=tool_name,
        command=[tool_name],
        exit_code=0,
        raw_stdout="",
        raw_stderr="",
        duration_seconds=1.5,
        records=records,
        filtered_count=0,
    )


class TestDirectories:
    async def test_directories_persists_results(self, manager, sample_hunt):
        records = [
            {
                "url": "https://api.example.com/admin",
                "input_value": "admin",
                "status_code": 200,
                "content_length": 4096,
                "word_count": 120,
                "line_count": 30,
                "content_type": "text/html",
                "redirect_location": "",
            },
            {
                "url": "https://api.example.com/.git",
                "input_value": ".git",
                "status_code": 403,
                "content_length": 0,
                "word_count": 0,
                "line_count": 0,
                "content_type": "",
                "redirect_location": "",
            },
        ]
        mock_run = AsyncMock(return_value=_make_result("ffuf", records))

        with patch("boba.tools.enum.FfufAdapter.run", mock_run):
            result = await enum.directories(manager.context, sample_hunt, "https://api.example.com")

        assert len(result.records) == 2
        saved = manager.context.get_directories(sample_hunt.id)
        assert len(saved) == 2
        saved_urls = {d["url"] for d in saved}
        assert "https://api.example.com/admin" in saved_urls
        assert "https://api.example.com/.git" in saved_urls

    async def test_directories_empty_targets(self, manager, sample_hunt):
        """directories() requires a url argument, so we test with a mocked empty result."""
        mock_run = AsyncMock(return_value=_make_result("ffuf", []))

        with patch("boba.tools.enum.FfufAdapter.run", mock_run):
            result = await enum.directories(manager.context, sample_hunt, "https://api.example.com")

        assert result.records == []

    async def test_directories_tool_run_logged(self, manager, sample_hunt):
        records = [
            {
                "url": "https://api.example.com/admin",
                "input_value": "admin",
                "status_code": 200,
                "content_length": 4096,
            },
        ]
        mock_run = AsyncMock(return_value=_make_result("ffuf", records))

        with patch("boba.tools.enum.FfufAdapter.run", mock_run):
            await enum.directories(manager.context, sample_hunt, "https://api.example.com")

        runs = manager.context.get_tool_runs(sample_hunt.id)
        assert any(r["tool_name"] == "ffuf" for r in runs)


class TestParameters:
    async def test_parameters_persists_results(self, manager, sample_hunt):
        records = [
            {
                "url": "https://api.example.com/search",
                "method": "GET",
                "name": "debug",
                "param_type": "query",
                "confirmed": True,
            },
            {
                "url": "https://api.example.com/search",
                "method": "GET",
                "name": "page",
                "param_type": "query",
                "confirmed": False,
            },
        ]
        mock_run = AsyncMock(return_value=_make_result("arjun", records))

        with patch("boba.tools.enum.ArjunAdapter.run", mock_run):
            result = await enum.parameters(
                manager.context,
                sample_hunt,
                "https://api.example.com/search",
            )

        assert len(result.records) == 2
        saved = manager.context.get_parameters(sample_hunt.id)
        assert len(saved) == 2
        assert {p["name"] for p in saved} == {"debug", "page"}
        assert sum(p["confirmed"] for p in saved) == 1

    async def test_parameters_empty_results(self, manager, sample_hunt):
        mock_run = AsyncMock(return_value=_make_result("arjun", []))

        with patch("boba.tools.enum.ArjunAdapter.run", mock_run):
            result = await enum.parameters(
                manager.context,
                sample_hunt,
                "https://api.example.com/search",
            )

        assert result.records == []
        assert manager.context.get_parameters(sample_hunt.id) == []

    async def test_parameters_tool_run_logged(self, manager, sample_hunt):
        records = [
            {
                "url": "https://api.example.com/profile",
                "method": "POST",
                "name": "role",
                "param_type": "body",
                "confirmed": True,
            },
        ]
        mock_run = AsyncMock(return_value=_make_result("arjun", records))

        with patch("boba.tools.enum.ArjunAdapter.run", mock_run):
            await enum.parameters(
                manager.context,
                sample_hunt,
                "https://api.example.com/profile",
                method="POST",
                body_type="json",
            )

        runs = manager.context.get_tool_runs(sample_hunt.id)
        assert any(r["tool_name"] == "arjun" for r in runs)


class TestApi:
    async def test_api_persists_results(self, manager, sample_hunt):
        records = [
            {
                "url": "https://api.example.com/api/v2/users",
                "method": "GET",
                "status_code": 200,
                "content_type": "application/json",
                "content_length": 4521,
                "host": "api.example.com",
                "path": "/api/v2/users",
                "framework": "",
            },
            {
                "url": "https://api.example.com/api/v2/transfer",
                "method": "POST",
                "status_code": 201,
                "content_type": "application/json",
                "content_length": 128,
                "host": "api.example.com",
                "path": "/api/v2/transfer",
                "framework": "",
            },
        ]
        mock_run = AsyncMock(return_value=_make_result("kiterunner", records))

        with patch("boba.tools.enum.KiterunnerAdapter.run", mock_run):
            result = await enum.api(
                manager.context,
                sample_hunt,
                url="https://api.example.com",
            )

        assert len(result.records) == 2
        saved = manager.context.get_api_endpoints(sample_hunt.id)
        assert len(saved) == 2
        methods = {ep["method"] for ep in saved}
        assert "GET" in methods
        assert "POST" in methods

    async def test_api_empty_targets(self, manager, sample_hunt):
        result = await enum.api(manager.context, sample_hunt, targets=[])
        assert result.records == []
        assert result.tool_name == "kiterunner"
        assert result.duration_seconds == 0.0

    async def test_api_tool_run_logged(self, manager, sample_hunt):
        records = [
            {
                "url": "https://api.example.com/api/v1/sessions",
                "method": "DELETE",
                "status_code": 204,
                "host": "api.example.com",
                "path": "/api/v1/sessions",
            },
        ]
        mock_run = AsyncMock(return_value=_make_result("kiterunner", records))

        with patch("boba.tools.enum.KiterunnerAdapter.run", mock_run):
            await enum.api(
                manager.context,
                sample_hunt,
                url="https://api.example.com",
            )

        runs = manager.context.get_tool_runs(sample_hunt.id)
        assert any(r["tool_name"] == "kiterunner" for r in runs)


class TestCrawl:
    async def test_crawl_persists_results(self, manager, sample_hunt):
        records = [
            {"url": "https://api.example.com/login", "host": "api.example.com", "path": "/login"},
            {"url": "https://api.example.com/signup", "host": "api.example.com", "path": "/signup"},
        ]
        mock_run = AsyncMock(return_value=_make_result("katana", records))

        with patch("boba.tools.enum.KatanaAdapter.run", mock_run):
            result = await enum.crawl(manager.context, sample_hunt, ["https://api.example.com"])

        assert len(result.records) == 2
        saved = manager.context.get_urls(sample_hunt.id)
        assert len(saved) == 2
        saved_urls = {u["url"] for u in saved}
        assert "https://api.example.com/login" in saved_urls
        assert "https://api.example.com/signup" in saved_urls

    async def test_crawl_empty_targets(self, manager, sample_hunt):
        result = await enum.crawl(manager.context, sample_hunt, [])
        assert result.records == []
        assert result.tool_name == "katana"
        assert result.duration_seconds == 0.0

    async def test_crawl_tool_run_logged(self, manager, sample_hunt):
        records = [
            {"url": "https://api.example.com/page", "host": "api.example.com", "path": "/page"},
        ]
        mock_run = AsyncMock(return_value=_make_result("katana", records))

        with patch("boba.tools.enum.KatanaAdapter.run", mock_run):
            await enum.crawl(manager.context, sample_hunt, ["https://api.example.com"])

        runs = manager.context.get_tool_runs(sample_hunt.id)
        assert any(r["tool_name"] == "katana" for r in runs)
