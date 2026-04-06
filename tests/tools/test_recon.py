"""Tests for high-level recon tool functions."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch


from boba.core.models import ToolResult
from boba.tools import recon


def _make_result(tool_name: str, records: list[dict]) -> ToolResult:
    """Build a fake ToolResult for mocking adapter.run()."""
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


class TestSubdomains:
    async def test_subdomains_persists_results(self, manager, sample_hunt):
        records = [
            {"subdomain": "api.example.com", "source": "subfinder"},
            {"subdomain": "mail.example.com", "source": "subfinder"},
        ]
        mock_run = AsyncMock(return_value=_make_result("subfinder", records))

        with patch("boba.tools.recon.SubfinderAdapter.run", mock_run):
            result = await recon.subdomains(manager.context, sample_hunt, ["example.com"])

        assert len(result.records) == 2
        saved = manager.context.get_subdomains(sample_hunt.id)
        assert len(saved) == 2
        saved_names = {s["subdomain"] for s in saved}
        assert "api.example.com" in saved_names
        assert "mail.example.com" in saved_names

    async def test_subdomains_empty_targets(self, manager, sample_hunt):
        result = await recon.subdomains(manager.context, sample_hunt, [])
        assert result.records == []
        assert result.tool_name == "subfinder"
        assert result.duration_seconds == 0.0


class TestHosts:
    async def test_hosts_persists_results(self, manager, sample_hunt):
        records = [
            {
                "host": "api.example.com",
                "ip": "1.2.3.4",
                "port": 443,
                "scheme": "https",
                "url": "https://api.example.com",
                "status_code": 200,
                "title": "API",
                "webserver": "nginx",
                "content_length": 1234,
                "content_type": "text/html",
            },
        ]
        mock_run = AsyncMock(return_value=_make_result("httpx", records))

        with patch("boba.tools.recon.HttpxRunnerAdapter.run", mock_run):
            result = await recon.hosts(manager.context, sample_hunt, ["api.example.com"])

        assert len(result.records) == 1
        saved = manager.context.get_hosts(sample_hunt.id)
        assert len(saved) == 1
        assert saved[0]["host"] == "api.example.com"


class TestPorts:
    async def test_ports_persists_results(self, manager, sample_hunt):
        records = [
            {"host": "api.example.com", "ip": "1.2.3.4", "port": 443, "protocol": "tcp"},
            {"host": "api.example.com", "ip": "1.2.3.4", "port": 80, "protocol": "tcp"},
        ]
        mock_run = AsyncMock(return_value=_make_result("naabu", records))

        with patch("boba.tools.recon.NaabuAdapter.run", mock_run):
            result = await recon.ports(manager.context, sample_hunt, ["api.example.com"])

        assert len(result.records) == 2
        saved = manager.context.get_ports(sample_hunt.id)
        assert len(saved) == 2
        port_numbers = {s["port"] for s in saved}
        assert port_numbers == {80, 443}


class TestUrls:
    async def test_urls_merges_parallel(self, manager, sample_hunt):
        gau_records = [
            {"url": "https://api.example.com/v1", "host": "api.example.com", "path": "/v1"},
        ]
        wayback_records = [
            {"url": "https://api.example.com/old", "host": "api.example.com", "path": "/old"},
        ]
        gau_result = _make_result("gau", gau_records)
        wayback_result = _make_result("waybackurls", wayback_records)

        mock_gau = AsyncMock(return_value=gau_result)
        mock_wayback = AsyncMock(return_value=wayback_result)

        with (
            patch("boba.tools.recon.GauAdapter.run", mock_gau),
            patch("boba.tools.recon.WaybackurlsAdapter.run", mock_wayback),
        ):
            result = await recon.urls(manager.context, sample_hunt, ["example.com"])

        # Both sources merged
        assert len(result.records) == 2
        assert result.tool_name == "recon.urls"
        saved = manager.context.get_urls(sample_hunt.id)
        assert len(saved) == 2
        saved_urls = {u["url"] for u in saved}
        assert "https://api.example.com/v1" in saved_urls
        assert "https://api.example.com/old" in saved_urls


class TestTech:
    async def test_tech_persists_results(self, manager, sample_hunt):
        records = [
            {
                "host": "api.example.com",
                "technologies": [
                    {"name": "nginx", "version": "1.21"},
                    {"name": "PHP", "version": "8.1"},
                ],
            },
        ]
        mock_run = AsyncMock(return_value=_make_result("whatweb", records))

        with patch("boba.tools.recon.WhatwebAdapter.run", mock_run):
            result = await recon.tech(manager.context, sample_hunt, ["https://api.example.com"])

        assert len(result.records) == 1
        saved = manager.context.get_technologies(sample_hunt.id)
        assert len(saved) == 2
        names = {t["name"] for t in saved}
        assert names == {"nginx", "PHP"}


class TestSecrets:
    async def test_secrets_persists_results(self, manager, sample_hunt):
        records = [
            {
                "rule_id": "aws-access-key-id",
                "secret_type": "key",
                "file_path": "config/deploy.env",
                "repo": "https://github.com/acme/webapp",
                "line_number": 42,
                "match_preview": "AKIA****XMPL",
                "commit": "a1b2c3d",
                "author": "dev@acme.com",
                "date": "2025-11-03",
                "entropy": 4.2,
            },
            {
                "rule_id": "github-pat",
                "secret_type": "token",
                "file_path": "scripts/ci.sh",
                "repo": "https://github.com/acme/webapp",
                "line_number": 5,
                "match_preview": "ghp_****7890",
                "commit": "b2c3d4e",
                "author": "ci@acme.com",
                "date": "2025-12-01",
                "entropy": 3.8,
            },
        ]
        mock_run = AsyncMock(return_value=_make_result("gitleaks", records))

        with patch("boba.tools.recon.GitleaksAdapter.run", mock_run):
            result = await recon.secrets(
                manager.context, sample_hunt, "https://github.com/acme/webapp"
            )

        assert len(result.records) == 2
        saved = manager.context.get_secrets(sample_hunt.id)
        assert len(saved) == 2
        rule_ids = {s["rule_id"] for s in saved}
        assert "aws-access-key-id" in rule_ids
        assert "github-pat" in rule_ids

    async def test_secrets_empty_target(self, manager, sample_hunt):
        result = await recon.secrets(manager.context, sample_hunt, "")
        assert result.records == []
        assert result.tool_name == "gitleaks"
        assert result.duration_seconds == 0.0

    async def test_secrets_tool_run_logged(self, manager, sample_hunt):
        records = [
            {
                "rule_id": "generic-api-key",
                "secret_type": "key",
                "file_path": "src/config.py",
                "repo": "https://github.com/acme/webapp",
                "line_number": 10,
                "match_preview": "sk_l****cdef",
            },
        ]
        mock_run = AsyncMock(return_value=_make_result("gitleaks", records))

        with patch("boba.tools.recon.GitleaksAdapter.run", mock_run):
            await recon.secrets(manager.context, sample_hunt, "https://github.com/acme/webapp")

        runs = manager.context.get_tool_runs(sample_hunt.id)
        assert any(r["tool_name"] == "gitleaks" for r in runs)

    async def test_secrets_org_target_enumerates_repos(self, manager, sample_hunt):
        repos = [
            "https://github.com/acme/webapp.git",
            "https://github.com/acme/tools.git",
        ]

        async def run_side_effect(*, targets, config):
            repo = targets[0]
            return _make_result(
                "gitleaks",
                [
                    {
                        "rule_id": "generic-api-key",
                        "secret_type": "key",
                        "file_path": "src/config.py",
                        "repo": repo,
                        "line_number": 10,
                        "match_preview": "sk_l****cdef",
                    }
                ],
            )

        with (
            patch("boba.tools.recon._list_public_github_repos", AsyncMock(return_value=repos)),
            patch("boba.tools.recon.GitleaksAdapter.run", AsyncMock(side_effect=run_side_effect)),
        ):
            result = await recon.secrets(manager.context, sample_hunt, "acme")

        assert len(result.records) == 2
        saved = manager.context.get_secrets(sample_hunt.id)
        assert len(saved) == 2
        assert {row["repo"] for row in saved} == set(repos)


class TestToolRunLogged:
    async def test_tool_run_logged(self, manager, sample_hunt):
        records = [{"subdomain": "test.example.com", "source": "subfinder"}]
        mock_run = AsyncMock(return_value=_make_result("subfinder", records))

        with patch("boba.tools.recon.SubfinderAdapter.run", mock_run):
            await recon.subdomains(manager.context, sample_hunt, ["example.com"])

        runs = manager.context.get_tool_runs(sample_hunt.id)
        assert len(runs) >= 1
        assert runs[0]["tool_name"] == "subfinder"
        assert runs[0]["status"] == "completed"
        assert runs[0]["records_found"] == 1
