"""Tests for V3 attack path prioritization — endpoint scoring, CLI."""

from __future__ import annotations

import json

import pytest

from boba.analysis.prioritize import prioritize_endpoints
from boba.core.models import Hunt, ScopeConfig


@pytest.fixture
def hunt_id(context):
    hunt = Hunt(id="prio_test_001", name="Priority Test", scope=ScopeConfig())
    context.create_hunt(hunt)
    return hunt.id


def _add_url(context, hunt_id, url, method="GET"):
    context.upsert_url(
        hunt_id,
        {
            "url": url,
            "host": url.split("//")[1].split("/")[0],
            "method": method,
        },
    )


# ═══════════════════ Scoring ═══════════════════


class TestPrioritizeEndpoints:
    def test_param_endpoints_higher(self, context, hunt_id):
        """URLs with query params rank higher than those without."""
        _add_url(context, hunt_id, "https://app.example.com/search?q=test")
        _add_url(context, hunt_id, "https://app.example.com/about")

        results = prioritize_endpoints(context, hunt_id)
        assert len(results) == 2
        # Param URL should be first (higher score)
        assert "q=test" in results[0]["url"]
        assert results[0]["priority_score"] > results[1]["priority_score"]

    def test_auth_endpoints_boosted(self, context, hunt_id):
        """Auth-related endpoints (login, reset) rank higher."""
        _add_url(context, hunt_id, "https://app.example.com/login")
        _add_url(context, hunt_id, "https://app.example.com/about")

        results = prioritize_endpoints(context, hunt_id)
        login = [r for r in results if "login" in r["url"]]
        about = [r for r in results if "about" in r["url"]]
        assert login[0]["priority_score"] > about[0]["priority_score"]
        assert "auth" in login[0]["suggested_tests"]

    def test_hot_host_boost(self, context, hunt_id):
        """Endpoints on hosts with existing findings get priority boost."""
        _add_url(context, hunt_id, "https://vuln.example.com/api/data")
        _add_url(context, hunt_id, "https://clean.example.com/api/data")

        # Create a finding on vuln.example.com
        context.upsert_finding(
            hunt_id,
            {
                "finding_type": "xss",
                "severity": "medium",
                "title": "XSS",
                "url": "https://vuln.example.com/search",
                "parameter": "q",
            },
        )

        results = prioritize_endpoints(context, hunt_id)
        vuln_ep = [r for r in results if "vuln.example.com" in r["url"]]
        clean_ep = [r for r in results if "clean.example.com" in r["url"]]
        assert vuln_ep[0]["priority_score"] > clean_ep[0]["priority_score"]

    def test_already_tested_excluded(self, context, hunt_id):
        """Endpoints with coverage rows are excluded from results."""
        _add_url(context, hunt_id, "https://app.example.com/tested")
        _add_url(context, hunt_id, "https://app.example.com/untested")

        context.upsert_coverage(
            hunt_id,
            {
                "url": "https://app.example.com/tested",
                "test_type": "xss",
            },
        )

        results = prioritize_endpoints(context, hunt_id)
        urls = [r["url"] for r in results]
        assert "https://app.example.com/tested" not in urls
        assert "https://app.example.com/untested" in urls

    def test_top_limit(self, context, hunt_id):
        """--top limits results."""
        for i in range(5):
            _add_url(context, hunt_id, f"https://app.example.com/page{i}")

        results = prioritize_endpoints(context, hunt_id, top=2)
        assert len(results) == 2

    def test_proxy_endpoint_ssrf_suggested(self, context, hunt_id):
        """Proxy/redirect endpoints suggest SSRF testing."""
        _add_url(context, hunt_id, "https://app.example.com/proxy/fetch")

        results = prioritize_endpoints(context, hunt_id)
        proxy = results[0]
        assert "ssrf" in proxy["suggested_tests"]

    def test_admin_endpoint_auth_suggested(self, context, hunt_id):
        """Admin endpoints suggest auth testing."""
        _add_url(context, hunt_id, "https://app.example.com/admin/dashboard")

        results = prioritize_endpoints(context, hunt_id)
        admin = results[0]
        assert "auth" in admin["suggested_tests"]

    def test_discovered_parameters_boost_score(self, context, hunt_id):
        """Endpoints with discovered hidden parameters rank higher."""
        _add_url(context, hunt_id, "https://app.example.com/search")
        _add_url(context, hunt_id, "https://app.example.com/about")
        context.upsert_parameter(
            hunt_id,
            {
                "url": "https://app.example.com/search",
                "method": "GET",
                "name": "debug",
                "param_type": "query",
                "confirmed": False,
            },
            source="arjun",
        )

        results = prioritize_endpoints(context, hunt_id)
        search = [r for r in results if r["url"].endswith("/search")]
        about = [r for r in results if r["url"].endswith("/about")]
        assert search[0]["priority_score"] > about[0]["priority_score"]
        assert any("Arjun found" in reason for reason in search[0]["reasons"])

    def test_confirmed_parameters_boost_more_than_unconfirmed(self, context, hunt_id):
        """Confirmed parameters get a larger score boost than unconfirmed ones."""
        _add_url(context, hunt_id, "https://app.example.com/search")
        _add_url(context, hunt_id, "https://app.example.com/profile")
        context.upsert_parameter(
            hunt_id,
            {
                "url": "https://app.example.com/search",
                "method": "GET",
                "name": "debug",
                "param_type": "query",
                "confirmed": False,
            },
            source="arjun",
        )
        context.upsert_parameter(
            hunt_id,
            {
                "url": "https://app.example.com/profile",
                "method": "GET",
                "name": "role",
                "param_type": "query",
                "confirmed": True,
            },
            source="arjun",
        )

        results = prioritize_endpoints(context, hunt_id)
        search = [r for r in results if r["url"].endswith("/search")]
        profile = [r for r in results if r["url"].endswith("/profile")]
        assert profile[0]["priority_score"] > search[0]["priority_score"]
        assert any("confirmed by response change" in reason for reason in profile[0]["reasons"])

    def test_parameter_boost_matches_query_variant(self, context, hunt_id):
        """Parameter discovery should match URLs even when stored without a query string."""
        _add_url(context, hunt_id, "https://app.example.com/search?q=test")
        context.upsert_parameter(
            hunt_id,
            {
                "url": "https://app.example.com/search",
                "method": "GET",
                "name": "q",
                "param_type": "query",
                "confirmed": True,
            },
            source="arjun",
        )

        results = prioritize_endpoints(context, hunt_id)
        assert len(results) == 1
        assert results[0]["url"].endswith("/search?q=test")
        assert any("Arjun found" in reason for reason in results[0]["reasons"])

    def test_empty_endpoints(self, context, hunt_id):
        """No endpoints returns empty list."""
        results = prioritize_endpoints(context, hunt_id)
        assert results == []


# ═══════════════════ CLI ═══════════════════


class TestCLIPrioritize:
    def test_cli_prioritize_json(self, tmp_path):
        """CLI analyze prioritize --format json produces valid output."""
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
                "url": "https://app.example.com/api/users?id=1",
                "host": "app.example.com",
                "method": "GET",
            },
        )
        mgr.close_context()

        result = runner.invoke(
            app,
            [
                "analyze",
                "prioritize",
                hunt.id,
                "--format",
                "json",
                "--data-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert len(data) == 1
        assert data[0]["priority_score"] > 0
        assert "suggested_tests" in data[0]

    def test_cli_prioritize_top(self, tmp_path):
        """CLI analyze prioritize --top 1 limits output."""
        from typer.testing import CliRunner
        from boba.cli.main import app
        from boba.core.hunt import HuntManager

        runner = CliRunner()
        db_path = str(tmp_path / "boba.db")
        mgr = HuntManager(db_path=db_path)
        hunt = mgr.create(name="CLI Test")

        for i in range(3):
            mgr.context.upsert_url(
                hunt.id,
                {
                    "url": f"https://app.example.com/page{i}",
                    "host": "app.example.com",
                    "method": "GET",
                },
            )
        mgr.close_context()

        result = runner.invoke(
            app,
            [
                "analyze",
                "prioritize",
                hunt.id,
                "--top",
                "1",
                "--format",
                "json",
                "--data-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert len(data) == 1
