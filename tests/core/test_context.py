"""Tests for the hunt context (SQLite persistence)."""

import json

from boba.core.models import Hunt, HuntStatus, ToolResult


class TestHuntCRUD:
    def test_create_and_get(self, context):
        hunt = Hunt(id="test123", name="Test")
        context.create_hunt(hunt)
        retrieved = context.get_hunt("test123")
        assert retrieved.name == "Test"
        assert retrieved.status == HuntStatus.ACTIVE

    def test_list_hunts(self, context):
        context.create_hunt(Hunt(id="a", name="First"))
        context.create_hunt(Hunt(id="b", name="Second"))
        hunts = context.list_hunts()
        assert len(hunts) == 2

    def test_update_status(self, context):
        context.create_hunt(Hunt(id="x", name="X"))
        context.update_hunt_status("x", HuntStatus.PAUSED)
        assert context.get_hunt("x").status == HuntStatus.PAUSED


class TestSubdomainUpsert:
    def test_insert_new(self, context, sample_hunt):
        context.upsert_subdomain(sample_hunt.id, "api.example.com", "example.com", "subfinder")
        subs = context.get_subdomains(sample_hunt.id)
        assert len(subs) == 1
        assert subs[0]["subdomain"] == "api.example.com"

    def test_source_merging(self, context, sample_hunt):
        context.upsert_subdomain(sample_hunt.id, "api.example.com", "example.com", "subfinder")
        context.upsert_subdomain(sample_hunt.id, "api.example.com", "example.com", "crtsh")
        subs = context.get_subdomains(sample_hunt.id)
        assert len(subs) == 1
        sources = json.loads(subs[0]["sources"])
        assert "subfinder" in sources
        assert "crtsh" in sources

    def test_preserves_first_seen(self, context, sample_hunt):
        context.upsert_subdomain(sample_hunt.id, "api.example.com", "example.com", "subfinder")
        first = context.get_subdomains(sample_hunt.id)[0]["first_seen_at"]
        context.upsert_subdomain(sample_hunt.id, "api.example.com", "example.com", "crtsh")
        second = context.get_subdomains(sample_hunt.id)[0]["first_seen_at"]
        assert first == second


class TestHostUpsert:
    def test_insert_and_query(self, context, sample_hunt):
        context.upsert_host(
            sample_hunt.id,
            {
                "host": "api.example.com",
                "ip": "1.2.3.4",
                "port": 443,
                "scheme": "https",
                "url": "https://api.example.com",
                "status_code": 200,
                "title": "API",
            },
        )
        hosts = context.get_hosts(sample_hunt.id, alive_only=True)
        assert len(hosts) == 1
        assert hosts[0]["title"] == "API"

    def test_updates_on_rescan(self, context, sample_hunt):
        context.upsert_host(
            sample_hunt.id,
            {
                "host": "api.example.com",
                "port": 443,
                "scheme": "https",
                "status_code": 200,
                "title": "Old Title",
            },
        )
        context.upsert_host(
            sample_hunt.id,
            {
                "host": "api.example.com",
                "port": 443,
                "scheme": "https",
                "status_code": 200,
                "title": "New Title",
            },
        )
        hosts = context.get_hosts(sample_hunt.id)
        assert len(hosts) == 1
        assert hosts[0]["title"] == "New Title"


class TestURLUpsert:
    def test_source_merging(self, context, sample_hunt):
        context.upsert_url(
            sample_hunt.id,
            {
                "url": "https://example.com/api",
                "host": "example.com",
                "source": "gau",
            },
        )
        context.upsert_url(
            sample_hunt.id,
            {
                "url": "https://example.com/api",
                "host": "example.com",
                "source": "waybackurls",
            },
        )
        urls = context.get_urls(sample_hunt.id)
        assert len(urls) == 1
        sources = json.loads(urls[0]["sources"])
        assert "gau" in sources and "waybackurls" in sources


class TestParameterUpsert:
    def test_insert_and_query(self, context, sample_hunt):
        context.upsert_parameter(
            sample_hunt.id,
            {
                "url": "https://example.com/search",
                "method": "GET",
                "name": "debug",
                "param_type": "query",
                "confirmed": True,
            },
            source="arjun",
        )
        params = context.get_parameters(sample_hunt.id)
        assert len(params) == 1
        assert params[0]["name"] == "debug"
        assert params[0]["confirmed"] == 1

    def test_source_merging_and_confirmed_promotion(self, context, sample_hunt):
        context.upsert_parameter(
            sample_hunt.id,
            {
                "url": "https://example.com/search",
                "method": "GET",
                "name": "debug",
                "param_type": "query",
                "confirmed": False,
            },
            source="arjun",
        )
        context.upsert_parameter(
            sample_hunt.id,
            {
                "url": "https://example.com/search",
                "method": "GET",
                "name": "debug",
                "param_type": "query",
                "confirmed": True,
            },
            source="manual",
        )
        params = context.get_parameters(sample_hunt.id)
        assert len(params) == 1
        assert params[0]["confirmed"] == 1
        sources = json.loads(params[0]["sources"])
        assert "arjun" in sources
        assert "manual" in sources

    def test_filters(self, context, sample_hunt):
        context.upsert_parameter(
            sample_hunt.id,
            {
                "url": "https://example.com/search",
                "method": "GET",
                "name": "q",
                "param_type": "query",
            },
            source="arjun",
        )
        context.upsert_parameter(
            sample_hunt.id,
            {
                "url": "https://example.com/profile",
                "method": "POST",
                "name": "role",
                "param_type": "body",
            },
            source="arjun",
        )
        params = context.get_parameters(
            sample_hunt.id, url="https://example.com/profile", method="POST"
        )
        assert len(params) == 1
        assert params[0]["name"] == "role"


class TestSecretUpsert:
    def test_insert_and_query(self, context, sample_hunt):
        context.upsert_secret(
            sample_hunt.id,
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
            source="gitleaks",
        )
        secrets = context.get_secrets(sample_hunt.id)
        assert len(secrets) == 1
        assert secrets[0]["rule_id"] == "aws-access-key-id"
        assert secrets[0]["secret_type"] == "key"
        assert secrets[0]["match_preview"] == "AKIA****XMPL"
        assert secrets[0]["line_number"] == 42
        assert secrets[0]["commit_sha"] == "a1b2c3d"

    def test_source_merging(self, context, sample_hunt):
        record = {
            "rule_id": "generic-api-key",
            "secret_type": "key",
            "file_path": "src/config.py",
            "repo": "https://github.com/acme/webapp",
            "line_number": 10,
            "match_preview": "sk_l****cdef",
        }
        context.upsert_secret(sample_hunt.id, record, source="gitleaks")
        context.upsert_secret(sample_hunt.id, record, source="manual")
        secrets = context.get_secrets(sample_hunt.id)
        assert len(secrets) == 1
        sources = json.loads(secrets[0]["sources"])
        assert "gitleaks" in sources
        assert "manual" in sources

    def test_null_line_number_dedupes(self, context, sample_hunt):
        record = {
            "rule_id": "generic-api-key",
            "secret_type": "key",
            "file_path": "src/config.py",
            "repo": "https://github.com/acme/webapp",
            "line_number": None,
            "match_preview": "sk_l****cdef",
        }
        context.upsert_secret(sample_hunt.id, record, source="gitleaks")
        context.upsert_secret(sample_hunt.id, record, source="manual")

        secrets = context.get_secrets(sample_hunt.id)
        assert len(secrets) == 1
        assert secrets[0]["line_number"] is None
        sources = json.loads(secrets[0]["sources"])
        assert "gitleaks" in sources
        assert "manual" in sources

    def test_filters(self, context, sample_hunt):
        context.upsert_secret(
            sample_hunt.id,
            {
                "rule_id": "aws-access-key-id",
                "secret_type": "key",
                "file_path": "config.env",
                "repo": "https://github.com/acme/webapp",
                "line_number": 1,
            },
            source="gitleaks",
        )
        context.upsert_secret(
            sample_hunt.id,
            {
                "rule_id": "github-pat",
                "secret_type": "token",
                "file_path": "ci.sh",
                "repo": "https://github.com/acme/tools",
                "line_number": 5,
            },
            source="gitleaks",
        )
        # Filter by type
        keys = context.get_secrets(sample_hunt.id, secret_type="key")
        assert len(keys) == 1
        assert keys[0]["rule_id"] == "aws-access-key-id"
        # Filter by repo
        tools = context.get_secrets(sample_hunt.id, repo="https://github.com/acme/tools")
        assert len(tools) == 1
        assert tools[0]["rule_id"] == "github-pat"

    def test_stats_include_secrets(self, context, sample_hunt):
        context.upsert_secret(
            sample_hunt.id,
            {
                "rule_id": "aws-access-key-id",
                "secret_type": "key",
                "file_path": "config.env",
                "repo": "https://github.com/acme/webapp",
                "line_number": 1,
            },
            source="gitleaks",
        )
        stats = context.get_hunt_stats(sample_hunt.id)
        assert stats["secrets"] == 1


class TestApiEndpointUpsert:
    def test_insert_and_query(self, context, sample_hunt):
        context.upsert_api_endpoint(
            sample_hunt.id,
            {
                "url": "https://api.example.com/api/v2/users",
                "method": "GET",
                "status_code": 200,
                "content_type": "application/json",
                "content_length": 4521,
                "host": "api.example.com",
                "path": "/api/v2/users",
            },
            source="kiterunner",
        )
        endpoints = context.get_api_endpoints(sample_hunt.id)
        assert len(endpoints) == 1
        assert endpoints[0]["url"] == "https://api.example.com/api/v2/users"
        assert endpoints[0]["method"] == "GET"
        assert endpoints[0]["status_code"] == 200

    def test_source_merging(self, context, sample_hunt):
        record = {
            "url": "https://api.example.com/api/v2/users",
            "method": "GET",
            "status_code": 200,
            "host": "api.example.com",
            "path": "/api/v2/users",
        }
        context.upsert_api_endpoint(sample_hunt.id, record, source="kiterunner")
        context.upsert_api_endpoint(sample_hunt.id, record, source="manual")
        endpoints = context.get_api_endpoints(sample_hunt.id)
        assert len(endpoints) == 1
        sources = json.loads(endpoints[0]["sources"])
        assert "kiterunner" in sources
        assert "manual" in sources

    def test_filters(self, context, sample_hunt):
        context.upsert_api_endpoint(
            sample_hunt.id,
            {
                "url": "https://api.example.com/api/v2/users",
                "method": "GET",
                "host": "api.example.com",
                "path": "/api/v2/users",
            },
            source="kiterunner",
        )
        context.upsert_api_endpoint(
            sample_hunt.id,
            {
                "url": "https://api.example.com/api/v2/transfer",
                "method": "POST",
                "host": "api.example.com",
                "path": "/api/v2/transfer",
            },
            source="kiterunner",
        )
        context.upsert_api_endpoint(
            sample_hunt.id,
            {
                "url": "https://other.example.com/api/v1/data",
                "method": "GET",
                "host": "other.example.com",
                "path": "/api/v1/data",
            },
            source="kiterunner",
        )
        # Filter by host
        api_eps = context.get_api_endpoints(sample_hunt.id, host="api.example.com")
        assert len(api_eps) == 2
        # Filter by method
        post_eps = context.get_api_endpoints(sample_hunt.id, method="POST")
        assert len(post_eps) == 1
        assert post_eps[0]["path"] == "/api/v2/transfer"

    def test_coalesce_on_re_upsert(self, context, sample_hunt):
        context.upsert_api_endpoint(
            sample_hunt.id,
            {
                "url": "https://api.example.com/api/v2/users",
                "method": "GET",
                "status_code": 200,
                "content_type": "application/json",
                "host": "api.example.com",
                "path": "/api/v2/users",
                "framework": "express",
            },
            source="kiterunner",
        )
        # Re-upsert with empty content_type and framework — should preserve
        context.upsert_api_endpoint(
            sample_hunt.id,
            {
                "url": "https://api.example.com/api/v2/users",
                "method": "GET",
                "status_code": 201,
                "content_type": "",
                "host": "api.example.com",
                "path": "/api/v2/users",
                "framework": "",
            },
            source="manual",
        )
        endpoints = context.get_api_endpoints(sample_hunt.id)
        assert len(endpoints) == 1
        assert endpoints[0]["status_code"] == 201  # updated
        assert endpoints[0]["content_type"] == "application/json"  # preserved
        assert endpoints[0]["framework"] == "express"  # preserved

    def test_stats_include_api_endpoints(self, context, sample_hunt):
        context.upsert_api_endpoint(
            sample_hunt.id,
            {
                "url": "https://api.example.com/api/v2/users",
                "method": "GET",
                "host": "api.example.com",
                "path": "/api/v2/users",
            },
            source="kiterunner",
        )
        stats = context.get_hunt_stats(sample_hunt.id)
        assert stats["api_endpoints"] == 1


class TestToolRunLogging:
    def test_log_and_query(self, context, sample_hunt):
        result = ToolResult(
            tool_name="subfinder",
            command=["subfinder", "-d", "example.com"],
            exit_code=0,
            raw_stdout="",
            raw_stderr="",
            duration_seconds=2.5,
            records=[{"subdomain": "api.example.com"}],
        )
        context.log_tool_run(sample_hunt.id, result)
        runs = context.get_tool_runs(sample_hunt.id)
        assert len(runs) == 1
        assert runs[0]["tool_name"] == "subfinder"
        assert runs[0]["records_found"] == 1


class TestBatchUpsert:
    def test_batch_subdomains(self, context, sample_hunt):
        records = [
            {"subdomain": "a.example.com", "root_domain": "example.com", "source": "subfinder"},
            {"subdomain": "b.example.com", "root_domain": "example.com", "source": "subfinder"},
            {"subdomain": "c.example.com", "root_domain": "example.com", "source": "subfinder"},
        ]
        context.upsert_records(sample_hunt.id, "subdomain", records, source="subfinder")
        subs = context.get_subdomains(sample_hunt.id)
        assert len(subs) == 3
