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
        context.upsert_host(sample_hunt.id, {
            "host": "api.example.com", "ip": "1.2.3.4", "port": 443, "scheme": "https",
            "url": "https://api.example.com", "status_code": 200, "title": "API",
        })
        hosts = context.get_hosts(sample_hunt.id, alive_only=True)
        assert len(hosts) == 1
        assert hosts[0]["title"] == "API"

    def test_updates_on_rescan(self, context, sample_hunt):
        context.upsert_host(sample_hunt.id, {
            "host": "api.example.com", "port": 443, "scheme": "https",
            "status_code": 200, "title": "Old Title",
        })
        context.upsert_host(sample_hunt.id, {
            "host": "api.example.com", "port": 443, "scheme": "https",
            "status_code": 200, "title": "New Title",
        })
        hosts = context.get_hosts(sample_hunt.id)
        assert len(hosts) == 1
        assert hosts[0]["title"] == "New Title"


class TestURLUpsert:
    def test_source_merging(self, context, sample_hunt):
        context.upsert_url(sample_hunt.id, {
            "url": "https://example.com/api", "host": "example.com", "source": "gau",
        })
        context.upsert_url(sample_hunt.id, {
            "url": "https://example.com/api", "host": "example.com", "source": "waybackurls",
        })
        urls = context.get_urls(sample_hunt.id)
        assert len(urls) == 1
        sources = json.loads(urls[0]["sources"])
        assert "gau" in sources and "waybackurls" in sources


class TestToolRunLogging:
    def test_log_and_query(self, context, sample_hunt):
        result = ToolResult(
            tool_name="subfinder", command=["subfinder", "-d", "example.com"],
            exit_code=0, raw_stdout="", raw_stderr="",
            duration_seconds=2.5, records=[{"subdomain": "api.example.com"}],
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
