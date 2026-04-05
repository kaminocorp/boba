"""Tests for individual adapter build_command and parse_record methods.

Each adapter is tested in isolation — no subprocess calls, no binary lookups.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from boba.adapters.ffuf import FfufAdapter
from boba.adapters.gau import GauAdapter
from boba.adapters.httpx_runner import HttpxRunnerAdapter
from boba.adapters.katana import KatanaAdapter
from boba.adapters.naabu import NaabuAdapter
from boba.adapters.nuclei import NucleiAdapter
from boba.adapters.subfinder import SubfinderAdapter
from boba.adapters.waybackurls import WaybackurlsAdapter
from boba.adapters.whatweb import WhatwebAdapter
from boba.core.models import AdapterConfig, ScopeAction, ScopeConfig, ScopeRule, ScopeRuleType
from boba.core.scope import ScopeEngine


@pytest.fixture
def scope():
    return ScopeEngine(
        ScopeConfig(
            rules=[
                ScopeRule("*.example.com", ScopeRuleType.DOMAIN, ScopeAction.INCLUDE),
            ]
        )
    )


@pytest.fixture
def config():
    return AdapterConfig()


# ── SubfinderAdapter ────────────────────────────────────────────────


class TestSubfinderAdapter:
    def test_build_command_single_target(self, scope, config):
        adapter = SubfinderAdapter(scope_engine=scope)
        adapter._binary_path = Path("/usr/bin/subfinder")
        cmd, output_file = adapter.build_command(["example.com"], config)
        assert output_file is None
        assert "-d" in cmd
        assert "example.com" in cmd
        assert "-dL" not in cmd

    def test_build_command_multiple_targets(self, scope, config):
        adapter = SubfinderAdapter(scope_engine=scope)
        adapter._binary_path = Path("/usr/bin/subfinder")
        cmd, output_file = adapter.build_command(["a.example.com", "b.example.com"], config)
        assert output_file is None
        assert "-dL" in cmd
        assert "-d" not in cmd
        # The temp file should have been created
        assert len(adapter._temp_files) == 1
        assert adapter._temp_files[0].exists()
        adapter._cleanup_temp_files()

    def test_parse_record(self, scope):
        adapter = SubfinderAdapter(scope_engine=scope)
        result = adapter.parse_record(
            {
                "host": "sub.example.com",
                "input": "example.com",
                "source": "crtsh",
            }
        )
        assert result["subdomain"] == "sub.example.com"
        assert result["root_domain"] == "example.com"
        assert result["source"] == "crtsh"

    def test_parse_record_defaults(self, scope):
        adapter = SubfinderAdapter(scope_engine=scope)
        result = adapter.parse_record({})
        assert result["subdomain"] == ""
        assert result["source"] == "unknown"


# ── HttpxRunnerAdapter ──────────────────────────────────────────────


class TestHttpxRunnerAdapter:
    def test_parse_record_full(self, scope):
        adapter = HttpxRunnerAdapter(scope_engine=scope)
        raw = {
            "input": "example.com",
            "a": ["93.184.216.34"],
            "port": "443",
            "scheme": "https",
            "url": "https://example.com",
            "status_code": 200,
            "title": "Example Domain",
            "webserver": "ECS (dcb/7F3B)",
            "content_length": 1256,
            "content_type": "text/html",
            "tech": ["Nginx"],
            "tls": {"version": "TLSv1.3"},
            "final_url": "https://example.com/",
        }
        result = adapter.parse_record(raw)
        assert result["host"] == "example.com"
        assert result["ip"] == "93.184.216.34"
        assert result["port"] == 443
        assert result["scheme"] == "https"
        assert result["status_code"] == 200
        assert result["title"] == "Example Domain"
        assert result["technologies"] == ["Nginx"]
        assert result["tls_version"] == "TLSv1.3"

    def test_parse_record_minimal(self, scope):
        adapter = HttpxRunnerAdapter(scope_engine=scope)
        result = adapter.parse_record({})
        assert result["host"] == ""
        assert result["ip"] == ""
        assert result["port"] == 0
        assert result["status_code"] is None
        assert result["technologies"] == []
        assert result["tls_version"] == ""


# ── NaabuAdapter ────────────────────────────────────────────────────


class TestNaabuAdapter:
    def test_parse_record(self, scope):
        adapter = NaabuAdapter(scope_engine=scope)
        result = adapter.parse_record({"host": "example.com", "port": 443, "ip": "93.184.216.34"})
        assert result["host"] == "example.com"
        assert result["port"] == 443
        assert result["ip"] == "93.184.216.34"
        assert result["protocol"] == "tcp"

    def test_parse_record_with_protocol(self, scope):
        adapter = NaabuAdapter(scope_engine=scope)
        result = adapter.parse_record(
            {
                "host": "example.com",
                "port": 53,
                "ip": "93.184.216.34",
                "protocol": "udp",
            }
        )
        assert result["protocol"] == "udp"

    def test_parse_record_defaults(self, scope):
        adapter = NaabuAdapter(scope_engine=scope)
        result = adapter.parse_record({})
        assert result["host"] == ""
        assert result["port"] == 0
        assert result["protocol"] == "tcp"


# ── GauAdapter ──────────────────────────────────────────────────────


class TestGauAdapter:
    def test_parse_record_url(self, scope):
        adapter = GauAdapter(scope_engine=scope)
        result = adapter.parse_record("https://api.example.com/v1/users?page=1")
        assert result["url"] == "https://api.example.com/v1/users?page=1"
        assert result["host"] == "api.example.com"
        assert result["path"] == "/v1/users"
        assert result["query"] == "page=1"
        assert result["source"] == "gau"

    def test_parse_record_simple_url(self, scope):
        adapter = GauAdapter(scope_engine=scope)
        result = adapter.parse_record("http://example.com")
        assert result["host"] == "example.com"
        assert result["path"] == ""
        assert result["query"] == ""


# ── WhatwebAdapter ──────────────────────────────────────────────────


class TestWhatwebAdapter:
    def test_parse_record_with_plugins(self, scope):
        adapter = WhatwebAdapter(scope_engine=scope)
        raw = {
            "target": "https://example.com",
            "http_status": 200,
            "plugins": {
                "Apache": {"version": ["2.4.41"], "string": ["Apache/2.4.41"]},
                "jQuery": {"version": ["3.6.0"]},
            },
        }
        result = adapter.parse_record(raw)
        assert result["url"] == "https://example.com"
        assert result["host"] == "example.com"
        assert result["status_code"] == 200
        assert len(result["technologies"]) == 2
        tech_names = {t["name"] for t in result["technologies"]}
        assert "Apache" in tech_names
        assert "jQuery" in tech_names
        apache = next(t for t in result["technologies"] if t["name"] == "Apache")
        assert apache["version"] == "2.4.41"
        assert apache["detail"] == "Apache/2.4.41"

    def test_parse_record_non_dict_plugins(self, scope):
        """Guard: plugins might not be a dict in malformed output."""
        adapter = WhatwebAdapter(scope_engine=scope)
        raw = {
            "target": "https://example.com",
            "http_status": 200,
            "plugins": "not a dict",
        }
        result = adapter.parse_record(raw)
        assert result["technologies"] == []

    def test_parse_record_no_plugins(self, scope):
        adapter = WhatwebAdapter(scope_engine=scope)
        raw = {"target": "https://example.com", "http_status": 200}
        result = adapter.parse_record(raw)
        assert result["technologies"] == []


# ── FfufAdapter ─────────────────────────────────────────────────────


class TestFfufAdapter:
    def test_parse_record(self, scope):
        adapter = FfufAdapter(scope_engine=scope)
        raw = {
            "url": "https://example.com/admin",
            "input": {"FUZZ": "admin"},
            "status": 200,
            "length": 4523,
            "words": 321,
            "lines": 45,
            "content-type": "text/html",
            "redirectlocation": "",
        }
        result = adapter.parse_record(raw)
        assert result["url"] == "https://example.com/admin"
        assert result["input_value"] == "admin"
        assert result["status_code"] == 200
        assert result["content_length"] == 4523
        assert result["word_count"] == 321
        assert result["line_count"] == 45
        assert result["content_type"] == "text/html"

    def test_parse_record_defaults(self, scope):
        adapter = FfufAdapter(scope_engine=scope)
        result = adapter.parse_record({})
        assert result["url"] == ""
        assert result["input_value"] == ""
        assert result["status_code"] == 0
        assert result["content_length"] == 0


# ── KatanaAdapter ───────────────────────────────────────────────────


class TestKatanaAdapter:
    def test_parse_record_with_endpoint(self, scope):
        adapter = KatanaAdapter(scope_engine=scope)
        raw = {
            "endpoint": "https://api.example.com/v2/login",
            "source": "https://example.com",
            "request": {"method": "POST", "endpoint": "https://api.example.com/v2/login"},
            "response": {"status_code": 200},
        }
        result = adapter.parse_record(raw)
        assert result["url"] == "https://api.example.com/v2/login"
        assert result["host"] == "api.example.com"
        assert result["path"] == "/v2/login"
        assert result["method"] == "POST"
        assert result["status_code"] == 200
        assert result["found_on"] == "https://example.com"
        assert result["source"] == "katana"

    def test_parse_record_fallback_to_request_endpoint(self, scope):
        """When top-level endpoint is missing, falls back to request.endpoint."""
        adapter = KatanaAdapter(scope_engine=scope)
        raw = {
            "request": {"endpoint": "https://example.com/fallback", "method": "GET"},
        }
        result = adapter.parse_record(raw)
        assert result["url"] == "https://example.com/fallback"
        assert result["method"] == "GET"

    def test_parse_record_defaults(self, scope):
        adapter = KatanaAdapter(scope_engine=scope)
        result = adapter.parse_record({})
        assert result["url"] == ""
        assert result["method"] == "GET"
        assert result["status_code"] is None


# ── NucleiAdapter ───────────────────────────────────────────────────


class TestNucleiAdapter:
    def test_parse_record_full_finding(self, scope):
        adapter = NucleiAdapter(scope_engine=scope)
        raw = {
            "template-id": "cve-2021-44228",
            "info": {
                "name": "Log4Shell RCE",
                "severity": "critical",
                "description": "Apache Log4j2 RCE",
                "reference": ["https://cve.mitre.org/cve-2021-44228"],
                "tags": ["cve", "rce", "log4j"],
            },
            "type": "http",
            "host": "https://app.example.com",
            "matched-at": "https://app.example.com/api/login",
            "extracted-results": ["${jndi:ldap://...}"],
            "curl-command": "curl -X POST ...",
            "matcher-name": "log4j-rce",
        }
        result = adapter.parse_record(raw)
        assert result["template_id"] == "cve-2021-44228"
        assert result["template_name"] == "Log4Shell RCE"
        assert result["severity"] == "critical"
        assert result["finding_type"] == "http"
        assert result["url"] == "https://app.example.com/api/login"
        assert result["host"] == "https://app.example.com"
        assert result["extracted_results"] == ["${jndi:ldap://...}"]
        assert result["tags"] == ["cve", "rce", "log4j"]
        assert result["matcher_name"] == "log4j-rce"

    def test_parse_record_minimal(self, scope):
        adapter = NucleiAdapter(scope_engine=scope)
        result = adapter.parse_record({})
        assert result["template_id"] == ""
        assert result["severity"] == "info"
        assert result["url"] == ""
        assert result["extracted_results"] == []
        assert result["tags"] == []

    def test_parse_record_string_fallback(self, scope):
        """Nuclei adapter handles raw string input."""
        adapter = NucleiAdapter(scope_engine=scope)
        result = adapter.parse_record("https://example.com/vulnerable")
        assert result["url"] == "https://example.com/vulnerable"

    def test_build_command_single_target(self, scope, config):
        adapter = NucleiAdapter(scope_engine=scope)
        adapter._binary_path = Path("/usr/bin/nuclei")
        cmd, output_file = adapter.build_command(["https://example.com"], config)
        assert output_file is None
        assert "-u" in cmd
        assert "https://example.com" in cmd

    def test_build_command_multiple_targets(self, scope, config):
        adapter = NucleiAdapter(scope_engine=scope)
        adapter._binary_path = Path("/usr/bin/nuclei")
        cmd, output_file = adapter.build_command(
            ["https://a.example.com", "https://b.example.com"], config
        )
        assert "-l" in cmd
        assert len(adapter._temp_files) == 1
        adapter._cleanup_temp_files()


# ── WaybackurlsAdapter ────────────────────────────────────────────────


class TestWaybackurlsAdapter:
    def test_build_command_returns_binary_and_extra_args(self, scope, config):
        adapter = WaybackurlsAdapter(scope_engine=scope)
        adapter._binary_path = Path("/usr/bin/waybackurls")
        config.extra_args = ["--no-subs"]
        cmd, output_file = adapter.build_command(["example.com"], config)
        assert output_file is None
        assert cmd[0] == "/usr/bin/waybackurls"
        assert "--no-subs" in cmd
        # Targets should NOT appear in the command (they go via stdin)
        assert "example.com" not in cmd

    def test_build_command_stores_stdin_targets(self, scope, config):
        adapter = WaybackurlsAdapter(scope_engine=scope)
        adapter._binary_path = Path("/usr/bin/waybackurls")
        adapter.build_command(["example.com", "sub.example.com"], config)
        assert adapter._stdin_targets == ["example.com", "sub.example.com"]

    def test_parse_record_simple_url(self, scope):
        adapter = WaybackurlsAdapter(scope_engine=scope)
        result = adapter.parse_record("https://example.com/about")
        assert result["url"] == "https://example.com/about"
        assert result["host"] == "example.com"
        assert result["path"] == "/about"
        assert result["query"] == ""
        assert result["source"] == "waybackurls"

    def test_parse_record_url_with_query(self, scope):
        adapter = WaybackurlsAdapter(scope_engine=scope)
        result = adapter.parse_record("https://api.example.com/search?q=test&page=2")
        assert result["url"] == "https://api.example.com/search?q=test&page=2"
        assert result["host"] == "api.example.com"
        assert result["path"] == "/search"
        assert result["query"] == "q=test&page=2"
        assert result["source"] == "waybackurls"

    def test_extract_scope_target(self, scope):
        adapter = WaybackurlsAdapter(scope_engine=scope)
        record = {"url": "https://example.com/path", "host": "example.com"}
        assert adapter.extract_scope_target(record) == "https://example.com/path"
