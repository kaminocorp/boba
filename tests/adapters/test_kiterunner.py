"""Tests for Kiterunner adapter build_command and parse_output behavior."""

from __future__ import annotations

from pathlib import Path

import pytest

from boba.adapters.kiterunner import KiterunnerAdapter
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


class TestKiterunnerAdapter:
    def test_build_command_basic(self, scope, config):
        adapter = KiterunnerAdapter(scope_engine=scope)
        adapter._binary_path = Path("/usr/local/bin/kr")

        cmd, output_file = adapter.build_command(["https://app.example.com"], config)

        assert cmd[0] == "/usr/local/bin/kr"
        assert "scan" in cmd
        assert "https://app.example.com" in cmd
        assert "--fail-status-codes" in cmd
        assert "404,400" in cmd
        assert output_file is None

    def test_build_command_with_wordlist(self, scope, config):
        adapter = KiterunnerAdapter(scope_engine=scope)
        adapter._binary_path = Path("/usr/local/bin/kr")
        config.extra_args_dict["wordlist"] = "/path/to/routes-large.kite"

        cmd, _ = adapter.build_command(["https://app.example.com"], config)

        assert "-w" in cmd
        assert "/path/to/routes-large.kite" in cmd

    def test_build_command_with_rate_limit(self, scope, config):
        adapter = KiterunnerAdapter(scope_engine=scope)
        adapter._binary_path = Path("/usr/local/bin/kr")
        config.rate_limit = 20

        cmd, _ = adapter.build_command(["https://app.example.com"], config)

        assert "-x" in cmd
        assert "20" in cmd

    def test_build_command_multiple_targets(self, scope, config):
        adapter = KiterunnerAdapter(scope_engine=scope)
        adapter._binary_path = Path("/usr/local/bin/kr")

        cmd, _ = adapter.build_command(
            ["https://app.example.com", "https://api.example.com"], config
        )

        assert "https://app.example.com" in cmd
        assert "https://api.example.com" in cmd

    def test_build_command_empty_targets_raises(self, scope, config):
        adapter = KiterunnerAdapter(scope_engine=scope)
        adapter._binary_path = Path("/usr/local/bin/kr")

        with pytest.raises(ValueError, match="at least one target"):
            adapter.build_command([], config)

    def test_parse_record_plain_line(self, scope):
        adapter = KiterunnerAdapter(scope_engine=scope)

        line = "GET     200 [   4521,   45,   12] https://app.example.com/api/v2/users 0cc72af3"
        record = adapter.parse_record(line)

        assert record["method"] == "GET"
        assert record["status_code"] == 200
        assert record["content_length"] == 4521
        assert record["url"] == "https://app.example.com/api/v2/users"
        assert record["host"] == "app.example.com"
        assert record["path"] == "/api/v2/users"

    def test_parse_record_post_method(self, scope):
        adapter = KiterunnerAdapter(scope_engine=scope)

        line = "POST    201 [    128,    5,    3] https://app.example.com/api/v2/transfer abc123"
        record = adapter.parse_record(line)

        assert record["method"] == "POST"
        assert record["status_code"] == 201
        assert record["content_length"] == 128
        assert record["url"] == "https://app.example.com/api/v2/transfer"

    def test_parse_record_delete_method(self, scope):
        adapter = KiterunnerAdapter(scope_engine=scope)

        line = "DELETE  204 [      0,    0,    0] https://app.example.com/api/v1/sessions def456"
        record = adapter.parse_record(line)

        assert record["method"] == "DELETE"
        assert record["status_code"] == 204
        assert record["content_length"] == 0

    def test_parse_record_json_input(self, scope):
        adapter = KiterunnerAdapter(scope_engine=scope)

        raw = {
            "url": "https://app.example.com/api/v2/users",
            "method": "GET",
            "status_code": 200,
            "content_type": "application/json",
            "content_length": 4521,
        }
        record = adapter.parse_record(raw)

        assert record["url"] == "https://app.example.com/api/v2/users"
        assert record["method"] == "GET"
        assert record["status_code"] == 200
        assert record["content_type"] == "application/json"
        assert record["content_length"] == 4521
        assert record["host"] == "app.example.com"
        assert record["path"] == "/api/v2/users"

    def test_parse_record_fallback_line(self, scope):
        adapter = KiterunnerAdapter(scope_engine=scope)

        line = "PUT https://app.example.com/api/v2/profile"
        record = adapter.parse_record(line)

        assert record["method"] == "PUT"
        assert record["url"] == "https://app.example.com/api/v2/profile"
        assert record["host"] == "app.example.com"

    def test_parse_output_multiple_lines(self, scope):
        adapter = KiterunnerAdapter(scope_engine=scope)

        stdout = (
            "GET     200 [   4521,   45,   12] https://app.example.com/api/v2/users 0cc72\n"
            "POST    201 [    128,    5,    3] https://app.example.com/api/v2/users abc12\n"
            "DELETE  204 [      0,    0,    0] https://app.example.com/api/v1/sessions def45\n"
        )
        records, parse_errors = adapter.parse_output(stdout)

        assert parse_errors == 0
        assert len(records) == 3
        methods = {r["method"] for r in records}
        assert methods == {"GET", "POST", "DELETE"}

    def test_parse_output_empty(self, scope):
        adapter = KiterunnerAdapter(scope_engine=scope)

        records, parse_errors = adapter.parse_output("")

        assert records == []
        assert parse_errors == 0

    def test_extract_scope_target_with_host(self, scope):
        adapter = KiterunnerAdapter(scope_engine=scope)
        record = {
            "host": "app.example.com",
            "url": "https://app.example.com/api/v2/users",
        }
        assert adapter.extract_scope_target(record) == "app.example.com"

    def test_extract_scope_target_empty_host(self, scope):
        adapter = KiterunnerAdapter(scope_engine=scope)
        record = {
            "host": "",
            "url": "https://app.example.com/api/v2/users",
        }
        assert adapter.extract_scope_target(record) == "https://app.example.com/api/v2/users"
