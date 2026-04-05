"""Tests for Arjun adapter build_command and parse_output behavior."""

from __future__ import annotations

from pathlib import Path

import pytest

from boba.adapters.arjun import ArjunAdapter
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


class TestArjunAdapter:
    def test_build_command_get(self, scope, config):
        adapter = ArjunAdapter(scope_engine=scope)
        adapter._binary_path = Path("/usr/bin/arjun")

        cmd, output_file = adapter.build_command(["https://app.example.com/search"], config)

        assert cmd[0] == "/usr/bin/arjun"
        assert "-u" in cmd
        assert "https://app.example.com/search" in cmd
        assert "-m" in cmd
        assert "GET" in cmd
        assert "-oJ" in cmd
        assert "--stable" in cmd
        assert output_file.exists()
        output_file.unlink(missing_ok=True)

    def test_build_command_post_json(self, scope, config):
        adapter = ArjunAdapter(scope_engine=scope)
        adapter._binary_path = Path("/usr/bin/arjun")
        config.extra_args_dict["method"] = "POST"
        config.extra_args_dict["body_type"] = "json"
        config.rate_limit = 8

        cmd, output_file = adapter.build_command(["https://app.example.com/profile"], config)

        assert "-m" in cmd
        assert "JSON" in cmd
        assert "-t" in cmd
        assert "8" in cmd
        output_file.unlink(missing_ok=True)

    def test_parse_output_single_object(self, scope):
        adapter = ArjunAdapter(scope_engine=scope)
        adapter._target_url = "https://app.example.com/search"
        adapter._http_method = "GET"
        adapter._param_type = "query"

        records, parse_errors = adapter.parse_output(
            "",
            output_file=None,
        )

        assert records == []
        assert parse_errors == 0

    def test_parse_output_url_and_params(self, scope, tmp_path):
        adapter = ArjunAdapter(scope_engine=scope)
        adapter._target_url = "https://app.example.com/search"
        adapter._http_method = "GET"
        adapter._param_type = "query"
        output_file = tmp_path / "arjun.json"
        output_file.write_text('{"url":"https://app.example.com/search","params":["id","debug"]}')

        records, parse_errors = adapter.parse_output("", output_file=output_file)

        assert parse_errors == 0
        assert len(records) == 2
        assert records[0]["url"] == "https://app.example.com/search"
        assert records[0]["method"] == "GET"
        assert records[0]["param_type"] == "query"
        assert {r["name"] for r in records} == {"id", "debug"}

    def test_parse_output_multi_target_mapping_shape(self, scope, tmp_path):
        adapter = ArjunAdapter(scope_engine=scope)
        adapter._http_method = "POST"
        adapter._param_type = "body"
        output_file = tmp_path / "arjun_multi.json"
        output_file.write_text(
            '{"https://app.example.com/search":["q","page"],"https://app.example.com/profile":["role"]}'
        )

        records, parse_errors = adapter.parse_output("", output_file=output_file)

        assert parse_errors == 0
        assert len(records) == 3
        assert all(r["method"] == "POST" for r in records)
        assert all(r["param_type"] == "body" for r in records)

    def test_parse_output_param_objects(self, scope, tmp_path):
        adapter = ArjunAdapter(scope_engine=scope)
        adapter._target_url = "https://app.example.com/profile"
        adapter._http_method = "POST"
        adapter._param_type = "body"
        output_file = tmp_path / "arjun_objects.json"
        output_file.write_text(
            '{"url":"https://app.example.com/profile","params":[{"name":"role","confirmed":true},{"name":"csrf","param_type":"header","confirmed":false}]}'
        )

        records, parse_errors = adapter.parse_output("", output_file=output_file)

        assert parse_errors == 0
        assert len(records) == 2
        role = next(r for r in records if r["name"] == "role")
        csrf = next(r for r in records if r["name"] == "csrf")
        assert role["confirmed"] is True
        assert csrf["param_type"] == "header"
        assert csrf["confirmed"] is False

    def test_extract_scope_target(self, scope):
        adapter = ArjunAdapter(scope_engine=scope)
        record = {"url": "https://app.example.com/search", "name": "debug"}
        assert adapter.extract_scope_target(record) == "https://app.example.com/search"
