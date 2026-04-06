"""Tests for gitleaks adapter build_command and parse_output behavior."""

from __future__ import annotations

from pathlib import Path

import pytest

from boba.adapters.gitleaks import GitleaksAdapter, _redact, _classify_secret_type
from boba.core.models import AdapterConfig, ScopeAction, ScopeConfig, ScopeRule, ScopeRuleType
from boba.core.scope import ScopeEngine


@pytest.fixture
def scope():
    return ScopeEngine(
        ScopeConfig(
            rules=[
                ScopeRule("*.example.com", ScopeRuleType.DOMAIN, ScopeAction.INCLUDE),
                ScopeRule("github.com", ScopeRuleType.DOMAIN, ScopeAction.INCLUDE),
            ]
        )
    )


@pytest.fixture
def config():
    return AdapterConfig()


class TestGitleaksAdapter:
    def test_build_command_basic(self, scope, config):
        adapter = GitleaksAdapter(scope_engine=scope)
        adapter._binary_path = Path("/usr/bin/gitleaks")

        cmd, output_file = adapter.build_command(["https://github.com/acme-corp/webapp"], config)

        assert cmd[0] == "/usr/bin/gitleaks"
        assert "detect" in cmd
        assert "--source" in cmd
        assert "https://github.com/acme-corp/webapp" in cmd
        assert "--report-format" in cmd
        assert "json" in cmd
        assert "--report-path" in cmd
        assert "--no-banner" in cmd
        assert output_file.exists()
        output_file.unlink(missing_ok=True)

    def test_build_command_no_git_flag(self, scope, config):
        adapter = GitleaksAdapter(scope_engine=scope)
        adapter._binary_path = Path("/usr/bin/gitleaks")
        config.extra_args_dict["no_git"] = True

        cmd, output_file = adapter.build_command(["/tmp/repo"], config)

        assert "--no-git" in cmd
        output_file.unlink(missing_ok=True)

    def test_build_command_empty_targets_raises(self, scope, config):
        adapter = GitleaksAdapter(scope_engine=scope)
        adapter._binary_path = Path("/usr/bin/gitleaks")

        with pytest.raises(ValueError, match="at least one target"):
            adapter.build_command([], config)

    def test_parse_record_full_gitleaks_output(self, scope):
        adapter = GitleaksAdapter(scope_engine=scope)
        adapter._repo = "https://github.com/acme-corp/webapp"

        raw = {
            "RuleID": "aws-access-key-id",
            "Secret": "AKIAIOSFODNN7EXAMPLE",
            "File": "config/deploy.env",
            "StartLine": 42,
            "Commit": "a1b2c3d4e5f6",
            "Author": "dev@acme.com",
            "Date": "2025-11-03",
            "Entropy": 4.2,
        }
        record = adapter.parse_record(raw)

        assert record["rule_id"] == "aws-access-key-id"
        assert record["secret_type"] == "key"
        assert record["file_path"] == "config/deploy.env"
        assert record["repo"] == "https://github.com/acme-corp/webapp"
        assert record["line_number"] == 42
        assert record["commit"] == "a1b2c3d4e5f6"
        assert record["author"] == "dev@acme.com"
        assert record["entropy"] == 4.2
        # Secret should be redacted
        assert "AKIAIOSFODNN7EXAMPLE" not in record["match_preview"]
        assert record["match_preview"].startswith("AKIA")
        assert record["match_preview"].endswith("MPLE")
        assert "****" in record["match_preview"]

    def test_parse_record_minimal(self, scope):
        adapter = GitleaksAdapter(scope_engine=scope)
        adapter._repo = "https://github.com/acme-corp/webapp"

        raw = {
            "RuleID": "generic-api-key",
            "Secret": "sk_live_1234567890abcdef",
            "File": "src/config.py",
        }
        record = adapter.parse_record(raw)

        assert record["rule_id"] == "generic-api-key"
        assert record["secret_type"] == "key"
        assert record["file_path"] == "src/config.py"
        assert record["line_number"] is None
        assert record["commit"] == ""
        assert record["entropy"] is None

    def test_parse_record_string_input(self, scope):
        adapter = GitleaksAdapter(scope_engine=scope)
        adapter._repo = "/tmp/repo"

        record = adapter.parse_record("some_secret_value_here")

        assert record["rule_id"] == "unknown"
        assert record["secret_type"] == "other"
        assert "****" in record["match_preview"]

    def test_parse_output_json_array(self, scope, tmp_path):
        adapter = GitleaksAdapter(scope_engine=scope)
        adapter._repo = "https://github.com/acme-corp/webapp"
        output_file = tmp_path / "gitleaks.json"
        output_file.write_text(
            '[{"RuleID":"aws-access-key-id","Secret":"AKIAIOSFODNN7EXAMPLE","File":"config.env","StartLine":10},'
            '{"RuleID":"github-pat","Secret":"ghp_abcdefghijklmnopqrstuvwxyz1234567890","File":"scripts/ci.sh","StartLine":5}]'
        )

        records, parse_errors = adapter.parse_output("", output_file=output_file)

        assert parse_errors == 0
        assert len(records) == 2
        assert records[0]["rule_id"] == "aws-access-key-id"
        assert records[0]["secret_type"] == "key"
        assert records[1]["rule_id"] == "github-pat"
        assert records[1]["secret_type"] == "token"

    def test_parse_output_empty(self, scope):
        adapter = GitleaksAdapter(scope_engine=scope)
        adapter._repo = "/tmp/repo"

        records, parse_errors = adapter.parse_output("[]")

        assert records == []
        assert parse_errors == 0

    def test_parse_output_empty_string(self, scope):
        adapter = GitleaksAdapter(scope_engine=scope)
        adapter._repo = "/tmp/repo"

        records, parse_errors = adapter.parse_output("")

        assert records == []
        assert parse_errors == 1

    def test_extract_scope_target_github_url(self, scope):
        adapter = GitleaksAdapter(scope_engine=scope)
        record = {
            "repo": "https://github.com/acme-corp/webapp",
            "file_path": "config.env",
        }
        assert adapter.extract_scope_target(record) == "https://github.com/acme-corp/webapp"

    def test_extract_scope_target_local_path(self, scope):
        adapter = GitleaksAdapter(scope_engine=scope)
        record = {"repo": "/home/user/repos/webapp", "file_path": "config.env"}
        assert adapter.extract_scope_target(record) == "/home/user/repos/webapp"

    def test_extract_scope_target_empty_repo(self, scope):
        adapter = GitleaksAdapter(scope_engine=scope)
        record = {"repo": "", "file_path": "config.env"}
        assert adapter.extract_scope_target(record) is None

    def test_explicit_targets_are_not_scope_filtered(self, scope):
        adapter = GitleaksAdapter(scope_engine=scope)
        targets = ["https://github.com/acme-corp/webapp", "/tmp/webapp"]

        assert adapter.pre_filter_targets(targets) == targets


class TestRedact:
    def test_redact_long_string(self):
        assert _redact("AKIAIOSFODNN7EXAMPLE") == "AKIA****MPLE"

    def test_redact_short_string(self):
        assert _redact("abc") == "****"

    def test_redact_exactly_8_chars(self):
        assert _redact("12345678") == "****"

    def test_redact_9_chars(self):
        assert _redact("123456789") == "1234****6789"


class TestClassifySecretType:
    def test_known_rules(self):
        assert _classify_secret_type("aws-access-key-id") == "key"
        assert _classify_secret_type("github-pat") == "token"
        assert _classify_secret_type("password-in-url") == "password"
        assert _classify_secret_type("private-key") == "certificate"

    def test_inferred_from_name(self):
        assert _classify_secret_type("custom-api-key") == "key"
        assert _classify_secret_type("custom-access-token") == "token"
        assert _classify_secret_type("database-password") == "password"
        assert _classify_secret_type("tls-cert-private") == "certificate"

    def test_unknown_falls_to_other(self):
        assert _classify_secret_type("completely-unknown-rule") == "other"
