"""Tests for Nuclei adapter."""

from __future__ import annotations

import json

import pytest

from boba.adapters.nuclei import NucleiAdapter
from boba.core.models import AdapterConfig


SAMPLE_NUCLEI_OUTPUT = json.dumps({
    "template-id": "exposed-env-file",
    "info": {
        "name": "Exposed .env File",
        "severity": "medium",
        "description": "Environment file is publicly accessible",
        "reference": ["https://example.com/ref"],
        "tags": ["exposure", "config"],
    },
    "type": "http",
    "host": "https://app.example.com",
    "matched-at": "https://app.example.com/.env",
    "extracted-results": ["DB_PASSWORD=secret"],
    "curl-command": "curl -X GET https://app.example.com/.env",
    "matcher-name": "env-keywords",
})

SAMPLE_NUCLEI_LINE_2 = json.dumps({
    "template-id": "git-config",
    "info": {
        "name": "Git Config Exposure",
        "severity": "low",
        "tags": ["git", "exposure"],
    },
    "type": "http",
    "host": "https://app.example.com",
    "matched-at": "https://app.example.com/.git/config",
})


@pytest.fixture
def adapter(scope_engine):
    return NucleiAdapter(scope_engine=scope_engine)


class TestParseRecord:
    def test_parse_full_record(self, adapter):
        raw = json.loads(SAMPLE_NUCLEI_OUTPUT)
        record = adapter.parse_record(raw)
        assert record["template_id"] == "exposed-env-file"
        assert record["template_name"] == "Exposed .env File"
        assert record["severity"] == "medium"
        assert record["finding_type"] == "http"
        assert record["url"] == "https://app.example.com/.env"
        assert record["extracted_results"] == ["DB_PASSWORD=secret"]
        assert "exposure" in record["tags"]
        assert record["matcher_name"] == "env-keywords"

    def test_parse_minimal_record(self, adapter):
        raw = {"template-id": "test", "info": {"name": "Test"}, "host": "https://x.com"}
        record = adapter.parse_record(raw)
        assert record["template_id"] == "test"
        assert record["severity"] == "info"


class TestBuildCommand:
    def test_single_target(self, adapter):
        adapter._binary_path = "/usr/bin/nuclei"
        cmd, output_file = adapter.build_command(
            ["https://example.com"], AdapterConfig()
        )
        assert cmd[0] == "/usr/bin/nuclei"
        assert "-u" in cmd
        assert "https://example.com" in cmd
        assert "-jsonl" in cmd
        assert output_file is None

    def test_severity_filter(self, adapter):
        adapter._binary_path = "/usr/bin/nuclei"
        config = AdapterConfig()
        config.extra_args_dict["severity"] = "high,critical"
        cmd, _ = adapter.build_command(["https://example.com"], config)
        idx = cmd.index("-severity")
        assert cmd[idx + 1] == "high,critical"

    def test_tags_filter(self, adapter):
        adapter._binary_path = "/usr/bin/nuclei"
        config = AdapterConfig()
        config.extra_args_dict["tags"] = "cve,exposure"
        cmd, _ = adapter.build_command(["https://example.com"], config)
        idx = cmd.index("-tags")
        assert cmd[idx + 1] == "cve,exposure"


class TestParseOutput:
    def test_parse_multi_line_output(self, adapter):
        stdout = SAMPLE_NUCLEI_OUTPUT + "\n" + SAMPLE_NUCLEI_LINE_2
        records, parse_errors = adapter.parse_output(stdout)
        assert len(records) == 2
        assert parse_errors == 0
        assert records[0]["template_id"] == "exposed-env-file"
        assert records[1]["template_id"] == "git-config"


class TestScopeFiltering:
    def test_extract_scope_target(self, adapter):
        record = {"host": "https://app.example.com", "url": "https://app.example.com/.env"}
        assert adapter.extract_scope_target(record) == "https://app.example.com"

    def test_in_scope_record_kept(self, adapter):
        records = [
            {"host": "https://app.example.com", "url": "https://app.example.com/.env"},
        ]
        kept, removed = adapter.post_filter_records(records)
        assert len(kept) == 1
        assert removed == 0

    def test_out_of_scope_record_removed(self, adapter):
        records = [
            {"host": "https://other.com", "url": "https://other.com/.env"},
        ]
        kept, removed = adapter.post_filter_records(records)
        assert len(kept) == 0
        assert removed == 1
