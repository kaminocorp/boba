"""Tests for the BaseAdapter — parse_output formats and temp file lifecycle."""

from __future__ import annotations

import json
from typing import Any


from boba.adapters.base import BaseAdapter
from boba.core.models import (
    AdapterConfig,
    OutputFormat,
    ScopeAction,
    ScopeConfig,
    ScopeRule,
    ScopeRuleType,
)
from boba.core.scope import ScopeEngine


# ── Concrete stub for testing the abstract BaseAdapter ──────────────


def _make_adapter(output_format: OutputFormat) -> BaseAdapter:
    """Create a minimal concrete adapter with the given output format."""

    class StubAdapter(BaseAdapter):
        TOOL_NAME = "stub"
        BINARY_NAMES = ["stub"]
        PRODUCES = "subdomain"
        SCOPE_MODE = "post"

        def __init__(self, fmt: OutputFormat, scope: ScopeEngine):
            self.OUTPUT_FORMAT = fmt
            super().__init__(scope)

        def install_hint(self) -> str:
            return "pip install stub"

        def build_command(
            self, targets: list[str], config: AdapterConfig
        ) -> tuple[list[str], None]:
            return ["stub"], None

        def parse_record(self, raw: dict[str, Any] | str) -> dict[str, Any]:
            if isinstance(raw, str):
                return {"value": raw}
            return dict(raw)

        def extract_scope_target(self, record: dict[str, Any]) -> str | None:
            return record.get("value")

    scope = ScopeEngine(
        ScopeConfig(
            rules=[
                ScopeRule("*.example.com", ScopeRuleType.DOMAIN, ScopeAction.INCLUDE),
            ]
        )
    )
    return StubAdapter(fmt=output_format, scope=scope)


# ── JSON_LINES ──────────────────────────────────────────────────────


class TestParseOutputJsonLines:
    def test_valid_multiline(self):
        adapter = _make_adapter(OutputFormat.JSON_LINES)
        stdout = '{"host":"a.example.com"}\n{"host":"b.example.com"}\n'
        records, errors = adapter.parse_output(stdout)
        assert len(records) == 2
        assert errors == 0
        assert records[0]["host"] == "a.example.com"
        assert records[1]["host"] == "b.example.com"

    def test_empty_input(self):
        adapter = _make_adapter(OutputFormat.JSON_LINES)
        records, errors = adapter.parse_output("")
        assert records == []
        assert errors == 0

    def test_malformed_line_increments_errors(self):
        adapter = _make_adapter(OutputFormat.JSON_LINES)
        stdout = '{"host":"good.example.com"}\nthis is not json\n{"host":"also.good"}\n'
        records, errors = adapter.parse_output(stdout)
        assert len(records) == 2
        assert errors == 1

    def test_blank_lines_skipped(self):
        adapter = _make_adapter(OutputFormat.JSON_LINES)
        stdout = '\n{"host":"a.example.com"}\n\n\n{"host":"b.example.com"}\n\n'
        records, errors = adapter.parse_output(stdout)
        assert len(records) == 2
        assert errors == 0


# ── JSON_OBJECT ─────────────────────────────────────────────────────


class TestParseOutputJsonObject:
    def test_valid_with_results_key(self):
        adapter = _make_adapter(OutputFormat.JSON_OBJECT)
        data = {"results": [{"url": "http://a.example.com"}, {"url": "http://b.example.com"}]}
        records, errors = adapter.parse_output(json.dumps(data))
        assert len(records) == 2
        assert errors == 0
        assert records[0]["url"] == "http://a.example.com"

    def test_valid_raw_list(self):
        """When the top-level JSON is a list, it should be iterated directly."""
        adapter = _make_adapter(OutputFormat.JSON_OBJECT)
        data = [{"url": "http://a.example.com"}]
        records, errors = adapter.parse_output(json.dumps(data))
        assert len(records) == 1
        assert errors == 0

    def test_valid_single_object_without_results(self):
        """A single dict without 'results' key wraps itself as [raw]."""
        adapter = _make_adapter(OutputFormat.JSON_OBJECT)
        data = {"url": "http://a.example.com"}
        records, errors = adapter.parse_output(json.dumps(data))
        assert len(records) == 1

    def test_empty_results(self):
        adapter = _make_adapter(OutputFormat.JSON_OBJECT)
        data = {"results": []}
        records, errors = adapter.parse_output(json.dumps(data))
        assert records == []
        assert errors == 0

    def test_invalid_json(self):
        adapter = _make_adapter(OutputFormat.JSON_OBJECT)
        records, errors = adapter.parse_output("not json at all")
        assert records == []
        assert errors == 1


# ── PLAIN_LINES ─────────────────────────────────────────────────────


class TestParseOutputPlainLines:
    def test_valid_lines(self):
        adapter = _make_adapter(OutputFormat.PLAIN_LINES)
        stdout = "http://a.example.com\nhttp://b.example.com\n"
        records, errors = adapter.parse_output(stdout)
        assert len(records) == 2
        assert errors == 0
        assert records[0]["value"] == "http://a.example.com"

    def test_empty_input(self):
        adapter = _make_adapter(OutputFormat.PLAIN_LINES)
        records, errors = adapter.parse_output("")
        assert records == []
        assert errors == 0

    def test_blank_lines_skipped(self):
        adapter = _make_adapter(OutputFormat.PLAIN_LINES)
        stdout = "\n  \nhttp://a.example.com\n\nhttp://b.example.com\n  \n"
        records, errors = adapter.parse_output(stdout)
        assert len(records) == 2
        assert errors == 0


# ── JSON_ARRAY ──────────────────────────────────────────────────────


class TestParseOutputJsonArray:
    def test_valid_array(self):
        adapter = _make_adapter(OutputFormat.JSON_ARRAY)
        data = [{"name": "Apache"}, {"name": "nginx"}]
        records, errors = adapter.parse_output(json.dumps(data))
        assert len(records) == 2
        assert errors == 0
        assert records[0]["name"] == "Apache"

    def test_empty_array(self):
        adapter = _make_adapter(OutputFormat.JSON_ARRAY)
        records, errors = adapter.parse_output("[]")
        assert records == []
        assert errors == 0

    def test_invalid_json(self):
        adapter = _make_adapter(OutputFormat.JSON_ARRAY)
        records, errors = adapter.parse_output("{broken")
        assert records == []
        assert errors == 1


# ── Output file fallback ────────────────────────────────────────────


class TestParseOutputFromFile:
    def test_reads_output_file_when_present(self, tmp_path):
        adapter = _make_adapter(OutputFormat.JSON_LINES)
        output_file = tmp_path / "output.json"
        output_file.write_text('{"host":"from_file.example.com"}\n')
        records, errors = adapter.parse_output("ignored stdout", output_file=output_file)
        assert len(records) == 1
        assert records[0]["host"] == "from_file.example.com"

    def test_falls_back_to_stdout_when_no_file(self):
        adapter = _make_adapter(OutputFormat.JSON_LINES)
        records, errors = adapter.parse_output(
            '{"host":"from_stdout.example.com"}\n', output_file=None
        )
        assert len(records) == 1
        assert records[0]["host"] == "from_stdout.example.com"


# ── Temp file lifecycle ─────────────────────────────────────────────


class TestTempFileLifecycle:
    def test_create_temp_file_exists_and_has_content(self):
        adapter = _make_adapter(OutputFormat.PLAIN_LINES)
        lines = ["target1.example.com", "target2.example.com"]
        path = adapter._create_temp_file(lines)
        assert path.exists()
        content = path.read_text()
        assert "target1.example.com" in content
        assert "target2.example.com" in content
        assert len(adapter._temp_files) == 1
        # Cleanup for this test
        adapter._cleanup_temp_files()

    def test_cleanup_removes_tracked_files(self):
        adapter = _make_adapter(OutputFormat.PLAIN_LINES)
        path1 = adapter._create_temp_file(["a"])
        path2 = adapter._create_temp_file(["b"])
        assert path1.exists()
        assert path2.exists()
        assert len(adapter._temp_files) == 2

        adapter._cleanup_temp_files()

        assert not path1.exists()
        assert not path2.exists()
        assert len(adapter._temp_files) == 0

    def test_cleanup_handles_already_deleted_files(self):
        adapter = _make_adapter(OutputFormat.PLAIN_LINES)
        path = adapter._create_temp_file(["a"])
        path.unlink()  # Delete before cleanup
        # Should not raise
        adapter._cleanup_temp_files()
        assert len(adapter._temp_files) == 0
