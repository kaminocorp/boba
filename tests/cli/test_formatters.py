"""Tests for boba.cli.formatters — JSON and table output helpers."""

from __future__ import annotations

import json

import pytest
import typer

from boba.cli.formatters import _auto_columns, _print_json, format_output


class TestAutoColumns:
    """Tests for _auto_columns helper."""

    def test_excludes_skip_set_keys(self):
        record = {
            "id": 1,
            "hunt_id": "h1",
            "domain": "example.com",
            "status": "active",
            "first_seen_at": "2025-01-01",
            "last_seen_at": "2025-01-02",
            "last_checked_at": "2025-01-02",
            "sources": ["subfinder"],
        }
        cols = _auto_columns(record)
        assert "id" not in cols
        assert "hunt_id" not in cols
        assert "first_seen_at" not in cols
        assert "last_seen_at" not in cols
        assert "last_checked_at" not in cols
        assert "sources" not in cols
        assert "domain" in cols
        assert "status" in cols

    def test_limits_to_eight_columns(self):
        record = {f"col_{i}": i for i in range(15)}
        cols = _auto_columns(record)
        assert len(cols) <= 8


class TestFormatOutputJson:
    """Tests for format_output with fmt='json'."""

    def test_json_output_is_valid(self, capsys):
        data = [{"host": "10.0.0.1", "port": 80}]
        format_output(data, fmt="json")
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed == data

    def test_json_single_dict(self, capsys):
        data = {"name": "test-hunt", "target": "example.com"}
        format_output(data, fmt="json")
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed == data


class TestFormatOutputTable:
    """Tests for format_output with fmt='table'."""

    def test_table_produces_output(self, capsys):
        data = [{"domain": "example.com", "status": "200"}]
        format_output(data, fmt="table")
        captured = capsys.readouterr()
        assert "example.com" in captured.out

    def test_empty_list_prints_no_results(self, capsys):
        format_output([], fmt="table")
        captured = capsys.readouterr()
        assert "No results" in captured.out

    def test_single_dict_prints_key_value_pairs(self, capsys):
        data = {"name": "hunt-1", "target": "example.com"}
        format_output(data, fmt="table")
        captured = capsys.readouterr()
        assert "name" in captured.out
        assert "hunt-1" in captured.out


class TestFormatOutputInvalid:
    """Tests for invalid format argument."""

    def test_invalid_fmt_raises_exit(self):
        with pytest.raises(typer.Exit):
            format_output([{"a": 1}], fmt="xml")


class TestPrintJson:
    """Tests for _print_json helper."""

    def test_output_is_parseable_json(self, capsys):
        data = [{"url": "https://example.com/path", "status": 200}]
        _print_json(data)
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed == data
