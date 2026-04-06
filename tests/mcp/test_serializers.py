"""Tests for MCP serialization helpers."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

from boba.mcp.serializers import serialize_result, serialize_tool_result


# -- serialize_result ---------------------------------------------------------


def test_serialize_dict():
    result = serialize_result({"key": "value", "num": 42})
    parsed = json.loads(result)
    assert parsed == {"key": "value", "num": 42}


def test_serialize_list_of_dicts():
    result = serialize_result([{"a": 1}, {"b": 2}])
    parsed = json.loads(result)
    assert parsed == [{"a": 1}, {"b": 2}]


def test_serialize_dataclass():
    @dataclass
    class Sample:
        name: str
        count: int

    result = serialize_result(Sample(name="test", count=5))
    parsed = json.loads(result)
    assert parsed == {"name": "test", "count": 5}


def test_serialize_list_of_dataclasses():
    @dataclass
    class Item:
        x: int

    result = serialize_result([Item(x=1), Item(x=2)])
    parsed = json.loads(result)
    assert parsed == [{"x": 1}, {"x": 2}]


def test_serialize_datetime_uses_default_str():
    """datetime fields are serialized via str() fallback."""
    ts = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
    result = serialize_result({"created": ts})
    parsed = json.loads(result)
    assert "2026" in parsed["created"]


def test_serialize_scalar_fallback():
    result = serialize_result(42)
    assert result == "42"


def test_serialize_mixed_list():
    """Lists with a mix of dicts and dataclasses."""

    @dataclass
    class DC:
        v: int

    result = serialize_result([DC(v=1), {"v": 2}])
    parsed = json.loads(result)
    assert parsed == [{"v": 1}, {"v": 2}]


# -- serialize_tool_result ----------------------------------------------------


def test_serialize_tool_result_success():
    @dataclass
    class FakeToolResult:
        tool_name: str = "subfinder"
        records: list = field(default_factory=lambda: [{"host": "a.example.com"}])
        filtered_count: int = 2
        duration_seconds: float = 1.5
        timed_out: bool = False
        exit_code: int = 0
        raw_stderr: str = ""

    result = serialize_tool_result(FakeToolResult())
    parsed = json.loads(result)
    assert parsed["summary"]["tool"] == "subfinder"
    assert parsed["summary"]["records_found"] == 1
    assert parsed["summary"]["filtered_out"] == 2
    assert parsed["summary"]["timed_out"] is False
    assert "exit_code" not in parsed["summary"]  # only included on non-zero
    assert len(parsed["records"]) == 1


def test_serialize_tool_result_with_error():
    @dataclass
    class FakeToolResult:
        tool_name: str = "naabu"
        records: list = field(default_factory=list)
        filtered_count: int = 0
        duration_seconds: float = 0.1
        timed_out: bool = False
        exit_code: int = 1
        raw_stderr: str = "binary not found"

    result = serialize_tool_result(FakeToolResult())
    parsed = json.loads(result)
    assert parsed["summary"]["exit_code"] == 1
    assert "binary not found" in parsed["summary"]["stderr"]


def test_serialize_tool_result_truncates_stderr():
    @dataclass
    class FakeToolResult:
        tool_name: str = "ffuf"
        records: list = field(default_factory=list)
        filtered_count: int = 0
        duration_seconds: float = 0.0
        timed_out: bool = False
        exit_code: int = 2
        raw_stderr: str = "x" * 1000

    result = serialize_tool_result(FakeToolResult())
    parsed = json.loads(result)
    assert len(parsed["summary"]["stderr"]) == 500
