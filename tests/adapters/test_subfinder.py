"""Tests for the subfinder adapter — uses mocked subprocess output."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from boba.adapters.subfinder import SubfinderAdapter
from boba.core.models import SubprocessResult

SAMPLE_OUTPUT = """\
{"host":"api.example.com","input":"example.com","source":"crtsh"}
{"host":"app.example.com","input":"example.com","source":"virustotal"}
{"host":"internal.example.com","input":"example.com","source":"crtsh"}
{"host":"dev.example.com","input":"example.com","source":"shodan"}
"""


@pytest.mark.asyncio
async def test_parses_json_lines(scope_engine):
    adapter = SubfinderAdapter(scope_engine=scope_engine)
    records, parse_errors = adapter.parse_output(SAMPLE_OUTPUT)
    assert len(records) == 4
    assert parse_errors == 0
    assert records[0]["subdomain"] == "api.example.com"
    assert records[0]["source"] == "crtsh"


@pytest.mark.asyncio
async def test_scope_filters_excluded(scope_engine):
    adapter = SubfinderAdapter(scope_engine=scope_engine)
    records, _ = adapter.parse_output(SAMPLE_OUTPUT)
    filtered, count = adapter.post_filter_records(records)
    assert count == 1  # internal.example.com
    hostnames = [r["subdomain"] for r in filtered]
    assert "internal.example.com" not in hostnames
    assert "api.example.com" in hostnames


@pytest.mark.asyncio
async def test_full_run_with_mock(scope_engine):
    adapter = SubfinderAdapter(scope_engine=scope_engine)

    mock_result = SubprocessResult(
        stdout=SAMPLE_OUTPUT,
        stderr="",
        exit_code=0,
        duration=1.5,
        timed_out=False,
    )

    with (
        patch.object(adapter, "find_binary", return_value="/usr/bin/subfinder"),
        patch(
            "boba.adapters.base.run_subprocess", new_callable=AsyncMock, return_value=mock_result
        ),
    ):
        result = await adapter.run(targets=["example.com"])

    assert len(result.records) == 3  # 4 found - 1 excluded
    assert result.filtered_count == 1
    assert result.tool_name == "subfinder"
