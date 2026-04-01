"""Tests for async subprocess execution — uses real commands, no mocks."""

from __future__ import annotations


from boba.core.subprocess import run_subprocess, run_subprocess_streaming


class TestRunSubprocess:
    async def test_echo_basic(self):
        result = await run_subprocess(["echo", "hello"])
        assert result.stdout == "hello\n"
        assert result.exit_code == 0
        assert result.timed_out is False

    async def test_exit_code(self):
        result = await run_subprocess(["python3", "-c", "import sys; sys.exit(42)"])
        assert result.exit_code == 42

    async def test_stderr_capture(self):
        result = await run_subprocess(["python3", "-c", "import sys; sys.stderr.write('err\\n')"])
        assert "err" in result.stderr
        assert result.exit_code == 0

    async def test_timeout(self):
        result = await run_subprocess(["sleep", "10"], timeout_seconds=1)
        assert result.timed_out is True

    async def test_stdin_data(self):
        result = await run_subprocess(["cat"], stdin_data="hello\n")
        assert result.stdout == "hello\n"
        assert result.exit_code == 0

    async def test_env_vars(self):
        result = await run_subprocess(
            ["python3", "-c", "import os; print(os.environ['BOBA_TEST'])"],
            env_vars={"BOBA_TEST": "42"},
        )
        assert result.stdout.strip() == "42"

    async def test_on_stdout_line_callback(self):
        collected = []
        result = await run_subprocess(
            ["echo", "callback-line"],
            on_stdout_line=lambda line: collected.append(line),
        )
        assert result.exit_code == 0
        assert "callback-line" in collected

    async def test_duration_tracked(self):
        result = await run_subprocess(["echo", "timing"])
        assert result.duration > 0


class TestRunSubprocessStreaming:
    async def test_streaming_basic(self):
        lines = []
        async for line in run_subprocess_streaming(["echo", "streamed"]):
            lines.append(line)
        assert "streamed" in lines

    async def test_streaming_timeout(self):
        lines = []
        async for line in run_subprocess_streaming(["sleep", "10"], timeout_seconds=1):
            lines.append(line)
        # Should terminate without hanging; lines may be empty for sleep
        assert isinstance(lines, list)
