"""Async subprocess execution utilities for CLI tool adapters."""

from __future__ import annotations

import asyncio
import os
import time
from collections.abc import AsyncIterator, Callable

from boba.core.models import SubprocessResult


_MAX_OUTPUT_BYTES = 256 * 1024 * 1024  # 256 MB cap to prevent OOM


async def run_subprocess(
    cmd: list[str],
    timeout_seconds: int = 300,
    env_vars: dict[str, str] | None = None,
    stdin_data: str | None = None,
    on_stdout_line: Callable[[str], None] | None = None,
    max_output_bytes: int = _MAX_OUTPUT_BYTES,
) -> SubprocessResult:
    """
    Execute a subprocess asynchronously.

    Captures stdout/stderr line-by-line with a size cap to prevent OOM.
    On timeout, sends SIGKILL and preserves partial output.

    Args:
        cmd: Command and arguments.
        timeout_seconds: Max wall-clock time. 0 = no timeout.
        env_vars: Additional env vars merged with os.environ.
        stdin_data: Data to pipe to stdin.
        on_stdout_line: Optional callback for each stdout line.
        max_output_bytes: Maximum bytes to capture before truncating (default 256MB).
    """
    env = os.environ.copy()
    if env_vars:
        env.update(env_vars)

    start = time.monotonic()
    timed_out = False

    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        stdin=asyncio.subprocess.PIPE if stdin_data else asyncio.subprocess.DEVNULL,
        env=env,
    )

    stdout_chunks: list[str] = []
    stderr_chunks: list[str] = []
    total_bytes = 0
    output_truncated = False

    async def read_stream(
        stream: asyncio.StreamReader,
        chunks: list[str],
        callback: Callable[[str], None] | None = None,
    ) -> None:
        nonlocal total_bytes, output_truncated
        while True:
            line = await stream.readline()
            if not line:
                break
            total_bytes += len(line)
            if total_bytes > max_output_bytes:
                # Stop accumulating to prevent OOM, but keep reading to drain
                output_truncated = True
                continue
            decoded = line.decode("utf-8", errors="replace")
            chunks.append(decoded)
            if callback:
                callback(decoded.rstrip("\n"))

    try:
        if stdin_data and process.stdin:
            try:
                process.stdin.write(stdin_data.encode())
                await process.stdin.drain()
            finally:
                process.stdin.close()

        timeout = timeout_seconds if timeout_seconds > 0 else None
        await asyncio.wait_for(
            asyncio.gather(
                read_stream(process.stdout, stdout_chunks, on_stdout_line),
                read_stream(process.stderr, stderr_chunks),
            ),
            timeout=timeout,
        )
        await process.wait()

    except asyncio.TimeoutError:
        timed_out = True
        process.kill()
        await process.wait()

    duration = time.monotonic() - start

    return SubprocessResult(
        stdout="".join(stdout_chunks),
        stderr="".join(stderr_chunks),
        exit_code=process.returncode if process.returncode is not None else -1,
        duration=duration,
        timed_out=timed_out,
        output_truncated=output_truncated,
    )


async def run_subprocess_streaming(
    cmd: list[str],
    timeout_seconds: int = 300,
    env_vars: dict[str, str] | None = None,
) -> AsyncIterator[str]:
    """
    Yield stdout lines as they arrive.

    For long-running tools (katana, ffuf) where incremental results are useful.
    """
    env = os.environ.copy()
    if env_vars:
        env.update(env_vars)

    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
        env=env,
    )

    deadline = time.monotonic() + timeout_seconds if timeout_seconds > 0 else float("inf")

    try:
        while True:
            if time.monotonic() > deadline:
                process.kill()
                break
            try:
                line = await asyncio.wait_for(process.stdout.readline(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            if not line:
                break
            yield line.decode("utf-8", errors="replace").rstrip("\n")
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()
