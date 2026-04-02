"""Base adapter — abstract class for all CLI tool wrappers."""

from __future__ import annotations

import json
import logging
import shutil
import tempfile
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from boba.core.errors import ToolNotFoundError
from boba.core.models import AdapterConfig, OutputFormat, SubprocessResult, ToolResult
from boba.core.scope import ScopeEngine
from boba.core.subprocess import run_subprocess

logger = logging.getLogger(__name__)


class BaseAdapter(ABC):
    """
    Abstract base for all CLI tool adapters.

    Lifecycle:
        find_binary() → pre_filter_targets() → build_command()
        → run_subprocess() → parse_output() → post_filter_records()
        → cleanup → return ToolResult
    """

    # Subclasses must override these
    TOOL_NAME: str = ""
    BINARY_NAMES: list[str] = []
    OUTPUT_FORMAT: OutputFormat = OutputFormat.JSON_LINES
    PRODUCES: str = ""  # "subdomain", "host", "port", "url", "technology", "directory"
    SCOPE_MODE: str = "post"  # "pre", "post", or "both"

    def __init__(self, scope_engine: ScopeEngine):
        self._scope = scope_engine
        self._binary_path: Path | None = None
        self._temp_files: list[Path] = []

    # ── Phase 1: Binary discovery ──

    def find_binary(self) -> Path:
        """Locate the tool binary in PATH or common install locations."""
        for name in self.BINARY_NAMES:
            path = shutil.which(name)
            if path:
                self._binary_path = Path(path)
                return self._binary_path

        # Check common Go/local install dirs
        for name in self.BINARY_NAMES:
            for prefix in [Path.home() / "go" / "bin", Path.home() / ".local" / "bin"]:
                candidate = prefix / name
                if candidate.is_file() and candidate.stat().st_mode & 0o111:
                    self._binary_path = candidate
                    return self._binary_path

        raise ToolNotFoundError(
            f"{self.TOOL_NAME} not found. Searched: {self.BINARY_NAMES}. "
            f"Install with: {self.install_hint()}"
        )

    @abstractmethod
    def install_hint(self) -> str:
        """Return the installation command for this tool."""
        ...

    # ── Phase 2: Input preparation ──

    def _create_temp_file(self, lines: list[str], suffix: str = ".txt") -> Path:
        """Write targets to a temp file for tools that accept -l file.txt."""
        tf = tempfile.NamedTemporaryFile(
            mode="w",
            suffix=suffix,
            prefix=f"boba_{self.TOOL_NAME}_",
            delete=False,
        )
        tf.write("\n".join(lines) + "\n")
        tf.close()
        path = Path(tf.name)
        self._temp_files.append(path)
        return path

    def _cleanup_temp_files(self) -> None:
        for f in self._temp_files:
            f.unlink(missing_ok=True)
        self._temp_files.clear()

    # ── Phase 3: Command construction ──

    @abstractmethod
    def build_command(
        self, targets: list[str], config: AdapterConfig
    ) -> tuple[list[str], Path | None]:
        """
        Build the CLI argv list.

        Returns:
            (command, output_file_path_or_None)
            output_file_path is for tools like ffuf/whatweb that write to a file.
        """
        ...

    # ── Phase 4: Scope enforcement ──

    def pre_filter_targets(self, targets: list[str]) -> list[str]:
        """Filter input targets against scope before execution.

        Uses entity_type="auto" because input targets are always hostnames,
        domains, or URLs — regardless of what the adapter PRODUCES as output.
        """
        in_scope, _ = self._scope.filter_targets(targets, "auto")
        return in_scope

    def post_filter_records(
        self, records: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], int]:
        """Filter output records against scope. Returns (kept, removed_count)."""
        kept: list[dict[str, Any]] = []
        removed = 0
        for record in records:
            target_value = self.extract_scope_target(record)
            if target_value is None or target_value == "":
                logger.debug(
                    "[%s] Dropping record with unmappable scope target (default-deny): %s",
                    self.TOOL_NAME,
                    {k: str(v)[:80] for k, v in record.items()} if record else record,
                )
                removed += 1
            elif self._scope.is_in_scope(target_value):
                kept.append(record)
            else:
                removed += 1
        return kept, removed

    @abstractmethod
    def extract_scope_target(self, record: dict[str, Any]) -> str | None:
        """Extract the value from a parsed record that should be scope-checked."""
        ...

    # ── Phase 5: Output parsing ──

    @abstractmethod
    def parse_record(self, raw: dict[str, Any] | str) -> dict[str, Any]:
        """Normalize one raw output record into Boba's canonical schema."""
        ...

    def parse_output(
        self, stdout: str, output_file: Path | None = None
    ) -> tuple[list[dict[str, Any]], int]:
        """Parse full tool output into records, delegating to parse_record.

        Returns (records, parse_error_count) so callers can surface data loss.
        """
        raw_text = stdout
        if output_file and output_file.exists():
            raw_text = output_file.read_text()

        records: list[dict[str, Any]] = []
        parse_errors = 0

        if self.OUTPUT_FORMAT == OutputFormat.JSON_LINES:
            for line in raw_text.strip().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                    records.append(self.parse_record(raw))
                except Exception as exc:
                    parse_errors += 1
                    logger.debug("%s: failed to parse line: %s", self.TOOL_NAME, exc)
                    continue
            if parse_errors:
                logger.warning(
                    "%s: %d lines failed to parse (out of %d total)",
                    self.TOOL_NAME,
                    parse_errors,
                    parse_errors + len(records),
                )

        elif self.OUTPUT_FORMAT == OutputFormat.JSON_OBJECT:
            try:
                raw = json.loads(raw_text)
                if isinstance(raw, list):
                    items = raw
                elif isinstance(raw, dict):
                    items = raw.get("results", [raw])
                else:
                    # Primitive value (string, number, null) — not parseable as records
                    items = []
                    parse_errors += 1
                    logger.warning(
                        "%s: JSON output is a %s, expected object or array",
                        self.TOOL_NAME,
                        type(raw).__name__,
                    )
                for item in items:
                    try:
                        records.append(self.parse_record(item))
                    except Exception as exc:
                        parse_errors += 1
                        logger.debug("%s: failed to parse record: %s", self.TOOL_NAME, exc)
            except json.JSONDecodeError:
                parse_errors += 1
                logger.warning(
                    "%s: failed to parse JSON output (%d bytes)",
                    self.TOOL_NAME,
                    len(raw_text),
                )

        elif self.OUTPUT_FORMAT == OutputFormat.PLAIN_LINES:
            for line in raw_text.strip().splitlines():
                line = line.strip()
                if line:
                    try:
                        records.append(self.parse_record(line))
                    except Exception as exc:
                        parse_errors += 1
                        logger.debug("%s: failed to parse line: %s", self.TOOL_NAME, exc)
            if parse_errors:
                logger.warning(
                    "%s: %d lines failed to parse (out of %d total)",
                    self.TOOL_NAME,
                    parse_errors,
                    parse_errors + len(records),
                )

        elif self.OUTPUT_FORMAT == OutputFormat.JSON_ARRAY:
            try:
                items = json.loads(raw_text)
                if isinstance(items, list):
                    for item in items:
                        try:
                            records.append(self.parse_record(item))
                        except Exception as exc:
                            parse_errors += 1
                            logger.debug("%s: failed to parse record: %s", self.TOOL_NAME, exc)
                else:
                    parse_errors += 1
                    logger.warning(
                        "%s: expected JSON array, got %s",
                        self.TOOL_NAME,
                        type(items).__name__,
                    )
            except json.JSONDecodeError:
                parse_errors += 1
                logger.warning(
                    "%s: failed to parse JSON array output (%d bytes)",
                    self.TOOL_NAME,
                    len(raw_text),
                )

        return records, parse_errors

    # ── Phase 6: Orchestration ──

    async def run(self, targets: list[str], config: AdapterConfig | None = None) -> ToolResult:
        """
        Full lifecycle execution:
        1. find_binary
        2. pre_filter if scope_mode in (pre, both)
        3. build_command
        4. run_subprocess
        5. parse_output
        6. post_filter if scope_mode in (post, both)
        7. cleanup
        8. return ToolResult
        """
        config = config or AdapterConfig()
        self.find_binary()

        # Pre-filter
        if self.SCOPE_MODE in ("pre", "both"):
            targets = self.pre_filter_targets(targets)
            if not targets:
                return ToolResult(
                    tool_name=self.TOOL_NAME,
                    command=[],
                    exit_code=0,
                    raw_stdout="",
                    raw_stderr="",
                    duration_seconds=0.0,
                    records=[],
                    filtered_count=0,
                )

        cmd, output_file = self.build_command(targets, config)

        try:
            result = await self._execute(cmd, config)
            if result.exit_code != 0:
                logger.warning(
                    "%s exited with code %d%s; stderr: %.200s",
                    self.TOOL_NAME,
                    result.exit_code,
                    " (timed out)" if result.timed_out else "",
                    result.stderr.strip() or "(empty)",
                )
            records, parse_errors = self.parse_output(result.stdout, output_file)

            # Post-filter
            filtered_count = 0
            if self.SCOPE_MODE in ("post", "both"):
                records, filtered_count = self.post_filter_records(records)

            return ToolResult(
                tool_name=self.TOOL_NAME,
                command=cmd,
                exit_code=result.exit_code,
                raw_stdout=result.stdout,
                raw_stderr=result.stderr,
                duration_seconds=result.duration,
                records=records,
                filtered_count=filtered_count,
                parse_errors=parse_errors,
                timed_out=result.timed_out,
            )
        finally:
            self._cleanup_temp_files()
            if output_file:
                output_file.unlink(missing_ok=True)

    async def _execute(self, cmd: list[str], config: AdapterConfig) -> SubprocessResult:
        """Run the subprocess. Override in adapters that need stdin piping."""
        return await run_subprocess(
            cmd,
            timeout_seconds=config.timeout_seconds,
            env_vars=config.env_vars if config.env_vars else None,
        )
