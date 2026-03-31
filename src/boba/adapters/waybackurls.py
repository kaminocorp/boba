"""Adapter for waybackurls — Wayback Machine URL discovery."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from boba.adapters.base import BaseAdapter
from boba.core.models import AdapterConfig, OutputFormat, SubprocessResult
from boba.core.subprocess import run_subprocess


class WaybackurlsAdapter(BaseAdapter):
    TOOL_NAME = "waybackurls"
    BINARY_NAMES = ["waybackurls"]
    OUTPUT_FORMAT = OutputFormat.PLAIN_LINES
    PRODUCES = "url"
    SCOPE_MODE = "post"

    def __init__(self, scope_engine):
        super().__init__(scope_engine)
        self._stdin_targets: list[str] = []

    def install_hint(self) -> str:
        return "go install -v github.com/tomnomnom/waybackurls@latest"

    def build_command(
        self, targets: list[str], config: AdapterConfig
    ) -> tuple[list[str], None]:
        cmd = [str(self._binary_path)]
        cmd.extend(config.extra_args)
        return cmd, None

    async def _execute(
        self, cmd: list[str], config: AdapterConfig
    ) -> SubprocessResult:
        """Override to pipe targets via stdin (waybackurls reads domains from stdin)."""
        return await run_subprocess(
            cmd,
            timeout_seconds=config.timeout_seconds,
            env_vars=config.env_vars if config.env_vars else None,
            stdin_data="\n".join(self._stdin_targets),
        )

    async def run(self, targets, config=None):
        """Override to store targets for stdin piping."""
        self._stdin_targets = targets
        return await super().run(targets, config)

    def parse_record(self, raw: str) -> dict[str, Any]:
        url = raw.strip()
        parsed = urlparse(url)
        return {
            "url": url,
            "host": parsed.hostname or "",
            "path": parsed.path,
            "query": parsed.query,
            "source": "waybackurls",
        }

    def extract_scope_target(self, record: dict[str, Any]) -> str | None:
        return record.get("url")
