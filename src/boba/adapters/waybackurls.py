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

    def build_command(self, targets: list[str], config: AdapterConfig) -> tuple[list[str], None]:
        # Store targets for stdin piping here (after pre-filtering in super().run())
        self._stdin_targets = targets
        cmd = [str(self._binary_path)]
        cmd.extend(config.extra_args)
        return cmd, None

    async def _execute(self, cmd: list[str], config: AdapterConfig) -> SubprocessResult:
        """Override to pipe targets via stdin (waybackurls reads domains from stdin)."""
        # Copy targets to local var to avoid race conditions if adapter is reused
        targets = list(self._stdin_targets)
        return await run_subprocess(
            cmd,
            timeout_seconds=config.timeout_seconds,
            env_vars=config.env_vars if config.env_vars else None,
            stdin_data="\n".join(targets) + "\n",
        )

    def parse_record(self, raw: str) -> dict[str, Any]:
        url = raw.strip()
        try:
            parsed = urlparse(url)
            host = parsed.hostname or ""
            path = parsed.path
            query = parsed.query
        except Exception:
            host, path, query = "", "", ""
        return {
            "url": url,
            "host": host,
            "path": path,
            "query": query,
            "source": "waybackurls",
        }

    def extract_scope_target(self, record: dict[str, Any]) -> str | None:
        return record.get("url")
