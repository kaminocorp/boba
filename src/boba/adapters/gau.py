"""Adapter for gau (GetAllUrls) — historical URL discovery."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from boba.adapters.base import BaseAdapter
from boba.core.models import AdapterConfig, OutputFormat


class GauAdapter(BaseAdapter):
    TOOL_NAME = "gau"
    BINARY_NAMES = ["gau"]
    OUTPUT_FORMAT = OutputFormat.PLAIN_LINES
    PRODUCES = "url"
    SCOPE_MODE = "post"

    def install_hint(self) -> str:
        return "go install -v github.com/lc/gau/v2/cmd/gau@latest"

    def build_command(self, targets: list[str], config: AdapterConfig) -> tuple[list[str], None]:
        cmd = [str(self._binary_path)]
        cmd.extend(config.extra_args)
        # Write targets to a temp file to avoid ARG_MAX limits with large target lists
        # and to prevent targets starting with - from being parsed as flags.
        target_file = self._create_temp_file(targets)
        cmd.extend(["--fp", str(target_file)])
        return cmd, None

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
            "source": "gau",
        }

    def extract_scope_target(self, record: dict[str, Any]) -> str | None:
        return record.get("url")
