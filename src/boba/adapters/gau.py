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
        cmd.extend(targets)
        cmd.extend(config.extra_args)
        return cmd, None

    def parse_record(self, raw: str) -> dict[str, Any]:
        url = raw.strip()
        parsed = urlparse(url)
        return {
            "url": url,
            "host": parsed.hostname or "",
            "path": parsed.path,
            "query": parsed.query,
            "source": "gau",
        }

    def extract_scope_target(self, record: dict[str, Any]) -> str | None:
        return record.get("url")
