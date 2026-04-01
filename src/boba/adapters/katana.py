"""Adapter for katana — modern web crawler with JS parsing."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from boba.adapters.base import BaseAdapter
from boba.core.models import AdapterConfig, OutputFormat


class KatanaAdapter(BaseAdapter):
    TOOL_NAME = "katana"
    BINARY_NAMES = ["katana"]
    OUTPUT_FORMAT = OutputFormat.JSON_LINES
    PRODUCES = "url"
    SCOPE_MODE = "both"

    def install_hint(self) -> str:
        return "go install -v github.com/projectdiscovery/katana/cmd/katana@latest"

    def build_command(self, targets: list[str], config: AdapterConfig) -> tuple[list[str], None]:
        input_file = self._create_temp_file(targets)
        cmd = [
            str(self._binary_path),
            "-list",
            str(input_file),
            "-json",
            "-silent",
            "-js-crawl",
            "-known-files",
            "all",
            "-depth",
            str(config.extra_args_dict.get("depth", "3")),
        ]
        if config.rate_limit:
            cmd.extend(["-rl", str(config.rate_limit)])
        cmd.extend(config.extra_args)
        return cmd, None

    def parse_record(self, raw: dict[str, Any]) -> dict[str, Any]:
        req = raw.get("request") if isinstance(raw.get("request"), dict) else {}
        resp = raw.get("response") if isinstance(raw.get("response"), dict) else {}
        endpoint = raw.get("endpoint", req.get("endpoint", ""))
        try:
            parsed = urlparse(endpoint)
            host = parsed.hostname or ""
            path = parsed.path
            query = parsed.query
        except Exception:
            host, path, query = "", "", ""
        return {
            "url": endpoint,
            "host": host,
            "path": path,
            "query": query,
            "found_on": raw.get("source", ""),
            "method": req.get("method", "GET"),
            "status_code": resp.get("status_code"),
            "source": "katana",
        }

    def extract_scope_target(self, record: dict[str, Any]) -> str | None:
        return record.get("url")
