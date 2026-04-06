"""Adapter for httpx (ProjectDiscovery) — live host probing with tech detection."""

from __future__ import annotations

from typing import Any

from boba.adapters.base import BaseAdapter
from boba.core.models import AdapterConfig, OutputFormat


def _safe_int(value: Any) -> int | None:
    """Safely convert a value to int, returning None on failure."""
    if value is None:
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


class HttpxRunnerAdapter(BaseAdapter):
    TOOL_NAME = "httpx"
    BINARY_NAMES = ["httpx"]
    OUTPUT_FORMAT = OutputFormat.JSON_LINES
    PRODUCES = "host"
    SCOPE_MODE = "both"

    def install_hint(self) -> str:
        return "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"

    def build_command(self, targets: list[str], config: AdapterConfig) -> tuple[list[str], None]:
        input_file = self._create_temp_file(targets)
        cmd = [
            str(self._binary_path),
            "-l",
            str(input_file),
            "-json",
            "-silent",
            "-status-code",
            "-title",
            "-tech-detect",
            "-webserver",
            "-content-length",
            "-content-type",
            "-follow-redirects",
            "-tls-grab",
        ]
        if config.rate_limit:
            cmd.extend(["-rl", str(config.rate_limit)])
        cmd.extend(config.extra_args)
        return cmd, None

    def parse_record(self, raw: dict[str, Any]) -> dict[str, Any]:
        a_records = raw.get("a")
        ip = a_records[0] if isinstance(a_records, list) and a_records else ""
        tls = raw.get("tls")
        tls_version = (tls.get("version") or "") if isinstance(tls, dict) else ""
        return {
            "host": raw.get("input", ""),
            "ip": ip,
            "port": _safe_int(raw.get("port")),
            "scheme": raw.get("scheme", ""),
            "url": raw.get("url", ""),
            "status_code": _safe_int(raw.get("status_code")),
            "title": raw.get("title", ""),
            "webserver": raw.get("webserver", ""),
            "content_length": _safe_int(raw.get("content_length")),
            "content_type": raw.get("content_type", ""),
            "technologies": raw.get("tech") or [],
            "tls_version": tls_version,
            "final_url": raw.get("final_url", ""),
        }

    def extract_scope_target(self, record: dict[str, Any]) -> str | None:
        host = record.get("host")
        return host if host is not None and host != "" else record.get("url")
