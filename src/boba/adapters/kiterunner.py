"""Adapter for Kiterunner — API endpoint discovery."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from boba.adapters.base import BaseAdapter
from boba.core.models import AdapterConfig, OutputFormat

logger = logging.getLogger(__name__)

# Regex for Kiterunner's plain-text output lines, e.g.:
# GET     200 [   1234,   45,   12] https://app.example.com/api/v2/users 0cc72...
_KR_LINE_RE = re.compile(
    r"^(?P<method>[A-Z]+)\s+"
    r"(?P<status>\d+)\s+"
    r"\[\s*(?P<length>\d+)\s*,\s*(?P<words>\d+)\s*,\s*(?P<lines>\d+)\s*\]\s+"
    r"(?P<url>\S+)"
)


class KiterunnerAdapter(BaseAdapter):
    TOOL_NAME = "kiterunner"
    BINARY_NAMES = ["kr"]
    OUTPUT_FORMAT = OutputFormat.PLAIN_LINES
    PRODUCES = "api_endpoint"
    SCOPE_MODE = "pre"

    def install_hint(self) -> str:
        return "go install github.com/assetnote/kiterunner/cmd/kr@latest"

    def build_command(
        self, targets: list[str], config: AdapterConfig
    ) -> tuple[list[str], Path | None]:
        if not targets:
            raise ValueError("kiterunner requires at least one target URL")

        cmd = [str(self._binary_path), "scan"]
        cmd.extend(targets)

        wordlist = config.extra_args_dict.get("wordlist")
        if wordlist:
            cmd.extend(["-w", str(wordlist)])

        if config.rate_limit:
            cmd.extend(["-x", str(config.rate_limit)])

        cmd.extend(["--fail-status-codes", "404,400"])

        cmd.extend(config.extra_args)
        return cmd, None

    def parse_record(self, raw: dict[str, Any] | str) -> dict[str, Any]:
        if isinstance(raw, str):
            return self._parse_line(raw)

        # JSON record (if -oJ is used or future versions)
        url = raw.get("url") or raw.get("URL") or ""
        method = (raw.get("method") or raw.get("Method") or "GET").upper()
        status_code = raw.get("status_code") or raw.get("StatusCode") or raw.get("status")
        content_type = raw.get("content_type") or raw.get("ContentType") or ""
        content_length = raw.get("content_length") or raw.get("ContentLength") or raw.get("length")

        if status_code is not None:
            try:
                status_code = int(status_code)
            except (ValueError, TypeError):
                status_code = None

        if content_length is not None:
            try:
                content_length = int(content_length)
            except (ValueError, TypeError):
                content_length = None

        parsed = urlparse(url)
        host = parsed.hostname or ""
        path = parsed.path or ""

        return {
            "url": url,
            "method": method,
            "status_code": status_code,
            "content_type": str(content_type),
            "content_length": content_length,
            "host": host,
            "path": path,
            "framework": str(raw.get("framework") or raw.get("Framework") or ""),
        }

    def _parse_line(self, line: str) -> dict[str, Any]:
        """Parse a single Kiterunner plain-text output line."""
        match = _KR_LINE_RE.match(line.strip())
        if not match:
            # Fallback: try to extract just a URL from the line
            parts = line.strip().split()
            url = ""
            method = "GET"
            for part in parts:
                if part.startswith("http://") or part.startswith("https://"):
                    url = part
                    break
            if len(parts) >= 1 and parts[0].isupper() and len(parts[0]) <= 7:
                method = parts[0]

            parsed = urlparse(url)
            return {
                "url": url,
                "method": method,
                "status_code": None,
                "content_type": "",
                "content_length": None,
                "host": parsed.hostname or "",
                "path": parsed.path or "",
                "framework": "",
            }

        url = match.group("url")
        parsed = urlparse(url)

        return {
            "url": url,
            "method": match.group("method"),
            "status_code": int(match.group("status")),
            "content_type": "",
            "content_length": int(match.group("length")),
            "host": parsed.hostname or "",
            "path": parsed.path or "",
            "framework": "",
        }

    def extract_scope_target(self, record: dict[str, Any]) -> str | None:
        host = record.get("host")
        if host is not None and host != "":
            return host
        return record.get("url")
