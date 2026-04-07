"""Nuclei adapter — template-based vulnerability scanning."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from boba.adapters.base import BaseAdapter
from boba.core.models import AdapterConfig, OutputFormat


def _coerce_list(value: Any) -> list:
    """Coerce a value to a list: lists pass through, strings wrap, anything else becomes []."""
    if isinstance(value, list):
        return value
    if isinstance(value, str) and value:
        return [value]
    return []


def _coerce_tags(value: Any) -> list[str]:
    """Coerce Nuclei tags field (list or comma-separated string) to a list of strings."""
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        return [t.strip() for t in value.split(",") if t.strip()]
    return []


class NucleiAdapter(BaseAdapter):
    """Wraps Nuclei for template-based vulnerability scanning."""

    TOOL_NAME = "nuclei"
    BINARY_NAMES = ["nuclei"]
    OUTPUT_FORMAT = OutputFormat.JSON_LINES
    PRODUCES = "finding"
    SCOPE_MODE = "both"

    def install_hint(self) -> str:
        return "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"

    def build_command(
        self, targets: list[str], config: AdapterConfig
    ) -> tuple[list[str], Path | None]:
        binary = str(self._binary_path)
        cmd = [binary]

        # Target input
        if len(targets) == 1:
            cmd.extend(["-u", targets[0]])
        else:
            target_file = self._create_temp_file(targets)
            cmd.extend(["-l", str(target_file)])

        # JSON output
        cmd.extend(["-jsonl", "-silent"])

        # Severity filter
        severity = config.extra_args_dict.get("severity")
        if severity:
            cmd.extend(["-severity", severity])

        # Tags filter
        tags = config.extra_args_dict.get("tags")
        if tags:
            cmd.extend(["-tags", tags])

        # Custom templates directory
        templates = config.extra_args_dict.get("templates")
        if templates:
            cmd.extend(["-t", templates])

        # Rate limit
        if config.rate_limit:
            cmd.extend(["-rate-limit", str(config.rate_limit)])

        # Extra raw args
        cmd.extend(config.extra_args)

        return cmd, None

    def parse_record(self, raw: dict[str, Any] | str) -> dict[str, Any]:
        if isinstance(raw, str):
            return {"url": raw}
        info = raw.get("info") if isinstance(raw.get("info"), dict) else {}
        return {
            "template_id": raw.get("template-id", ""),
            "template_name": info.get("name", ""),
            "severity": info.get("severity", "info"),
            "finding_type": raw.get("type", ""),
            "host": raw.get("host", ""),
            "url": raw.get("matched-at", raw.get("host", "")),
            "extracted_results": raw.get("extracted-results")
            if isinstance(raw.get("extracted-results"), list)
            else [],
            "curl_command": raw.get("curl-command", ""),
            "description": info.get("description", ""),
            "reference": _coerce_list(info.get("reference")),
            "tags": _coerce_tags(info.get("tags")),
            "matcher_name": raw.get("matcher-name", ""),
        }

    def extract_scope_target(self, record: dict[str, Any]) -> str | None:
        host = record.get("host")
        return host if host is not None and host != "" else record.get("url")
