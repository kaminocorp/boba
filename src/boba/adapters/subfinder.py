"""Adapter for subfinder — passive subdomain discovery."""

from __future__ import annotations

from typing import Any

from boba.adapters.base import BaseAdapter
from boba.core.models import AdapterConfig, OutputFormat


class SubfinderAdapter(BaseAdapter):
    TOOL_NAME = "subfinder"
    BINARY_NAMES = ["subfinder"]
    OUTPUT_FORMAT = OutputFormat.JSON_LINES
    PRODUCES = "subdomain"
    SCOPE_MODE = "post"

    def install_hint(self) -> str:
        return "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"

    def build_command(
        self, targets: list[str], config: AdapterConfig
    ) -> tuple[list[str], None]:
        cmd = [str(self._binary_path), "-json", "-silent", "-all"]
        if len(targets) == 1:
            cmd.extend(["-d", targets[0]])
        else:
            input_file = self._create_temp_file(targets)
            cmd.extend(["-dL", str(input_file)])
        if config.rate_limit:
            cmd.extend(["-rl", str(config.rate_limit)])
        cmd.extend(config.extra_args)
        return cmd, None

    def parse_record(self, raw: dict[str, Any]) -> dict[str, Any]:
        return {
            "subdomain": raw.get("host", ""),
            "root_domain": raw.get("input", ""),
            "source": raw.get("source", "unknown"),
        }

    def extract_scope_target(self, record: dict[str, Any]) -> str | None:
        return record.get("subdomain")
