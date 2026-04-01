"""Adapter for naabu — fast port scanning."""

from __future__ import annotations

from typing import Any

from boba.adapters.base import BaseAdapter
from boba.core.models import AdapterConfig, OutputFormat


class NaabuAdapter(BaseAdapter):
    TOOL_NAME = "naabu"
    BINARY_NAMES = ["naabu"]
    OUTPUT_FORMAT = OutputFormat.JSON_LINES
    PRODUCES = "port"
    SCOPE_MODE = "pre"

    def install_hint(self) -> str:
        return "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"

    def build_command(
        self, targets: list[str], config: AdapterConfig
    ) -> tuple[list[str], None]:
        input_file = self._create_temp_file(targets)
        cmd = [
            str(self._binary_path),
            "-l", str(input_file),
            "-json",
            "-silent",
        ]
        if "ports" in config.extra_args_dict:
            cmd.extend(["-p", str(config.extra_args_dict["ports"])])
        if config.rate_limit:
            cmd.extend(["-rate", str(config.rate_limit)])
        cmd.extend(config.extra_args)
        return cmd, None

    def parse_record(self, raw: dict[str, Any]) -> dict[str, Any]:
        return {
            "host": raw.get("host", ""),
            "ip": raw.get("ip", ""),
            "port": raw.get("port", 0),
            "protocol": raw.get("protocol", "tcp"),
        }

    def extract_scope_target(self, record: dict[str, Any]) -> str | None:
        return record.get("host")
