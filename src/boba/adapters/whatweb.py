"""Adapter for whatweb — technology fingerprinting."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from boba.adapters.base import BaseAdapter
from boba.core.models import AdapterConfig, OutputFormat


class WhatwebAdapter(BaseAdapter):
    TOOL_NAME = "whatweb"
    BINARY_NAMES = ["whatweb"]
    OUTPUT_FORMAT = OutputFormat.JSON_ARRAY
    PRODUCES = "technology"
    SCOPE_MODE = "pre"

    def install_hint(self) -> str:
        return "gem install whatweb  # or: apt install whatweb"

    def build_command(
        self, targets: list[str], config: AdapterConfig
    ) -> tuple[list[str], Path]:
        tf = tempfile.NamedTemporaryFile(
            suffix=".json", prefix="boba_whatweb_", delete=False
        )
        tf.close()
        output_file = Path(tf.name)
        input_file = self._create_temp_file(targets)
        cmd = [
            str(self._binary_path),
            "--input-file", str(input_file),
            "--log-json", str(output_file),
            "-a", "3",
            "--quiet",
        ]
        cmd.extend(config.extra_args)
        return cmd, output_file

    def parse_record(self, raw: dict[str, Any]) -> dict[str, Any]:
        technologies = []
        for name, details in raw.get("plugins", {}).items():
            tech: dict[str, Any] = {"name": name}
            if isinstance(details, dict):
                versions = details.get("version", [])
                if versions:
                    tech["version"] = versions[0] if isinstance(versions, list) else str(versions)
                strings = details.get("string", [])
                if strings:
                    tech["detail"] = strings[0] if isinstance(strings, list) else str(strings)
            technologies.append(tech)

        target = raw.get("target", "")
        return {
            "url": target,
            "host": urlparse(target).hostname or "" if target else "",
            "status_code": raw.get("http_status"),
            "technologies": technologies,
        }

    def extract_scope_target(self, record: dict[str, Any]) -> str | None:
        return record.get("url") or record.get("host")
