"""Adapter for Arjun — hidden HTTP parameter discovery."""

from __future__ import annotations

import json
import logging
import tempfile
from pathlib import Path
from typing import Any

from boba.adapters.base import BaseAdapter
from boba.core.models import AdapterConfig, OutputFormat

logger = logging.getLogger(__name__)


class ArjunAdapter(BaseAdapter):
    TOOL_NAME = "arjun"
    BINARY_NAMES = ["arjun"]
    OUTPUT_FORMAT = OutputFormat.JSON_OBJECT
    PRODUCES = "parameter"
    SCOPE_MODE = "pre"

    def __init__(self, scope_engine):
        super().__init__(scope_engine)
        self._http_method = "GET"
        self._param_type = "query"
        self._target_url = ""

    def install_hint(self) -> str:
        return "pipx install arjun  # or: python3 -m pip install arjun"

    def _resolve_mode(self, method: str, body_type: str | None) -> tuple[str, str, str]:
        normalized_method = (method or "GET").upper()
        normalized_body_type = (body_type or "").lower()

        if normalized_method == "GET":
            return "GET", "GET", "query"
        if normalized_method == "POST":
            if normalized_body_type == "json":
                return "JSON", "POST", "body"
            return "POST", "POST", "body"
        if normalized_method == "JSON":
            return "JSON", "POST", "body"
        raise ValueError(f"Unsupported Arjun method: {method}")

    def build_command(self, targets: list[str], config: AdapterConfig) -> tuple[list[str], Path]:
        if not targets:
            raise ValueError("arjun requires at least one target URL")
        if len(targets) > 1:
            logger.warning(
                "arjun only supports a single target URL; using first target, ignoring %d additional targets",
                len(targets) - 1,
            )

        self._target_url = targets[0]
        arjun_mode, http_method, param_type = self._resolve_mode(
            config.extra_args_dict.get("method", "GET"),
            config.extra_args_dict.get("body_type"),
        )
        self._http_method = http_method
        self._param_type = param_type

        tf = tempfile.NamedTemporaryFile(suffix=".json", prefix="boba_arjun_", delete=False)
        tf.close()
        output_file = Path(tf.name)
        self._temp_files.append(output_file)

        cmd = [
            str(self._binary_path),
            "-u",
            self._target_url,
            "-m",
            arjun_mode,
            "-oJ",
            str(output_file),
            "--stable",
        ]
        if config.rate_limit:
            cmd.extend(["-t", str(config.rate_limit)])
        cmd.extend(config.extra_args)
        return cmd, output_file

    def parse_record(self, raw: dict[str, Any] | str) -> dict[str, Any]:
        if isinstance(raw, str):
            return {
                "url": self._target_url,
                "method": self._http_method,
                "name": raw,
                "param_type": self._param_type,
                "confirmed": True,
            }

        return {
            "url": raw.get("url", self._target_url),
            "method": str(raw.get("method", self._http_method)).upper(),
            "name": raw.get("name") or raw.get("param", ""),
            "param_type": raw.get("param_type", self._param_type),
            "confirmed": bool(raw.get("confirmed", True)),
        }

    def parse_output(
        self, stdout: str, output_file: Path | None = None
    ) -> tuple[list[dict[str, Any]], int]:
        raw_text = stdout
        if output_file and output_file.exists():
            raw_text = output_file.read_text()

        if not raw_text.strip():
            return [], 0

        try:
            raw = json.loads(raw_text)
        except json.JSONDecodeError:
            logger.warning(
                "%s: failed to parse JSON output (%d bytes)", self.TOOL_NAME, len(raw_text)
            )
            return [], 1

        items: list[dict[str, Any]] = []
        parse_errors = 0

        if isinstance(raw, dict):
            if "params" in raw or "parameters" in raw:
                items = [raw]
            else:
                for url, params in raw.items():
                    if isinstance(params, list):
                        items.append({"url": url, "params": params})
                    else:
                        parse_errors += 1
        elif isinstance(raw, list):
            items = [item for item in raw if isinstance(item, dict)]
            parse_errors += sum(1 for item in raw if not isinstance(item, dict))
        else:
            logger.warning(
                "%s: expected JSON object or array, got %s", self.TOOL_NAME, type(raw).__name__
            )
            return [], 1

        records: list[dict[str, Any]] = []
        for item in items:
            url = item.get("url", self._target_url)
            params = item.get("params", item.get("parameters", []))
            if isinstance(params, dict):
                params = list(params.keys())
            if not isinstance(params, list):
                parse_errors += 1
                continue

            for param in params:
                if isinstance(param, str):
                    records.append(
                        self.parse_record(
                            {
                                "url": url,
                                "name": param,
                                "confirmed": item.get("confirmed", True),
                            }
                        )
                    )
                    continue
                if isinstance(param, dict):
                    name = param.get("name") or param.get("param")
                    if not name:
                        parse_errors += 1
                        continue
                    records.append(
                        self.parse_record(
                            {
                                "url": url,
                                "method": param.get(
                                    "method", item.get("method", self._http_method)
                                ),
                                "name": name,
                                "param_type": param.get(
                                    "param_type", param.get("type", self._param_type)
                                ),
                                "confirmed": param.get("confirmed", item.get("confirmed", True)),
                            }
                        )
                    )
                    continue
                parse_errors += 1

        return records, parse_errors

    def extract_scope_target(self, record: dict[str, Any]) -> str | None:
        return record.get("url")
