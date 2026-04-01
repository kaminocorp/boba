"""Adapter for ffuf — directory/file/parameter fuzzing."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

import logging

from boba.adapters.base import BaseAdapter
from boba.core.models import AdapterConfig, OutputFormat

logger = logging.getLogger(__name__)


# Common locations where SecLists might be installed
_WORDLIST_SEARCH_PATHS = [
    Path("/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt"),
    Path("/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-words.txt"),
    Path.home() / "SecLists" / "Discovery" / "Web-Content" / "raft-medium-words.txt",
    Path.home() / "wordlists" / "raft-medium-words.txt",
]


def _find_default_wordlist() -> str | None:
    """Try to find a default wordlist on the system."""
    for path in _WORDLIST_SEARCH_PATHS:
        if path.exists():
            return str(path)
    return None


class FfufAdapter(BaseAdapter):
    TOOL_NAME = "ffuf"
    BINARY_NAMES = ["ffuf"]
    OUTPUT_FORMAT = OutputFormat.JSON_OBJECT
    PRODUCES = "directory"
    SCOPE_MODE = "pre"

    def install_hint(self) -> str:
        return "go install -v github.com/ffuf/ffuf/v2@latest"

    def build_command(self, targets: list[str], config: AdapterConfig) -> tuple[list[str], Path]:
        if len(targets) > 1:
            logger.warning(
                "ffuf only supports a single target URL; using first target, "
                "ignoring %d additional targets",
                len(targets) - 1,
            )
        url = targets[0]
        if "FUZZ" not in url:
            url = url.rstrip("/") + "/FUZZ"

        tf = tempfile.NamedTemporaryFile(suffix=".json", prefix="boba_ffuf_", delete=False)
        tf.close()
        output_file = Path(tf.name)

        wordlist = config.extra_args_dict.get("wordlist") or _find_default_wordlist()
        if not wordlist:
            raise FileNotFoundError(
                "No wordlist provided and no default found. Pass --wordlist or install SecLists."
            )

        match_codes = config.extra_args_dict.get("match_codes", "200,301,302,403")

        cmd = [
            str(self._binary_path),
            "-u",
            url,
            "-w",
            wordlist,
            "-o",
            str(output_file),
            "-of",
            "json",
            "-mc",
            match_codes,
            "-silent",
        ]
        if config.rate_limit:
            cmd.extend(["-rate", str(config.rate_limit)])
        cmd.extend(config.extra_args)
        return cmd, output_file

    def parse_record(self, raw: dict[str, Any]) -> dict[str, Any]:
        return {
            "url": raw.get("url", ""),
            "input_value": raw.get("input", {}).get("FUZZ", ""),
            "status_code": raw.get("status", 0),
            "content_length": raw.get("length", 0),
            "word_count": raw.get("words", 0),
            "line_count": raw.get("lines", 0),
            "content_type": raw.get("content-type", ""),
            "redirect_location": raw.get("redirectlocation", ""),
        }

    def extract_scope_target(self, record: dict[str, Any]) -> str | None:
        return record.get("url")
