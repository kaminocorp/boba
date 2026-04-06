"""Adapter for gitleaks — secret scanning in git repositories."""

from __future__ import annotations

import logging
import tempfile
from pathlib import Path
from typing import Any

from boba.adapters.base import BaseAdapter
from boba.core.models import AdapterConfig, OutputFormat

logger = logging.getLogger(__name__)

# Mapping from gitleaks rule IDs to high-level secret types.
_RULE_TYPE_MAP: dict[str, str] = {
    "aws-access-key-id": "key",
    "aws-secret-access-key": "key",
    "github-pat": "token",
    "github-fine-grained-pat": "token",
    "github-oauth": "token",
    "github-app-token": "token",
    "gitlab-pat": "token",
    "gitlab-ptt": "token",
    "gitlab-rrt": "token",
    "generic-api-key": "key",
    "private-key": "certificate",
    "slack-web-hook": "token",
    "slack-bot-token": "token",
    "slack-app-token": "token",
    "stripe-access-token": "key",
    "stripe-publishable-key": "key",
    "gcp-service-account": "key",
    "gcp-api-key": "key",
    "heroku-api-key": "key",
    "jwt": "token",
    "npm-access-token": "token",
    "pypi-upload-token": "token",
    "sendgrid-api-token": "token",
    "twilio-api-key": "key",
    "twitter-api-key": "key",
    "mailchimp-api-key": "key",
    "password-in-url": "password",
    "mailgun-private-api-token": "token",
    "shopify-access-token": "token",
    "shopify-shared-secret": "key",
    "telegram-bot-api-token": "token",
    "hashicorp-tf-api-token": "token",
    "hashicorp-vault-token": "token",
    "datadog-access-token": "token",
    "newrelic-user-api-key": "key",
    "age-secret-key": "key",
}


def _classify_secret_type(rule_id: str) -> str:
    """Map a gitleaks rule ID to a high-level secret type."""
    if rule_id in _RULE_TYPE_MAP:
        return _RULE_TYPE_MAP[rule_id]
    lower = rule_id.lower()
    if "key" in lower:
        return "key"
    if "token" in lower:
        return "token"
    if "password" in lower or "passwd" in lower:
        return "password"
    if "cert" in lower or "private" in lower:
        return "certificate"
    return "other"


def _redact(value: str) -> str:
    """Redact a secret value for safe storage.

    Secrets of 16 characters or fewer are fully replaced with ``****``.
    Longer secrets (API keys, tokens) show the first and last 4 characters
    to aid identification while hiding the bulk of the value.
    """
    if len(value) <= 16:
        return "****"
    return f"{value[:4]}****{value[-4:]}"


class GitleaksAdapter(BaseAdapter):
    TOOL_NAME = "gitleaks"
    BINARY_NAMES = ["gitleaks"]
    OUTPUT_FORMAT = OutputFormat.JSON_ARRAY
    PRODUCES = "secret"
    SCOPE_MODE = "pre"

    def __init__(self, scope_engine):
        super().__init__(scope_engine)
        self._repo = ""

    def install_hint(self) -> str:
        return "brew install gitleaks  # or: go install github.com/gitleaks/gitleaks/v8@latest"

    def pre_filter_targets(self, targets: list[str]) -> list[str]:
        """Secret scanning trusts the explicitly requested repo/org targets.

        Repo locators live on GitHub/local disk, not on the hunted asset's domain,
        so normal scope matching would incorrectly discard valid scans.
        """
        return [target for target in targets if target]

    def build_command(self, targets: list[str], config: AdapterConfig) -> tuple[list[str], Path]:
        if not targets:
            raise ValueError("gitleaks requires at least one target (repo path or URL)")
        if len(targets) > 1:
            logger.warning(
                "gitleaks only supports a single target; using first target, ignoring %d others",
                len(targets) - 1,
            )

        self._repo = targets[0]

        tf = tempfile.NamedTemporaryFile(suffix=".json", prefix="boba_gitleaks_", delete=False)
        tf.close()
        output_file = Path(tf.name)

        cmd = [
            str(self._binary_path),
            "detect",
            "--source",
            self._repo,
            "--report-format",
            "json",
            "--report-path",
            str(output_file),
            "--no-banner",
        ]

        if config.extra_args_dict.get("no_git"):
            cmd.append("--no-git")

        cmd.extend(config.extra_args)
        return cmd, output_file

    def parse_record(self, raw: dict[str, Any] | str) -> dict[str, Any]:
        if isinstance(raw, str):
            return {
                "rule_id": "unknown",
                "secret_type": "other",
                "file_path": "",
                "repo": self._repo,
                "line_number": None,
                "match_preview": _redact(raw),
                "commit": "",
                "author": "",
                "date": "",
                "entropy": None,
            }

        rule_id = raw.get("RuleID") or raw.get("rule_id") or raw.get("ruleID") or "unknown"
        secret_type = _classify_secret_type(rule_id)

        match_val = raw.get("Secret") or raw.get("Match") or raw.get("secret") or ""
        match_preview = _redact(match_val) if match_val else ""

        file_path = raw.get("File") or raw.get("file") or ""
        line = raw.get("StartLine") or raw.get("line_number") or raw.get("Line")
        commit = raw.get("Commit") or raw.get("commit") or ""
        author = raw.get("Author") or raw.get("author") or ""
        date = raw.get("Date") or raw.get("date") or ""
        entropy = raw.get("Entropy") or raw.get("entropy")

        if entropy is not None:
            try:
                entropy = float(entropy)
            except (ValueError, TypeError):
                entropy = None

        if line is not None:
            try:
                line = int(line)
            except (ValueError, TypeError):
                line = None

        return {
            "rule_id": str(rule_id),
            "secret_type": secret_type,
            "file_path": str(file_path),
            "repo": self._repo,
            "line_number": line,
            "match_preview": match_preview,
            "commit": str(commit),
            "author": str(author),
            "date": str(date),
            "entropy": entropy,
        }

    def extract_scope_target(self, record: dict[str, Any]) -> str | None:
        return record.get("repo") or None
