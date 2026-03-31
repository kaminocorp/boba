"""All shared type definitions for Boba."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any


# ──────────────────────────── Enums ────────────────────────────


class HuntStatus(str, Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"


class ScopeAction(str, Enum):
    INCLUDE = "include"
    EXCLUDE = "exclude"


class ScopeRuleType(str, Enum):
    DOMAIN = "domain"
    IP_RANGE = "ip_range"
    URL_PREFIX = "url_prefix"


class OutputFormat(str, Enum):
    JSON_LINES = "jsonl"
    JSON_OBJECT = "json"
    PLAIN_LINES = "plain"
    JSON_ARRAY = "json_array"


class ToolRunStatus(str, Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


# ──────────────────────────── Scope ────────────────────────────


@dataclass
class ScopeRule:
    pattern: str
    rule_type: ScopeRuleType
    action: ScopeAction = ScopeAction.INCLUDE


@dataclass
class ScopeConfig:
    rules: list[ScopeRule] = field(default_factory=list)


# ──────────────────────────── Hunt ─────────────────────────────


@dataclass
class Hunt:
    id: str
    name: str
    status: HuntStatus = HuntStatus.ACTIVE
    scope: ScopeConfig = field(default_factory=ScopeConfig)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    config: dict[str, Any] = field(default_factory=dict)


# ──────────────────────────── Adapter I/O ──────────────────────


@dataclass
class AdapterConfig:
    """Per-invocation configuration for an adapter run."""

    timeout_seconds: int = 300
    extra_args: list[str] = field(default_factory=list)
    extra_args_dict: dict[str, str] = field(default_factory=dict)
    env_vars: dict[str, str] = field(default_factory=dict)
    rate_limit: int | None = None


@dataclass
class ToolResult:
    """Standardized result returned by every adapter."""

    tool_name: str
    command: list[str]
    exit_code: int
    raw_stdout: str
    raw_stderr: str
    duration_seconds: float
    records: list[dict[str, Any]]
    filtered_count: int = 0
    timed_out: bool = False


@dataclass
class SubprocessResult:
    """Raw result from async subprocess execution."""

    stdout: str
    stderr: str
    exit_code: int
    duration: float
    timed_out: bool
