"""All shared type definitions for Boba."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
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


class AuthMethod(str, Enum):
    FORM = "form"
    COOKIE = "cookie"
    BEARER = "bearer"
    BASIC = "basic"
    CUSTOM_HEADER = "header"
    OAUTH2 = "oauth2"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    POSSIBLE = "possible"


class FuzzAttackType(str, Enum):
    SNIPER = "sniper"
    BATTERING_RAM = "battering_ram"
    PITCHFORK = "pitchfork"
    CLUSTER_BOMB = "cluster_bomb"


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
    parse_errors: int = 0
    timed_out: bool = False


@dataclass
class SubprocessResult:
    """Raw result from async subprocess execution."""

    stdout: str
    stderr: str
    exit_code: int
    duration: float
    timed_out: bool
    output_truncated: bool = False


# ──────────────────────────── V2: Interaction ─────────────────────────


@dataclass
class BrowserConfig:
    """Configuration for the Playwright browser."""

    headless: bool = True
    proxy: str | None = None
    user_agent: str | None = None
    viewport: dict[str, int] = field(default_factory=lambda: {"width": 1280, "height": 720})
    ignore_https_errors: bool = True
    extra_headers: dict[str, str] = field(default_factory=dict)
    slow_mo: int = 0


@dataclass
class SessionState:
    """Serializable authentication state for a named session."""

    name: str
    target_url: str
    auth_method: AuthMethod = AuthMethod.FORM
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    tokens: dict[str, str] = field(default_factory=dict)
    storage_state: dict[str, Any] | None = None
    is_valid: bool = True
    created_at: str = ""
    last_used_at: str = ""


@dataclass
class PageInfo:
    """Returned by browser navigate() — summary for agent reasoning."""

    url: str
    final_url: str
    status_code: int
    title: str
    content_type: str
    headers: dict[str, str] = field(default_factory=dict)
    cookies: list[dict[str, Any]] = field(default_factory=list)
    timing_ms: float = 0.0
    requests_captured: int = 0


@dataclass
class DOMExtraction:
    """Returned by browser extract() — structured DOM data."""

    url: str
    title: str
    forms: list[dict[str, Any]] = field(default_factory=list)
    links: list[dict[str, str]] = field(default_factory=list)
    scripts: list[dict[str, str]] = field(default_factory=list)
    meta: dict[str, str] = field(default_factory=dict)
    comments: list[str] = field(default_factory=list)
    inputs: list[dict[str, Any]] = field(default_factory=list)
    text_content: str = ""


@dataclass
class HttpResponse:
    """Returned by HttpClient.request() — structured HTTP response."""

    request_id: int
    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    body_text: str = ""
    elapsed_ms: float = 0.0
    redirect_chain: list[str] = field(default_factory=list)


@dataclass
class CompareResult:
    """Returned by HttpClient.compare() — structured diff of two responses."""

    status_match: bool = True
    status_a: int = 0
    status_b: int = 0
    header_diffs: list[dict[str, Any]] = field(default_factory=list)
    body_diff_summary: str = "identical"
    body_length_a: int = 0
    body_length_b: int = 0
    timing_diff_ms: float = 0.0


@dataclass
class FuzzResult:
    """Returned by HttpClient.fuzz() — aggregated fuzz results."""

    total_requests: int = 0
    results: list[dict[str, Any]] = field(default_factory=list)
    anomalies: list[dict[str, Any]] = field(default_factory=list)
    baseline_status: int = 0
    baseline_length: int = 0


@dataclass
class VulnTestResult:
    """Returned by vulnerability testing tools."""

    test_type: str
    vulnerable: bool
    confidence: Confidence = Confidence.POSSIBLE
    title: str = ""
    description: str = ""
    severity: Severity = Severity.INFO
    evidence: list[dict[str, Any]] = field(default_factory=list)
    request_ids: list[int] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
