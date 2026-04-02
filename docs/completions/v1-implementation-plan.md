# Boba V1 Implementation Plan — Foundation: Recon & Enumeration

## 1. Overview

V1 delivers the foundation layer: an agent (or human) can create a hunt, define scope, run a full reconnaissance pipeline, enumerate endpoints, and query everything discovered — all with structured JSON output suitable for LLM agent consumption.

### What V1 Delivers

| Capability | Description |
|---|---|
| Hunt management | Create, configure, query, and close hunts |
| Scope engine | Define and enforce target boundaries — defensive by default |
| Hunt context | SQLite persistence for all discovered data across tool runs |
| CLI tool adapters | subfinder, httpx, naabu, gau, waybackurls, whatweb, katana, ffuf |
| High-level tools | `recon.subdomains`, `recon.hosts`, `recon.ports`, `recon.urls`, `recon.tech`, `enum.directories` |
| CLI | Typer-based CLI with `--format json` for agent consumption |

### What an Agent Can Do After V1

```
boba hunt create --name "Acme Corp" --scope scope.yaml
boba recon subdomains <hunt-id> --domain acme.com
boba recon hosts <hunt-id>
boba recon ports <hunt-id>
boba recon urls <hunt-id> --domain acme.com
boba recon tech <hunt-id>
boba enum directories <hunt-id> --url https://app.acme.com
boba context assets <hunt-id> --format json
```

The agent has a complete picture of the target's attack surface, persisted and queryable.

---

## 2. Project Structure

```
boba/
├── pyproject.toml
├── src/
│   └── boba/
│       ├── __init__.py              # Version, top-level exports
│       ├── core/
│       │   ├── __init__.py
│       │   ├── models.py            # All dataclasses and type definitions
│       │   ├── errors.py            # Exception hierarchy
│       │   ├── config.py            # Global configuration
│       │   ├── context.py           # HuntContext — SQLite persistence
│       │   ├── hunt.py              # Hunt lifecycle management
│       │   ├── scope.py             # ScopeEngine — target boundary enforcement
│       │   └── subprocess.py        # Async subprocess execution utilities
│       ├── adapters/
│       │   ├── __init__.py          # Adapter registry
│       │   ├── base.py              # BaseAdapter abstract class
│       │   ├── subfinder.py
│       │   ├── httpx_runner.py      # Named to avoid conflict with httpx Python lib
│       │   ├── naabu.py
│       │   ├── gau.py
│       │   ├── waybackurls.py
│       │   ├── whatweb.py
│       │   ├── katana.py
│       │   └── ffuf.py
│       ├── tools/
│       │   ├── __init__.py
│       │   ├── recon.py             # recon.subdomains/hosts/ports/urls/tech
│       │   └── enum.py              # enum.directories
│       └── cli/
│           ├── __init__.py
│           ├── main.py              # Typer app, top-level command groups
│           └── formatters.py        # Table and JSON output formatting
└── tests/
    ├── __init__.py
    ├── conftest.py                  # Shared fixtures (tmp db, mock scope, etc.)
    ├── core/
    │   ├── test_scope.py
    │   ├── test_context.py
    │   └── test_hunt.py
    ├── adapters/
    │   ├── test_base.py
    │   ├── test_subfinder.py
    │   ├── test_httpx_runner.py
    │   └── ...                      # One per adapter
    └── tools/
        ├── test_recon.py
        └── test_enum.py
```

### pyproject.toml

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "boba"
version = "0.1.0"
description = "Agent-native bug bounty hunting framework"
requires-python = ">=3.11"
dependencies = [
    "pydantic>=2.0",
    "typer[all]>=0.9",
    "rich>=13.0",
    "pyyaml>=6.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0",
    "pytest-asyncio>=0.21",
    "pytest-cov>=4.0",
    "ruff>=0.1",
]

[project.scripts]
boba = "boba.cli.main:app"

[tool.hatch.build.targets.wheel]
packages = ["src/boba"]

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]

[tool.ruff]
target-version = "py311"
line-length = 100
```

**Key decisions:**
- **Python 3.11+** — required for modern typing (`str | None`), and SQLite 3.38+ JSON functions (`json_each`, `json_group_array`)
- **Pydantic v2** — for model validation and JSON serialization
- **Typer + Rich** — modern CLI with beautiful table output and `--format json` for agents
- **src/ layout** — prevents accidental imports from project root
- **No async runtime dependency** — uses stdlib `asyncio` only; CLI calls `asyncio.run()` at the top level

---

## 3. Core Models

> File: `src/boba/core/models.py`

All shared type definitions live here. Adapters, tools, and the CLI all import from this single source of truth.

```python
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional


# ──────────────────────────── Enums ────────────────────────────

class HuntStatus(str, Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"

class ScopeAction(str, Enum):
    INCLUDE = "include"
    EXCLUDE = "exclude"

class ScopeRuleType(str, Enum):
    DOMAIN = "domain"          # *.example.com, example.com
    IP_RANGE = "ip_range"      # 192.168.1.0/24, 10.0.0.1
    URL_PREFIX = "url_prefix"  # https://app.example.com/*

class OutputFormat(str, Enum):
    JSON_LINES = "jsonl"       # One JSON object per line (subfinder, httpx, naabu, katana)
    JSON_OBJECT = "json"       # Single JSON object/wrapper (ffuf)
    PLAIN_LINES = "plain"      # One result per line (gau, waybackurls)
    JSON_ARRAY = "json_array"  # JSON array in file (whatweb)

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
    filtered_count: int = 0           # Records removed by scope filtering
    timed_out: bool = False

@dataclass
class SubprocessResult:
    """Raw result from async subprocess execution."""
    stdout: str
    stderr: str
    exit_code: int
    duration: float
    timed_out: bool
```

---

## 4. Error Hierarchy

> File: `src/boba/core/errors.py`

```python
class BobaError(Exception):
    """Base exception for all Boba errors."""

class ToolNotFoundError(BobaError):
    """CLI tool binary not found in PATH."""

class ToolTimeoutError(BobaError):
    """Tool execution exceeded timeout."""

class ToolExecutionError(BobaError):
    """Tool exited with non-zero code."""
    def __init__(self, message: str, exit_code: int, stderr: str):
        super().__init__(message)
        self.exit_code = exit_code
        self.stderr = stderr

class ScopeViolationError(BobaError):
    """Target is outside the defined scope."""

class HuntNotFoundError(BobaError):
    """Hunt ID does not exist in the context database."""
```

---

## 5. Scope Engine

> File: `src/boba/core/scope.py`

The scope engine is the "defensive by default" enforcement layer. Every adapter passes through it. The design uses pre-compiled regex patterns for domain matching and stdlib `ipaddress` for CIDR matching.

### Evaluation Rules

1. If **any exclusion rule** matches → OUT of scope (exclusions always win)
2. If **any inclusion rule** matches → IN scope
3. If **no rule matches** → OUT of scope (default deny)

### Per-Adapter Scope Mode

Each adapter declares a `SCOPE_MODE` that determines when filtering happens:

| Adapter | SCOPE_MODE | Pre-filter input? | Post-filter output? | Rationale |
|---------|------------|-------------------|---------------------|-----------|
| subfinder | `post` | No | Yes | Discovers new subdomains; can't pre-filter unknown targets |
| httpx | `both` | Yes | Yes | Input must be in scope; redirects can escape scope |
| naabu | `pre` | Yes | No | Scans specific hosts; if input is valid, ports are too |
| gau | `post` | No | Yes | Discovers historical URLs that may be out of scope |
| waybackurls | `post` | No | Yes | Same as gau |
| whatweb | `pre` | Yes | No | Fingerprints a specific target; output is inherently in scope |
| katana | `both` | Yes (seed URLs) | Yes | Crawler follows links and can leave scope |
| ffuf | `pre` | Yes (target URL) | No | Fuzzes a specific URL; pre-validation is sufficient |

### Matching Logic

```python
# Domain: *.example.com
#   → Regex: ^(.+\.)?example\.com$
#   → Matches: example.com, sub.example.com, deep.sub.example.com
#   → Does not match: notexample.com, example.com.evil.com

# IP range: 192.168.1.0/24
#   → Uses ipaddress.ip_network(pattern, strict=False)
#   → Matches any IP in the /24 range

# URL prefix: https://app.example.com/*
#   → Simple startswith check (after stripping wildcard)
#   → Domain must ALSO pass domain matching (double gate)
```

### Scope Config YAML Format

```yaml
# scope.yaml — passed to `boba hunt create --scope scope.yaml`
rules:
  - pattern: "*.acme.com"
    type: domain
    action: include
  - pattern: "acme.com"
    type: domain
    action: include
  - pattern: "staging.acme.com"
    type: domain
    action: exclude
  - pattern: "internal.acme.com"
    type: domain
    action: exclude
  - pattern: "10.0.0.0/8"
    type: ip_range
    action: exclude
```

### Implementation Skeleton

```python
class ScopeEngine:
    def __init__(self, config: ScopeConfig):
        self._rules = config.rules
        # Pre-compile into separate include/exclude lists by type
        self._domain_includes: list[re.Pattern] = []
        self._domain_excludes: list[re.Pattern] = []
        self._ip_includes: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._ip_excludes: list[...] = []
        self._url_includes: list[str] = []
        self._url_excludes: list[str] = []
        self._compile()

    def is_in_scope(self, target: str, entity_type: str = "auto") -> bool:
        """Check if a target is within scope. entity_type: subdomain|ip|url|auto."""

    def filter_targets(self, targets: list[str], entity_type: str = "auto") -> tuple[list[str], list[str]]:
        """Returns (in_scope, out_of_scope)."""

    # Private matching methods
    def _match_domain(self, hostname: str) -> bool | None:  # None = no rule matched
    def _match_ip(self, ip_str: str) -> bool | None:
    def _match_url(self, url: str) -> bool | None:
    def _extract_hostname(self, target: str) -> str:
    def _guess_entity_type(self, target: str) -> str:

    @staticmethod
    def _domain_to_regex(pattern: str) -> re.Pattern:
        """*.example.com → ^(.+\\.)?example\\.com$"""

    @classmethod
    def from_yaml(cls, path: Path) -> ScopeEngine:
        """Load scope config from YAML file."""
```

---

## 6. Hunt Context — SQLite Persistence

> File: `src/boba/core/context.py`

The hunt context is the stateful memory of the entire hunting process. Every tool run persists its results here. The agent can query at any time to understand what's been discovered and what hasn't been tested.

### SQLite Pragmas

```sql
PRAGMA journal_mode = WAL;    -- Concurrent reads during writes
PRAGMA foreign_keys = ON;     -- Enforce referential integrity
```

WAL mode is critical: it allows the CLI to query the database while a background adapter is writing results.

### Full Schema (DDL)

```sql
-- ═══════════════════ HUNTS ═══════════════════
CREATE TABLE IF NOT EXISTS hunts (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'active',
    scope_json  TEXT NOT NULL,               -- Serialized ScopeConfig
    config_json TEXT NOT NULL DEFAULT '{}',   -- Hunt-wide settings
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

-- ═══════════════════ SCOPE RULES ═══════════════════
-- Denormalized from scope_json for queryability
CREATE TABLE IF NOT EXISTS scope_rules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id     TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    pattern     TEXT NOT NULL,
    rule_type   TEXT NOT NULL,               -- domain, ip_range, url_prefix
    action      TEXT NOT NULL DEFAULT 'include',
    UNIQUE(hunt_id, pattern, rule_type)
);

-- ═══════════════════ SUBDOMAINS ═══════════════════
CREATE TABLE IF NOT EXISTS subdomains (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id       TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    subdomain     TEXT NOT NULL,
    root_domain   TEXT,
    sources       TEXT NOT NULL DEFAULT '[]', -- JSON array: ["crtsh", "virustotal"]
    first_seen_at TEXT NOT NULL,
    last_seen_at  TEXT NOT NULL,
    UNIQUE(hunt_id, subdomain)
);

-- ═══════════════════ HOSTS ═══════════════════
-- A "host" is a live service: (hostname, port, scheme) tuple
CREATE TABLE IF NOT EXISTS hosts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id         TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    host            TEXT NOT NULL,
    ip              TEXT,
    port            INTEGER,
    scheme          TEXT,
    url             TEXT,
    status_code     INTEGER,
    title           TEXT,
    webserver       TEXT,
    content_length  INTEGER,
    content_type    TEXT,
    technologies    TEXT DEFAULT '[]',       -- JSON array: ["Nginx", "React"]
    tls_version     TEXT,
    final_url       TEXT,                    -- After redirects
    first_seen_at   TEXT NOT NULL,
    last_seen_at    TEXT NOT NULL,
    last_checked_at TEXT NOT NULL,
    UNIQUE(hunt_id, host, COALESCE(port, 0), COALESCE(scheme, ''))
);

-- ═══════════════════ PORTS ═══════════════════
CREATE TABLE IF NOT EXISTS ports (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id       TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    host          TEXT NOT NULL,
    ip            TEXT,
    port          INTEGER NOT NULL,
    protocol      TEXT NOT NULL DEFAULT 'tcp',
    first_seen_at TEXT NOT NULL,
    last_seen_at  TEXT NOT NULL,
    UNIQUE(hunt_id, host, port, protocol)
);

-- ═══════════════════ URLS ═══════════════════
-- Discovered URLs from gau, waybackurls, katana, or crawling
CREATE TABLE IF NOT EXISTS urls (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id       TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    url           TEXT NOT NULL,
    host          TEXT,
    path          TEXT,
    query         TEXT,
    method        TEXT DEFAULT 'GET',
    status_code   INTEGER,
    sources       TEXT NOT NULL DEFAULT '[]', -- JSON array: ["gau", "katana"]
    found_on      TEXT,                       -- Referrer page (katana)
    first_seen_at TEXT NOT NULL,
    last_seen_at  TEXT NOT NULL,
    UNIQUE(hunt_id, url, COALESCE(method, 'GET'))
);

-- ═══════════════════ TECHNOLOGIES ═══════════════════
CREATE TABLE IF NOT EXISTS technologies (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id       TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    host          TEXT NOT NULL,
    name          TEXT NOT NULL,
    version       TEXT,
    detail        TEXT,
    sources       TEXT NOT NULL DEFAULT '[]',
    first_seen_at TEXT NOT NULL,
    last_seen_at  TEXT NOT NULL,
    UNIQUE(hunt_id, host, name)
);

-- ═══════════════════ DIRECTORIES ═══════════════════
-- Results from ffuf directory/file fuzzing
CREATE TABLE IF NOT EXISTS directories (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id           TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    url               TEXT NOT NULL,
    input_value       TEXT,                   -- The FUZZ word that matched
    status_code       INTEGER NOT NULL,
    content_length    INTEGER,
    word_count        INTEGER,
    line_count        INTEGER,
    content_type      TEXT,
    redirect_location TEXT,
    first_seen_at     TEXT NOT NULL,
    last_seen_at      TEXT NOT NULL,
    UNIQUE(hunt_id, url)
);

-- ═══════════════════ TOOL RUNS ═══════════════════
-- Audit log of every tool invocation
CREATE TABLE IF NOT EXISTS tool_runs (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id          TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    tool_name        TEXT NOT NULL,
    command_json     TEXT NOT NULL,           -- JSON-serialized argv
    status           TEXT NOT NULL,           -- running, completed, failed
    started_at       TEXT NOT NULL,
    finished_at      TEXT,
    duration_seconds REAL,
    exit_code        INTEGER,
    records_found    INTEGER,
    records_filtered INTEGER,
    timed_out        INTEGER DEFAULT 0,
    error_message    TEXT
);

-- ═══════════════════ INDEXES ═══════════════════
CREATE INDEX IF NOT EXISTS idx_subdomains_hunt    ON subdomains(hunt_id);
CREATE INDEX IF NOT EXISTS idx_hosts_hunt         ON hosts(hunt_id);
CREATE INDEX IF NOT EXISTS idx_hosts_status       ON hosts(hunt_id, status_code);
CREATE INDEX IF NOT EXISTS idx_ports_hunt         ON ports(hunt_id);
CREATE INDEX IF NOT EXISTS idx_ports_host         ON ports(hunt_id, host);
CREATE INDEX IF NOT EXISTS idx_urls_hunt          ON urls(hunt_id);
CREATE INDEX IF NOT EXISTS idx_urls_host          ON urls(hunt_id, host);
CREATE INDEX IF NOT EXISTS idx_technologies_hunt  ON technologies(hunt_id);
CREATE INDEX IF NOT EXISTS idx_directories_hunt   ON directories(hunt_id);
CREATE INDEX IF NOT EXISTS idx_tool_runs_hunt     ON tool_runs(hunt_id);
CREATE INDEX IF NOT EXISTS idx_tool_runs_status   ON tool_runs(hunt_id, status);
```

### Upsert Strategy Per Table

The key principle: **UNIQUE constraints define identity; upserts update mutable fields and merge list fields.**

| Table | Identity (UNIQUE) | On conflict: update | On conflict: merge | On conflict: preserve |
|---|---|---|---|---|
| subdomains | `(hunt_id, subdomain)` | `last_seen_at` | `sources` (JSON array) | `first_seen_at` |
| hosts | `(hunt_id, host, port, scheme)` | All mutable fields (status_code, title, webserver, technologies, etc.), `last_seen_at`, `last_checked_at` | — | `first_seen_at` |
| ports | `(hunt_id, host, port, protocol)` | `ip`, `last_seen_at` | — | `first_seen_at` |
| urls | `(hunt_id, url, method)` | `status_code` (only if new value is non-null), `last_seen_at` | `sources` (JSON array) | `first_seen_at` |
| technologies | `(hunt_id, host, name)` | `version` (only if non-empty), `detail` (only if non-empty), `last_seen_at` | `sources` (JSON array) | `first_seen_at` |
| directories | `(hunt_id, url)` | All fields (status may change on rescan), `last_seen_at` | — | `first_seen_at` |

**Source merging** uses SQLite's `json_each` and `json_group_array` functions (available in SQLite 3.38+, bundled with Python 3.11+):

```sql
-- Example: merge a new source into subdomains.sources
ON CONFLICT(hunt_id, subdomain) DO UPDATE SET
    sources = (
        SELECT json_group_array(DISTINCT value) FROM (
            SELECT value FROM json_each(subdomains.sources)
            UNION ALL
            SELECT ?  -- new source
        ) WHERE value != ''
    ),
    last_seen_at = excluded.last_seen_at
```

**Batch writes** use a single transaction for performance:

```python
def upsert_records(self, hunt_id: str, table: str, records: list[dict], source: str = ""):
    """Batch upsert. Wraps all writes in a single transaction."""
    with self._conn:  # auto-commit/rollback
        for record in records:
            self._upsert_one(hunt_id, table, record, source)
```

### Query Methods

The context provides query methods that high-level tools and the CLI use:

```python
class HuntContext:
    # CRUD
    def create_hunt(self, hunt: Hunt) -> str
    def get_hunt(self, hunt_id: str) -> Hunt
    def list_hunts(self) -> list[Hunt]
    def update_hunt_status(self, hunt_id: str, status: HuntStatus) -> None

    # Asset queries
    def get_subdomains(self, hunt_id: str) -> list[dict]
    def get_hosts(self, hunt_id: str, alive_only: bool = False) -> list[dict]
    def get_ports(self, hunt_id: str, host: str | None = None) -> list[dict]
    def get_urls(self, hunt_id: str, host: str | None = None) -> list[dict]
    def get_technologies(self, hunt_id: str, host: str | None = None) -> list[dict]
    def get_directories(self, hunt_id: str, url_prefix: str | None = None) -> list[dict]

    # Tool run queries
    def get_tool_runs(self, hunt_id: str) -> list[dict]
    def log_tool_run(self, hunt_id: str, result: ToolResult) -> int

    # Persistence
    def upsert_subdomain(self, hunt_id: str, subdomain: str, root_domain: str, source: str)
    def upsert_host(self, hunt_id: str, record: dict)
    def upsert_port(self, hunt_id: str, record: dict)
    def upsert_url(self, hunt_id: str, record: dict)
    def upsert_technology(self, hunt_id: str, host: str, tech: dict, source: str)
    def upsert_directory(self, hunt_id: str, record: dict)
    def upsert_records(self, hunt_id: str, table: str, records: list[dict], source: str)

    # Statistics
    def get_hunt_stats(self, hunt_id: str) -> dict
    # Returns: {"subdomains": 142, "hosts_alive": 87, "ports": 234, "urls": 1893, ...}
```

### Data Directory

```
~/.boba/
├── boba.db             # Main SQLite database (all hunts share one DB)
└── tmp/                # Temporary files for tool I/O (auto-cleaned)
```

Configurable via `BOBA_DATA_DIR` environment variable or `--data-dir` CLI flag.

---

## 7. Async Subprocess Utility

> File: `src/boba/core/subprocess.py`

All adapters delegate process execution to this module. It handles: async execution, stdout/stderr capture, timeouts, stdin piping, and streaming for long-running tools.

### Core Function

```python
async def run_subprocess(
    cmd: list[str],
    timeout_seconds: int = 300,
    env_vars: dict[str, str] | None = None,
    stdin_data: str | None = None,
    on_stdout_line: Callable[[str], None] | None = None,
) -> SubprocessResult:
    """
    Execute a subprocess asynchronously.

    - Captures stdout and stderr line-by-line (memory-bounded)
    - Supports optional stdin piping (for tools that read from stdin)
    - Supports streaming callback for incremental processing
    - On timeout: sends SIGKILL, preserves partial output
    """
```

### Streaming Variant

```python
async def run_subprocess_streaming(
    cmd: list[str],
    timeout_seconds: int = 300,
    env_vars: dict[str, str] | None = None,
) -> AsyncIterator[str]:
    """
    Yield stdout lines as they arrive.
    For long-running tools (katana, ffuf) where incremental results are useful.
    """
```

### Design Decisions

- **Line-by-line reading** instead of `communicate()` — bounds memory for tools producing megabytes of output
- **SIGKILL on timeout** (not SIGTERM) — Go-based tools can take a long time to flush on SIGTERM; for a hard timeout, kill is correct. Partial output already captured is preserved.
- **Stdin support** for tools that accept piped input (e.g., `echo "domains" | httpx`) — but temp files are preferred for large inputs (no pipe buffer limits)
- **Streaming** for katana/ffuf — enables persisting results incrementally as they arrive during long runs

---

## 8. Base Adapter

> File: `src/boba/adapters/base.py`

The adapter pattern is the backbone of V1. Every CLI tool wrapper inherits from `BaseAdapter` and implements a defined lifecycle.

### Adapter Lifecycle Phases

```
find_binary() → pre_filter_targets() → build_command() → run_subprocess()
    → parse_output() → post_filter_records() → return ToolResult
```

### Abstract Base Class

```python
class BaseAdapter(ABC):
    """Abstract base for all CLI tool adapters."""

    # ── Class-level metadata (subclasses override) ──
    TOOL_NAME: str                    # "subfinder", "httpx", etc.
    BINARY_NAMES: list[str]           # ["subfinder"] — for binary discovery
    OUTPUT_FORMAT: OutputFormat        # How the tool emits output
    PRODUCES: str                     # Entity type: "subdomain", "host", "port", "url", etc.
    SCOPE_MODE: str                   # "pre", "post", or "both"

    def __init__(self, scope_engine: ScopeEngine):
        self._scope = scope_engine
        self._binary_path: Path | None = None
        self._temp_files: list[Path] = []

    # ── Phase 1: Binary discovery ──
    def find_binary(self) -> Path:
        """Locate the tool binary. Searches: PATH → ~/go/bin → ~/.local/bin."""

    @abstractmethod
    def install_hint(self) -> str:
        """Return installation command for the tool."""

    # ── Phase 2: Input preparation ──
    def _create_temp_file(self, lines: list[str], suffix: str = ".txt") -> Path:
        """Write targets to a temp file for tools that read from -l file."""

    def _cleanup_temp_files(self):
        """Remove all temp files created during this run."""

    # ── Phase 3: Command construction ──
    @abstractmethod
    def build_command(self, targets: list[str], config: AdapterConfig) -> tuple[list[str], Path | None]:
        """
        Build CLI argv list.
        Returns: (command, output_file_path_or_None)
        output_file_path for tools like ffuf/whatweb that write to a file.
        """

    # ── Phase 4: Scope enforcement ──
    def pre_filter_targets(self, targets: list[str]) -> list[str]:
        """Filter input targets against scope."""

    def post_filter_records(self, records: list[dict]) -> tuple[list[dict], int]:
        """Filter output records against scope. Returns (kept, removed_count)."""

    @abstractmethod
    def extract_scope_target(self, record: dict) -> str | None:
        """Extract the value from a parsed record for scope checking."""

    # ── Phase 5: Output parsing ──
    @abstractmethod
    def parse_record(self, raw: dict | str) -> dict:
        """Normalize one raw output record into Boba's canonical schema."""

    def parse_output(self, stdout: str, output_file: Path | None = None) -> list[dict]:
        """Parse full tool output. Delegates to parse_record per line/item."""
        # Handles JSON_LINES, JSON_OBJECT, PLAIN_LINES, JSON_ARRAY
        # based on self.OUTPUT_FORMAT

    # ── Phase 6: Orchestration ──
    async def run(self, targets: list[str], config: AdapterConfig | None = None) -> ToolResult:
        """
        Full lifecycle execution:
        1. find_binary()
        2. pre_filter if SCOPE_MODE in (pre, both)
        3. build_command()
        4. run_subprocess()
        5. parse_output()
        6. post_filter if SCOPE_MODE in (post, both)
        7. cleanup temp files
        8. return ToolResult
        """
```

### Binary Discovery Order

1. `shutil.which()` — respects PATH
2. `~/go/bin/` — where `go install` places Go tools (most of these are Go-based)
3. `~/.local/bin/` — common user install location

Each adapter's `install_hint()` returns the exact install command (usually `go install ...@latest`).

### Output Parsing Strategy

The base class `parse_output()` handles all 4 formats generically:

| Format | Tools | Parsing |
|--------|-------|---------|
| `JSON_LINES` | subfinder, httpx, naabu, katana | Split by newline, `json.loads()` each line, skip malformed |
| `JSON_OBJECT` | ffuf | `json.loads()` whole output, extract `results` array |
| `PLAIN_LINES` | gau, waybackurls | Split by newline, pass raw string to `parse_record()` |
| `JSON_ARRAY` | whatweb | `json.loads()` whole output (it's a JSON array), iterate |

---

## 9. Individual Tool Adapters

Each adapter section specifies: command construction, exact JSON output fields, canonical record mapping, and scope target extraction.

### 9.1 subfinder

> File: `src/boba/adapters/subfinder.py`

**Purpose:** Passive subdomain discovery from multiple sources (certificate transparency, search engines, DNS datasets).

| Property | Value |
|---|---|
| TOOL_NAME | `"subfinder"` |
| BINARY_NAMES | `["subfinder"]` |
| OUTPUT_FORMAT | `JSON_LINES` |
| PRODUCES | `"subdomain"` |
| SCOPE_MODE | `"post"` |
| Install | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |

**Command construction:**
```python
def build_command(self, targets, config):
    cmd = [str(self._binary_path), "-json", "-silent"]
    if len(targets) == 1:
        cmd.extend(["-d", targets[0]])
    else:
        input_file = self._create_temp_file(targets)
        cmd.extend(["-dL", str(input_file)])
    if config.rate_limit:
        cmd.extend(["-rl", str(config.rate_limit)])
    cmd.extend(["-all"])  # Use all sources
    cmd.extend(config.extra_args)
    return cmd, None
```

**JSON output per line:**
```json
{"host": "api.example.com", "input": "example.com", "source": "crtsh"}
```

**Canonical mapping:**
```python
def parse_record(self, raw: dict) -> dict:
    return {
        "subdomain": raw["host"],
        "root_domain": raw.get("input", ""),
        "source": raw.get("source", "unknown"),
    }

def extract_scope_target(self, record: dict) -> str | None:
    return record.get("subdomain")
```

---

### 9.2 httpx (ProjectDiscovery)

> File: `src/boba/adapters/httpx_runner.py`

**Purpose:** Probe discovered subdomains for live HTTP services. Returns status codes, titles, technologies, web server info.

| Property | Value |
|---|---|
| TOOL_NAME | `"httpx"` |
| BINARY_NAMES | `["httpx"]` |
| OUTPUT_FORMAT | `JSON_LINES` |
| PRODUCES | `"host"` |
| SCOPE_MODE | `"both"` |
| Install | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` |

**Command construction:**
```python
def build_command(self, targets, config):
    input_file = self._create_temp_file(targets)
    cmd = [
        str(self._binary_path),
        "-l", str(input_file),
        "-json",
        "-silent",
        "-status-code",
        "-title",
        "-tech-detect",
        "-webserver",
        "-content-length",
        "-content-type",
        "-follow-redirects",
        "-tls-grab",
    ]
    if config.rate_limit:
        cmd.extend(["-rl", str(config.rate_limit)])
    cmd.extend(config.extra_args)
    return cmd, None
```

**JSON output per line:**
```json
{
  "url": "https://api.example.com",
  "input": "api.example.com",
  "status_code": 200,
  "title": "API Documentation",
  "webserver": "nginx",
  "content_length": 15234,
  "content_type": "text/html",
  "tech": ["Nginx", "React", "Node.js"],
  "host": "93.184.216.34",
  "port": "443",
  "scheme": "https",
  "final_url": "https://api.example.com/docs",
  "failed": false,
  "tls": {"version": "tls13"}
}
```

**Canonical mapping:**
```python
def parse_record(self, raw: dict) -> dict:
    return {
        "host": raw.get("input", ""),
        "ip": raw.get("a", [""])[0] if raw.get("a") else raw.get("host", ""),
        "port": int(raw.get("port", 0)) or None,
        "scheme": raw.get("scheme", ""),
        "url": raw.get("url", ""),
        "status_code": raw.get("status_code"),
        "title": raw.get("title", ""),
        "webserver": raw.get("webserver", ""),
        "content_length": raw.get("content_length"),
        "content_type": raw.get("content_type", ""),
        "technologies": raw.get("tech", []),
        "tls_version": raw.get("tls", {}).get("version", ""),
        "final_url": raw.get("final_url", ""),
    }

def extract_scope_target(self, record: dict) -> str | None:
    # Check both the original host and the final URL (after redirects)
    return record.get("host") or record.get("url")
```

**Note on SCOPE_MODE `"both"`:** Pre-filter ensures we only probe in-scope hosts. Post-filter catches cases where a redirect leads to an out-of-scope domain (e.g., `app.example.com` redirects to `login.third-party.com`).

---

### 9.3 naabu

> File: `src/boba/adapters/naabu.py`

**Purpose:** Fast port scanning on discovered hosts.

| Property | Value |
|---|---|
| TOOL_NAME | `"naabu"` |
| BINARY_NAMES | `["naabu"]` |
| OUTPUT_FORMAT | `JSON_LINES` |
| PRODUCES | `"port"` |
| SCOPE_MODE | `"pre"` |
| Install | `go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` |

**Command construction:**
```python
def build_command(self, targets, config):
    input_file = self._create_temp_file(targets)
    cmd = [
        str(self._binary_path),
        "-l", str(input_file),
        "-json",
        "-silent",
    ]
    # Optional: specific port range
    if "ports" in config.extra_args_dict:
        cmd.extend(["-p", config.extra_args_dict["ports"]])
    if config.rate_limit:
        cmd.extend(["-rate", str(config.rate_limit)])
    cmd.extend(config.extra_args)
    return cmd, None
```

**JSON output per line:**
```json
{"host": "api.example.com", "ip": "93.184.216.34", "port": 443, "timestamp": "..."}
```

**Canonical mapping:**
```python
def parse_record(self, raw: dict) -> dict:
    return {
        "host": raw.get("host", ""),
        "ip": raw.get("ip", ""),
        "port": raw.get("port", 0),
        "protocol": raw.get("protocol", "tcp"),
    }

def extract_scope_target(self, record: dict) -> str | None:
    return record.get("host")
```

---

### 9.4 gau (GetAllUrls)

> File: `src/boba/adapters/gau.py`

**Purpose:** Fetch historical URLs from Wayback Machine, Common Crawl, OTX, URLScan.

| Property | Value |
|---|---|
| TOOL_NAME | `"gau"` |
| BINARY_NAMES | `["gau"]` |
| OUTPUT_FORMAT | `PLAIN_LINES` |
| PRODUCES | `"url"` |
| SCOPE_MODE | `"post"` |
| Install | `go install -v github.com/lc/gau/v2/cmd/gau@latest` |

**Command construction:**
```python
def build_command(self, targets, config):
    # gau reads domains from stdin or as positional args
    cmd = [str(self._binary_path)]
    cmd.extend(targets)  # gau domain1 domain2 ...
    cmd.extend(config.extra_args)
    return cmd, None
```

**Output:** Plain text, one URL per line.

**Canonical mapping:**
```python
def parse_record(self, raw: str) -> dict:
    from urllib.parse import urlparse
    parsed = urlparse(raw.strip())
    return {
        "url": raw.strip(),
        "host": parsed.hostname or "",
        "path": parsed.path,
        "query": parsed.query,
        "source": "gau",
    }

def extract_scope_target(self, record: dict) -> str | None:
    return record.get("url")  # Scope engine extracts hostname from URL
```

---

### 9.5 waybackurls

> File: `src/boba/adapters/waybackurls.py`

**Purpose:** Fetch URLs from the Wayback Machine specifically.

| Property | Value |
|---|---|
| TOOL_NAME | `"waybackurls"` |
| BINARY_NAMES | `["waybackurls"]` |
| OUTPUT_FORMAT | `PLAIN_LINES` |
| PRODUCES | `"url"` |
| SCOPE_MODE | `"post"` |
| Install | `go install -v github.com/tomnomnom/waybackurls@latest` |

**Command construction:**
```python
def build_command(self, targets, config):
    # waybackurls reads from stdin: echo "domain" | waybackurls
    # We'll use stdin_data in the subprocess call
    cmd = [str(self._binary_path)]
    cmd.extend(config.extra_args)
    return cmd, None
    # Note: targets are passed via stdin_data in the run() override
```

**Special handling:** waybackurls reads domains from stdin. The adapter overrides `run()` to pass targets as `stdin_data` to the subprocess:

```python
async def run(self, targets, config=None):
    # Override to pipe targets via stdin
    stdin_data = "\n".join(targets)
    # ... pass stdin_data to run_subprocess
```

**Output:** Plain text, one URL per line. Same canonical mapping as gau (with `"source": "waybackurls"`).

---

### 9.6 whatweb

> File: `src/boba/adapters/whatweb.py`

**Purpose:** Technology fingerprinting — identify web servers, frameworks, CMS, JS libraries.

| Property | Value |
|---|---|
| TOOL_NAME | `"whatweb"` |
| BINARY_NAMES | `["whatweb"]` |
| OUTPUT_FORMAT | `JSON_ARRAY` |
| PRODUCES | `"technology"` |
| SCOPE_MODE | `"pre"` |
| Install | `gem install whatweb` (or package manager) |

**Command construction:**
```python
def build_command(self, targets, config):
    import tempfile
    output_file = Path(tempfile.mktemp(suffix=".json", prefix="boba_whatweb_"))
    input_file = self._create_temp_file(targets)
    cmd = [
        str(self._binary_path),
        "--input-file", str(input_file),
        "--log-json", str(output_file),
        "-a", "3",               # Aggression level 3 (stealthy but thorough)
        "--quiet",
    ]
    cmd.extend(config.extra_args)
    return cmd, output_file
```

**JSON output (array in file):**
```json
[
  {
    "target": "https://api.example.com",
    "http_status": 200,
    "plugins": {
      "HTTPServer": {"string": ["nginx/1.18.0"]},
      "Title": {"string": ["API Docs"]},
      "jQuery": {"version": ["3.6.0"]},
      "Bootstrap": {"version": ["5.1"]}
    }
  }
]
```

**Canonical mapping:**
```python
def parse_record(self, raw: dict) -> dict:
    technologies = []
    for name, details in raw.get("plugins", {}).items():
        tech = {"name": name}
        if "version" in details and details["version"]:
            tech["version"] = details["version"][0]
        if "string" in details and details["string"]:
            tech["detail"] = details["string"][0]
        technologies.append(tech)
    return {
        "url": raw.get("target", ""),
        "host": urlparse(raw.get("target", "")).hostname or "",
        "status_code": raw.get("http_status"),
        "technologies": technologies,
    }
```

**Persistence note:** Each technology in the array is persisted separately via `upsert_technology()`, keyed on `(hunt_id, host, name)`.

---

### 9.7 katana

> File: `src/boba/adapters/katana.py`

**Purpose:** Modern web crawler — follows links, parses JS, discovers endpoints in JS-heavy SPAs.

| Property | Value |
|---|---|
| TOOL_NAME | `"katana"` |
| BINARY_NAMES | `["katana"]` |
| OUTPUT_FORMAT | `JSON_LINES` |
| PRODUCES | `"url"` |
| SCOPE_MODE | `"both"` |
| Install | `go install -v github.com/projectdiscovery/katana/cmd/katana@latest` |

**Command construction:**
```python
def build_command(self, targets, config):
    input_file = self._create_temp_file(targets)
    cmd = [
        str(self._binary_path),
        "-list", str(input_file),
        "-json",
        "-silent",
        "-js-crawl",           # Parse JavaScript for endpoints
        "-known-files", "all", # Check for robots.txt, sitemap.xml, etc.
        "-depth", "3",         # Crawl depth
    ]
    if config.rate_limit:
        cmd.extend(["-rl", str(config.rate_limit)])
    cmd.extend(config.extra_args)
    return cmd, None
```

**JSON output per line:**
```json
{
  "endpoint": "https://example.com/api/v2/users",
  "source": "https://example.com/app.js",
  "tag": "script",
  "attribute": "src"
}
```

**Canonical mapping:**
```python
def parse_record(self, raw: dict) -> dict:
    endpoint = raw.get("endpoint", "")
    parsed = urlparse(endpoint)
    return {
        "url": endpoint,
        "host": parsed.hostname or "",
        "path": parsed.path,
        "query": parsed.query,
        "found_on": raw.get("source", ""),
        "method": raw.get("request", {}).get("method", "GET"),
        "status_code": raw.get("response", {}).get("status_code"),
        "source": "katana",
    }

def extract_scope_target(self, record: dict) -> str | None:
    return record.get("url")
```

**SCOPE_MODE `"both"`:** Pre-filter validates seed URLs. Post-filter catches crawled URLs that escape scope (e.g., external links, third-party CDN URLs).

---

### 9.8 ffuf

> File: `src/boba/adapters/ffuf.py`

**Purpose:** Directory, file, and parameter fuzzing with wordlists.

| Property | Value |
|---|---|
| TOOL_NAME | `"ffuf"` |
| BINARY_NAMES | `["ffuf"]` |
| OUTPUT_FORMAT | `JSON_OBJECT` |
| PRODUCES | `"directory"` |
| SCOPE_MODE | `"pre"` |
| Install | `go install -v github.com/ffuf/ffuf/v2@latest` |

**Command construction:**
```python
def build_command(self, targets, config):
    # targets[0] is the URL with FUZZ keyword, e.g., "https://example.com/FUZZ"
    import tempfile
    output_file = Path(tempfile.mktemp(suffix=".json", prefix="boba_ffuf_"))
    url = targets[0]
    wordlist = config.extra_args_dict.get("wordlist", self._default_wordlist())
    cmd = [
        str(self._binary_path),
        "-u", url,
        "-w", wordlist,
        "-o", str(output_file),
        "-of", "json",
        "-mc", config.extra_args_dict.get("match_codes", "200,301,302,403"),
        "-silent",
    ]
    if config.rate_limit:
        cmd.extend(["-rate", str(config.rate_limit)])
    cmd.extend(config.extra_args)
    return cmd, output_file
```

**JSON output (single object in file):**
```json
{
  "results": [
    {
      "input": {"FUZZ": "admin"},
      "status": 200,
      "length": 1523,
      "words": 234,
      "lines": 45,
      "content-type": "text/html",
      "url": "https://example.com/admin",
      "redirectlocation": "",
      "duration": 125000000
    }
  ]
}
```

**Canonical mapping:**
```python
def parse_record(self, raw: dict) -> dict:
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

def extract_scope_target(self, record: dict) -> str | None:
    return record.get("url")
```

**Wordlist note:** ffuf requires an external wordlist. V1 expects the user to provide the path. A sensible default can check for SecLists at common locations: `/usr/share/seclists/`, `~/SecLists/`, etc.

---

## 10. High-Level Tools

> Files: `src/boba/tools/recon.py`, `src/boba/tools/enum.py`

High-level tools compose adapters + scope + context into the user-facing API. They add: context-aware defaults (pull targets from DB when not specified), parallel execution, deduplication, and result persistence.

### recon.subdomains

```python
async def subdomains(context: HuntContext, hunt: Hunt, domains: list[str]) -> ToolResult:
    """
    Discover subdomains using subfinder.
    - Runs subfinder with all sources
    - Scope-filters results (post)
    - Persists to subdomains table (upsert, merges sources)
    - Returns ToolResult with deduplication stats
    """
    adapter = SubfinderAdapter(scope_engine=ScopeEngine(hunt.scope))
    result = await adapter.run(targets=domains)
    context.upsert_records(hunt.id, "subdomain", result.records, source="subfinder")
    context.log_tool_run(hunt.id, result)
    return result
```

### recon.hosts

```python
async def hosts(context: HuntContext, hunt: Hunt, targets: list[str] | None = None) -> ToolResult:
    """
    Check which subdomains are live.
    - If no targets given, pulls all subdomains from context
    - Runs httpx with tech detection, title, status codes
    - Persists to hosts table
    """
    if targets is None:
        subs = context.get_subdomains(hunt.id)
        targets = [s["subdomain"] for s in subs]
    adapter = HttpxRunnerAdapter(scope_engine=ScopeEngine(hunt.scope))
    result = await adapter.run(targets=targets)
    context.upsert_records(hunt.id, "host", result.records)
    context.log_tool_run(hunt.id, result)
    return result
```

### recon.ports

```python
async def ports(context: HuntContext, hunt: Hunt,
                targets: list[str] | None = None,
                port_range: str | None = None) -> ToolResult:
    """
    Port scan live hosts.
    - If no targets, pulls alive hosts from context
    - Runs naabu
    - Persists to ports table
    """
    if targets is None:
        alive = context.get_hosts(hunt.id, alive_only=True)
        targets = list({h["host"] for h in alive})
    config = AdapterConfig()
    if port_range:
        config.extra_args.extend(["-p", port_range])
    adapter = NaabuAdapter(scope_engine=ScopeEngine(hunt.scope))
    result = await adapter.run(targets=targets, config=config)
    context.upsert_records(hunt.id, "port", result.records)
    context.log_tool_run(hunt.id, result)
    return result
```

### recon.urls

```python
async def urls(context: HuntContext, hunt: Hunt, domains: list[str]) -> ToolResult:
    """
    Discover historical URLs using gau AND waybackurls in parallel.
    - Runs both tools concurrently via asyncio.gather
    - Merges and deduplicates results
    - Persists to urls table (sources merged on conflict)
    """
    scope = ScopeEngine(hunt.scope)
    gau_adapter = GauAdapter(scope_engine=scope)
    wayback_adapter = WaybackurlsAdapter(scope_engine=scope)

    gau_result, wayback_result = await asyncio.gather(
        gau_adapter.run(targets=domains),
        wayback_adapter.run(targets=domains),
    )

    # Persist both (upsert handles dedup, merges sources)
    context.upsert_records(hunt.id, "url", gau_result.records, source="gau")
    context.upsert_records(hunt.id, "url", wayback_result.records, source="waybackurls")

    context.log_tool_run(hunt.id, gau_result)
    context.log_tool_run(hunt.id, wayback_result)

    # Return combined result
    combined = ToolResult(
        tool_name="recon.urls",
        command=[],
        exit_code=0,
        raw_stdout="",
        raw_stderr="",
        duration_seconds=max(gau_result.duration_seconds, wayback_result.duration_seconds),
        records=gau_result.records + wayback_result.records,
        filtered_count=gau_result.filtered_count + wayback_result.filtered_count,
    )
    return combined
```

### recon.tech

```python
async def tech(context: HuntContext, hunt: Hunt, targets: list[str] | None = None) -> ToolResult:
    """
    Fingerprint technology stacks on live hosts.
    - If no targets, pulls alive host URLs from context
    - Runs whatweb
    - Persists each technology to technologies table
    """
    if targets is None:
        alive = context.get_hosts(hunt.id, alive_only=True)
        targets = [h["url"] for h in alive if h.get("url")]
    adapter = WhatwebAdapter(scope_engine=ScopeEngine(hunt.scope))
    result = await adapter.run(targets=targets)
    # Whatweb records contain nested technologies - flatten for persistence
    for record in result.records:
        host = record.get("host", "")
        for tech in record.get("technologies", []):
            context.upsert_technology(hunt.id, host, tech, source="whatweb")
    context.log_tool_run(hunt.id, result)
    return result
```

### enum.directories

```python
async def directories(context: HuntContext, hunt: Hunt,
                      url: str,
                      wordlist: str | None = None,
                      match_codes: str = "200,301,302,403",
                      extensions: list[str] | None = None) -> ToolResult:
    """
    Fuzz for directories and files using ffuf.
    - Requires FUZZ keyword in URL or appends it
    - Persists to directories table
    """
    if "FUZZ" not in url:
        url = url.rstrip("/") + "/FUZZ"
    config = AdapterConfig()
    config.extra_args_dict = {"match_codes": match_codes}
    if wordlist:
        config.extra_args_dict["wordlist"] = wordlist
    if extensions:
        config.extra_args.extend(["-e", ",".join(extensions)])
    adapter = FfufAdapter(scope_engine=ScopeEngine(hunt.scope))
    result = await adapter.run(targets=[url], config=config)
    context.upsert_records(hunt.id, "directory", result.records)
    context.log_tool_run(hunt.id, result)
    return result
```

---

## 11. CLI Design

> File: `src/boba/cli/main.py`

Typer-based CLI with command groups mirroring the tool categories. Every command supports `--format json` for agent consumption and `--format table` (default) for humans.

### Command Tree

```
boba
├── hunt
│   ├── create   --name NAME --scope SCOPE_YAML [--config CONFIG_YAML]
│   ├── list
│   ├── status   HUNT_ID
│   ├── pause    HUNT_ID
│   ├── resume   HUNT_ID
│   └── close    HUNT_ID
├── recon
│   ├── subdomains  HUNT_ID --domain DOMAIN [--domain DOMAIN2]
│   ├── hosts       HUNT_ID [--targets HOST1,HOST2]
│   ├── ports       HUNT_ID [--targets HOST1,HOST2] [--range 1-1000]
│   ├── urls        HUNT_ID --domain DOMAIN [--domain DOMAIN2]
│   └── tech        HUNT_ID [--targets URL1,URL2]
├── enum
│   └── directories HUNT_ID --url URL [--wordlist PATH] [--extensions php,html]
│                   [--match-codes 200,301,302,403]
└── context
    ├── assets      HUNT_ID [--type subdomain|host|port|url|technology|directory]
    ├── subdomains  HUNT_ID
    ├── hosts       HUNT_ID [--alive-only]
    ├── ports       HUNT_ID [--host HOST]
    ├── urls        HUNT_ID [--host HOST]
    ├── tech        HUNT_ID [--host HOST]
    ├── directories HUNT_ID [--url-prefix PREFIX]
    ├── runs        HUNT_ID
    └── stats       HUNT_ID

Global options:
    --format json|table     Output format (default: table)
    --data-dir PATH         Data directory (default: ~/.boba)
    --verbose / -v          Enable debug logging
```

### Output Formatting

> File: `src/boba/cli/formatters.py`

```python
def format_output(data: list[dict] | dict, fmt: str = "table", columns: list[str] | None = None):
    """
    Format data for CLI output.
    - "json": json.dumps with indent=2, to stdout
    - "table": Rich table with auto-detected columns
    """
```

**JSON mode** outputs structured data that agents can parse directly:
```json
{
  "hunt_id": "abc123",
  "tool": "recon.subdomains",
  "stats": {"found": 142, "new": 89, "filtered": 3},
  "records": [
    {"subdomain": "api.example.com", "source": "crtsh"},
    ...
  ]
}
```

**Table mode** uses Rich for human-readable output:
```
┌──────────────────────┬──────────────┬──────────┐
│ Subdomain            │ Source       │ First Seen│
├──────────────────────┼──────────────┼──────────┤
│ api.example.com      │ crtsh        │ 2h ago   │
│ app.example.com      │ virustotal   │ 2h ago   │
│ dev.example.com      │ crtsh        │ 2h ago   │
└──────────────────────┴──────────────┴──────────┘
Found 142 subdomains (89 new, 3 filtered out-of-scope)
```

---

## 12. Implementation Milestones

Ordered by dependency. Each milestone is independently testable.

### Milestone 1: Project Skeleton & Core Models
**Dependencies:** None
**Files:** `pyproject.toml`, all `__init__.py`, `core/models.py`, `core/errors.py`, `core/config.py`
**Deliverable:** Installable package with `pip install -e .`, all types importable.
**Estimated scope:** ~5 files, ~200 lines

### Milestone 2: Hunt Context (SQLite)
**Dependencies:** M1
**Files:** `core/context.py`
**Deliverable:** `HuntContext` class with full schema creation, all CRUD methods, all upsert methods, query methods. Tested with in-memory SQLite.
**Estimated scope:** ~1 file, ~400 lines
**Tests:** `tests/core/test_context.py` — test every upsert (including conflict handling), every query, source merging, batch operations.

### Milestone 3: Scope Engine
**Dependencies:** M1
**Files:** `core/scope.py`
**Deliverable:** `ScopeEngine` with domain wildcard matching, IP/CIDR matching, URL prefix matching, exclusion precedence, YAML loading.
**Estimated scope:** ~1 file, ~200 lines
**Tests:** `tests/core/test_scope.py` — extensive: wildcards, bare domains, CIDR ranges, exclusion precedence, edge cases (ports in targets, URLs, IP-as-hostname).

### Milestone 4: Hunt Management
**Dependencies:** M1, M2, M3
**Files:** `core/hunt.py`
**Deliverable:** Create/list/status/pause/resume/close hunts. Integrates scope loading and context initialization.
**Estimated scope:** ~1 file, ~150 lines
**Tests:** `tests/core/test_hunt.py`

### Milestone 5: Subprocess Utility
**Dependencies:** M1
**Files:** `core/subprocess.py`
**Deliverable:** `run_subprocess()` with timeout, stdin, streaming. `run_subprocess_streaming()` async generator.
**Estimated scope:** ~1 file, ~150 lines
**Tests:** Test with simple commands (`echo`, `cat`, `sleep` for timeout).

### Milestone 6: Base Adapter
**Dependencies:** M1, M3, M5
**Files:** `adapters/base.py`
**Deliverable:** `BaseAdapter` ABC with full lifecycle: binary discovery, temp file management, output parsing for all 4 formats, scope integration hooks.
**Estimated scope:** ~1 file, ~250 lines
**Tests:** `tests/adapters/test_base.py` — test with a mock adapter subclass.

### Milestone 7: Tool Adapters (Recon)
**Dependencies:** M6
**Files:** `adapters/subfinder.py`, `adapters/httpx_runner.py`, `adapters/naabu.py`, `adapters/gau.py`, `adapters/waybackurls.py`, `adapters/whatweb.py`
**Deliverable:** All 6 recon adapters. Each tested with mocked subprocess output matching real tool JSON.
**Estimated scope:** ~6 files, ~100 lines each
**Tests:** One test file per adapter. Tests mock `run_subprocess` and verify parsing of real tool output samples.

### Milestone 8: Tool Adapters (Enumeration)
**Dependencies:** M6
**Files:** `adapters/katana.py`, `adapters/ffuf.py`
**Deliverable:** Both enumeration adapters.
**Estimated scope:** ~2 files, ~100 lines each
**Tests:** Same pattern as M7.

### Milestone 9: High-Level Tools
**Dependencies:** M2, M4, M7, M8
**Files:** `tools/recon.py`, `tools/enum.py`
**Deliverable:** All high-level tools: `recon.subdomains`, `recon.hosts`, `recon.ports`, `recon.urls`, `recon.tech`, `enum.directories`. Context-aware defaults, parallel execution for `recon.urls`, persistence integration.
**Estimated scope:** ~2 files, ~300 lines total
**Tests:** Integration tests with mocked adapters, verifying context persistence.

### Milestone 10: CLI
**Dependencies:** M4, M9
**Files:** `cli/main.py`, `cli/formatters.py`
**Deliverable:** Full Typer CLI with all commands, `--format json|table`, `--data-dir`, `--verbose`.
**Estimated scope:** ~2 files, ~400 lines
**Tests:** Test CLI output via Typer's CliRunner.

### Dependency Graph

```
M1 (Models/Errors/Config)
├── M2 (Context/SQLite)
│   └── M4 (Hunt Management) ── requires M3
│       └── M9 (High-Level Tools) ── requires M7, M8
│           └── M10 (CLI)
├── M3 (Scope Engine)
│   └── M6 (Base Adapter) ── requires M5
│       ├── M7 (Recon Adapters)
│       └── M8 (Enum Adapters)
└── M5 (Subprocess Utility)
```

**Parallelizable work:**
- M2 and M3 can be built in parallel (both depend only on M1)
- M5 can be built in parallel with M2/M3
- M7 and M8 can be built in parallel (both depend only on M6)

---

## 13. Testing Strategy

### Unit Tests (no external tools required)

| Component | What to Test | Mocking |
|---|---|---|
| ScopeEngine | Wildcard matching, CIDR, exclusion precedence, edge cases | None needed |
| HuntContext | CRUD, upserts, source merging, batch writes, query methods | In-memory SQLite (`:memory:`) |
| Hunt management | Create/list/status lifecycle | In-memory context |
| BaseAdapter | Binary discovery, temp file management, output parsing (all 4 formats) | Mock subprocess, mock scope |
| Each adapter | Command construction, record parsing, scope target extraction | Mock subprocess with real tool output samples |
| High-level tools | Composition, context persistence, parallel execution | Mock adapters |
| CLI | Command parsing, output formatting | Mock tools, CliRunner |

### Test Fixtures

```python
# tests/conftest.py

@pytest.fixture
def tmp_context(tmp_path):
    """HuntContext backed by a temp SQLite database."""
    db_path = str(tmp_path / "test.db")
    return HuntContext(db_path)

@pytest.fixture
def sample_scope():
    """Scope config matching *.example.com, excluding internal.example.com."""
    return ScopeConfig(rules=[
        ScopeRule("*.example.com", ScopeRuleType.DOMAIN, ScopeAction.INCLUDE),
        ScopeRule("example.com", ScopeRuleType.DOMAIN, ScopeAction.INCLUDE),
        ScopeRule("internal.example.com", ScopeRuleType.DOMAIN, ScopeAction.EXCLUDE),
    ])

@pytest.fixture
def sample_hunt(tmp_context, sample_scope):
    """A pre-created hunt for testing."""
    ...
```

### Adapter Test Pattern

Each adapter test includes a `SAMPLE_OUTPUT` constant containing real tool output (captured from actual runs):

```python
# tests/adapters/test_subfinder.py

SAMPLE_OUTPUT = """
{"host":"api.example.com","input":"example.com","source":"crtsh"}
{"host":"app.example.com","input":"example.com","source":"virustotal"}
{"host":"internal.example.com","input":"example.com","source":"crtsh"}
"""

async def test_subfinder_parses_output(mock_subprocess, sample_scope):
    mock_subprocess.return_value = SubprocessResult(
        stdout=SAMPLE_OUTPUT, stderr="", exit_code=0, duration=2.5, timed_out=False
    )
    adapter = SubfinderAdapter(scope_engine=ScopeEngine(sample_scope))
    result = await adapter.run(targets=["example.com"])

    assert len(result.records) == 2   # internal.example.com filtered by scope
    assert result.filtered_count == 1
    assert result.records[0]["subdomain"] == "api.example.com"
```

### Integration Tests (optional, require tools installed)

Marked with `@pytest.mark.integration` and skipped by default. Run with `pytest -m integration`. These test actual tool execution against safe targets (e.g., `scanme.nmap.org` for naabu).

---

## 14. Open Design Decisions

These decisions should be resolved during implementation, not up front:

| Decision | Options | Recommendation |
|---|---|---|
| **Sync vs async context** | HuntContext could be async (aiosqlite) or sync (sqlite3) | Start sync — SQLite writes are fast, and asyncio adds complexity. The adapters are async but context calls are quick sync operations between async tool runs. |
| **Adapter registry** | Explicit imports vs. auto-discovery via entry points | Explicit for V1. A registry dict in `adapters/__init__.py` mapping tool names to classes. |
| **AdapterConfig.extra_args_dict** | Typed per-adapter configs vs. generic dict | Generic dict for V1 to avoid explosion of config classes. Type-safe per-adapter configs can be added in V2 if needed. |
| **Wordlist management** | Bundle defaults vs. require user to provide | Require user paths in V1. Add SecLists auto-detection as a follow-up. |
| **Database per hunt vs. shared** | Separate SQLite files vs. one DB | Shared DB (`~/.boba/boba.db`). Simpler, enables cross-hunt queries. Hunt isolation via `hunt_id` foreign key. |
| **Streaming persistence** | Persist after full run vs. stream records to DB during run | After full run for V1. Streaming persistence (via `on_stdout_line` callback) can be added for long-running tools in a follow-up. |
