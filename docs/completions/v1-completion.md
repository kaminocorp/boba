# Boba V1 Completion Notes — Foundation: Recon & Enumeration

**Date:** 2026-03-31
**Status:** Implemented and tested
**Scope:** 33 Python files, ~3,000 lines of code, 29 passing tests

---

## What Was Implemented

### 1. Project Structure & Packaging

**Files:** `pyproject.toml`, all `__init__.py` files

- Hatchling-based build with `src/` layout
- Python 3.11+ required (for modern typing + SQLite 3.38 JSON functions)
- Dependencies: `typer[all]`, `rich`, `pyyaml`
- Dev dependencies: `pytest`, `pytest-asyncio`, `pytest-cov`, `ruff`
- CLI entry point registered: `boba = boba.cli.main:app`
- Editable install confirmed working: `pip install -e ".[dev]"`

### 2. Core Models (`src/boba/core/models.py`)

All shared type definitions as `dataclass` classes (not ORMs — raw SQL in the context layer):

| Model | Purpose |
|---|---|
| `HuntStatus` | Enum: active, paused, completed |
| `ScopeAction` | Enum: include, exclude |
| `ScopeRuleType` | Enum: domain, ip_range, url_prefix |
| `OutputFormat` | Enum: jsonl, json, plain, json_array |
| `ToolRunStatus` | Enum: running, completed, failed |
| `ScopeRule` | Pattern + type + action |
| `ScopeConfig` | List of ScopeRules |
| `Hunt` | id, name, status, scope, timestamps, config |
| `AdapterConfig` | timeout, extra_args, env_vars, rate_limit |
| `ToolResult` | Standardized result from any adapter |
| `SubprocessResult` | Raw stdout/stderr/exit_code from subprocess |

**Design decision:** Used `dataclasses` over Pydantic for simplicity — V1 doesn't need validation at the model layer since all data flows through typed adapter methods. Can migrate to Pydantic if needed for MCP serialization in future phases.

### 3. Error Hierarchy (`src/boba/core/errors.py`)

```
BobaError
├── ToolNotFoundError    — binary not in PATH
├── ToolTimeoutError     — execution exceeded timeout
├── ToolExecutionError   — non-zero exit (carries exit_code + stderr)
├── ScopeViolationError  — target outside defined scope
└── HuntNotFoundError    — hunt_id doesn't exist in DB
```

### 4. Configuration (`src/boba/core/config.py`)

- Data directory: `~/.boba/` (overridable via `BOBA_DATA_DIR` env var)
- Database: `~/.boba/boba.db` (shared across all hunts)
- Temp files: `~/.boba/tmp/`

### 5. Scope Engine (`src/boba/core/scope.py`)

**What it does:** Determines whether a target (domain, IP, URL) is within the defined scope boundary. Every adapter passes through this before or after execution.

**Evaluation rules:**
1. Exclusions always win (checked first)
2. At least one inclusion must match
3. Default deny if no rule matches

**Matching logic:**
- **Domain wildcards:** `*.example.com` → compiled to regex `^(.+\.)?example\.com$` (matches bare domain + any subdomain depth)
- **IP/CIDR:** Uses stdlib `ipaddress.ip_network()` for range matching
- **URL prefix:** Stripped of trailing `*`, then `startswith()` check. Domain must also pass domain matching (double gate).
- **Auto-detection:** `_guess_entity_type()` inspects the target string to determine if it's a URL, IP, or domain

**YAML loading:** `ScopeEngine.from_yaml(path)` parses scope definition files.

**Per-adapter scope mode** (critical safety design):

| Adapter | Mode | Why |
|---|---|---|
| subfinder | post | Discovers new targets — can't pre-filter unknown data |
| httpx | both | Pre-filter input; post-filter catches redirects escaping scope |
| naabu | pre | Validates targets before sending port scan traffic |
| gau/waybackurls | post | Historical URLs may reference out-of-scope domains |
| whatweb | pre | Validates target before fingerprinting |
| katana | both | Pre-filter seeds; post-filter catches crawled links leaving scope |
| ffuf | pre | Validates target URL before fuzzing |

**Tests:** 15 tests covering wildcards, CIDR, exclusion precedence, URL prefix, edge cases (ports in targets, similar domains, default deny).

### 6. Hunt Context — SQLite Persistence (`src/boba/core/context.py`)

**What it does:** The stateful memory of the hunting process. All tool results persist here. Agents query it to understand what's been discovered.

**SQLite pragmas:**
- `journal_mode = WAL` — concurrent reads during writes
- `foreign_keys = ON` — referential integrity

**8 tables:**

| Table | UNIQUE constraint | Upsert behavior |
|---|---|---|
| `hunts` | `id` | Standard CRUD |
| `scope_rules` | `(hunt_id, pattern, rule_type)` | Insert or ignore |
| `subdomains` | `(hunt_id, subdomain)` | Merge sources via `json_each` + `json_group_array`, preserve `first_seen_at` |
| `hosts` | `(hunt_id, host, port, scheme)` | Update all mutable fields, preserve `first_seen_at` |
| `ports` | `(hunt_id, host, port, protocol)` | Update IP, `last_seen_at` |
| `urls` | `(hunt_id, url, method)` | Merge sources, conditionally update `status_code` |
| `technologies` | `(hunt_id, host, name)` | Conditionally update version/detail, merge sources |
| `directories` | `(hunt_id, url)` | Update all fields on rescan |
| `tool_runs` | Auto-increment | Append-only audit log |

**Source merging** — the key innovation: When subfinder finds `api.example.com` from `crtsh`, and amass later finds it from `virustotal`, the sources array becomes `["crtsh", "virustotal"]` via a single SQL upsert using `json_each()` + `json_group_array(DISTINCT value)`. No read-modify-write cycle.

**Schema fix during implementation:** The plan used `COALESCE()` in UNIQUE constraints (e.g., `UNIQUE(hunt_id, host, COALESCE(port, 0), COALESCE(scheme, ''))`). SQLite doesn't support expressions in UNIQUE constraints. Fixed by making `port` and `scheme` NOT NULL with defaults (`0` and `''`), and the upsert methods coerce `None` to defaults.

**Batch writes:** `upsert_records()` wraps all writes in a single transaction (`with self._conn:`) for performance on batches of hundreds of records.

### 7. Hunt Management (`src/boba/core/hunt.py`)

`HuntManager` class providing:
- `create(name, scope, scope_yaml, config)` → generates 12-char hex ID, persists hunt + scope rules
- `get(hunt_id)` / `list_hunts()` → retrieve from DB
- `pause(hunt_id)` / `resume(hunt_id)` / `close(hunt_id)` → status transitions
- `stats(hunt_id)` → counts per table

### 8. Async Subprocess Utility (`src/boba/core/subprocess.py`)

Two functions:

**`run_subprocess()`** — primary execution method:
- Line-by-line stdout/stderr reading (memory-bounded, unlike `communicate()`)
- Timeout via `asyncio.wait_for()` → SIGKILL on expiry (partial output preserved)
- Optional stdin piping for tools reading from stdin (waybackurls)
- Optional `on_stdout_line` callback for streaming

**`run_subprocess_streaming()`** — async generator yielding stdout lines as they arrive. For long-running tools where incremental processing is useful.

### 9. Base Adapter (`src/boba/adapters/base.py`)

Abstract base class with 6-phase lifecycle:

```
find_binary() → pre_filter_targets() → build_command()
→ _execute() → parse_output() → post_filter_records()
```

**Class-level metadata** each subclass declares:
- `TOOL_NAME`, `BINARY_NAMES`, `OUTPUT_FORMAT`, `PRODUCES`, `SCOPE_MODE`

**Binary discovery:** `shutil.which()` → `~/go/bin/` → `~/.local/bin/`. Falls back with install instructions.

**Temp file management:** `_create_temp_file()` writes targets to temp files for tools accepting `-l file.txt`. Tracked and auto-cleaned in `finally` block.

**Output parsing:** Generic handler for all 4 formats (JSON lines, JSON object, plain lines, JSON array). Delegates per-record normalization to `parse_record()`.

**Override hook:** `_execute()` method allows adapters to customize subprocess execution (e.g., waybackurls overrides to pipe stdin).

### 10. Tool Adapters (8 total)

Each adapter: ~40-80 lines, implements `build_command()`, `parse_record()`, `extract_scope_target()`, `install_hint()`.

| File | Tool | Output Format | Key detail |
|---|---|---|---|
| `subfinder.py` | subfinder | JSON lines | `-d` for single domain, `-dL` for file |
| `httpx_runner.py` | httpx | JSON lines | Named `_runner` to avoid conflict with Python `httpx` lib. Enables `-tech-detect`, `-tls-grab` |
| `naabu.py` | naabu | JSON lines | Optional port range via `extra_args_dict["ports"]` |
| `gau.py` | gau | Plain lines | Domains as positional args |
| `waybackurls.py` | waybackurls | Plain lines | Overrides `_execute()` to pipe domains via stdin |
| `whatweb.py` | whatweb | JSON array | Writes to `--log-json` output file. Nested `plugins` dict flattened to technology list |
| `katana.py` | katana | JSON lines | JS crawling enabled, configurable depth |
| `ffuf.py` | ffuf | JSON object | Writes to `-o` output file. Auto-appends `/FUZZ` if missing. Searches common paths for SecLists wordlists |

**Adapter registry** in `adapters/__init__.py`: Lazy-import dict mapping tool names to classes.

### 11. High-Level Tools

**`tools/recon.py`** — 5 functions:
- `subdomains()` — runs subfinder, persists to context
- `hosts()` — runs httpx. If no targets given, pulls subdomains from context
- `ports()` — runs naabu. If no targets, pulls alive hosts from context
- `urls()` — runs gau + waybackurls **in parallel** via `asyncio.gather()`, merges to context
- `tech()` — runs whatweb. Flattens nested technology records for per-tech persistence

**`tools/enum.py`** — 2 functions:
- `directories()` — runs ffuf against a URL
- `crawl()` �� runs katana. If no targets, pulls alive host URLs from context

**Context-aware defaults:** When `targets=None`, tools automatically query the hunt context for the appropriate data (e.g., `recon.hosts()` pulls all discovered subdomains).

### 12. CLI (`src/boba/cli/main.py`, `src/boba/cli/formatters.py`)

Typer-based CLI with 4 command groups:

```
boba hunt    {create, list, status, pause, resume, close}
boba recon   {subdomains, hosts, ports, urls, tech}
boba enum    {directories}
boba context {subdomains, hosts, ports, urls, tech, directories, runs, stats}
```

**Global options:** `--format json|table`, `--data-dir PATH`

**Output formatting:**
- `--format json` — structured JSON to stdout (for agent consumption)
- `--format table` — Rich tables with auto-detected columns (for humans)

**Resource management:** Every command uses `try/finally` to close the database connection.

### 13. Tests (29 passing)

| Test file | Tests | What's tested |
|---|---|---|
| `test_scope.py` | 15 | Wildcards, CIDR, exclusion precedence, URL prefix, filter_targets, default deny, edge cases |
| `test_context.py` | 11 | Hunt CRUD, subdomain/host/URL upsert, source merging, first_seen preservation, tool run logging, batch upsert |
| `test_subfinder.py` | 3 | JSON parsing, scope filtering, full lifecycle with mocked subprocess |

---

## Deviations from the Plan

| Plan | Actual | Reason |
|---|---|---|
| `COALESCE()` in UNIQUE constraints | `NOT NULL DEFAULT` + direct columns | SQLite doesn't support expressions in UNIQUE constraints |
| Pydantic models | Dataclasses | Simpler for V1; no validation overhead needed at model layer |
| `config.extra_args_dict` not in plan models | Added to `AdapterConfig` | Several adapters need typed config (port range, wordlist path, match codes) beyond raw CLI args |
| `enum.crawl()` not in plan | Added | Katana wrapper naturally belongs in enum tools alongside ffuf |
| Separate test files per adapter | Only subfinder test file for now | Pattern established; other adapters follow same mocking approach |

## What's NOT Implemented (Deferred to V2+)

- Browser/HTTP adapter (Playwright) — V2
- Vulnerability testing tools (test.idor, test.ssrf, etc.) — V2
- Report generation and platform submission — V3
- Program selection and continuous monitoring — V4
- Elephantasm integration for cross-hunt learning — V4
- Streaming persistence (persist records as they arrive during long tool runs)
- SecLists auto-installation
- MCP server wrapper

## How to Verify

```bash
# Install
cd boba && pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Try the CLI
boba hunt create --name "Test"
boba hunt list
boba hunt status <hunt-id>
boba context stats <hunt-id>

# With scope
echo 'rules:
  - pattern: "*.example.com"
    type: domain
    action: include' > /tmp/scope.yaml
boba hunt create --name "Scoped" --scope /tmp/scope.yaml

# JSON output for agents
boba hunt list --format json
```
