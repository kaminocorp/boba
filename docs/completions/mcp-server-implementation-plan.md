# Boba MCP Server Implementation Plan — Agent-Native Tool Access

## 1. Overview

Boba's tools are currently exposed only through the Typer CLI. While any agent that can execute shell commands can use `boba <command> -f json`, this has real limitations: subprocess overhead per call, string-based JSON parsing, no streaming, no tool schema discovery, and no lifecycle management for stateful resources (HTTP clients, browser sessions, OOB listeners).

An MCP (Model Context Protocol) server is the natural next step. Boba's architecture was explicitly designed for this — the product vision calls it "library-first, MCP-ready." Every tool function is already `async`, returns structured dataclasses, and follows a consistent signature pattern. The MCP server is a thin exposure layer over the existing library, not a rewrite.

### What the MCP Server Delivers

| Capability | Description |
|---|---|
| Tool discovery | Agents see all ~48 Boba tools with typed schemas via MCP's `tools/list` |
| Direct invocation | Agents call tools as native MCP tool calls — no shell, no JSON parsing |
| Stateful sessions | HTTP client, browser, and OOB listener lifecycles managed by the server |
| Structured results | Tool results returned as typed MCP content, not raw stdout |
| Transport flexibility | STDIO for local agents, Streamable HTTP for remote/networked agents |
| Zero Boba changes | The MCP server imports Boba as a library — no modifications to existing code |

### What an Agent Sees After This

```json
{
  "tools": [
    {
      "name": "hunt_create",
      "description": "Create a new hunt with scope boundaries",
      "inputSchema": {
        "type": "object",
        "properties": {
          "name": {"type": "string", "description": "Hunt name"},
          "scope_yaml": {"type": "string", "description": "YAML scope definition"}
        },
        "required": ["name"]
      }
    },
    {
      "name": "recon_subdomains",
      "description": "Discover subdomains for target domains using subfinder",
      "inputSchema": {
        "type": "object",
        "properties": {
          "hunt_id": {"type": "string"},
          "domains": {"type": "array", "items": {"type": "string"}}
        },
        "required": ["hunt_id", "domains"]
      }
    }
  ]
}
```

Every tool the CLI exposes becomes a first-class MCP tool with typed parameters and structured responses. Hermes Agent, Claude Code, or any MCP-compatible agent can operate Boba without knowing it's a CLI tool underneath.

### Architectural Approach

The MCP server is a **separate package** inside the Boba repo, not woven into the existing CLI. This keeps concerns clean:

```
Existing:   CLI (Typer) ──► Boba Library (tools, context, adapters)
New:        MCP Server   ──► Boba Library (tools, context, adapters)
```

Both the CLI and MCP server are thin wrappers calling the same library functions. The MCP server manages resource lifecycles (HuntContext, HttpClient, BrowserManager, SessionManager, OOBManager) that the CLI currently creates per-command.

---

## 2. Project Structure

### New Files

```
src/boba/
├── mcp/
│   ├── __init__.py                  # NEW — package init
│   ├── server.py                    # NEW — FastMCP instance, lifecycle hooks
│   ├── tools_hunt.py                # NEW — hunt management tools
│   ├── tools_recon.py               # NEW — recon tools (subdomains, hosts, ports, urls, tech)
│   ├── tools_enum.py                # NEW — enum tools (directories, crawl)
│   ├── tools_scan.py                # NEW — scan tools (nuclei)
│   ├── tools_interaction.py         # NEW — browser, http, session tools
│   ├── tools_vuln.py                # NEW — 11 vulnerability test tools
│   ├── tools_analysis.py            # NEW — coverage, dedupe, severity, chain, prioritize
│   ├── tools_reporting.py           # NEW — draft, format, poc
│   ├── tools_context.py             # NEW — data query tools (subdomains, hosts, etc.)
│   ├── resources.py                 # NEW — managed resource pool (context, http, browser, etc.)
│   └── serializers.py               # NEW — dataclass → MCP content converters

tests/
├── mcp/
│   ├── __init__.py                  # NEW
│   ├── conftest.py                  # NEW — MCP test fixtures
│   ├── test_server.py               # NEW — server lifecycle, tool listing
│   ├── test_tools_hunt.py           # NEW — hunt management via MCP
│   ├── test_tools_recon.py          # NEW — recon tools via MCP
│   ├── test_tools_enum.py           # NEW — enum tools via MCP
│   ├── test_tools_vuln.py           # NEW — vuln tools via MCP
│   ├── test_tools_analysis.py       # NEW — analysis tools via MCP
│   ├── test_tools_context.py        # NEW — context query tools via MCP
│   ├── test_resources.py            # NEW — resource pool lifecycle
│   └── test_serializers.py          # NEW — serialization correctness
```

### Modified Files

```
pyproject.toml                       # ADD: mcp dependency, boba-mcp entry point, [mcp] optional dep group
```

### New Dependencies

```toml
[project.optional-dependencies]
mcp = [
    "mcp>=1.0",       # MCP Python SDK (FastMCP)
]
dev = [
    # ... existing dev deps ...
    "mcp>=1.0",       # needed for MCP tests
]

[project.scripts]
boba = "boba.cli.main:app"
boba-mcp = "boba.mcp:main"          # NEW — MCP server entry point
```

The `mcp` dependency is optional — users who only want the CLI don't need it. The MCP server is installed via `pip install boba[mcp]`.

---

## 3. Resource Management Architecture

The CLI creates resources per-command and tears them down immediately. The MCP server needs resources that persist across tool calls within a session — an agent calling `recon_subdomains` and then `context_subdomains` expects to read from the same database.

### 3.1 Resource Pool

> `src/boba/mcp/resources.py`

A singleton resource manager that holds:

```python
@dataclass
class ServerResources:
    """Managed resources shared across MCP tool calls."""
    data_dir: Path                                    # SQLite database directory
    context: HuntContext | None = None                 # lazily initialized
    http_clients: dict[str, HttpClient] = field(...)   # keyed by hunt_id
    browser: BrowserManager | None = None              # single browser instance
    session_managers: dict[str, SessionManager] = field(...)  # keyed by hunt_id
    oob_managers: dict[str, OOBManager] = field(...)   # keyed by hunt_id
```

**Lifecycle:**
- `context` is created once on first tool call and reused for all subsequent calls
- `http_clients` are created per-hunt on first interaction tool call
- `browser` is started lazily on first browser tool call, stopped on server shutdown
- `session_managers` and `oob_managers` are created per-hunt on demand

**Cleanup:**
```python
async def shutdown(self) -> None:
    """Release all resources on server stop."""
    for client in self.http_clients.values():
        await client.aclose()
    if self.browser:
        await self.browser.stop()
    for oob in self.oob_managers.values():
        await oob.stop()
```

### 3.2 Server Lifecycle

> `src/boba/mcp/server.py`

```python
from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    name="boba",
    instructions="Boba is an agent-native bug bounty hunting toolkit. "
                 "Use hunt_create to start, then recon/enum/test/analyze/report tools.",
)

resources = ServerResources(data_dir=Path(os.environ.get("BOBA_DATA_DIR", ".")))

@mcp.on_event("shutdown")
async def on_shutdown():
    await resources.shutdown()
```

The `BOBA_DATA_DIR` environment variable sets where SQLite databases live. Defaults to the current working directory.

---

## 4. Serialization Layer

> `src/boba/mcp/serializers.py`

Every Boba tool returns a dataclass. MCP tools return text or structured content. The serialization layer bridges this gap.

### 4.1 Core Serializer

```python
import dataclasses
import json
from typing import Any

def serialize_result(obj: Any) -> str:
    """Convert any Boba result to a JSON string for MCP response."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return json.dumps(dataclasses.asdict(obj), default=str)
    if isinstance(obj, list):
        return json.dumps(
            [dataclasses.asdict(item) if dataclasses.is_dataclass(item) else item for item in obj],
            default=str,
        )
    if isinstance(obj, dict):
        return json.dumps(obj, default=str)
    return str(obj)
```

This handles all return types in the codebase: `ToolResult`, `VulnTestResult`, `CVSSScore`, `CoverageSummary`, `AttackChain`, `ReportDraft`, `PoCPackage`, `list[dict]`, and `list[DedupeGroup]`.

### 4.2 Tool Result Summarization

For large results (e.g., `recon_subdomains` returning 500 records), provide both a summary and full data:

```python
def serialize_tool_result(result: ToolResult) -> str:
    """Serialize ToolResult with a human-readable summary prefix."""
    summary = {
        "tool": result.tool_name,
        "records_found": len(result.records),
        "filtered_out": result.filtered_count,
        "duration_seconds": result.duration_seconds,
        "timed_out": result.timed_out,
    }
    if result.exit_code != 0:
        summary["exit_code"] = result.exit_code
        summary["stderr"] = result.raw_stderr[:500]
    payload = {"summary": summary, "records": result.records}
    return json.dumps(payload, default=str)
```

---

## 5. Implementation Phases

### Phase 1 — Server Skeleton & Hunt Management

**Goal:** MCP server starts, lists tools, manages hunts. Validates the full round-trip: agent → MCP → Boba library → SQLite → MCP → agent.

This phase proves the architecture works before adding the bulk of tools.

#### 5.1 Server Entry Point

> `src/boba/mcp/__init__.py`

```python
def main():
    """Entry point for boba-mcp command."""
    from boba.mcp.server import mcp
    mcp.run()
```

> `src/boba/mcp/server.py`

Create the `FastMCP` instance, initialize `ServerResources`, wire up lifecycle hooks. Import and register tool modules.

```python
import os
from pathlib import Path
from mcp.server.fastmcp import FastMCP
from boba.mcp.resources import ServerResources

mcp = FastMCP(
    name="boba",
    instructions=(
        "Boba is an agent-native bug bounty hunting toolkit. "
        "Start with hunt_create to set up a scoped engagement, "
        "then use recon/enum/test/analyze/report tools."
    ),
)

resources = ServerResources(data_dir=Path(os.environ.get("BOBA_DATA_DIR", ".")))

# Import tool modules to register them with the mcp instance
from boba.mcp import tools_hunt  # noqa: F401, E402
# ... additional tool modules added in later phases
```

#### 5.2 Resource Pool

> `src/boba/mcp/resources.py`

Implement `ServerResources` with:
- `get_context()` — returns shared `HuntContext`, creates on first call
- `get_hunt(hunt_id)` — shorthand for `context.get_hunt(hunt_id)` with error handling
- `shutdown()` — cleanup hook

No interaction resources yet (HTTP client, browser, OOB) — those arrive in Phase 3.

#### 5.3 Serializers

> `src/boba/mcp/serializers.py`

Implement `serialize_result()` and `serialize_tool_result()` as described in Section 4.

#### 5.4 Hunt Management Tools

> `src/boba/mcp/tools_hunt.py`

| MCP Tool | Maps To | Description |
|---|---|---|
| `hunt_create` | `HuntManager.create_hunt()` | Create a new hunt with name and optional scope YAML |
| `hunt_status` | `context.get_hunt()` + `context.get_hunt_stats()` | Get hunt details and discovery counts |
| `hunt_list` | `context.list_hunts()` | List all hunts |
| `hunt_pause` | `context.update_hunt_status()` | Pause an active hunt |
| `hunt_resume` | `context.update_hunt_status()` | Resume a paused hunt |
| `hunt_close` | `context.update_hunt_status()` | Close a completed hunt |

Example tool implementation:

```python
from typing import Annotated
from boba.mcp.server import mcp, resources
from boba.mcp.serializers import serialize_result

@mcp.tool(description="Create a new bug bounty hunt with scope boundaries")
async def hunt_create(
    name: Annotated[str, "Name for the hunt engagement"],
    scope_yaml: Annotated[str | None, "YAML string defining scope rules (inclusions/exclusions)"] = None,
) -> str:
    ctx = resources.get_context()
    hunt = ctx.create_hunt(name=name, scope_yaml=scope_yaml)
    return serialize_result({"hunt_id": hunt.id, "name": hunt.name, "status": hunt.status.value})
```

#### 5.5 pyproject.toml Changes

Add `mcp` optional dependency group and `boba-mcp` entry point.

#### 5.6 Tests

> `tests/mcp/conftest.py`

- Shared fixtures: `tmp_data_dir`, `server_resources` (using `tmp_path`), `mcp_server` (FastMCP test client)

> `tests/mcp/test_server.py`

- Server starts and lists tools
- `tools/list` returns expected tool names and schemas
- Server shutdown cleans up resources

> `tests/mcp/test_tools_hunt.py`

- `hunt_create` → returns hunt ID, hunt exists in SQLite
- `hunt_create` with scope YAML → scope rules persisted
- `hunt_status` → returns stats
- `hunt_list` → returns all hunts
- `hunt_pause` / `hunt_resume` / `hunt_close` → status transitions work
- Error case: invalid hunt ID → clean error message

> `tests/mcp/test_serializers.py`

- `serialize_result` handles: `ToolResult`, `VulnTestResult`, `dict`, `list[dict]`, dataclass with datetime fields
- `serialize_tool_result` produces summary + records structure

**Estimated new tests: ~20**

---

### Phase 2 — Recon, Enumeration, Scan & Context Query Tools

**Goal:** All passive and active discovery tools are available via MCP, plus all context query tools so agents can inspect what's been found.

This phase delivers the complete recon→enumerate→query loop without any interaction or vuln testing.

#### 5.7 Recon Tools

> `src/boba/mcp/tools_recon.py`

| MCP Tool | Maps To | Key Parameters |
|---|---|---|
| `recon_subdomains` | `recon.subdomains()` | `hunt_id`, `domains: list[str]` |
| `recon_hosts` | `recon.hosts()` | `hunt_id`, `targets: list[str] | None` |
| `recon_ports` | `recon.ports()` | `hunt_id`, `targets: list[str] | None`, `port_range: str | None` |
| `recon_urls` | `recon.urls()` | `hunt_id`, `domains: list[str]` |
| `recon_tech` | `recon.tech()` | `hunt_id`, `targets: list[str] | None` |

Each tool:
1. Gets `context` and `hunt` from `resources`
2. Calls the corresponding `recon.*()` async function
3. Returns `serialize_tool_result(result)`

Example:

```python
@mcp.tool(description="Discover subdomains for target domains using subfinder")
async def recon_subdomains(
    hunt_id: Annotated[str, "Hunt ID"],
    domains: Annotated[list[str], "Target domains to enumerate subdomains for"],
    timeout_seconds: Annotated[int, "Timeout in seconds"] = 300,
) -> str:
    ctx = resources.get_context()
    hunt = resources.get_hunt(hunt_id)
    config = AdapterConfig(timeout_seconds=timeout_seconds) if timeout_seconds != 300 else None
    result = await recon.subdomains(ctx, hunt, domains, config=config)
    return serialize_tool_result(result)
```

#### 5.8 Enumeration Tools

> `src/boba/mcp/tools_enum.py`

| MCP Tool | Maps To | Key Parameters |
|---|---|---|
| `enum_directories` | `enum.directories()` | `hunt_id`, `url`, `wordlist`, `match_codes`, `extensions` |
| `enum_crawl` | `enum.crawl()` | `hunt_id`, `targets: list[str] | None`, `depth` |

#### 5.9 Scan Tools

> `src/boba/mcp/tools_scan.py`

| MCP Tool | Maps To | Key Parameters |
|---|---|---|
| `scan_nuclei` | `scan.nuclei_scan()` | `hunt_id`, `targets`, `severity`, `tags`, `templates` |

#### 5.10 Context Query Tools

> `src/boba/mcp/tools_context.py`

These are read-only tools that query the SQLite database without running any external tools.

| MCP Tool | Maps To | Key Parameters |
|---|---|---|
| `context_subdomains` | `context.get_subdomains()` | `hunt_id` |
| `context_hosts` | `context.get_hosts()` | `hunt_id`, `alive_only: bool` |
| `context_ports` | `context.get_ports()` | `hunt_id`, `host: str | None` |
| `context_urls` | `context.get_urls()` | `hunt_id`, `host: str | None` |
| `context_tech` | `context.get_technologies()` | `hunt_id`, `host: str | None` |
| `context_directories` | `context.get_directories()` | `hunt_id`, `url_prefix: str | None` |
| `context_findings` | `context.get_findings()` | `hunt_id`, `severity: str | None` |
| `context_sessions` | `context.get_sessions()` | `hunt_id` |
| `context_http_history` | `context.get_http_history()` | `hunt_id`, `host`, `method`, `limit` |
| `context_tool_runs` | `context.get_tool_runs()` | `hunt_id` |
| `context_stats` | `context.get_hunt_stats()` | `hunt_id` |

These are critical — they let the agent inspect state between tool calls, which is the primary advantage over CLI-based invocation.

#### 5.11 Tests

> `tests/mcp/test_tools_recon.py`

- Each recon tool: mock the adapter's `run()` to avoid needing real binaries, verify tool result serialization, verify records persisted to context
- Error case: missing binary → clean error message with install hint
- Error case: invalid hunt ID → clean error

> `tests/mcp/test_tools_enum.py`

- `enum_directories`: mock ffuf adapter, verify persistence
- `enum_crawl`: mock katana adapter, verify persistence

> `tests/mcp/test_tools_context.py`

- Seed database with known records, verify each `context_*` tool returns them
- Verify filter parameters work (host filter, severity filter, etc.)
- Empty results → empty list, not error

**Estimated new tests: ~35**

---

### Phase 3 — Interaction Tools (Browser, HTTP, Sessions)

**Goal:** Agents can browse targets, send crafted requests, manage auth sessions, and use OOB listeners — all via MCP. This is the phase that delivers Burp Suite parity.

This phase depends on Phase 1 (resources) and adds the stateful resource management for HTTP clients, browser, and OOB.

#### 5.12 Resource Pool Extensions

> `src/boba/mcp/resources.py` — extend `ServerResources`

Add methods:
- `get_http_client(hunt_id)` — creates `HttpClient` per hunt (with `HuntContext` as sink), caches it
- `get_browser()` — lazily starts `BrowserManager`, returns shared instance
- `get_session_manager(hunt_id)` — creates `SessionManager` per hunt, caches it
- `get_oob_manager(hunt_id)` — creates `OOBManager` per hunt, starts it, caches it

Extend `shutdown()` to close all managed clients.

#### 5.13 Session Tools

> `src/boba/mcp/tools_interaction.py`

| MCP Tool | Maps To | Key Parameters |
|---|---|---|
| `session_create` | `SessionManager.create()` | `hunt_id`, `name`, `target_url`, `auth_method` |
| `session_login_token` | `SessionManager.login_bearer()` | `hunt_id`, `session_name`, `token` |
| `session_login_basic` | `SessionManager.login_basic()` | `hunt_id`, `session_name`, `username`, `password` |
| `session_login_cookies` | `SessionManager.login_cookies()` | `hunt_id`, `session_name`, `cookies: dict` |
| `session_login_header` | `SessionManager.login_header()` | `hunt_id`, `session_name`, `header_name`, `header_value` |
| `session_list` | `SessionManager.list_sessions()` | `hunt_id` |
| `session_delete` | `SessionManager.delete()` | `hunt_id`, `session_name` |

#### 5.14 HTTP Tools

| MCP Tool | Maps To | Key Parameters |
|---|---|---|
| `http_request` | `HttpClient.request()` | `hunt_id`, `url`, `method`, `headers: dict`, `body`, `session_name` |
| `http_replay` | `HttpClient.replay()` | `hunt_id`, `request_id`, `modify_headers: dict`, `modify_body` |
| `http_compare` | `HttpClient.compare()` | `hunt_id`, `request_id_a`, `request_id_b` |
| `http_fuzz` | `HttpClient.fuzz()` | `hunt_id`, `template_url`, `injection_points`, `wordlists`, `attack_type` |

Session-aware: if `session_name` is provided, the tool applies the session's headers/cookies before sending.

#### 5.15 Browser Tools

| MCP Tool | Maps To | Key Parameters |
|---|---|---|
| `browser_navigate` | `BrowserManager.navigate()` | `hunt_id`, `url`, `session_name` |
| `browser_screenshot` | `BrowserManager.screenshot()` | `hunt_id`, `url`, `output_path` |
| `browser_extract` | `BrowserManager.extract()` | `hunt_id`, `url` |

Browser tools apply session state (cookies/headers) to the browser context when `session_name` is provided.

#### 5.16 OOB Tools

| MCP Tool | Maps To | Key Parameters |
|---|---|---|
| `oob_create_listener` | `OOBManager.create_listener()` | `hunt_id`, `purpose`, `target_url`, `parameter` |
| `oob_get_payload` | `OOBManager.get_payload_url()` | `callback_domain`, `protocol` |
| `oob_poll` | `OOBManager.poll()` | `hunt_id`, `listener_id`, `timeout_seconds` |

#### 5.17 Tests

> `tests/mcp/test_tools_interaction.py` (split from test_tools_vuln to keep focused)

- Session lifecycle: create → login → use in request → delete
- HTTP request: send request, verify stored in http_history, verify response serialized
- HTTP replay: modify header, verify modified request sent
- HTTP compare: two requests, verify diff structure
- Browser navigate: mock Playwright, verify PageInfo returned
- Browser extract: mock Playwright, verify DOMExtraction structure
- OOB create/poll: mock interactsh, verify listener lifecycle
- Resource cleanup: verify `shutdown()` closes all clients

**Estimated new tests: ~25**

---

### Phase 4 — Vulnerability Testing Tools

**Goal:** All 11 vulnerability test tools available via MCP with consistent parameter patterns.

Depends on Phase 3 (interaction resources — vuln tools need `HttpClient`, `SessionState`, optionally `BrowserManager` and `OOBManager`).

#### 5.18 Vulnerability Test Tools

> `src/boba/mcp/tools_vuln.py`

Each vuln tool follows the same pattern: get resources, resolve sessions, call the test function, serialize the result.

| MCP Tool | Maps To | Key Parameters |
|---|---|---|
| `test_idor` | `vuln.test_idor()` | `hunt_id`, `endpoint`, `session_a`, `session_b`, `method`, `body`, `object_ids` |
| `test_ssrf` | `vuln.test_ssrf()` | `hunt_id`, `url`, `param`, `method`, `session_name` |
| `test_sqli` | `vuln.test_sqli()` | `hunt_id`, `url`, `param`, `method`, `session_name` |
| `test_xss` | `vuln.test_xss()` | `hunt_id`, `url`, `param`, `method`, `check_dom`, `session_name` |
| `test_auth` | `vuln.test_auth()` | `hunt_id`, `endpoint`, `method`, `session_name`, `jwt` |
| `test_race` | `vuln.test_race()` | `hunt_id`, `url`, `method`, `body`, `session_name`, `concurrency` |
| `test_redirect` | `vuln.test_redirect()` | `hunt_id`, `url`, `param`, `session_name` |
| `test_csrf` | `vuln.test_csrf()` | `hunt_id`, `url`, `method`, `body`, `session_name` |
| `test_mass_assign` | `vuln.test_mass_assign()` | `hunt_id`, `url`, `method`, `session_name` |
| `test_reset` | `vuln.test_reset()` | `hunt_id`, `url`, `email_param` |
| `test_ai` | `vuln.test_ai()` | `hunt_id`, `url`, `param`, `method`, `session_name` |

**Parameter simplification:** The CLI already does this — it converts simple string parameters (like `--param url`) into the dicts that the vuln functions expect (`injection_points=[{"param": "url", "location": "query"}]`). The MCP tools do the same translation, keeping the MCP interface agent-friendly while the underlying functions stay flexible.

Example:

```python
@mcp.tool(description="Test an endpoint for SQL injection (error-based, boolean, time-based)")
async def test_sqli(
    hunt_id: Annotated[str, "Hunt ID"],
    url: Annotated[str, "URL to test"],
    param: Annotated[str, "Parameter name to inject into"],
    method: Annotated[str, "HTTP method"] = "GET",
    session_name: Annotated[str | None, "Session name for authenticated testing"] = None,
) -> str:
    ctx = resources.get_context()
    hunt = resources.get_hunt(hunt_id)
    http_client = await resources.get_http_client(hunt_id)
    session = _resolve_session(hunt_id, session_name)
    scope_engine = resources.get_scope_engine(hunt)

    result = await vuln.test_sqli(
        http_client=http_client,
        url=url,
        method=method,
        params={param: "1"},
        session=session,
        scope_engine=scope_engine,
        context=ctx,
        hunt_id=hunt_id,
    )
    return serialize_result(result)
```

#### 5.19 Tests

> `tests/mcp/test_tools_vuln.py`

- Each of 11 vuln tools: mock HttpClient responses, verify `VulnTestResult` serialized correctly
- Session resolution: verify session headers applied to requests
- Scope enforcement: out-of-scope URL → rejection before any requests sent
- Error cases: missing session → clean error, missing required param → schema validation error

**Estimated new tests: ~25**

---

### Phase 5 — Analysis & Reporting Tools

**Goal:** Complete the pipeline — agents can deduplicate, score, chain, check coverage, draft reports, and package PoC evidence.

No new resource types needed. All analysis/reporting tools operate on data already in SQLite.

#### 5.20 Analysis Tools

> `src/boba/mcp/tools_analysis.py`

| MCP Tool | Maps To | Key Parameters |
|---|---|---|
| `analyze_coverage` | `coverage.get_coverage_summary()` | `hunt_id`, `host`, `test_types` |
| `analyze_coverage_gaps` | `coverage.get_coverage_gaps()` | `hunt_id`, `test_types`, `host` |
| `analyze_dedupe` | `dedup.deduplicate_findings()` | `hunt_id`, `dry_run: bool` |
| `analyze_severity` | `severity.score_findings()` | `hunt_id`, `finding_ids`, `platform` |
| `analyze_chain` | `chaining.detect_chains()` | `hunt_id` |
| `analyze_prioritize` | `prioritize.prioritize_endpoints()` | `hunt_id`, `top: int` |

#### 5.21 Reporting Tools

> `src/boba/mcp/tools_reporting.py`

| MCP Tool | Maps To | Key Parameters |
|---|---|---|
| `report_draft` | `draft.draft_finding_report()` or `draft.draft_chain_report()` | `hunt_id`, `finding_id` or `chain_id` |
| `report_format` | `formatter.format_*()` | `hunt_id`, `report_id`, `platform` |
| `report_poc` | `poc.package_poc()` | `hunt_id`, `finding_id` or `chain_id`, `output_dir` |
| `report_list` | `context.get_reports()` | `hunt_id`, `status` |
| `report_show` | `context.get_report()` | `hunt_id`, `report_id` |

#### 5.22 Tests

> `tests/mcp/test_tools_analysis.py`

- Seed database with findings, verify coverage/dedupe/severity/chain/prioritize tools produce correct output
- Dry run dedupe → no side effects
- Chain detection → returns structured `AttackChain` data

> `tests/mcp/test_tools_reporting.py` (part of analysis test file or separate)

- Draft from finding → `ReportDraft` with title, steps, impact
- Draft from chain → multi-finding report
- Format for HackerOne/Bugcrowd/Markdown → platform-specific string
- PoC packaging → verify file structure

**Estimated new tests: ~20**

---

### Phase 6 — Documentation, Packaging & Release

**Goal:** The MCP server is installable, documented, and usable by any MCP-compatible agent.

#### 5.23 Agent Configuration Guide

> `docs/mcp-setup.md`

Documentation for agents and operators covering:

1. **Installation**: `pip install boba[mcp]`
2. **Running**: `boba-mcp` (STDIO) or `BOBA_DATA_DIR=/path boba-mcp` (custom data dir)
3. **Claude Desktop config**:
   ```json
   {
     "mcpServers": {
       "boba": {
         "command": "boba-mcp",
         "env": {"BOBA_DATA_DIR": "/path/to/hunts"}
       }
     }
   }
   ```
4. **Streamable HTTP** (for remote agents):
   ```bash
   BOBA_DATA_DIR=/data BOBA_MCP_TRANSPORT=streamable-http BOBA_MCP_PORT=3000 boba-mcp
   ```
5. **Tool reference**: auto-generated from tool decorators (name, description, parameters)
6. **Complete hunt walkthrough** via MCP tool calls

#### 5.24 Transport Configuration

> `src/boba/mcp/__init__.py` — extend `main()`

Support transport selection via environment variables:

```python
def main():
    from boba.mcp.server import mcp
    transport = os.environ.get("BOBA_MCP_TRANSPORT", "stdio")
    port = int(os.environ.get("BOBA_MCP_PORT", "3000"))
    if transport == "streamable-http":
        mcp.run(transport="streamable-http", port=port)
    else:
        mcp.run()  # defaults to stdio
```

#### 5.25 Update agent-orientation.md

Add an "MCP Access" section to the agent orientation guide explaining that agents can use Boba via MCP instead of CLI, with the same tools and same workflow.

#### 5.26 README / Changelog

- Update README with MCP server section
- Add changelog entry for the MCP server release

#### 5.27 Tests

- Integration test: full hunt workflow via MCP (create → recon → test → analyze → report) using mocked adapters
- Transport test: verify streamable-http starts and accepts connections

**Estimated new tests: ~5**

---

## 6. Tool Count Summary

| Category | Tools | Phase |
|---|---|---|
| Hunt management | 6 | Phase 1 |
| Recon | 5 | Phase 2 |
| Enumeration | 2 | Phase 2 |
| Scanning | 1 | Phase 2 |
| Context queries | 11 | Phase 2 |
| Session management | 7 | Phase 3 |
| HTTP interaction | 4 | Phase 3 |
| Browser | 3 | Phase 3 |
| OOB listeners | 3 | Phase 3 |
| Vulnerability testing | 11 | Phase 4 |
| Analysis | 6 | Phase 5 |
| Reporting | 5 | Phase 5 |
| **Total** | **64** | |

---

## 7. Phase Dependencies & Ordering

```
Phase 1: Server Skeleton & Hunt Management
│   ├── FastMCP instance, resource pool, serializers
│   ├── Hunt CRUD tools (6 tools)
│   └── Tests (~20 new)
│
├──► Phase 2: Recon, Enum, Scan & Context Queries
│       ├── 5 recon + 2 enum + 1 scan + 11 context tools (19 tools)
│       └── Tests (~35 new)
│
├──► Phase 3: Interaction Tools
│       ├── Resource pool extensions (HTTP client, browser, session, OOB)
│       ├── 7 session + 4 HTTP + 3 browser + 3 OOB tools (17 tools)
│       └── Tests (~25 new)
│
│       ├──► Phase 4: Vulnerability Testing
│       │       ├── 11 vuln test tools
│       │       └── Tests (~25 new)
│       │
│       └──► Phase 5: Analysis & Reporting
│               ├── 6 analysis + 5 reporting tools (11 tools)
│               └── Tests (~20 new)
│
└──► Phase 6: Documentation, Packaging & Release
        ├── Agent setup guide, transport config
        ├── README/changelog updates
        └── Tests (~5 new)
```

- **Phase 1** must come first — everything depends on the server skeleton and resource pool
- **Phase 2** depends on Phase 1 (needs context and hunt management)
- **Phase 3** depends on Phase 1 (needs resource pool for stateful clients)
- **Phase 4** depends on Phase 3 (vuln tools need HTTP client, sessions, optionally browser/OOB)
- **Phase 5** depends on Phase 1 only (analysis/reporting work on SQLite data, no interaction resources needed) — can be built in parallel with Phases 3-4
- **Phase 6** should come last (documents the finished product)

**Estimated total new tests: ~130** (bringing project total from 592 to ~722).

---

## 8. Design Decisions & Rationale

### Separate package, not CLI extension

The MCP server lives in `src/boba/mcp/`, not mixed into `src/boba/cli/`. This keeps the CLI and MCP server as independent exposure layers. Users who only want the CLI don't install `mcp` as a dependency.

### Optional dependency group

`pip install boba[mcp]` installs the MCP SDK. Plain `pip install boba` does not. This avoids bloating the base install — the MCP SDK pulls in FastAPI, uvicorn, and other HTTP server dependencies that CLI-only users don't need.

### One tool per action, not composite tools

Each MCP tool maps to one Boba function. We don't create "run full recon pipeline" composite tools. Agents compose tools themselves — that's the "composable primitives" design principle from the product vision.

### hunt_id on every tool

Every tool takes `hunt_id` as first parameter, matching the CLI pattern. This keeps tools stateless from the MCP server's perspective — any tool can operate on any hunt. The server doesn't track "current hunt."

### Environment variables for configuration

`BOBA_DATA_DIR`, `BOBA_MCP_TRANSPORT`, `BOBA_MCP_PORT` — simple, works with Docker, works with Claude Desktop's env config, works with systemd. No config files needed.

### No authentication on the MCP server

MCP servers run locally (STDIO) or behind a reverse proxy. Authentication is an infrastructure concern, not an application concern. If deployed via streamable-http, operators put it behind nginx/Caddy with TLS and auth.
