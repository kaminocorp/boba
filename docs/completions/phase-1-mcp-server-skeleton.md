# Phase 1 Completion — MCP Server Skeleton & Hunt Management

**Date:** 2026-04-06
**Scope:** MCP server foundation, resource pool, serializers, 6 hunt management tools.
**Test delta:** +34 new tests, 0 regressions (756 total, up from 722).

---

## What Was Built

Phase 1 of the MCP server implementation plan. The FastMCP server starts, lists tools, and manages hunts end-to-end. This validates the full round-trip: agent → MCP tool call → Boba library → SQLite → MCP response → agent.

### New Files

| File | Lines | Purpose |
|---|---|---|
| `src/boba/mcp/__init__.py` | 16 | Entry point for `boba-mcp` command. Reads `BOBA_MCP_TRANSPORT` and `BOBA_MCP_PORT` env vars. Supports STDIO (default) and streamable-http transports. |
| `src/boba/mcp/server.py` | 40 | FastMCP instance (`name="boba"`), module-level `ServerResources`, lifespan context manager for shutdown cleanup. Imports tool modules to register them. |
| `src/boba/mcp/resources.py` | 43 | `ServerResources` class — lazy singleton for `HuntManager`. `get_manager()`, `get_hunt()`, `shutdown()`. Later phases extend this with HTTP clients, browser, sessions, OOB. |
| `src/boba/mcp/serializers.py` | 50 | `serialize_result()` for dataclasses/dicts/lists → JSON. `serialize_tool_result()` for `ToolResult` with summary + records structure. |
| `src/boba/mcp/tools_hunt.py` | 104 | 6 MCP tools: `hunt_create`, `hunt_status`, `hunt_list`, `hunt_pause`, `hunt_resume`, `hunt_close`. |
| `tests/mcp/__init__.py` | 0 | Package marker. |
| `tests/mcp/conftest.py` | 40 | `mcp_resources` (temp-dir-backed), `_patch_resources` (monkeypatches module-level resources), `mcp_server` (patched FastMCP instance). |
| `tests/mcp/test_server.py` | 40 | Tool listing, schema validation, server name, shutdown lifecycle. |
| `tests/mcp/test_serializers.py` | 100 | 10 tests covering dicts, dataclasses, lists, datetimes, scalars, ToolResult success/error/truncation. |
| `tests/mcp/test_resources.py` | 55 | Lazy creation, singleton, delegation, error propagation, shutdown idempotency, DB file creation. |
| `tests/mcp/test_tools_hunt.py` | 105 | End-to-end hunt CRUD via MCP: create, create with scope YAML, list, status with stats, pause/resume/close, terminal state enforcement, persistence round-trip. |

### Modified Files

| File | Change |
|---|---|
| `pyproject.toml` | Added `mcp = ["mcp>=1.0"]` optional dep group. Added `"mcp>=1.0"` to dev deps. Added `boba-mcp = "boba.mcp:main"` entry point. |

---

## Key Design Decisions

### 1. Direct FastMCP `call_tool()` for testing

The MCP Python SDK's `FastMCP` class supports `await mcp.call_tool(name, args)` and `await mcp.list_tools()` without needing a transport layer. This means tests call tools in-process — no STDIO/HTTP overhead, no subprocess, no client/server setup. Tests run in ~0.6s for all 34.

### 2. Module-level `resources` with monkeypatch for test isolation

`server.py` declares `resources = ServerResources(data_dir=...)` at module level. Tools import and use this directly. Tests monkeypatch it to point at a temp directory via the `_patch_resources` fixture. This keeps the production code clean (no dependency injection boilerplate) while making tests fully isolated.

### 3. `HuntManager` as the Phase 1 resource

The plan called for `ServerResources` to hold a `HuntContext` directly. Instead, we wrap `HuntManager` — which already encapsulates `HuntContext` plus hunt creation logic (ID generation, scope YAML parsing, status transitions). This avoids duplicating business logic in the MCP layer.

### 4. Lifespan context manager instead of `on_event`

The MCP SDK v1.27 doesn't have `on_event("shutdown")`. It uses a `lifespan` async context manager on the `FastMCP` constructor — `yield` marks the boundary between startup and shutdown. The shutdown path calls `resources.shutdown()` to release the SQLite connection.

### 5. `serialize_result()` vs `serialize_tool_result()`

Two serializers for two use cases:
- `serialize_result()` — general purpose, handles any dict/dataclass/list. Used by hunt tools that return simple dicts.
- `serialize_tool_result()` — specific to `ToolResult` (the adapter return type). Adds a summary object with record count, duration, filter stats. Used by recon/enum tools in Phase 2+.

---

## What This Enables

An MCP-compatible agent can now:

```
1. hunt_create(name="Acme Corp", scope_yaml="/path/to/scope.yaml")
   → {"hunt_id": "a1b2c3d4e5f6", "name": "Acme Corp", "status": "active", "scope_rules": 3}

2. hunt_status(hunt_id="a1b2c3d4e5f6")
   → {"hunt_id": "...", "name": "...", "status": "active", "stats": {"subdomains": 0, ...}}

3. hunt_list()
   → [{"hunt_id": "...", "name": "Acme Corp", "status": "active", "created_at": "..."}]

4. hunt_pause(hunt_id="a1b2c3d4e5f6") → {"status": "paused"}
5. hunt_resume(hunt_id="a1b2c3d4e5f6") → {"status": "active"}
6. hunt_close(hunt_id="a1b2c3d4e5f6") → {"status": "completed"}
```

---

## What's Next (Phase 2)

Phase 2 adds 19 tools: 5 recon (`recon_subdomains`, `recon_hosts`, `recon_ports`, `recon_urls`, `recon_tech`), 2 enum (`enum_directories`, `enum_crawl`), 1 scan (`scan_nuclei`), and 11 context query tools (`context_subdomains`, `context_hosts`, etc.). These are the data-producing and data-querying tools that give agents the complete recon→enumerate→query loop.

Phase 2 depends on Phase 1's `resources.get_manager()` for hunt lookup and `serialize_tool_result()` for adapter output. No new resource types needed.
