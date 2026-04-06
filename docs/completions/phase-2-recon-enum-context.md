# Phase 2 Completion — Recon, Enumeration, Scan & Context Query Tools

**Date:** 2026-04-06
**Scope:** 19 new MCP tools (5 recon + 2 enum + 1 scan + 11 context query), resource pool extensions.
**Test delta:** +32 new tests (66 MCP total), 0 regressions (788 total, up from 756).

---

## What Was Built

Phase 2 delivers the complete **recon → enumerate → scan → query** loop via MCP. Agents can now discover subdomains, probe live hosts, scan ports, harvest URLs, fingerprint technologies, fuzz directories, crawl web apps, run Nuclei scans — and then query all persisted results without re-running tools.

### New Files

| File | Lines | Purpose |
|---|---|---|
| `src/boba/mcp/tools_recon.py` | 78 | 5 recon tools: `recon_subdomains`, `recon_hosts`, `recon_ports`, `recon_urls`, `recon_tech` |
| `src/boba/mcp/tools_enum.py` | 48 | 2 enum tools: `enum_directories`, `enum_crawl` |
| `src/boba/mcp/tools_scan.py` | 38 | 1 scan tool: `scan_nuclei` |
| `src/boba/mcp/tools_context.py` | 113 | 11 context query tools: subdomains, hosts, ports, urls, tech, directories, findings, sessions, http_history, tool_runs, stats |
| `tests/mcp/test_tools_recon.py` | 145 | 9 tests — mock adapters, verify serialization and persistence |
| `tests/mcp/test_tools_enum.py` | 75 | 4 tests — mock ffuf/katana adapters, verify persistence |
| `tests/mcp/test_tools_scan.py` | 85 | 3 tests — mock nuclei adapter, verify finding persistence |
| `tests/mcp/test_tools_context.py` | 300 | 16 tests — seed DB, query via MCP, verify filters/empty/error cases |

### Modified Files

| File | Change |
|---|---|
| `src/boba/mcp/resources.py` | Added `get_context()`, `get_scope_engine()` |
| `src/boba/mcp/server.py` | Added imports for `tools_recon`, `tools_enum`, `tools_scan`, `tools_context` |
| `tests/mcp/conftest.py` | Extended `_patch_resources` to monkeypatch all 5 tool modules |
| `tests/mcp/test_server.py` | Updated tool count assertion from 6 → 25 |

---

## Tool Inventory (25 total)

| Category | Count | Tools |
|---|---|---|
| Hunt management | 6 | `hunt_create`, `hunt_status`, `hunt_list`, `hunt_pause`, `hunt_resume`, `hunt_close` |
| Recon | 5 | `recon_subdomains`, `recon_hosts`, `recon_ports`, `recon_urls`, `recon_tech` |
| Enumeration | 2 | `enum_directories`, `enum_crawl` |
| Scanning | 1 | `scan_nuclei` |
| Context queries | 11 | `context_subdomains`, `context_hosts`, `context_ports`, `context_urls`, `context_tech`, `context_directories`, `context_findings`, `context_sessions`, `context_http_history`, `context_tool_runs`, `context_stats` |

---

## Key Design Decisions

### 1. Thin delegation to existing tool functions

Each MCP tool is 5–10 lines: get context, get hunt, create config, call the library function, serialize. No business logic in the MCP layer — the library functions handle scope construction, adapter lifecycle, persistence, and tool run logging internally. This means the MCP layer is trivially correct if the library is correct.

### 2. `timeout_seconds` as the universal config knob

Every recon/enum/scan tool exposes `timeout_seconds` (default 300). We create a fresh `AdapterConfig(timeout_seconds=...)` per call rather than exposing the full `extra_args`/`extra_args_dict`/`env_vars`/`rate_limit` surface. This keeps the MCP schema agent-friendly. If agents need advanced config, they can use the CLI.

### 3. Context query tools return raw lists, not summaries

Recon/enum/scan tools use `serialize_tool_result()` (summary + records). Context query tools use `serialize_result()` (raw JSON list). The reasoning: query tools return data the agent needs to inspect directly — adding a summary wrapper would just be noise. The agent knows it asked for subdomains; it doesn't need a `{"tool": "query", "records_found": 5}` header.

### 4. Hunt validation in `context_stats`

`get_hunt_stats()` at the library level silently returns zeroes for nonexistent hunts (it's a COUNT query — no rows is valid). The MCP tool adds a `resources.get_hunt(hunt_id)` guard before calling it, so agents get a clear `HuntNotFoundError` instead of a confusing all-zeroes response.

### 5. Test strategy: mock adapters, seed DB directly

Recon/enum/scan tests mock `Adapter.run()` to avoid requiring real binaries (subfinder, naabu, ffuf, etc.) — the same pattern used in `tests/tools/test_recon.py`. Context query tests seed the database directly via `ctx.upsert_records()` then query via MCP tools. Both approaches test the MCP layer's serialization, parameter passing, and persistence behavior without external dependencies.

---

## What This Enables

An agent can now run a complete passive recon flow:

```
1. hunt_create(name="Acme Corp", scope_yaml="scope.yaml")
2. recon_subdomains(hunt_id, domains=["acme.com"])
3. recon_hosts(hunt_id)                          # auto-uses discovered subdomains
4. recon_ports(hunt_id)                          # auto-uses alive hosts
5. recon_urls(hunt_id, domains=["acme.com"])
6. recon_tech(hunt_id)                           # auto-uses alive hosts
7. enum_directories(hunt_id, url="https://acme.com")
8. scan_nuclei(hunt_id, severity="critical,high")
9. context_stats(hunt_id)                        # see what was found
10. context_findings(hunt_id)                     # review scan results
```

Each recon/enum step persists to SQLite, and subsequent tools auto-consume prior results (e.g., `recon_hosts` reads subdomains, `recon_ports` reads alive hosts). Context tools let the agent inspect state at any point.

---

## What's Next (Phase 3)

Phase 3 adds 17 interaction tools: 7 session management, 4 HTTP client, 3 browser, 3 OOB listener. These require extending `ServerResources` with stateful per-hunt HTTP clients, a shared browser instance, and OOB manager lifecycle. This is the phase that delivers Burp Suite parity via MCP.
