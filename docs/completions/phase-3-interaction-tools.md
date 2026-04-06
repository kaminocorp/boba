# Phase 3 Completion — Interaction Tools (Sessions, HTTP, Browser, OOB)

**Date:** 2026-04-06
**Scope:** 17 new MCP tools (7 session + 4 HTTP + 3 browser + 3 OOB), full resource lifecycle management.
**Test delta:** +21 new tests (87 MCP total), 0 regressions (809 total, up from 788).

---

## What Was Built

Phase 3 delivers Burp Suite-equivalent interaction capabilities via MCP. Agents can now manage authentication sessions, send crafted HTTP requests, replay and compare responses, fuzz parameters, navigate a headless browser, take screenshots, extract DOM data, and use out-of-band callback listeners for blind vulnerability detection.

### New Files

| File | Lines | Purpose |
|---|---|---|
| `src/boba/mcp/tools_interaction.py` | ~280 | 17 tools: 7 session, 4 HTTP, 3 browser, 3 OOB |
| `tests/mcp/test_tools_interaction.py` | ~310 | 21 tests: session lifecycle, HTTP mock, browser mock, OOB mock, resource cleanup |

### Modified Files

| File | Change |
|---|---|
| `src/boba/mcp/resources.py` | Added `get_http_client()`, `get_session_manager()`, `get_browser()`, `get_oob_manager()`. Extended `shutdown()` to close all interaction resources. Added per-hunt caches for clients/sessions/OOB. |
| `src/boba/mcp/server.py` | Added `tools_interaction` import |
| `tests/mcp/conftest.py` | Added `interaction_mod` to monkeypatch loop |
| `tests/mcp/test_server.py` | Updated tool count 25 → 42, added interaction spot-checks |

---

## Tool Inventory (42 total)

| Category | Count | Tools |
|---|---|---|
| Hunt management | 6 | `hunt_create`, `hunt_status`, `hunt_list`, `hunt_pause`, `hunt_resume`, `hunt_close` |
| Recon | 5 | `recon_subdomains`, `recon_hosts`, `recon_ports`, `recon_urls`, `recon_tech` |
| Enumeration | 2 | `enum_directories`, `enum_crawl` |
| Scanning | 1 | `scan_nuclei` |
| Context queries | 11 | `context_subdomains`, `context_hosts`, `context_ports`, `context_urls`, `context_tech`, `context_directories`, `context_findings`, `context_sessions`, `context_http_history`, `context_tool_runs`, `context_stats` |
| **Session management** | **7** | `session_create`, `session_login_token`, `session_login_basic`, `session_login_cookies`, `session_login_header`, `session_list`, `session_delete` |
| **HTTP client** | **4** | `http_request`, `http_replay`, `http_compare`, `http_fuzz` |
| **Browser** | **3** | `browser_navigate`, `browser_screenshot`, `browser_extract` |
| **OOB listeners** | **3** | `oob_create_listener`, `oob_get_payload`, `oob_poll` |

---

## Key Design Decisions

### 1. Per-hunt resource caching

`ServerResources` maintains `dict[hunt_id, resource]` caches for HTTP clients, session managers, and OOB managers. Each is created lazily on first access and reused for subsequent calls with the same hunt. The browser is global (one Playwright instance shared across hunts). This matches the MCP server's session model — an agent working on one hunt gets a persistent HTTP connection pool, session store, and OOB listener set.

### 2. Session-aware HTTP tools via `_resolve_session()`

The `http_request` and `http_fuzz` tools accept an optional `session_name`. When provided, `_resolve_session()` merges the session's auth headers and cookies into the request parameters before sending. This keeps the tool interface simple (one `session_name` string) while the underlying session application is automatic. The same pattern applies to `browser_navigate` via `browser.apply_session()`.

### 3. Response body truncation in serialization

`_response_to_dict()` caps `body_text` at 5,000 characters. Full response bodies can be megabytes — returning them wholesale in MCP text content would waste agent context window. The `request_id` is always returned, so agents can use `context_http_history` to inspect the full record if needed.

### 4. OOB start-on-first-use with idempotent guard

`oob_create_listener` calls `await oob.start()` wrapped in a try/except. This means the OOB manager starts on first listener creation and is a no-op on subsequent calls. The alternative (starting in `get_oob_manager()`) would require making that method async, which would propagate async up through all callers.

### 5. Browser as a global singleton

Unlike per-hunt HTTP clients, the browser is shared. Playwright startup is expensive (~1-2s), and agents rarely need multiple browser instances. The browser applies session state (cookies/headers) via named contexts, so multi-hunt use is safe. Shutdown is handled by `resources.shutdown()`.

### 6. Graceful shutdown with exception swallowing

`shutdown()` wraps each resource teardown in try/except. If the browser fails to stop (Playwright crash), we still close HTTP clients and OOB managers. This prevents one broken resource from blocking cleanup of all others.

---

## What This Enables

An agent can now run a complete IDOR test:

```
1. session_create(hunt_id, name="user_a", target_url="https://app.example.com")
2. session_login_token(hunt_id, session_name="user_a", token="tok_user_a")
3. session_create(hunt_id, name="user_b", target_url="https://app.example.com")
4. session_login_token(hunt_id, session_name="user_b", token="tok_user_b")
5. http_request(hunt_id, url="https://app.example.com/api/profile/123", session_name="user_a")
6. http_request(hunt_id, url="https://app.example.com/api/profile/123", session_name="user_b")
7. http_compare(hunt_id, request_id_a=1, request_id_b=2)  # → if both 200, IDOR confirmed
```

Or blind SSRF testing:

```
1. oob_create_listener(hunt_id, purpose="blind SSRF on webhook_url")
2. oob_get_payload(hunt_id, callback_domain="abc123.oast.live")
3. http_request(hunt_id, url="https://target.com/api/webhook", method="POST",
               body='{"url": "http://abc123.oast.live"}')
4. oob_poll(hunt_id, timeout_seconds=30)  # → check for callbacks
```

---

## What's Next (Phase 4)

Phase 4 adds 11 vulnerability testing tools (`test_idor`, `test_ssrf`, `test_sqli`, `test_xss`, `test_auth`, `test_race`, `test_redirect`, `test_csrf`, `test_mass_assign`, `test_reset`, `test_ai`). These depend on Phase 3's HTTP client and session resources. Each vuln tool follows the same pattern: resolve session, get HTTP client, call the vuln test function, serialize the `VulnTestResult`.
