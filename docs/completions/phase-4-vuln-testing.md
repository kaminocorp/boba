# Phase 4 Completion — Vulnerability Testing Tools

**Date:** 2026-04-06
**Scope:** 12 vulnerability test MCP tools wrapping all vuln engines.
**Test delta:** +15 new tests (102 MCP total), 0 regressions (824 total, up from 809).

---

## What Was Built

Phase 4 wraps all 12 vulnerability test functions as MCP tools. Agents can now test for IDOR, SSRF, SQLi, XSS, auth bypass, race conditions, open redirects, CSRF, mass assignment, password reset flaws, and AI prompt injection — all via MCP tool calls with simplified, agent-friendly parameters.

### New Files

| File | Lines | Purpose |
|---|---|---|
| `src/boba/mcp/tools_vuln.py` | ~295 | 12 vuln tools + 3 helper functions (`_get_session`, `_get_required_session`, `_common_kwargs`) |
| `tests/mcp/test_tools_vuln.py` | ~370 | 15 tests: one per vuln tool + session error, hunt validation, serialization correctness |

### Modified Files

| File | Change |
|---|---|
| `src/boba/mcp/server.py` | Added `tools_vuln` import |
| `tests/mcp/conftest.py` | Added `vuln_mod` to monkeypatch loop |
| `tests/mcp/test_server.py` | Updated tool count 42 → 54 |

---

## Tool Inventory (54 total)

| Category | Count | Phase |
|---|---|---|
| Hunt management | 6 | 1 |
| Recon | 5 | 2 |
| Enumeration | 2 | 2 |
| Scanning | 1 | 2 |
| Context queries | 11 | 2 |
| Session management | 7 | 3 |
| HTTP client | 4 | 3 |
| Browser | 3 | 3 |
| OOB listeners | 3 | 3 |
| **Vulnerability testing** | **12** | **4** |

### Vulnerability Tools

| MCP Tool | Tests For | Requires Sessions |
|---|---|---|
| `test_idor` | Insecure Direct Object Reference | Yes (two: `session_a`, `session_b`) |
| `test_ssrf` | Server-Side Request Forgery | No (optional) |
| `test_sqli` | SQL Injection (error, boolean, time-based) | No (optional) |
| `test_xss` | Cross-Site Scripting (reflected, DOM, blind) | No (optional) |
| `test_auth` | Authentication/authorization bypass, JWT manipulation | No (optional) |
| `test_race` | Race conditions via concurrent requests | Yes (one) |
| `test_redirect` | Open redirect | No (optional) |
| `test_csrf` | Cross-Site Request Forgery | Yes (one) |
| `test_mass_assign` | Mass assignment / parameter pollution | Yes (one) |
| `test_reset` | Password reset flow vulnerabilities | No (optional) |
| `test_ai` | AI/LLM prompt injection (single-request) | No (optional) |
| `test_ai_conversation` | AI/LLM multi-turn conversation testing | No (optional) |

---

## Key Design Decisions

### 1. `_common_kwargs()` helper

All 12 vuln functions take `scope_engine`, `context`, and `hunt_id`. Rather than repeat this in every tool, `_common_kwargs(hunt_id)` builds the dict once. This also ensures scope engine construction and hunt validation happen consistently.

### 2. Required vs optional sessions

The vuln functions have two patterns: some require sessions (IDOR needs two, race/CSRF/mass_assign need one), others accept them optionally. The MCP tools mirror this — `test_idor` takes `session_a: str` and `session_b: str` as required parameters, while `test_sqli` takes `session_name: str | None = None`. `_get_required_session()` raises a clear error if the session doesn't exist; `_get_session()` returns None.

### 3. Parameter simplification

The underlying vuln functions accept complex types like `injection_points: list[dict]` and `params: dict[str, str]`. The MCP tools simplify to single strings: `param: str` gets expanded to `params={param: "1"}` or `injection_points=[{"location": "url_param", "name": param}]`. This keeps the MCP schema agent-friendly while the library functions stay flexible.

### 4. 12 tools not 11

The implementation plan listed 11 vuln tools, but `test_ai_conversation` was added in v0.5.6 after the plan was written. It's included here for completeness — there's no reason to leave a library function unwrapped.

### 5. Mock strategy: patch `vuln.test_*` not the HTTP client

Tests mock the vuln functions themselves rather than the underlying HTTP client. This is correct because: (a) the vuln functions are already thoroughly tested in `tests/tools/test_vuln.py`, (b) what we're testing here is that the MCP layer correctly resolves sessions, passes parameters, and serializes `VulnTestResult`.

---

## What This Enables

An agent can now run a complete vulnerability assessment:

```
1. session_create(hunt_id, name="user_a", ...)
2. session_login_token(hunt_id, "user_a", token="...")
3. session_create(hunt_id, name="user_b", ...)
4. session_login_token(hunt_id, "user_b", token="...")
5. test_idor(hunt_id, endpoint="/api/user/123", session_a="user_a", session_b="user_b")
6. test_sqli(hunt_id, url="https://target.com/search", param="q", session_name="user_a")
7. test_xss(hunt_id, url="https://target.com/search", param="q")
8. test_ssrf(hunt_id, url="https://target.com/fetch", param="url")
9. test_auth(hunt_id, endpoint="/admin", jwt="eyJ...")
10. test_ai(hunt_id, url="https://target.com/chat", param="message")
11. context_findings(hunt_id)  # review all discovered vulnerabilities
```

---

## What's Next (Phase 5)

Phase 5 adds 11 analysis and reporting tools: `analyze_coverage`, `analyze_coverage_gaps`, `analyze_dedupe`, `analyze_severity`, `analyze_chain`, `analyze_prioritize`, `report_draft`, `report_format`, `report_poc`, `report_list`, `report_show`. These operate on SQLite data (no new resources needed) and complete the find→analyze→report pipeline.
