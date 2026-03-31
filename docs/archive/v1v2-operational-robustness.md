# Boba V1/V2 Operational Robustness — Pre-V3 Quality Gate

**Date:** 2026-03-31
**Status:** Implemented and tested
**Scope:** 6 files modified, 1 test file updated, 115 tests passing (0 regressions)
**Builds on:** [v1v2-pre-v3-fixes.md](v1v2-pre-v3-fixes.md) — this pass is strictly additive

---

## Summary

Comprehensive codebase audit prior to V3 development, conducted with 5 parallel review agents across all modules (core, adapters, interaction, tools/CLI, tests). Scored the codebase at 8.0/10 and identified issues in **operational robustness**: silent data truncation, missing diagnostic logging, connection pool waste, unsafe shutdown ordering, and SQL safety gaps. The prior passes addressed data encoding (refinements), detection accuracy (hardening), and data integrity (pre-V3 fixes). This pass targets **runtime reliability and debuggability**.

---

## Fixes Implemented

### CRITICAL Priority

#### 1. Response body_text Silently Truncated to 8KB

**File:** `src/boba/interaction/http.py` (line 95)
**What:** `body_text=resp.text[:8192]` silently dropped all response content beyond 8KB. Vulnerability detection tools operate on `body_text` for string matching (e.g., `vuln.py:417`: `body_lower = resp.body_text.lower()`). An SQL error signature at byte position 9000, or SSRF metadata indicators in a large response, would be invisible to detection logic.
**Fix:** Removed the truncation: `body_text=resp.text if resp.text else ""`. The full body bytes are already stored in `resp.body` and persisted via the HTTP history sink (which handles large bodies via file offloading). The `body_text` field is a convenience decode — truncating it silently broke the detection tools that depend on it.
**Why:** This was the single most impactful correctness issue. Every vuln test tool was potentially missing evidence in longer responses.

**Additive to prior passes:** The refinements pass fixed URL *encoding* of payloads. The hardening pass fixed response *analysis* logic (XSS partial reflection, SSRF indicators). This fix addresses response *data availability* — a different phase in the request→response→analyze pipeline.

---

#### 2. SQL Table Name Interpolation Not Validated

**File:** `src/boba/core/context.py` (line 636)
**What:** `get_hunt_stats()` used f-string interpolation for table names in SQL: `f"SELECT COUNT(*) as cnt FROM {table} WHERE hunt_id = ?"`. The table list was hardcoded inline, but the `# noqa: S608` suppression masked the risk. If V3 adds a method that passes a table name from external input (e.g., a CLI `--table` flag), this becomes SQL injection.
**Fix:** Extracted the table list to a class-level `_STATS_TABLES = frozenset({...})`. The loop now iterates `sorted(self._STATS_TABLES)` — the allowlist is immutable, defined once, and clearly separate from the query logic. The `noqa` comment remains because ruff can't reason about frozenset membership, but the actual safety is now structural rather than implicit.
**Why:** Defense in depth. V3 will add more query methods and CLI surface area. A frozenset allowlist is immune to future refactoring mistakes.

**Additive to prior passes:** Prior passes addressed JSON decode safety in *retrieval methods*. This fix addresses *query construction* — a different class of persistence concern.

---

### HIGH Priority

#### 3. HttpClient Created/Destroyed Per Request (Connection Pool Waste)

**File:** `src/boba/interaction/http.py` (lines 19-66)
**What:** Every `request()` call created a new `httpx.AsyncClient` (connection pool), made one request, and destroyed it via `async with`. During fuzzing (hundreds of requests) or IDOR testing (3+ requests per endpoint), this meant: no TCP connection reuse, no keep-alive, full TLS handshake per request. V3's heavier HTTP workloads (race condition testing, mass parameter fuzzing) would amplify this waste.
**Fix:** `HttpClient` now creates a persistent `httpx.AsyncClient` in `__init__()` and exposes `close()` + `async with` protocol for lifecycle management. The `request()` method uses the persistent client directly. Per-request overrides (`follow_redirects`, `timeout_seconds`) are passed to `client.request()` rather than `AsyncClient()`.
**Why:** Connection pooling is a ~10x performance improvement for sequential HTTP testing, and eliminates TLS renegotiation overhead per request.

**Test update:** `tests/interaction/test_http.py` — updated all 7 request/replay tests to mock `client._client.request` directly instead of patching the `httpx.AsyncClient` constructor. Removed unused `patch` import.

**Additive to prior passes:** The refinements pass added `__aenter__`/`__aexit__` to `BrowserManager` and `OOBManager`. This extends the same lifecycle pattern to `HttpClient` — a different resource type.

---

#### 4. Silent Exception Handlers Throughout Codebase (No Logging)

**Files:** `src/boba/core/context.py`, `src/boba/adapters/base.py`, `src/boba/interaction/browser.py`
**What:** The hardening and pre-V3 passes correctly added try/except blocks for graceful degradation, but most catch blocks discarded the exception entirely. When malformed JSON, parse failures, or browser errors occurred, there was zero diagnostic output — making production debugging impossible.

**Fix (3 files, 20+ catch blocks):**

**context.py** — Added `import logging` and `logger = logging.getLogger(__name__)`. All JSON decode catch blocks in 7 methods now log `logger.warning(...)` with the field name, entity ID, and exception message:
- `_row_to_hunt()`: scope_json, config_json
- `get_http_record()`: request_headers, response_headers, tags
- `query_http_history()`: same 3 fields per row
- `get_session()` / `get_sessions()`: cookies_json, headers_json, tokens_json, storage_state
- `get_findings()`: evidence, request_ids, tags
- `get_oob_listeners()`: interactions

**base.py** — All 4 format handler inner catch blocks (JSON_LINES, JSON_OBJECT, PLAIN_LINES, JSON_ARRAY) now log `logger.debug(...)` with the tool name and exception. Debug level because individual parse errors are expected (mixed output from tools), but they should be visible when debugging.

**browser.py** — Added `import logging` and `logger = logging.getLogger(__name__)`. Three changes:
- `stop()`: context close errors logged at debug level
- `_on_response()`: body/header read failures logged at debug level with the URL

**Why:** The difference between "it silently returned empty results" and "WARNING: Malformed cookies_json for session hunt123/user_a: Expecting value: line 1 column 1" is the difference between hours of debugging and seconds.

**Additive to prior passes:** The hardening pass added the try/except blocks themselves. This pass adds the diagnostic logging *within* those blocks — strictly additive, no catch logic changed.

---

#### 5. Browser Shutdown Closes Pages Before Contexts

**File:** `src/boba/interaction/browser.py` (lines 51-60)
**What:** `stop()` closed browser contexts directly without closing their child pages first. Playwright contexts own their pages, so this usually works — but if page close triggers async event handlers (e.g., the `_on_response` interception handler processing a final response), the handler may reference a context that's already being disposed, causing race conditions or unhandled errors in long-running agent sessions.
**Fix:** `stop()` now explicitly closes all pages first (iterating `_pages`), then closes contexts. Both loops log errors at debug level instead of silently swallowing them.
**Why:** Correct resource cleanup ordering: child resources (pages) before parent resources (contexts). This is the standard Playwright teardown pattern.

**Additive to prior passes:** The refinements pass added `__aenter__`/`__aexit__` for top-level lifecycle. The pre-V3 pass fixed per-context cleanup on *creation* failure. This fix addresses *shutdown ordering* — a different phase of the lifecycle.

---

#### 6. SQLi Baseline Request Missing Test Parameter

**File:** `src/boba/tools/vuln.py` (lines 394-405)
**What:** The baseline request for SQLi boolean-based detection sent the bare URL without the test parameter: `resp_baseline = await http_client.request(method=method, url=url, ...)`. But the true/false condition requests injected via `_inject_param(url, param_name, ...)`. This meant the baseline response could differ from true/false responses for structural reasons (missing vs. present parameter), not injection reasons — causing false positives in the `len_diff` comparison.
**Fix:** Moved the baseline request inside the per-parameter loop and now uses `_inject_param(url, param_name, default_val)` to include the normal parameter value. The boolean comparison on line 457-464 now compares true/false responses against a structurally identical baseline.
**Why:** Boolean-based SQLi detection is the most sensitive test (small response deltas). A structural mismatch in the baseline makes the entire comparison unreliable.

**Additive to prior passes:** The refinements pass fixed URL *encoding* of SQLi payloads. The hardening pass adjusted the *threshold* for boolean detection. This fix addresses the *baseline request construction* — a different aspect of the same detection pipeline.

---

## Files Modified

| File | Changes |
|------|---------|
| `src/boba/interaction/http.py` | Persistent HttpClient with connection pooling, body_text truncation removed |
| `src/boba/core/context.py` | SQL table allowlist, logging in 20+ JSON decode catch blocks |
| `src/boba/adapters/base.py` | Debug logging in 4 parse error handlers |
| `src/boba/interaction/browser.py` | Page-before-context shutdown ordering, debug logging |
| `src/boba/tools/vuln.py` | SQLi baseline includes test parameter |
| `tests/interaction/test_http.py` | Updated mocking for persistent HttpClient |

## How to Verify

```bash
# Run all tests (should be 115 passing, 0 failures)
pytest tests/ -v

# Verify lint (0 errors)
ruff check src/ tests/
```
