# Boba V1/V2 Pre-V3 Fixes — Data Integrity, Resource Safety & Code Hygiene

**Date:** 2026-03-31
**Status:** Implemented and tested
**Scope:** 8 files modified, 115 tests passing (0 regressions)
**Builds on:** [v1v2-hardening.md](v1v2-hardening.md) — this pass is strictly additive

---

## Summary

Comprehensive codebase review prior to V3 development uncovered **data integrity bugs**, **resource safety gaps**, and **code hygiene issues** across the V1/V2 codebase. The refinements pass (v1v2-refinements.md) fixed data-level concerns (URL encoding, IPv6, parse errors). The hardening pass (v1v2-hardening.md) fixed detection accuracy and defensive robustness. This pre-V3 pass targets **transaction safety**, **exception handling completeness**, **resource lifecycle management**, and **lint compliance**.

---

## Fixes Implemented

### CRITICAL Priority

#### 1. Technology Records Not Committed to Database

**File:** `src/boba/core/context.py` (line 513), `src/boba/tools/recon.py` (line 160)
**What:** The 6 individual `upsert_*` methods (subdomain, host, port, url, technology, directory) don't call `commit()` individually — they're designed to be called from `upsert_records()` which wraps them in `with self._conn:` for transactional safety. However, `upsert_technology` was **not in the `upsert_records` dispatch table**, and `recon.tech()` called it directly outside any transaction. Technology data was written to SQLite's WAL but never committed — it persisted only because a later `log_tool_run()` happened to call `commit()`. A crash between the two calls would silently lose all technology data.
**Fix:** Two changes:
1. Added `"technology"` to the `upsert_records()` dispatch table with a lambda that matches the method's `(hunt_id, host, tech_dict, source)` signature
2. Rewrote `recon.tech()` to flatten technology records and call `context.upsert_records(hunt.id, "technology", flat_techs, source="whatweb")` instead of calling `upsert_technology()` directly

**Why:** Data loss on crash is unacceptable for a persistence layer. The batch dispatch table is the single correct entry point for all record writes — bypassing it creates implicit coupling to commit timing of unrelated methods.

**Additive to prior passes:** The refinements pass added JSON decode safety to retrieval methods. The hardening pass added JSON decode safety to V2 methods. This fix addresses the *write path* — a different phase of the persistence lifecycle.

---

#### 2. Adapter parse_record() Exceptions Crash Entire Run

**File:** `src/boba/adapters/base.py` (lines 164, 181, 212)
**What:** The JSON_LINES handler caught only `(json.JSONDecodeError, KeyError)`, and JSON_OBJECT/JSON_ARRAY inner handlers caught only `(KeyError, TypeError)`. But `parse_record()` implementations can raise `ValueError` (e.g., `int(raw["port"])` in httpx_runner with non-numeric port), `AttributeError`, or other exceptions. An unhandled exception crashed the entire adapter run and lost all remaining records.

The PLAIN_LINES handler (added in the hardening pass) already correctly used `except Exception`.
**Fix:** Changed all three inner `parse_record()` exception handlers to `except Exception`, matching the PLAIN_LINES pattern. The outer JSON structure parsing still catches only `json.JSONDecodeError` (correct — a non-JSON response is a different failure mode than a single bad record).
**Why:** One malformed record in a 10,000-record output should not crash the run and lose the other 9,999 records. This was the exact scenario httpx_runner could trigger with a non-numeric port value.

**Additive to prior passes:** The refinements pass added `parse_errors` tracking and logging to the format handlers. The hardening pass extended error handling to PLAIN_LINES. This fix completes the pattern across all four format handlers.

---

### HIGH Priority

#### 3. HuntContext Has No Context Manager Protocol

**File:** `src/boba/core/context.py` (line 286)
**What:** `HuntContext` had a `close()` method but no `__enter__`/`__exit__`. CLI commands used `try/finally` with `manager.close_context()`, but this is fragile — if an exception occurs before the manager is assigned, cleanup is skipped and SQLite WAL files accumulate.
**Fix:** Added `__enter__` (returns self) and `__exit__` (calls `close()`) methods, enabling `with HuntContext(db_path) as ctx:` usage.
**Why:** Context managers are the standard Python pattern for resource lifecycle. This makes correct cleanup automatic rather than requiring caller discipline.

**Additive to prior passes:** The refinements pass added `__aenter__`/`__aexit__` to `BrowserManager` and `OOBManager`. This extends the same pattern to `HuntContext` — a different resource type.

---

#### 4. 37 Lint Errors Across Codebase

**Files:** 15 files across `src/boba/` and `tests/`
**What:** Ruff reported 37 errors after the hardening pass:
- 8 unused `Path` imports across adapters and models (F401)
- 15 unused `hunt` variable assignments in CLI commands (F841)
- 1 unused `binary` variable in base adapter (F841)
- 1 unused `Any` import in recon.py (F401)
- 12 unused imports in test files (F401)

**Fix:**
- Auto-fixed 21 unused imports via `ruff check --fix`
- Removed `binary = self.find_binary()` assignment in `base.py` (call kept for side-effect)
- Removed unused `hunt =` assignments in 15 CLI commands where `manager.get(hunt_id)` was called only for validation (call kept, assignment dropped)

**Why:** Lint errors indicate code that was modified without a final lint pass. Clean lint is a prerequisite for V3 development — accumulated warnings mask real issues.

---

#### 5. Body File Naming Race Condition in HTTP History

**File:** `src/boba/interaction/history.py` (line 111)
**What:** `_prepare_body()` used `glob()` + `len(existing)` to compute sequential file IDs for large body storage. Two concurrent calls could both count the same number of existing files, compute the same index, and silently overwrite each other's data.

Additionally, the body directory was never explicitly created — `_get_body_dir()` returned a path that might not exist, causing `FileNotFoundError` on first write.
**Fix:**
1. Replaced `glob()` + sequential counter with `uuid.uuid4().hex[:12]` for collision-free naming
2. Added `body_dir.mkdir(parents=True, exist_ok=True)` before file creation

**Why:** HTTP history is evidence for vulnerability reports. Silent data loss in the evidence layer undermines the entire framework's trustworthiness. UUID-based naming eliminates the race window entirely.

**Additive to prior passes:** The refinements pass added `BODY_INLINE_LIMIT` for the inline/file storage split. This fix addresses the *file creation mechanism* — a different aspect of the same feature.

---

### MEDIUM Priority

#### 6. Browser Context Leak on Page/Interception Failure

**File:** `src/boba/interaction/browser.py` (line 99)
**What:** `get_or_create_context()` registered the Playwright browser context in `self._contexts` at line 104 *before* creating the page (line 108) and setting up interception (line 109). If either `new_page()` or `_setup_interception()` raised an exception, the context was registered but had no page — a zombie context consuming Chromium process resources. On retry with the same name, the existing (broken) context was returned.
**Fix:** Restructured to register context, page, and request count *only after* all setup succeeds. Added try/except around the setup phase that closes the context on any failure:
```python
context = await self._browser.new_context(**ctx_kwargs)
try:
    # cookies, page, interception setup
except Exception:
    await context.close()
    raise
# Only register after success
self._contexts[name] = context
```
**Why:** In long-running agent sessions (the primary use case), repeated failed context creation attempts accumulate zombie Chromium processes until the system runs out of resources.

**Additive to prior passes:** The refinements pass added `__aenter__`/`__aexit__` to `BrowserManager` for top-level lifecycle. This fix addresses *per-context* lifecycle within the manager — a different granularity.

---

#### 7. asyncio.gather() in recon.urls() Loses Results on Single Adapter Failure

**File:** `src/boba/tools/recon.py` (line 109)
**What:** `recon.urls()` ran gau and waybackurls in parallel via `asyncio.gather()`. If one adapter failed (binary not found, timeout, parse error), the exception propagated immediately and the other adapter's successful results were lost.
**Fix:** Added `return_exceptions=True` to the gather call. Results are now processed in a loop that:
- Logs warnings for failed adapters via `logging.getLogger(__name__)`
- Persists and aggregates successful results
- Returns a combined `ToolResult` with whatever data was recovered

**Why:** Partial results are far more valuable than no results. A missing waybackurls binary shouldn't discard 10,000 URLs that gau successfully found.

---

## Files Modified

| File | Changes |
|------|---------|
| `src/boba/core/context.py` | Technology in dispatch table, `__enter__`/`__exit__` context manager |
| `src/boba/adapters/base.py` | Broadened exception handling in 3 format handlers, removed unused variable |
| `src/boba/tools/recon.py` | Technology uses `upsert_records`, gather with `return_exceptions=True`, logging |
| `src/boba/interaction/history.py` | UUID body file naming, directory creation |
| `src/boba/interaction/browser.py` | Context cleanup on setup failure, deferred registration |
| `src/boba/cli/main.py` | Removed 15 unused variable assignments |
| `src/boba/adapters/*.py` | Removed unused imports (7 files) |
| `tests/**/*.py` | Removed unused imports (6 files) |

## How to Verify

```bash
# Run all tests (should be 115 passing, 0 failures)
pytest tests/ -v

# Verify lint (0 errors)
ruff check src/ tests/
```
