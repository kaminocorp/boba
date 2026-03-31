# Boba V1/V2 Refinements — Code Quality & Correctness Fixes

**Date:** 2026-03-31
**Status:** Implemented and tested
**Scope:** 12 files modified, 115 tests passing (0 regressions)

---

## Summary

Post-implementation quality review of V1 and V2 identified correctness, safety, and robustness issues across the codebase. This refinement pass addresses all HIGH and MEDIUM issues, plus key LOW-priority improvements. Original score: 7.5/10 — these fixes target 8.5+.

---

## Fixes Implemented

### HIGH Priority

#### 1. IPv6 Address Handling in Scope Engine

**File:** `src/boba/core/scope.py`
**What:** `_check_ip()`, `_extract_hostname()`, and `_guess_entity_type()` all used `target.split(":")[0]` to strip ports from IP strings. This destroys IPv6 addresses — `2001:db8::1` becomes `2001`.
**Fix:** New `_strip_port()` static method that correctly handles:
- Bracketed IPv6 with port: `[::1]:443` → `::1`
- IPv4 with port: `10.0.0.1:8080` → `10.0.0.1`
- Bare IPv6: `2001:db8::1` → unchanged
- Bare IPv4: `10.0.0.1` → unchanged

All three methods now use this for port stripping. `_guess_entity_type` also cleans the string before passing to `ipaddress.ip_address()`.

**Why:** Scope engine silently misclassified IPv6 targets, meaning IPv6 scope rules would never match. A security boundary that doesn't work is worse than no boundary.

---

#### 2. URL Encoding for Vulnerability Payloads

**File:** `src/boba/tools/vuln.py`
**What:** All 5 vuln testing tools (`test_idor`, `test_ssrf`, `test_xss`, `test_sqli`, `test_auth`) injected payloads into URLs via raw string concatenation: `f"{url}?{param}={payload}"`. Payloads containing `&`, `#`, `=`, `%` broke URL structure, causing payloads to be split across parameters or truncated.
**Fix:** New `_inject_param(url, param_name, value)` helper that:
- Parses the URL with `urlparse`
- Preserves existing query parameters via `parse_qs`
- Properly encodes the injected value with `urllib.parse.quote`
- Reconstructs the URL with `urlunparse`

All 9 injection points across `test_ssrf`, `test_xss`, `test_sqli`, and their OOB variants now use this helper.

**Why:** This was the single biggest correctness issue. SQLi payloads like `' AND '1'='1` were split at `=` signs. XSS payloads with `&` were truncated. Every vuln test was producing unreliable results — both false negatives (broken payloads) and malformed requests.

**Tests updated:** `test_reflected_xss` and `test_error_based_sqli` mock functions now use `unquote()` to decode URLs before checking for payload presence, matching real server behavior.

---

#### 3. Uninitialized `_stdin_targets` in WaybackurlsAdapter

**File:** `src/boba/adapters/waybackurls.py`
**What:** `_stdin_targets` was set in `run()` but accessed in `_execute()`. If `_execute()` was ever called directly (e.g., by a subclass or test), it raised `AttributeError`.
**Fix:** Added `self._stdin_targets: list[str] = []` initialization in `__init__`.
**Why:** Defensive initialization prevents AttributeError and makes the adapter's contract explicit.

---

#### 4. Silent JSON Parse Failures in Adapter Output Parsing

**Files:** `src/boba/adapters/base.py`, `src/boba/core/models.py`
**What:** When tools output mixed JSON + error text (common with nuclei, httpx on failure), malformed lines were silently dropped via `except: continue`. Users saw 0 results with no explanation.
**Fix:**
- `parse_output()` now returns `tuple[list[dict], int]` — records + parse error count
- Each format handler (JSON lines, JSON object, JSON array) counts parse failures
- Warnings logged via `logging.getLogger(__name__)` when lines are dropped
- New `parse_errors: int` field on `ToolResult` dataclass propagates the count to callers
- `run()` method passes `parse_errors` through to the result

**Why:** Data loss without indication is a trust-eroding bug. When nuclei finds 50 results but 10 have non-JSON error lines, the caller needs to know about the discrepancy.

**Tests updated:** `test_subfinder.py` and `test_nuclei.py` updated to unpack the new tuple return.

---

### MEDIUM Priority

#### 5. Async Context Managers for BrowserManager and OOBManager

**Files:** `src/boba/interaction/browser.py`, `src/boba/interaction/oob.py`
**What:** Both managers had `start()`/`stop()` methods but no `__aenter__`/`__aexit__`. Forgetting to call `stop()` leaked Chromium processes or Interactsh connections.
**Fix:** Added `async with` support to both:
```python
async with BrowserManager(config, sink) as browser:
    await browser.navigate(url)
# Chromium automatically closed
```
**Why:** Resource leaks in long-running agent sessions (the primary use case) accumulate and eventually crash the system.

---

#### 6. Deprecated `mktemp()` Replaced with `NamedTemporaryFile`

**Files:** `src/boba/adapters/whatweb.py`, `src/boba/adapters/ffuf.py`
**What:** Both used `tempfile.mktemp()` (deprecated since Python 3.0) for output files. TOCTOU race condition: the file doesn't exist yet when `mktemp` returns, so another process could create it first.
**Fix:** Replaced with `tempfile.NamedTemporaryFile(delete=False)` + `.close()`, matching the pattern already used by `BaseAdapter._create_temp_file()`.
**Why:** Consistency with rest of codebase + eliminates race condition, even though the window is narrow in practice.

---

#### 7. JSON Decode Safety in Context Retrieval

**File:** `src/boba/core/context.py`
**What:** `_row_to_hunt()` called `json.loads(row["scope_json"])` without error handling. If stored JSON was malformed (corruption, partial write), hunt retrieval crashed with uncaught `JSONDecodeError`. Same issue in `get_http_record()` and `query_http_history()`.
**Fix:**
- `_row_to_hunt()`: wrapped `scope_json` and `config_json` parsing in try/except with sensible defaults (`{"rules": []}` and `{}`)
- `get_http_record()` and `query_http_history()`: unified JSON parsing loop with per-field try/except and defaults (`{}` for headers, `[]` for tags)

**Why:** Database corruption shouldn't crash the entire hunt. Graceful degradation (empty scope, empty headers) is better than an exception.

---

#### 8. Scope Rule Validation at Compile Time

**File:** `src/boba/core/scope.py`
**What:** `_compile()` called `_domain_to_regex()` and `ip_network()` without catching errors. Malformed patterns in YAML scope files crashed at match time (first `is_in_scope()` call) instead of load time.
**Fix:** Wrapped both `re.compile()` (via `_domain_to_regex`) and `ipaddress.ip_network()` in try/except, raising `ValueError` with a descriptive message including the offending pattern.
**Why:** Fail-fast at config load time is much easier to debug than a crash deep in an adapter run.

---

#### 9. Improved IDOR Response Similarity Check

**File:** `src/boba/tools/vuln.py`
**What:** `_bodies_similar()` only compared response body lengths (ratio > 0.8). Two completely different resources of similar size (e.g., different 1KB JSON objects) were considered "similar," causing false positive IDOR detections.
**Fix:** Three-stage comparison:
1. Exact byte equality (fast path)
2. SHA-256 hash comparison (fast path for large identical bodies)
3. Line-based structural overlap — splits bodies on newlines, computes `|intersection| / |union|`, requires overlap > threshold

**Why:** IDOR detection is the highest-value vuln test. False positives waste agent time and human review effort. Structural comparison catches the common case where two different API responses happen to be the same length.

---

#### 10. SQLi Boolean Detection Threshold Improvement

**File:** `src/boba/tools/vuln.py`
**What:** Boolean-based SQLi required a 50+ byte difference between true/false conditions. Real-world apps often return smaller deltas (different timestamps, CSRF tokens, whitespace).
**Fix:** Dual threshold: `len_diff > 20` (absolute) OR `relative_diff > 0.05` (5% of baseline). Also requires `len_diff > 0` to avoid false positives on identical responses.
**Why:** The 50-byte threshold missed real injections in apps with small response variations, which is the common case for boolean-based detection.

---

### LOW Priority

#### 11. Output Size Bounding in Subprocess

**File:** `src/boba/core/subprocess.py`
**What:** `run_subprocess` accumulated entire stdout in memory with no cap. A tool outputting >1GB could OOM the process.
**Fix:** Added `max_output_bytes` parameter (default 256MB). The `read_stream` coroutine tracks total bytes read and stops accumulating (but continues draining) once the cap is reached. The stream is still fully consumed to prevent the subprocess from blocking.
**Why:** Security tools can produce unexpectedly large output (e.g., waybackurls on a large target, ffuf with broad wordlists). A 256MB cap prevents OOM while being generous enough for any realistic use case.

---

## Files Modified

| File | Changes |
|------|---------|
| `src/boba/core/scope.py` | IPv6 handling, regex validation at compile time |
| `src/boba/core/context.py` | JSON decode safety in 3 methods |
| `src/boba/core/models.py` | `parse_errors` field on `ToolResult` |
| `src/boba/core/subprocess.py` | Output size bounding |
| `src/boba/adapters/base.py` | `parse_output` returns error count, logging |
| `src/boba/adapters/waybackurls.py` | `_stdin_targets` initialization |
| `src/boba/adapters/whatweb.py` | `mktemp` → `NamedTemporaryFile` |
| `src/boba/adapters/ffuf.py` | `mktemp` → `NamedTemporaryFile` |
| `src/boba/interaction/browser.py` | `__aenter__`/`__aexit__` context manager |
| `src/boba/interaction/oob.py` | `__aenter__`/`__aexit__` context manager |
| `src/boba/tools/vuln.py` | URL encoding, IDOR similarity, SQLi threshold |
| `tests/adapters/test_subfinder.py` | Updated for `parse_output` tuple return |
| `tests/adapters/test_nuclei.py` | Updated for `parse_output` tuple return |
| `tests/tools/test_vuln.py` | Updated mocks for URL-encoded payloads |

## How to Verify

```bash
# Run all tests (should be 115 passing, 0 failures)
pytest tests/ -v

# Verify lint (no new issues introduced)
ruff check src/ tests/
```
