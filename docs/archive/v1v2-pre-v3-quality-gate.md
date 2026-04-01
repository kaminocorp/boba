# Boba V1/V2 Pre-V3 Quality Gate — Critical Bug Fixes

**Date:** 2026-03-31
**Status:** Implemented and tested
**Scope:** 8 files modified, 115 tests passing (0 regressions)
**Builds on:** [v1v2-operational-robustness.md](v1v2-operational-robustness.md) — this pass is strictly additive

---

## Summary

Final quality gate before V3 development. A 4-agent parallel codebase review uncovered **2 critical bugs** (one a scope bypass, one causing every successful subprocess to report failure), **3 high-priority correctness issues**, and **3 medium-priority robustness gaps**. All prior hardening passes (refinements, hardening, pre-v3-fixes, operational-robustness) addressed different issues — this pass targets bugs that survived those rounds.

Several review findings were **verified as false alarms** and not fixed:
- HttpClient timeout is not "ignored" — it's applied at the `httpx.AsyncClient` level and works correctly.
- Session cache write order is correct — `_persist()` writes DB first, then cache.
- Playwright `page.on("response", async_fn)` does await async handlers internally.
- Browser cleanup order (pages before contexts) is correct — prevents dangling event handlers.

---

## Fixes Implemented

### CRITICAL Priority

#### 1. Subprocess Exit Code 0 Misreported as -1

**File:** `src/boba/core/subprocess.py` (line 106)
**What:** `exit_code=process.returncode or -1` used Python truthiness to check for `None`. Since `0` is falsy, every successfully-completed process (`returncode == 0`) was reported as `exit_code = -1`.
**Fix:** Changed to `process.returncode if process.returncode is not None else -1`, which only substitutes `-1` when the returncode is genuinely unavailable.
**Why:** Every caller inspecting `ToolResult.exit_code` to detect failures would see `-1` for successful runs, making success/failure indistinguishable. The base adapter's new exit-code warning (fix #6 below) would have fired on every single run.

**Additive to prior passes:** The refinements pass added `output_truncated` signaling to `SubprocessResult`. The operational-robustness pass added diagnostic logging. This fix addresses the core `exit_code` field that both depend on.

---

#### 2. Scope URL Prefix Rule Bypass via Empty Pattern

**File:** `src/boba/core/scope.py` (line 70)
**What:** `rule.pattern.rstrip("*").rstrip("/")` on a bare `"*"` or `"*/"` pattern produced an empty string `""`. Since `"".startswith("")` always returns `True` in Python, this meant every URL was considered in-scope — a complete scope bypass.
**Fix:** Added an explicit empty-prefix check: `if not prefix: continue`. Bare wildcard URL prefix rules are now silently skipped (they're semantically meaningless in a default-deny model).
**Why:** The scope engine is a security boundary. A single malformed rule silently disabling all URL-level scope enforcement is a critical defect.

**Additive to prior passes:** The refinements pass added scope rule validation at compile time (catching malformed CIDR/regex). This fix addresses a logic error in the URL prefix branch that wasn't caught by compile-time validation because the pattern was syntactically valid.

---

### HIGH Priority

#### 3. OOB Fallback Silently Masks Total Failure

**File:** `src/boba/interaction/oob.py` (lines 34-36)
**What:** When `interactsh` was not installed, `OOBManager.start()` caught `ImportError` and silently substituted `_FallbackOOBClient()` — a mock that never detects callbacks. All blind vulnerability tests (SSRF, XSS) using OOB would execute, appear to work, and report "no callbacks detected" without any indication that the detection mechanism was completely non-functional.
**Fix:** Added `logging.warning()` with an explicit message: "interactsh package not installed — OOB detection disabled. Blind SSRF/XSS tests will not detect callbacks."
**Why:** Silent failures in security tooling are dangerous — they create false confidence. An agent running `test_ssrf` with OOB and seeing "not vulnerable" needs to know that the OOB channel was dead.

**Additive to prior passes:** The hardening pass fixed OOB listener ID matching (substring → startswith). This fix addresses a different failure mode: the entire OOB subsystem being silently disabled.

---

#### 4. Httpx Adapter Port 0 Treated as None

**File:** `src/boba/adapters/httpx_runner.py` (line 49)
**What:** `int(raw["port"]) if raw.get("port") else None` used truthiness to check for the port field. Port `0` is a valid value but falsy in Python, so it was silently converted to `None`.
**Fix:** Changed to `raw.get("port") is not None`, which correctly distinguishes between "field absent" (None) and "field is 0" (valid port).
**Why:** While port 0 in httpx output is rare, the pattern is a category of bug (falsy-value-as-absent) that appeared in multiple places. Fixing it here establishes the correct idiom.

---

#### 5. Ffuf Adapter Silently Ignores Multiple Targets

**File:** `src/boba/adapters/ffuf.py` (line 43)
**What:** `url = targets[0]` used only the first target and silently discarded the rest. An agent passing 10 URLs to directory fuzzing would only scan 1 with no indication that 9 were dropped.
**Fix:** Added `logger.warning()` when `len(targets) > 1`, stating how many targets were ignored.
**Why:** Silent data loss. When the high-level `enum.directories()` tool queries context for live hosts and passes them to ffuf, the caller needs to know that ffuf only processes one at a time.

---

### MEDIUM Priority

#### 6. Base Adapter Non-Zero Exit Code Not Logged

**File:** `src/boba/adapters/base.py` (line 264)
**What:** When a tool exited with a non-zero code (crash, missing args, permission error), the adapter silently returned the exit code in `ToolResult` without any log. Callers had to explicitly check `result.exit_code` — and most didn't.
**Fix:** Added `logger.warning()` after `_execute()` when `result.exit_code != 0`, including the exit code, timeout status, and first 200 chars of stderr.
**Why:** Non-zero exits with empty stdout produce `ToolResult(records=[])` — indistinguishable from "tool ran, found nothing." The warning surfaces the actual failure to logging, where it's visible to operators and agents.

**Additive to prior passes:** The operational-robustness pass added diagnostic logging inside catch blocks. This fix adds logging for a different failure mode (non-exception tool failure signaled via exit code).

---

#### 7. Browser Interception Timing Uses Wrong Playwright API Value

**File:** `src/boba/interaction/browser.py` (line 157)
**What:** `response.request.timing.get("responseEnd", 0)` recorded a raw Playwright timing value as `elapsed_ms`. Playwright's timing dict values are relative to `navigationStart`, not per-request elapsed time. This produced incorrect (often misleading) timing values in HTTP history for browser-captured traffic.
**Fix:** Changed to `elapsed_ms=0` with a comment explaining the limitation. Page-level latency is correctly measured in `navigate()` using `time.monotonic()` — that value is reliable. Per-request timing from the response handler is not.
**Why:** Incorrect timing data in HTTP history could mislead an agent doing time-based analysis (e.g., time-based SQLi via browser). Explicit 0 is better than wrong data.

---

#### 8. HTTP Compare Crashes on Bytes Response Bodies

**File:** `src/boba/interaction/http.py` (lines 172-184)
**What:** `compare()` read `response_body` from context and called `.splitlines()` on it. The `isinstance(body_a, str)` guard produced `[]` for bytes bodies, making the diff always "0 lines differ" when one body was bytes. While context normally stores strings, defensive code should handle both.
**Fix:** Added explicit bytes→str normalization: `raw_a.decode("utf-8", errors="replace") if isinstance(raw_a, bytes) else raw_a`. Removed the now-unnecessary `isinstance` guard on `splitlines()`.
**Why:** Defensive robustness. If a future code path writes bytes to context (or a migration changes storage), `compare()` won't silently produce wrong diffs.

---

## Files Modified

| File | Changes |
|------|---------|
| `src/boba/core/subprocess.py` | Exit code truthiness fix (`or -1` → `if is not None`) |
| `src/boba/core/scope.py` | Empty URL prefix skip |
| `src/boba/interaction/oob.py` | Logging import, fallback warning |
| `src/boba/adapters/httpx_runner.py` | Port 0 truthiness fix |
| `src/boba/adapters/ffuf.py` | Logging import, multi-target warning |
| `src/boba/adapters/base.py` | Non-zero exit code warning |
| `src/boba/interaction/browser.py` | Timing value → explicit 0 |
| `src/boba/interaction/http.py` | Bytes body normalization in compare() |
| `src/boba/__init__.py` | Version bump 0.2.4 → 0.2.5 |
| `pyproject.toml` | Version bump 0.2.4 → 0.2.5 |

## How to Verify

```bash
# Run all tests (should be 115 passing, 0 failures)
pytest tests/ -v

# Verify lint (no new issues introduced)
ruff check src/ tests/
```
