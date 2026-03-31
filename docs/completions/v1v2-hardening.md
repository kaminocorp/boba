# Boba V1/V2 Hardening — Detection Correctness & Defensive Robustness

**Date:** 2026-03-31
**Status:** Implemented and tested
**Scope:** 10 files modified, 115 tests passing (0 regressions)
**Builds on:** [v1v2-refinements.md](v1v2-refinements.md) — this pass is strictly additive

---

## Summary

Second quality review of V1/V2 uncovered **correctness bugs in vulnerability detection logic**, **error handling gaps** in the adapter/interaction/persistence layers, and **CLI usability issues**. The refinements pass (v1v2-refinements.md) fixed data-level concerns (URL encoding, IPv6, parse errors, temp files). This hardening pass targets **detection accuracy** (false positives/negatives in the 5 vuln tools) and **defensive robustness** (resource cleanup, silent failures, missing validation).

---

## Fixes Implemented

### CRITICAL Priority

#### 1. IDOR Object ID Enumeration Broken for Trailing Slashes

**File:** `src/boba/tools/vuln.py` (line 124)
**What:** Object ID enumeration used `endpoint.replace(endpoint.split("/")[-1], obj_id)`. Two bugs: (1) if URL ends with `/`, the last segment is `""` and `str.replace("", obj_id)` inserts `obj_id` between every character, corrupting the URL. (2) if the object ID appears elsewhere in the URL (e.g., `/api/v123/users/123`), all occurrences are replaced.
**Fix:** Replaced with proper URL path manipulation using `urlparse`/`urlunparse`:
```python
parsed_ep = urlparse(endpoint)
path_parts = parsed_ep.path.rstrip("/").split("/")
path_parts[-1] = obj_id
test_url = urlunparse(parsed_ep._replace(path="/".join(path_parts)))
```
**Why:** IDOR enumeration is a critical capability — silently producing malformed URLs means the test reports false negatives for every enumerated object ID.

**Additive to refinements:** The refinements pass fixed URL *parameter* encoding (`_inject_param()`). This fix addresses URL *path segment* manipulation — a different injection point.

---

#### 2. SSRF Indicator List Conditionally Incomplete

**File:** `src/boba/tools/vuln.py` (line 195)
**What:** `"internal server error"` was only added to the SSRF indicator list when `"127.0.0.1" in payload`. AWS metadata payloads (`169.254.169.254`), GCP payloads, and other SSRF vectors never got this indicator checked, meaning a server returning "internal server error" for an AWS metadata SSRF attempt would be missed.
**Fix:** Made `"internal server error"` unconditional in the indicator list. Removed the `if indicator and` guard (no longer needed since all indicators are always strings).
**Why:** The indicator was designed to catch servers that error when processing internal requests. This applies to all SSRF vectors, not just localhost.

---

#### 3. Auth Endpoint Detection False Positives via Substring Match

**File:** `src/boba/tools/vuln.py` (line 570)
**What:** `"/admin" in endpoint.lower()` matched `/gadmin`, `/administrator`, `/read-admin-guide` — any URL containing the substring. Same issue for `/manage`, `/internal`, `/superuser`.
**Fix:** Replaced substring check with regex using path-boundary matching:
```python
_ADMIN_RE = re.compile(r"/(admin|manage|internal|superuser)([/?#]|$)", re.IGNORECASE)
if _ADMIN_RE.search(endpoint):
```
This matches `/admin`, `/admin/`, `/admin?foo=bar` but not `/gadmin` or `/administrator`.
**Why:** False positive privilege escalation reports waste agent time and human review effort.

---

#### 4. Version Mismatch Between Package and pyproject.toml

**File:** `src/boba/__init__.py` (line 3)
**What:** `__version__ = "0.1.0"` while `pyproject.toml` declared `version = "0.2.0"`.
**Fix:** Updated to `__version__ = "0.2.0"`.
**Why:** Any code reading `boba.__version__` (logging, report generation, user-agent strings) would report the wrong version.

---

### HIGH Priority

#### 5. XSS Partial Reflection Detection Overly Broad

**File:** `src/boba/tools/vuln.py` (line 319)
**What:** Partial reflection check stripped all `<>` characters and checked if the concatenated remainder existed in the response. For `<img onerror=alert(1)>`, this checked for `img onerror=alert(1)` — fragments like `img` or `onerror` could match benign HTML content, causing false positives.
**Fix:** Uses `re.sub(r"<[^>]*>", "", payload)` to extract only the inner content between tags (the actual executable part, e.g., `alert(1)`). Requires the inner content be at least 8 characters to avoid noise.
**Why:** XSS partial reflection at POSSIBLE confidence still gets logged. False positives in this check create noise that buries real findings.

**Additive to refinements:** The refinements pass fixed URL encoding of XSS payloads. This fix addresses the response *analysis* logic — a different phase of the same tool.

---

#### 6. context.py JSON Decode Safety Gaps in V2 Methods

**File:** `src/boba/core/context.py`
**What:** The refinements pass added try/except to `_row_to_hunt()`, `get_http_record()`, and `query_http_history()`. But `get_session()`, `get_sessions()`, `get_findings()`, and `get_oob_listeners()` still had unwrapped `json.loads()` calls that would crash on malformed data.
**Fix:** Wrapped all `json.loads()` calls in these 4 methods with try/except, using sensible defaults: `{}` for cookies/headers/tokens, `None` for evidence/storage_state, `[]` for request_ids/tags/interactions.
**Why:** Consistency with the pattern established in the refinements pass. Same rationale: database corruption shouldn't crash the entire hunt.

**Additive to refinements:** Extends the same fix pattern to the 4 V2 methods that were added after the refinements pass.

---

#### 7. Subprocess stdin Pipe Not Cleaned Up on Drain Failure

**File:** `src/boba/core/subprocess.py` (line 77-80)
**What:** If `process.stdin.drain()` raised (e.g., broken pipe to a crashing subprocess), `process.stdin.close()` was skipped, leaking the pipe.
**Fix:** Wrapped the stdin write/drain/close sequence in try/finally:
```python
if stdin_data and process.stdin:
    try:
        process.stdin.write(stdin_data.encode())
        await process.stdin.drain()
    finally:
        process.stdin.close()
```
**Why:** The waybackurls adapter pipes target lists via stdin. If the subprocess crashes mid-write, the pipe must still be closed.

**Additive to refinements:** The refinements pass added output size bounding. This fix addresses the *input* side of subprocess I/O — a different resource.

---

#### 8. Subprocess Output Truncation Now Signaled

**File:** `src/boba/core/subprocess.py`, `src/boba/core/models.py`
**What:** When output exceeded the 256MB cap (added in refinements), data was silently dropped with no indication to callers.
**Fix:** Added `output_truncated: bool = False` field to `SubprocessResult`. The `read_stream` coroutine sets this flag when the cap is hit. Callers can now detect and log truncation.
**Why:** Silent data loss without any signal is a trust-eroding pattern. The refinements pass added the cap but omitted the signal.

**Additive to refinements:** Completes the output bounding feature from the refinements pass.

---

#### 9. PLAIN_LINES Adapter Format Missing Error Handling

**File:** `src/boba/adapters/base.py` (line 190-194)
**What:** JSON format handlers (JSON_LINES, JSON_OBJECT, JSON_ARRAY) all had try/except around `parse_record()`. The PLAIN_LINES handler (used by gau, waybackurls) had none — if `parse_record()` threw an exception (e.g., `urlparse` failure on malformed URL), the entire parse crashed.
**Fix:** Added try/except with the same pattern: catch Exception, increment `parse_errors`, continue. Added warning log when lines are dropped.
**Why:** Consistency across all 4 format handlers. gau and waybackurls can produce malformed URLs that cause `urlparse` failures.

**Additive to refinements:** The refinements pass added parse_errors tracking to the JSON format handlers. This extends the same pattern to PLAIN_LINES.

---

#### 10. Session login_form Silently Fails on Missing Selectors

**File:** `src/boba/interaction/session.py` (line 95-121)
**What:** Both the form field filling loop and the submit button loop caught all exceptions and continued silently. If no CSS selector matched, the form was never filled and/or never submitted — but `login_form()` returned successfully, giving the caller a session with no auth state.
**Fix:** Added `filled`/`submitted` tracking booleans. If the loops exhaust all selectors without success, `SessionError` is raised with a descriptive message listing the selectors that were tried.
**Why:** A session that silently fails to authenticate causes every subsequent authenticated test to produce false results. Failing loudly lets the agent retry with different selectors.

---

### MEDIUM Priority

#### 11. OOB Listener ID Matching Used Substring Instead of Prefix

**File:** `src/boba/interaction/oob.py` (line 130)
**What:** `if lid in entry.get("full_id", "")` used substring matching. Listener ID `"abc"` would incorrectly match interaction `"xyzabcdef"` from a different listener.
**Fix:** Changed to `entry.get("full_id", "").startswith(lid)` — which matches the Interactsh protocol where the full interaction ID is prefixed with the listener ID.
**Why:** False listener matches cause interactions to be attributed to the wrong injection point, corrupting blind SSRF/XSS results.

---

#### 12. CLI Hardening (4 sub-fixes)

**Files:** `src/boba/cli/main.py`, `src/boba/cli/formatters.py`

**12a. HTTP request URL was optional (default `""`)** — Made `url` a required parameter by removing the default. Reordered parameters so required `url` comes before optional `method`.

**12b. Comma-separated targets not whitespace-stripped** — `targets.split(",")` at 4 locations and `extensions.split(",")` at 1 location now use `[t.strip() for t in ...]`. Without this, `"host1, host2"` produced `["host1", " host2"]` with a leading space.

**12c. Missing help text on hunt arguments** — `hunt pause`, `hunt resume`, `hunt close` had `typer.Argument()` without `help="Hunt ID"`. Added for CLI help completeness.

**12d. Invalid --format values silently fell back to table** — `format_output()` now prints an error message for unrecognized format values before falling back to table display.

---

## Files Modified

| File | Changes |
|------|---------|
| `src/boba/tools/vuln.py` | IDOR URL path fix, SSRF indicators, auth regex, XSS partial reflection |
| `src/boba/__init__.py` | Version bump 0.1.0 → 0.2.0 |
| `src/boba/core/context.py` | JSON decode safety in get_session, get_sessions, get_findings, get_oob_listeners |
| `src/boba/core/subprocess.py` | stdin try/finally, output_truncated flag |
| `src/boba/core/models.py` | `output_truncated` field on SubprocessResult |
| `src/boba/adapters/base.py` | PLAIN_LINES parse error handling |
| `src/boba/interaction/session.py` | login_form raises on selector miss |
| `src/boba/interaction/oob.py` | Listener ID startswith matching |
| `src/boba/cli/main.py` | URL required, comma-strip, help text, param reorder |
| `src/boba/cli/formatters.py` | Format validation |

## How to Verify

```bash
# Run all tests (should be 115 passing, 0 failures)
pytest tests/ -v

# Verify lint (no new issues introduced)
ruff check src/ tests/
```
