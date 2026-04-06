# V4 Phase 1 Completion — WAF Detection Signal

## Summary

Implemented Phase 1 of the V4 enrichment plan: Boba now surfaces a `waf_detected` signal on `VulnTestResult` so agents can distinguish likely payload blocking from a simply clean endpoint.

## Why

Before this change, repeated blocked responses were returned as plain `vulnerable=False`, which gave agents no hint that they should retry with WAF-bypass payloads. The new signal preserves the existing vuln result contract while exposing that operational context.

## What Changed

### 1. `VulnTestResult` model extended

**File:** `src/boba/core/models.py`

- Added `waf_detected: bool = False` to `VulnTestResult`
- Kept a safe default so existing callers and JSON serialization remain backward-compatible

### 2. Shared WAF detection heuristic added

**File:** `src/boba/tools/vuln.py`

- Added `_WAF_STATUS_CODES`
- Added `_WAF_BODY_SIGNATURES`
- Added `_detect_waf(responses: list[HttpResponse]) -> bool`

Current heuristic:

- Requires at least 3 collected responses
- Flags likely WAF blocking when:
  - all collected responses use blocking-style status codes (`403`, `406`, `429`, `503`),
  - response bodies collapse to 1-2 near-template variants,
  - and at least one body includes a WAF-style signature such as `blocked`, `waf`, `firewall`, `cloudflare`, `akamai`, `incapsula`, `sucuri`, `mod_security`, `request blocked`, or `security policy`
- Also flags when all collected responses contain WAF-style body signatures even if the status codes vary

This was intentionally tightened beyond a pure status/body-template heuristic to avoid false positives from normal auth and CSRF middleware responses.

### 3. Integrated into all existing vuln engines

**File:** `src/boba/tools/vuln.py`

Collected relevant `HttpResponse` objects and now set `waf_detected` in:

- `test_idor`
- `test_ssrf`
- `test_xss`
- `test_sqli`
- `test_auth`
- `test_race`
- `test_redirect`
- `test_csrf`
- `test_mass_assign`
- `test_reset`
- `test_ai`

Implementation detail:

- `waf_detected` is only set when `vulnerable` is still `False`
- This avoids downgrading successful findings that happened despite edge filtering or partial blocking

## Tests Added / Updated

**Files:**

- `tests/tools/test_vuln.py`
- `tests/tools/test_vuln_v3.py`

Coverage added:

- helper-level WAF detection tests
- SSRF integration test for blocked payload templates
- race-condition integration test for blocked concurrent requests
- regression assertions that successful findings keep `waf_detected=False`
- regression assertions that normal clean results keep `waf_detected=False`

## Validation

Ran successfully:

- `python3 -m ruff check src tests`
- `python3 -m ruff format --check` on changed files
- `python3 -m pytest`

Result: **598 tests passed**

## Notes / Trade-offs

- Some engines naturally generate fewer meaningful attack responses than others, so the signal is strongest on payload-heavy tests like SSRF, XSS, SQLi, redirect, race, and AI.
- The current heuristic is intentionally conservative: it prefers missing a weak WAF signal over falsely labeling standard authorization/CSRF defenses as WAF behavior.
