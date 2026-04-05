# V3 Phase 6 Completion — Advanced Vulnerability Tools

**Date:** 2026-04-02
**Scope:** 7 files modified/created, 16 new tests, 579 tests passing (16 new, 0 regressions)

## What Was Done

Phase 6 adds **6 new vulnerability test types** to the testing toolkit, completing the capability map from the product vision. After this phase, the agent can test for 11 distinct vulnerability classes.

## New Test Types

| Tool | What It Tests | Detection Method |
|---|---|---|
| `test_race` | Race conditions (double-spend, resource claiming) | Send N concurrent identical requests, detect divergent responses or multiple successes |
| `test_redirect` | Open redirect | Inject external URLs into redirect parameters, check Location header for external hosts |
| `test_csrf` | Cross-Site Request Forgery | Send without CSRF token, with invalid token, with cross-origin headers — check if accepted |
| `test_mass_assign` | Mass assignment / parameter pollution | Send extra JSON fields (isAdmin, role), re-fetch to check if they persisted |
| `test_reset` | Password reset flaws | Host header injection in reset URL, rate limiting check |
| `test_ai` | AI/LLM prompt injection | Inject override/exfiltration payloads, detect canary markers or system prompt leak indicators |

## Changes By File

### New Files

| File | Purpose |
|---|---|
| `src/boba/payloads/redirect.py` | Open redirect payloads (direct, protocol-relative, backslash, encoded, subdomain confusion) |
| `src/boba/payloads/csrf.py` | CSRF token parameter names, protection headers, cross-origin test headers |
| `src/boba/payloads/ai.py` | Prompt injection payloads (exfiltration, override), canary markers, leak indicators |
| `tests/tools/test_vuln_v3.py` | 16 tests covering all 6 new tool types |

### Modified Files

| File | What Changed |
|---|---|
| `src/boba/tools/vuln.py` | Added `test_race()`, `test_redirect()`, `test_csrf()`, `test_mass_assign()`, `test_reset()`, `test_ai()` — all with auto-coverage recording |
| `src/boba/cli/main.py` | Added 6 CLI commands: `test race`, `test redirect`, `test csrf`, `test mass-assign`, `test reset`, `test ai` |

## Key Design Decisions

### 1. Race condition via asyncio.gather

`test_race` uses `asyncio.gather` to fire N requests truly concurrently (not sequentially). This matters because race conditions only manifest under concurrent load — sequential requests would serialize through any server-side mutex. The default concurrency of 10 is enough to trigger most race conditions while staying within responsible testing bounds.

### 2. Open redirect checks the Location header, not body

Some redirect implementations return 200 with a JS redirect or meta refresh. `test_redirect` focuses on server-side redirects (3xx + Location header) because these are the highest-confidence signals. The check explicitly excludes same-host and subdomain redirects to avoid false positives on legitimate internal routing.

### 3. CSRF uses three-signal detection

1. No token → accepted (most common CSRF)
2. Invalid token → accepted (token present but not validated)
3. Cross-origin headers → accepted (Origin/Referer check missing)

If signal 1 AND signal 2 both fire, confidence upgrades to CONFIRMED. This mirrors how real triagers assess CSRF — a single missing check is LIKELY, two missing checks is CONFIRMED.

### 4. Mass assignment checks persistence, not response

Simply getting a 200 response to a request with extra fields doesn't mean mass assignment worked — the server might silently ignore unknown fields. `test_mass_assign` does a before/after GET comparison to verify that the injected fields actually persisted. This eliminates false positives from permissive APIs.

### 5. AI prompt injection uses canary markers

Rather than trying to semantically analyze LLM responses (fragile), the engine injects payloads that instruct the LLM to include specific canary strings ("PWNED", "CANARY42"). If the canary appears in the response, injection succeeded. For system prompt leaks, it counts leak indicators (≥3 matches required) to avoid false positives from legitimate AI-related content.

### 6. All 6 tools auto-record coverage

Every new test function calls `_record_coverage()` before returning, consistent with the Phase 1 pattern. This means the coverage tracker automatically knows what's been tested without any extra work.

## Complete Vulnerability Test Inventory (11 types)

| Phase | Test Type | Severity | CLI Command |
|---|---|---|---|
| V2 | IDOR | High | `boba test idor` |
| V2 | SSRF | Critical | `boba test ssrf` |
| V2 | XSS | Medium | `boba test xss` |
| V2 | SQLi | Critical | `boba test sqli` |
| V2 | Auth bypass | Critical | `boba test auth` |
| V3 | Race condition | High | `boba test race` |
| V3 | Open redirect | Medium | `boba test redirect` |
| V3 | CSRF | Medium | `boba test csrf` |
| V3 | Mass assignment | High | `boba test mass-assign` |
| V3 | Password reset | High | `boba test reset` |
| V3 | AI prompt injection | High | `boba test ai` |

## Test Coverage (16 new tests)

| Test Class | Count | What's Tested |
|---|---|---|
| `TestRaceCondition` | 3 | Divergent responses, identical responses, concurrency count |
| `TestOpenRedirect` | 3 | External redirect, same-host clean, no redirect clean |
| `TestCSRF` | 2 | No token accepted, token required |
| `TestMassAssign` | 2 | Field persisted, field rejected |
| `TestPasswordReset` | 3 | Host header injection, rate limit, clean reset |
| `TestAIPromptInjection` | 3 | Instruction override, system prompt leak, clean response |

## CLI Usage

```bash
boba test race <hunt-id> --url URL --method POST --concurrency 10
boba test redirect <hunt-id> --url URL --param next
boba test csrf <hunt-id> --url URL --session user_a --method POST
boba test mass-assign <hunt-id> --url URL --session user_a
boba test reset <hunt-id> --url URL --email-param email
boba test ai <hunt-id> --url URL --param message
```

## What's Next

Phase 7: **Platform API Integration** — submit reports to HackerOne and Bugcrowd, track status, respond to triagers.
