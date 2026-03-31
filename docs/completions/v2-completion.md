# Boba V2 Completion Notes — Interaction: Browser, HTTP & Vulnerability Testing

**Date:** 2026-03-31
**Status:** Implemented and tested
**Scope:** 20 new Python files, ~3,200 lines of new code, 115 total tests passing (86 new)

---

## What Was Implemented

### 1. Dependencies & Packaging (`pyproject.toml`)

Added three new runtime dependencies:
- `playwright>=1.40` — headless browser automation for web interaction
- `httpx>=0.27` — async HTTP client for crafted requests (Burp Repeater/Intruder equivalent)
- `pyjwt[crypto]>=2.8` — JWT manipulation for auth testing

Added optional dependency group:
- `oob = ["interactsh-py>=0.1"]` — for OOB/blind vulnerability detection

### 2. New Error Types (`core/errors.py`)

Added 3 new errors to the hierarchy:
```
BobaError
├── ... (existing V1 errors)
├── BrowserError      — Playwright automation failures
├── SessionError      — Session management failures
└── OOBError          — Interactsh/OOB listener failures
```

### 3. Configuration Extensions (`core/config.py`)

Added per-hunt directory functions:
- `get_hunt_dir(hunt_id)` → `~/.boba/hunts/<hunt_id>/`
- `get_bodies_dir(hunt_id)` → `~/.boba/hunts/<hunt_id>/bodies/` (large HTTP body storage)
- `get_templates_dir(hunt_id)` → `~/.boba/hunts/<hunt_id>/templates/` (custom Nuclei templates)

### 4. New Models (`core/models.py`)

**New enums (4):**

| Enum | Values |
|---|---|
| `AuthMethod` | form, cookie, bearer, basic, header, oauth2 |
| `Severity` | critical, high, medium, low, info |
| `Confidence` | confirmed, likely, possible |
| `FuzzAttackType` | sniper, battering_ram, pitchfork, cluster_bomb |

**New dataclasses (9):**

| Dataclass | Purpose |
|---|---|
| `BrowserConfig` | Playwright browser settings (headless, proxy, viewport, user agent) |
| `SessionState` | Serializable auth state (cookies, headers, tokens, storage state) |
| `PageInfo` | Returned by `browser.navigate()` — URL, status, title, timing, cookies |
| `DOMExtraction` | Returned by `browser.extract()` — forms, links, scripts, comments, inputs |
| `HttpResponse` | Returned by `HttpClient.request()` — status, headers, body, timing |
| `CompareResult` | Returned by `HttpClient.compare()` — structured diff of two responses |
| `FuzzResult` | Returned by `HttpClient.fuzz()` — all results + anomaly detection |
| `VulnTestResult` | Returned by all `test_*()` tools — vulnerable, confidence, evidence, request IDs |

### 5. Schema Extensions (`core/context.py`)

**4 new SQLite tables:**

| Table | UNIQUE constraint | Key design |
|---|---|---|
| `http_history` | Auto-increment (no dedup) | Full request/response capture with `source`, `session_name`, `parent_request_id` for correlation. 7 indexes for performant querying. |
| `sessions` | `(hunt_id, name)` | Stores serialized auth state (cookies/headers/tokens as JSON). Upsert updates on name conflict. |
| `findings` | `(hunt_id, finding_type, url, parameter)` | Deduplicates findings by type+url+param. `parameter` is NOT NULL DEFAULT '' (V1 lesson: no COALESCE in UNIQUE). |
| `oob_listeners` | `(hunt_id, listener_id)` | Tracks OOB callback domains and their interactions. Upsert merges interactions. |

**New context methods (16):**

| Category | Methods |
|---|---|
| HTTP History | `insert_http_record()`, `get_http_record()`, `query_http_history()`, `update_http_record_tags()`, `update_http_record_notes()` |
| Sessions | `upsert_session()`, `get_session()`, `get_sessions()`, `delete_session()`, `touch_session()` |
| Findings | `upsert_finding()`, `get_findings()` |
| OOB | `insert_oob_listener()`, `update_oob_interactions()`, `get_oob_listeners()` |

**Stats extended:** `get_hunt_stats()` now includes `http_history`, `sessions`, and `findings` counts.

### 6. HttpHistorySink (`interaction/history.py`)

**What it does:** Single write path for all HTTP exchanges — browser traffic, raw HTTP requests, replays, and fuzz results all flow through this interface.

**Large body handling:** Bodies ≤ 64KB stored inline in SQLite. Bodies > 64KB written to `~/.boba/hunts/<hunt_id>/bodies/<prefix>_<idx>.bin` with a 4KB truncated preview inline. Full body retrievable via `get_full_body()`.

**Interface:** `record()`, `get()`, `get_full_body()`, `query()`, `tag()`, `annotate()`

### 7. HttpClient (`interaction/http.py`)

**What it does:** Burp Repeater + Intruder equivalent. Async HTTP client using `httpx` with full TLS/header/redirect control. Every request persisted via the sink.

**Core methods:**
- `request()` — send arbitrary HTTP requests with full header/body/cookie control
- `replay()` — replay a request from http_history with modifications, linked via `parent_request_id`
- `compare()` — structured diff of two responses (status, headers, body, timing)
- `fuzz()` — systematic parameter fuzzing with all 4 Burp Intruder attack types

**Fuzz attack types:**

| Type | Behavior |
|---|---|
| `sniper` | One position at a time, cycle payloads |
| `battering_ram` | All positions get same payload |
| `pitchfork` | Positions paired by index |
| `cluster_bomb` | Cartesian product |

**Anomaly detection:** Fuzz results compare against first response (baseline). Entries with different status codes or >10% body length deviation are flagged as anomalies.

**Why httpx, not Playwright:** Connection-level control (custom Host headers, malformed headers, no auto-cookies), no browser overhead per request, async-native.

### 8. SessionManager (`interaction/session.py`)

**What it does:** Manages named auth sessions. Sessions are **data, not connections** — serializable blobs of auth state that can be applied to either browser contexts or HTTP clients.

**Auth methods implemented:**
- `login_bearer()` — set Authorization: Bearer header
- `login_basic()` — set HTTP Basic auth
- `login_cookies()` — inject raw cookies
- `login_header()` — set arbitrary custom header
- `login_form()` — browser-based form login (fills form, submits, captures cookies/storage)

**Persistence:** Sessions survive across manager instances via SQLite. In-memory cache for fast access.

**IDOR workflow enabled:**
1. `create("user_a")` + `create("user_b")`
2. Login both sessions
3. `apply_to_headers("user_a")` → request endpoint → response_a
4. `apply_to_headers("user_b")` → same request → response_b
5. Compare: if response_b ≈ response_a → IDOR

### 9. BrowserManager (`interaction/browser.py`)

**What it does:** Playwright-based browser automation with traffic interception. Replaces Chrome + Burp Proxy.

**Architecture:** One Playwright instance → one Chromium browser → N named browser contexts (one per session + "default"). Each context has its own cookies, storage, and page.

**Traffic interception:** Uses `page.on("response", handler)` for real-time capture. Every request/response written to SQLite via HttpHistorySink as it happens. Not HAR (which is post-hoc).

**Core methods:**
- `navigate(url)` → `PageInfo` (status, title, timing, cookies, requests captured)
- `extract()` → `DOMExtraction` (forms, links, scripts, meta, HTML comments, inputs, text)
- `screenshot(path)` → saves PNG for evidence/PoC
- `execute_js(script)` → run arbitrary JavaScript (for XSS verification)
- `fill_form(selector, values)` → fill and optionally submit forms
- `click(selector)` → click elements
- `apply_session(state)` → inject SessionState into a named browser context

**DOM extraction** runs a single `page.evaluate()` call with inline JS that extracts all structural data. HTML comments are captured (they often leak debug info, internal endpoints, credentials).

### 10. OOBManager (`interaction/oob.py`)

**What it does:** Manages out-of-band listeners for detecting blind vulnerabilities (blind SSRF, blind XSS, blind command injection).

**Design:** Each listener gets a unique callback domain from Interactsh. The `purpose`, `target_url`, `parameter`, and `test_payload` fields enable correlation back to the exact injection point.

**Fallback:** When `interactsh-py` is not installed, a `_FallbackOOBClient` generates random `.oast.local` domains. No real callbacks — useful for testing and environments without Interactsh.

**Interface:** `start()`, `stop()`, `create_listener()`, `get_payload_url()`, `poll()`, `check_all()`

### 11. Nuclei Adapter (`adapters/nuclei.py`)

Follows the V1 `BaseAdapter` pattern exactly:

| Property | Value |
|---|---|
| TOOL_NAME | `"nuclei"` |
| OUTPUT_FORMAT | `JSON_LINES` |
| PRODUCES | `"finding"` |
| SCOPE_MODE | `"pre"` |

**Command construction:** Supports `-severity`, `-tags`, `-t` (custom templates), `-rate-limit`, and extra args. Single target uses `-u`, multiple targets use `-l` with temp file.

**Output parsing:** Maps Nuclei's JSON output to canonical finding records: `template_id`, `severity`, `url`, `extracted_results`, `tags`, etc.

**High-level tool:** `tools/scan.py::nuclei_scan()` runs Nuclei and persists results to the findings table.

**Registry updated:** `adapters/__init__.py` now includes `"nuclei": NucleiAdapter`.

### 12. Built-in Payloads (`payloads/`)

4 Python modules exporting `list[str]` constants:

| Module | Contents | Count |
|---|---|---|
| `xss.py` | BASIC, POLYGLOTS, EVENT_HANDLERS, ENCODING_BYPASS, DOM_CANARY, BLIND_TEMPLATES | ~30 payloads |
| `sqli.py` | ERROR_BASED, BOOLEAN_BASED, TIME_BASED (MySQL/PG/MSSQL/SQLite), UNION_BASED, ERROR_SIGNATURES | ~40 payloads |
| `ssrf.py` | LOCALHOST, AWS/GCP/AZURE_METADATA, INTERNAL_RANGES, PROTOCOL_SMUGGLE | ~30 payloads |
| `auth.py` | JWT helpers (`jwt_decode_parts`, `jwt_none_algorithm`, `jwt_modify_claims`), ESCALATION_CLAIMS, COMMON_JWT_SECRETS | Functions + ~20 entries |

**Design:** Python modules, not external files. Each has an `ALL` list for default usage. Agents can also pass custom payloads via function parameters.

### 13. Vulnerability Testing Tools (`tools/vuln.py`)

5 testing functions that compose all interaction primitives:

| Function | What it tests | Detection method |
|---|---|---|
| `test_idor()` | Broken access control | Compare responses across 3 auth levels (owner, attacker, no-auth) |
| `test_ssrf()` | Server-side request forgery | Response content analysis (metadata signatures) + OOB callbacks |
| `test_xss()` | Cross-site scripting | Reflected payload detection + DOM-based via browser + blind via OOB |
| `test_sqli()` | SQL injection | Error signatures + boolean-based (true/false response diff) |
| `test_auth()` | Auth/authz bypass | No-auth access + JWT none algorithm + claim escalation |

**Common pattern:** Each returns `VulnTestResult` with `vulnerable`, `confidence`, `severity`, `evidence` (structured proof), and `request_ids` (links to http_history).

**SSRF fix during implementation:** The metadata check (`200 for 169.254.169.254`) was overwriting `CONFIRMED` confidence from earlier indicator detection. Fixed by guarding with `if not vulnerable`.

### 14. CLI Extensions (`cli/main.py`)

5 new command groups + 4 context extensions:

```
boba browser
├── navigate    — Navigate URL, capture traffic
├── screenshot  — Capture page screenshot
└── extract     — Extract structured DOM data

boba http
├── request     — Send crafted HTTP request
├── replay      — Replay from history with modifications
└── compare     — Diff two responses

boba session
├── create      — Create named session
├── login-token — Set Bearer token
├── list        — List sessions
└── delete      — Delete session

boba scan
└── nuclei      — Run Nuclei scanner

boba test
├── idor        — Test for IDOR
├── ssrf        — Test for SSRF
├── xss         — Test for XSS
├── sqli        — Test for SQL injection
└── auth        — Test authentication controls

boba context    (extended)
├── http-history — Query HTTP history
├── findings    — List vulnerability findings
├── sessions    — List active sessions
└── oob         — List OOB listeners
```

Total: 9 command groups (4 existing + 5 new), 36 commands (14 existing + 22 new).

### 15. Tests (86 new, 115 total)

| Test file | Tests | What's tested |
|---|---|---|
| `test_context_v2.py` | 17 | http_history CRUD/query, sessions CRUD, findings upsert/dedup, OOB listeners, V2 stats |
| `test_history.py` | 11 | Record persistence, large body file storage, query filters, tag/annotate |
| `test_http.py` | 11 | Request with mocked httpx, replay from history, response comparison, all 4 fuzz attack types |
| `test_session.py` | 14 | Create, login (bearer/basic/cookies/header), apply to headers/cookies, persistence across instances |
| `test_browser.py` | 5 | Lifecycle, navigate, extract DOM, screenshot, session application (all mocked Playwright) |
| `test_oob.py` | 9 | Lifecycle, listener creation/persistence, payload URLs, polling with fallback |
| `test_nuclei.py` | 9 | JSON parsing, command construction, severity/tags filters, scope filtering |
| `test_vuln.py` | 10 | IDOR (confirmed + not-vulnerable), SSRF (metadata detection + safe), XSS (reflected + escaped), SQLi (error-based + safe), Auth (no-auth bypass + enforced) |

---

## Deviations from the Plan

| Plan | Actual | Reason |
|---|---|---|
| SQLmap adapter | Deferred | Lower priority than core interaction tools; agents can use built-in SQLi payloads for detection. SQLmap can be added later for exploitation. |
| `fuzz()` with position markers in URL | Uses `§position§` markers | Follows Burp Intruder convention for marking injection points |
| OAuth2 login flow | Deferred | Complex flow requiring multiple redirects; form login + bearer token cover most cases |
| Interactsh Python library as primary | Fallback-first design | `interactsh-py` may not be installed; fallback client enables testing and development without it |
| `boba session login` (browser-based) | `boba session login-token` CLI only | Browser-based form login requires long-running browser; better suited for programmatic use than CLI |
| pytest collection conflict | Used `from boba.tools import vuln` | Functions named `test_*` in vuln.py were collected by pytest when imported directly |

## What's NOT Implemented (Deferred to V3+)

- OAuth2 browser-based login flow — V3
- SQLmap adapter for automated SQL exploitation — V3
- Response diffing with actual unified diff output — V3
- HTTP smuggling / request splitting tools — V3
- Stealth browser plugins (playwright-extra + stealth) — V4
- Streaming persistence during long fuzz runs — future
- SecLists auto-installation / wordlist management — future
- MCP server wrapper — future

## How to Verify

```bash
# Install (includes new deps)
cd boba && pip install -e ".[dev]"

# Install Playwright browsers (required for browser commands)
playwright install chromium

# Run all tests
pytest tests/ -v

# Try the CLI — new command groups
boba browser --help
boba http --help
boba session --help
boba scan --help
boba test --help

# Context extensions
boba context http-history --help
boba context findings --help
boba context sessions --help
boba context oob --help

# Example workflow (requires a live target):
# boba hunt create --name "IDOR Test"
# boba session create <hunt-id> --name user_a --target https://app.example.com
# boba session create <hunt-id> --name user_b --target https://app.example.com
# boba session login-token <hunt-id> user_a --token <token_a>
# boba session login-token <hunt-id> user_b --token <token_b>
# boba test idor <hunt-id> --endpoint https://app.example.com/api/users/123 \
#     --session-a user_a --session-b user_b
# boba context findings <hunt-id> --format json
# boba context http-history <hunt-id> --source test_idor
```
