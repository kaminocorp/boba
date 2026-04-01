# Changelog

- [0.2.7](#027--pre-v3-final-quality-gate) — Critical _safe_close recursion fix, SSRF false-positive cleanup, XSS decoded reflection, OOB O(n*m) fix, session deepcopy, cluster bomb cap, CSS escape, 15 fixes total
- [0.2.6](#026--final-review--pre-v3-readiness) — Per-request timeout, time-based SQLi, XSS partial reflection, JWT exceptions, IDOR enumeration, CLI safety, 16 fixes total
- [0.2.5](#025--pre-v3-quality-gate) — Subprocess exit code fix, scope URL bypass fix, OOB warning, adapter exit code logging, browser timing, compare bytes
- [0.2.4](#024--operational-robustness) — Persistent HTTP client, body_text truncation fix, diagnostic logging, SQLi baseline fix
- [0.2.3](#023--data-integrity--resource-safety) — Technology commit fix, broader parse error handling, HuntContext context manager, lint cleanup, gather partial results
- [0.2.2](#022--detection-correctness--defensive-robustness) — IDOR URL path fix, SSRF indicators, auth regex, XSS reflection, subprocess signaling, CLI hardening
- [0.2.1](#021--code-quality--correctness) — IPv6 scope handling, URL encoding for payloads, JSON decode safety, IDOR similarity, SQLi threshold, output bounding
- [0.2.0](#020--interaction-browser-http--vulnerability-testing) — Browser automation, HTTP client, session management, OOB listeners, 5 vuln test tools, Nuclei adapter, CLI extensions
- [0.1.0](#010--foundation-recon--enumeration) — Core framework, 8 tool adapters, scope engine, SQLite persistence, CLI

---

## 0.2.7 — Pre-V3 Final Quality Gate

**Date:** 2026-03-31
**Scope:** 14 files modified, 116 tests passing (0 regressions)
**Details:** [v1v2-pre-v3-final-gate.md](completions/v1v2-pre-v3-final-gate.md)

5-agent parallel codebase review uncovered 1 critical bug, 7 high-priority issues, and 7 medium-priority fixes surviving all prior hardening rounds. Score: 6.5/10 → 8.5/10.

- **`_safe_close()` infinite recursion fixed** — helper called itself instead of `manager.close_context()`, leaking SQLite connections on every CLI invocation
- **`SystemExit(1)` → `typer.Exit(code=1)`** — invalid `--format` no longer bypasses Typer's `finally` blocks
- **SSRF false positives eliminated** — removed generic "internal server error" from confirmed indicators; evidence collection no longer halted by early false match; break after confirmed
- **XSS decoded reflection check** — URL-encoded payloads now also checked in decoded form; partial reflection threshold tightened (8→16 chars)
- **OOB poll O(n*m) → O(n+m)** — listeners fetched once before interaction loop, not per-interaction
- **SessionState `get()` returns deepcopy** — callers can no longer accidentally mutate cached session state
- **Cluster bomb capped at 100K combinations** — prevents accidental OOM from Cartesian product explosion
- **CSS selector injection fixed** — field names escaped in `fill_form()` and `login_form()` before CSS interpolation
- **Scope CIDR classification fixed** — `10.0.0.0/24` no longer misclassified as URL
- **`enum.py` config mutation prevented** — caller-provided configs are deepcopied before mutation
- **SSRF `PROTOCOL_SMUGGLE` added to `ALL`** — `file:///etc/passwd` now tested by default
- **SQLi MSSQL payload removed from MySQL list** — eliminates duplicate request
- **Body file path traversal validation** — `get_full_body()` validates path is within body directory
- **Browser `stop()` exception-safe** — browser/playwright close failures no longer prevent each other
- **Dead hash comparison removed** from `_bodies_similar`

---

## 0.2.6 — Final Review & Pre-V3 Readiness

**Date:** 2026-03-31
**Scope:** 14 files modified, 116 tests passing (1 new, 0 regressions)
**Details:** [v1v2-final-review.md](completions/v1v2-final-review.md)

Comprehensive 5-agent parallel codebase review for V3-readiness. Fixed 7 correctness bugs, 7 robustness issues, and 2 code quality fixes that survived all prior hardening rounds.

- **Per-request timeout now works in HttpClient** — `timeout_seconds` parameter was accepted but never passed to httpx; also removed misleading unused `verify_ssl`/`proxy` params from `request()`
- **Time-based SQL injection detection implemented** — completes the 4-method SQLi detection documented in the docstring; uses SLEEP payloads with 3s delay threshold over baseline
- **XSS partial reflection now flags as vulnerable** — inner payload content reflected without tags is reported with POSSIBLE confidence instead of silently discarded
- **JWT exception handler narrowed** — `except (ValueError, Exception)` replaced with specific `(ValueError, KeyError, IndexError)` to stop masking real errors
- **IDOR object enumeration always runs** — no longer gated on prior `vulnerable=True`; provided test IDs are always tested and can upgrade confidence
- **SQLi boolean threshold includes boundary** — `> 20` → `>= 20` bytes; `> 0.05` → `>= 0.05` relative
- **Scope post-filter handles empty-string targets** — `""` targets no longer bypass scope checking via Python truthiness
- **`create_hunt()` is now transactional** — hunt + scope_rules wrapped in `with self._conn:`; prevents partial state
- **OOB poll loop logs exceptions** — `except Exception: pass` replaced with debug logging
- **Browser `fill_form` has timeout** — `wait_for_load_state("networkidle")` no longer hangs indefinitely
- **CLI finally blocks can't mask exceptions** — 41 locations now use `_safe_close()` helper
- **Invalid `--format` exits with error** — no longer silently falls back to table output
- **HttpHistorySink gracefully handles file I/O errors** — falls back to truncated inline storage
- **DOM XSS evidence includes URL** — adds traceability for browser-based detection
- **Dead code removed** from `get_hunt_stats()`
- **Duplicate XSS payload removed** from polyglots list

---

## 0.2.5 — Pre-V3 Quality Gate

**Date:** 2026-03-31
**Scope:** 8 files modified, 115 tests passing (0 regressions)
**Details:** [v1v2-pre-v3-quality-gate.md](completions/v1v2-pre-v3-quality-gate.md)

Final quality gate before V3 development. 4-agent parallel codebase review uncovered 2 critical bugs and 6 correctness/robustness issues that survived prior hardening rounds.

- **Subprocess exit code 0 no longer misreported as -1** — `process.returncode or -1` treated success (0) as falsy; now uses explicit `is not None` check
- **Scope URL prefix bypass eliminated** — bare `"*"` pattern produced empty prefix that matched every URL via `startswith("")`; empty prefixes now skipped
- **OOB fallback logs warning** — silent `ImportError` catch no longer masks disabled blind vulnerability detection
- **Httpx port 0 correctly parsed** — truthiness check replaced with `is not None`
- **Ffuf warns on multiple targets** — no longer silently drops targets beyond the first
- **Base adapter logs non-zero exit codes** — tool failures no longer silently return empty results
- **Browser interception timing corrected** — replaced unreliable Playwright timing value with explicit 0
- **HTTP compare() handles bytes bodies** — defensive normalization prevents wrong diffs

---

## 0.2.4 — Operational Robustness

**Date:** 2026-03-31
**Scope:** 6 files modified, 1 test file updated, 115 tests passing (0 regressions)
**Details:** [v1v2-operational-robustness.md](completions/v1v2-operational-robustness.md)

Final quality gate before V3 development. Addresses runtime reliability and debuggability issues found during a comprehensive 5-agent codebase audit.

- **Response body_text no longer truncated** — removed silent 8KB cap that caused vuln detection tools to miss evidence in longer responses
- **Persistent HttpClient** — connection pool reused across requests instead of create/destroy per call; `async with` lifecycle support
- **Diagnostic logging in 20+ catch blocks** — all JSON decode failures in context.py, parse errors in base adapter, and browser interception errors now emit warnings/debug logs with entity IDs and exception details
- **SQL table name validation** — `get_hunt_stats()` uses immutable `frozenset` allowlist instead of inline list
- **Browser shutdown ordering** — pages closed before their parent contexts to prevent race conditions in async handlers
- **SQLi baseline includes test parameter** — boolean-based detection now compares against structurally identical baseline request

---

## 0.2.3 — Data Integrity & Resource Safety

**Date:** 2026-03-31
**Scope:** 8 files modified, 115 tests passing (0 regressions)
**Details:** [v1v2-pre-v3-fixes.md](completions/v1v2-pre-v3-fixes.md)

Pre-V3 pass targeting transaction safety, exception handling completeness, and resource lifecycle.

- **Technology records committed to database** — `upsert_technology` added to `upsert_records()` dispatch table; `recon.tech()` rewritten to use batch path
- **Broader parse_record() exception handling** — JSON_LINES, JSON_OBJECT, JSON_ARRAY handlers now catch `Exception` (matching PLAIN_LINES), preventing one bad record from crashing the entire run
- **HuntContext context manager** — `__enter__`/`__exit__` for automatic SQLite cleanup
- **37 lint errors resolved** — unused imports and variable assignments across 15 files
- **HTTP body file naming** — UUID-based (collision-free) instead of glob-counter (race-prone)
- **Browser context cleanup on setup failure** — context registered only after page+interception succeed
- **`asyncio.gather()` partial results** — `recon.urls()` uses `return_exceptions=True` so one adapter failure doesn't discard the other's results

---

## 0.2.2 — Detection Correctness & Defensive Robustness

**Date:** 2026-03-31
**Scope:** 10 files modified, 115 tests passing (0 regressions)
**Details:** [v1v2-hardening.md](completions/v1v2-hardening.md)

Second quality pass targeting detection accuracy in the 5 vuln tools and defensive robustness in adapter/interaction/persistence layers.

- **IDOR URL path manipulation** — `urlparse`/`urlunparse` instead of naive `str.replace()` that corrupted URLs with trailing slashes or duplicate segments
- **SSRF indicator list unconditional** — `"internal server error"` checked for all SSRF vectors, not just localhost
- **Auth endpoint regex** — path-boundary matching (`/admin/`, `/admin?`) instead of substring (`/gadmin`, `/administrator`)
- **XSS partial reflection** — extracts inner content between tags with 8-char minimum, reducing false positives
- **Version sync** — `__version__` updated to 0.2.0 to match pyproject.toml
- **JSON decode safety in V2 methods** — `get_session()`, `get_sessions()`, `get_findings()`, `get_oob_listeners()` wrapped with try/except
- **Subprocess stdin cleanup** — try/finally ensures pipe closed even on drain failure
- **Subprocess truncation signal** — `output_truncated` field on `SubprocessResult`
- **PLAIN_LINES error handling** — matches JSON format handlers' try/except pattern
- **Session login_form validation** — raises `SessionError` if no selectors match instead of returning silently
- **OOB listener matching** — `startswith` instead of substring `in` check
- **CLI hardening** — required URL param, comma whitespace stripping, help text, format validation

---

## 0.2.1 — Code Quality & Correctness

**Date:** 2026-03-31
**Scope:** 12 files modified, 115 tests passing (0 regressions)
**Details:** [v1v2-refinements.md](completions/v1v2-refinements.md)

First quality pass addressing correctness, safety, and robustness issues across the V1/V2 codebase.

- **IPv6 scope handling** — new `_strip_port()` method correctly handles bracketed IPv6, bare IPv6, and IPv4 with ports
- **URL encoding for vuln payloads** — new `_inject_param()` helper uses `urlparse`/`urlencode` instead of raw string concatenation across all 9 injection points
- **WaybackurlsAdapter initialization** — `_stdin_targets` initialized in `__init__` to prevent `AttributeError`
- **Parse error tracking** — `parse_output()` returns `(records, parse_errors)` tuple; `parse_errors` field on `ToolResult`
- **Async context managers** — `BrowserManager` and `OOBManager` support `async with`
- **Temp file safety** — `mktemp()` replaced with `NamedTemporaryFile` in whatweb and ffuf adapters
- **JSON decode safety** — `_row_to_hunt()`, `get_http_record()`, `query_http_history()` wrapped with try/except
- **Scope rule validation** — malformed patterns caught at compile time instead of match time
- **IDOR similarity check** — three-stage comparison (exact → SHA-256 → structural line overlap) instead of length-only
- **SQLi boolean threshold** — dual threshold (absolute 20 bytes OR relative 5%) instead of fixed 50 bytes
- **Output size bounding** — 256MB cap on subprocess stdout accumulation

---

## 0.2.0 — Interaction: Browser, HTTP & Vulnerability Testing

**Date:** 2026-03-31
**Scope:** 20 new files, ~3,200 lines of new code, 115 tests passing (86 new)

V2 gives agents the ability to interact with web applications and test for vulnerabilities — replacing what a human does with Burp Suite + a browser.

### Interaction Layer (`interaction/`)

- **HttpHistorySink** — single write path for all HTTP exchanges. Large bodies (>64KB) stored as files with inline preview. Query by host, method, status, source, session.
- **HttpClient** — Burp Repeater/Intruder equivalent. `request()`, `replay()`, `compare()`, `fuzz()` with all 4 attack types (sniper, battering_ram, pitchfork, cluster_bomb).
- **SessionManager** — named auth sessions with bearer, basic, cookie, header, and form login. Sessions are serializable data, applicable to both browser and HTTP client.
- **BrowserManager** — Playwright-based. Navigate, screenshot, extract DOM, execute JS, fill forms. Traffic intercepted in real-time via `page.on("response")`.
- **OOBManager** — Interactsh integration for blind vulnerability detection. Fallback client when Interactsh unavailable.

### Vulnerability Testing (`tools/vuln.py`)

- `test_idor()` — compare responses across 3 auth levels (owner, attacker, no-auth)
- `test_ssrf()` — response content analysis + OOB callback detection
- `test_xss()` — reflected payload detection + DOM-based via browser
- `test_sqli()` — error signatures + boolean-based response diff
- `test_auth()` — no-auth access + JWT none algorithm + claim escalation

### New Adapter

- **Nuclei** (`adapters/nuclei.py`) — template-based vulnerability scanning. Results persisted to findings table. Supports severity/tags/template filters.

### Built-in Payloads (`payloads/`)

- XSS: polyglots, event handlers, encoding bypasses, blind callbacks
- SQLi: error-based, boolean-based, time-based (MySQL/PG/MSSQL/SQLite)
- SSRF: localhost variants, cloud metadata (AWS/GCP/Azure), internal ranges
- Auth: JWT manipulation helpers, escalation claims

### Schema Extensions

4 new tables: `http_history`, `sessions`, `findings`, `oob_listeners`. 16 new context methods.

### CLI

5 new command groups (browser, http, session, scan, test) + 4 context extensions (http-history, findings, sessions, oob). Total: 9 command groups, 36 commands.

---

## 0.1.0 — Foundation: Recon & Enumeration

**Date:** 2026-03-31
**Scope:** 33 files, ~3,000 lines, 29 tests passing

The initial release establishes Boba's core architecture and delivers a complete recon/enumeration toolkit that agents can use to discover and map attack surfaces.

### Core Framework

- **Scope engine** (`core/scope.py`) — default-deny model with domain wildcards (`*.example.com`), IP/CIDR ranges, and URL prefix matching. Exclusions always win. Per-adapter scope modes (pre, post, both) enforce boundaries at the right point in each tool's lifecycle.
- **Hunt context** (`core/context.py`) — SQLite-backed persistence (WAL mode, foreign keys) with 8 tables. Upserts deduplicate records and merge sources via `json_each()` + `json_group_array()` — no read-modify-write cycles.
- **Hunt management** (`core/hunt.py`) — create, pause, resume, close hunts with 12-char hex IDs. Stats query across all tables.
- **Async subprocess** (`core/subprocess.py`) — line-by-line stdout reading (memory-bounded), timeout with SIGKILL, optional stdin piping, streaming async generator variant.
- **Error hierarchy** — `BobaError` base with `ToolNotFoundError`, `ToolTimeoutError`, `ToolExecutionError`, `ScopeViolationError`, `HuntNotFoundError`.
- **Data models** (`core/models.py`) — dataclass-based: `Hunt`, `ScopeRule`, `ScopeConfig`, `AdapterConfig`, `ToolResult`, `SubprocessResult`, plus enums for status, scope actions, output formats.

### Adapters (8 tools)

Base adapter with 6-phase lifecycle: `find_binary() → pre_filter_targets() → build_command() → run_subprocess() → parse_output() → post_filter_records()`. Binary discovery searches PATH, `~/go/bin/`, `~/.local/bin/`.

| Adapter | Tool | Produces | Output Format |
|---|---|---|---|
| `subfinder.py` | subfinder | subdomains | JSON lines |
| `httpx_runner.py` | httpx | hosts | JSON lines |
| `naabu.py` | naabu | ports | JSON lines |
| `gau.py` | gau | urls | plain lines |
| `waybackurls.py` | waybackurls | urls | plain lines (stdin-piped) |
| `whatweb.py` | whatweb | technologies | JSON array (output file) |
| `katana.py` | katana | urls | JSON lines |
| `ffuf.py` | ffuf | directories | JSON object (output file) |

### High-Level Tools

- **`tools/recon.py`** — `subdomains()`, `hosts()`, `ports()`, `urls()`, `tech()`. Context-aware defaults: when no targets given, tools pull from previously discovered data. `urls()` runs gau + waybackurls in parallel via `asyncio.gather()`.
- **`tools/enum.py`** — `directories()` (ffuf), `crawl()` (katana). Auto-pulls alive hosts from context when no targets specified.

### CLI

Typer app with 4 command groups and `--format json|table` output:

```
boba hunt    {create, list, status, pause, resume, close}
boba recon   {subdomains, hosts, ports, urls, tech}
boba enum    {directories}
boba context {subdomains, hosts, ports, urls, tech, directories, runs, stats}
```
