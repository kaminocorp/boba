# Changelog

- [0.2.15](#0215--v3-readiness-final-gate) — Upsert commit safety, SSRF/IDOR/XSS detection hardening, CLI `_parse_targets()` helper, adapter urlparse safety, waybackurls concurrency fix, 1 new test file + 34 new tests (361 total)
- [0.2.14](#0214--pre-v3-quality-gate) — JSON-aware IDOR body comparison, CLI deduplication (5 helpers extracted), missing `enum crawl` command, httpx int guard, context.py JSON refactor, XSS HTML entity detection, OOB evidence enrichment, scan config deepcopy, 3 new test files + 41 new tests (327 total)
- [0.2.13](#0213--another-v3-readiness-audit) — IDOR/SQLi false-positive reduction, fuzz baseline fix, gau ARG_MAX fix, scope filter consistency, CLI test coverage for recon/enum/scan/session, 13 fixes + 21 new tests (286 total)
- [0.2.12](#0212--another-v3-readiness-review) — LIKE wildcard injection, gau argument injection, IDOR/SSRF false-positive reduction, fuzz header substitution, CLI error handling, 11 fixes + 59 new tests (265 total)
- [0.2.11](#0211--pre-v3-quality-gate--test-coverage) — 5 bug fixes (scope YAML null, OOB listener guard, OOB dedup, subprocess timeout, SQLi case sensitivity), 90 new tests covering hunt manager, subprocess, all adapters, recon/enum tools, CLI
- [0.2.10](#0210--v3-readiness-final-quality-pass) — Findings upsert stale flags, hunt state validation, tool_run started_at, MSSQL payload, OOB poll drift, navigate/login timeout, YAML scope errors, IDOR body comparison, CLI event loop, 10 fixes total
- [0.2.9](#029--v3-readiness-final-gate) — HttpClient connection leak fix, JWT padding bug, null-safe tech flattening, whatweb type guard, body similarity boundary, str() command args, XSS DOM canary, 7 fixes total
- [0.2.8](#028--v3-readiness-gate) — Scope URL prefix bypass, HttpClient network resilience, SQLi multi-baseline timing, SSRF/XSS false-positive reduction, OOB fallback fix, 12 fixes total
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

## 0.2.15 — V3 Readiness Final Gate

**Date:** 2026-04-01
**Scope:** 9 files fixed, 1 new test file, 361 tests passing (34 new, 0 regressions)

Comprehensive 5-agent parallel codebase review followed by targeted fixes for transaction safety, detection accuracy, CLI duplication, and adapter robustness. All fixes are strictly additive. Test count: 327 → 361.

### Transaction Safety (HIGH)

- **6 upsert methods missing `commit()`** — `upsert_subdomain()`, `upsert_host()`, `upsert_port()`, `upsert_url()`, `upsert_technology()`, and `upsert_directory()` executed writes but never called `.commit()`. When called within `upsert_records()` (which uses `with self._conn:` context manager), data was committed by the outer transaction. But direct calls (e.g., from tests or future V3 tools) would lose data on connection close. Now each method explicitly commits.

### Detection Accuracy (HIGH)

- **SSRF regex patterns tightened** — Previous patterns generated false positives from incidental matches (e.g., `root:` matching "root cause", `instance-id` matching generic error text). New patterns require structural context: `/etc/passwd` must match full colon-delimited format (`root:[^:]*:\d+:\d+:[^:]*:[^:]*:`), AMI IDs need 8+ hex chars, GCP metadata requires version (`computeMetadata/v\d`), AWS instance metadata requires JSON format (`"instanceId"\s*:`).

- **IDOR body similarity threshold lowered (0.8 → 0.7)** — The 0.8 threshold was too strict for JSON endpoints where key sets overlap but aren't identical. Lowering to 0.7 reduces false negatives while keeping false positive risk low (JSON structural comparison already provides strong signal).

- **IDOR enumeration requires body similarity** — Previously, IDOR object ID enumeration flagged any 2xx response as evidence. Now verifies that the enumerated response body is structurally similar to the owner's response, filtering out generic success/error pages that return 200.

- **XSS DOM canary CSP fallback** — DOM-based XSS detection now checks for both the `window.__xss_fired` canary and `img[src*="xss"]` elements. The secondary check provides a fallback when Content-Security-Policy blocks `window` property assignment.

### CLI Architecture (MEDIUM)

- **Extracted `_parse_targets()` helper** — Consolidated 9 instances of `[t.strip() for t in targets.split(",")] if targets else None` into a single `_parse_targets()` function. Also filters empty entries from doubled commas (e.g., `"a.com,,b.com"`).

### Adapter Robustness (MEDIUM)

- **Waybackurls concurrency safety** — `_execute()` now copies `_stdin_targets` to a local variable before use, preventing race conditions if the adapter instance is reused across concurrent runs. Also adds trailing newline to stdin data to ensure the final target is parsed.

- **urlparse error handling in 4 adapters** — `parse_record()` in GauAdapter, WaybackurlsAdapter, KatanaAdapter, and WhatwebAdapter now wraps `urlparse()` calls in try/except. Malformed URLs from tool output no longer crash the adapter; instead, fields default to empty strings.

### Test Coverage (34 new tests)

- **`tests/test_fixes_0215.py`** (33 tests, new file):
  - Upsert commit persistence across connections (6 tests) — verifies all 6 upsert methods persist data when called directly, verified by opening a second connection
  - `_parse_targets()` helper (6 tests) — None, empty, single, multiple, whitespace, empty entries
  - `_bodies_similar()` threshold (2 tests) — validates 0.7 threshold behavior
  - SSRF indicator regex (3 tests) — full passwd format, AMI length, GCP version
  - IDOR enumeration body check (1 test) — verifies body similarity required for enum
  - Adapter urlparse safety (4 tests) — gau, waybackurls, katana, whatweb with malformed input
  - Browser CLI commands (3 tests) — navigate, screenshot, extract with mocked browser
  - HTTP CLI commands (3 tests) — request, replay, compare with mocked client
  - Vuln/test CLI commands (5 tests) — idor, ssrf, xss, sqli, auth with mocked tools

- **`tests/tools/test_vuln.py`** (+1 test):
  - `test_ssrf_detected_via_metadata_likely` — verifies LIKELY confidence for cloud metadata substring match (vs CONFIRMED for full regex match)

---

## 0.2.14 — Pre-V3 Quality Gate

**Date:** 2026-04-01
**Scope:** 8 files fixed, 3 new test files, 327 tests passing (41 new, 0 regressions)

Comprehensive 5-agent parallel codebase review followed by targeted fixes to bring quality from 7.3/10 to 8.5+/10. Focus areas: CLI duplication, detection accuracy, JSON handling, and test coverage gaps. All fixes are strictly additive.

### Detection Accuracy (HIGH)

- **`_bodies_similar()` JSON-aware comparison** — Previous Jaccard-on-lines approach failed for JSON responses where lines differ only in values (e.g. `/api/me` returning `{"user":"alice"}` vs `{"user":"bob"}` — after structural line removal, overlap was 0%). Now parses both bodies as JSON when possible and compares key-structure (set of dotted key paths). Two responses with identical keys but different values are correctly identified as "similar" (same-shape endpoint, not IDOR). Non-JSON bodies fall back to the existing line overlap check.

- **XSS HTML entity encoding detection** — Reflected XSS check now detects payloads that appear in the response after HTML entity decoding (`<script>` → `&lt;script&gt;`). Records evidence as `reflected_html_encoded` but does NOT flag as vulnerable since entity encoding is a server-side mitigation. Enables follow-up bypass analysis.

### CLI Architecture (HIGH)

- **Missing `enum crawl` CLI command** — `enum.crawl()` function existed in `tools/enum.py` but was inaccessible from CLI. Added `boba enum crawl` command with `--targets`, `--depth`, and `--format` options.

- **Extracted 5 CLI helper functions** — Deduplicated repeated initialization patterns across 12+ commands:
  - `_get_http_client(manager, hunt_id)` — creates HttpClient with history sink (was repeated in 6 commands)
  - `_get_browser_manager(manager, hunt_id)` — creates BrowserManager with config/sink (was repeated in 3 commands)
  - `_get_session_manager(manager, hunt_id)` — creates SessionManager (was repeated in 4 commands)
  - `_parse_headers(header_list)` — parses `KEY:VALUE` headers with typer.Exit on invalid format (was repeated in 2 commands)
  - Net reduction: ~120 lines of duplicated imports and initialization code.

### Safety & Correctness (MEDIUM)

- **httpx adapter unguarded `int()` conversion** — `parse_record()` called `int(raw["port"])` which would crash on non-numeric port strings from malformed httpx output. Now uses `_safe_int()` helper that returns None on ValueError/TypeError.

- **`scan.py` config mutation** — `nuclei_scan()` mutated the caller's `AdapterConfig` when setting severity/tags/templates. Now deepcopies the config before modification, matching the pattern in `enum.py`.

- **OOB evidence enrichment** — `test_ssrf()` OOB callback evidence now includes `listener_id`, `purpose`, `target_url`, and `parameter` from the listener metadata. Previously only stored `{"type": "oob_callback", "interaction": {...}}`, making it impossible to map callbacks to specific injection points.

### Code Quality (MEDIUM)

- **Extracted `_parse_json_field()` in context.py** — Consolidated 6 identical try/except json.loads patterns into a single helper function with `label` and `record_id` parameters for consistent warning messages. Applied to: `get_http_record`, `query_http_history`, `get_session`, `get_sessions` (now `_deserialize_session_row`), `get_findings`, `get_oob_listeners`.

- **Extracted `_deserialize_session_row()` in context.py** — `get_session()` and `get_sessions()` shared 30 lines of identical JSON deserialization logic for cookies_json/headers_json/tokens_json/storage_state. Now consolidated into a single private method.

- **Extracted `_extract_json_keys()` in vuln.py** — Recursive helper for extracting dotted key paths from nested JSON structures. Used by the improved `_bodies_similar()` for structural comparison.

### Test Coverage (41 new tests)

- **`tests/core/test_config.py`** (7 tests, new file):
  - `get_data_dir()` default path and BOBA_DATA_DIR env var override
  - `get_db_path()`, `get_tmp_dir()`, `get_hunt_dir()`, `get_bodies_dir()`, `get_templates_dir()` directory creation

- **`tests/cli/test_formatters.py`** (9 tests, new file):
  - `_auto_columns()` skip-set exclusion and 8-column limit
  - `format_output()` JSON and table modes, empty list, single dict, invalid format
  - `_print_json()` parseable output

- **`tests/test_fixes_0214.py`** (25 tests, new file):
  - `_bodies_similar()` JSON key-structure comparison (5 tests)
  - `_safe_int()` edge cases (5 tests)
  - `_parse_json_field()` valid/malformed/None/empty (4 tests)
  - `_extract_json_keys()` nested dicts, lists, empty (3 tests)
  - `nuclei_scan` config deepcopy verification (1 test)
  - XSS HTML entity detection evidence (1 test)
  - `_parse_headers()` valid/invalid/None/multiple/colon-in-value (5 tests)
  - `enum crawl` command registration (1 test)

### Known Design Decision

- **Timestamp type inconsistency** (`Hunt.created_at` is `datetime`, `SessionState.created_at` is `str`) — Documented but not changed in this release. Unifying would require a cross-cutting refactor touching models, context, CLI, and all tests. Low risk since SessionState timestamps are DB-sourced display strings only.

---

## 0.2.13 — Another V3 Readiness Audit

**Date:** 2026-04-01
**Scope:** 10 files fixed, 1 test file expanded, 286 tests passing (21 new, 0 regressions)

5-agent parallel codebase review across all layers. Found 0 critical, 4 high, and 10 medium issues surviving all prior hardening rounds (0.2.1–0.2.12). All fixes are strictly additive. Test count: 265 → 286.

### Detection Accuracy (HIGH)

- **IDOR `_bodies_similar` false-positive on same-shape JSON** — Structural-only lines (braces, brackets, commas) inflated overlap score, causing two JSON responses with identical keys but different values (e.g., `/api/me` per-user data) to be falsely flagged as similar. Now excludes JSON structural lines from the overlap calculation via compiled regex.
- **Boolean-based SQLi false-positive on dynamic pages** — The 20-byte / 5% length-diff threshold triggered on pages with natural length variance (ads, CSRF tokens, timestamps). Added baseline similarity guard: the true-condition response body must be similar to the baseline before flagging, confirming the true payload actually "passes through."

### Safety & Correctness (MEDIUM)

- **`gau` targets ARG_MAX risk** — Targets were passed as positional CLI arguments, risking OS argument length limits with large target lists. Now writes targets to a temp file and passes via `--fp` flag.
- **`post_filter_records` empty-string scope targets silently dropped** — Empty-string targets (`""`) were treated as falsy and removed, while `None` targets were kept. Now treats both consistently: empty-string and `None` both result in keeping the record.
- **Fuzz baseline was first payload** — If the first fuzz payload triggered an anomalous response, all subsequent normal responses were flagged as anomalies. Now sends an unfuzzed baseline request before the fuzz loop.
- **`session.login_form` accessed private `browser._get_page()`** — Broke encapsulation. Added public `BrowserManager.get_page()` method; `login_form` now uses the public API.
- **`urls()` returned duplicate records** — `all_records` list from gau + waybackurls contained cross-adapter duplicates. Now deduplicates by URL before returning in the merged `ToolResult`.
- **`ports()` mutated caller's `config.extra_args_dict`** — Unlike `enum.py` which uses `copy.deepcopy(config)`, `ports()` mutated the original. Now deepcopies the config before modification.
- **`_ADMIN_RE` compiled on every `test_auth()` call** — Regex was defined inside the function body. Moved to module-level compiled constant.

### Robustness (MEDIUM)

- **Consistent `except typer.Exit: raise` across CLI** — `http request` and `http replay` commands raised `typer.Exit(1)` on invalid `--header` format inside the try block, but lacked the `except typer.Exit: raise` guard before the generic `except Exception`, causing double error printing. Added the guard to match the pattern in `session create` and `test idor`.
- **Added `logging.getLogger(__name__)` to `vuln.py`, `enum.py`, `scan.py`** — These tool modules had no logger. JWT manipulation failures in `test_auth()` were silently swallowed; now logged at debug level.

### Test Coverage (21 new tests)

- **`tests/cli/test_cli.py`** (+21 tests):
  - `TestReconSubdomainsCLI` (2 tests) — table + JSON output with mocked tool
  - `TestReconHostsCLI` (2 tests) — with targets (verifies comma-split) + without targets (verifies None passthrough)
  - `TestReconPortsCLI` (2 tests) — with targets + without targets (None passthrough)
  - `TestReconUrlsCLI` (1 test) — domain flag with mocked tool
  - `TestReconTechCLI` (2 tests) — with targets + without targets
  - `TestEnumDirectoriesCLI` (2 tests) — table + JSON output
  - `TestScanNucleiCLI` (3 tests) — with targets + without targets (None passthrough) + JSON format
  - `TestSessionCreateCLI` (3 tests) — create + invalid method error + JSON format
  - `TestSessionListCLI` (2 tests) — empty + after create
  - `TestSessionDeleteCLI` (1 test) — create then delete
  - `TestHttpHeaderValidation` (1 test) — invalid header format exits with error

---

## 0.2.12 — Another V3 Readiness Review

**Date:** 2026-04-01
**Scope:** 7 files fixed, 3 test files expanded/created, 265 tests passing (59 new, 0 regressions)

5-agent parallel codebase review across all layers. Found 0 critical, 0 high, and 11 medium/low issues surviving all prior hardening rounds (0.2.1–0.2.11). All fixes are strictly additive. Test count: 206 → 265.

### Correctness

- **SQL LIKE wildcard injection in `get_directories()` and `query_http_history()`** — `%` and `_` in caller-provided `url_prefix`/`path_prefix` were passed unescaped to LIKE queries, matching unintended rows. Now escaped with `ESCAPE '\'` clause.
- **IDOR bodies-differ false positive** — when User A and User B both get 2xx but bodies differ (e.g., `/api/me` returning per-user data), confidence downgraded from `LIKELY` to `POSSIBLE` and `vulnerable` set to `False`
- **SSRF cloud metadata 200 check too permissive** — bare `200` status for `169.254.169.254` payloads now requires metadata-like body content (`ami-id`, `instance-id`, `computeMetadata`, etc.) to reduce false positives from generic WAF/error pages
- **`recon.hosts()` missing source attribution** — `upsert_records` call now passes `source="httpx"` for proper provenance tracking

### Safety

- **`gau` argument injection** — targets passed as positional CLI arguments could be interpreted as flags if starting with `-`; now preceded by `--` separator
- **Waybackurls pre-filter bypass** — `_stdin_targets` was set before `super().run()` pre-filtering; moved into `build_command()` which receives already-filtered targets
- **IDOR `object_ids` scope enforcement** — reconstructed enumeration URLs now validated against hunt scope before requesting; out-of-scope URLs are skipped

### Robustness

- **Fuzz header marker substitution** — `HttpClient.fuzz()` now substitutes `§FUZZ§` markers in headers (alongside url/body) and copies headers per iteration to prevent cross-contamination
- **Browser `sink.record()` exception safety** — `_on_response` handler wraps `sink.record()` in try/except so database errors don't crash Playwright's event loop
- **CLI context commands error handling** — all 12 context query commands (`subdomains`, `hosts`, `ports`, `urls`, `tech`, `directories`, `runs`, `stats`, `http-history`, `findings`, `sessions`, `oob`) now catch `Exception` with `print_error()` instead of exposing raw tracebacks
- **`session_create` double error printing** — `except typer.Exit: raise` added before the general `Exception` handler to prevent `typer.Exit(1)` from being caught and printed as `Error: 1`

### Test Coverage (59 new tests)

- **`tests/cli/test_cli.py`** (+26 tests) — hunt resume, all 10 context query commands (empty + with data + JSON format)
- **`tests/adapters/test_adapters.py`** (+5 tests) — WaybackurlsAdapter build_command, stdin target storage, parse_record, extract_scope_target
- **`tests/tools/test_scan.py`** (28 tests, new file) — nuclei_scan tool-layer composition, NucleiAdapter parse_record/build_command/extract_scope_target, severity/tags/template filters

---

## 0.2.11 — Pre-V3 Quality Gate & Test Coverage

**Date:** 2026-04-01
**Scope:** 5 files fixed, 8 new test files, 206 tests passing (90 new, 0 regressions)

Comprehensive 4-agent parallel codebase review followed by bug fixes and major test coverage expansion. Test count: 116 → 206.

### Bug Fixes

- **`from_yaml()` crashes on empty YAML** — `yaml.safe_load()` returns `None` for empty files; now validates result is a dict before calling `.get()`
- **OOB empty `listener_id` matches everything** — added `lid` truthiness guard so `startswith("")` can't match all interactions
- **OOB interaction deduplication** — `poll()` now deduplicates by `full_id` before appending, preventing duplicate interactions across multiple poll calls
- **Streaming subprocess `wait()` can hang forever** — added 5s timeout to `process.wait()` after kill in `run_subprocess_streaming()` finally block
- **SQLi error signatures case-sensitive** — lowercased all signatures; detection already uses `.lower()` on both sides, now consistent

### Test Coverage (90 new tests)

- **`tests/core/test_hunt.py`** (14 tests) — HuntManager CRUD, scope persistence, YAML loading, state transitions, terminal state enforcement, stats
- **`tests/core/test_subprocess.py`** (10 tests) — echo, exit codes, stderr, timeout, stdin, env vars, callbacks, streaming, duration tracking
- **`tests/adapters/test_base_adapter.py`** (20 tests) — parse_output for all 4 formats (JSONL, JSON_OBJECT, PLAIN_LINES, JSON_ARRAY), error counting, file-based output, temp file lifecycle
- **`tests/adapters/test_adapters.py`** (24 tests) — build_command and parse_record for all 8 adapters + Nuclei
- **`tests/tools/test_recon.py`** (7 tests) — subdomains, hosts, ports, urls (parallel merge), tech, tool run logging
- **`tests/tools/test_enum.py`** (6 tests) — directories, crawl, empty targets, tool run logging
- **`tests/cli/test_cli.py`** (9 tests) — hunt create/list/status/pause/close, JSON format, invalid format error, context stats

---

## 0.2.10 — V3 Readiness Final Quality Pass

**Date:** 2026-04-01
**Scope:** 8 files modified, 116 tests passing (0 regressions)
**Details:** [v1v2-v3-readiness-final-gate.md](completions/v1v2-v3-readiness-final-gate.md)

5-agent parallel codebase review across all layers. Found 10 medium-severity issues surviving all prior hardening rounds (0.2.1–0.2.9). All fixes are strictly additive. Score: 7.5/10 → 8.5+/10.

### Correctness

- **`upsert_finding` ON CONFLICT now updates `false_positive` and `reported` flags** — re-scans no longer leave stale flags from the original insert
- **Hunt state transition validation** — `completed` is now a terminal state; invalid transitions (e.g., resume a completed hunt) raise `ValueError` with allowed transitions listed
- **`log_tool_run` computes accurate `started_at`** — `finished_at - duration_seconds` instead of recording current time for both fields
- **MSSQL time-based SQLi payload fixed** — replaced MySQL `SLEEP()` syntax with MSSQL `WAITFOR DELAY` in the second MSSQL payload
- **IDOR body comparison added to primary detection path** — when unauth is denied but both users get 2xx, bodies are now compared; similar → CONFIRMED, different → LIKELY (prevents FP on shared endpoints like `/api/me`)

### Robustness

- **OOB `poll()` uses wall-clock timeout** — `time.monotonic()` deadline replaces additive `elapsed += poll_interval` that drifted with network I/O time
- **`navigate()` accepts caller-controllable timeout** — new `timeout_ms` parameter (default 30s) passed to Playwright's `page.goto()`
- **`login_form` post-submit wait has 30s timeout** — `wait_for_load_state("networkidle")` no longer hangs indefinitely on long-polling pages

### Validation & Safety

- **`from_yaml` validates scope rule dicts** — missing `pattern`/`type` keys now raise `ValueError` with rule index and content, instead of raw `KeyError`
- **CLI `_safe_close_http` uses explicit event loop lifecycle** — `asyncio.new_event_loop()` with proper `try/finally/close()` instead of fragile `asyncio.run()` after prior loop closure

---

## 0.2.9 — V3 Readiness Final Gate

**Date:** 2026-04-01
**Scope:** 9 files modified, 116 tests passing (0 regressions)

5-agent parallel codebase review across all layers. Found 2 critical, 4 high, and 1 medium issue surviving all prior hardening rounds. 8 review findings verified as false alarms and not fixed. Score: 7.5/10 → 8.5+/10.

### Critical

- **HttpClient connection pool never closed in CLI** — 8 CLI commands created `HttpClient(sink)` but never called `close()`, leaking httpx TCP connections and file descriptors on every invocation. Added `_safe_close_http()` helper with cleanup in all 8 finally blocks.
- **JWT base64 padding adds 4 extra bytes** — `(4 - len(s) % 4)` produces 4 when length is already a multiple of 4. Fixed to `(4 - len(s) % 4) % 4`.

### High

- **`recon.tech()` crashes on null technologies** — `record.get("technologies", [])` doesn't handle present-but-None values; changed to `record.get("technologies") or []`
- **WhatwebAdapter crashes on non-dict plugins** — `raw.get("plugins", {}).items()` fails if plugins is a string/list/null; added `isinstance(plugins, dict)` guard
- **`_bodies_similar()` boundary excludes threshold** — `len_ratio <= threshold` excluded the exact boundary value (0.8); changed to `< threshold` for inclusive comparison
- **Naabu/Katana command args not converted to string** — `extra_args_dict` values passed directly to subprocess could be integers; wrapped in `str()`

### Medium

- **XSS `ALL` missing DOM canary payloads** — `DOM_CANARY` payloads excluded from `ALL` list; tests using default payloads now include DOM-based detection

---

## 0.2.8 — V3 Readiness Gate

**Date:** 2026-04-01
**Scope:** 7 files modified, 116 tests passing (0 regressions)

4-agent parallel codebase review targeting 8.5/10 quality across all layers. Uncovered 3 critical, 6 high, and 3 medium issues spanning scope enforcement, network resilience, detection accuracy, and CLI validation. Score: 7.0/10 → 8.5/10.

### Critical

- **Scope URL prefix bypass for scheme-less URLs fixed** — targets without a scheme (e.g. `app.example.com/admin`) were passed unnormalized to `_check_url_prefix()`, causing URL prefix exclusion rules to silently miss. Now normalizes to `https://` before prefix matching.
- **`hunt_list` missing `except` clause fixed** — command had `try/finally` but no `except`, causing raw Python tracebacks instead of user-friendly error messages
- **OOB fallback client async methods added** — `_FallbackOOBClient` lacked `register()`/`deregister()` methods, causing `AttributeError` when Interactsh is not installed and `stop()` calls `deregister()`

### High

- **HttpClient network error resilience** — `httpx.RequestError` exceptions (timeout, connection refused, DNS failure) now caught and recorded in HTTP history with `status_code=0` and `network_error` tag instead of crashing mid-scan
- **Time-based SQLi uses multiple baselines** — single baseline measurement replaced with 3 samples using median; reduces false positives from network jitter and false negatives from high-variance servers
- **`recon.tech()` record mutation fixed** — `t["host"] = host` mutated original `ToolResult` records in-place; replaced with `{**t, "host": host}` copy
- **Subprocess `await` after kill on deadline** — `run_subprocess_streaming()` now calls `await process.wait()` after `process.kill()` on deadline exceeded, preventing zombie processes
- **OOB listener ID extraction validated** — `callback_domain.split(".")[0]` now guarded against missing dots and empty IDs with `OOBError` exceptions
- **Empty target validation in recon tools** — `recon.subdomains()` and `recon.urls()` return empty results immediately when given empty domain lists instead of running tools with no arguments

### Medium

- **XSS partial reflection tightened** — inner content match now requires JS-specific patterns (`on\w+=`, `javascript:`, `alert(`, etc.) in addition to 16-char minimum, reducing false positives from common strings reflected in error pages
- **SSRF indicators context-aware** — plain substring checks (`"ami-"`, `"root:"`) replaced with regex patterns requiring structural context (`ami-[0-9a-f]{5,}`, `root:[^:]*:\d+:\d+:`, `instance-id\b`, `computeMetadata/`), eliminating false positives from product names
- **CLI header validation** — `--header` values without colons now raise an error with guidance (`expected KEY:VALUE`) instead of being silently dropped; `--method` on session create validates against `AuthMethod` enum with valid options listed on error

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
