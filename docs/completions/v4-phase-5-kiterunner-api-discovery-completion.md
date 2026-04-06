# V4 Phase 5 Completion — Kiterunner API Surface Mapping

## Summary

Implemented Phase 5 of the V4 enrichment plan: Boba can now discover API endpoints invisible to crawlers using Kiterunner, persist them in hunt context, expose them through CLI queries, filter by host or method, and use them to raise endpoint priority for downstream vulnerability testing.

## Why

This phase closes a significant attack surface gap in the agent's enumeration workflow.

Before this change:

- the agent could only test API endpoints found via crawling (katana) or historical URL discovery (gau/waybackurls)
- REST endpoints behind conventions (e.g., `POST /api/v2/transfers`, `DELETE /api/v1/sessions`) that aren't linked from the frontend were invisible
- prioritization could not distinguish "API endpoint found by intelligent probing" from "any URL found by crawling"

After this phase:

- API endpoint discovery is a first-class enumeration step
- Kiterunner-discovered endpoints are persisted, queryable, and tracked in hunt statistics
- prioritization scores Kiterunner-discovered endpoints higher than crawler-found URLs
- state-changing methods (POST, PUT, DELETE, PATCH) on API endpoints get the highest priority scores
- the agent can find IDOR, auth bypass, and mass assignment bugs on hidden APIs

## What Changed

### 1. Added `KiterunnerAdapter`

**File:** `src/boba/adapters/kiterunner.py`

Added a new adapter:

- `TOOL_NAME = "kiterunner"`
- `BINARY_NAMES = ["kr"]`
- `OUTPUT_FORMAT = OutputFormat.PLAIN_LINES`
- `PRODUCES = "api_endpoint"`
- `SCOPE_MODE = "pre"`

Implemented:

- `install_hint()`
- `build_command()`
- `parse_record()`
- `_parse_line()`
- `extract_scope_target()`

### 2. Implemented plain-text output parsing

**File:** `src/boba/adapters/kiterunner.py`

Kiterunner's default output is plain-text lines in the format:

```
GET     200 [   4521,   45,   12] https://app.example.com/api/v2/users 0cc72af3
```

The adapter uses a regex (`_KR_LINE_RE`) to parse method, status code, content length, word count, line count, and URL from each line. A fallback parser handles non-standard lines by extracting URLs and methods from whitespace-separated tokens.

The adapter also supports JSON dict input for future Kiterunner versions or `-oJ` flag usage.

### 3. Implemented command construction

**File:** `src/boba/adapters/kiterunner.py`

Command shape:

```bash
kr scan <url> [-w <wordlist>] [-x <rate_limit>] --fail-status-codes 404,400
```

Behavior:

- supports multiple targets (all passed to `kr scan`)
- `config.extra_args_dict["wordlist"]` maps to `-w`
- `config.rate_limit` maps to `-x` (max connections)
- `--fail-status-codes 404,400` filters out noise
- no output file needed (parses stdout directly)

### 4. Registered the adapter

**File:** `src/boba/adapters/__init__.py`

Added `KiterunnerAdapter` to the lazy adapter registry.

### 5. Added persistent `api_endpoints` storage

**File:** `src/boba/core/context.py`

Added a new SQLite table:

- `api_endpoints`

Stored fields:

- `hunt_id`
- `url`
- `method`
- `status_code`
- `content_type`
- `content_length`
- `host`
- `path`
- `framework`
- `sources`
- `created_at`
- `updated_at`

Added indexes:

- `idx_api_hunt`
- `idx_api_host`

### 6. Added API endpoint upsert/query helpers

**File:** `src/boba/core/context.py`

Added:

- `upsert_api_endpoint()`
- `get_api_endpoints()`

Behavior:

- dedupes on `(hunt_id, url, method)`
- merges `sources` using the standard `json_group_array(DISTINCT value)` pattern
- uses `COALESCE` for `status_code` and `content_length` to preserve existing values
- preserves non-empty `content_type` and `framework` using `CASE WHEN excluded != '' THEN excluded ELSE existing END`
- supports filtering by `host` and `method`

Also updated:

- `upsert_records()` dispatch to support `"api_endpoint"`
- `_STATS_TABLES` so hunt stats include `api_endpoints`

### 7. Added high-level enum integration

**File:** `src/boba/tools/enum.py`

Added:

- `api()`

This tool function:

- accepts optional `url`, `targets` list, and `wordlist`
- if no targets given, pulls alive host URLs from context
- deep-copies adapter config
- runs the adapter with scope enforcement
- persists discovered records through `context.upsert_records(..., "api_endpoint", ...)`
- logs the tool run

### 8. Added CLI commands

**File:** `src/boba/cli/main.py`

Added:

- `boba enum api`
- `boba context api-endpoints`

#### `boba enum api`

Supports:

- `--url` — single target URL
- `--targets` — comma-separated target URLs
- `--wordlist` — Kiterunner wordlist path
- normal `--format`
- normal `--data-dir`

#### `boba context api-endpoints`

Supports:

- `--host` — filter by host
- `--method` — filter by HTTP method
- normal `--format`
- normal `--data-dir`

Table output includes:

- `method`
- `status_code`
- `url`
- `host`
- `path`
- `content_type`
- `framework`

### 9. Integrated API endpoint discovery into prioritization

**File:** `src/boba/analysis/prioritize.py`

Extended `prioritize_endpoints()` to account for Kiterunner-discovered API endpoints.

New behavior:

- loads `context.get_api_endpoints(hunt_id)`
- builds a set of `(method, url)` tuples for Kiterunner-discovered endpoints
- adds discovered API endpoints to the endpoint pool (alongside URLs and directories)
- Kiterunner-discovered endpoints get a higher base score than path-pattern-matched API endpoints
- state-changing methods (POST, PUT, DELETE, PATCH) get additional score bonus
- suggests `idor` + `auth` for all Kiterunner-discovered endpoints
- suggests `mass_assign` for state-changing methods

Scoring additions:

- `+3.0` for Kiterunner-discovered API endpoint
- `+1.5` extra for state-changing methods (POST, PUT, DELETE, PATCH)
- vs `+2.0` for path-pattern-matched API endpoints (existing)

Reason strings added:

- `Kiterunner-discovered API endpoint`
- `State-changing method (POST)` / `(PUT)` / `(DELETE)` / `(PATCH)`

The Kiterunner signal takes precedence over the path-pattern signal (uses `elif` to avoid double-counting).

## Tests Added / Updated

### Adapter tests

**File:** `tests/adapters/test_kiterunner.py`

Added coverage for:

- basic command construction
- wordlist flag injection
- rate limit flag injection
- multiple targets support
- empty targets error handling
- plain-text line parsing (GET, POST, DELETE methods)
- JSON dict input parsing
- fallback line parsing for non-standard formats
- multi-line output parsing
- empty output handling
- scope target extraction (host present, host empty)

### Tool tests

**File:** `tests/tools/test_enum.py`

Added coverage for:

- API endpoint result persistence (2 records with different methods)
- empty targets handling
- tool run logging

### Context tests

**File:** `tests/core/test_context.py`

Added coverage for:

- insert/query behavior
- source merging
- filtering by host and method
- COALESCE preservation on re-upsert (content_type, framework preserved)
- stats including `api_endpoints`

### CLI tests

**File:** `tests/cli/test_cli.py`

Added coverage for:

- `context api-endpoints` empty result
- `context api-endpoints` with data (JSON format)
- `context api-endpoints` filter by host

### Prioritization tests

**File:** `tests/analysis/test_prioritize.py`

Added coverage for:

- Kiterunner endpoint scores higher than crawler-found URL
- state-changing method (POST) scores higher than GET
- Kiterunner endpoints suggest `idor` and `auth` tests
- PUT endpoints suggest `mass_assign`

### Regression / consistency tests

**File:** `tests/test_fixes_0218.py`

Added coverage for:

- invalid-hunt query behavior for `get_api_endpoints()`
- valid-hunt empty query for `get_api_endpoints()`

## Validation

Ran successfully during implementation:

- `python3 -m ruff check src/ tests/` — all checks passed
- `python3 -m ruff format --check` on changed files — all formatted
- `python3 -m pytest` — **688 tests passed**, 0 failures, 0 regressions

## Test Count

| Phase | Tests |
|---|---|
| Baseline (after Phase 4) | 658 |
| Phase 5 new tests | 30 |
| **Total** | **688** |

## Notes / Trade-offs

- Kiterunner was not available in the local environment during implementation, so the adapter was designed defensively around documented command and output format.
- The adapter uses `SCOPE_MODE = "pre"` because Kiterunner targets are URLs that can be scope-checked before scanning.
- The adapter parses Kiterunner's plain-text output by default (the common case), with JSON dict support as a fallback for future versions or `-oJ` flag usage.
- The regex parser includes a fallback for non-standard lines, extracting URLs and methods from whitespace-separated tokens rather than failing.
- Prioritization uses a `(method, url)` tuple set for Kiterunner lookups, so a GET endpoint found by both crawling and Kiterunner is correctly identified as Kiterunner-discovered.
- The Kiterunner priority signal is additive and takes precedence over the existing API-path-pattern signal (via `elif`) to avoid double-counting on endpoints like `/api/v2/users`.
- This phase focuses on discovery, persistence, and prioritization. Automatic execution of vuln tests against every discovered endpoint belongs to the agent layer.
