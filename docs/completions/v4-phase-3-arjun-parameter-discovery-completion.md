# V4 Phase 3 Completion — Arjun Parameter Discovery

## Summary

Implemented Phase 3 of the V4 enrichment plan: Boba can now discover hidden HTTP parameters with Arjun, persist them in hunt context, expose them through CLI queries, and use them to raise endpoint priority for downstream vulnerability testing.

## Why

This phase closes the highest-leverage recon gap in the system.

Before this change:

- the vuln engines mostly depended on parameters already visible in URLs, forms, or JavaScript
- hidden parameters like `debug`, `role`, `callback`, `internal`, or `redirect_url` were not being surfaced into the workflow
- prioritization could not distinguish “plain untested endpoint” from “endpoint with confirmed hidden inputs”

After this phase:

- parameter discovery becomes a first-class enumeration step
- hidden inputs are persisted and queryable
- prioritization can steer the agent toward endpoints with richer attack surface

## What Changed

### 1. Added `ArjunAdapter`

**File:** `src/boba/adapters/arjun.py`

Added a new adapter:

- `TOOL_NAME = "arjun"`
- `BINARY_NAMES = ["arjun"]`
- `OUTPUT_FORMAT = OutputFormat.JSON_OBJECT`
- `PRODUCES = "parameter"`
- `SCOPE_MODE = "pre"`

Implemented:

- `install_hint()`
- `_resolve_mode()`
- `build_command()`
- `parse_record()`
- `parse_output()`
- `extract_scope_target()`

### 2. Implemented method/body-type aware command construction

**File:** `src/boba/adapters/arjun.py`

The adapter now maps Boba’s enum inputs to Arjun modes:

- `GET` → query parameter discovery
- `POST` + form/default → body parameter discovery
- `POST` + `json` body type → JSON/body parameter discovery

Command shape:

```bash
arjun -u <url> -m <GET|POST|JSON> -oJ <tempfile> --stable
```

Additional behavior:

- `config.rate_limit` maps to `-t`
- output is written to a temp JSON file and then parsed by the adapter
- single-target semantics are enforced, with warning on extra targets

### 3. Made Arjun parsing resilient to multiple JSON shapes

**File:** `src/boba/adapters/arjun.py`

The adapter accepts more than one result shape so Boba is less brittle at the subprocess boundary.

Supported shapes include:

- single object with `url` + `params`
- top-level map of `url -> [params]`
- parameter objects with extra metadata such as `method`, `param_type`, and `confirmed`

Normalized record shape:

```python
{
    "url": "...",
    "method": "GET" | "POST",
    "name": "<param>",
    "param_type": "query" | "body" | "header" | ...,
    "confirmed": True | False,
}
```

### 4. Registered the adapter

**File:** `src/boba/adapters/__init__.py`

Added `ArjunAdapter` to the lazy adapter registry so the adapter surface stays complete and consistent.

### 5. Added persistent `parameters` storage

**File:** `src/boba/core/context.py`

Added a new SQLite table:

- `parameters`

Stored fields:

- `hunt_id`
- `url`
- `method`
- `name`
- `param_type`
- `sources`
- `confirmed`
- `created_at`
- `updated_at`

Added indexes:

- `idx_parameters_hunt`
- `idx_parameters_url`

### 6. Added parameter upsert/query helpers

**File:** `src/boba/core/context.py`

Added:

- `upsert_parameter()`
- `get_parameters()`

Behavior:

- dedupes on `(hunt_id, url, method, name, param_type)`
- merges `sources`
- promotes `confirmed` using `MAX(existing, excluded)`
- supports filtering by `url` and `method`

Also updated:

- `upsert_records()` dispatch to support `"parameter"`
- `_STATS_TABLES` so hunt stats include `parameters`

### 7. Added high-level enum integration

**File:** `src/boba/tools/enum.py`

Added:

- `parameters()`

This tool function:

- deep-copies adapter config
- injects method and body-type config for Arjun
- runs the adapter with scope enforcement
- persists discovered records through `context.upsert_records(..., "parameter", ...)`
- logs the tool run

### 8. Added CLI commands

**File:** `src/boba/cli/main.py`

Added:

- `boba enum parameters`
- `boba context parameters`

#### `boba enum parameters`

Supports:

- `--url`
- `--method`
- `--body-type`
- normal `--format`
- normal `--data-dir`

#### `boba context parameters`

Supports:

- `--url`
- `--method`
- normal `--format`
- normal `--data-dir`

Table output includes:

- `url`
- `method`
- `name`
- `param_type`
- `confirmed`
- `sources`

### 9. Integrated parameter discovery into prioritization

**File:** `src/boba/analysis/prioritize.py`

Extended `prioritize_endpoints()` to account for hidden parameter discovery.

New behavior:

- loads `context.get_parameters(hunt_id)`
- groups parameter rows by canonical endpoint key
- adds score when Arjun has found parameters for an endpoint
- adds extra score when any of those parameters are `confirmed`
- adds explanatory reasons to the priority output
- suggests `mass_assign` when state-changing endpoints have body parameters

Scoring additions:

- `+2.0` for discovered hidden parameters
- `+1.0` extra when confirmed parameters exist

Reason strings added:

- `Arjun found N parameter(s)`
- `M parameter(s) confirmed by response change`

Normalization detail:

- endpoint matching strips query strings when building the internal key
- this lets a stored parameter record for `/search` still boost `/search?q=test`

## Tests Added / Updated

### Adapter tests

**File:** `tests/adapters/test_arjun.py`

Added coverage for:

- GET command construction
- POST/JSON command construction
- empty output handling
- single-object JSON parsing
- multi-target mapping-shape parsing
- param-object parsing
- scope target extraction

### Tool tests

**File:** `tests/tools/test_enum.py`

Added coverage for:

- parameter result persistence
- empty result handling
- tool run logging

### Context tests

**Files:**

- `tests/core/test_context.py`
- `tests/core/test_context_v2.py`

Added coverage for:

- insert/query behavior
- source merging
- confirmed promotion
- URL/method filtering
- stats including `parameters`

### CLI tests

**File:** `tests/cli/test_cli.py`

Added coverage for:

- `context parameters` empty/table/json output
- `enum parameters` table/json output

### Prioritization tests

**File:** `tests/analysis/test_prioritize.py`

Added coverage for:

- hidden-parameter score boost
- confirmed-parameter extra boost
- canonical endpoint matching across query variants

### Regression / consistency tests

**Files:**

- `tests/test_fixes_0215.py`
- `tests/test_fixes_0218.py`

Added coverage for:

- parameter persistence across reopened database connections
- invalid-hunt query behavior for `get_parameters()`

## Validation

Ran successfully during implementation:

- `python3 -m ruff check src tests`
- `python3 -m ruff format --check` on changed files
- `python3 -m pytest`

Result at completion time: **627 tests passed**

## Notes / Trade-offs

- Arjun was not available in the local environment during implementation, so the adapter was designed defensively around documented command shape and flexible JSON parsing.
- The adapter is intentionally tolerant of multiple JSON output structures to reduce fragility.
- Parameter prioritization is additive only: it boosts endpoint scores without changing the existing prioritization return schema or coverage semantics.
- Canonical endpoint matching strips query strings for comparison, which is useful for prioritization but intentionally does not rewrite or mutate persisted URL records.
- This phase focuses on discovery and workflow integration, not automatic execution of vuln tests against every discovered parameter. That orchestration still belongs to the agent layer.
