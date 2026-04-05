# V3 Phase 1 Completion — Coverage Tracking

**Date:** 2026-04-02
**Scope:** 6 files modified/created, 19 new tests, 465 tests passing (19 new, 0 regressions)

## What Was Done

Phase 1 delivers **coverage tracking** — the agent can now answer "what have I tested?" and "what should I test next?" Coverage is recorded automatically when vulnerability tests run, and can be queried via CLI or programmatically.

## Changes By File

### New Files

| File | Purpose |
|---|---|
| `src/boba/analysis/__init__.py` | New V3 analysis package |
| `src/boba/analysis/coverage.py` | Coverage summary + gap analysis functions |
| `tests/analysis/__init__.py` | Test package |
| `tests/analysis/test_coverage.py` | 19 tests covering all coverage functionality |

### Modified Files

| File | What Changed |
|---|---|
| `src/boba/core/context.py` | Added `coverage` table to schema, added to `_STATS_TABLES`, added `upsert_coverage()`, `get_coverage()`, `get_untested_endpoints()` methods |
| `src/boba/core/models.py` | Added `CoverageEntry` and `CoverageSummary` dataclasses |
| `src/boba/tools/vuln.py` | Added `context`/`hunt_id` optional params to all 5 `test_*` functions, added `_record_coverage()` helper, wired auto-recording into each test function |
| `src/boba/cli/main.py` | Added `analyze` command group with `coverage` subcommand (supports `--host`, `--untested-only`, `--test-type`, `--format`) |

## Schema Addition

```sql
CREATE TABLE IF NOT EXISTS coverage (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id         TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    url             TEXT NOT NULL,
    method          TEXT NOT NULL DEFAULT 'GET',
    parameter       TEXT NOT NULL DEFAULT '',
    test_type       TEXT NOT NULL,
    tested_at       TEXT NOT NULL,
    tool_run_id     INTEGER REFERENCES tool_runs(id),
    finding_id      INTEGER REFERENCES findings(id),
    notes           TEXT,
    UNIQUE(hunt_id, url, method, parameter, test_type)
);
```

Unique constraint on `(hunt_id, url, method, parameter, test_type)` — same endpoint tested twice with the same test type updates the row rather than duplicating.

## Key Design Decisions

### 1. Auto-recording via optional parameters (not a wrapper)

Coverage recording is wired into the existing `test_*` functions via optional `context` and `hunt_id` parameters, not via a wrapper or decorator. This preserves backwards compatibility — callers that don't pass `context` get identical behavior to before. The `_record_coverage` helper silently catches and logs any errors to avoid breaking test execution if coverage recording fails.

**Why not a decorator/wrapper:** The test functions have heterogeneous signatures (different params for IDOR vs XSS vs SQLi). A decorator would need to introspect arguments to extract URL/method/parameter, which is fragile. Explicit calls at the end of each function are clearer and let each function specify exactly what to record (e.g., XSS records one row per parameter tested, SSRF records the injection point name).

### 2. Gap analysis via SQL cross-join

`get_untested_endpoints()` uses a SQL cross-join between known endpoints (from `urls` + `directories` tables) and a list of test types, then LEFT JOINs against the `coverage` table to find missing rows. This is a single query that scales well — no Python-side set operations needed.

### 3. Coverage in `_STATS_TABLES`

Added `coverage` to the stats table set so `get_hunt_stats()` includes the coverage count. This means `boba context stats <hunt-id>` automatically shows how many coverage entries exist.

### 4. Analysis as a separate package

The new `src/boba/analysis/` package keeps V3 intelligence modules separate from V1/V2 data-production modules. Analysis modules only *read* from V1/V2 tables — they never write back. They write to their own V3 tables (`coverage`, and later `chains`, `dedup_groups`, `reports`). This prevents circular dependencies and makes the data flow direction clear.

## Test Coverage (19 new tests)

| Test Class | Count | What's Tested |
|---|---|---|
| `TestCoverageUpsertAndQuery` | 5 | Basic CRUD, unique constraint updates, filter by test_type, filter by host |
| `TestUntestedEndpoints` | 4 | Gaps from urls table, gaps from directories table, tested endpoints excluded, partial coverage |
| `TestAutoRecordCoverage` | 4 | IDOR auto-records, XSS records per-param, SQLi auto-records, no coverage without context (backwards compat) |
| `TestCoverageSummary` | 3 | Summary counts, empty hunt, host filtering |
| `TestCoverageInStats` | 1 | Coverage appears in hunt stats |
| `TestCLICoverage` | 2 | JSON output, untested-only with test-type filter |

## CLI Usage

```bash
# Full coverage summary
boba analyze coverage <hunt-id>

# JSON output for agent consumption
boba analyze coverage <hunt-id> --format json

# Filter by host
boba analyze coverage <hunt-id> --host app.example.com

# Show only untested endpoints
boba analyze coverage <hunt-id> --untested-only

# Filter by test types
boba analyze coverage <hunt-id> --untested-only --test-type idor,xss

# Combine filters
boba analyze coverage <hunt-id> --untested-only --host app.example.com --test-type ssrf --format json
```

## What's Next

Phase 2: **Finding Deduplication** — detect when multiple tool runs found the same underlying vulnerability, group them, and select a canonical finding per group.
