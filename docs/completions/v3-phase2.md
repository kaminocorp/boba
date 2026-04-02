# V3 Phase 2 Completion — Finding Deduplication

**Date:** 2026-04-02
**Scope:** 6 files modified/created, 20 new tests, 485 tests passing (20 new, 0 regressions)

## What Was Done

Phase 2 delivers **finding deduplication** — the engine detects when multiple tool runs or test types found the same underlying vulnerability, groups them, and selects a canonical (best) finding per group. This prevents inflated severity assessments and duplicate report submissions.

## Changes By File

### New Files

| File | Purpose |
|---|---|
| `src/boba/analysis/dedup.py` | Dedup engine — `deduplicate_findings()`, `check_duplicate()`, canonical selection, union-find grouping |
| `tests/analysis/test_dedup.py` | 20 tests covering context CRUD, engine logic, canonical selection, inline checks, CLI |

### Modified Files

| File | What Changed |
|---|---|
| `src/boba/core/context.py` | Added `dedup_groups` table to schema. Added `insert_dedup_group()`, `get_dedup_groups()`, `delete_dedup_groups()`, `is_duplicate()`, `get_canonical_finding()`, `_get_finding_by_id()` methods |
| `src/boba/core/models.py` | Added `DedupeGroup` dataclass |
| `src/boba/core/errors.py` | Added `AnalysisError` exception |
| `src/boba/cli/main.py` | Added `analyze dedupe` command with `--dry-run` and `--format` flags |

## Schema Addition

```sql
CREATE TABLE IF NOT EXISTS dedup_groups (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id         TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    canonical_id    INTEGER NOT NULL REFERENCES findings(id),
    finding_ids     TEXT NOT NULL DEFAULT '[]',
    reason          TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    UNIQUE(hunt_id, canonical_id)
);
```

## Key Design Decisions

### 1. Union-find algorithm for transitive grouping

The dedup engine uses a union-find (disjoint set) data structure to handle transitive relationships. If finding A matches finding B via Signal 1, and finding B matches finding C via Signal 2, all three are grouped together. This correctly handles cases where the connection between A and C is only visible through B.

### 2. Three dedup signals with increasing breadth

1. **Signal 1a — Exact URL + parameter (cross-type):** Catches when Nuclei and a manual test both find the same endpoint vulnerable. This groups across finding types regardless of vuln class.
2. **Signal 1b — Exact URL + parameter + vuln class:** Groups same-type findings on the same endpoint.
3. **Signal 2 — Same host + parameter + vuln class:** Catches when `/api/v1/users?id=` and `/api/v2/users?id=` both have IDOR — different API versions of the same underlying vulnerability.

Signals are applied in this order and unioned together, so broader matches don't override narrower ones — they extend them.

### 3. Canonical selection: confirmed > severity > evidence > recency

When multiple findings represent the same vulnerability, the "canonical" (best) one is selected by:
1. Confirmed flag (confirmed findings always win)
2. Severity rank (critical > high > medium > low > info)
3. Evidence count (more evidence = better documented)
4. Recency (most recently updated = most current)

### 4. Idempotent re-analysis via delete-then-insert

Running `deduplicate_findings()` twice produces the same result. The engine deletes all existing groups for the hunt before inserting new ones. This means the agent can safely re-run dedup after new findings are added without accumulating stale groups.

### 5. dry_run for preview

`--dry-run` returns groups without persisting, so the agent (or human) can preview what would be grouped before committing. This is especially useful for verifying the engine's logic on a new codebase.

## Test Coverage (20 new tests)

| Test Class | Count | What's Tested |
|---|---|---|
| `TestDedupGroupCRUD` | 5 | Insert/query, delete, is_duplicate, get_canonical (grouped + ungrouped) |
| `TestDeduplicateFindings` | 9 | Exact URL+param dedup, same host+param, no false dedup (different params), no false dedup (different hosts), canonical selection (confirmed wins, severity tiebreak), idempotent, dry run, single finding |
| `TestCheckDuplicate` | 3 | Exact match, host+param match, no match |
| `TestCLIDedupe` | 3 | JSON output, dry run, no-dupes message |

## CLI Usage

```bash
# Run dedup analysis
boba analyze dedupe <hunt-id>

# Preview without persisting
boba analyze dedupe <hunt-id> --dry-run

# Machine output for agents
boba analyze dedupe <hunt-id> --format json
```

## What's Next

Phase 3: **Severity Assessment (CVSS 3.1)** — standardized scoring for findings, with platform payout mapping for HackerOne and Bugcrowd.
