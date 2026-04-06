# Code Assessment — Part 3 R1: Split `context.py` into `context/` Package

**Date:** 2026-04-06
**Source:** [Code Assessment](../plans/code-assessment.md) Part 3, R1
**Scope:** `src/boba/core/context.py` (2,204 lines) → `src/boba/core/context/` package (14 files, 2,399 lines). Zero-behaviour-change refactor. 0 new tests, 0 regressions (722 tests pass).

---

## Problem

A single `HuntContext` class in one file contained schema DDL (388 lines), connection lifecycle, migration logic, hunt CRUD, 9 entity upserts, 12 query methods, HTTP history, sessions, findings, OOB listeners, coverage tracking, dedup groups, chains, and reports. Every concern was tangled in a 2,204-line file. Navigating to any single method required scrolling past hundreds of lines of unrelated SQL.

---

## Approach: Mixin Classes

Three approaches were evaluated:

| Approach | Pros | Cons |
|----------|------|------|
| **Composition** (separate objects, forwarded `conn`) | Clean separation | Every method needs `conn` passed or stored redundantly; `upsert_records` dispatches to 9 methods across multiple objects; changes internal calling patterns |
| **Partial class via imports** (methods in separate files, attached to class) | Minimal boilerplate | No IDE support for method discovery; `self` typing is awkward; fragile |
| **Mixins** (multiple inheritance, method-only classes) | Standard Python pattern (Django, DRF, Flask); IDE navigation works; `self._conn` just works; zero API change | Slightly more total lines (type stubs in mixins) |

**Mixins won** because `HuntContext` has 50+ methods that all share `self._conn` (a single SQLite connection) and `self._in_transaction` (a batch flag). Composition would require threading the connection through every call or storing it redundantly. Mixins let each method reference `self._conn` naturally — at runtime `self` is always a fully-composed `HuntContext`.

---

## File Structure

```
src/boba/core/context/
├── __init__.py          157 lines   HuntContext (inherits all mixins), lifecycle, migration
├── _helpers.py           85 lines   _now, _resolve_upsert_id, _parse_json_field, _json_array_merge
├── _schema.py           390 lines   _SCHEMA_SQL DDL constant
├── _hunt_crud.py        119 lines   HuntCrudMixin: create/get/list/update hunt, _row_to_hunt
├── _upserts.py          475 lines   UpsertMixin: 9 entity upserts + upsert_records batch dispatch
├── _queries.py          229 lines   QueryMixin: 12 get_* methods, log_tool_run, get_hunt_stats
├── _http_history.py     150 lines   HttpHistoryMixin: insert/get/query/update HTTP records
├── _sessions.py          96 lines   SessionMixin: upsert/get/delete/touch sessions
├── _findings.py         138 lines   FindingMixin: upsert_finding, get_findings, get_finding_by_id
├── _oob.py               70 lines   OobMixin: insert/update/get OOB listeners
├── _coverage.py         123 lines   CoverageMixin: upsert/get coverage, get_untested_endpoints
├── _dedup.py             97 lines   DedupMixin: dedup groups, is_duplicate, get_canonical_finding
├── _chains.py           105 lines   ChainMixin: upsert/get/delete chains
└── _reports.py          165 lines   ReportMixin: upsert/get/update reports
```

All internal modules are `_`-prefixed — they are implementation details. The only public import path remains `from boba.core.context import HuntContext`.

---

## Class Hierarchy

```python
class HuntContext(
    HuntCrudMixin,      # hunt CRUD + state machine
    UpsertMixin,        # 9 entity upserts + batch dispatch
    QueryMixin,         # 12 get_* methods + tool runs + stats
    HttpHistoryMixin,   # HTTP request/response history
    SessionMixin,       # authenticated session management
    FindingMixin,       # vulnerability findings
    OobMixin,           # out-of-band listener records
    CoverageMixin,      # test coverage tracking
    DedupMixin,         # finding deduplication groups
    ChainMixin,         # attack chain persistence
    ReportMixin,        # vulnerability reports
):
```

`HuntContext.__init__` is the sole constructor — no mixin has `__init__`. All mixins reference `self._conn`, `self._maybe_commit()`, and `self._in_transaction` which are provided by `HuntContext`.

### Mixin stubs

Two mixins (`UpsertMixin`, `CoverageMixin`) call `self._maybe_commit()`, which is defined in `HuntContext.__init__.py`, not in the mixin itself. They include a stub:

```python
def _maybe_commit(self) -> None: ...  # provided by HuntContext
```

This serves as documentation and enables IDE navigation. At runtime, the real `HuntContext._maybe_commit()` takes precedence via MRO.

Similarly, `DedupMixin` calls `self.get_finding_by_id()` from `FindingMixin`:

```python
def get_finding_by_id(self, finding_id: int) -> dict[str, Any] | None: ...  # FindingMixin
```

This is the only cross-mixin method call in the entire codebase.

---

## What Stays in `__init__.py`

The connection lifecycle methods stay in `__init__.py` because they manage the shared state that all mixins depend on:

- `__init__` — opens connection, sets WAL mode, registers `json_array_merge`, creates tables, runs migrations
- `_create_tables` — executes `_SCHEMA_SQL`
- `_maybe_migrate` — findings table migration (adding `method` column)
- `_maybe_commit` — conditional commit (suppressed during batch `upsert_records`)
- `close`, `__enter__`, `__exit__` — resource lifecycle

---

## Import Compatibility

### No caller changes required

All 20+ callers use `from boba.core.context import HuntContext`. Python resolves `boba.core.context` to `boba/core/context/__init__.py` identically to how it resolved `boba/core/context.py` — the import path is the same.

### One backward-compat re-export

`tests/test_fixes_0214.py` imports `from boba.core.context import _parse_json_field`. The `__init__.py` imports this from `_helpers.py` and includes it in `__all__`:

```python
from boba.core.context._helpers import _json_array_merge, _parse_json_field
__all__ = ["HuntContext", "_parse_json_field"]
```

---

## Method Assignment Summary

| Mixin | Methods |
|-------|---------|
| `HuntCrudMixin` | `create_hunt`, `get_hunt`, `list_hunts`, `update_hunt_status`, `_row_to_hunt`, `_VALID_TRANSITIONS` |
| `UpsertMixin` | `upsert_subdomain`, `upsert_host`, `upsert_port`, `upsert_url`, `upsert_technology`, `upsert_directory`, `upsert_parameter`, `upsert_secret`, `upsert_api_endpoint`, `upsert_records` |
| `QueryMixin` | `_ensure_hunt`, `get_subdomains`, `get_hosts`, `get_ports`, `get_urls`, `get_technologies`, `get_directories`, `get_parameters`, `get_secrets`, `get_api_endpoints`, `get_tool_runs`, `log_tool_run`, `get_hunt_stats`, `_STATS_TABLES` |
| `HttpHistoryMixin` | `insert_http_record`, `get_http_record`, `query_http_history`, `update_http_record_tags`, `update_http_record_notes` |
| `SessionMixin` | `upsert_session`, `get_session`, `get_sessions`, `_deserialize_session_row`, `delete_session`, `touch_session` |
| `FindingMixin` | `upsert_finding`, `get_findings`, `get_finding_by_id` |
| `OobMixin` | `insert_oob_listener`, `update_oob_interactions`, `get_oob_listeners` |
| `CoverageMixin` | `upsert_coverage`, `get_coverage`, `get_untested_endpoints` |
| `DedupMixin` | `insert_dedup_group`, `get_dedup_groups`, `delete_dedup_groups`, `is_duplicate`, `get_canonical_finding` |
| `ChainMixin` | `upsert_chain`, `get_chains`, `get_chain`, `update_chain_confidence`, `delete_chains` |
| `ReportMixin` | `upsert_report`, `get_reports`, `get_report`, `_deserialize_report_row`, `update_report_status` |

---

## Verification

1. `python3 -m pytest tests/ -x -q` — **722 passed** in 17.83s
2. `ruff check src/boba/core/context/` — **All checks passed**
3. `ruff format --check src/boba/core/context/` — **14 files already formatted**
4. MRO verification — all 11 mixins present in correct order:
   ```
   HuntContext → HuntCrudMixin → UpsertMixin → QueryMixin → HttpHistoryMixin →
   SessionMixin → FindingMixin → OobMixin → CoverageMixin → DedupMixin →
   ChainMixin → ReportMixin → object
   ```
5. Backward-compat re-export — `from boba.core.context import _parse_json_field` works
