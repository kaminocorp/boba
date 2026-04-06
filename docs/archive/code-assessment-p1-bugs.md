# Code Assessment — Part 1: Bugs

**Date:** 2026-04-06
**Source:** [Code Assessment](../plans/code-assessment.md) Part 1
**Scope:** 2 bugs in `src/boba/tools/vuln.py`. 0 new tests, 0 regressions (722 tests pass).

---

## BUG-1. `test_race` inconsistent `test_type` on total failure

**File:** `src/boba/tools/vuln.py:1175`

### Problem

When all concurrent requests in `test_race` raise exceptions (total failure), the function returned `test_type="race_condition"`. Every other code path in `test_race` uses `test_type="race"`, and the finding is persisted via `_persist_finding(…, "race")`.

The `findings` table has a `UNIQUE(hunt_id, finding_type, url, method, parameter)` constraint. The inconsistent type string meant a "total failure" result could never collide with an existing finding row for the same endpoint, silently breaking dedup. If a previous run had recorded a `"race"` finding for the same URL, and a later run hit total failure, the `"race_condition"` result would be treated as a distinct finding rather than an update.

### Fix

```python
# Before
test_type="race_condition",

# After
test_type="race",
```

Single-line change. The `test_type` field is an identity key — it must match everywhere: return values, persistence calls, coverage records, and chain rule `required_types`.

---

## BUG-2. `_bodies_similar` shadowed module-level `json` import

**File:** `src/boba/tools/vuln.py:2163`

### Problem

`_bodies_similar()` contained a local import inside the function body:

```python
import json as _json  # line 2163
```

The module already imports `json` at line 6:

```python
import json as _json_mod  # line 6
```

This created two different aliases for the same module in the same file. The local import worked but had two issues:

1. **Per-call overhead.** Python's `import` statement inside a function body re-executes import machinery on every call (lock acquisition, `sys.modules` dict lookup). `_bodies_similar` is called in hot paths during IDOR comparison loops.

2. **Maintenance trap.** Two aliases (`_json` and `_json_mod`) for the same module invites confusion. A future contributor could reasonably assume `_json` refers to something different, or use the wrong alias in a refactor.

### Fix

Removed the local `import json as _json` and replaced all 4 usages with the existing module-level `_json_mod`:

| Line | Before | After |
|------|--------|-------|
| 2163 | `import json as _json` | *(deleted)* |
| 2166 | `_json.loads(body_a)` | `_json_mod.loads(body_a)` |
| 2167 | `_json.loads(body_b)` | `_json_mod.loads(body_b)` |
| 2177 | `_json.dumps(json_a, ...)` | `_json_mod.dumps(json_a, ...)` |
| 2178 | `_json.dumps(json_b, ...)` | `_json_mod.dumps(json_b, ...)` |
