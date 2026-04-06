# Code Assessment — Boba v0.6.0

**Date:** 2026-04-06
**Scope:** Full codebase — 13,740 lines source (`src/boba/`), 12,542 lines tests (`tests/`)
**Methodology:** Two independent full-codebase assessments merged and cross-verified

---

## Summary

The codebase is **technically sound and functionally complete** for V4. The adapter pattern, scope engine, persistence layer, and vulnerability testing pipeline are all well-designed. Detection logic is accurate, false-positive mitigations are thoughtful, and the test suite (722 tests) provides strong regression coverage.

Three files have grown significantly beyond maintainable size and must be refactored. Seven verified correctness issues were found — two bugs, three semantic/logic issues, and two resource management problems. The rest of the findings are code quality issues that affect readability and long-term maintainability.

---

## Part 1: Bugs (Fix Immediately)

### BUG-1. `test_race` returns inconsistent `test_type` on total failure
**File:** `src/boba/tools/vuln.py:1175`
**Verified:** Yes

When all concurrent requests fail (all raise exceptions), the function returns `test_type="race_condition"`. Every other path in `test_race` uses `test_type="race"`, and the finding is persisted with `_persist_finding(…, "race")`. The `findings` table has a `UNIQUE(hunt_id, finding_type, url, method, parameter)` constraint — the inconsistent type means a "total failure" result could never match an existing finding row, breaking dedup.

**Fix:** Change `test_type="race_condition"` to `test_type="race"` on line 1175.

---

### BUG-2. `_bodies_similar` uses unnecessary local json import
**File:** `src/boba/tools/vuln.py:2163`
**Verified:** Yes

```python
import json as _json  # local import inside function body
```

The module already imports `json` aliased as `_json_mod` at line 6. This local re-import under a different alias (`_json`) works but is confusing and incurs per-call overhead.

**Fix:** Replace `_json.loads` / `_json.dumps` with `_json_mod.loads` / `_json_mod.dumps`. Remove the local import.

---

## Part 2: Correctness Issues

### CORR-1. CVSS cloud metadata scoring assigns wrong impact vector
**File:** `src/boba/analysis/severity.py:163-164`
**Verified:** Yes — semantic bug

Cloud metadata access (`169.254.169.254`) sets `integrity="H"`, but IMDSv1 credential theft is primarily a **confidentiality** impact (reading IAM credentials, tokens, roles), not integrity. OOB callback confirmation separately sets `confidentiality="H"`, meaning SSRF with both signals gets correct confidentiality but inflated integrity.

**Fix:** Set `confidentiality="H"` for cloud_metadata; only set `integrity="H"` when there's evidence of write/modify actions.

---

### CORR-2. Coverage host filter gated behind directory check
**File:** `src/boba/analysis/coverage.py:93-94`
**Verified:** Yes

```python
if host and directories:  # host filter only applied when directories exist
```

When `directories` is empty (no directory scan results), the host filter is never applied, mixing endpoints from all hosts into per-host coverage reports.

**Fix:** Move host filter outside the directories check:
```python
if host:
    endpoint_set = {ep for ep in endpoint_set if urlparse(ep).hostname == host}
```

---

### CORR-3. Chaining takes only first finding per type for cross-host rules
**File:** `src/boba/analysis/chaining.py:314`
**Verified:** Yes

```python
all_findings.append(type_matches[rtype][0])  # always picks first
```

For cross-host chain rules (e.g., `redirect_to_ssrf`), this always selects the first finding of each required type rather than the highest-severity or highest-confidence match. A low-confidence SSRF paired with a confirmed redirect produces a weaker chain than necessary.

**Fix:** Sort `type_matches[rtype]` by severity/confidence descending before selecting `[0]`.

---

### CORR-4. Temp file leak in FfufAdapter and ArjunAdapter
**Files:** `src/boba/adapters/ffuf.py:57-59`, `src/boba/adapters/arjun.py:64-66`
**Verified:** Yes

Both create `tempfile.NamedTemporaryFile(..., delete=False)` for output but never add the path to `self._temp_files`. BaseAdapter provides `self._create_temp_file()` which properly appends to the cleanup list. If the adapter crashes between file creation and result parsing, the temp file persists on disk.

**Fix:** Use `self._create_temp_file()` instead of direct `tempfile.NamedTemporaryFile()`, or add `self._temp_files.append(output_file)` after creation.

---

### CORR-5. Redundant `test_params` re-initialization (two instances)
**Files:** `src/boba/tools/vuln.py:683` (test_xss), `src/boba/tools/vuln.py:934` (test_sqli)
**Verified:** Yes — two separate copy-paste artifacts

In `test_xss`, `test_params = params or {"q": ""}` is defined at line 548 and identically re-defined at line 683 after the main loop. In `test_sqli`, `test_params = params or {"id": "1"}` is defined at line 728 and re-defined at line 934. Both second assignments are dead code with no effect.

**Fix:** Remove lines 683 and 934.

---

## Part 3: Refactoring Required (>500 Lines)

### R1. Split `core/context.py` (2,204 lines) — DONE

Completed 2026-04-06. See [completion notes](../completions/code-assessment-p3-r1-context-split.md).

Split into 14-file `context/` package using mixin classes. `HuntContext` inherits 11 mixins (`HuntCrudMixin`, `UpsertMixin`, `QueryMixin`, `HttpHistoryMixin`, `SessionMixin`, `FindingMixin`, `OobMixin`, `CoverageMixin`, `DedupMixin`, `ChainMixin`, `ReportMixin`). Largest file is `_upserts.py` (475 lines), smallest is `_oob.py` (70 lines). Zero import changes across 20+ callers. 722 tests pass.

---

### R2. Split `tools/vuln.py` (2,197 lines)

**Problem:** 11 independent vulnerability test functions + helper functions, all in one file. Each function is 100–250 lines and follows an identical pattern (scope check → send requests → analyze → persist).

**Proposed split (package `src/boba/tools/vuln/`):**

| New file | Contents | Est. lines |
|---|---|---|
| `vuln/_helpers.py` | `_inject_param`, `_bodies_similar`, `_detect_waf`, `_extract_json_keys`, `_record_coverage`, `_persist_finding`, `_scope_skip` + shared constants | ~140 |
| `vuln/injection.py` | `test_xss`, `test_sqli` | ~450 |
| `vuln/access_control.py` | `test_idor`, `test_auth`, `test_csrf` | ~500 |
| `vuln/server_side.py` | `test_ssrf`, `test_redirect` | ~350 |
| `vuln/logic.py` | `test_race`, `test_mass_assign`, `test_reset` | ~400 |
| `vuln/ai.py` | `test_ai`, `test_ai_conversation` | ~320 |
| `vuln/__init__.py` | Re-export all public test functions | ~20 |

**Boilerplate reduction opportunities (post-split):**
- Extract scope-check guard (11 identical copies) into `_scope_skip()` helper
- Extract `TestContext` dataclass to replace 5-line initialization boilerplate in every function
- Extract result-builder function to DRY the WAF-detect + VulnTestResult assembly pattern

---

### R3. Split `cli/main.py` (1,976 lines)

**Problem:** 58 commands across 12 Typer sub-apps concatenated in one file. Each sub-app is self-contained with no cross-dependencies.

**Proposed split (package `src/boba/cli/commands/`):**

| New file | Typer app | Est. lines |
|---|---|---|
| `commands/hunt.py` | `hunt_app` (create, list, status, pause, resume, close) | ~100 |
| `commands/recon.py` | `recon_app` (subdomains, hosts, ports, urls, secrets, tech) | ~200 |
| `commands/enum.py` | `enum_app` (parameters, directories, crawl, api) | ~160 |
| `commands/context_cmds.py` | `context_app` (subdomains, hosts, ports, urls, tech, parameters, secrets, api-endpoints, directories, runs, stats, http-history, findings, sessions, oob) | ~350 |
| `commands/browser.py` | `browser_app` (navigate, screenshot, extract) | ~100 |
| `commands/http_cmds.py` | `http_app` (request, replay, compare) | ~90 |
| `commands/session.py` | `session_app` (create, login-token, list, delete) | ~100 |
| `commands/scan.py` | `scan_app` (nuclei) | ~55 |
| `commands/analyze.py` | `analyze_app` (coverage, dedupe, severity, chain, prioritize) | ~250 |
| `commands/report.py` | `report_app` (draft, format, poc, list, show) | ~150 |
| `commands/test_cmds.py` | `test_app` (idor, ssrf, xss, sqli, auth, race, redirect, csrf, mass-assign, reset, ai) | ~380 |
| `cli/shared.py` | `_managed`, `_managed_http`, `_parse_headers`, `_parse_targets`, `_get_manager` | ~80 |
| `cli/main.py` | App creation + `app.add_typer(…)` calls | ~80 |

---

## Part 4: Code Quality Issues

### Dead / Redundant Code

| Item | Location | Issue |
|---|---|---|
| Redundant `by_url_param_typed` dedup index | `analysis/dedup.py:123-148` | Produces identical keys to `by_url_param_exact` when `ftype` is non-empty (~100% of real findings). Union calls are no-ops. Remove. |
| `_get_page` alias | `interaction/browser.py:217-218` | Refactoring remnant — `_get_page = get_page`. Remove alias, update internal callers to `get_page`. |
| Nuclei `parse_record` string fallback | `adapters/nuclei.py:82-84` | `isinstance(raw, str)` branch is unreachable — JSON_LINES format never passes strings. Remove. |

### Duplication

| Pattern | Instances | Location | Fix |
|---|---|---|---|
| Scope check boilerplate | 11 | `tools/vuln.py` | Extract `_scope_skip()` helper |
| Response collection init | 11 | `tools/vuln.py` | Extract `TestContext` dataclass |
| WAF detect + result assembly | 11 | `tools/vuln.py` | Extract result-builder function |
| `_safe_int()` function | 2 | `adapters/naabu.py`, `adapters/httpx_runner.py` | Move to `adapters/_utils.py` |
| `_extract_host()` function | 2 | `analysis/dedup.py`, `analysis/chaining.py` | Move to shared utility |
| Inline `from dataclasses import asdict` | 17 | `cli/main.py` | Move to top-level import |

### Type Safety / Naming

| Item | Location | Issue | Fix |
|---|---|---|---|
| `test_ai_cmd --mode` stringly-typed | `cli/main.py:1832` | Accepts any string; should be `"single"` or `"conversation"` | Add Typer `Choice` or Enum |
| `_parse_json_field()` vague name | `core/context.py:48` | Suggest `_safe_json_parse()` | Rename |
| Deferred import in `_chain_cvss` | `analysis/chaining.py:353` | Circular import workaround | Move `calculate_cvss` to `boba.analysis.base` or `boba.core.models` |

### Edge Cases (Low Priority)

| Item | Location | Issue |
|---|---|---|
| CSS selector escaping incomplete | `interaction/browser.py:352`, `interaction/session.py:99-102` | Misses `:`, `;`, newlines. Field named `email:required` breaks selector. |
| Browser `_request_counts` unsynchronized | `interaction/browser.py:207` | Safe under asyncio single-thread model but fragile if execution model changes. |
| PoC report silently skips missing HTTP records | `reporting/draft.py:257-265` | Should log a warning when referenced request IDs are not found. |

---

## Part 5: Test Suite Assessment

### Positive Observations
- 722 tests with 0 regressions across all recent releases
- `pytest-asyncio` auto mode works cleanly
- `tmp_path` fixture isolation is well-implemented
- Good coverage of adapter parsing edge cases

### Structure Issues

| File | Lines | Issue |
|---|---|---|
| `tests/cli/test_cli.py` | 1,342 | Covers 71 commands but unorganized; should split by subgroup |
| `tests/test_fixes_0214.py` through `tests/test_fixes_0218.py` | 2,210 total | Grouped by release version rather than feature area — hard to find all tests for a given component |

### Coverage Gaps
- No error-path testing for CLI commands (invalid hunt_id, missing sessions)
- No tests for `enum_crawl`, browser commands (navigate/screenshot/extract)
- Limited fixtures in `tests/conftest.py` (63 lines) — no pre-populated hunt fixtures
- No integration test for concurrent WAL-mode SQLite access
- Missing scope edge-case tests: bare IPs, IPv6 bracket format, scheme-insensitive URL prefix

---

## Part 6: Vision Coverage

Checked against `docs/vision.md`:

| Capability | Status |
|---|---|
| Subdomain enumeration (subfinder) | Done |
| Historical URLs (gau + waybackurls) | Done |
| Host liveness (httpx) | Done |
| Port scanning (naabu) | Done |
| Technology fingerprinting (whatweb) | Done |
| Directory + parameter fuzzing (ffuf + arjun) | Done |
| Web crawling (katana) | Done |
| API endpoint discovery (kiterunner) | Done |
| Secret scanning (gitleaks) | Done |
| Nuclei template scanning | Done |
| IDOR, SSRF, XSS, SQLi, Auth bypass | Done |
| Race conditions, CSRF, mass assignment, password reset | Done |
| Open redirect | Done |
| Prompt injection (single-turn + multi-turn conversation) | Done |
| File upload testing (unrestricted, path traversal, SVG XSS) | Done |
| Browser automation (Playwright) | Done |
| Session management (form, bearer, cookie, OAuth2) | Done |
| OOB callbacks (Interactsh) | Done |
| Vulnerability chaining (13 rules) | Done |
| CVSS 3.1 scoring | Done |
| Deduplication | Done |
| Coverage tracking | Done |
| Endpoint prioritization | Done |
| Report formatting (HackerOne, Bugcrowd, markdown) | Done |
| PoC packaging | Done |
| **GraphQL testing (Clairvoyance)** | Not implemented |
| **JS endpoint mining (LinkFinder)** | Not implemented |
| **ASN enumeration** | Not implemented |
| **S3 bucket scanning** | Not implemented |
| **Amass integration** | Not implemented |
| **Continuous monitoring / new asset alerts** | Not implemented |

The unimplemented items are all Phase 2/3 tooling from the vision doc. They represent future V5+ work, not gaps in the current V4 scope.

---

## Part 7: Layer-by-Layer Summary

| Layer | Verdict | Key Issues |
|---|---|---|
| **Adapters** (`src/boba/adapters/`) | Good | Temp file leak in ffuf/arjun (CORR-4), `_safe_int` duplication |
| **Core** (`src/boba/core/`) | Good (context.py split done) | R1 complete, `get_hunt_stats` f-string SQL |
| **Interaction** (`src/boba/interaction/`) | Good | CSS escaping gaps, `_get_page` remnant, `_request_counts` fragility |
| **Tools** (`src/boba/tools/`) | Functional (vuln.py needs split) | BUG-1, BUG-2, CORR-5, R2 monolith |
| **Analysis** (`src/boba/analysis/`) | Good with edge cases | CORR-1 (CVSS), CORR-2 (coverage), CORR-3 (chaining), dedup redundancy |
| **Reporting** (`src/boba/reporting/`) | Good | Silent missing HTTP records |
| **CLI** (`src/boba/cli/`) | Functional (main.py needs split) | R3 monolith, stringly-typed mode param |

---

## Prioritized Action List

### P0 — Bugs (fix now, 1-line changes) — DONE

Completed 2026-04-06. See [completion notes](../completions/code-assessment-p1-bugs.md).

| # | Action | File | Status |
|---|---|---|---|
| BUG-1 | Fix `test_type="race_condition"` → `"race"` | `vuln.py:1175` | Done |
| BUG-2 | Remove inline `import json as _json`, use `_json_mod` | `vuln.py:2163` | Done |

### P1 — Correctness issues (fix this week) — DONE

Completed 2026-04-06. See [completion notes](../completions/code-assessment-p2-correctness.md).

| # | Action | File | Status |
|---|---|---|---|
| CORR-1 | CVSS cloud metadata: set both `confidentiality="H"` and `integrity="H"` | `severity.py:163` | Done |
| CORR-2 | Move coverage host filter outside directory check | `coverage.py:93` | Done |
| CORR-3 | Sort chain candidates by severity before selecting | `chaining.py:314` | Done |
| CORR-4 | Register temp files via `self._temp_files.append()` in ffuf/arjun | `ffuf.py:60`, `arjun.py:67` | Done |
| CORR-5 | Remove redundant `test_params` re-init (2 sites) | `vuln.py:683, 934` | Done |

### P2 — Refactoring (plan and execute over 1–2 weeks)

| # | Action | File(s) | Status |
|---|---|---|---|
| R1 | Split `context.py` → `context/` package (mixin classes) | `core/context/` (14 files) | Done — see [completion notes](../completions/code-assessment-p3-r1-context-split.md) |
| R2 | Split `vuln.py` → `vuln/` package | `tools/vuln.py` | Pending |
| R3 | Split `cli/main.py` → `cli/commands/` package | `cli/main.py` | Pending |

### P3 — Code quality (address during refactoring)

| Action | File(s) | Effort |
|---|---|---|
| Remove redundant `by_url_param_typed` dedup index | `dedup.py` | Small |
| Extract `_scope_skip` helper (during R2) | `vuln.py` | Small |
| Remove `_get_page` alias | `browser.py` | 1 line |
| Remove nuclei string fallback dead code | `nuclei.py` | 3 lines |
| Add Typer `Choice` to `test_ai_cmd --mode` | `cli/main.py` | 5 lines |
| Extract `_safe_int` to shared adapter utility | `naabu.py`, `httpx_runner.py` | Small |
| Move inline `asdict` imports to top-level | `cli/main.py` | Small |
| Resolve deferred import in `_chain_cvss` | `chaining.py` | Small |

### P4 — Test suite improvements (ongoing)

| Action | Effort |
|---|---|
| Split `test_cli.py` by subcommand group | Medium |
| Reorganize `test_fixes_*` files by feature area | Medium |
| Add CLI error-path tests | Medium |
| Add browser command tests | Medium |
| Add scope edge-case tests (bare IPs, IPv6, scheme-insensitive) | Small |
