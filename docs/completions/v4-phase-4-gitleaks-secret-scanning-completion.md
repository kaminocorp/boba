# V4 Phase 4 Completion — Gitleaks Secret Scanning

## Summary

Implemented Phase 4 of the V4 enrichment plan: Boba can now scan git repositories for leaked credentials, API keys, internal URLs, and sensitive configuration using gitleaks, persist results in hunt context, expose them through CLI queries, and filter by secret type or repository.

## Why

This phase closes a high-value, low-effort gap in the agent's recon workflow.

Before this change:

- the agent had no way to scan target repositories for leaked credentials
- leaked AWS keys, GitHub tokens, database passwords, and internal API endpoints were invisible
- the agent could not programmatically find P1 Critical findings that require zero target interaction

After this phase:

- secret scanning is a first-class reconnaissance step
- secrets are persisted, redacted, queryable, and tracked in hunt statistics
- the agent can find instant P1 Critical findings from leaked credentials in public repositories

## What Changed

### 1. Added `GitleaksAdapter`

**File:** `src/boba/adapters/gitleaks.py`

Added a new adapter:

- `TOOL_NAME = "gitleaks"`
- `BINARY_NAMES = ["gitleaks"]`
- `OUTPUT_FORMAT = OutputFormat.JSON_ARRAY`
- `PRODUCES = "secret"`
- `SCOPE_MODE = "post"`

Implemented:

- `install_hint()`
- `build_command()`
- `parse_record()`
- `extract_scope_target()`

### 2. Implemented secret redaction

**File:** `src/boba/adapters/gitleaks.py`

The adapter redacts all secrets before they reach persistence. The `_redact()` function keeps only the first 4 and last 4 characters, replacing the middle with `****`. Secrets of 8 characters or fewer are fully redacted to `****`. This ensures full credential values are never stored in the SQLite database.

Example: `AKIAIOSFODNN7EXAMPLE` becomes `AKIA****MPLE` — enough to identify the secret type and draft a PoC, but not enough to exploit it.

### 3. Implemented automatic secret type classification

**File:** `src/boba/adapters/gitleaks.py`

The `_classify_secret_type()` function maps gitleaks rule IDs to high-level categories:

- `key` — AWS access keys, API keys, GCP keys, Stripe keys, etc.
- `token` — GitHub PATs, Slack tokens, JWT tokens, npm tokens, etc.
- `password` — passwords found in URLs or config
- `certificate` — private keys, TLS certificates
- `other` — unrecognized rules

A lookup table of ~40 known gitleaks rules provides exact mappings. Unknown rules are classified by keyword inference (e.g., rule containing "key" maps to `key`).

### 4. Implemented resilient JSON parsing

**File:** `src/boba/adapters/gitleaks.py`

The adapter handles gitleaks' JSON output format which uses PascalCase field names (`RuleID`, `Secret`, `File`, `StartLine`, `Commit`, `Author`, `Date`, `Entropy`). The parser also accepts lowercase variants for forward compatibility. Missing fields gracefully default to empty strings, `None`, or `"unknown"`.

### 5. Registered the adapter

**File:** `src/boba/adapters/__init__.py`

Added `GitleaksAdapter` to the lazy adapter registry.

### 6. Added persistent `secrets` storage

**File:** `src/boba/core/context.py`

Added a new SQLite table:

- `secrets`

Stored fields:

- `hunt_id`
- `rule_id`
- `secret_type`
- `file_path`
- `repo`
- `line_number`
- `match_preview`
- `commit_sha` (renamed from `commit` to avoid SQLite reserved keyword conflict)
- `author`
- `date`
- `entropy`
- `sources`
- `created_at`

Added indexes:

- `idx_secrets_hunt`
- `idx_secrets_type`

Note: the column was named `commit_sha` instead of `commit` because `COMMIT` is a reserved keyword in SQLite. The adapter record uses `commit` as the dict key, and the upsert method maps it to `commit_sha` transparently.

### 7. Added secret upsert/query helpers

**File:** `src/boba/core/context.py`

Added:

- `upsert_secret()`
- `get_secrets()`

Behavior:

- dedupes on `(hunt_id, repo, file_path, rule_id, line_number)`
- merges `sources` using the standard `json_group_array(DISTINCT value)` pattern
- preserves non-empty `match_preview`, `commit_sha`, `author` using `CASE WHEN excluded != '' THEN excluded ELSE existing END`
- preserves `entropy` using `COALESCE(excluded, existing)`
- supports filtering by `secret_type` and `repo`

Also updated:

- `upsert_records()` dispatch to support `"secret"`
- `_STATS_TABLES` so hunt stats include `secrets`

### 8. Added high-level recon integration

**File:** `src/boba/tools/recon.py`

Added:

- `secrets()`

This tool function:

- accepts a target (GitHub org, user, or repo path/URL) and optional specific repo URL
- deep-copies adapter config
- runs the adapter with scope enforcement
- persists discovered records through `context.upsert_records(..., "secret", ...)`
- logs the tool run
- returns early with empty result for empty targets

### 9. Added CLI commands

**File:** `src/boba/cli/main.py`

Added:

- `boba recon secrets`
- `boba context secrets`

#### `boba recon secrets`

Supports:

- `--target` — GitHub org, user, or repo path
- `--repo` — specific repo URL (overrides target)
- normal `--format`
- normal `--data-dir`

#### `boba context secrets`

Supports:

- `--type` — filter by secret type (key, token, password, certificate, other)
- `--repo` — filter by repository
- normal `--format`
- normal `--data-dir`

Table output includes:

- `rule_id`
- `secret_type`
- `file_path`
- `match_preview`
- `repo`
- `line_number`
- `commit_sha`

## Tests Added / Updated

### Adapter tests

**File:** `tests/adapters/test_gitleaks.py`

Added coverage for:

- basic command construction
- `--no-git` flag injection
- empty targets error handling
- full gitleaks JSON record parsing (PascalCase fields)
- minimal record parsing (missing optional fields)
- string input fallback
- JSON array output parsing (multiple records)
- empty output handling
- empty string output handling
- scope target extraction from GitHub URLs
- scope target extraction from local paths
- scope target extraction with empty repo

### Helper tests

**File:** `tests/adapters/test_gitleaks.py`

Added coverage for:

- `_redact()` with long, short, 8-char, and 9-char strings
- `_classify_secret_type()` for known rules, inferred types, and unknown fallback

### Tool tests

**File:** `tests/tools/test_recon.py`

Added coverage for:

- secret result persistence (2 records)
- empty target handling
- tool run logging

### Context tests

**File:** `tests/core/test_context.py`

Added coverage for:

- insert/query behavior
- source merging
- filtering by type and repo
- stats including `secrets`

### CLI tests

**File:** `tests/cli/test_cli.py`

Added coverage for:

- `context secrets` empty result
- `context secrets` with data (JSON format)
- `context secrets` JSON output
- `context secrets` filter by type

### Regression / consistency tests

**Files:**

- `tests/test_fixes_0218.py`

Added coverage for:

- invalid-hunt query behavior for `get_secrets()`
- valid-hunt empty query for `get_secrets()`

## Validation

Ran successfully during implementation:

- `python3 -m ruff check src/ tests/` — all checks passed
- `python3 -m ruff format --check` on changed files — all formatted
- `python3 -m pytest` — **658 tests passed**, 0 failures, 0 regressions

## Test Count

| Phase | Tests |
|---|---|
| Baseline (after Phase 3) | 627 |
| Phase 4 new tests | 31 |
| **Total** | **658** |

## Notes / Trade-offs

- Gitleaks was not available in the local environment during implementation, so the adapter was designed defensively around documented command and output format.
- The `commit` column was renamed to `commit_sha` because `COMMIT` is a reserved keyword in SQLite. The adapter record dict still uses `commit` as the key; the `upsert_secret()` method transparently maps `record.get("commit", record.get("commit_sha", ""))`.
- Secret redaction happens at the adapter layer (parse_record), not at the persistence layer. This means full secret values never reach context.py — defense in depth.
- The adapter uses `SCOPE_MODE = "post"` because scope filtering before scanning a repo is not meaningful (the repo URL/path is the target, and secrets within it can reference any domain). Post-filtering uses the repo URL's hostname for scope checking.
- The `_classify_secret_type()` function maps ~40 known gitleaks rules to categories and infers from rule name keywords for unknown rules, minimizing the chance of producing unhelpful "other" classifications.
- This phase focuses on discovery and persistence. Automatic report generation for leaked secrets (instant P1 drafts) is left to the agent layer — Boba provides the data, the agent decides what to do with it.
