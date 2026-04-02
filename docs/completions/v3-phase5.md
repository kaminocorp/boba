# V3 Phase 5 Completion — Report Generation & PoC Packaging

**Date:** 2026-04-02
**Scope:** 10 files modified/created, 23 new tests, 563 tests passing (23 new, 0 regressions)

## What Was Done

Phase 5 delivers the **reporting pipeline** — the final step that turns analyzed findings into platform-ready vulnerability reports. Three layers: draft (structured data), format (platform-specific markdown), and PoC package (evidence directory).

## Changes By File

### New Files

| File | Purpose |
|---|---|
| `src/boba/reporting/__init__.py` | New reporting package |
| `src/boba/reporting/draft.py` | `draft_finding_report()`, `draft_chain_report()` — generate structured reports from findings/chains |
| `src/boba/reporting/formatter.py` | `format_hackerone()`, `format_bugcrowd()`, `format_markdown()` — platform-specific formatting |
| `src/boba/reporting/poc.py` | `package_poc()` — compile evidence into a directory (HTTP dumps, evidence.json, README) |
| `tests/reporting/__init__.py` | Test package |
| `tests/reporting/test_draft.py` | 7 tests for report drafting |
| `tests/reporting/test_formatter.py` | 8 tests for platform formatting |
| `tests/reporting/test_poc.py` | 4 tests for PoC packaging |
| `tests/reporting/test_cli_report.py` | 4 tests for CLI commands |

### Modified Files

| File | What Changed |
|---|---|
| `src/boba/core/context.py` | Added `reports` table to schema. Added `upsert_report()`, `get_reports()`, `get_report()`, `update_report_status()`, `_deserialize_report_row()` |
| `src/boba/core/models.py` | Added `ReportStatus` enum, `Platform` enum, `ReportDraft` dataclass, `PoCPackage` dataclass |
| `src/boba/core/errors.py` | Added `ReportError` exception |
| `src/boba/cli/main.py` | Added `report` command group with `draft`, `format`, `poc`, `list`, `show` subcommands |

## Key Design Decisions

### 1. Three-layer reporting architecture

- **Draft** — structured `ReportDraft` dataclass with all report fields. Persisted to the `reports` table. This is the source of truth.
- **Format** — stateless functions that take a `ReportDraft` and produce platform-specific markdown. No side effects, no DB access.
- **PoC** — file-system operation that compiles evidence into a directory tree with HTTP dumps, evidence.json, and a README.

Each layer is independently useful. The agent can draft without formatting, format without packaging, or package without submitting.

### 2. Auto-generated report content

`draft_finding_report()` generates everything from the finding record:
- **Title:** `[Component] — [Vuln Type] via [Param] Leads to [Impact]` (e.g., "api/users — Insecure Direct Object Reference via `id` Parameter Leads to Unauthorized Data Access")
- **Summary:** Derived from finding description, or auto-generated from finding type + URL + parameter
- **Steps:** Built from evidence payloads + HTTP history records (up to 5 requests)
- **Impact:** Concrete, type-specific impact statement (not hypothetical "could" language)
- **Remediation:** Type-specific fix suggestions

### 3. HTTP dumps in RFC 7230 format

PoC `.http` files follow standard HTTP message format:
```
GET /api/users/123 HTTP/1.1
Host: app.example.com
Cookie: session=attacker_token

###

HTTP/1.1 200 OK
Content-Type: application/json

{"id": 123, "email": "victim@example.com"}
```

This format is directly importable into Burp Suite, Postman, and most HTTP testing tools.

### 4. Platform formatting differences

| Feature | HackerOne | Bugcrowd | Generic |
|---|---|---|---|
| Title format | ## heading | ## heading | # heading |
| Severity | Bold text + CVSS | VRT classification (P1-P5) + CVSS | Inline severity + CVSS |
| Sections | Summary, Steps, Impact, Remediation, Supporting Material | Location, Description, Steps, Impact, Severity Justification, Remediation | Summary, Steps, Impact, Remediation, CVSS Details |
| Evidence | Supporting Material section | Inline | Inline |

### 5. Chain reports merge evidence

`draft_chain_report()` iterates over all chained findings and merges:
- Steps: ordered as "Step 1: Exploit [type] on [url]" with evidence sub-items
- Request IDs: union of all findings' request_ids
- Impact: from the chain's impact field (combined impact)

## Schema Addition

```sql
CREATE TABLE IF NOT EXISTS reports (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id             TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    finding_id          INTEGER REFERENCES findings(id),
    chain_id            INTEGER REFERENCES chains(id),
    title               TEXT NOT NULL,
    severity            TEXT NOT NULL,
    cvss_score          REAL,
    cvss_vector         TEXT,
    summary             TEXT,
    steps               TEXT DEFAULT '[]',
    impact              TEXT,
    remediation         TEXT,
    evidence_refs       TEXT DEFAULT '[]',
    request_ids         TEXT DEFAULT '[]',
    platform            TEXT,
    platform_report_id  TEXT,
    platform_status     TEXT,
    submitted_at        TEXT,
    status              TEXT NOT NULL DEFAULT 'draft',
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL
);
```

## Test Coverage (23 new tests)

| Test Class | Count | What's Tested |
|---|---|---|
| `TestDraftFindingReport` | 5 | Structure, title format, evidence in steps, persistence, nonexistent finding |
| `TestDraftChainReport` | 2 | Chain merges findings, nonexistent chain |
| `TestHackerOneFormat` | 4 | Required sections, numbered steps, CVSS vector, evidence refs |
| `TestBugcrowdFormat` | 2 | VRT classification, severity justification |
| `TestMarkdownFormat` | 2 | Heading structure, no CVSS section without vector |
| `TestPoCPackaging` | 4 | Directory structure, evidence.json, HTTP dumps, README summary |
| `TestCLIReportDraft` | 2 | JSON output, requires --finding-id or --chain-id |
| `TestCLIReportFormat` | 1 | HackerOne format output |
| `TestCLIReportList` | 1 | List reports JSON |

## CLI Usage

```bash
# Draft a report from a finding
boba report draft <hunt-id> --finding-id 7

# Draft from a chain
boba report draft <hunt-id> --chain-id 1

# Format for HackerOne
boba report format <hunt-id> --report-id 1 --platform hackerone

# Format for Bugcrowd
boba report format <hunt-id> --report-id 1 --platform bugcrowd

# Package PoC evidence
boba report poc <hunt-id> --finding-id 7 --output-dir ./evidence

# List all reports
boba report list <hunt-id>
boba report list <hunt-id> --status draft --format json

# Show full report
boba report show <hunt-id> --report-id 1
```

## What's Next

Phase 6: **Advanced Vulnerability Tools** — 6 new test types (race conditions, open redirect, CSRF, mass assignment, password reset, AI/LLM prompt injection).
