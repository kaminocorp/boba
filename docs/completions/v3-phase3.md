# V3 Phase 3 Completion — Severity Assessment (CVSS 3.1)

**Date:** 2026-04-02
**Scope:** 4 files modified/created, 26 new tests, 511 tests passing (26 new, 0 regressions)

## What Was Done

Phase 3 delivers **standardized severity scoring** — every finding gets a CVSS 3.1 base score, a severity level, and an optional payout estimate for HackerOne or Bugcrowd. This is the prerequisite for chaining (Phase 4) and reporting (Phase 5).

## Changes By File

### New Files

| File | Purpose |
|---|---|
| `src/boba/analysis/severity.py` | CVSS 3.1 calculator, auto-scoring heuristics, payout mapping, batch scoring |
| `tests/analysis/test_severity.py` | 26 tests covering CVSS math, boundaries, auto-scoring, payouts, batch, CLI |

### Modified Files

| File | What Changed |
|---|---|
| `src/boba/core/models.py` | Added `CVSSScore` dataclass (score, vector, all 8 metrics) |
| `src/boba/cli/main.py` | Added `analyze severity` command with `--finding-id`, `--platform`, `--format` flags |

## Key Design Decisions

### 1. Exact CVSS 3.1 specification implementation

The `calculate_cvss()` function implements the CVSS 3.1 base score formula exactly as specified by FIRST. This includes:
- The roundup function (smallest number with one decimal place ≥ input)
- Scope-dependent privilege required weights (`_PR_UNCHANGED` vs `_PR_CHANGED`)
- Scope-dependent impact formula (linear for Unchanged, polynomial for Changed)
- The 1.08 multiplier for Changed scope

Verified against published reference vectors: `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` = 10.0 (Log4Shell), `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` = 6.1 (reflected XSS).

### 2. Auto-scoring as starting point, not final word

`auto_score_finding()` maps finding types to CVSS metrics using heuristic rules, then refines based on evidence. For example:
- IDOR → C:H/I:L by default, but write operations (DELETE, PUT) upgrade to I:H
- SSRF → S:C/C:H by default, but cloud metadata access adds I:H
- XSS → reflected gets AC:H, stored keeps AC:L (lower bar to exploit)

These are starting points. The agent should review and adjust — the auto-score provides a consistent baseline so no finding goes unscored.

### 3. Read-only batch scoring

`score_findings()` does NOT mutate the findings table. It reads findings, computes CVSS, and returns enriched dicts. This keeps the scoring pipeline side-effect-free — the agent can score findings repeatedly without worrying about data corruption. If the finding's severity needs updating, that's a separate explicit action.

### 4. Platform payout mapping as separate concern

Payout estimates are decoupled from CVSS scoring — they're added as optional fields only when a `--platform` flag is specified. This keeps the core scoring clean and avoids baking platform-specific assumptions into the severity model.

## CVSS Metrics Quick Reference

| Metric | Values | Meaning |
|---|---|---|
| AV (Attack Vector) | N, A, L, P | Network → Adjacent → Local → Physical |
| AC (Attack Complexity) | L, H | Low → High |
| PR (Privileges Required) | N, L, H | None → Low → High |
| UI (User Interaction) | N, R | None → Required |
| S (Scope) | U, C | Unchanged → Changed (crosses trust boundary) |
| C (Confidentiality) | N, L, H | None → Low → High |
| I (Integrity) | N, L, H | None → Low → High |
| A (Availability) | N, L, H | None → Low → High |

## Test Coverage (26 new tests)

| Test Class | Count | What's Tested |
|---|---|---|
| `TestCVSSCalculation` | 7 | Max score 10.0, zero impact, Log4Shell vector, medium vector (6.1), physical access, scope changed vs unchanged, vector string format |
| `TestSeverityFromScore` | 1 | All 5 boundary transitions (info/low/medium/high/critical) |
| `TestAutoScoring` | 7 | IDOR default, IDOR write, SSRF cloud metadata, XSS reflected vs stored, SQLi critical, auth critical, unknown type fallback |
| `TestPayoutMapping` | 4 | HackerOne critical, Bugcrowd high, info zero, unknown platform fallback |
| `TestBatchScoring` | 4 | Score all, score specific, score with platform, empty hunt |
| `TestCLISeverity` | 3 | JSON output, platform payout, no-findings message |

## CLI Usage

```bash
# Score all findings
boba analyze severity <hunt-id>

# Score a specific finding
boba analyze severity <hunt-id> --finding-id 7

# Include HackerOne payout estimates
boba analyze severity <hunt-id> --platform hackerone

# Machine output
boba analyze severity <hunt-id> --platform bugcrowd --format json
```

## What's Next

Phase 4: **Vulnerability Chaining** — correlate findings into attack chains where combined impact exceeds individual severity (e.g., P4 redirect + P4 SSRF → P1 internal network access).
