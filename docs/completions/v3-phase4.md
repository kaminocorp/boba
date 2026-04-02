# V3 Phase 4 Completion — Vulnerability Chaining & Prioritization

**Date:** 2026-04-02
**Scope:** 7 files modified/created, 29 new tests, 540 tests passing (29 new, 0 regressions)

## What Was Done

Phase 4 delivers the two highest-value analysis capabilities:

1. **Vulnerability chaining** — correlate findings into attack chains where combined impact exceeds individual severity (e.g., P4 redirect + P4 SSRF → P1 internal access).
2. **Attack path prioritization** — rank untested endpoints by likelihood of containing vulnerabilities, so the agent tests the highest-value targets first.

## Changes By File

### New Files

| File | Purpose |
|---|---|
| `src/boba/analysis/chaining.py` | Chain rules engine, `detect_chains()`, `suggest_chains()`, `validate_chain()` |
| `src/boba/analysis/prioritize.py` | `prioritize_endpoints()` — scoring by params, auth patterns, hot hosts, proxy patterns |
| `tests/analysis/test_chaining.py` | 19 tests for chain detection, suggestion, validation, context CRUD, CLI |
| `tests/analysis/test_prioritize.py` | 10 tests for endpoint scoring, exclusion, suggestions, CLI |

### Modified Files

| File | What Changed |
|---|---|
| `src/boba/core/context.py` | Added `chains` table to schema. Added `upsert_chain()`, `get_chains()`, `get_chain()`, `update_chain_confidence()`, `delete_chains()` |
| `src/boba/core/models.py` | Added `ChainStatus` enum, `AttackChain` dataclass |
| `src/boba/cli/main.py` | Added `analyze chain` and `analyze prioritize` commands |

## Schema Addition

```sql
CREATE TABLE IF NOT EXISTS chains (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id         TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    title           TEXT NOT NULL,
    description     TEXT,
    severity        TEXT NOT NULL DEFAULT 'info',
    confidence      TEXT NOT NULL DEFAULT 'hypothetical',
    cvss_score      REAL,
    cvss_vector     TEXT,
    finding_ids     TEXT NOT NULL DEFAULT '[]',
    chain_order     TEXT NOT NULL DEFAULT '[]',
    impact          TEXT,
    prerequisites   TEXT DEFAULT '[]',
    tags            TEXT DEFAULT '[]',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    UNIQUE(hunt_id, title)
);
```

## Key Design Decisions

### 1. Rules-based chain detection

The chaining engine uses 8 predefined `ChainRule` patterns, each specifying:
- `required_types` — which finding types must be present
- `same_host` — whether findings must be on the same host
- `evidence_keywords` — evidence signals that must be present (e.g., "169.254.169.254" for cloud metadata SSRF)
- `combined_severity` — the chain's severity (always ≥ max individual severity)

This is deliberately rule-based rather than ML-based — it's transparent, auditable, and the agent can understand *why* a chain was detected.

### 2. Single-finding chains for evidence-upgraded vulnerabilities

Some chain rules only require one finding type but check for evidence that escalates severity. For example, an SSRF finding alone is high severity, but SSRF + cloud metadata evidence → critical. This models the real-world pattern where the same vulnerability has different impact depending on what it can reach.

### 3. Dedup-aware chain detection

`detect_chains()` calls `_get_non_duplicate_findings()` to exclude non-canonical dedup group members. This prevents the same vulnerability from appearing in multiple chains via its duplicate copies.

### 4. Three-tier chain confidence

- **Hypothetical** — rule matched findings, but the chain hasn't been end-to-end tested
- **Partial** — some links in the chain are confirmed, others aren't
- **Validated** — agent confirmed the full chain works end-to-end

The agent starts with hypothetical chains from `detect_chains()`, then calls `validate_chain()` after manual confirmation.

### 5. Prioritization scoring model

Endpoints are scored by additive signals:

| Signal | Score | Suggested Tests |
|---|---|---|
| Has query parameters | +3.0 | xss, sqli, idor |
| Auth-related path | +3.0 | auth |
| Proxy/redirect path | +3.0 | ssrf |
| Admin path | +2.5 | auth |
| API endpoint | +2.0 | idor |
| File handling | +2.0 | — |
| Hot host (existing findings) | +2.0 | — |
| Untested (minimum) | +1.0 | xss, sqli |

Already-tested endpoints (with coverage rows) are excluded from results.

## Chain Rules Reference

| Rule | Required Types | Same Host | Evidence | Combined Severity |
|---|---|---|---|---|
| redirect_to_ssrf | redirect, ssrf | No | — | Critical |
| xss_to_account_takeover | xss, csrf | Yes | — | Critical |
| idor_mass_exfil | idor | — | enum, sequential | Critical |
| sqli_to_rce | sqli | — | error/time/boolean | Critical |
| auth_bypass_admin | auth | — | admin, privilege | Critical |
| ssrf_cloud_metadata | ssrf | — | 169.254.169.254, aws | Critical |
| xss_session_hijack | xss | — | reflected, dom, confirmed | High |
| idor_plus_sqli | idor, sqli | Yes | — | Critical |

## Test Coverage (29 new tests)

| Test Class | Count | What's Tested |
|---|---|---|
| `TestDetectChains` | 9 | SSRF cloud chain, auth admin, IDOR+SQLi same host, no chain without evidence, same_host different hosts, dedup excluded, severity ≥ max individual, idempotent, empty |
| `TestSuggestChains` | 2 | Targeted suggestion, no-match behavior |
| `TestValidateChain` | 2 | Confidence transition, nonexistent chain |
| `TestChainContextCRUD` | 4 | Upsert/query, get by ID, severity filter, delete |
| `TestCLIChain` | 2 | JSON detection, no-chains message |
| `TestPrioritizeEndpoints` | 8 | Param boost, auth boost, hot host, tested exclusion, top limit, proxy→SSRF, admin→auth, empty |
| `TestCLIPrioritize` | 2 | JSON output, top limit |

## CLI Usage

```bash
# Detect all chains
boba analyze chain <hunt-id>

# Suggest chains for specific findings
boba analyze chain <hunt-id> --finding-ids 3,7,12

# Mark a chain as validated
boba analyze chain <hunt-id> --validate 1

# Prioritize untested endpoints
boba analyze prioritize <hunt-id>

# Top 10 only
boba analyze prioritize <hunt-id> --top 10

# Machine output
boba analyze chain <hunt-id> --format json
boba analyze prioritize <hunt-id> --format json
```

## What's Next

Phase 5: **Report Generation & PoC Packaging** — generate platform-ready vulnerability reports from findings and chains, with evidence compilation and HackerOne/Bugcrowd formatting.
