# V4 Phase 2 Completion — AI Chain Rules

## Summary

Implemented Phase 2 of the V4 enrichment plan: Boba’s chaining engine now understands AI findings as first-class attack-chain inputs instead of treating prompt injection as an isolated result.

## Why

Before this phase, the chaining engine had no AI-aware rules. That meant:

- prompt injection findings stayed standalone even when they clearly implied higher impact
- AI findings could not combine with auth findings or XSS findings to represent realistic compromise paths
- Phase 6’s future multi-turn/tool-abuse evidence had no stable rule surface waiting for it

This phase fixed the chain-model gap without changing Boba’s core design principle: Boba provides capability, while the agent decides what to do next.

## What Changed

### 1. Added stable AI evidence identifiers

**File:** `src/boba/payloads/ai.py`

Added:

- `EVIDENCE_TYPES`

Current identifiers:

- `instruction_override`
- `system_prompt_leak`
- `function_call`
- `tool_use`
- `api_call`
- `credential_leak`

Why this matters:

- gives the AI feature area a stable vocabulary for future detectors
- lets chain rules match against explicit evidence tokens instead of ad hoc strings
- keeps the prompt-injection pipeline aligned with future Phase 6 expansion

### 2. Extended the chain rule set with AI-specific chains

**File:** `src/boba/analysis/chaining.py`

Added 4 new `ChainRule` entries to `CHAIN_RULES`:

#### `ai_tool_abuse`

- **Type:** single-type AI rule
- **Severity:** `critical`
- **Purpose:** upgrade AI findings that show tool or function invocation behavior
- **Evidence keywords:** `function_call`, `tool_use`, `api_call`

#### `ai_data_exfiltration`

- **Type:** single-type AI rule
- **Severity:** `high`
- **Purpose:** upgrade prompt/system-prompt leakage into a sensitive data exposure chain
- **Evidence keywords:** `system_prompt_leak`, `credential_leak`, `api_key`

#### `xss_to_ai_injection`

- **Type:** multi-finding same-host rule
- **Severity:** `critical`
- **Purpose:** model the path where XSS can poison LLM-facing surfaces on the same host

#### `ai_plus_auth_bypass`

- **Type:** multi-finding same-host rule
- **Severity:** `critical`
- **Purpose:** model the path where auth bypass exposes privileged AI capability and prompt injection abuses it

### 3. Reused the existing chaining engine instead of adding AI-specific logic branches

**File:** `src/boba/analysis/chaining.py`

No new analysis subsystem was introduced.

The implementation intentionally reused:

- existing `ChainRule` structure
- existing `_match_rule()` behavior
- existing `_evidence_contains()` keyword-based evidence matcher
- existing persistence flow through `detect_chains()`

That kept the change small and consistent with the V3 analysis architecture.

## Implementation Details

### Evidence matching strategy

The current chaining engine matches `evidence_keywords` via substring search over serialized evidence.

Because of that, Phase 2 used specific snake_case identifiers instead of generic words. For example:

- `function_call` instead of `function`
- `credential_leak` instead of `credential`
- `system_prompt_leak` instead of `prompt`

This reduces false positives and makes future evidence emitters easier to reason about.

### Why these rules were added now

These rules were selected because they fit the current system cleanly:

- single-type AI chains work with today’s AI evidence and future richer evidence
- same-host AI/auth and XSS/AI rules do not require new infrastructure
- they integrate directly with existing attack-chain scoring and persistence

## Tests Added / Updated

**File:** `tests/analysis/test_chaining.py`

Added dedicated tests for:

- AI tool-abuse chain detection
- AI data-exfiltration chain detection
- XSS + AI same-host chain detection
- AI + auth same-host chain detection
- negative case: AI tool-abuse chain requires matching evidence
- negative case: AI + auth chain requires same host

These tests were added alongside the existing chaining suite instead of creating a separate AI-only suite, which keeps rule validation in the same place as all other chain behavior.

## Validation

Ran successfully during implementation:

- `python3 -m ruff check src tests`
- `python3 -m ruff format --check` on changed files
- `python3 -m pytest`

Result at completion time: **604 tests passed**

## Notes / Trade-offs

- The chain matcher is still substring-based, so evidence token naming remains important.
- `ai_tool_abuse` is effectively a forward-compatible rule right now: it is fully implemented, but it becomes more valuable once richer AI evidence is emitted in later phases.
- `xss_to_ai_injection` models realistic same-host coupling but does not attempt to prove stored persistence at the engine layer; that higher-order reasoning remains an agent concern.
- This phase intentionally avoided changing `test_ai()` behavior. It added chain capability first, so later AI testing improvements have a ready analysis surface.
