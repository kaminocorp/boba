# V4 Phase 6 Completion — AI Multi-Turn Conversation Mode

## Summary

Implemented Phase 6 of the V4 enrichment plan: Boba can now conduct multi-turn conversations with LLM endpoints via POST/JSON, test for tool/function abuse, detect indirect injection, and identify credential leaks in AI responses. The existing `test_ai` (single GET) remains unchanged.

## Why

This phase transforms Boba's AI testing from "inject one string" to "have a conversation that leads to compromise."

Before this change:

- `test_ai` sent single GET requests with payloads in a query parameter
- real LLM features are conversational POST endpoints accepting JSON with message history
- the most effective prompt injection techniques (few-shot jailbreaking, context pollution, gradual escalation) require multi-turn interaction
- tool/function abuse and indirect injection were not testable
- credential leaks in AI responses were not detected

After this phase:

- `test_ai_conversation` sends POST requests with JSON bodies and accumulates conversation history
- three attack modes: multi-turn conversations, tool abuse probes, indirect injection
- configurable field names (`message_field`, `history_field`) adapt to different API shapes
- richer evidence tagging (`function_call`, `credential_leak`) matches AI chain rules from Phase 2
- CLI supports `--mode conversation` with `--message-field` and `--history-field` options

## What Changed

### 1. Added new payload sets

**File:** `src/boba/payloads/ai.py`

Added:

- `CONVERSATIONS` — 5 multi-turn conversation payloads (gradual escalation, few-shot jailbreak, context pollution, role confusion, instruction smuggling via encoding)
- `TOOL_ABUSE` — 5 single-turn payloads targeting function/tool calling
- `INDIRECT` — 4 indirect injection payloads (HTML comments, system tags, conversation format smuggling)
- `TOOL_ABUSE_INDICATORS` — 7 response indicators for tool/function abuse detection
- `CREDENTIAL_PATTERNS` — 4 regex patterns for credential leak detection (API keys, AWS keys, OpenAI/Anthropic keys, GitHub PATs)

### 2. Implemented `test_ai_conversation()`

**File:** `src/boba/tools/vuln.py`

New function with signature:

```python
async def test_ai_conversation(
    http_client, url, session=None,
    conversations=None, tool_payloads=None, indirect_payloads=None,
    content_type="application/json",
    message_field="message", history_field="messages",
    scope_engine=None, context=None, hunt_id="",
    max_test_seconds=300,
) -> VulnTestResult
```

Key behaviors:

- **POST with JSON body**: sends `{message_field: "...", history_field: [...]}` instead of GET with query param
- **Multi-turn state**: accumulates conversation history across turns, sending the full history each time
- **Three attack modes** run sequentially (stops on first finding):
  1. Multi-turn conversations from `CONVERSATIONS`
  2. Tool abuse probes from `TOOL_ABUSE`
  3. Indirect injection from `INDIRECT`
- **Five detection types**: canary markers (CONFIRMED), system prompt leaks (LIKELY), tool abuse indicators (LIKELY), credential patterns (CONFIRMED), and WAF detection
- **Configurable field names**: `message_field` and `history_field` let the agent adapt to different API shapes
- **Scope enforcement**: out-of-scope URLs are skipped with descriptive message
- **Deadline enforcement**: `max_test_seconds` caps total wall-clock time across all modes
- **Evidence tagging**: evidence includes `instruction_override`, `system_prompt_leak`, `function_call`, and `credential_leak` types that the AI chain rules from Phase 2 match against

### 3. Updated CLI

**File:** `src/boba/cli/main.py`

Extended `boba test ai` with:

- `--mode` (`single` | `conversation`, default: `single`)
- `--message-field` (default: `message`)
- `--history-field` (default: `messages`)

When `--mode conversation`, the CLI calls `test_ai_conversation()` instead of `test_ai()`.

### 4. Backward compatibility

- `test_ai` is completely unchanged — still works for simple GET-parameter injection
- `test_ai_conversation` is a new function, not a replacement
- both share the same evidence types, chain rules, and `test_type="ai"`
- default CLI behavior (`--mode single`) is unchanged

## Tests Added

**File:** `tests/tools/test_vuln_v3.py`

11 new tests in `TestAIConversation`:

1. `test_conversation_canary_detected` — canary marker in multi-turn conversation triggers CONFIRMED injection
2. `test_conversation_history_accumulates` — verifies history grows correctly across turns (empty → [Turn 1] → [Turn 1, Turn 2])
3. `test_tool_abuse_detection` — tool abuse indicator in response produces `function_call` evidence
4. `test_indirect_injection_canary` — indirect injection triggers canary detection
5. `test_credential_leak_detection` — credential pattern in response produces `credential_leak` evidence
6. `test_custom_field_names` — verifies custom `message_field` and `history_field` are used in request body
7. `test_clean_response_not_flagged` — normal response across all modes produces no finding
8. `test_scope_enforcement` — out-of-scope URL is skipped
9. `test_waf_detected_conversation` — WAF blocking across conversation responses sets `waf_detected`
10. `test_system_prompt_leak_in_conversation` — leak indicators in conversation produce `system_prompt_leak` evidence
11. `test_posts_json_body` — verifies all requests use POST method

## Validation

Ran successfully during implementation:

- `python3 -m ruff check src/ tests/` — all checks passed
- `python3 -m ruff format --check` on changed files — all formatted
- `python3 -m pytest` — **699 tests passed**, 0 failures, 0 regressions

## Test Count

| Phase | Tests |
|---|---|
| Baseline (after Phase 5) | 688 |
| Phase 6 new tests | 11 |
| **Total** | **699** |

## Notes / Trade-offs

- `test_ai_conversation` shares `test_type="ai"` with `test_ai` so both feed into the same AI chain rules from Phase 2 and the same coverage tracking.
- The inner `_check_response()` closure is shared across all three attack modes to avoid code duplication for the five detection types.
- Credential pattern matching uses pre-compiled regexes for performance across many responses.
- The conversation history is a simple list of strings (user messages only). Response content is not added to history — this matches common chatbot API patterns where the server maintains its own conversation state.
- Tool abuse and indirect injection modes use single-turn POST (no history) because these attacks don't require conversation buildup.
- The `Content-Type` header defaults to `application/json` and is only set if not already present in the session headers, avoiding override conflicts with custom session configurations.
