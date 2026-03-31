# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is Boba

Boba is an agent-native bug bounty hunting framework. It wraps external security tools (subfinder, httpx, naabu, gau, waybackurls, whatweb, ffuf) behind a unified Python interface with scope enforcement, SQLite persistence, and a Typer CLI. The goal is 100% capability parity with a human bug bounty hunter.

## Commands

```bash
# Install (editable, with dev deps)
pip install -e ".[dev]"

# Run CLI
boba --help

# Tests
pytest                          # all tests
pytest tests/core/test_scope.py # single file
pytest -k "test_name"           # single test by name

# Lint
ruff check src/ tests/
ruff format --check src/ tests/
```

## Architecture

### Adapter pattern (src/boba/adapters/)

Every external tool has an adapter that extends `BaseAdapter`. The adapter lifecycle is:
`find_binary() → pre_filter_targets() → build_command() → run_subprocess() → parse_output() → post_filter_records()`

Key class attributes on each adapter:
- `TOOL_NAME`, `BINARY_NAMES` — tool identity and binary lookup
- `OUTPUT_FORMAT` — how to parse stdout (jsonl, json, plain lines, json array)
- `PRODUCES` — entity type: "subdomain", "host", "port", "url", "technology", "directory"
- `SCOPE_MODE` — when scope filtering happens: "pre", "post", or "both"

To add a new tool: create an adapter in `src/boba/adapters/`, implement `build_command`, `parse_record`, `extract_scope_target`, `install_hint`. Then compose it in a tool function under `src/boba/tools/`.

### Scope engine (src/boba/core/scope.py)

Default-deny model: exclusions always win, then inclusions are checked, unmatched targets are rejected. Supports domain wildcards (`*.example.com`), IP ranges (CIDR), and URL prefixes. Scope is defined per-hunt via YAML or programmatic `ScopeConfig`.

### Context / persistence (src/boba/core/context.py)

`HuntContext` is a SQLite-backed store (WAL mode, foreign keys on). All discovered data is upserted — duplicates merge sources and update timestamps. Tables: hunts, scope_rules, subdomains, hosts, ports, urls, technologies, directories, tool_runs.

### Tool layer (src/boba/tools/)

`recon.py` and `enum.py` are the composition layer: each function instantiates an adapter + scope engine, runs it, persists results via `HuntContext`, and logs the tool run. Some tools (like `urls`) run multiple adapters in parallel via `asyncio.gather`.

### CLI (src/boba/cli/main.py)

Typer app with subcommand groups: `hunt`, `recon`, `enum`, `context`. Every command accepts `--format json|table` and `--data-dir`. The `context` subcommands query persisted data without running tools.

## Conventions

- Python 3.11+, dataclasses for models (not Pydantic), ruff for linting (line-length 100)
- Async adapters (`async def run`), but CLI bridges with `asyncio.run()`
- Tests use `tmp_path` fixtures for isolated SQLite databases — see `tests/conftest.py` for shared fixtures (`tmp_db`, `context`, `manager`, `sample_hunt`, `scope_engine`)
- `pytest-asyncio` with `asyncio_mode = "auto"` — async test functions just work
