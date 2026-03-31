# Changelog

- [0.1.0](#010--foundation-recon--enumeration) — Core framework, 8 tool adapters, scope engine, SQLite persistence, CLI

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
