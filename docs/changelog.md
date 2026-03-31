# Changelog

- [0.2.0](#020--interaction-browser-http--vulnerability-testing) — Browser automation, HTTP client, session management, OOB listeners, 5 vuln test tools, Nuclei adapter, CLI extensions
- [0.1.0](#010--foundation-recon--enumeration) — Core framework, 8 tool adapters, scope engine, SQLite persistence, CLI

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
