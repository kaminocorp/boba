## Boba — TLDR

Boba is an **agent-native bug bounty hunting framework** built in Python. Its core thesis: LLM agents can already reason, write, and orchestrate — what they lack is structured access to the full security toolchain a human hunter uses. Boba closes that gap by wrapping external security tools (subfinder, httpx, naabu, gau, waybackurls, whatweb, ffuf, katana, Nuclei) behind a unified async adapter layer, enforcing scope boundaries at the framework level so agents physically cannot hit out-of-scope targets, and persisting all discovered data to a SQLite-backed "hunt context" that gives agents memory across tool invocations.

The architecture is layered: **adapters** normalize the wildly different CLI tools into a consistent lifecycle (`find_binary → build_command → run_subprocess → parse_output → post_filter`). **Tool functions** compose adapters with scope enforcement and persistence — e.g., `recon.urls()` runs gau + waybackurls in parallel, deduplicates, scope-checks, and upserts results. An **interaction layer** (Playwright browser, HTTP client with replay/fuzz/compare, session management, OOB listeners) replaces what a human does with Burp Suite. Twelve **vulnerability testing tools** (IDOR, SSRF, XSS, SQLi, auth bypass, CSRF, race conditions, open redirect, mass assignment, password reset, AI prompt injection, multi-turn AI conversation) automate manual exploitation patterns. An **analysis layer** handles coverage tracking, finding deduplication, CVSS 3.1 scoring, vulnerability chaining (e.g., redirect + SSRF → P1), and attack path prioritization. A **reporting layer** drafts structured reports, formats them for HackerOne/Bugcrowd, and packages PoC evidence. Two access modes: a **Typer CLI** with `--format json` for shell-based agents, and an **MCP server** (`boba-mcp`) exposing all 65 tools as native MCP tool calls for MCP-compatible agents (Claude Code, Claude Desktop, Hermes).

The project is at **v0.7.0** with V1–V4 (recon, interaction, vuln testing, analysis, reporting, enrichment) and the MCP server complete across 839 tests.

**Key design choices:**
- **Default-deny scope engine** — exclusions always win, wildcards/CIDR/URL prefixes supported
- **Dataclasses over Pydantic**, async everywhere, `pytest-asyncio` with auto mode
- **Composable primitives over pipelines** — agents assemble different tool combinations per hunt strategy
- **Progressive autonomy** — human controls how much the agent can do unsupervised
- **End goal:** 100% capability parity with a top-100 HackerOne researcher
