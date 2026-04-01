## Boba — TLDR

Boba is an **agent-native bug bounty hunting framework** built in Python. Its core thesis: LLM agents can already reason, write, and orchestrate — what they lack is structured access to the full security toolchain a human hunter uses. Boba closes that gap by wrapping external security tools (subfinder, httpx, naabu, gau, waybackurls, whatweb, ffuf, Nuclei, etc.) behind a unified async adapter layer, enforcing scope boundaries at the framework level so agents physically cannot hit out-of-scope targets, and persisting all discovered data to a SQLite-backed "hunt context" that gives agents memory across tool invocations.

The architecture is layered: **adapters** normalize the wildly different CLI tools into a consistent lifecycle (`find_binary → build_command → run_subprocess → parse_output → post_filter`). **Tool functions** compose adapters with scope enforcement and persistence — e.g., `recon.urls()` runs gau + waybackurls in parallel, deduplicates, scope-checks, and upserts results. An **interaction layer** (Playwright browser, HTTP client with replay/fuzz/compare, session management, OOB listeners) replaces what a human does with Burp Suite. Five **vulnerability testing tools** (IDOR, SSRF, XSS, SQLi, auth bypass) automate manual exploitation patterns. A **Typer CLI** with `--format json` makes everything agent-consumable.

The project is currently at **v0.2.11** with V1 (recon/enumeration) and V2 (browser + HTTP interaction + vuln testing) complete and heavily hardened across 11 quality passes (206 tests). Next up is V3 (analysis, vuln chaining, report generation, platform API submission) and eventually V4 (fully autonomous hunt loops with program selection and continuous monitoring).

**Key design choices:**
- **Default-deny scope engine** — exclusions always win, wildcards/CIDR/URL prefixes supported
- **Dataclasses over Pydantic**, async everywhere, `pytest-asyncio` with auto mode
- **Composable primitives over pipelines** — agents assemble different tool combinations per hunt strategy
- **Progressive autonomy** — human controls how much the agent can do unsupervised
- **End goal:** 100% capability parity with a top-100 HackerOne researcher
