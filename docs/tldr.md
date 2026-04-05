## Boba — TLDR

Boba is an **agent-native bug bounty hunting framework** built in Python. Its core thesis: LLM agents can already reason, write, and orchestrate — what they lack is structured access to the full security toolchain a human hunter uses. Boba closes that gap by wrapping external security tools (subfinder, httpx, naabu, gau, waybackurls, whatweb, ffuf, katana, Nuclei) behind a unified async adapter layer, enforcing scope boundaries at the framework level so agents physically cannot hit out-of-scope targets, and persisting all discovered data to a SQLite-backed "hunt context" that gives agents memory across tool invocations.

The architecture is layered: **adapters** normalize the wildly different CLI tools into a consistent lifecycle (`find_binary → build_command → run_subprocess → parse_output → post_filter`). **Tool functions** compose adapters with scope enforcement and persistence — e.g., `recon.urls()` runs gau + waybackurls in parallel, deduplicates, scope-checks, and upserts results. An **interaction layer** (Playwright browser, HTTP client with replay/fuzz/compare, session management, OOB listeners) replaces what a human does with Burp Suite. Eleven **vulnerability testing tools** (IDOR, SSRF, XSS, SQLi, auth bypass, CSRF, race conditions, open redirect, mass assignment, password reset, AI prompt injection) automate manual exploitation patterns. An **analysis layer** handles coverage tracking, finding deduplication, CVSS 3.1 scoring, vulnerability chaining (e.g., redirect + SSRF → P1), and attack path prioritization. A **reporting layer** drafts structured reports, formats them for HackerOne/Bugcrowd, and packages PoC evidence. A **Typer CLI** with `--format json` makes everything agent-consumable.

The project is at **v0.4.2** with V1 (recon/enumeration), V2 (browser + HTTP interaction + vuln testing), and V3 (analysis, chaining, severity scoring, report generation) complete and heavily hardened across 24+ quality passes (592 tests). Next up is V4 (recon breadth — parameter discovery, API surface mapping, secret scanning, GraphQL introspection, ASN enumeration, cloud bucket discovery).

**Key design choices:**
- **Default-deny scope engine** — exclusions always win, wildcards/CIDR/URL prefixes supported
- **Dataclasses over Pydantic**, async everywhere, `pytest-asyncio` with auto mode
- **Composable primitives over pipelines** — agents assemble different tool combinations per hunt strategy
- **Progressive autonomy** — human controls how much the agent can do unsupervised
- **End goal:** 100% capability parity with a top-100 HackerOne researcher
