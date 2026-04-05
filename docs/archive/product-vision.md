# Boba: Product Vision

## What is Boba?

Boba is an **agent-native bug bounty hunting framework** — a complete suite of tools that gives AI agents (Claude Code, Hermes Agent, or any LLM-based agent) every capability a professional human bug bounty hunter has. No gaps. No "this part requires a human."

After all implementation phases, an agent equipped with Boba should be able to hunt bugs with the same effectiveness as a top-100 HackerOne researcher — selecting programs, mapping attack surfaces, navigating web applications, testing for vulnerabilities, chaining findings, and submitting well-written reports — with minimal human guidance.

## The Core Thesis

A professional bug bounty hunter uses:
1. **Recon tools** (subfinder, amass, httpx) to discover assets
2. **A web browser** to navigate applications, understand flows, maintain sessions
3. **A proxy/interceptor** (Burp Suite) to inspect, modify, and replay HTTP traffic
4. **Scanners** (Nuclei, SQLmap) to detect known vulnerability patterns
5. **Manual reasoning** to find business logic bugs, chain vulnerabilities, and assess impact
6. **Report writing** to communicate findings with clear reproduction steps and PoC

LLM agents can already reason, write reports, and orchestrate CLI tools. What they lack is **structured access** to the full toolchain — especially the browser and HTTP interaction layer that humans use for manual testing. Boba closes every gap.

## Design Principles

### 1. Full Capability Parity
Every technique a human hunter uses maps to an agent-operable Boba tool. If a human can do it with Burp Suite and a browser, an agent can do it with Boba. The test is simple: "is there anything a human could do in this hunt phase that the agent cannot?" If yes, that's a gap to close.

### 2. Composable Primitives Over Monolithic Pipelines
Small, focused tools that agents compose into workflows — not rigid pipelines. An agent hunting for IDOR bugs uses a different composition than one hunting for SSRF, and it adapts mid-hunt based on what it finds.

### 3. Stateful Context, Not Stateless Commands
Boba maintains a **hunt context** — discovered assets, tested endpoints, HTTP history, findings, program scope — that persists across tool invocations. The agent always knows what it has already tried.

### 4. Progressive Autonomy
Start with human-in-the-loop for every action. As trust builds, the operator widens the agent's autonomy envelope: auto-run passive recon, auto-test discovered endpoints, auto-draft reports. The human controls the dial.

### 5. Defensive by Default
Scope boundaries are enforced at the framework level. The agent physically cannot test out-of-scope assets. Rate limiting, rules of engagement, and ethical constraints are built in — not left to the agent's judgment.

## Human-to-Agent Capability Map

This is the definitive reference. Every row must have a Boba equivalent — no gaps allowed.

### Reconnaissance & Enumeration

| Human Capability | Human Tool | Boba Equivalent |
|---|---|---|
| Subdomain discovery | subfinder, amass, crt.sh | `recon.subdomains` — wraps multiple tools, deduplicates, persists to context |
| Live host detection | httpx | `recon.hosts` — check which subdomains are alive, capture status/tech/title |
| Port scanning | naabu, nmap | `recon.ports` — fast port scan with service fingerprinting |
| Historical URL mining | gau, waybackurls | `recon.urls` — fetch archived URLs, find forgotten endpoints |
| Technology fingerprinting | whatweb, wappalyzer | `recon.tech` — identify tech stacks per host |
| Directory/endpoint fuzzing | ffuf, dirsearch | `enum.directories` — fuzz with wordlists, capture responses |
| Parameter discovery | ffuf, Arjun | `enum.parameters` — discover hidden query/body parameters |
| API surface mapping | Kiterunner, manual | `enum.api` — discover API endpoints, methods, schemas |
| JavaScript analysis | LinkFinder, manual | `enum.js` — download and parse JS for endpoints, secrets, config |
| GraphQL introspection | Manual, Clairvoyance | `enum.graphql` — test introspection, enumerate schema |
| Cloud bucket discovery | S3Scanner | `recon.cloud` — check for misconfigured storage buckets |
| GitHub secret scanning | trufflehog, git-dorks | `recon.secrets` — scan repos for leaked credentials |
| ASN/IP range enumeration | amass, bgp.tools | `recon.asn` — find all IP ranges owned by target |
| Continuous monitoring | cron + diffing | `monitor.assets` — watch for new subdomains, ports, changes over time |

### Web Interaction & Traffic

| Human Capability | Human Tool | Boba Equivalent |
|---|---|---|
| Browse a web application | Chrome/Firefox | `browser.navigate` — headless Playwright browser, navigate pages, render JS |
| Intercept HTTP traffic | Burp Proxy | `browser.intercept` — capture all requests/responses during navigation |
| Send crafted HTTP requests | Burp Repeater, curl | `http.request` — send arbitrary requests with full header/body control |
| Replay and modify requests | Burp Repeater | `http.replay` — take a captured request, modify it, resend |
| Compare responses | Burp Comparer | `http.compare` — diff two responses (headers, body, status) |
| Fuzz request parameters | Burp Intruder | `http.fuzz` — systematic parameter fuzzing with payloads |
| Maintain authenticated session | Browser cookies, Burp | `session.create` — login to target, persist cookies/tokens across requests |
| Handle OAuth/SSO flows | Browser | `session.oauth` — automated OAuth flow handling |
| Take page screenshots | Browser | `browser.screenshot` — capture visual state for evidence/PoC |
| Extract page content | Browser DevTools | `browser.extract` — get DOM, text, forms, links from rendered page |
| Detect out-of-band interactions | Burp Collaborator, Interactsh | `oob.listen` — deploy OOB listener, check for callbacks |

### Vulnerability Testing

| Human Capability | Human Tool | Boba Equivalent |
|---|---|---|
| IDOR / broken access control | Manual (two accounts) | `test.idor` — access resource as User A, replay as User B, compare |
| SSRF detection | Manual + OOB listener | `test.ssrf` — inject internal URLs/OOB callbacks into URL parameters |
| SQL injection | SQLmap + manual | `test.sqli` — automated detection + manual payload crafting |
| XSS (stored/reflected) | Manual + Burp | `test.xss` — inject payloads, check reflection in response/DOM |
| Authentication bypass | Manual | `test.auth` — JWT manipulation, algorithm confusion, token analysis |
| Authorization / privilege escalation | Manual (role comparison) | `test.authz` — access admin endpoints as regular user, compare roles |
| CSRF | Manual | `test.csrf` — check token presence, test cross-origin submission |
| Business logic bugs | Manual (creative reasoning) | `test.logic` — agent reasons about workflows, uses http/browser tools to probe |
| Race conditions | Manual (concurrent requests) | `test.race` — send concurrent identical requests, check for double-processing |
| Password reset flaws | Manual | `test.reset` — test token predictability, host header injection |
| Mass assignment | Manual | `test.mass_assign` — send extra JSON fields, check if they persist |
| Open redirect | Manual | `test.redirect` — test redirect parameters with external URLs |
| Prompt injection / AI bugs | Manual + Augustus | `test.ai` — systematic adversarial testing of LLM features |
| Known CVE scanning | Nuclei | `test.nuclei` — template-based scanning with custom + community templates |
| Template-based custom checks | Custom Nuclei YAML | `test.nuclei_custom` — manage and run proprietary Nuclei templates |

### Analysis & Intelligence

| Human Capability | Human Tool | Boba Equivalent |
|---|---|---|
| Chain vulnerabilities | Mental model | `analyze.chain` — correlate findings, suggest chains (e.g., redirect + SSRF → P1) |
| Assess severity / CVSS | Experience + framework | `analyze.severity` — calculate CVSS, map to program's payout tiers |
| Deduplicate findings | Platform search | `analyze.dedupe` — check if finding overlaps with already-reported issues |
| Prioritize attack paths | Experience | `analyze.prioritize` — rank endpoints by likelihood of vulnerability |
| Review HTTP history | Burp history tab | `context.http_history` — query all captured requests/responses |
| Track what's been tested | Notes / spreadsheet | `context.coverage` — show which assets/endpoints have been tested and how |

### Reporting & Platform Interaction

| Human Capability | Human Tool | Boba Equivalent |
|---|---|---|
| Write vulnerability report | Manual | `report.draft` — generate structured report from finding + evidence |
| Format for platform | Manual | `report.format` — format for HackerOne, Bugcrowd, etc. |
| Create PoC artifacts | Screenshots, video, HTTP dumps | `report.poc` — compile evidence (screenshots, request/response pairs) |
| Submit report | Platform web UI | `report.submit` — submit via platform API (HackerOne, Bugcrowd) |
| Respond to triager | Platform web UI | `report.respond` — read and reply to triager comments |
| Check report status | Platform web UI | `report.status` — query report state, payout status |

### Program Selection & Strategy

| Human Capability | Human Tool | Boba Equivalent |
|---|---|---|
| Evaluate programs | Platform browsing | `program.search` — query programs by scope, payout, tech stack, freshness |
| Check competition level | Hall of fame / activity | `program.analyze` — assess competition, response time, payout history |
| Read program policy | Platform | `program.policy` — fetch and parse scope, rules of engagement, exclusions |
| Track multiple programs | Spreadsheet / notes | `program.portfolio` — manage active programs, track ROI per program |

### Infrastructure

| Human Capability | Human Tool | Boba Equivalent |
|---|---|---|
| Manage VPS fleet | SSH + cloud console | `infra.deploy` — provision and manage scanning VPS instances |
| Distribute scans | Axiom / Fleex | `infra.distribute` — parallelize scans across multiple nodes |
| Schedule jobs | cron | `infra.schedule` — schedule recurring recon/monitoring jobs |
| Alert on new assets | Slack/Telegram bots | `infra.alert` — notify on new subdomains, open ports, tech changes |

## Architecture: Library-First, MCP-Ready

Boba is built as a **Python library with a CLI** — clean, typed interfaces that any agent can call directly. MCP server exposure is added later as a thin wrapper, not a core dependency.

Every tool is a **Python function with typed inputs and structured outputs** (Pydantic models). This makes it trivially MCP-compatible: each function maps 1:1 to an MCP tool definition.

```
┌──────────────────────────────────────────────────────────────────┐
│                     FUTURE: Exposure Layers                       │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐    │
│  │MCP Server│  │   CLI    │  │ REST API │  │  Agent SDK   │    │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └──────┬───────┘    │
│       └──────────────┴─────────────┴───────────────┘            │
└──────────────────────────┬──────────────────────────────────────┘
                           │ calls
┌──────────────────────────▼──────────────────────────────────────┐
│                     Boba Core Library                            │
│                                                                  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐           │
│  │  Scope   │ │  Recon   │ │   Test   │ │  Report  │  ...      │
│  │  Engine  │ │  Tools   │ │  Tools   │ │  Tools   │           │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘           │
│       └─────────────┴────────────┴─────────────┘                │
│                                                                  │
│  ┌──────────────────────────────────────────────────────┐       │
│  │              Hunt Context (SQLite)                    │       │
│  │  hunts │ assets │ findings │ http_history │ tool_runs │       │
│  └──────────────────────────────────────────────────────┘       │
├──────────────────────────────────────────────────────────────────┤
│                     Adapter Layer                                 │
│                                                                  │
│  ┌─────────────────────────────┐ ┌───────────────────────────┐  │
│  │   CLI Tool Adapters         │ │  Browser/HTTP Adapter     │  │
│  │   (subprocess wrappers)     │ │  (Playwright)             │  │
│  │                             │ │                           │  │
│  │  subfinder, httpx, nuclei,  │ │  Navigate, intercept,     │  │
│  │  ffuf, nmap, katana,        │ │  request, replay, fuzz,   │  │
│  │  sqlmap, gau, whatweb...    │ │  screenshot, session mgmt │  │
│  └─────────────────────────────┘ └───────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

### The Two Adapter Types

**CLI Tool Adapters** — subprocess wrappers for existing security tools. Each adapter: discovers the binary, builds arguments, runs via async subprocess, parses output (preferring `-json` mode), returns structured `ToolResult`.

**Browser/HTTP Adapter** — Playwright-based. This single adapter replaces what a human does with Burp Suite + a browser:
- **Navigate** web applications (headless browser with full JS rendering)
- **Intercept** all HTTP traffic during navigation (Burp Proxy equivalent)
- **Send** arbitrary crafted HTTP requests (Burp Repeater equivalent)
- **Fuzz** parameters systematically (Burp Intruder equivalent)
- **Manage sessions** — login, persist cookies/tokens, handle OAuth flows
- **Screenshot** pages for evidence
- **Extract** DOM content, forms, links from rendered pages

This is the critical piece that gives agents parity with humans for manual testing.

## Implementation Phases

### V1 — Foundation: Recon & Enumeration
The agent can discover and map attack surfaces.

**Delivers:**
- Hunt management (create, configure, query status)
- Scope engine (define and enforce boundaries)
- Hunt context (SQLite persistence for all data)
- CLI tool adapters: subfinder, httpx, naabu, gau, waybackurls, whatweb, katana, ffuf
- High-level tools: `recon.*`, `enum.directories`
- CLI with `--format json` for agent consumption

**Agent can:** Create a hunt, define scope, run full recon pipeline, enumerate endpoints, query what's been discovered — all with structured output.

### V2 — Interaction: Browser, HTTP, and Vulnerability Testing
The agent can interact with web applications and test for vulnerabilities.

**Delivers:**
- Playwright browser adapter (navigate, intercept, screenshot, extract)
- HTTP request tool (send, replay, compare, fuzz)
- Session management (login, cookie persistence, OAuth)
- OOB listener integration (Interactsh)
- Vuln testing tools: `test.idor`, `test.ssrf`, `test.auth`, `test.sqli`, `test.xss`
- Nuclei adapter with custom template support
- HTTP history persistence in hunt context

**Agent can:** Log into a target application, navigate it, intercept traffic, send crafted requests, test for IDOR/SSRF/auth bypass, detect blind vulns via OOB — the full manual testing workflow.

### V3 — Intelligence: Analysis, Chaining, and Reporting
The agent can assess what it found and communicate it.

**Delivers:**
- Finding analysis tools: `analyze.chain`, `analyze.severity`, `analyze.dedupe`
- Coverage tracking: what's been tested, what hasn't
- Report generation: `report.draft`, `report.format`, `report.poc`
- Platform API integration: `report.submit`, `report.status` (HackerOne, Bugcrowd)
- Advanced vuln tools: `test.logic`, `test.race`, `test.ai`

**Agent can:** Chain a P4 redirect + P4 SSRF into a P1, generate a platform-ready report with PoC artifacts, submit it via API, and respond to triager questions.

### V4 — Autonomy: Full Hunt Loop
The agent can run complete hunts with minimal human guidance.

**Delivers:**
- Program selection and analysis: `program.search`, `program.analyze`, `program.policy`
- Portfolio management across multiple programs
- Continuous monitoring and alerting: `monitor.assets`, `infra.alert`
- Infrastructure management: `infra.deploy`, `infra.distribute`, `infra.schedule`
- Configurable autonomy levels with human checkpoints
- Cross-hunt learning: templates and patterns from past hunts applied to new targets

**Agent can:** Select promising programs, run continuous recon, hunt autonomously with human review at configurable checkpoints, manage its own infrastructure, and improve over time.

## Open Questions

- **Credential management**: Secure storage for target app credentials. Vault integration? Encrypted local store?
- **Rate limiting**: Adaptive rate limiting per target to avoid WAF triggers and IP bans. Need per-host throttling in the adapter layer.
- **Legal boundaries**: Encoding program-specific rules of engagement (no DoS, no social engineering, etc.) as enforceable scope constraints.
- **Platform API access**: HackerOne and Bugcrowd API access for report submission — requires researcher accounts and API keys.
- **Cost model**: VPS fleet + Burp license + API costs vs. bounty income. What's the break-even?
- **Browser fingerprinting**: Headless browsers are detectable. May need stealth plugins or real browser profiles.
