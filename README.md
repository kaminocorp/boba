<p align="center">
  <img src="assets/logo.png" alt="boba" width="200" />
</p>

<h1 align="center">boba</h1>

<p align="center">
  <strong>Agent-native bug bounty hunting framework.</strong><br>
  Everything an LLM agent needs to go from target scope to submitted vulnerability report.
</p>

<p align="center">
  <a href="#quickstart">Quickstart</a> &middot;
  <a href="#what-it-does">What It Does</a> &middot;
  <a href="#architecture">Architecture</a> &middot;
  <a href="docs/product-vision.md">Vision</a> &middot;
  <a href="docs/changelog.md">Changelog</a>
</p>

---

Bug bounty hunting is a closed-loop process: discover attack surface, interact with the target, test for vulnerabilities, chain findings, report. Human hunters do this with a browser, Burp Suite, and a dozen CLI tools held together by bash scripts and muscle memory.

LLM agents can reason and write — but they have no way to hold an authenticated session, replay a modified HTTP request, or diff two responses to confirm an IDOR. Boba gives them that. Every phase of the hunting lifecycle is exposed as a typed Python function with structured I/O: subprocess adapters normalize 9+ security tools into a uniform interface, a Playwright-based interaction layer replaces Burp Suite, and a SQLite-backed hunt context gives the agent persistent state across the entire engagement. Scope enforcement is framework-level — the agent cannot touch what it shouldn't.

## Quickstart

```bash
pip install -e ".[dev]"
boba --help
```

```bash
# Create a hunt, define scope, run recon
boba hunt create --name acme --domains "*.acme.com"
boba recon subdomains --hunt-id <id> --domains acme.com
boba recon hosts --hunt-id <id>
boba recon urls --hunt-id <id>

# Test for vulnerabilities
boba test idor --hunt-id <id> --url https://app.acme.com/api/user/42
boba test ssrf --hunt-id <id> --url https://app.acme.com/fetch?url=
boba test xss --hunt-id <id> --url "https://app.acme.com/search?q="

# Query what you've found
boba context stats --hunt-id <id> --format json
```

Every command supports `--format json` for agent consumption.

## What It Does

**Recon & Enumeration** — Subdomain discovery, live host detection, port scanning, historical URL mining, tech fingerprinting, directory fuzzing. 9 adapters wrapping subfinder, httpx, naabu, gau, waybackurls, whatweb, katana, ffuf, nuclei.

**Web Interaction** — Headless Playwright browser with real-time traffic interception. HTTP client with `request()`, `replay()`, `compare()`, `fuzz()` — four Burp Intruder attack types. Named auth sessions (bearer, basic, cookie, form login). OOB callback listeners via Interactsh for blind vuln detection.

**Vulnerability Testing** — Five detection engines: IDOR (multi-account response diffing), SSRF (response content analysis + OOB callbacks), XSS (reflected + DOM-based via browser), SQLi (error/boolean/time-based with multi-DBMS payloads), auth bypass (JWT `alg:none`, claim escalation, endpoint ACL testing). Nuclei adapter for template-based scanning with custom YAML support.

**Scope Enforcement** — Default-deny model. Exclusions always win over inclusions. Domain wildcards, CIDR ranges, URL prefixes. Enforced at the adapter layer — the agent cannot touch out-of-scope targets regardless of what it tries to pass downstream.

**Persistence** — SQLite (WAL mode, FK constraints) backing every entity: subdomains, hosts, ports, URLs, technologies, directories, HTTP exchanges, findings, tool runs. Upserts deduplicate via `json_each()` merges. Full hunt state survives across invocations — the agent never loses context.

## Architecture

```
CLI / MCP Server / Agent SDK          <- exposure layer
        │
   Tool Functions                     <- composition (recon.py, vuln.py)
        │
   Adapter Layer                      <- normalize external tools
   ├── CLI Adapters (subprocess)         subfinder, httpx, nuclei, ffuf...
   └── Interaction Adapters              Playwright browser, HTTP client
        │
   Core                               <- scope engine, hunt context (SQLite), models
```

Every adapter follows a 6-phase lifecycle: `find_binary → pre_filter → build_command → run_subprocess → parse_output → post_filter`. This normalizes tools with wildly different I/O (JSON lines, JSON arrays, plain text, file-based output, stdin piping) into a uniform `ToolResult`. Tool functions compose one or more adapters with scope checking and context persistence. The CLI bridges async with `asyncio.run()`.

## External Tools

Boba wraps these — install whichever you need:

| Tool | Purpose | Install |
|---|---|---|
| [subfinder](https://github.com/projectdiscovery/subfinder) | Subdomain discovery | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| [httpx](https://github.com/projectdiscovery/httpx) | Live host detection | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| [naabu](https://github.com/projectdiscovery/naabu) | Port scanning | `go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` |
| [gau](https://github.com/lc/gau) | Historical URLs | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| [waybackurls](https://github.com/tomnomnom/waybackurls) | Wayback Machine URLs | `go install github.com/tomnomnom/waybackurls@latest` |
| [whatweb](https://github.com/urbanadventurer/WhatWeb) | Tech fingerprinting | `gem install whatweb` |
| [katana](https://github.com/projectdiscovery/katana) | Web crawling | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| [ffuf](https://github.com/ffuf/ffuf) | Directory fuzzing | `go install github.com/ffuf/ffuf/v2@latest` |
| [nuclei](https://github.com/projectdiscovery/nuclei) | Template scanning | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |

## Development

```bash
pip install -e ".[dev]"

pytest                          # 206 tests
ruff check src/ tests/          # lint
ruff format --check src/ tests/ # format check
```

Python 3.11+. Fully async. Dataclasses (not Pydantic). Ruff for lint + format (line-length 100).

## Roadmap

- [x] **V1** — Recon & enumeration (8 adapters, scope engine, persistence, CLI)
- [x] **V2** — Browser, HTTP interaction, vulnerability testing (5 vuln tools, Nuclei, sessions, OOB)
- [ ] **V3** — Analysis, vuln chaining, report generation, platform API submission
- [ ] **V4** — Autonomous hunt loops, program selection, continuous monitoring, infrastructure management

## License

Apache 2.0 — see [LICENSE](LICENSE).
