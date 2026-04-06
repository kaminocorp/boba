# Boba: Agent Orientation Guide

You are about to conduct a bug bounty hunt using **Boba**, an agent-native security toolkit. This guide tells you everything you need to operate it. You don't need to read source code — just follow the workflow, use the commands, and reason about what you find.

---

## What Boba Is

Boba is a CLI toolkit that wraps security tools behind a unified interface with:
- **Scope enforcement** — you physically cannot test out-of-scope targets
- **SQLite persistence** — every discovery, request, and finding is stored automatically
- **Structured output** — `--format json` on every command for machine-readable results

All commands follow the pattern: `boba <group> <command> <hunt-id> [options]`

Add `-f json` to any command for JSON output (default is human-readable tables).

---

## Required External Tools

Boba wraps external binaries. Install the ones you need before running commands that use them. If a tool is missing, Boba will tell you exactly what to install.

| Tool | Install | Used by |
|---|---|---|
| subfinder | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` | `recon subdomains` |
| httpx | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` | `recon hosts` |
| naabu | `go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` | `recon ports` |
| gau | `go install -v github.com/lc/gau/v2/cmd/gau@latest` | `recon urls` |
| waybackurls | `go install -v github.com/tomnomnom/waybackurls@latest` | `recon urls` |
| whatweb | `gem install whatweb` or `apt install whatweb` | `recon tech` |
| ffuf | `go install -v github.com/ffuf/ffuf/v2@latest` | `enum directories` |
| katana | `go install -v github.com/projectdiscovery/katana/cmd/katana@latest` | `enum crawl` |
| nuclei | `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` | `scan nuclei` |

Browser-based commands (`browser`, `http`, `session`, `test`) use Python's Playwright — no external binary needed beyond `playwright install chromium`.

---

## The Hunt Workflow

Every engagement follows this pipeline. Each phase feeds the next.

```
1. CREATE HUNT     Set up scope boundaries
       |
2. RECON           Discover subdomains, hosts, ports, URLs, tech stacks
       |
3. ENUMERATE       Fuzz directories, crawl pages, extract DOM
       |
4. INTERACT        Log in, browse, send requests, replay traffic
       |
5. TEST            Run vuln tests against discovered endpoints
       |
6. ANALYZE         Deduplicate, score severity, detect chains, find coverage gaps
       |
7. REPORT          Draft report, format for platform, package PoC evidence
```

---

## Phase 1: Create a Hunt

A hunt is a scoped engagement. All data is isolated per-hunt.

```bash
# Create a hunt with a scope YAML file
boba hunt create --name "acme-corp" --scope scope.yaml

# Or create and add scope later
boba hunt create --name "acme-corp"
```

**Scope YAML format:**
```yaml
rules:
  - pattern: "*.acme.com"
    type: domain
    action: include
  - pattern: "internal.acme.com"
    type: domain
    action: exclude
  - pattern: "10.0.0.0/8"
    type: ip_range
    action: exclude
  - pattern: "https://acme.com/api/"
    type: url_prefix
    action: include
```

Rules are **default-deny**: anything not explicitly included is out of scope. Exclusions always win over inclusions.

**Save your hunt ID** — you'll pass it to every subsequent command.

```bash
# Check hunt status and stats at any time
boba hunt status <hunt-id>
boba hunt list
```

Other lifecycle commands: `boba hunt pause`, `boba hunt resume`, `boba hunt close`.

---

## Phase 2: Reconnaissance

Discover the attack surface. Each command persists results to the hunt's database automatically.

### Subdomain Discovery
```bash
boba recon subdomains <hunt-id> --domain acme.com
boba recon subdomains <hunt-id> --domain acme.com --domain acme.io  # multiple domains
```
Uses subfinder. Results go into the `subdomains` table.

### Live Host Detection
```bash
boba recon hosts <hunt-id>                           # tests all discovered subdomains
boba recon hosts <hunt-id> --targets sub1.acme.com,sub2.acme.com  # specific targets
```
Uses httpx. Captures status codes, page titles, web servers, technologies, TLS info. Results go into the `hosts` table.

### Port Scanning
```bash
boba recon ports <hunt-id>                           # scans all live hosts
boba recon ports <hunt-id> --targets 10.0.0.1        # specific host
boba recon ports <hunt-id> --range 1-10000           # custom port range
```
Uses naabu. Results go into the `ports` table.

### Historical URL Mining
```bash
boba recon urls <hunt-id> --domain acme.com
```
Runs **both** gau and waybackurls in parallel, deduplicates results. Finds forgotten endpoints, old API versions, debug paths. Results go into the `urls` table.

### Technology Fingerprinting
```bash
boba recon tech <hunt-id>                            # fingerprints all live hosts
boba recon tech <hunt-id> --targets https://app.acme.com
```
Uses whatweb. Identifies frameworks, CMS, languages, server versions. Results go into the `technologies` table.

### Recommended recon sequence
```bash
HUNT=<your-hunt-id>
boba recon subdomains $HUNT --domain acme.com
boba recon hosts $HUNT
boba recon ports $HUNT
boba recon urls $HUNT --domain acme.com
boba recon tech $HUNT
```

---

## Phase 3: Enumeration

Actively probe discovered hosts for paths and content.

### Directory Fuzzing
```bash
boba enum directories $HUNT --url https://app.acme.com
boba enum directories $HUNT --url https://app.acme.com --match-codes 200,301,302,403
boba enum directories $HUNT --url https://app.acme.com --wordlist /path/to/wordlist.txt
boba enum directories $HUNT --url https://app.acme.com --extensions php,asp,jsp
```
Uses ffuf. Auto-appends `/FUZZ` to the URL. Results go into the `directories` table.

### Web Crawling
```bash
boba enum crawl $HUNT                                # crawls all live hosts
boba enum crawl $HUNT --targets https://app.acme.com
boba enum crawl $HUNT --depth 5                      # deeper crawl (default: 3)
```
Uses katana with JS rendering enabled (`-js-crawl`). Extracts links, endpoints, forms. Results go into the `urls` table.

---

## Phase 4: Interaction

Browse the target, set up sessions, send crafted requests. This is where you go from passive discovery to active testing.

### Session Management

Set up named sessions for authenticated testing. You need sessions for IDOR testing (two different users), CSRF testing, and any auth-dependent endpoint.

```bash
# Create a session
boba session create $HUNT --name user_a --target https://app.acme.com

# Set a bearer token
boba session login-token $HUNT user_a --token "eyJhbGciOiJI..."

# List sessions
boba session list $HUNT

# Delete a session
boba session delete $HUNT user_a
```

**Auth methods supported:** `form`, `cookie`, `bearer`, `basic`, `header`. Set with `--method` on create.

For form-based login, use the Python API directly (browser-based login fills form fields and submits).

### Browser Navigation

Navigate pages in a headless Chromium browser. All HTTP traffic is automatically captured.

```bash
# Navigate and capture traffic
boba browser navigate $HUNT --url https://app.acme.com/dashboard

# Take a screenshot (for PoC evidence)
boba browser screenshot $HUNT --url https://app.acme.com/admin --path evidence/admin.png

# Extract DOM structure (forms, links, scripts, comments, inputs)
boba browser extract $HUNT --url https://app.acme.com/settings -f json
```

The `extract` command is especially useful — it returns all forms with their fields, all links, script sources, HTML comments (which often leak internal info), and meta tags.

### HTTP Requests (Burp Repeater equivalent)

Send crafted requests with full control over method, headers, and body.

```bash
# Send a request
boba http request $HUNT --url https://app.acme.com/api/user/42 --method GET

# Add custom headers
boba http request $HUNT --url https://app.acme.com/api/admin \
  --method POST \
  --header "Authorization:Bearer eyJ..." \
  --header "Content-Type:application/json" \
  --body '{"action":"delete","user_id":1}'

# Replay a previous request with modifications
boba http replay $HUNT --request-id 42 --modify-header "Cookie:session=attacker_token"

# Compare two responses (IDOR detection pattern)
boba http compare $HUNT --id-a 42 --id-b 43
```

Every request and response is saved to `http_history`. Query it anytime:
```bash
boba context http-history $HUNT --host app.acme.com --method POST -f json
```

---

## Phase 5: Vulnerability Testing

Boba has 11 automated vulnerability tests. Each returns a structured result with `vulnerable` (bool), `confidence` (confirmed/likely/possible), and `evidence` (request IDs, payloads, indicators).

### IDOR (Insecure Direct Object Reference)
```bash
boba test idor $HUNT --endpoint https://app.acme.com/api/user/42 \
  --session-a user_a --session-b user_b --method GET
```
Compares responses between two sessions. If user B can access user A's data, that's an IDOR.

### SSRF (Server-Side Request Forgery)
```bash
boba test ssrf $HUNT --url https://app.acme.com/proxy --param url
boba test ssrf $HUNT --url https://app.acme.com/fetch --param target --method POST
```
Injects internal URLs (169.254.169.254, localhost, etc.) and checks for cloud metadata, internal content, or OOB callbacks.

### SQL Injection
```bash
boba test sqli $HUNT --url https://app.acme.com/search --param q
boba test sqli $HUNT --url https://app.acme.com/user --param id --method GET
```
Tests error-based (11 payloads, 16 error signatures), boolean-based (true/false pairs with length analysis), and time-based (SLEEP across MySQL, PostgreSQL, MSSQL, SQLite).

### XSS (Cross-Site Scripting)
```bash
boba test xss $HUNT --url https://app.acme.com/search --param q
boba test xss $HUNT --url https://app.acme.com/comment --param text --method POST
```
Tests reflected XSS (payload reflection), DOM-based XSS (browser canary), and partial reflection. Uses polyglots, event handlers, and encoding bypasses.

### Authentication / Authorization
```bash
boba test auth $HUNT --endpoint https://app.acme.com/admin/dashboard
boba test auth $HUNT --endpoint https://app.acme.com/api/users --jwt "eyJ..."
```
Tests unauthenticated access to protected endpoints, JWT `alg:none` bypass, JWT claim escalation (role/admin/permissions), and privilege escalation on admin-pattern URLs.

### Race Conditions
```bash
boba test race $HUNT --url https://app.acme.com/api/claim --method POST \
  --body '{"code":"GIFT50"}' --concurrency 10
boba test race $HUNT --url https://app.acme.com/api/transfer --method POST \
  --session user_a --concurrency 20
```
Sends N concurrent identical requests and checks for response divergence (status or body). Filters out benign variance (304, 429).

### Open Redirect
```bash
boba test redirect $HUNT --url https://app.acme.com/login --param next
boba test redirect $HUNT --url https://app.acme.com/goto --param url
```
Injects external URLs into redirect parameters and checks if the server issues a 3xx to an external host.

### CSRF (Cross-Site Request Forgery)
```bash
boba test csrf $HUNT --url https://app.acme.com/settings --session user_a --method POST
boba test csrf $HUNT --url https://app.acme.com/api/transfer --session user_a \
  --method POST --body '{"amount":100}'
```
Tests three conditions: no CSRF token required, invalid token accepted, cross-origin request accepted.

### Mass Assignment
```bash
boba test mass-assign $HUNT --url https://app.acme.com/api/profile \
  --session user_a --method PUT
```
Sends extra fields (`isAdmin`, `role`, `verified`, `balance`, `plan`) via PUT/PATCH and checks if they persist.

### Password Reset
```bash
boba test reset $HUNT --url https://app.acme.com/reset-password
boba test reset $HUNT --url https://app.acme.com/forgot --email-param email
```
Tests Host header injection in reset links and rate limiting (5 rapid requests).

### AI / Prompt Injection
```bash
boba test ai $HUNT --url https://app.acme.com/api/chat --param message
boba test ai $HUNT --url https://app.acme.com/api/summarize --param text
```
Tests system prompt exfiltration (weighted scoring with strong/weak indicators) and instruction override (canary markers).

### Nuclei Scanning (Known CVEs)
```bash
boba scan nuclei $HUNT                               # scan all live hosts
boba scan nuclei $HUNT --severity high,critical       # high/critical only
boba scan nuclei $HUNT --tags cve,exposure            # filter by tags
boba scan nuclei $HUNT --targets https://app.acme.com
boba scan nuclei $HUNT --templates /path/to/custom/   # custom templates
```
Template-based scanning with 7,000+ community templates.

---

## Phase 6: Analysis

After testing, analyze what you found.

### Coverage — What Haven't We Tested?
```bash
boba analyze coverage $HUNT                          # full summary
boba analyze coverage $HUNT --untested-only          # show gaps
boba analyze coverage $HUNT --host app.acme.com      # filter by host
boba analyze coverage $HUNT --test-type sqli,xss     # specific test types
```
This tells you which endpoints have been tested for which vulnerability types, and where the gaps are.

### Deduplication — Are Any Findings the Same Bug?
```bash
boba analyze dedupe $HUNT                            # group duplicates
boba analyze dedupe $HUNT --dry-run                  # preview without persisting
```
Groups findings that share the same root cause (same URL + method + param + type). Selects a canonical finding per group.

### Severity — CVSS Scoring
```bash
boba analyze severity $HUNT                          # score all findings
boba analyze severity $HUNT --finding-id 7           # score one finding
boba analyze severity $HUNT --platform hackerone     # include payout estimates
```
Full CVSS 3.1 scoring with severity-to-payout mapping for HackerOne and Bugcrowd.

### Chaining — Turn Low-Severity into High-Severity
```bash
boba analyze chain $HUNT                             # auto-detect chains
boba analyze chain $HUNT --finding-ids 3,7,12        # suggest chains for specific findings
boba analyze chain $HUNT --validate 1                # confirm a chain works
```
Detects patterns like redirect + SSRF = internal access (P1), XSS + session cookie = account takeover (P1), SQLi + file write = RCE (Critical). This is where P4 findings become P1 payouts.

### Prioritization — What Should We Test Next?
```bash
boba analyze prioritize $HUNT                        # rank all untested endpoints
boba analyze prioritize $HUNT --top 20               # top 20 only
```
Ranks endpoints by vulnerability likelihood based on signals: query parameters, API patterns, auth/admin paths, "hot hosts" with existing findings.

---

## Phase 7: Reporting

Generate platform-ready reports from findings.

### Draft a Report
```bash
boba report draft $HUNT --finding-id 7               # report for a single finding
boba report draft $HUNT --chain-id 1                 # report for a chain
```
Auto-generates title, summary, reproduction steps, impact statement, and remediation.

### Format for a Platform
```bash
boba report format $HUNT --report-id 1 --platform hackerone
boba report format $HUNT --report-id 1 --platform bugcrowd
boba report format $HUNT --report-id 1 --platform markdown
```
Outputs the report in the platform's expected format.

### Package PoC Evidence
```bash
boba report poc $HUNT --finding-id 7 --output-dir ./evidence
boba report poc $HUNT --chain-id 1 --output-dir ./chain_evidence
```
Creates a directory with: README.md, HTTP request/response dumps (RFC 7230 format), and evidence.json.

### Manage Reports
```bash
boba report list $HUNT                               # list all reports
boba report list $HUNT --status draft                # filter by status
boba report show $HUNT --report-id 1 -f json         # full report details
```

---

## Querying Discovered Data

At any point, query what Boba has found without running any tools:

```bash
boba context subdomains $HUNT
boba context hosts $HUNT
boba context ports $HUNT
boba context urls $HUNT
boba context tech $HUNT
boba context directories $HUNT
boba context findings $HUNT
boba context findings $HUNT --type sqli --severity high
boba context sessions $HUNT
boba context http-history $HUNT --host app.acme.com --method POST --limit 50
boba context oob $HUNT
boba context runs $HUNT                              # tool run history
boba context stats $HUNT                             # counts of everything
```

All commands support `-f json` for structured output.

---

## Decision-Making Guide

As you hunt, use this reasoning framework:

### After Recon: What to enumerate first?
- **Hosts with non-standard ports** → likely internal services, fuzz directories
- **Hosts running outdated tech** (from `recon tech`) → run `scan nuclei --severity high,critical`
- **Historical URLs with query parameters** (from `recon urls`) → immediate candidates for SQLi, XSS, SSRF
- **Hosts with many subdomains** → crawl with `enum crawl` to find application structure

### After Enumeration: What to test first?
Run `boba analyze prioritize $HUNT --top 20` to get a ranked list. Then:
- **API endpoints** (`/api/`, `/v1/`, `/v2/`) → test IDOR, auth, mass assignment
- **Search/filter endpoints** (params like `q`, `search`, `query`, `filter`) → test SQLi, XSS
- **URL/redirect params** (`url`, `next`, `redirect`, `callback`, `return`) → test SSRF, open redirect
- **State-changing endpoints** (POST/PUT/DELETE) → test CSRF, race conditions
- **Auth endpoints** (`/login`, `/admin`, `/reset`, `/api/token`) → test auth bypass, password reset
- **AI/chat features** (`/api/chat`, `/api/summarize`, `/api/assist`) → test prompt injection

### After Testing: What to do with findings?
1. Run `boba analyze dedupe $HUNT` — collapse duplicates
2. Run `boba analyze severity $HUNT --platform hackerone` — know what each finding is worth
3. Run `boba analyze chain $HUNT` — look for chains that upgrade severity
4. Run `boba analyze coverage $HUNT --untested-only` — check if you missed anything
5. For each confirmed finding: `boba report draft`, `boba report format`, `boba report poc`

### When stuck or unsure:
- `boba context stats $HUNT` — see what data you have
- `boba context http-history $HUNT -f json` — review all traffic
- `boba analyze coverage $HUNT --untested-only` — find gaps
- `boba analyze prioritize $HUNT` — let the scoring guide you

---

## MCP Access (Alternative to CLI)

Boba also exposes all 65 tools as an MCP (Model Context Protocol) server. If you're connected via MCP, you call tools directly instead of running shell commands — no subprocess overhead, no JSON parsing, typed parameters.

**How to use:** Instead of `boba recon subdomains $HUNT -d example.com -f json`, call:
```
recon_subdomains(hunt_id="abc123", domains=["example.com"])
```

The MCP server returns structured JSON responses. All tools follow the same workflow as the CLI — the difference is the transport layer.

**Key differences from CLI:**
- Tool names use underscores instead of spaces (`recon_subdomains` not `recon subdomains`)
- No `-f json` flag needed — responses are always structured
- Sessions are referenced by name (`session_name="user_a"`) instead of `--session user_a`
- Recon/enum tools that default to "all known hosts" still do so — just omit the `targets` parameter

See `docs/mcp-setup.md` for full setup and tool reference.

---

## Key Things to Remember

1. **Every command needs a hunt ID.** Save it after `boba hunt create`.
2. **Scope is enforced automatically.** You don't need to worry about testing out-of-scope assets — Boba blocks it.
3. **Everything is persisted.** Discoveries, requests, findings, reports — all stored in SQLite. You never lose state.
4. **Use `-f json` for machine-readable output.** Table format is for human review.
5. **IDOR testing needs two sessions.** Create `user_a` and `user_b` before running `boba test idor`.
6. **Nuclei needs templates.** Run `nuclei -update-templates` once before first use.
7. **The analyze commands work on existing data.** They don't make any requests — they correlate what you've already found.
8. **Chain everything.** A P4 open redirect alone is worth ~$200. Combined with SSRF, it's P1 ($5,000+). Always run `boba analyze chain` after testing.
